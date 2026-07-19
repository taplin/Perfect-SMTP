//
//  DirectMXTransportTests.swift
//  PerfectSMTPTests
//
//  Plan §9 Phase 3 / this task's required coverage list: MX preference-order
//  host fallback, null-MX hard-fail, no-MX A/AAAA implicit-MX fallback,
//  multi-recipient/multi-domain independence, circuit-breaker integration,
//  and `.ambiguous` never being queued for retry. Uses the `MXResolving`
//  seam (`FakeMXResolver`) plus `DirectMXTransport`'s test-only injectable-
//  dialer `init` (mirroring `SMTPConnectionPool`'s own test seam) so every
//  test here is fully deterministic, in-memory, and touches neither a real
//  socket nor real DNS.
//

import Foundation
import NIOCore
import NIOEmbedded
import Testing
@testable import PerfectSMTP

struct DirectMXTransportTests {
    private func envelope(mailFrom: String = "from@sender.example", recipients: [String]) throws -> SMTPEnvelope {
        try SMTPEnvelope(mailFrom: .address(mailFrom), recipients: recipients)
    }

    private func message() -> SignedMessage {
        SignedMessage(rfc5322: Array("Subject: hi\r\nFrom: from@sender.example\r\n\r\nbody".utf8))
    }

    // MARK: - MX preference-order host fallback

    @Test func firstPreferenceHostFailsSecondPreferenceHostSucceeds() async throws {
        let resolver = FakeMXResolver(mxRecords: [
            "fallback.example": [
                DNSResolver.MXRecord(preference: 10, exchange: "mx1.fallback.example"),
                DNSResolver.MXRecord(preference: 20, exchange: "mx2.fallback.example"),
            ]
        ])
        let succeedingHost = scriptedDialer()
        let dialer: @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection = { key in
            switch key.host {
            case "mx1.fallback.example": throw SimulatedConnectFailure(label: "mx1 down")
            case "mx2.fallback.example": return try await succeedingHost(key)
            default: throw SimulatedConnectFailure(label: "unexpected host \(key.host)")
            }
        }

        let transport = DirectMXTransport(resolver: resolver, group: NIOAsyncTestingEventLoop(), dialer: dialer)
        let results = try await transport.send(try envelope(recipients: ["rcpt@fallback.example"]), message())

        #expect(results.count == 1)
        guard case .delivered = results[0].outcome else {
            Issue.record("expected .delivered via the fallback host, got \(results[0].outcome)")
            return
        }
    }

    // MARK: - Null-MX hard-fail

    @Test func nullMXHardFailsWithNoRetryAndNoAddressFallback() async throws {
        let resolveAddressesCalls = CallCountBox()
        let resolver = FakeMXResolver(
            mxErrors: ["nullmx.example": .nullMX],
            onResolveAddresses: { _ in Task { await resolveAddressesCalls.increment() } }
        )
        // Any dial attempt at all is a bug for this test -- null-MX must
        // hard-fail before ever reaching the connection pool.
        let transport = DirectMXTransport(resolver: resolver, group: NIOAsyncTestingEventLoop(), dialer: failingDialer())

        let results = try await transport.send(try envelope(recipients: ["victim@nullmx.example"]), message())

        #expect(results.count == 1)
        guard case .permanentlyFailed(let reply) = results[0].outcome else {
            Issue.record("expected .permanentlyFailed, got \(results[0].outcome)")
            return
        }
        #expect(reply.code == 556)

        // No retry queued -- permanent failures never enter the retry queue.
        let pending = await transport.pendingRetryEntries()
        #expect(pending.isEmpty)

        // The RFC 5321 §5.1 implicit-MX fallback must never be attempted
        // for a null-MX domain -- that's the entire point of RFC 7505.
        try await Task.sleep(for: .milliseconds(10))
        #expect(await resolveAddressesCalls.count == 0)
    }

    // MARK: - No-MX-records -> A/AAAA implicit-MX fallback

    @Test func noMXRecordsFallsBackToTheDomainsOwnAddressRecord() async throws {
        // `nomx.example` is deliberately absent from `mxRecords` -- `FakeMXResolver`
        // throws `.noRecordsFound` for any domain it doesn't recognize,
        // exactly like a real NODATA response.
        let resolver = FakeMXResolver()
        let dialer: @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection = { key in
            // The only way this dialer is ever invoked with `key.host ==
            // "nomx.example"` (the domain itself, not an MX exchange name)
            // is if `deliverToDomain` correctly fell back to treating the
            // domain as its own implicit MX.
            guard key.host == "nomx.example" else { throw SimulatedConnectFailure(label: "unexpected host \(key.host)") }
            return try await scriptedDialer()(key)
        }

        let transport = DirectMXTransport(resolver: resolver, group: NIOAsyncTestingEventLoop(), dialer: dialer)
        let results = try await transport.send(try envelope(recipients: ["rcpt@nomx.example"]), message())

        #expect(results.count == 1)
        guard case .delivered = results[0].outcome else {
            Issue.record("expected .delivered via the domain's own implicit MX, got \(results[0].outcome)")
            return
        }
    }

    // MARK: - Multi-recipient, multi-domain independence

    @Test func oneDomainsFailureDoesNotAffectAnotherDomainsDelivery() async throws {
        let resolver = FakeMXResolver(
            mxRecords: ["good.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.good.example")]],
            mxErrors: ["bad.example": .nullMX]
        )
        let dialer: @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection = { key in
            guard key.host == "mx.good.example" else { throw SimulatedConnectFailure(label: "unexpected host \(key.host)") }
            return try await scriptedDialer()(key)
        }

        let transport = DirectMXTransport(resolver: resolver, group: NIOAsyncTestingEventLoop(), dialer: dialer)
        let results = try await transport.send(
            try envelope(recipients: ["good@good.example", "bad@bad.example"]), message()
        )

        #expect(results.count == 2)
        let good = results.first { $0.recipient == "good@good.example" }
        let bad = results.first { $0.recipient == "bad@bad.example" }

        guard let good, case .delivered = good.outcome else {
            Issue.record("expected good@good.example delivered, got \(String(describing: good?.outcome))")
            return
        }
        guard let bad, case .permanentlyFailed = bad.outcome else {
            Issue.record("expected bad@bad.example permanently failed, got \(String(describing: bad?.outcome))")
            return
        }
    }

    // MARK: - Circuit breaker integration

    @Test func repeatedHostFailuresTripTheBreakerAndFallbackRoutesAroundIt() async throws {
        let resolver = FakeMXResolver(mxRecords: [
            "breaker.example": [
                DNSResolver.MXRecord(preference: 10, exchange: "flaky.breaker.example"),
                DNSResolver.MXRecord(preference: 20, exchange: "reliable.breaker.example"),
            ]
        ])
        let flakyDialAttempts = CallCountBox()
        let succeedingHost = scriptedDialer()
        let dialer: @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection = { key in
            switch key.host {
            case "flaky.breaker.example":
                await flakyDialAttempts.increment()
                throw SimulatedConnectFailure(label: "flaky host down")
            case "reliable.breaker.example":
                return try await succeedingHost(key)
            default:
                throw SimulatedConnectFailure(label: "unexpected host \(key.host)")
            }
        }

        let threshold = 2
        let config = DirectMXConfig(pool: .init(maxPerHost: 4, maxTotal: 100, circuitBreakerThreshold: threshold, circuitBreakerResetTimeout: .seconds(30)))
        let transport = DirectMXTransport(resolver: resolver, config: config, group: NIOAsyncTestingEventLoop(), dialer: dialer)

        // Every call still succeeds end-to-end (via the fallback host),
        // regardless of the flaky host's breaker state -- fallback and
        // breaker tripping are independent, composing correctly together.
        for _ in 0..<(threshold + 2) {
            let results = try await transport.send(try envelope(recipients: ["rcpt@breaker.example"]), message())
            guard case .delivered = results[0].outcome else {
                Issue.record("expected .delivered via the fallback host even while the flaky host's breaker is tripping")
                return
            }
        }

        // Once the breaker opens (after `threshold` consecutive dial
        // failures), `SMTPConnectionPool.checkout` short-circuits with
        // `.circuitOpen` *before* ever calling the dialer again -- so the
        // flaky host's dial-attempt count must stop climbing at exactly
        // `threshold`, proving the breaker tripped and
        // `deliverToDomain`'s own host-fallback loop is routing around it
        // (not just coincidentally retrying a host that keeps failing).
        #expect(await flakyDialAttempts.count == threshold)
    }

    @Test func allHostsBreakerTrippedSurfacesCircuitOpenAsFailed() async throws {
        let resolver = FakeMXResolver(mxRecords: [
            "alldown.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.alldown.example")]
        ])
        let threshold = 2
        let config = DirectMXConfig(pool: .init(circuitBreakerThreshold: threshold, circuitBreakerResetTimeout: .seconds(30)))
        let transport = DirectMXTransport(
            resolver: resolver, config: config, group: NIOAsyncTestingEventLoop(),
            dialer: failingDialer(label: "always down")
        )

        var lastResults: [DeliveryResult] = []
        for _ in 0..<(threshold + 1) {
            lastResults = try await transport.send(try envelope(recipients: ["rcpt@alldown.example"]), message())
        }

        #expect(lastResults.count == 1)
        guard case .failed(let error) = lastResults[0].outcome else {
            Issue.record("expected .failed once the sole host's breaker is open, got \(lastResults[0].outcome)")
            return
        }
        guard let smtpError = error as? SMTPError, case .circuitOpen = smtpError else {
            Issue.record("expected the .failed outcome to wrap SMTPError.circuitOpen, got \(error)")
            return
        }
    }

    // MARK: - `.ambiguous` is never queued for retry

    @Test func ambiguousOutcomeIsNeverQueuedForRetry() async throws {
        let resolver = FakeMXResolver(mxRecords: [
            "ambiguous.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.ambiguous.example")]
        ])
        let dialer: @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection = { _ in
            let (connection, channel) = try await ConnectionHarness.make()
            Task {
                guard let ehlo = try? await expectClientLine(channel), ehlo.hasPrefix("EHLO") else { return }
                try? await serverSend(channel, "250 mx.ambiguous.example Hello")
                guard let mail = try? await expectClientLine(channel), mail.hasPrefix("MAIL FROM") else { return }
                try? await serverSend(channel, "250 2.1.0 OK")
                guard let rcpt = try? await expectClientLine(channel), rcpt.hasPrefix("RCPT TO") else { return }
                try? await serverSend(channel, "250 2.1.5 OK")
                guard let data = try? await expectClientLine(channel), data == "DATA" else { return }
                try? await serverSend(channel, "354 Go ahead")
                _ = try? await channel.waitForOutboundWrite(as: ByteBuffer.self)
                // Simulate a disconnect exactly in the point-of-no-return
                // window (after the DATA payload is sent, before the final
                // reply arrives) instead of ever sending a final reply --
                // this is what `SMTPConnection.sendBodyAndFinalize`
                // classifies as `.ambiguous`.
                channel.close(promise: nil)
            }
            try await connection.negotiateCapabilities()
            return connection
        }

        let transport = DirectMXTransport(resolver: resolver, group: NIOAsyncTestingEventLoop(), dialer: dialer)
        let results = try await transport.send(try envelope(recipients: ["victim@ambiguous.example"]), message())

        #expect(results.count == 1)
        guard case .ambiguous = results[0].outcome else {
            Issue.record("expected .ambiguous, got \(results[0].outcome)")
            return
        }

        // `send(_:_:)` awaits its own retry-enqueue step before returning,
        // so this is safe to assert immediately -- `.ambiguous` must never
        // reach the retry queue at all.
        let pending = await transport.pendingRetryEntries()
        #expect(pending.isEmpty)
    }
}

/// A trivial actor counter -- used by these tests to assert on how many
/// times a dialer/resolver method was actually invoked.
actor CallCountBox {
    private(set) var count = 0
    func increment() { count += 1 }
}
