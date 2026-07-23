//
//  RelayTransportPoolHealthTests.swift
//  PerfectSMTPTests
//
//  FIX #1 (milestone architecture + SMTP-protocol reviews): confirms the
//  shared `SMTPConnectionPool.withConnection(to:isHealthy:_:)` fix applies
//  to `RelayTransport`, not just `DirectMXTransport`. `RelayTransport` has
//  no MX-host fallback to break, but it owns the same pool/breaker
//  machinery, and `SMTPConnection.sendMessage` returns RCPT/DATA-phase
//  rejections (`.ambiguous`, a `421`) as normal data exactly the same way
//  for both transports -- so without `isHealthy:` wired through here too,
//  a mid-DATA disconnect against a relay would never feed the breaker or
//  get proactively closed either.
//

import NIOCore
import NIOEmbedded
import Testing
@testable import PerfectSMTP

struct RelayTransportPoolHealthTests {
    private func relayConfig(circuitBreakerThreshold: Int) -> RelayConfig {
        RelayConfig(
            host: "relay.example.com", port: 587, tls: .none,
            pool: .init(circuitBreakerThreshold: circuitBreakerThreshold, circuitBreakerResetTimeout: 30)
        )
    }

    private func envelope() throws -> SMTPEnvelope {
        try SMTPEnvelope(mailFrom: .address("from@sender.example"), recipients: ["rcpt@relay.example.com"])
    }

    private func message() -> SignedMessage {
        SignedMessage(rfc5322: Array("Subject: hi\r\nFrom: from@sender.example\r\n\r\nbody".utf8))
    }

    /// Mirrors `DirectMXTransportTests
    /// .ambiguousMidDataDisconnectFeedsBreakerFailureCountNotSuccess`, but
    /// against `RelayTransport` -- a single mid-DATA disconnect, with
    /// `circuitBreakerThreshold: 1`, must open the breaker so a second
    /// `send` fails with `SMTPError.circuitOpen` rather than dialing again.
    @Test func ambiguousMidDataDisconnectFeedsBreakerOnRelayTransportToo() async throws {
        let dialAttempts = CallCountBox()
        let dialer: @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection = { _ in
            await dialAttempts.increment()
            let attemptNumber = await dialAttempts.count
            guard attemptNumber == 1 else {
                throw SimulatedConnectFailure(label: "unexpected second dial -- breaker should already be open")
            }
            let (connection, channel) = try await ConnectionHarness.make()
            Task {
                guard let ehlo = try? await expectClientLine(channel), ehlo.hasPrefix("EHLO") else { return }
                try? await serverSend(channel, "250 relay.example.com Hello")
                guard let mail = try? await expectClientLine(channel), mail.hasPrefix("MAIL FROM") else { return }
                try? await serverSend(channel, "250 2.1.0 OK")
                guard let rcpt = try? await expectClientLine(channel), rcpt.hasPrefix("RCPT TO") else { return }
                try? await serverSend(channel, "250 2.1.5 OK")
                guard let data = try? await expectClientLine(channel), data == "DATA" else { return }
                try? await serverSend(channel, "354 Go ahead")
                _ = try? await channel.waitForOutboundWrite(as: ByteBuffer.self)
                channel.close(promise: nil)
            }
            try await connection.negotiateCapabilities()
            return connection
        }

        let transport = RelayTransport(config: relayConfig(circuitBreakerThreshold: 1), group: NIOAsyncTestingEventLoop(), dialer: dialer)

        let r1 = try await transport.send(try envelope(), message())
        guard case .ambiguous = r1[0].outcome else {
            Issue.record("expected the first attempt to be .ambiguous, got \(r1[0].outcome)")
            return
        }

        await #expect(throws: SMTPError.self) {
            _ = try await transport.send(try self.envelope(), self.message())
        }
        #expect(await dialAttempts.count == 1)

        await transport.shutdown()
    }
}
