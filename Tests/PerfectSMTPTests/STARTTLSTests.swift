//
//  STARTTLSTests.swift
//  PerfectSMTPTests
//
//  The CVE-2026-41319-class buffer-discipline invariant, as an automated
//  regression (plan §4.3/§5): "no byte read from the socket before the TLS
//  handshake may be processed as post-TLS input." Feeds `220 Ready\r\n`
//  and then, as a **second, separate** inbound buffer (not concatenated),
//  injects `EHLO evil.example\r\n`; asserts `SMTPBootstrapHandler` throws
//  `.starttlsInjection`, closes the channel, and never processes the
//  injected command. A companion test confirms the clean single-`220`-
//  then-silence path upgrades correctly (decoder swapped, TLS handler
//  inserted, no throw) -- the EHLO re-issue with capabilities reset is
//  Phase B's job, covered separately in `SMTPConnectionStateMachineTests`.
//

import NIOCore
import NIOEmbedded
import NIOSSL
import Testing
@testable import PerfectSMTP

struct STARTTLSTests {

    /// Drives the harness through greeting + pre-TLS EHLO (advertising
    /// STARTTLS) + the client's STARTTLS command, leaving it parked
    /// waiting for the server's `220` -- the shared setup for every test
    /// below.
    private func primeUpToSTARTTLSReply(_ built: BootstrapHarness.Built) throws {
        try built.channel.writeInbound(ByteBuffer(string: "220 smtp.example.com ESMTP\r\n"))
        pump(built.channel)
        try expectOutboundLine(built.channel, "EHLO localhost")
        try built.channel.writeInbound(ByteBuffer(string: "250-smtp.example.com\r\n250 STARTTLS\r\n"))
        pump(built.channel)
        try expectOutboundLine(built.channel, "STARTTLS")
    }

    /// Reads the promise's outcome without blocking -- `EmbeddedEventLoop`
    /// has no real clock or background thread, so a genuinely-still-
    /// pending promise (e.g. waiting on a real TLS peer that doesn't exist
    /// in this test) must never be awaited with a blocking `.wait()`,
    /// which would hang forever. `nil` means "not yet resolved".
    private func immediateOutcome<V: Sendable>(_ future: EventLoopFuture<V>) -> Result<V, Error>? {
        let box = OutcomeBox<V>()
        future.whenComplete { box.outcome = $0 }
        return box.outcome
    }

    @Test func sameBufferInjectionIsRejected() throws {
        let built = try BootstrapHarness.make(tls: .startTLS)
        try primeUpToSTARTTLSReply(built)

        // The "simpler case" the plan calls out: injected bytes
        // concatenated into the *same* buffer as the 220.
        var malicious = ByteBuffer(string: "220 Ready\r\n")
        malicious.writeString("EHLO evil.example\r\n")
        writeInboundIgnoringError(built.channel, malicious)
        pump(built.channel)

        #expect(!built.channel.isActive)
        guard case .failure(let error) = immediateOutcome(built.promise.futureResult) else {
            Issue.record("expected the bootstrap promise to have failed")
            return
        }
        if case .some(.starttlsInjection) = error as? SMTPError { } else { Issue.record("expected .starttlsInjection, got \(error)") }
    }

    @Test func separateBufferInjectionIsRejected() throws {
        let built = try BootstrapHarness.make(tls: .startTLS)
        try primeUpToSTARTTLSReply(built)

        // The harder case the plan specifically calls out: the 220 arrives
        // alone first...
        try built.channel.writeInbound(ByteBuffer(string: "220 Ready\r\n"))
        pump(built.channel)

        // ...then, as a second, separate inbound buffer, the injection
        // attempt. By this point Phase A has already removed the plaintext
        // decoder and inserted `NIOSSLClientHandler` (mid-handshake); this
        // plaintext garbage cannot be parsed as a valid TLS record, so the
        // handshake fails -- which this handler, still armed for the
        // fenced upgrade window, maps to `.starttlsInjection` rather than
        // letting a generic TLS error escape.
        writeInboundIgnoringError(built.channel, ByteBuffer(string: "EHLO evil.example\r\n"))
        pump(built.channel)

        guard case .failure(let error) = immediateOutcome(built.promise.futureResult) else {
            Issue.record("expected the bootstrap promise to have failed")
            return
        }
        if case .some(.starttlsInjection) = error as? SMTPError { } else { Issue.record("expected .starttlsInjection, got \(error)") }
        #expect(!built.channel.isActive)
    }

    @Test func cleanUpgradeSwapsDecoderAndInsertsTLSHandlerWithoutThrowing() throws {
        let built = try BootstrapHarness.make(tls: .startTLS)
        try primeUpToSTARTTLSReply(built)

        // Clean path: only the 220, then silence. Must not throw.
        try built.channel.writeInbound(ByteBuffer(string: "220 Ready to start TLS\r\n"))
        pump(built.channel)

        // The plaintext bootstrap decoder is gone; a `NIOSSLClientHandler`
        // is now in the pipeline (mid-handshake, since no real TLS peer is
        // driving it in this unit test -- completing a real handshake is
        // exercised at the gated live-integration tier, not here).
        _ = try built.channel.pipeline.syncOperations.handler(type: NIOSSLClientHandler.self)

        // The promise has not resolved yet (handshake never completes in
        // this synchronous unit test) -- but critically, it also has not
        // *failed*, confirming Phase A treated this as the legitimate
        // clean-upgrade path, not an injection.
        #expect(immediateOutcome(built.promise.futureResult) == nil)
        #expect(built.channel.isActive)
    }
}

/// `@unchecked Sendable`: only ever touched synchronously, single-threaded,
/// within one `EmbeddedEventLoop`'s inline callback execution.
private final class OutcomeBox<V>: @unchecked Sendable {
    var outcome: Result<V, Error>?
}
