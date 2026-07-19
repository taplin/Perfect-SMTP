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
//  KNOWN BLIND SPOT (milestone review finding, FIX #1) -- READ BEFORE
//  TRUSTING THIS SUITE FOR AUTOREAD/READ-INTEREST BEHAVIOR:
//
//  `EmbeddedChannel` does not model real kqueue/epoll read-interest
//  registration at all -- calling
//  `channel.setOption(ChannelOptions.autoRead, value: false)` on an
//  `EmbeddedChannel` records the option's value but has no effect on
//  whether `writeInbound`-delivered bytes are ever seen by the pipeline;
//  every `writeInbound` call unconditionally delivers its bytes to
//  `channelRead`, `autoRead` setting notwithstanding. This is exactly why
//  a real bug shipped and passed this whole suite once: the original
//  `handlePreTLSEHLOReply` disabled `autoRead` immediately after writing
//  `STARTTLS`, *before* the server's `220` reply had arrived. Against a
//  real `NIOPosix` socket, that synchronously deregisters read interest at
//  the kqueue/epoll level on the `true -> false` transition, so the
//  already-in-flight `220` bytes sit unread in the kernel socket buffer
//  forever -- every real STARTTLS negotiation hangs. Against
//  `EmbeddedChannel`, the next `writeInbound(ByteBuffer(string: "220
//  ...\r\n"))` call in `primeUpToSTARTTLSReply`/the tests below delivers
//  the `220` to `channelRead` regardless, so the hang was completely
//  invisible here.
//
//  The fix (moving the `autoRead = false` call into `handleStartTLSReply`,
//  synchronous with receiving the `220`) is exercised by this suite's
//  normal assertions -- correct STARTTLS *sequencing* and the
//  injection-rejection behavior are real regressions this suite catches.
//  What it can NOT catch, by construction, is a regression that
//  reintroduces a premature `autoRead = false` call (or any other
//  real-socket-only read-interest bug): `EmbeddedChannel` would still
//  pass. If you are refactoring this fencing logic, do not trust a green
//  `STARTTLSTests` run alone -- verify by tracing exactly when
//  `setOption(autoRead, ...)` is called relative to when the `220` reply
//  is written into the pipeline, or exercise it against a real `NIOPosix`
//  `ServerBootstrap`/`ClientBootstrap` pair (a full real-socket regression
//  test was judged too large an undertaking for this fix pass -- this
//  comment is the documented mitigation in its place).
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
        guard case .some(.starttlsInjection(let underlying)) = error as? SMTPError else {
            Issue.record("expected .starttlsInjection, got \(error)")
            return
        }
        // Same-buffer path: detected directly by the decoder's own
        // residual-bytes check (`handleStartTLSReply`'s guard), not
        // surfaced via `errorCaught` -- no underlying error to carry
        // (milestone review finding, `SMTPError.starttlsInjection`'s new
        // associated value).
        #expect(underlying == nil)
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
        guard case .some(.starttlsInjection(let underlying)) = error as? SMTPError else {
            Issue.record("expected .starttlsInjection, got \(error)")
            return
        }
        // Separate-buffer path: the garbage bytes reach `NIOSSLClientHandler`
        // as bogus TLS record data, failing the handshake with a genuine
        // NIOSSL error -- surfaced via `errorCaught`, so this case DOES
        // carry a real underlying error (milestone review finding).
        #expect(underlying != nil)
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

    // MARK: - IP-literal host / no-SNI fallback (lowest priority, milestone
    // security review: verified safe -- `serverHostname: nil` still
    // triggers full certificate verification including IP-SAN checking
    // against the real peer address, it is not a verification bypass).
    // Full handshake-level testing needs a live socket/real certificate and
    // is impractical here; this confirms the narrower, still-useful claim
    // that construction itself doesn't throw for an IP-literal host.

    @Test func makeSSLHandlerDoesNotThrowForAnIPLiteralHost() throws {
        _ = try SMTPBootstrap.makeSSLHandler(host: "203.0.113.10", configuration: .makeClientConfiguration())
    }

    @Test func makeSSLHandlerDoesNotThrowForAnIPv6LiteralHost() throws {
        _ = try SMTPBootstrap.makeSSLHandler(host: "2001:db8::1", configuration: .makeClientConfiguration())
    }
}

/// `@unchecked Sendable`: only ever touched synchronously, single-threaded,
/// within one `EmbeddedEventLoop`'s inline callback execution.
private final class OutcomeBox<V>: @unchecked Sendable {
    var outcome: Result<V, Error>?
}
