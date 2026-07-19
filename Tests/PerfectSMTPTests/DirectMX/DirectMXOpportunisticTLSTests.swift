//
//  DirectMXOpportunisticTLSTests.swift
//  PerfectSMTPTests
//
//  Plan §9 Phase 4, point 4: the new opportunistic-TLS-by-default behavior,
//  end-to-end against real `NIOPosix` sockets -- mirroring
//  `STARTTLSRealSocketTests.swift`/`DirectMXRealSocketTests.swift`'s
//  established pattern (a minimal in-process fake SMTP server driven by
//  `ServerBootstrap`, not `EmbeddedChannel`), because this behavior is
//  specifically about what `DirectMXTransport`'s *production* dialer
//  (`makeDialer`, via `SMTPBootstrap.connect`) actually does against a real
//  socket -- the same reason `DirectMXRealSocketTests` exists rather than
//  relying solely on the test-only injectable-dialer seam.
//
//  Three scenarios, matching this task's required coverage exactly:
//  (1) a server advertising STARTTLS gets a TLS attempt by default (no MTA-
//      STS policy needed -- `DirectMXConfig()`'s own new default,
//      `tlsPolicy: .opportunistic`, is exercised with no override at all);
//  (2) a server not advertising STARTTLS falls back to plaintext rather
//      than failing the whole delivery;
//  (3) **the security-critical one:** a genuine STARTTLS-injection
//      detection during the opportunistic attempt still hard-fails --
//      it must NOT fall back to plaintext, which would be exactly the
//      downgrade-attack outcome the STARTTLS buffer-discipline design
//      (plan §4.3) exists to prevent.
//

import NIOCore
import NIOPosix
import Testing
@testable import PerfectSMTP

struct DirectMXOpportunisticTLSTests {
    private func envelope(recipients: [String]) throws -> SMTPEnvelope {
        try SMTPEnvelope(mailFrom: .address("from@sender.example"), recipients: recipients)
    }

    private func message() -> SignedMessage {
        SignedMessage(rfc5322: Array("Subject: hi\r\nFrom: from@sender.example\r\n\r\nbody".utf8))
    }

    // MARK: - (1) STARTTLS advertised -> gets a real attempt by default

    @Test func aServerAdvertisingSTARTTLSGetsATLSAttemptByDefaultWithNoMTASTSPolicyNeeded() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let sawSTARTTLS = SeenFlag()
        let server = try await AdvertisingButNeverUpgradingFakeSMTPServer.start(group: group, onSTARTTLS: { await sawSTARTTLS.markSeen() })

        let resolver = FakeMXResolver(
            mxRecords: ["advertises.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.advertises.example")]],
            addresses: ["mx.advertises.example": [.v4([127, 0, 0, 1])]]
        )
        // Deliberately the plain default `DirectMXConfig()`'s
        // `tlsPolicy`/MTA-STS behavior -- no override, no policy provider
        // -- specifically to prove this is the library's *default*
        // behavior, not something that needs to be opted into. Only
        // `replyTimeout` is shortened from the 300s production default:
        // this fake server never completes a real handshake, and (exactly
        // like `serviceUnavailable421FeedsBreakerAndConnectionIsNotReturnedToIdlePool`'s
        // real-time-bounded precedent) this test only cares whether
        // STARTTLS was attempted at all, not what the connection's
        // eventual fate is -- a short timeout keeps this test fast
        // regardless of exactly how the post-`220`-then-close ambiguity
        // (a legitimate disconnect during the fenced upgrade window is
        // conservatively classified the same as a possible injection --
        // see `SMTPBootstrapHandler.errorCaught`'s own doc comment) plays
        // out on this particular run.
        let transport = DirectMXTransport(
            resolver: resolver,
            config: DirectMXConfig(port: server.port, replyTimeout: .seconds(2), allowPrivateAddresses: true),
            group: group
        )

        let envelope = try envelope(recipients: ["rcpt@advertises.example"])
        _ = try await transport.send(envelope, message())
        await transport.shutdown()
        try await server.channel.close()
        try await group.shutdownGracefully()

        #expect(await sawSTARTTLS.value, "the client must have sent STARTTLS by default -- no policy or explicit config was needed for the attempt itself")
    }

    // MARK: - (2) STARTTLS not advertised -> falls back to plaintext rather than failing

    @Test func aServerNotAdvertisingSTARTTLSFallsBackToPlaintextRatherThanFailingTheWholeDelivery() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let server = try await PlainAcceptingFakeSMTPServer.start(group: group)

        // `DirectMXTransport.domain(of:)` lowercases the recipient's domain
        // before grouping/resolving -- the `FakeMXResolver` dictionary key
        // must match that lowercased form exactly (an exact-match fake, no
        // case-folding of its own), so both the recipient and the
        // registered MX record key use "nostarttls.example" throughout.
        let resolver = FakeMXResolver(
            mxRecords: ["nostarttls.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.nostarttls.example")]],
            addresses: ["mx.nostarttls.example": [.v4([127, 0, 0, 1])]]
        )
        let transport = DirectMXTransport(
            resolver: resolver, config: DirectMXConfig(port: server.port, allowPrivateAddresses: true), group: group
        )

        let envelope = try envelope(recipients: ["rcpt@nostarttls.example"])
        let results = try await transport.send(envelope, message())
        await transport.shutdown()
        try await server.channel.close()
        try await group.shutdownGracefully()

        #expect(results.count == 1)
        guard case .delivered = results[0].outcome else {
            Issue.record("expected .delivered via the opportunistic plaintext fallback, got \(results[0].outcome)")
            return
        }
    }

    // MARK: - (3) Injection detection during the opportunistic attempt hard-fails -- never falls back to plaintext

    @Test func aGenuineSTARTTLSInjectionDuringTheOpportunisticAttemptHardFailsAndDoesNotFallBackToPlaintext() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let server = try await SameBufferInjectingFakeSMTPServer.start(group: group)

        let resolver = FakeMXResolver(
            mxRecords: ["injection.example": [DNSResolver.MXRecord(preference: 10, exchange: "mx.injection.example")]],
            addresses: ["mx.injection.example": [.v4([127, 0, 0, 1])]]
        )
        let transport = DirectMXTransport(
            resolver: resolver, config: DirectMXConfig(port: server.port, allowPrivateAddresses: true), group: group
        )

        let envelope = try envelope(recipients: ["rcpt@injection.example"])
        let results = try await transport.send(envelope, message())
        await transport.shutdown()
        try await server.channel.close()
        try await group.shutdownGracefully()

        #expect(results.count == 1)
        guard case .failed(let error) = results[0].outcome else {
            Issue.record("expected .failed (an injection must hard-fail, never silently degrade to plaintext delivery), got \(results[0].outcome)")
            return
        }
        guard let smtpError = error as? SMTPError, case .starttlsInjection = smtpError else {
            Issue.record("expected the failure to be classified as SMTPError.starttlsInjection specifically -- got \(error) -- a different classification here would mean the injection went undetected or was misclassified as an ordinary opportunistic-fallback trigger")
            return
        }
    }
}

/// A single-set-once, `async`-safe flag -- mirrors `STARTTLSRealSocketTests
/// .OutcomeBox`'s established shape for exactly this purpose.
private actor SeenFlag {
    private(set) var value = false
    func markSeen() { value = true }
}

// MARK: - Fake server 1: advertises STARTTLS, replies `220` to it, then
// closes without ever completing a real handshake -- same behavior as
// `STARTTLSRealSocketTests.FakeSMTPServer`, plus a callback fired the
// moment `STARTTLS` itself is received, so this test can assert the
// attempt was actually made independent of whatever `DirectMXTransport`
// ultimately classifies the resulting connection failure as (a real
// server hanging up before completing the handshake is exactly the
// ambiguous case this codebase's own fail-safe fencing conservatively
// treats as a possible injection -- see `SMTPBootstrapHandler
// .errorCaught`'s doc comment -- so this test deliberately does not assert
// on the final delivery outcome, only on whether the attempt itself
// happened).

private enum AdvertisingButNeverUpgradingFakeSMTPServer {
    struct Running {
        let channel: Channel
        let port: Int
    }

    static func start(group: any EventLoopGroup, onSTARTTLS: @escaping @Sendable () async -> Void) async throws -> Running {
        let bootstrap = ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(AdvertisingHandler(onSTARTTLS: onSTARTTLS))
                }
            }
        let channel = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
        guard let port = channel.localAddress?.port else { throw FakeServerError.noLocalPort }
        return Running(channel: channel, port: port)
    }
}

private final class AdvertisingHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private var accumulated = ByteBuffer()
    private let onSTARTTLS: @Sendable () async -> Void

    init(onSTARTTLS: @escaping @Sendable () async -> Void) {
        self.onSTARTTLS = onSTARTTLS
    }

    func channelActive(context: ChannelHandlerContext) {
        writeLine(context: context, "220 fake.example ESMTP")
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = Self.unwrapInboundIn(data)
        accumulated.writeBuffer(&incoming)
        while let line = extractLine(&accumulated) {
            handle(line: line, context: context)
        }
    }

    private func handle(line: String, context: ChannelHandlerContext) {
        let upper = line.uppercased()
        if upper.hasPrefix("EHLO") {
            writeLine(context: context, "250-fake.example Hello")
            writeLine(context: context, "250 STARTTLS")
        } else if upper == "STARTTLS" {
            let callback = onSTARTTLS
            Task { await callback() }
            writeLine(context: context, "220 Ready to start TLS")
            context.close(promise: nil)
        }
    }

    private func writeLine(context: ChannelHandlerContext, _ text: String) {
        var buffer = context.channel.allocator.buffer(capacity: text.utf8.count + 2)
        buffer.writeString(text)
        buffer.writeString("\r\n")
        context.writeAndFlush(Self.wrapOutboundOut(buffer), promise: nil)
    }
}

// MARK: - Fake server 2: never advertises STARTTLS at all, accepts a full
// plain EHLO/MAIL FROM/RCPT TO/DATA conversation -- identical in spirit to
// `DirectMXRealSocketTests.AcceptingFakeSMTPServerHandler`, redefined here
// (private to this file, matching that file's own scoping) so this test
// file doesn't reach into another test file's private types.

private enum PlainAcceptingFakeSMTPServer {
    struct Running {
        let channel: Channel
        let port: Int
    }

    static func start(group: any EventLoopGroup) async throws -> Running {
        let bootstrap = ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(PlainAcceptingHandler())
                }
            }
        let channel = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
        guard let port = channel.localAddress?.port else { throw FakeServerError.noLocalPort }
        return Running(channel: channel, port: port)
    }
}

private final class PlainAcceptingHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private var accumulated = ByteBuffer()
    private var inData = false

    func channelActive(context: ChannelHandlerContext) {
        writeLine(context: context, "220 fake.example ESMTP")
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = Self.unwrapInboundIn(data)
        accumulated.writeBuffer(&incoming)
        if inData {
            drainDataPhaseIfTerminated(context: context)
            return
        }
        while let line = extractLine(&accumulated) {
            handle(line: line, context: context)
        }
    }

    private func handle(line: String, context: ChannelHandlerContext) {
        let upper = line.uppercased()
        if upper.hasPrefix("EHLO") {
            // Deliberately no `STARTTLS` line -- this is the one thing
            // that differs from `AdvertisingHandler` above.
            writeLine(context: context, "250 fake.example Hello")
        } else if upper.hasPrefix("MAIL FROM") {
            writeLine(context: context, "250 2.1.0 OK")
        } else if upper.hasPrefix("RCPT TO") {
            writeLine(context: context, "250 2.1.5 OK")
        } else if upper == "DATA" {
            writeLine(context: context, "354 Go ahead")
            inData = true
            drainDataPhaseIfTerminated(context: context)
        }
    }

    private func drainDataPhaseIfTerminated(context: ChannelHandlerContext) {
        let terminator: [UInt8] = [0x0D, 0x0A, 0x2E, 0x0D, 0x0A] // "\r\n.\r\n"
        guard accumulated.readableBytesView.count >= terminator.count,
              Array(accumulated.readableBytesView.suffix(terminator.count)) == terminator
        else { return }
        accumulated.moveReaderIndex(forwardBy: accumulated.readableBytes)
        inData = false
        writeLine(context: context, "250 2.0.0 Queued as 12345")
    }

    private func writeLine(context: ChannelHandlerContext, _ text: String) {
        var buffer = context.channel.allocator.buffer(capacity: text.utf8.count + 2)
        buffer.writeString(text)
        buffer.writeString("\r\n")
        context.writeAndFlush(Self.wrapOutboundOut(buffer), promise: nil)
    }
}

// MARK: - Fake server 3: the CVE-2026-41319-class same-buffer injection --
// advertises STARTTLS, then replies to the client's `STARTTLS` command with
// the `220` and an injected command concatenated into **one** write (one
// `ByteBuffer`, one `writeAndFlush` call), mirroring `STARTTLSTests
// .sameBufferInjectionIsRejected`'s fixture shape but over a real socket
// instead of `EmbeddedChannel`.

private enum SameBufferInjectingFakeSMTPServer {
    struct Running {
        let channel: Channel
        let port: Int
    }

    static func start(group: any EventLoopGroup) async throws -> Running {
        let bootstrap = ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(SameBufferInjectingHandler())
                }
            }
        let channel = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
        guard let port = channel.localAddress?.port else { throw FakeServerError.noLocalPort }
        return Running(channel: channel, port: port)
    }
}

private final class SameBufferInjectingHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private var accumulated = ByteBuffer()

    func channelActive(context: ChannelHandlerContext) {
        writeLine(context: context, "220 fake.example ESMTP")
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = Self.unwrapInboundIn(data)
        accumulated.writeBuffer(&incoming)
        while let line = extractLine(&accumulated) {
            handle(line: line, context: context)
        }
    }

    private func handle(line: String, context: ChannelHandlerContext) {
        let upper = line.uppercased()
        if upper.hasPrefix("EHLO") {
            writeLine(context: context, "250-fake.example Hello")
            writeLine(context: context, "250 STARTTLS")
        } else if upper == "STARTTLS" {
            // The attack: the `220` reply and a would-be post-upgrade
            // command are written as one buffer, one flush -- exactly the
            // same-buffer injection shape `SMTPBootstrapHandler`'s
            // residual-bytes check (plan §4.3 step 3) exists to catch.
            var buffer = context.channel.allocator.buffer(capacity: 64)
            buffer.writeString("220 Ready to start TLS\r\n")
            buffer.writeString("EHLO evil.example\r\n")
            context.writeAndFlush(Self.wrapOutboundOut(buffer), promise: nil)
        }
    }

    private func writeLine(context: ChannelHandlerContext, _ text: String) {
        var buffer = context.channel.allocator.buffer(capacity: text.utf8.count + 2)
        buffer.writeString(text)
        buffer.writeString("\r\n")
        context.writeAndFlush(Self.wrapOutboundOut(buffer), promise: nil)
    }
}

// MARK: - Shared line-extraction helper (LF-terminated, tolerating a
// missing CR -- same simplification `STARTTLSRealSocketTests`/
// `DirectMXRealSocketTests` make, for the same reason: test-only, trusted
// input).

private func extractLine(_ buffer: inout ByteBuffer) -> String? {
    guard let lfIndex = buffer.readableBytesView.firstIndex(of: 0x0A) else { return nil }
    let length = lfIndex - buffer.readerIndex
    guard let bytes = buffer.readBytes(length: length) else { return nil }
    buffer.moveReaderIndex(forwardBy: 1)
    var text = String(decoding: bytes, as: UTF8.self)
    if text.hasSuffix("\r") { text.removeLast() }
    return text
}

private enum FakeServerError: Error {
    case noLocalPort
}
