//
//  STARTTLSRealSocketTests.swift
//  PerfectSMTPTests
//
//  Milestone review finding (FIX #1): `STARTTLSTests.swift` is entirely
//  `EmbeddedChannel`-based, which does not model real kqueue/epoll
//  read-interest deregistration at all -- see the blind-spot comment at the
//  top of that file. That blind spot is exactly how the original
//  `handlePreTLSEHLOReply` bug (disabling `autoRead` *before* the server's
//  `220` reply to STARTTLS had arrived, permanently starving the reactor of
//  notification that the already-in-flight `220` bytes were sitting in the
//  kernel socket buffer) shipped and passed the whole existing suite.
//
//  This test exercises `SMTPBootstrap.connect(tls: .startTLS, ...)` against
//  a real `NIOPosix` socket (a minimal in-process fake SMTP server driven by
//  `ServerBootstrap`/`ClientBootstrap`, not `EmbeddedChannel`) specifically
//  so a regression of that class of bug reintroduces a real, observable
//  hang here, not just a passing green suite.
//
//  This test earned its keep immediately: writing it surfaced a SECOND,
//  independent real-socket-only hang in the same STARTTLS sequence, sitting
//  one step further down the pipeline from the originally-reported bug and
//  invisible to `EmbeddedChannel` for the identical reason. Fixed
//  `handlePreTLSEHLOReply`/`handleStartTLSReply` alone (moving the
//  `autoRead = false` fence) still hung indefinitely against this test's
//  real fake server -- `insertTLSAndFreshDecoder` left `autoRead` disabled
//  all the way until the TLS handshake-completed event, but
//  `NIOSSLClientHandler` never proactively pulls a read to *start* that
//  handshake (it only pulls a follow-up read reactively, from inside its
//  own `channelRead` handling, once one has already occurred) -- so with
//  read interest deregistered, the handshake could never receive its first
//  byte. Fixed by re-enabling `autoRead` immediately after inserting the
//  SSL handler and fresh decoder (`insertTLSAndFreshDecoder`), matching the
//  plan's literal step 6 ordering, rather than deferring it to
//  handshake-completion -- see that method's comment for why this doesn't
//  reopen the injection window (the protection comes from
//  `NIOSSLClientHandler`'s pipeline position, not from `autoRead`).
//
//  Bounded WITHOUT relying on `Task` cancellation actually interrupting a
//  stuck real-socket operation (real sockets don't guarantee that -- a
//  cancelled `Task` awaiting `EventLoopFuture.get()` does not force the
//  underlying NIO operation to abort, and `withThrowingTaskGroup`/
//  `withTaskGroup` must fully drain every child, including a stubbornly-
//  still-running one, before returning -- an earlier version of this test
//  used exactly that pattern and hung indefinitely waiting for that drain
//  while the second bug above was still present). Instead:
//  `SMTPBootstrap.connect(...)` is launched on a plain, unstructured `Task`
//  that this test function never awaits -- the test polls a shared,
//  actor-guarded outcome box on a bounded loop and returns as soon as
//  either the outcome is set or the poll budget is exhausted, regardless of
//  whether the unstructured task itself has finished. If it hasn't, it is
//  simply abandoned and left to resolve or not on its own -- the test
//  process exits at the end of the suite regardless, which reclaims it.
//

import NIOCore
import NIOPosix
import Testing
@testable import PerfectSMTP

struct STARTTLSRealSocketTests {

    @Test func startTLSProcessesTheServersReplyInsteadOfHangingOnARealSocket() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let server = try await FakeSMTPServer.start(group: group)

        let outcomeBox = OutcomeBox()
        // Deliberately unstructured: this `Task` is never awaited by this
        // test function (see the file header comment for why -- structured
        // concurrency's forced drain-on-return is exactly what made an
        // earlier version of this test hang). It sets `outcomeBox` when
        // (if) it finishes; the test itself is bounded purely by the poll
        // loop below, independent of whether this task ever completes.
        Task {
            // `try?`: we don't care whether this ultimately succeeds or
            // throws -- the fake server never completes a real TLS
            // handshake, so a thrown error here is an *expected*, correct
            // outcome. What matters is that it resolves at all, promptly,
            // rather than hanging forever waiting on a `220` that was never
            // going to be delivered (the pre-fix bug).
            _ = try? await SMTPBootstrap.connect(
                host: "127.0.0.1", port: server.port, tls: .startTLS, group: group
            )
            await outcomeBox.markCompleted()
        }

        var completed = false
        for _ in 0..<50 {
            if await outcomeBox.isCompleted {
                completed = true
                break
            }
            try? await Task.sleep(nanoseconds: UInt64(100) * 1_000_000)
        }

        try? await server.channel.close()
        try? await group.shutdownGracefully()

        let failureMessage = "SMTPBootstrap.connect(tls: .startTLS, ...) hung against a real socket -- "
            + "this is the exact FIX #1 regression (autoRead disabled before the STARTTLS "
            + "220 reply arrived, permanently starving the reactor of read notifications)"
        #expect(completed, Comment(rawValue: failureMessage))
    }
}

/// A single-set-once flag, safe to read/write from both this test's poll
/// loop and the unstructured `Task` racing against it.
private actor OutcomeBox {
    private(set) var isCompleted = false
    func markCompleted() { isCompleted = true }
}

/// A minimal, real-socket fake SMTP server: greets with `220`, replies to
/// `EHLO` with a `STARTTLS`-advertising capability list, replies to
/// `STARTTLS` with `220 Ready`, then closes the connection -- it never
/// speaks real TLS. Line framing is hand-rolled (LF-terminated, tolerating
/// a missing CR) rather than pulling in a framing dependency, since this is
/// a test-only, trusted-input server.
private enum FakeSMTPServer {
    struct Running {
        let channel: Channel
        let port: Int
    }

    static func start(group: any EventLoopGroup) async throws -> Running {
        let bootstrap = ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(FakeSMTPServerHandler())
                }
            }
        let channel = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
        guard let port = channel.localAddress?.port else {
            throw FakeSMTPServerError.noLocalPort
        }
        return Running(channel: channel, port: port)
    }
}

private enum FakeSMTPServerError: Error {
    case noLocalPort
}

private final class FakeSMTPServerHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private var accumulated = ByteBuffer()

    func channelActive(context: ChannelHandlerContext) {
        writeLine(context: context, "220 fake.example ESMTP")
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = Self.unwrapInboundIn(data)
        accumulated.writeBuffer(&incoming)
        while let line = extractLine() {
            handle(line: line, context: context)
        }
    }

    private func extractLine() -> String? {
        guard let lfIndex = accumulated.readableBytesView.firstIndex(of: 0x0A) else { return nil }
        let length = lfIndex - accumulated.readerIndex
        guard let bytes = accumulated.readBytes(length: length) else { return nil }
        accumulated.moveReaderIndex(forwardBy: 1) // consume the LF itself
        var text = String(decoding: bytes, as: UTF8.self)
        if text.hasSuffix("\r") { text.removeLast() }
        return text
    }

    private func handle(line: String, context: ChannelHandlerContext) {
        let upper = line.uppercased()
        if upper.hasPrefix("EHLO") {
            writeLine(context: context, "250-fake.example Hello")
            writeLine(context: context, "250 STARTTLS")
        } else if upper == "STARTTLS" {
            writeLine(context: context, "220 Ready to start TLS")
            // Deliberately close rather than attempting a real TLS
            // handshake -- see this file's header comment for why this
            // keeps the test bounded without depending on `Task`
            // cancellation interrupting a hung real-socket read.
            context.close(promise: nil)
        }
        // Any further bytes (a real client would send a TLS ClientHello
        // here) are not CRLF-terminated text and simply never form another
        // line -- harmless, since the server side is done at this point.
    }

    private func writeLine(context: ChannelHandlerContext, _ text: String) {
        var buffer = context.channel.allocator.buffer(capacity: text.utf8.count + 2)
        buffer.writeString(text)
        buffer.writeString("\r\n")
        context.writeAndFlush(Self.wrapOutboundOut(buffer), promise: nil)
    }
}
