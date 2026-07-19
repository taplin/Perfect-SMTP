//
//  SMTPResponseDecoderCapsTests.swift
//  PerfectSMTPTests
//
//  FIX #6 (milestone security review, medium): unbounded reply buffering
//  enables DoS from a malicious/compromised server. Two independent caps,
//  each targeting a different unbounded-growth vector, both matter for
//  `TLSMode.none` (explicitly supported for trusted-network relays per
//  `RelayTransport`'s own doc comment) and for any relay that later turns
//  hostile/compromised, before TLS-verification-driven trust even applies:
//
//   1. `ByteToMessageHandler`'s own cumulation buffer, now bounded by an
//      explicit `maximumBufferSize` (`SMTPBootstrap.maximumReplyBufferSize`)
//      instead of NIO's unbounded default -- a server sending one
//      arbitrarily long line with no CRLF would otherwise grow that buffer
//      without limit.
//   2. `SMTPResponseDecoder.pendingLines`, now capped at a fixed number of
//      accumulated continuation lines -- a server that keeps sending
//      well-formed `250-x\r\n` continuation lines and never sends the
//      terminal line would otherwise grow that array without limit. This is
//      a distinct growth vector from #1: each individual line can be short
//      (well under the cumulation buffer's cap), so only the *count* of
//      lines accumulated for one multiline reply, not the raw byte count,
//      is what's unbounded here.
//

import NIOCore
import NIOEmbedded
import Testing
@testable import PerfectSMTP

struct SMTPResponseDecoderCapsTests {

    @Test func unterminatedLineBeyondMaximumBufferSizeThrowsRatherThanGrowingUnbounded() throws {
        let channel = EmbeddedChannel()
        defer { _ = try? channel.finish() }
        try channel.pipeline.syncOperations.addHandler(
            ByteToMessageHandler(SMTPResponseDecoder(), maximumBufferSize: SMTPBootstrap.maximumReplyBufferSize)
        )

        // One line, no CRLF anywhere, deliberately larger than the cap --
        // simulates a hostile/compromised server sending an arbitrarily
        // long line with no terminator.
        var oversized = ByteBufferAllocator().buffer(capacity: SMTPBootstrap.maximumReplyBufferSize + 1)
        oversized.writeBytes(repeatElement(UInt8(ascii: "2"), count: SMTPBootstrap.maximumReplyBufferSize + 1))

        #expect(throws: (any Error).self) {
            try channel.writeInbound(oversized)
        }
    }

    @Test func wellFormedButNeverTerminatedMultilineReplyIsCappedByContinuationLineCount() throws {
        let channel = EmbeddedChannel()
        defer { _ = try? channel.finish() }
        try channel.pipeline.syncOperations.addHandler(
            ByteToMessageHandler(SMTPResponseDecoder(), maximumBufferSize: SMTPBootstrap.maximumReplyBufferSize)
        )

        // Every line here is short, well-formed, and individually
        // unremarkable (`250-...\r\n`, a valid continuation line) -- the
        // attack this cap defends against is a server that just never
        // sends the terminal (`250 `) line, growing `pendingLines`
        // forever. None of these lines would ever trip
        // `maximumBufferSize` (each is a few bytes; `ByteToMessageHandler`
        // also compacts consumed bytes as lines are read out), so this
        // test genuinely exercises the second, independent cap.
        var caught: Error?
        lineLoop: for i in 0..<200 {
            do {
                try channel.writeInbound(ByteBuffer(string: "250-line \(i)\r\n"))
            } catch {
                caught = error
                break lineLoop
            }
        }

        guard let caught else {
            Issue.record("expected the decoder to throw once the continuation-line cap was exceeded")
            return
        }
        guard let decoderError = caught as? SMTPResponseDecoder.DecoderError,
              case .tooManyContinuationLines = decoderError
        else {
            Issue.record("expected .tooManyContinuationLines, got \(caught)")
            return
        }
    }
}
