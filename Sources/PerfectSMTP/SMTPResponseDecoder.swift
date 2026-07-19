//
//  SMTPResponseDecoder.swift
//  PerfectSMTP
//
//  Accumulates multiline SMTP reply lines into one `SMTPReply` (plan §4.3,
//  "Reply decoding"). Continuation lines have a `-` after the 3-digit code
//  (`250-`), the terminal line has a space (`250 `). Reuses Phase 0's
//  `SMTPReply`/`EnhancedStatusCode` from `PerfectSMTPCore` — no redefinition.
//
//  A reference type (`final class`), not a struct: `SMTPBootstrapHandler`
//  keeps its own external reference to the *same* decoder instance it hands
//  to `ByteToMessageHandler`, so it can query `hasResidualBytesAfterLastReply`
//  directly without reaching into `ByteToMessageHandler`'s private
//  cumulation buffer (which isn't exposed through any public API). Class
//  reference semantics make that possible; `ByteToMessageDecoder`'s
//  `mutating func` requirements are satisfied trivially by a class's
//  ordinary (non-`mutating`) methods.
//

import NIOCore

public final class SMTPResponseDecoder: ByteToMessageDecoder, @unchecked Sendable {
    public typealias InboundOut = SMTPReply

    public enum DecoderError: Error, Sendable, Equatable {
        case malformedReplyLine(String)
        case codeMismatchInMultiline(expected: Int, got: Int)
        /// Thrown from `decodeLast` when bytes remain in the buffer at the
        /// moment this decoder is removed from the pipeline (or the channel
        /// goes inactive) — plan §4.3 step 4: `ByteToMessageDecoder` removal
        /// triggers `decodeLast`, which by default flushes remaining bytes
        /// through one more `decode` loop; the opposite of "discard
        /// entirely" is exactly wrong here, since surviving bytes at this
        /// exact moment are the CVE-2026-41319-class buffer-discipline
        /// violation this decoder exists to catch. `SMTPBootstrapHandler`
        /// maps this to `SMTPError.starttlsInjection` when it occurs during
        /// the STARTTLS upgrade window; elsewhere (e.g. a truncated reply at
        /// ordinary connection close) it surfaces as a plain connection
        /// error, which is still correct — a reply cut off mid-line at
        /// close is a genuine protocol violation, not something to
        /// silently ignore.
        case residualBytesOnRemoval
    }

    private var pendingCode: Int?
    private var pendingLines: [String] = []

    /// True immediately after `decode(context:buffer:)` successfully emits
    /// a full `SMTPReply`, if the buffer it was decoding from still had more
    /// readable bytes beyond the consumed reply line(s) at that exact
    /// moment. Used by `SMTPBootstrapHandler`'s STARTTLS residual-bytes
    /// assertion (plan §4.3 step 3) — this catches the "injected bytes
    /// concatenated into the same buffer as the 220" case; the harder
    /// "second, separate buffer" case is caught by `decodeLast` above
    /// instead (see the regression test for both).
    public private(set) var hasResidualBytesAfterLastReply = false

    public init() {}

    public func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        guard let line = try readLine(from: &buffer) else { return .needMoreData }
        guard let parsed = Self.parseLine(line) else {
            throw DecoderError.malformedReplyLine(line)
        }
        if let expected = pendingCode, expected != parsed.code {
            throw DecoderError.codeMismatchInMultiline(expected: expected, got: parsed.code)
        }
        pendingCode = parsed.code
        pendingLines.append(parsed.text)

        guard !parsed.isContinuation else { return .continue }

        let reply = SMTPReply(code: parsed.code, lines: pendingLines)
        pendingCode = nil
        pendingLines = []
        hasResidualBytesAfterLastReply = buffer.readableBytes > 0
        context.fireChannelRead(Self.wrapInboundOut(reply))
        return .continue
    }

    public func decodeLast(
        context: ChannelHandlerContext,
        buffer: inout ByteBuffer,
        seenEOF: Bool
    ) throws -> DecodingState {
        while try decode(context: context, buffer: &buffer) == .continue {}
        if buffer.readableBytes > 0 {
            throw DecoderError.residualBytesOnRemoval
        }
        return .needMoreData
    }

    // MARK: - Line framing

    private func readLine(from buffer: inout ByteBuffer) throws -> String? {
        guard let lfIndex = buffer.readableBytesView.firstIndex(of: 0x0A) else { return nil }
        guard lfIndex > buffer.readerIndex,
              buffer.getInteger(at: lfIndex - 1, as: UInt8.self) == 0x0D
        else {
            throw DecoderError.malformedReplyLine("line terminated by bare LF without a preceding CR")
        }
        let lineLength = (lfIndex - 1) - buffer.readerIndex
        guard let bytes = buffer.readBytes(length: lineLength) else { return nil }
        buffer.moveReaderIndex(forwardBy: 2) // consume CRLF
        return String(decoding: bytes, as: UTF8.self)
    }

    // MARK: - Reply-line parsing

    private struct ParsedLine {
        let code: Int
        let text: String
        let isContinuation: Bool
    }

    private static func parseLine(_ line: String) -> ParsedLine? {
        guard line.count >= 3 else { return nil }
        let codeChars = line.prefix(3)
        guard codeChars.allSatisfy({ $0.isASCII && $0.isNumber }), let code = Int(codeChars) else {
            return nil
        }
        if line.count == 3 {
            return ParsedLine(code: code, text: "", isContinuation: false)
        }
        let separatorIndex = line.index(line.startIndex, offsetBy: 3)
        let separator = line[separatorIndex]
        guard separator == "-" || separator == " " else { return nil }
        let text = String(line[line.index(after: separatorIndex)...])
        return ParsedLine(code: code, text: text, isContinuation: separator == "-")
    }
}
