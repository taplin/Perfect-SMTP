//
//  SMTPCommand.swift
//  PerfectSMTP
//
//  The `Outbound` type of `NIOAsyncChannel<SMTPReply, SMTPCommand>` (plan
//  §4.3, Phase B). `SMTPCommandEncoder` turns these into wire bytes; nothing
//  upstream of it needs to know the wire format.
//

import NIOCore

/// One outbound unit written to the SMTP connection: either a single
/// command line (CRLF appended by the encoder) or pre-formatted raw bytes
/// — used exclusively for the DOT-stuffed DATA payload, which must be
/// written as-is with no additional framing.
public enum SMTPCommand: Sendable, Equatable {
    case line(String)
    case raw([UInt8])

    var estimatedByteCount: Int {
        switch self {
        case .line(let line): return line.utf8.count + 2
        case .raw(let bytes): return bytes.count
        }
    }

    func encode(into buffer: inout ByteBuffer) {
        switch self {
        case .line(let line):
            buffer.writeString(line)
            buffer.writeString("\r\n")
        case .raw(let bytes):
            buffer.writeBytes(bytes)
        }
    }
}

/// Encodes `SMTPCommand` values into wire bytes. Outbound-only — inbound
/// events pass through untouched, so its position in the pipeline relative
/// to `SMTPResponseDecoder` doesn't matter functionally.
public final class SMTPCommandEncoder: ChannelOutboundHandler, Sendable {
    public typealias OutboundIn = SMTPCommand
    public typealias OutboundOut = ByteBuffer

    public init() {}

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let command = Self.unwrapOutboundIn(data)
        var buffer = context.channel.allocator.buffer(capacity: command.estimatedByteCount)
        command.encode(into: &buffer)
        context.write(Self.wrapOutboundOut(buffer), promise: promise)
    }
}
