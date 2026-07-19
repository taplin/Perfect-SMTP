//
//  DNSTCPFrameDecoder.swift
//  PerfectSMTP
//
//  RFC 1035 §4.2.2: a DNS message sent over TCP is prefixed with its own
//  2-byte big-endian length. This decoder strips that framing and emits one
//  `ByteBuffer` per complete DNS message -- `DNSMessage.decode(_:)` (which
//  knows nothing about TCP framing) is then applied to that buffer's bytes,
//  exactly as it is for a UDP datagram's payload. Mirrors
//  `SMTPResponseDecoder`'s existing convention in this codebase of
//  hand-rolling a small `ByteToMessageDecoder` for wire framing rather than
//  reaching for `swift-nio-extras`' `LengthFieldBasedFrameDecoder` (the plan
//  §4.1 already excludes that dependency package-wide).
//

import NIOCore

final class DNSTCPFrameDecoder: ByteToMessageDecoder, Sendable {
    typealias InboundOut = ByteBuffer

    /// RFC 1035 §4.2.2's length prefix is itself a `UInt16`, so a DNS
    /// message can never exceed 65535 bytes -- this is already the maximum
    /// any well-formed length prefix can encode, not an additional cap this
    /// decoder imposes. `ByteToMessageHandler`'s own `maximumBufferSize`
    /// (set by the caller when constructing it, matching
    /// `SMTPBootstrap.maximumReplyBufferSize`'s precedent) is what actually
    /// bounds unbounded accumulation from a peer that never sends a
    /// complete frame.
    func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        guard let length = buffer.getInteger(at: buffer.readerIndex, as: UInt16.self) else {
            return .needMoreData
        }
        guard buffer.readableBytes >= 2 + Int(length) else { return .needMoreData }
        buffer.moveReaderIndex(forwardBy: 2)
        guard let message = buffer.readSlice(length: Int(length)) else { return .needMoreData }
        context.fireChannelRead(Self.wrapInboundOut(message))
        return .continue
    }

    func decodeLast(context: ChannelHandlerContext, buffer: inout ByteBuffer, seenEOF: Bool) throws -> DecodingState {
        while try decode(context: context, buffer: &buffer) == .continue {}
        return .needMoreData
    }
}
