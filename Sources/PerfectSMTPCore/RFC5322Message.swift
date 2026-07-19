//
//  RFC5322Message.swift
//  PerfectSMTPCore
//
//  The output of `MIMEComposer.compose()` and the input/output of
//  `DKIMSigner.sign(_:)` (Phase 2). Signing is the last transformation
//  before the message is frozen into a transport's `SignedMessage` —
//  nothing downstream re-encodes (plan §4.6).
//

/// A composed, not-yet-signed RFC 5322 message: an ordered list of
/// top-level headers, plus a body (which, for a multipart message, already
/// contains the fully-serialized nested MIME structure with its own
/// boundaries — see `MIMEComposer`).
public struct RFC5322Message: Sendable {
    /// Ordered `(name, value)` pairs, emitted exactly in this order.
    /// Order matters for DKIM canonicalization (Phase 2) and is otherwise
    /// preserved as a courtesy to receivers that read top-to-bottom.
    public var headers: [(name: String, value: String)]
    /// Logical body bytes — CRLF line endings, MIME boundaries already
    /// applied where relevant. NOT yet dot-stuffed; that's a wire-transport
    /// concern applied by the transport's DATA writer (see `DotStuffing`).
    public var body: [UInt8]

    public init(headers: [(name: String, value: String)], body: [UInt8]) {
        self.headers = headers
        self.body = body
    }

    /// Serializes headers + CRLFCRLF + body into the full logical message.
    public func serialized() -> [UInt8] {
        var out = [UInt8]()
        for (name, value) in headers {
            out.append(contentsOf: Array("\(name): \(value)\r\n".utf8))
        }
        out.append(contentsOf: Array("\r\n".utf8))
        out.append(contentsOf: body)
        return out
    }
}
