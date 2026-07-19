//
//  SMTPTransport.swift
//  PerfectSMTP
//
//  The `Transport` abstraction (plan §4.2). `SMTPMailer` is generic over
//  `any SMTPTransport`; `RelayTransport` and `LocalMTATransport` (both
//  Phase 1) are the two conforming strategies that ship in this phase —
//  `DirectMXTransport` is Phase 3.
//

/// A pluggable message-delivery strategy. The message bytes are
/// transmitted verbatim (modulo wire-level dot-stuffing, which is
/// signature-preserving — plan §4.6): a transport MUST NOT add, reorder,
/// or re-encode headers or body.
public protocol SMTPTransport: Sendable {
    func send(_ envelope: SMTPEnvelope, _ message: SignedMessage) async throws -> [DeliveryResult]
}

/// A composed, signed (or deliberately unsigned, when no `MessageSigner`
/// was configured) message frozen for transport. `rfc5322` is headers +
/// CRLFCRLF + body, with any `DKIM-Signature` header already prepended by
/// the signing step — nothing downstream re-encodes.
public struct SignedMessage: Sendable {
    public let rfc5322: [UInt8]
    public let estimatedSize: Int

    public init(rfc5322: [UInt8], estimatedSize: Int? = nil) {
        self.rfc5322 = rfc5322
        self.estimatedSize = estimatedSize ?? rfc5322.count
    }
}
