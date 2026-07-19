//
//  MessageSigner.swift
//  PerfectSMTPCore
//
//  The Phase 2 `DKIMSigner` doesn't exist yet (see
//  Documentation/swift6-nio-rewrite-plan.md §4.6/§9's Phase 2). This
//  protocol is the seam Phase 1's `SMTPMailer` (Sources/PerfectSMTP/SMTPMailer.swift)
//  is built against instead of the concrete signer type, so Phase 1 ships a
//  fully working mailer with no DKIM step at all (`signer: nil`), and Phase 2
//  can introduce `DKIMSigner: MessageSigner` later with zero public-API
//  breakage on `SMTPMailer`.
//
//  Deliberately defined here in `PerfectSMTPCore` (not `PerfectSMTP`): both
//  the composer (`MIMEComposer`, no-NIO) and the eventual signer live in the
//  no-NIO core per §4.1's compile-time boundary ("MIME composition and DKIM
//  signing are transport-agnostic and must not be able to reach into a live
//  channel"), so the signing seam belongs here too, not in the NIO-dependent
//  target.
//

/// Transforms a composed-but-unsigned `RFC5322Message` into a signed one —
/// conformed to by Phase 2's `DKIMSigner`. `sign(_:)` is the last
/// transformation before the message is frozen into a transport's
/// `SignedMessage` (plan §4.6) — nothing downstream re-encodes.
public protocol MessageSigner: Sendable {
    func sign(_ message: RFC5322Message) throws -> RFC5322Message
}
