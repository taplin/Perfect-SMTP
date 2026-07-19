//
//  DeliveryResult.swift
//  PerfectSMTPCore
//
//  Pure data model, no NIO — see plan §4.8. The retry queue that actually
//  schedules `.queuedForRetry`/computes `.expired` is Phase 1/3; this type
//  only carries the per-recipient outcome shape.
//

import Foundation

public struct DeliveryResult: Sendable {
    public let recipient: String
    public let outcome: Outcome

    public init(recipient: String, outcome: Outcome) {
        self.recipient = recipient
        self.outcome = outcome
    }

    public enum Outcome: Sendable {
        case delivered(SMTPReply)
        case queuedForRetry(nextAttempt: Date, attempt: Int, last: SMTPReply)
        case permanentlyFailed(SMTPReply)
        /// Retry ceiling reached (configurable expiry / max-attempt cap,
        /// enforced by Phase 1/3's retry queue) — distinct from
        /// `.permanentlyFailed` so callers can distinguish "the
        /// destination actively rejected this" (5yz) from "we gave up
        /// retrying a destination that kept saying try-again-later".
        case expired(attempts: Int, last: SMTPReply)
        /// Failure occurred after `354`/DATA but before `250` — the point
        /// of no return. Surfaced, never auto-retried (default policy:
        /// at-most-once) — a retry here risks double delivery.
        case ambiguous(SMTPReply?)
        /// A transport-level or pre-flight failure with no `SMTPReply` to
        /// attach at all — a connection/timeout error, a DKIM/compose
        /// failure, a circuit-breaker rejection, or any other thrown error
        /// that isn't a classified SMTP-protocol reply. Added for FIX #5
        /// (milestone architecture/concurrency review): `SMTPMailer`'s
        /// batch `send([EmailMessage], envelopeFrom:)` maps a single
        /// message's thrown failure to this case (one per that message's
        /// would-be recipients) instead of letting the throw cancel and
        /// discard every other in-flight/pending message in the batch —
        /// same shape as `SMTPError.connectionFailed(any Error &
        /// Sendable)`'s existing precedent for carrying an opaque
        /// underlying error.
        case failed(any Error & Sendable)
    }
}
