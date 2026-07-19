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
    }
}
