//
//  RetryBackoffPolicy.swift
//  PerfectSMTPCore
//
//  Pure data + a pure classification function, no NIO -- see plan §4.8.
//
//  Phase 1's `SMTPConnection.outcomeFor` (`Sources/PerfectSMTP/SMTPConnection.swift`)
//  originally hardcoded three backoff durations (900s/300s/120s) directly
//  into its own body, with a doc comment explicitly flagging them as
//  "placeholders populating `DeliveryResult`'s existing
//  `.queuedForRetry(nextAttempt:...)` shape correctly... even though
//  nothing in Phase 1 acts on it yet," deferring making them real to Phase
//  3. This type is that: a small, `Sendable`, transport-agnostic policy
//  carrying the same three durations (same default values, so every
//  existing Phase 1 call site's behavior is unchanged unless it opts in to
//  a different policy), plus the mechanical reply -> outcome classification
//  itself, factored out so both `SMTPConnection` (Phase 1, RCPT/DATA-phase
//  rejections) and `DirectMXRetryQueue` (Phase 3, MAIL-FROM-phase
//  rejections and every rescheduled retry) apply the *same* configured
//  policy rather than two independently-hardcoded copies of it.
//

import Foundation

/// The 421-vs-greylist-vs-other-4yz backoff policy (plan §4.8's corrected
/// distinction). Every `SMTPConnection` and `DirectMXRetryQueue` in this
/// package defaults to the exact same values Phase 1 originally hardcoded,
/// so adopting this type changes nothing for an existing caller who doesn't
/// explicitly configure a different policy.
public struct RetryBackoffPolicy: Sendable {
    /// Backoff after a `421` (RFC 5321 §3.8/§4.2.1: "service unavailable,
    /// closing the channel" -- typically overload/rate-limit). Deliberately
    /// longer than `greylist` -- retrying an overloaded receiver quickly is
    /// exactly the aggressive-reconnection behavior that makes the
    /// overload worse (plan §4.8's 421-vs-greylist correction).
    public var serviceUnavailable: Duration
    /// Backoff after a first-contact greylist response (`450`/`451`/`452`)
    /// -- a normal, expected pattern from many receivers, not a failure
    /// signal.
    public var greylist: Duration
    /// Backoff for any other `4yz` not covered above.
    public var defaultTransient: Duration

    public init(
        serviceUnavailable: Duration = .seconds(900),
        greylist: Duration = .seconds(300),
        defaultTransient: Duration = .seconds(120)
    ) {
        self.serviceUnavailable = serviceUnavailable
        self.greylist = greylist
        self.defaultTransient = defaultTransient
    }

    /// Mechanically classifies a reply into a `DeliveryResult.Outcome`,
    /// exactly like `SMTPError.classify(_:)` classifies it into a
    /// `SMTPError` case -- `.permanentlyFailed` for `5yz`,
    /// `.queuedForRetry` with this policy's matching backoff for anything
    /// else. Callers that have already classified a reply as a rejection
    /// (this codebase never calls this for a `2yz`/`3yz` reply) get a
    /// correctly-backed-off retry hint either way.
    public func classify(_ reply: SMTPReply, attempt: Int) -> DeliveryResult.Outcome {
        guard reply.replyClass != .permanentNegative else { return .permanentlyFailed(reply) }
        let backoff: Duration
        switch SMTPError.classify(reply) {
        case .serviceUnavailable: backoff = serviceUnavailable
        case .greylisted: backoff = greylist
        default: backoff = defaultTransient
        }
        return .queuedForRetry(nextAttempt: Date().addingTimeInterval(backoff.timeIntervalValue), attempt: attempt, last: reply)
    }
}

extension Duration {
    /// `Duration` has no built-in conversion back to `Foundation.TimeInterval`
    /// (only the reverse, via `.seconds(Double)`) -- used to compute
    /// `Date.addingTimeInterval`-compatible offsets from a configured
    /// backoff `Duration`.
    public var timeIntervalValue: TimeInterval {
        let c = components
        return TimeInterval(c.seconds) + TimeInterval(c.attoseconds) / 1e18
    }
}
