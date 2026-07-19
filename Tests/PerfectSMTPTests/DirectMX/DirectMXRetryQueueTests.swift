//
//  DirectMXRetryQueueTests.swift
//  PerfectSMTPTests
//
//  Plan §4.8 / this task's required coverage list: 421 vs. 450/451/452 get
//  different, actually-configured backoff durations; an entry retried past
//  the max-attempt cap or max-age becomes `.expired`, not stuck retrying
//  forever or silently dropped; `shutdown()` cancels the background loop
//  cleanly (no hang, no crash) -- mirroring `SMTPConnectionPoolTests`'
//  pattern for testing pool shutdown from Phase 1.
//

import Foundation
import Testing
@testable import PerfectSMTP

struct DirectMXRetryQueueTests {
    // MARK: - 421 vs. greylist vs. other 4yz backoff durations

    @Test func classifyAppliesTheExactConfiguredBackoffPerReplyClass() {
        let policy = RetryBackoffPolicy(
            serviceUnavailable: .seconds(111),
            greylist: .seconds(22),
            defaultTransient: .seconds(3)
        )
        let reply421 = SMTPReply(code: 421, lines: ["4.3.2 Service unavailable, closing channel"])
        let reply450 = SMTPReply(code: 450, lines: ["4.2.0 Greylisted, try again later"])
        let reply451 = SMTPReply(code: 451, lines: ["4.3.0 Local error"])
        let reply452 = SMTPReply(code: 452, lines: ["4.2.2 Mailbox full"])
        let reply441 = SMTPReply(code: 441, lines: ["4.4.1 Some other transient condition"])

        let before = Date()
        let outcome421 = policy.classify(reply421, attempt: 1)
        let outcome450 = policy.classify(reply450, attempt: 1)
        let outcome451 = policy.classify(reply451, attempt: 1)
        let outcome452 = policy.classify(reply452, attempt: 1)
        let outcome441 = policy.classify(reply441, attempt: 1)

        #expect(isApproximately(backoffSeconds(outcome421, since: before), 111))
        #expect(isApproximately(backoffSeconds(outcome450, since: before), 22))
        #expect(isApproximately(backoffSeconds(outcome451, since: before), 22))
        #expect(isApproximately(backoffSeconds(outcome452, since: before), 22))
        #expect(isApproximately(backoffSeconds(outcome441, since: before), 3))

        // Explicitly not just "these differ" -- 421 must be the *longest*
        // backoff (plan §4.8's 421-vs-greylist correction: retrying an
        // overloaded receiver quickly worsens the overload).
        #expect(backoffSeconds(outcome421, since: before) > backoffSeconds(outcome450, since: before))
        #expect(backoffSeconds(outcome450, since: before) > backoffSeconds(outcome441, since: before))
    }

    @Test func aPermanentReplyIsNeverBackedOffEvenWithAConfiguredPolicy() {
        let policy = RetryBackoffPolicy(serviceUnavailable: .seconds(999), greylist: .seconds(999), defaultTransient: .seconds(999))
        let reply550 = SMTPReply(code: 550, lines: ["5.1.1 User unknown"])
        guard case .permanentlyFailed = policy.classify(reply550, attempt: 1) else {
            Issue.record("expected .permanentlyFailed for a 5yz reply regardless of policy")
            return
        }
    }

    // MARK: - Retry ceiling: max attempts

    @Test func exceedingMaxAttemptsBecomesExpiredNotStuckForever() async throws {
        let collector = OutcomeCollector()
        let config = DirectMXRetryQueue.Configuration(
            backoff: .init(serviceUnavailable: .milliseconds(5), greylist: .milliseconds(5), defaultTransient: .milliseconds(5)),
            maxAttempts: 2,
            maxAge: .seconds(3600) // effectively disabled for this test -- only the attempt cap should trigger
        )
        // Always comes back greylisted -- a destination that never
        // recovers, the exact scenario the attempt cap exists for.
        let redeliverCalls = CallCountBox()
        let queue = DirectMXRetryQueue(
            configuration: config,
            redeliver: { envelope, _ in
                await redeliverCalls.increment()
                let reply = SMTPReply(code: 450, lines: ["4.2.0 still greylisted"])
                // The `attempt` value returned here is deliberately wrong
                // (always 1) -- exactly like every real classification
                // site in this codebase (`SMTPConnection.outcomeFor`,
                // `DirectMXTransport.classify(smtpError:)`), none of which
                // have any memory of retry history. This is precisely what
                // `DirectMXRetryQueue.handle(results:entry:)` must not
                // trust -- it tracks the real attempt count itself.
                return envelope.recipients.map { DeliveryResult(recipient: $0, outcome: config.classify(reply, attempt: 1)) }
            },
            onTerminalOutcome: { result in await collector.record(result) }
        )

        let firstReply = SMTPReply(code: 450, lines: ["4.2.0 greylisted"])
        await queue.enqueue(
            recipients: ["r@example.com"], mailFrom: .address("f@example.com"), message: DirectMXRetryQueueTests.message(),
            outcome: .queuedForRetry(nextAttempt: Date(), attempt: 1, last: firstReply)
        )

        let terminal = try await collector.waitForFirst()
        guard case .expired(let attempts, _) = terminal.outcome else {
            Issue.record("expected .expired once the attempt cap is exceeded, got \(terminal.outcome)")
            return
        }
        #expect(attempts > config.maxAttempts)
        // The entry must actually have been retried -- not dropped after
        // the very first failure.
        #expect(await redeliverCalls.count >= 1)

        await queue.shutdown()
    }

    // MARK: - Retry ceiling: max age

    @Test func exceedingMaxAgeBecomesExpiredEvenWithAttemptsRemaining() async throws {
        let collector = OutcomeCollector()
        let config = DirectMXRetryQueue.Configuration(
            backoff: .init(serviceUnavailable: .milliseconds(5), greylist: .milliseconds(5), defaultTransient: .milliseconds(5)),
            maxAttempts: 1000, // effectively disabled -- only maxAge should trigger
            maxAge: .milliseconds(30)
        )
        let queue = DirectMXRetryQueue(
            configuration: config,
            redeliver: { envelope, _ in
                let reply = SMTPReply(code: 450, lines: ["4.2.0 still greylisted"])
                return envelope.recipients.map { DeliveryResult(recipient: $0, outcome: config.classify(reply, attempt: 1)) }
            },
            onTerminalOutcome: { result in await collector.record(result) }
        )

        let firstReply = SMTPReply(code: 450, lines: ["4.2.0 greylisted"])
        await queue.enqueue(
            recipients: ["r@example.com"], mailFrom: .address("f@example.com"), message: DirectMXRetryQueueTests.message(),
            outcome: .queuedForRetry(nextAttempt: Date(), attempt: 1, last: firstReply)
        )

        let terminal = try await collector.waitForFirst(timeoutSeconds: 3)
        guard case .expired = terminal.outcome else {
            Issue.record("expected .expired once maxAge elapses, got \(terminal.outcome)")
            return
        }

        await queue.shutdown()
    }

    // MARK: - `.ambiguous` (and every other non-`.queuedForRetry` outcome) is never enqueued

    @Test func enqueueIsANoOpForEveryNonQueuedForRetryOutcome() async throws {
        let queue = DirectMXRetryQueue(configuration: .init(), redeliver: { envelope, _ in
            envelope.recipients.map { DeliveryResult(recipient: $0, outcome: .delivered(SMTPReply(code: 250, lines: ["OK"]))) }
        })
        let reply = SMTPReply(code: 550, lines: ["5.1.1 rejected"])
        let message = DirectMXRetryQueueTests.message()

        let ambiguousAccepted = await queue.enqueue(recipients: ["a@example.com"], mailFrom: .address("f@example.com"), message: message, outcome: .ambiguous(nil))
        let deliveredAccepted = await queue.enqueue(recipients: ["b@example.com"], mailFrom: .address("f@example.com"), message: message, outcome: .delivered(reply))
        let permanentAccepted = await queue.enqueue(recipients: ["c@example.com"], mailFrom: .address("f@example.com"), message: message, outcome: .permanentlyFailed(reply))
        let expiredAccepted = await queue.enqueue(recipients: ["d@example.com"], mailFrom: .address("f@example.com"), message: message, outcome: .expired(attempts: 5, last: reply))

        #expect(!ambiguousAccepted)
        #expect(!deliveredAccepted)
        #expect(!permanentAccepted)
        #expect(!expiredAccepted)
        #expect(await queue.pendingEntriesSnapshot().isEmpty)

        await queue.shutdown()
    }

    // MARK: - Lifecycle: shutdown cancels the background loop cleanly

    @Test func shutdownCancelsTheBackgroundLoopCleanlyAndReportsStillPendingEntries() async throws {
        let collector = OutcomeCollector()
        let redeliverCalls = CallCountBox()
        let queue = DirectMXRetryQueue(
            configuration: .init(backoff: .init(serviceUnavailable: .seconds(3600), greylist: .seconds(3600), defaultTransient: .seconds(3600))),
            redeliver: { envelope, _ in
                await redeliverCalls.increment()
                return envelope.recipients.map { DeliveryResult(recipient: $0, outcome: .delivered(SMTPReply(code: 250, lines: ["OK"]))) }
            },
            onTerminalOutcome: { result in await collector.record(result) }
        )

        // Scheduled far in the future -- guaranteed to still be pending
        // (never redelivered) when `shutdown()` runs below.
        let reply = SMTPReply(code: 450, lines: ["4.2.0 greylisted"])
        await queue.enqueue(
            recipients: ["stuck@example.com"], mailFrom: .address("f@example.com"), message: DirectMXRetryQueueTests.message(),
            outcome: .queuedForRetry(nextAttempt: Date().addingTimeInterval(3600), attempt: 1, last: reply)
        )
        #expect(await queue.pendingEntriesSnapshot().count == 1)

        // `shutdown()` itself must return promptly -- no hang -- and must
        // not crash regardless of whether the background loop happened to
        // be asleep (the common case here) or mid-iteration.
        await queue.shutdown()

        // Never redelivered -- the loop was genuinely cancelled, not
        // allowed to fire once more before stopping.
        #expect(await redeliverCalls.count == 0)

        // The still-pending entry is reported as terminal (`.failed`,
        // wrapping `DirectMXRetryQueueError.shutdownWhilePending`) rather
        // than silently discarded -- this queue's documented shutdown
        // decision (see `DirectMXRetryQueue.shutdown()`'s doc comment).
        let terminal = try await collector.waitForFirst()
        #expect(terminal.recipient == "stuck@example.com")
        guard case .failed(let error) = terminal.outcome, let queueError = error as? DirectMXRetryQueueError,
              case .shutdownWhilePending = queueError
        else {
            Issue.record("expected .failed(.shutdownWhilePending), got \(terminal.outcome)")
            return
        }

        // A second `shutdown()` call must not hang or crash either.
        await queue.shutdown()
        // Calling `enqueue` after shutdown is a documented no-op, not a crash.
        let acceptedAfterShutdown = await queue.enqueue(
            recipients: ["late@example.com"], mailFrom: .address("f@example.com"), message: DirectMXRetryQueueTests.message(),
            outcome: .queuedForRetry(nextAttempt: Date(), attempt: 1, last: reply)
        )
        #expect(!acceptedAfterShutdown)
    }

    // MARK: - Happy path: a rescheduled entry that eventually succeeds is reported `.delivered`

    @Test func aRescheduledEntryThatEventuallySucceedsReportsDelivered() async throws {
        let collector = OutcomeCollector()
        let attemptsSoFar = CallCountBox()
        let config = DirectMXRetryQueue.Configuration(
            backoff: .init(serviceUnavailable: .milliseconds(5), greylist: .milliseconds(5), defaultTransient: .milliseconds(5)),
            maxAttempts: 10, maxAge: .seconds(3600)
        )
        let queue = DirectMXRetryQueue(
            configuration: config,
            redeliver: { envelope, _ in
                await attemptsSoFar.increment()
                let n = await attemptsSoFar.count
                if n < 2 {
                    let reply = SMTPReply(code: 450, lines: ["4.2.0 greylisted"])
                    return envelope.recipients.map { DeliveryResult(recipient: $0, outcome: config.classify(reply, attempt: 1)) }
                }
                return envelope.recipients.map { DeliveryResult(recipient: $0, outcome: .delivered(SMTPReply(code: 250, lines: ["OK"]))) }
            },
            onTerminalOutcome: { result in await collector.record(result) }
        )

        let firstReply = SMTPReply(code: 450, lines: ["4.2.0 greylisted"])
        await queue.enqueue(
            recipients: ["r@example.com"], mailFrom: .address("f@example.com"), message: DirectMXRetryQueueTests.message(),
            outcome: .queuedForRetry(nextAttempt: Date(), attempt: 1, last: firstReply)
        )

        let terminal = try await collector.waitForFirst()
        guard case .delivered = terminal.outcome else {
            Issue.record("expected .delivered once the destination recovers, got \(terminal.outcome)")
            return
        }
        #expect(await attemptsSoFar.count == 2)

        await queue.shutdown()
    }

    private static func message() -> SignedMessage {
        SignedMessage(rfc5322: Array("Subject: hi\r\n\r\nbody".utf8))
    }
}

private func isApproximately(_ lhs: Double, _ rhs: Double) -> Bool { abs(lhs - rhs) < 1.0 }

private func backoffSeconds(_ outcome: DeliveryResult.Outcome, since: Date) -> Double {
    guard case .queuedForRetry(let nextAttempt, _, _) = outcome else {
        Issue.record("expected .queuedForRetry, got \(outcome)")
        return -1
    }
    return nextAttempt.timeIntervalSince(since)
}

/// Collects every `DeliveryResult` reported via a `DirectMXRetryQueue`'s
/// `onTerminalOutcome` callback, and lets a test await the first one
/// (bounded, polling) without a fixed `Task.sleep` guess.
actor OutcomeCollector {
    private var results: [DeliveryResult] = []
    private var waiters: [CheckedContinuation<DeliveryResult, Error>] = []

    func record(_ result: DeliveryResult) {
        if let waiter = waiters.first {
            waiters.removeFirst()
            waiter.resume(returning: result)
        } else {
            results.append(result)
        }
    }

    /// Bounded wait for the first recorded outcome -- resumes immediately
    /// if one is already recorded, otherwise parks until `record(_:)`
    /// delivers one or `timeoutSeconds` elapses.
    func waitForFirst(timeoutSeconds: Double = 2) async throws -> DeliveryResult {
        if !results.isEmpty { return results.removeFirst() }
        return try await withThrowingTaskGroup(of: DeliveryResult.self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<DeliveryResult, Error>) in
                    Task { await self.park(continuation) }
                }
            }
            group.addTask {
                try await Task.sleep(for: .seconds(timeoutSeconds))
                throw OutcomeCollectorError.timedOut
            }
            defer { group.cancelAll() }
            guard let result = try await group.next() else { throw OutcomeCollectorError.timedOut }
            return result
        }
    }

    private func park(_ continuation: CheckedContinuation<DeliveryResult, Error>) {
        if !results.isEmpty {
            continuation.resume(returning: results.removeFirst())
        } else {
            waiters.append(continuation)
        }
    }
}

private enum OutcomeCollectorError: Error {
    case timedOut
}
