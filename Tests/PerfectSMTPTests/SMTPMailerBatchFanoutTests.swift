//
//  SMTPMailerBatchFanoutTests.swift
//  PerfectSMTPTests
//
//  Plan §4.9/§5: bounded batch fan-out -- a batch large enough (200+
//  messages) against a small in-flight task cap, asserting the number of
//  concurrently in-flight sends never exceeds the configured cap. Tracked
//  via a counter incremented/decremented around a simulated send, proving
//  the sliding-window task-group pattern (prime N, add one as one
//  completes) rather than a naive `for msg in messages { group.addTask }`
//  that launches every child eagerly.
//

import Testing
@testable import PerfectSMTP

struct SMTPMailerBatchFanoutTests {

    @Test func inFlightSendsNeverExceedConfiguredCap() async throws {
        let cap = 8
        let tracker = InFlightTracker()
        let transport = CountingTransport(tracker: tracker)
        let mailer = SMTPMailer(transport: transport, configuration: .init(maxInFlightBatchSends: cap))

        let messages = (0..<250).map { i -> EmailMessage in
            var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
            message.to = [EmailAddress(address: "user\(i)@example.com")]
            message.textBody = "hello \(i)"
            return message
        }

        let results = await mailer.send(messages, envelopeFrom: .address("bounce@example.com"))

        #expect(results.count == 250)
        #expect(await tracker.maxObserved <= cap)
        #expect(await tracker.maxObserved > 0) // sanity: fan-out actually happened concurrently
        #expect(await tracker.totalSends == 250)
    }

    // MARK: - FIX #5: a single message's transport-level throw must not
    // cancel/discard the rest of the batch.

    @Test func middleMessageTransportFailureDoesNotDiscardTheOtherMessagesResults() async throws {
        // A transport that throws (a connection-level failure, not a
        // per-recipient rejection) for exactly one message in the batch --
        // identified by its sole recipient's address -- and succeeds
        // normally for every other message. Before FIX #5, `send`'s use of
        // `withThrowingTaskGroup` meant this single throw would cancel
        // every other in-flight/pending child and propagate out of the
        // whole call, discarding the two good messages' results entirely.
        let transport = SelectivelyFailingTransport(failingRecipient: "bad@example.com")
        let mailer = SMTPMailer(transport: transport, configuration: .init(maxInFlightBatchSends: 8))

        func message(_ recipient: String) -> EmailMessage {
            var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
            message.to = [EmailAddress(address: recipient)]
            message.textBody = "hello"
            return message
        }

        let messages = [
            message("good1@example.com"),
            message("bad@example.com"),
            message("good2@example.com"),
        ]

        let results = await mailer.send(messages, envelopeFrom: .address("bounce@example.com"))

        // All three messages are represented -- the middle failure didn't
        // erase the other two.
        #expect(results.count == 3)

        let good1 = results.first { $0.recipient == "good1@example.com" }
        let good2 = results.first { $0.recipient == "good2@example.com" }
        let bad = results.first { $0.recipient == "bad@example.com" }

        guard let good1, case .delivered = good1.outcome else {
            Issue.record("expected good1@example.com delivered, got \(String(describing: good1?.outcome))")
            return
        }
        guard let good2, case .delivered = good2.outcome else {
            Issue.record("expected good2@example.com delivered, got \(String(describing: good2?.outcome))")
            return
        }
        guard let bad, case .failed = bad.outcome else {
            Issue.record("expected bad@example.com to surface as .failed, got \(String(describing: bad?.outcome))")
            return
        }
    }
}

/// A `SMTPTransport` that throws a plain transport-level error (not a
/// per-recipient `DeliveryResult` rejection) whenever the envelope's
/// recipients include `failingRecipient`, and otherwise succeeds normally
/// -- used to simulate a connection/envelope-level failure for exactly one
/// message in a batch (FIX #5's regression scenario).
private struct SelectivelyFailingTransport: SMTPTransport {
    struct SimulatedTransportFailure: Error, Sendable {}

    let failingRecipient: String

    func send(_ envelope: SMTPEnvelope, _ message: SignedMessage) async throws -> [DeliveryResult] {
        guard !envelope.recipients.contains(failingRecipient) else {
            throw SimulatedTransportFailure()
        }
        return envelope.recipients.map {
            DeliveryResult(recipient: $0, outcome: .delivered(SMTPReply(code: 250, lines: ["OK"])))
        }
    }
}

private actor InFlightTracker {
    private(set) var current = 0
    private(set) var maxObserved = 0
    private(set) var totalSends = 0

    func enter() {
        current += 1
        maxObserved = max(maxObserved, current)
        totalSends += 1
    }

    func exit() {
        current -= 1
    }
}

/// A `SMTPTransport` that simulates network latency (a short sleep) around
/// a counter increment/decrement, so the fan-out's actual concurrency is
/// observable without a real connection pool or socket.
private struct CountingTransport: SMTPTransport {
    let tracker: InFlightTracker

    func send(_ envelope: SMTPEnvelope, _ message: SignedMessage) async throws -> [DeliveryResult] {
        await tracker.enter()
        do {
            try await Task.sleep(nanoseconds: UInt64(5) * 1_000_000)
        } catch {
            await tracker.exit()
            throw error
        }
        await tracker.exit()
        return envelope.recipients.map {
            DeliveryResult(recipient: $0, outcome: .delivered(SMTPReply(code: 250, lines: ["OK"])))
        }
    }
}
