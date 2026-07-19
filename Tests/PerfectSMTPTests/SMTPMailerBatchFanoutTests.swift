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

        let results = try await mailer.send(messages, envelopeFrom: .address("bounce@example.com"))

        #expect(results.count == 250)
        #expect(await tracker.maxObserved <= cap)
        #expect(await tracker.maxObserved > 0) // sanity: fan-out actually happened concurrently
        #expect(await tracker.totalSends == 250)
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
            try await Task.sleep(for: .milliseconds(5))
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
