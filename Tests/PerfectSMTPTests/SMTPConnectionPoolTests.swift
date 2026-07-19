//
//  SMTPConnectionPoolTests.swift
//  PerfectSMTPTests
//
//  Plan §4.4/§5: cancellation (a `Task` cancelled while parked waiting for
//  a connection slot resolves with `CancellationError`, removed from the
//  waiter queue, no double-resume against a concurrent `release()`) and
//  reentrancy (concurrent checkouts under `maxPerHost` don't overshoot the
//  cap).
//

import Foundation
import NIOCore
import NIOEmbedded
import NIOPosix
import Testing
@testable import PerfectSMTP

struct SMTPConnectionPoolTests {
    private let key = SMTPConnectionPool.Key(host: "smtp.example.com", port: 587, tls: .none)

    /// Builds a pool with an injectable dialer that never touches a real
    /// socket: each dial creates a lightweight in-memory `SMTPConnection`
    /// backed by its own `NIOAsyncTestingChannel`, after an artificial
    /// delay/gate the test controls.
    private func makePool(
        maxPerHost: Int,
        onDial: @escaping @Sendable () async -> Void = {}
    ) -> SMTPConnectionPool {
        SMTPConnectionPool(
            configuration: .init(maxPerHost: maxPerHost, maxTotal: 100),
            group: NIOAsyncTestingEventLoop(),
            dialer: { _ in
                await onDial()
                let (connection, _) = try await ConnectionHarness.make()
                return connection
            }
        )
    }

    @Test func reentrantCheckoutsDoNotOvershootMaxPerHost() async throws {
        let dialGate = DialGate()
        let pool = makePool(maxPerHost: 1) {
            await dialGate.recordDialStartAndWaitForRelease()
        }

        // Race two checkouts against a pool capped at 1 connection for
        // this host. Reentrancy discipline (plan §4.4) requires the
        // capacity check + reservation to happen synchronously, before the
        // first `await`, in the same actor activation -- so only one
        // dial should ever be in flight at a time.
        async let first: Void = pool.withConnection(to: key) { _ in
            try await Task.sleep(for: .milliseconds(50))
        }
        async let second: Void = pool.withConnection(to: key) { _ in
            try await Task.sleep(for: .milliseconds(50))
        }

        // Give both tasks a chance to reach `checkout`.
        try await Task.sleep(for: .milliseconds(20))
        #expect(await dialGate.concurrentDialCount <= 1)
        await dialGate.release()

        _ = try await (first, second)
        #expect(await dialGate.maxObservedConcurrentDials == 1)

        await pool.shutdown()
    }

    @Test func cancelledWaiterResolvesWithCancellationErrorAndIsRemovedFromQueue() async throws {
        let releaseGate = ManualGate()
        let pool = makePool(maxPerHost: 1)

        // Occupy the only slot for a controlled duration.
        let holderTask = Task {
            try await pool.withConnection(to: key) { _ in
                await releaseGate.wait()
            }
        }
        try await Task.sleep(for: .milliseconds(20)) // let the holder actually check out

        // Park a second checkout as a waiter, then cancel it before the
        // slot ever frees up.
        let waiterTask = Task {
            try await pool.withConnection(to: key) { _ in () }
        }
        try await Task.sleep(for: .milliseconds(20)) // let it park as a waiter
        waiterTask.cancel()

        let waiterResult = await waiterTask.result
        guard case .failure(let error) = waiterResult, error is CancellationError else {
            Issue.record("expected CancellationError, got \(waiterResult)")
            await releaseGate.open()
            _ = await holderTask.result
            return
        }

        // Now free the slot. A third checkout must succeed promptly --
        // proving the cancelled waiter was actually removed from the
        // queue (not left parked forever, and not double-resumed when the
        // holder's release() runs next).
        await releaseGate.open()
        _ = await holderTask.result

        try await pool.withConnection(to: key) { _ in () }
        await pool.shutdown()
    }
}

/// Gates a controlled number of concurrent "dial" calls so the reentrancy
/// test can assert on how many were ever in flight simultaneously, and
/// release them all at once on command. `@unchecked Sendable`: all access
/// is behind the actor.
private actor DialGate {
    private(set) var concurrentDialCount = 0
    private(set) var maxObservedConcurrentDials = 0
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var released = false

    func recordDialStartAndWaitForRelease() async {
        concurrentDialCount += 1
        maxObservedConcurrentDials = max(maxObservedConcurrentDials, concurrentDialCount)
        if released {
            concurrentDialCount -= 1
            return
        }
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            waiters.append(continuation)
        }
        concurrentDialCount -= 1
    }

    func release() {
        released = true
        for waiter in waiters { waiter.resume() }
        waiters.removeAll()
    }
}

/// A simple open-once gate for coordinating test task ordering.
private actor ManualGate {
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        if isOpen { return }
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            waiters.append(continuation)
        }
    }

    func open() {
        isOpen = true
        for waiter in waiters { waiter.resume() }
        waiters.removeAll()
    }
}
