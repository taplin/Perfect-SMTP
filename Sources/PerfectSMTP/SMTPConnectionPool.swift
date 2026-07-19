//
//  SMTPConnectionPool.swift
//  PerfectSMTP
//
//  Connection pool actor (plan §4.4). Per-destination keying by
//  `(host, port, tls)`. Bounded concurrency enforced inside the actor (no
//  locks — the actor is the mutual-exclusion mechanism).
//

import Foundation
import NIOCore

public actor SMTPConnectionPool {
    public struct Key: Hashable, Sendable {
        public let host: String
        public let port: Int
        public let tls: TLSMode
        public init(host: String, port: Int, tls: TLSMode) {
            self.host = host
            self.port = port
            self.tls = tls
        }
    }

    public struct Configuration: Sendable {
        public var maxPerHost: Int
        public var maxTotal: Int
        public var idleTimeout: Duration
        public var connectTimeout: TimeAmount
        public var circuitBreakerThreshold: Int
        public var circuitBreakerResetTimeout: Duration

        public init(
            maxPerHost: Int = 4,
            maxTotal: Int = 32,
            idleTimeout: Duration = .seconds(60),
            connectTimeout: TimeAmount = .seconds(30),
            circuitBreakerThreshold: Int = 5,
            circuitBreakerResetTimeout: Duration = .seconds(30)
        ) {
            self.maxPerHost = maxPerHost
            self.maxTotal = maxTotal
            self.idleTimeout = idleTimeout
            self.connectTimeout = connectTimeout
            self.circuitBreakerThreshold = circuitBreakerThreshold
            self.circuitBreakerResetTimeout = circuitBreakerResetTimeout
        }
    }

    public enum PoolError: Error, Sendable, Equatable {
        case shutdown
    }

    /// Resolved atomically, within a single actor activation, when a
    /// parked waiter is woken (plan §4.4: "slot ownership transfers
    /// atomically as part of the same actor activation that resumes a
    /// waiter, so a fresh checkout can't race in and steal it").
    private enum WaiterOutcome: Sendable {
        /// A live, healthy connection handed directly to the waiter —
        /// `activeCount` is intentionally left unchanged by the resolving
        /// call, since ownership transferred rather than being released
        /// then reacquired.
        case connection(SMTPConnection)
        /// The freed capacity (not a live connection) was reserved for
        /// this waiter — it must dial for itself, outside the atomic
        /// section, but the reservation itself already happened inside it.
        case reservedSlotDialYourself
    }

    /// `@unchecked Sendable`: every method that touches `resolved` is only
    /// ever called from within this pool actor's isolated methods
    /// (`cancelWaiter`/`handOff`), which the actor itself serializes —
    /// never truly concurrent, matching this codebase's other
    /// single-owner `@unchecked Sendable` precedents. The `resolved` flag
    /// is a second, explicit line of defense against a double-resume
    /// (plan §4.4's required single-owner guard) on top of the primary
    /// mechanism (removing the waiter from the list before resolving it).
    private final class Waiter: @unchecked Sendable {
        let id = UUID()
        private var continuation: CheckedContinuation<WaiterOutcome, Error>?
        private var resolved = false

        init(_ continuation: CheckedContinuation<WaiterOutcome, Error>) {
            self.continuation = continuation
        }

        @discardableResult
        func resolve(_ result: Result<WaiterOutcome, Error>) -> Bool {
            guard !resolved else { return false }
            resolved = true
            let cont = continuation
            continuation = nil
            switch result {
            case .success(let value): cont?.resume(returning: value)
            case .failure(let error): cont?.resume(throwing: error)
            }
            return true
        }
    }

    private struct IdleEntry {
        let connection: SMTPConnection
        let returnedAt: ContinuousClock.Instant
    }

    private enum BreakerState {
        case closed(consecutiveFailures: Int)
        case open(until: ContinuousClock.Instant)
    }

    private var idle: [Key: [IdleEntry]] = [:]
    private var activeCount: [Key: Int] = [:]
    private var breaker: [Key: BreakerState] = [:]
    private var waiters: [Key: [(id: UUID, waiter: Waiter)]] = [:]
    private var isShutDown = false

    private let configuration: Configuration
    private let group: any EventLoopGroup
    private let ehloHostname: String
    /// Injectable for testing (e.g. racing checkouts against a pool with
    /// `maxPerHost = 1` without a real socket). Defaults to the real
    /// `SMTPBootstrap`-backed dialer.
    private let dialer: @Sendable (Key) async throws -> SMTPConnection
    private let clock = ContinuousClock()

    public init(configuration: Configuration = .init(), ehloHostname: String = "localhost", group: any EventLoopGroup) {
        self.configuration = configuration
        self.ehloHostname = ehloHostname
        self.group = group
        let capturedGroup = group
        let capturedTimeout = configuration.connectTimeout
        let capturedHostname = ehloHostname
        self.dialer = { key in
            let asyncChannel = try await SMTPBootstrap.connect(
                host: key.host, port: key.port, tls: key.tls,
                connectTimeout: capturedTimeout, group: capturedGroup
            )
            let connection = SMTPConnection(asyncChannel: asyncChannel, ehloHostname: capturedHostname)
            try await connection.negotiateCapabilities()
            return connection
        }
    }

    /// Test/internal-only initializer: overrides the dialer entirely so
    /// pool behavior (reentrancy, cancellation, breaker) can be exercised
    /// without a real socket.
    init(configuration: Configuration = .init(), group: any EventLoopGroup, dialer: @escaping @Sendable (Key) async throws -> SMTPConnection) {
        self.configuration = configuration
        self.ehloHostname = "localhost"
        self.group = group
        self.dialer = dialer
    }

    // MARK: - Public API

    public func withConnection<R: Sendable>(to key: Key, _ body: (SMTPConnection) async throws -> R) async throws -> R {
        let connection = try await checkout(key)
        do {
            let result = try await body(connection)
            release(key, connection: connection, healthy: true)
            return result
        } catch {
            release(key, connection: connection, healthy: false)
            throw error
        }
    }

    public func shutdown() async {
        isShutDown = true
        for (_, entries) in idle {
            for entry in entries { entry.connection.channel.close(promise: nil) }
        }
        idle.removeAll()
        for (key, list) in waiters {
            for entry in list { entry.waiter.resolve(.failure(PoolError.shutdown)) }
            waiters[key] = []
        }
        waiters.removeAll()
    }

    // MARK: - Checkout

    private func checkout(_ key: Key) async throws -> SMTPConnection {
        guard !isShutDown else { throw PoolError.shutdown }
        try checkBreaker(key)

        if let reused = popValidatedIdle(key) {
            activeCount[key, default: 0] += 1
            return reused
        }

        let currentActive = activeCount[key, default: 0]
        let totalActive = activeCount.values.reduce(0, +)
        if currentActive < configuration.maxPerHost, totalActive < configuration.maxTotal {
            // Reentrancy discipline (plan §4.4): reserve the slot
            // synchronously, in this same actor activation, before the
            // first `await` -- closing the check-then-act race where a
            // second concurrent checkout could observe the same
            // not-yet-incremented count during the first checkout's dial.
            activeCount[key, default: 0] += 1
            do {
                let connection = try await dialer(key)
                recordSuccess(key)
                return connection
            } catch {
                activeCount[key, default: 0] -= 1
                recordFailure(key)
                throw error
            }
        }

        return try await parkAsWaiter(key)
    }

    private func popValidatedIdle(_ key: Key) -> SMTPConnection? {
        guard var list = idle[key], !list.isEmpty else { return nil }
        var result: SMTPConnection?
        while !list.isEmpty {
            let entry = list.removeFirst()
            let age = clock.now - entry.returnedAt
            if age > configuration.idleTimeout || !entry.connection.channel.isActive {
                entry.connection.channel.close(promise: nil)
                continue
            }
            result = entry.connection
            break
        }
        idle[key] = list
        return result
    }

    private func parkAsWaiter(_ key: Key) async throws -> SMTPConnection {
        let waiterID = UUID()
        let outcome: WaiterOutcome = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<WaiterOutcome, Error>) in
                let waiter = Waiter(continuation)
                waiters[key, default: []].append((id: waiterID, waiter: waiter))
            }
        } onCancel: {
            Task { await self.cancelWaiter(key, id: waiterID) }
        }
        switch outcome {
        case .connection(let connection):
            return connection
        case .reservedSlotDialYourself:
            do {
                let connection = try await dialer(key)
                await recordSuccessAsync(key)
                return connection
            } catch {
                await releaseFailedReservation(key)
                throw error
            }
        }
    }

    private func cancelWaiter(_ key: Key, id: UUID) {
        guard var list = waiters[key], let idx = list.firstIndex(where: { $0.id == id }) else { return }
        let waiter = list[idx].waiter
        // Single-owner guard: whichever of {cancellation, a concurrent
        // release()} resolves the waiter first wins; the other no-ops.
        if waiter.resolve(.failure(CancellationError())) {
            list.remove(at: idx)
            waiters[key] = list
        }
    }

    private func recordSuccessAsync(_ key: Key) async { recordSuccess(key) }
    private func releaseFailedReservation(_ key: Key) async {
        activeCount[key, default: 1] -= 1
        recordFailure(key)
    }

    // MARK: - Release

    private func release(_ key: Key, connection: SMTPConnection, healthy: Bool) {
        if healthy, connection.channel.isActive {
            recordSuccess(key)
            if handOff(key, outcome: .connection(connection)) { return }
            activeCount[key, default: 1] -= 1
            idle[key, default: []].append(IdleEntry(connection: connection, returnedAt: clock.now))
            return
        }
        if !healthy { recordFailure(key) } else { recordSuccess(key) }
        connection.channel.close(promise: nil)
        if handOff(key, outcome: .reservedSlotDialYourself) { return }
        activeCount[key, default: 1] -= 1
    }

    /// Hands `outcome` to the first still-live waiter for `key`, if any,
    /// atomically within this actor activation. Returns `true` if a waiter
    /// was resolved.
    private func handOff(_ key: Key, outcome: WaiterOutcome) -> Bool {
        guard var list = waiters[key], !list.isEmpty else { return false }
        while !list.isEmpty {
            let entry = list.removeFirst()
            if entry.waiter.resolve(.success(outcome)) {
                waiters[key] = list
                return true
            }
        }
        waiters[key] = list
        return false
    }

    // MARK: - Circuit breaker (co-located, plan §4.4)

    private func checkBreaker(_ key: Key) throws {
        guard let state = breaker[key] else { return }
        switch state {
        case .closed:
            return
        case .open(let until):
            if clock.now >= until {
                breaker[key] = .closed(consecutiveFailures: 0)
            } else {
                throw SMTPError.circuitOpen
            }
        }
    }

    private func recordFailure(_ key: Key) {
        let current: Int
        if case .closed(let n) = breaker[key] ?? .closed(consecutiveFailures: 0) { current = n } else { current = 0 }
        let next = current + 1
        breaker[key] = next >= configuration.circuitBreakerThreshold
            ? .open(until: clock.now + configuration.circuitBreakerResetTimeout)
            : .closed(consecutiveFailures: next)
    }

    private func recordSuccess(_ key: Key) {
        breaker[key] = .closed(consecutiveFailures: 0)
    }
}
