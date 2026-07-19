//
//  LocalMTATransport.swift
//  PerfectSMTP
//
//  Plan §3/§9 Phase 1: async-safe wrapper around `sendmail`/`postfix -t`
//  via `Foundation.Process`, for operators who already run a hardened MTA
//  on the same host. Delivery/retry/TLS from the point of handoff onward
//  is the local MTA's responsibility, not this library's — a
//  `DeliveryResult` from this transport reflects only "did the local MTA
//  accept the handoff," not per-recipient delivery.
//
//  Design notes called out explicitly by the plan, all addressed here:
//   - a single-resume guard bridging `Process.terminationHandler` to a
//     continuation (never resume twice);
//   - concurrent stdout/stderr draining to avoid a pipe-buffer deadlock (a
//     process that writes enough to stderr while only stdout is being
//     read, or vice versa, blocks forever without this);
//   - confinement behind an actor, since `Foundation.Process` is not
//     `Sendable`.
//

import Foundation

public struct LocalMTAConfig: Sendable {
    /// Path to the MTA binary. Defaults to `sendmail`'s conventional
    /// location; `/usr/sbin/sendmail` is itself frequently a symlink to
    /// Postfix/Exim/etc.'s sendmail-compatible shim, which is exactly the
    /// interface this transport targets (plan §3: "the same pattern PHP's
    /// `mail()` and countless other language runtimes use").
    public var executablePath: String
    /// Extra arguments before the recipient list. `-i` (don't treat a
    /// lone `.` as end-of-input -- irrelevant here since we pass the
    /// envelope via `-t`/args, not stdin-terminated-by-dot, but harmless
    /// and conventional) and `-t` (read recipients from the message
    /// headers) are common; `-t` is NOT passed by default here because
    /// this transport passes the envelope recipients explicitly as
    /// trailing arguments instead, which is the more precise, Bcc-safe
    /// interface (matches `SMTPEnvelope.recipients` being the sole source
    /// of truth for who receives the message, header content aside).
    public var extraArguments: [String]
    public var processTimeout: Duration

    public init(
        executablePath: String = "/usr/sbin/sendmail",
        extraArguments: [String] = ["-i"],
        processTimeout: Duration = .seconds(60)
    ) {
        self.executablePath = executablePath
        self.extraArguments = extraArguments
        self.processTimeout = processTimeout
    }
}

public enum LocalMTAError: Error, Sendable, Equatable {
    case nonZeroExit(code: Int32, stderr: String)
    case processLaunchFailed(String)
    case timedOut
}

/// Confines `Foundation.Process` (not `Sendable`) behind an actor, per the
/// plan's explicit design note.
public actor LocalMTATransport: SMTPTransport {
    private let config: LocalMTAConfig

    public init(config: LocalMTAConfig = .init()) {
        self.config = config
    }

    public func send(_ envelope: SMTPEnvelope, _ message: SignedMessage) async throws -> [DeliveryResult] {
        try await runProcess(envelope: envelope, message: message)
        // The local MTA accepted the handoff (zero exit) -- this is the
        // full extent of what this transport can observe; per-recipient
        // delivery from here on is the local MTA's own responsibility.
        return envelope.recipients.map {
            DeliveryResult(recipient: $0, outcome: .delivered(SMTPReply(code: 250, lines: ["Handed off to local MTA"])))
        }
    }

    private func runProcess(envelope: SMTPEnvelope, message: SignedMessage) async throws {
        var arguments = config.extraArguments
        switch envelope.mailFrom {
        case .address(let address):
            arguments.append(contentsOf: ["-f", address])
        case .null:
            arguments.append(contentsOf: ["-f", "<>"])
        }
        arguments.append(contentsOf: envelope.recipients)

        try await Self.execute(
            executablePath: config.executablePath,
            arguments: arguments,
            input: message.rfc5322,
            timeout: config.processTimeout
        )
    }

    /// Launches the process, feeds `input` to stdin, and awaits
    /// termination — all off the actor (a `static` function, so it can't
    /// accidentally touch actor state from a background thread), since
    /// `Process` itself does the real work via its own delegate/callback
    /// machinery, not actor-isolated code.
    private static func execute(
        executablePath: String,
        arguments: [String],
        input: [UInt8],
        timeout: Duration
    ) async throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executablePath)
        process.arguments = arguments

        let stdinPipe = Pipe()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardInput = stdinPipe
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        // Concurrent stdout/stderr draining (plan's explicit design note):
        // a process that writes enough to one pipe while only the other is
        // being read blocks forever on the full pipe's kernel buffer once
        // it fills -- both must be drained concurrently with each other
        // and with writing stdin, not sequentially. All four tasks below
        // run side by side; only the "wait for termination or timeout"
        // task decides the overall outcome -- the drain/stdin tasks simply
        // run to completion (or get cancelled at scope exit) alongside it.
        let stderrBox = NIOLockedBox<[UInt8]>([])

        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                let handle = stderrPipe.fileHandleForReading
                var collected: [UInt8] = []
                while true {
                    let chunk = handle.availableData
                    if chunk.isEmpty { break }
                    collected.append(contentsOf: chunk)
                }
                stderrBox.value = collected
            }

            group.addTask {
                // sendmail-compatible shims are usually silent on stdout,
                // but a verbose one (or `-v`) could otherwise deadlock the
                // same way an undrained stderr would.
                let handle = stdoutPipe.fileHandleForReading
                while true {
                    let chunk = handle.availableData
                    if chunk.isEmpty { break }
                }
            }

            group.addTask {
                let handle = stdinPipe.fileHandleForWriting
                try handle.write(contentsOf: Data(input))
                try handle.close()
            }

            group.addTask {
                try await Self.raceTerminationAgainstTimeout(process: process, stderrBox: stderrBox, timeout: timeout)
            }

            try await group.waitForAll()
        }
    }

    /// Races "the process terminates" against "the timeout elapses",
    /// whichever happens first. The loser is cancelled and, for the
    /// timeout case, its still-running `awaitTermination` task is left to
    /// resolve naturally once `process.terminate()` actually takes effect
    /// -- discarded (not awaited further) once this function returns.
    private static func raceTerminationAgainstTimeout(
        process: Process,
        stderrBox: NIOLockedBox<[UInt8]>,
        timeout: Duration
    ) async throws {
        try await withThrowingTaskGroup(of: Void.self) { race in
            race.addTask {
                try await Self.awaitTermination(process: process, stderrBox: stderrBox)
            }
            race.addTask {
                try await Task.sleep(for: timeout)
                if process.isRunning { process.terminate() }
                throw LocalMTAError.timedOut
            }
            defer { race.cancelAll() }
            try await race.next()
        }
    }

    /// Bridges `Process.terminationHandler` to a continuation with a
    /// single-resume guard.
    ///
    /// Self-check against a double-resume: `Process.terminationHandler` is
    /// documented to fire exactly once per process (either normal exit or
    /// uncaught signal, never both, never twice) -- confirmed by
    /// Foundation's own implementation, which clears the handler after
    /// invoking it. The `resumed` flag below is defense-in-depth on top of
    /// that guarantee, not a workaround for a known double-fire: even if a
    /// future Foundation change (or a platform-specific `Process` behavior
    /// difference) ever violated that contract, this guard makes a
    /// double-resume a silent no-op instead of the fatal "SWIFT TASK
    /// CONTINUATION MISUSE" crash a raw continuation would produce. A
    /// genuine concurrent-double-completion *test* isn't practical without
    /// either forking Foundation's `Process` or invoking private SPI to
    /// fire the handler twice -- this comment plus the guard's presence is
    /// the documented code-review-level self-check the plan calls for when
    /// a real race test isn't practical for a subprocess.
    private static func awaitTermination(process: Process, stderrBox: NIOLockedBox<[UInt8]>) async throws {
        let guardBox = ResumeGuard()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            process.terminationHandler = { proc in
                if proc.terminationStatus == 0 {
                    guardBox.resumeOnce(continuation, .success(()))
                } else {
                    let stderrText = String(decoding: stderrBox.value, as: UTF8.self)
                    guardBox.resumeOnce(
                        continuation,
                        .failure(LocalMTAError.nonZeroExit(code: proc.terminationStatus, stderr: stderrText))
                    )
                }
            }
            do {
                try process.run()
            } catch {
                guardBox.resumeOnce(continuation, .failure(LocalMTAError.processLaunchFailed("\(error)")))
            }
        }
    }
}

/// A `NSLock`-protected single-resume guard shared between
/// `Process.terminationHandler` (invoked from Foundation's own
/// termination-notification thread) and the synchronous `process.run()`
/// failure path -- see `awaitTermination`'s doc comment for why the guard
/// is defense-in-depth, not a workaround for a known double-fire.
/// `@unchecked Sendable`: all mutable state (`resumed`) is behind the lock.
private final class ResumeGuard: @unchecked Sendable {
    private let lock = NSLock()
    private var resumed = false

    func resumeOnce(_ continuation: CheckedContinuation<Void, Error>, _ result: Result<Void, Error>) {
        lock.lock()
        let shouldResume = !resumed
        resumed = true
        lock.unlock()
        guard shouldResume else { return }
        switch result {
        case .success: continuation.resume()
        case .failure(let error): continuation.resume(throwing: error)
        }
    }
}

/// A minimal `NSLock`-protected box for a value crossing from a
/// non-Swift-Concurrency callback context (a pipe-reading loop on a plain
/// `Task`, and `Process.terminationHandler`'s background thread) back into
/// the awaited result. `@unchecked Sendable` is warranted here: all access
/// is serialized by `NSLock`, matching this codebase's established pattern
/// for value types that must cross a callback boundary Swift Concurrency
/// doesn't isolate for you.
final class NIOLockedBox<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: Value

    init(_ value: Value) { self._value = value }

    var value: Value {
        get { lock.lock(); defer { lock.unlock() }; return _value }
        set { lock.lock(); defer { lock.unlock() }; _value = newValue }
    }
}
