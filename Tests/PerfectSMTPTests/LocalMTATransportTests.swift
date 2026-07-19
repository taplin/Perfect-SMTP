//
//  LocalMTATransportTests.swift
//  PerfectSMTPTests
//
//  Plan §5: a test that a slow/large stderr writer doesn't deadlock the
//  stdin/stdout exchange -- the pipe-buffer-deadlock scenario the design
//  note calls out (a process that writes enough to one pipe's kernel
//  buffer while only the other is being drained blocks forever without
//  concurrent draining). The termination-handler-to-continuation
//  double-resume guard is documented as a code-review-level self-check in
//  `LocalMTATransport.swift` itself (a genuine concurrent race isn't
//  practical to construct without forking Foundation's `Process`).
//

import Foundation
import Testing
@testable import PerfectSMTP

struct LocalMTATransportTests {

    /// Writes a small, portable Python "fake MTA" script to a temp file
    /// and marks it executable. `stderrBytes` controls how much it writes
    /// to stderr before exiting -- large enough to exceed the OS pipe
    /// buffer (typically 64KiB) proves the deadlock scenario is real, not
    /// just theoretical.
    private func makeFakeMTA(stderrBytes: Int, exitCode: Int32 = 0) throws -> URL {
        let script = """
        #!/usr/bin/env python3
        import sys
        data = sys.stdin.buffer.read()
        sys.stderr.buffer.write(b"E" * \(stderrBytes))
        sys.stderr.buffer.flush()
        sys.stdout.buffer.write(b"O" * \(stderrBytes))
        sys.stdout.buffer.flush()
        sys.exit(\(exitCode))
        """
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("fake-mta-\(UUID().uuidString).py")
        try script.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        return url
    }

    /// Races `body` against a timeout, failing the test explicitly (rather
    /// than hanging the whole suite forever) if the deadlock scenario this
    /// test exists to catch were ever reintroduced.
    private func withDeadlockGuard<T: Sendable>(
        seconds: Double = 10,
        _ body: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask { try await body() }
            group.addTask {
                try await Task.sleep(for: .seconds(seconds))
                throw DeadlockGuardError.timedOut
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }

    @Test func slowStderrWriterDoesNotDeadlockStdinStdoutExchange() async throws {
        // 4x a typical 64KiB pipe buffer, on both stdout AND stderr --
        // large enough that without concurrent draining of both, the
        // process blocks forever trying to write past the full kernel
        // buffer, which in turn blocks our stdin write/close, which in
        // turn means the process never sees EOF on stdin and never exits.
        let scriptURL = try makeFakeMTA(stderrBytes: 256 * 1024)
        defer { try? FileManager.default.removeItem(at: scriptURL) }

        let transport = LocalMTATransport(config: LocalMTAConfig(executablePath: scriptURL.path, processTimeout: .seconds(15)))
        let envelope = try SMTPEnvelope(mailFrom: .address("from@example.com"), recipients: ["to@example.com"])
        // A non-trivial body so the stdin-write side also has real work to
        // do concurrently with the pipe-filling stdout/stderr writer.
        let body = Array(repeating: "X", count: 50_000).joined()
        let message = SignedMessage(rfc5322: Array("Subject: hi\r\n\r\n\(body)".utf8))

        let results = try await withDeadlockGuard {
            try await transport.send(envelope, message)
        }

        #expect(results.count == 1)
        guard case .delivered = results[0].outcome else {
            Issue.record("expected delivered, got \(results[0].outcome)")
            return
        }
    }

    @Test func nonZeroExitSurfacesStderrInTheThrownError() async throws {
        let scriptURL = try makeFakeMTA(stderrBytes: 100, exitCode: 1)
        defer { try? FileManager.default.removeItem(at: scriptURL) }

        let transport = LocalMTATransport(config: LocalMTAConfig(executablePath: scriptURL.path))
        let envelope = try SMTPEnvelope(mailFrom: .address("from@example.com"), recipients: ["to@example.com"])
        let message = SignedMessage(rfc5322: Array("Subject: hi\r\n\r\nbody".utf8))

        await #expect(throws: LocalMTAError.self) {
            _ = try await withDeadlockGuard {
                try await transport.send(envelope, message)
            }
        }
    }
}

private enum DeadlockGuardError: Error {
    case timedOut
}
