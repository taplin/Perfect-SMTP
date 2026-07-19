//
//  DirectMXTestHelpers.swift
//  PerfectSMTPTests
//
//  A scripted, in-memory "server" for `DirectMXTransport`'s pool dialer:
//  drives EHLO, then a full MAIL FROM / RCPT TO* / DATA conversation, over
//  a `NIOAsyncTestingChannel` -- no real socket, no real DNS -- reusing
//  `ConnectionHarness`/`serverSend`/`expectClientLine` from
//  `TestHelpers.swift` exactly the way `SMTPConnectionStateMachineTests`
//  does for a single connection. `DirectMXTransport`'s test-only `init(...
//  dialer:)` seam (mirroring `SMTPConnectionPool`'s own) is what lets a
//  test wire this up per pool `Key.host`, so a "first MX host fails,
//  second succeeds" test can make the *first* host's dialer simply
//  `throw` (a real connection failure needs no NIO machinery to simulate)
//  while the *second* host's dialer uses this scripted harness.
//

import Foundation
import NIOCore
import NIOEmbedded
import Testing
@testable import PerfectSMTP

struct SimulatedConnectFailure: Error, Sendable, Equatable {
    let label: String
}

/// A dialer that always fails immediately, for the pool `Key`(s) a test
/// wants to simulate as unreachable.
func failingDialer(label: String = "simulated connection failure") -> @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection {
    { _ in throw SimulatedConnectFailure(label: label) }
}

/// Builds a dialer-compatible closure that drives a full, scripted
/// EHLO/MAIL FROM/RCPT TO*/DATA conversation over an in-memory
/// `ConnectionHarness` connection. `rcptReply` is consulted once per `RCPT
/// TO` line the client sends, keyed by the recipient address parsed out of
/// it, so a test can script per-recipient outcomes (e.g. one accepted, one
/// rejected) within a single scripted host.
func scriptedDialer(
    greeting: String = "250 mx.example.com Hello",
    mailFromReply: String = "250 2.1.0 OK",
    rcptReply: @escaping @Sendable (String) -> String = { _ in "250 2.1.5 OK" },
    dataReply: String = "354 Go ahead",
    finalReply: String = "250 2.0.0 Queued as 12345"
) -> @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection {
    { _ in
        let (connection, channel) = try await ConnectionHarness.make()
        // Unstructured, deliberately not awaited by this dialer: the
        // dialer itself only needs to await EHLO's completion (matching
        // the production dialer's `try await connection.negotiateCapabilities()`)
        // before handing the connection back -- this task keeps running
        // afterward, driven by whatever `SMTPConnection.sendMessage` call
        // the code under test makes next.
        Task {
            guard let ehloLine = try? await expectClientLine(channel), ehloLine.hasPrefix("EHLO") else { return }
            try? await serverSend(channel, greeting)
            guard let mailLine = try? await expectClientLine(channel), mailLine.hasPrefix("MAIL FROM") else { return }
            try? await serverSend(channel, mailFromReply)
            guard mailFromReply.hasPrefix("2") else { return }
            while true {
                guard let line = try? await expectClientLine(channel) else { return }
                if line == "DATA" {
                    try? await serverSend(channel, dataReply)
                    guard dataReply.hasPrefix("3") else { return }
                    // The dot-stuffed body + terminator is written as one
                    // `.raw(...)` command -- one more outbound read drains
                    // it in full.
                    _ = try? await channel.waitForOutboundWrite(as: ByteBuffer.self)
                    try? await serverSend(channel, finalReply)
                    return
                }
                guard line.hasPrefix("RCPT TO:<"), let openAngle = line.firstIndex(of: "<"), let closeAngle = line.firstIndex(of: ">") else { return }
                let recipient = String(line[line.index(after: openAngle)..<closeAngle])
                try? await serverSend(channel, rcptReply(recipient))
            }
        }
        try await connection.negotiateCapabilities()
        return connection
    }
}
