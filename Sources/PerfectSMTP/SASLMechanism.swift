//
//  SASLMechanism.swift
//  PerfectSMTP
//
//  AUTH abstraction (plan §4.5). `SASLPlain`/`SASLLogin` are the workhorses
//  (SendGrid/Postmark/SES issue API keys as SMTP passwords); `XOAuth2` is
//  first-class and mandatory-in-practice for Gmail/Workspace (legacy SMTP
//  password auth disabled since March 2025) and Microsoft 365 (Basic-auth
//  SMTP being phased out through 2027). `SASLCramMD5`/`SASLScramSHA256` are
//  deliberately not implemented — deferred per plan §4.5/§10.
//

import Foundation

public protocol SASLMechanism: Sendable {
    var name: String { get }
    mutating func initialResponse() async throws -> [UInt8]?
    mutating func respond(to challenge: [UInt8]) async throws -> [UInt8]
    var isComplete: Bool { get }
}

/// RFC 4616. `authzid` is almost always empty for SMTP AUTH (the
/// authentication identity and authorization identity are the same
/// mailbox); exposed for completeness.
public struct SASLPlain: SASLMechanism {
    public let name = "PLAIN"
    public let authzid: String
    public let username: String
    public let password: String
    private var sentInitial = false

    public init(authzid: String = "", username: String, password: String) {
        self.authzid = authzid
        self.username = username
        self.password = password
    }

    public mutating func initialResponse() async throws -> [UInt8]? {
        sentInitial = true
        var bytes: [UInt8] = []
        bytes.append(contentsOf: Array(authzid.utf8))
        bytes.append(0)
        bytes.append(contentsOf: Array(username.utf8))
        bytes.append(0)
        bytes.append(contentsOf: Array(password.utf8))
        return bytes
    }

    public mutating func respond(to challenge: [UInt8]) async throws -> [UInt8] {
        // PLAIN's whole exchange is the initial response; a server that
        // still issues a mid-exchange continuation gets an empty reply.
        []
    }

    public var isComplete: Bool { sentInitial }
}

/// RFC 4954's `AUTH LOGIN` (a de facto standard, not itself an RFC-defined
/// SASL mechanism, but universally supported). No initial response; the
/// server issues two base64 `334` challenges ("Username:" then
/// "Password:") in order.
public struct SASLLogin: SASLMechanism {
    public let name = "LOGIN"
    public let username: String
    public let password: String
    private var step = 0

    public init(username: String, password: String) {
        self.username = username
        self.password = password
    }

    public mutating func initialResponse() async throws -> [UInt8]? { nil }

    public mutating func respond(to challenge: [UInt8]) async throws -> [UInt8] {
        step += 1
        return step == 1 ? Array(username.utf8) : Array(password.utf8)
    }

    public var isComplete: Bool { step >= 2 }
}

/// RFC 7628 XOAUTH2/OAUTHBEARER framing:
/// `user=<username>\x01auth=Bearer <token>\x01\x01`. The library only
/// formats this framing and invokes the caller-supplied `tokenProvider` —
/// it does not itself run an OAuth2 authorization flow. On a `535`, the
/// connection-level `authenticate(_:)` calls `tokenProvider()` again and
/// retries the whole exchange once (plan §4.5) before surfacing
/// `SMTPError.authenticationFailed`.
public struct XOAuth2: SASLMechanism {
    public let name = "XOAUTH2"
    public let username: String
    public let tokenProvider: @Sendable () async throws -> String
    private var sentInitial = false

    public init(username: String, tokenProvider: @escaping @Sendable () async throws -> String) {
        self.username = username
        self.tokenProvider = tokenProvider
    }

    public mutating func initialResponse() async throws -> [UInt8]? {
        sentInitial = true
        let token = try await tokenProvider()
        let framed = "user=\(username)\u{1}auth=Bearer \(token)\u{1}\u{1}"
        return Array(framed.utf8)
    }

    public mutating func respond(to challenge: [UInt8]) async throws -> [UInt8] {
        // A `334` here is Google's XOAUTH2 error-detail continuation (a
        // base64 JSON error object); RFC 7628 §3.2.3 requires responding
        // with an empty message so the server then returns its real 5xx,
        // which `authenticate(_:)`'s exchange loop classifies normally.
        []
    }

    public var isComplete: Bool { sentInitial }
}
