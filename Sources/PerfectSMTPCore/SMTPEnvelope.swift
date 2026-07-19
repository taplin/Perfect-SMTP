//
//  SMTPEnvelope.swift
//  PerfectSMTPCore
//
//  See Documentation/swift6-nio-rewrite-plan.md §4.7.
//

/// `MAIL FROM` reverse-path. Modeled as an enum (not a plain `String`)
/// specifically so the RFC 5321 §4.5.5 null return-path required for
/// bounces/DSNs/auto-replies (`MAIL FROM:<>`) is representable and
/// guaranteed by the serializer — a plain `String` can neither represent
/// nor guarantee this (plan §4.7).
public enum ReversePath: Sendable, Hashable {
    /// `MAIL FROM:<address>`
    case address(String)
    /// `MAIL FROM:<>` — required for DSNs/bounces/auto-replies, RFC 5321 §4.5.5.
    case null

    /// The literal `MAIL FROM:<...>` command text. `.null` serializes to
    /// exactly `MAIL FROM:<>`.
    public var mailFromCommand: String {
        switch self {
        case .address(let address):
            return "MAIL FROM:<\(address)>"
        case .null:
            return "MAIL FROM:<>"
        }
    }
}

/// Delivery Status Notification request parameters (RFC 3461), carried on
/// `MAIL FROM`/`RCPT TO` as `RET`/`ENVID`/`NOTIFY`. Pure data in Phase 0 —
/// the transport that actually emits these ESMTP parameters is Phase 1.
public struct DSNRequest: Sendable, Hashable {
    public enum ReturnType: String, Sendable {
        case full = "FULL"
        case headers = "HDRS"
    }

    public enum NotifyOption: String, Sendable, CaseIterable {
        case never = "NEVER"
        case success = "SUCCESS"
        case failure = "FAILURE"
        case delay = "DELAY"
    }

    public var ret: ReturnType?
    public var envelopeID: String?
    public var notify: Set<NotifyOption>?

    public init(ret: ReturnType? = nil, envelopeID: String? = nil, notify: Set<NotifyOption>? = nil) {
        self.ret = ret
        self.envelopeID = envelopeID
        self.notify = notify
    }
}

/// The SMTP envelope — routing information that is entirely separate from
/// the composed message's headers. `recipients` is the *only* place a Bcc
/// address ever lives (the Bug #1 fix, plan §4.7): `to` + `cc` + Bcc
/// addr-specs, supplied by the caller, all end up here as plain strings
/// destined for individual `RCPT TO` commands — never serialized into any
/// header.
public struct SMTPEnvelope: Sendable {
    public var mailFrom: ReversePath
    public var recipients: [String]
    public var size: Int?
    public var dsn: DSNRequest?

    public init(mailFrom: ReversePath, recipients: [String], size: Int? = nil, dsn: DSNRequest? = nil) {
        self.mailFrom = mailFrom
        self.recipients = recipients
        self.size = size
        self.dsn = dsn
    }
}
