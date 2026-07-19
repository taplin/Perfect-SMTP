//
//  SMTPReply.swift
//  PerfectSMTPCore
//
//  Pure Sendable data types, no NIO — see plan §4.8. Classification is
//  mechanical from `replyClass` (2/3/4/5yz), never guessed.
//

/// RFC 2034 enhanced status code, `X.Y.Z`.
public struct EnhancedStatusCode: Sendable, Equatable {
    public let clazz: Int
    public let subject: Int
    public let detail: Int

    public init(clazz: Int, subject: Int, detail: Int) {
        self.clazz = clazz
        self.subject = subject
        self.detail = detail
    }

    /// Parses a leading `X.Y.Z` token (e.g. from the start of a reply
    /// line's text). Returns nil if `token` isn't exactly three dot-
    /// separated non-negative integers.
    public init?(parsing token: some StringProtocol) {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3,
              let c = Int(parts[0]), let s = Int(parts[1]), let d = Int(parts[2]),
              c >= 0, s >= 0, d >= 0
        else { return nil }
        self.clazz = c
        self.subject = s
        self.detail = d
    }

    public var description: String { "\(clazz).\(subject).\(detail)" }
}

/// The mechanical grouping of an SMTP reply code's first digit.
public enum ReplyClass: Sendable, Equatable {
    /// 2yz — positive completion.
    case positiveCompletion
    /// 3yz — positive intermediate (e.g. 354 after DATA).
    case positiveIntermediate
    /// 4yz — transient negative.
    case transientNegative
    /// 5yz — permanent negative.
    case permanentNegative
    /// Any code outside 2yz-5yz (malformed/unexpected).
    case unknown
}

/// One parsed SMTP server reply — a numeric code plus its (possibly
/// multiline) text, and the RFC 2034 enhanced status code when present.
public struct SMTPReply: Sendable, Equatable {
    public let code: Int
    public let enhancedStatus: EnhancedStatusCode?
    /// Reply text, one entry per line, with the leading 3-digit code and
    /// its `-`/` ` separator already stripped by whoever constructed this
    /// (Phase 1's `SMTPResponseDecoder`) — i.e. for the wire line
    /// `550-5.1.1 User unknown`, the corresponding entry here is
    /// `"5.1.1 User unknown"`.
    public let lines: [String]

    /// - Parameters:
    ///   - enhancedStatus: Pass explicitly when the caller (e.g. a NIO
    ///     response decoder in Phase 1) has already parsed it more
    ///     precisely; otherwise it's derived from the leading token of
    ///     `lines.first`.
    public init(code: Int, lines: [String], enhancedStatus: EnhancedStatusCode? = nil) {
        self.code = code
        self.lines = lines
        self.enhancedStatus = enhancedStatus ?? Self.parseEnhancedStatus(from: lines)
    }

    /// Mechanically derived from `code`'s first digit — 2/3/4/5yz.
    public var replyClass: ReplyClass {
        switch code / 100 {
        case 2: return .positiveCompletion
        case 3: return .positiveIntermediate
        case 4: return .transientNegative
        case 5: return .permanentNegative
        default: return .unknown
        }
    }

    private static func parseEnhancedStatus(from lines: [String]) -> EnhancedStatusCode? {
        guard let first = lines.first else { return nil }
        guard let spaceIndex = first.firstIndex(of: " ") else {
            return EnhancedStatusCode(parsing: first)
        }
        return EnhancedStatusCode(parsing: first[first.startIndex..<spaceIndex])
    }
}
