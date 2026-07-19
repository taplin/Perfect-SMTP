//
//  Capabilities.swift
//  PerfectSMTP
//
//  Parsed from the EHLO multiline reply (plan §4.3). Nothing downstream
//  ever assumes a capability not present in this struct.
//

/// The server capabilities negotiated by the most recent EHLO. An empty
/// `Capabilities()` means "not yet negotiated" (or the server only speaks
/// HELO) — every flag defaults to `false`/`nil`/empty, so downstream code
/// naturally degrades to the most conservative behavior (lock-step,
/// PLAIN/LOGIN-only if even that, no SIZE pre-check) rather than crashing.
public struct Capabilities: Sendable, Equatable {
    public var startTLS = false
    public var authMechanisms: [String] = []
    /// The advertised SIZE limit in bytes, when the server declared one
    /// (`SIZE 35882577`). `nil` when SIZE wasn't advertised, or was
    /// advertised with no explicit limit — disambiguated by `sizeAdvertised`.
    public var size: Int?
    /// True whenever the `SIZE` keyword appeared at all, independent of
    /// whether a numeric limit followed it — this, not `size != nil`, is
    /// what should gate whether `MAIL FROM` includes a `SIZE=` parameter.
    public var sizeAdvertised = false
    public var eightBitMIME = false
    public var smtpUTF8 = false
    public var pipelining = false
    public var chunking = false
    public var dsn = false
    public var enhancedStatusCodes = false

    public init() {}

    /// Parses an EHLO reply's lines (as already split by `SMTPResponseDecoder`
    /// — i.e. `SMTPReply.lines`, with the leading code+separator already
    /// stripped). The first line is the greeting text (domain + optional
    /// message), not a capability — every subsequent line is one capability
    /// keyword, optionally followed by space-separated arguments.
    public init(parsingEHLOLines lines: [String]) {
        for line in lines.dropFirst() {
            parse(line)
        }
    }

    private mutating func parse(_ line: String) {
        let parts = line.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
        guard let keyword = parts.first else { return }
        switch keyword.uppercased() {
        case "STARTTLS": startTLS = true
        case "PIPELINING": pipelining = true
        case "8BITMIME": eightBitMIME = true
        case "SMTPUTF8": smtpUTF8 = true
        case "CHUNKING": chunking = true
        case "DSN": dsn = true
        case "ENHANCEDSTATUSCODES": enhancedStatusCodes = true
        case "SIZE":
            sizeAdvertised = true
            if parts.count > 1, let value = Int(parts[1]) { size = value }
        case "AUTH":
            if parts.count > 1 {
                authMechanisms = parts[1].split(separator: " ").map { String($0).uppercased() }
            }
        default:
            break
        }
    }
}
