//
//  MTASTSPolicy.swift
//  PerfectSMTP
//
//  Plan §9 Phase 4: the RFC 8461 policy model and its defensive, fail-safe
//  parser. Pure data + a pure parsing function -- no networking, no DNS, no
//  NIO -- so it can be unit-tested against hand-crafted policy-file text
//  with no fetch/cache machinery involved at all (mirroring how
//  `DNSResolver.processMXAnswers` is kept pure and separately testable from
//  the query/transport machinery around it).
//

import Foundation

/// RFC 8461 §3.2's three policy modes.
public enum MTASTSMode: String, Sendable, Equatable {
    /// Mandatory: only deliver to policy-matching MX hosts, only over
    /// verified TLS; a delivery that can't satisfy this must hard-fail
    /// rather than silently degrade (RFC 8461 §5, plan §9 Phase 4's
    /// "enforce-mode hard-fail" requirement).
    case enforce
    /// Attempt policy-matching hosts over verified TLS first, but never
    /// let a policy-driven failure block delivery -- fall back to
    /// whatever this transport would otherwise do. RFC 8460 TLSRPT
    /// aggregate reporting (the mechanism `testing` mode exists to
    /// support in the wider MTA-STS ecosystem) is explicitly out of scope
    /// for this library -- see `MTASTSPolicy`'s own doc comment.
    case testing
    /// An explicit, authoritative "no MTA-STS constraint" -- deliberately
    /// distinct from "no policy published at all" (the caller sees `nil`
    /// from `MTASTSPolicyProviding.policy(for:)` in that case): a `mode:
    /// none` policy was successfully fetched and parsed, it just carries
    /// no enforcement obligation. Both cases resolve to identical
    /// `DirectMXTransport` behavior (today's opportunistic-by-default
    /// delivery, plan §9 Phase 4 point 4), so callers rarely need to tell
    /// them apart, but the distinction is preserved here rather than
    /// collapsed, since a caller building diagnostics/logging on top of
    /// this API might care.
    case none
}

/// A fully parsed, valid MTA-STS policy (RFC 8461 §3.2/§4.1). Never
/// constructed directly by application code in the normal flow --
/// `MTASTSPolicyParser.parse(_:)` is the only place one of these comes from
/// besides tests.
///
/// **Forward-looking note for a future DANE phase (plan §9 Phase 4's own
/// scope decision -- DANE is deferred entirely in this phase, see the plan
/// document's Phase 4 bullet for the full rationale):** per RFC 8461's own
/// text and general best practice, if DANE/TLSA is ever added in a future
/// phase, a DANE failure must never be overridden by an MTA-STS pass for the
/// same connection -- DANE is the stronger signal when both are present for
/// a domain. Nothing in this type or its consumers (`DirectMXTransport`)
/// implements DANE today; this note exists purely so whoever eventually
/// revisits the DANE-deferral decision sees the precedence rule stated
/// up front rather than having to re-derive it.
public struct MTASTSPolicy: Sendable, Equatable {
    public let mode: MTASTSMode
    /// RFC 8461 §4.1 `mx:` patterns, exactly as they appeared in the policy
    /// file (one entry per `mx:` line) -- may include a leading `*.`
    /// wildcard label. Matched against candidate MX hostnames by
    /// `MXPatternMatcher.matches(pattern:host:)`. Empty when the policy
    /// file had no `mx:` lines at all (a malformed-in-spirit but not
    /// wire-invalid policy -- `MXPatternMatcher` simply never matches
    /// anything against an empty pattern list, which `DirectMXTransport`'s
    /// `enforce`/`testing` handling already treats correctly as "no
    /// candidate host").
    public let mxPatterns: [String]
    /// RFC 8461 §3.2 `max_age`, in seconds --
    /// `MTASTSPolicyManager`'s cache expiry window for this policy.
    public let maxAge: TimeInterval

    public init(mode: MTASTSMode, mxPatterns: [String], maxAge: TimeInterval) {
        self.mode = mode
        self.mxPatterns = mxPatterns
        self.maxAge = maxAge
    }
}

/// Parses an RFC 8461 §3.2 policy file: simple `key: value` pairs, one per
/// line. Deliberately fail-safe throughout -- a malformed policy file
/// returns `nil` rather than throwing or crashing, matching plan §9 Phase
/// 4's explicit instruction ("a malformed policy file should be treated as
/// 'no usable policy' (fail safe), not crash") and this codebase's existing
/// convention for untrusted-input parsing (e.g. `DNSWireFormat`'s decoder
/// never force-unwraps into attacker-controlled bytes).
public enum MTASTSPolicyParser {
    /// RFC 8461 §3.2's documented upper bound on `max_age`: 31557600
    /// seconds (~1 year, i.e. 60*60*24*365.25). A value outside `0
    /// ... maximumMaxAgeSeconds` is treated as malformed -- fail-safe,
    /// same as every other validation failure in this parser.
    public static let maximumMaxAgeSeconds = 31_557_600

    /// - Parameter text: The policy file body, decoded as UTF-8 by the
    ///   caller (`MTASTSPolicyManager`) from the raw HTTPS response bytes.
    /// - Returns: A valid `MTASTSPolicy`, or `nil` if `text` doesn't parse
    ///   into one -- missing/unrecognized `version`, missing or
    ///   unrecognized `mode`, or a missing/out-of-range/non-numeric
    ///   `max_age`. Unrecognized keys are ignored (RFC 8461 §3.2's
    ///   forward-compatibility allowance -- a future policy-file version
    ///   adding new keys shouldn't make every implementation that predates
    ///   it treat the whole file as malformed), and a line with no `:` at
    ///   all is skipped rather than failing the whole parse (defensive
    ///   tolerance for stray blank/malformed lines, not a spec requirement).
    public static func parse(_ text: String) -> MTASTSPolicy? {
        var version: String?
        var mode: MTASTSMode?
        var mxPatterns: [String] = []
        var maxAgeSeconds: Int?

        // Normalize CRLF to LF before splitting -- Swift's `Character`
        // treats `"\r\n"` as a single extended grapheme cluster distinct
        // from a bare `"\n"`, so `split(separator: "\n")` alone would never
        // find a split point at all in a CRLF-terminated policy file (the
        // RFC 8461 §3.2-conventional line ending for an HTTP response
        // body) -- every line would silently collapse into one, and the
        // whole file would fail to parse. Normalizing first sidesteps that
        // entirely rather than trying to split on a `Character` set that
        // would still miss whichever grapheme-cluster form wasn't listed.
        let normalized = text.replacingOccurrences(of: "\r\n", with: "\n")
        for rawLine in normalized.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !line.isEmpty, let colonIndex = line.firstIndex(of: ":") else { continue }
            let key = line[line.startIndex..<colonIndex].trimmingCharacters(in: .whitespaces)
            let value = line[line.index(after: colonIndex)...].trimmingCharacters(in: .whitespaces)
            switch key {
            case "version":
                version = value
            case "mode":
                mode = MTASTSMode(rawValue: value)
            case "mx":
                guard !value.isEmpty else { continue }
                mxPatterns.append(value)
            case "max_age":
                maxAgeSeconds = Int(value)
            default:
                break // forward-compatible: unknown keys are ignored, not fatal.
            }
        }

        // RFC 8461 §3.2: `version` MUST be exactly `STSv1`.
        guard version == "STSv1" else { return nil }
        guard let mode else { return nil }
        guard let maxAgeSeconds, (0...maximumMaxAgeSeconds).contains(maxAgeSeconds) else { return nil }

        return MTASTSPolicy(mode: mode, mxPatterns: mxPatterns, maxAge: TimeInterval(maxAgeSeconds))
    }
}
