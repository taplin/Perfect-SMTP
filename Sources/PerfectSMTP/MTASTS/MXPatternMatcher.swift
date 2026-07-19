//
//  MXPatternMatcher.swift
//  PerfectSMTP
//
//  Plan §9 Phase 4: RFC 8461 §4.1's `mx:` pattern-matching rule, factored
//  out as a pure, standalone function -- no policy/cache/transport state
//  involved -- so it can be unit-tested directly against hand-picked
//  pattern/host pairs, including the wildcard edge cases the RFC is
//  precise (and easy to get wrong) about.
//

/// Matches a candidate MX hostname (`DNSResolver.MXRecord.exchange`, i.e.
/// already name-decompressed, no trailing dot) against one RFC 8461 §4.1
/// `mx:` pattern from a parsed `MTASTSPolicy`.
public enum MXPatternMatcher {
    /// RFC 8461 §4.1: an `mx:` pattern is either a literal hostname or a
    /// single leading wildcard label (`*.`) followed by a literal domain
    /// suffix. **The wildcard matches exactly one DNS label, never zero and
    /// never more than one:**
    ///   - `*.mail.example.com` matches `mta1.mail.example.com` (exactly
    ///     one label, `mta1`, before the literal suffix).
    ///   - `*.mail.example.com` does **not** match
    ///     `mta1.mta2.mail.example.com` (two labels, `mta1.mta2`, would be
    ///     covered by the wildcard -- not allowed).
    ///   - `*.mail.example.com` does **not** match bare `mail.example.com`
    ///     (the wildcard requires a non-empty label to be present; it
    ///     cannot match zero labels).
    ///
    /// Matching is case-insensitive (DNS names are case-insensitive) and
    /// tolerant of an optional trailing `.` on either side (a fully-
    /// qualified-domain-name root label, cosmetic either way).
    public static func matches(pattern: String, host: String) -> Bool {
        let patternLower = normalize(pattern)
        let hostLower = normalize(host)

        guard patternLower.hasPrefix("*.") else {
            return patternLower == hostLower
        }

        let suffix = String(patternLower.dropFirst(2))
        guard !suffix.isEmpty else { return false }

        let requiredSuffix = "." + suffix
        // `hostLower.count > requiredSuffix.count` (strictly greater, not
        // `>=`) is what enforces "the wildcard label must be non-empty" --
        // a host exactly equal to `requiredSuffix` (i.e. bare
        // `mail.example.com` against pattern `*.mail.example.com`) would
        // otherwise satisfy `hasSuffix` with zero characters left over for
        // the wildcard label.
        guard hostLower.count > requiredSuffix.count, hostLower.hasSuffix(requiredSuffix) else {
            return false
        }
        let wildcardLabel = String(hostLower.dropLast(requiredSuffix.count))
        // The wildcard covers exactly one label -- if what's left over
        // (everything before the matched suffix) itself contains a `.`,
        // that's two-or-more labels trying to hide under one wildcard,
        // which RFC 8461 §4.1 does not allow.
        return !wildcardLabel.isEmpty && !wildcardLabel.contains(".")
    }

    private static func normalize(_ name: String) -> String {
        let lower = name.lowercased()
        return lower.hasSuffix(".") ? String(lower.dropLast()) : lower
    }
}
