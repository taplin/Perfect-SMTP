//
//  DKIMCanonicalization.swift
//  PerfectSMTPCore
//
//  RFC 6376 §3.4 canonicalization -- both "simple" and "relaxed", for
//  headers and body. Kept as pure, standalone functions (no key material,
//  no I/O) so they're independently unit-testable byte-exact against the
//  RFC's own worked whitespace examples (§3.4.5) and the real RFC 8463
//  Appendix A message, separate from the crypto/signing layer in
//  DKIMSigner.swift and SigningKey.swift.
//

import Foundation

extension DKIMSigner {
    /// RFC 6376 §3.4's two canonicalization algorithms, one selectable
    /// independently for headers and body via `DKIMSigner.canon`. Default
    /// is `(.relaxed, .relaxed)` per plan §4.6 (the RFC's own unqualified
    /// default is `simple/simple`, but `relaxed/relaxed` tolerates the
    /// common in-transit modifications -- whitespace/line-rewrapping --
    /// this ecosystem's mail path is more likely to encounter).
    public enum Mode: String, Sendable {
        case simple
        case relaxed
    }
}

enum DKIMCanonicalization {
    private static let cr: UInt8 = 0x0D
    private static let lf: UInt8 = 0x0A
    private static let sp: UInt8 = 0x20
    private static let tab: UInt8 = 0x09

    // MARK: - Header canonicalization (§3.4.1 / §3.4.2)

    /// Canonicalizes one header field ("name: value") per RFC 6376 §3.4.1
    /// (simple) or §3.4.2 (relaxed). Always returns the line terminated
    /// with a single trailing CRLF; the one caller that needs the
    /// DKIM-Signature header's own contribution -- which must NOT have a
    /// trailing CRLF per §3.7 step 2 -- strips the last two bytes itself
    /// (`DKIMSigningInput.headerHashInput`), rather than this function
    /// growing a "no trailing CRLF" flag for a single call site.
    static func canonicalizeHeader(name: String, value: String, mode: DKIMSigner.Mode) -> String {
        switch mode {
        case .simple:
            // "does not change header fields in any way ... presented
            // exactly as they are in the message" (§3.4.1). `RFC5322Message`
            // always serializes a header as "name: value\r\n" -- see
            // `RFC5322Message.serialized()` -- so reproducing that exact
            // template here *is* "exactly as in the message": there is no
            // other line-folding or whitespace variation this composer
            // ever introduces between the stored (name, value) pair and
            // the transmitted bytes.
            return "\(name): \(value)\r\n"
        case .relaxed:
            let raw = "\(name): \(value)"
            guard let colonIndex = raw.firstIndex(of: ":") else {
                return raw + "\r\n"
            }
            let lowerName = raw[..<colonIndex].lowercased()
            var rawValue = String(raw[raw.index(after: colonIndex)...])
            rawValue = unfoldFWS(rawValue)
            rawValue = collapseWSP(rawValue)
            rawValue = rawValue.trimmingCharacters(in: .dkimWhitespace)
            return "\(lowerName):\(rawValue)\r\n"
        }
    }

    /// Removes folding CRLFs (a CRLF immediately followed by WSP) per
    /// §3.4.2's "unfold" step -- "lines with terminators embedded in
    /// continued header field values ... MUST be interpreted without the
    /// CRLF." Only the CRLF itself is dropped; the WSP that follows is
    /// left in place for `collapseWSP` to fold together with any adjacent
    /// whitespace, exactly as the RFC's own two-step description implies.
    private static func unfoldFWS(_ s: String) -> String {
        guard s.contains("\r\n") else { return s }
        // Deliberately walks `unicodeScalars`, not `Character`s: Swift's
        // default grapheme-cluster segmentation treats a CR immediately
        // followed by LF as a *single* `Character` (Unicode text
        // segmentation's own CRLF rule), so `Array(s)` here would never
        // let a bare "\r" or "\n" comparison match at all -- silently
        // making this whole function a no-op. `unicodeScalars` operates
        // on raw code points, where CR (U+000D) and LF (U+000A) are always
        // two distinct elements regardless of adjacency.
        let scalars = Array(s.unicodeScalars)
        var result = String.UnicodeScalarView()
        result.reserveCapacity(scalars.count)
        var i = 0
        while i < scalars.count {
            if i + 2 < scalars.count, scalars[i] == "\r", scalars[i + 1] == "\n",
               scalars[i + 2] == " " || scalars[i + 2] == "\t" {
                i += 2
                continue
            }
            result.append(scalars[i])
            i += 1
        }
        return String(result)
    }

    /// Collapses every run of one or more WSP (space/tab) characters to a
    /// single SP, per §3.4.2's "reduce whitespace" step. Note this only
    /// ever *collapses* multiple whitespace characters -- a lone single
    /// space is already "a single SP" and is left exactly as-is, never
    /// removed. (This distinction matters: it's why a hand-formatted
    /// tag-value string with single spaces already in place round-trips
    /// through relaxed canonicalization unchanged, which the RFC 8463
    /// Appendix A vector test below relies on.)
    private static func collapseWSP(_ s: String) -> String {
        var result = ""
        result.reserveCapacity(s.count)
        var lastWasWSP = false
        for ch in s {
            if ch == " " || ch == "\t" {
                if !lastWasWSP { result.append(" ") }
                lastWasWSP = true
            } else {
                result.append(ch)
                lastWasWSP = false
            }
        }
        return result
    }

    // MARK: - Body canonicalization (§3.4.3 / §3.4.4)

    /// Canonicalizes the message body per §3.4.3 (simple) or §3.4.4
    /// (relaxed). Operates on raw bytes (not `String`) so it stays correct
    /// for content that isn't valid UTF-8 and matches the RFC's own
    /// byte-oriented framing exactly.
    static func canonicalizeBody(_ body: [UInt8], mode: DKIMSigner.Mode) -> [UInt8] {
        switch mode {
        case .simple: return simpleBody(body)
        case .relaxed: return relaxedBody(body)
        }
    }

    /// "Ignores all empty lines at the end of the message body ... If
    /// there is no body or no trailing CRLF ... a CRLF is added." A
    /// completely empty (or all-blank-lines) body canonicalizes to a
    /// single CRLF (2 octets) -- confirmed against the RFC's own published
    /// empty-body SHA-256, `frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=`
    /// (§3.4.3), which is exercised as a unit test.
    private static func simpleBody(_ body: [UInt8]) -> [UInt8] {
        if body.isEmpty { return [cr, lf] }
        var end = body.count
        while end >= 2, body[end - 2] == cr, body[end - 1] == lf {
            end -= 2
        }
        var trimmed = Array(body[0..<end])
        trimmed.append(cr)
        trimmed.append(lf)
        return trimmed
    }

    /// Relaxed body canonicalization: per-line whitespace reduction, then
    /// trailing-empty-line removal. Unlike `simpleBody`, a body that is
    /// empty *or reduces entirely to trailing empty lines* canonicalizes
    /// to zero bytes ("a null input"), not a CRLF -- confirmed against the
    /// RFC's own published empty-body SHA-256,
    /// `47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=` (the hash of the
    /// empty string, §3.4.4), also exercised as a unit test. This is the
    /// single easiest place to introduce a subtle body-canonicalization
    /// bug (treating empty-relaxed the same as empty-simple), so it's
    /// called out explicitly here rather than left implicit in the code.
    private static func relaxedBody(_ body: [UInt8]) -> [UInt8] {
        guard !body.isEmpty else { return [] }
        var lines = splitOnCRLF(body).map(reduceLineWhitespace)
        while let last = lines.last, last.isEmpty {
            lines.removeLast()
        }
        guard !lines.isEmpty else { return [] }
        var result: [UInt8] = []
        for (index, line) in lines.enumerated() {
            if index > 0 {
                result.append(cr)
                result.append(lf)
            }
            result.append(contentsOf: line)
        }
        result.append(cr)
        result.append(lf)
        return result
    }

    /// Splits on CRLF the way RFC 6376's body algorithm implicitly
    /// assumes: a body ending in CRLF produces a trailing empty element
    /// (the "nothing after the last line break", which is what lets the
    /// trailing-empty-line-removal step recognize and normalize it); a
    /// body with no trailing CRLF leaves its last partial line as the
    /// final element with no implicit empty line appended, so it's never
    /// mistaken for a blank line to strip.
    private static func splitOnCRLF(_ body: [UInt8]) -> [[UInt8]] {
        var lines: [[UInt8]] = []
        var current: [UInt8] = []
        var i = 0
        while i < body.count {
            if body[i] == cr, i + 1 < body.count, body[i + 1] == lf {
                lines.append(current)
                current = []
                i += 2
            } else {
                current.append(body[i])
                i += 1
            }
        }
        lines.append(current)
        return lines
    }

    /// Per-line whitespace reduction (§3.4.4a): collapse internal WSP runs
    /// to a single SP, then strip trailing WSP. Leading whitespace is
    /// deliberately left untouched -- unlike header canonicalization
    /// (which strips WSP immediately after the colon), the RFC's body
    /// algorithm never strips leading whitespace on a line.
    private static func reduceLineWhitespace(_ line: [UInt8]) -> [UInt8] {
        var collapsed: [UInt8] = []
        collapsed.reserveCapacity(line.count)
        var lastWasWSP = false
        for byte in line {
            if byte == sp || byte == tab {
                if !lastWasWSP { collapsed.append(sp) }
                lastWasWSP = true
            } else {
                collapsed.append(byte)
                lastWasWSP = false
            }
        }
        while let last = collapsed.last, last == sp || last == tab {
            collapsed.removeLast()
        }
        return collapsed
    }
}

private extension CharacterSet {
    /// RFC 6376's WSP is exactly space and tab -- not the broader Unicode
    /// whitespace set `.whitespaces` implies, though in practice header
    /// values here are already ASCII-only by this point. Spelled out
    /// explicitly rather than relying on `.whitespaces`' broader
    /// definition matching by coincidence.
    static let dkimWhitespace = CharacterSet(charactersIn: " \t")
}
