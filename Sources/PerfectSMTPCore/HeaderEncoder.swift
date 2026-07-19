//
//  HeaderEncoder.swift
//  PerfectSMTPCore
//
//  Real RFC 2047 encoded-words — this is Bug #2's actual fix (plan §4.7).
//  The old code emitted a fake, unescaped
//  `Subject: =?utf-8?Q?<raw>?=` for any subject that didn't happen to hit
//  the base64 branch. Two corrections called out explicitly by the
//  protocol review are implemented here:
//
//  (a) Folding at the 75-char-per-encoded-word limit happens on Unicode
//      scalar (character) boundaries only — a byte-oriented fold can cut a
//      multi-byte UTF-8 sequence in half, producing mojibake on decode.
//  (b) Encoded-words are never emitted inside an RFC 5322 quoted-string
//      (RFC 2047 §5 forbids it — a receiver that sees `"=?utf-8?B?…?="`
//      would treat it as literal text, not decode it). Non-ASCII phrases
//      are always emitted as bare encoded-words; ASCII-but-special-
//      character phrases use an ordinary quoted-string; never both on the
//      same phrase.
//

import Foundation

public enum HeaderEncoder {
    /// Maximum total length of one `=?charset?enc?...?=` token, per RFC 2047 §2.
    private static let maxEncodedWordLength = 75
    /// `"=?utf-8?B?" + "?="` fixed overhead around the base64 payload = 12
    /// characters. Payload capped at 45 bytes so the base64 expansion
    /// (ceil(45/3)*4 = 60 chars) plus overhead stays comfortably at or
    /// under `maxEncodedWordLength`.
    private static let maxPayloadBytesPerWord = 45

    private static let atextChars: Set<Character> = Set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-/=?^_`{|}~"
    )

    /// Encodes an unstructured header value (e.g. `Subject`) per RFC 2047.
    /// Pure-ASCII, control-character-free input is returned unmodified;
    /// anything else is emitted as one or more folded encoded-words.
    public static func encodeUnstructured(_ text: String) -> String {
        let sanitized = sanitizeForHeader(text)
        guard needsEncoding(sanitized) else { return sanitized }
        return encodedWords(for: sanitized).joined(separator: "\r\n ")
    }

    /// Encodes an RFC 5322 `phrase` (e.g. a mailbox display name).
    /// ASCII phrases that are plain space-separated atoms are emitted bare;
    /// ASCII phrases needing quoting (commas, quotes, etc.) become an
    /// ordinary `quoted-string`; any non-ASCII content is emitted as
    /// encoded-word(s) — never combined with quoting on the same phrase.
    public static func encodePhrase(_ text: String) -> String {
        let sanitized = sanitizeForHeader(text)
        guard !sanitized.isEmpty else { return sanitized }
        if sanitized.utf8.allSatisfy({ $0 < 0x80 }) {
            return isPlainAtomsPhrase(sanitized) ? sanitized : quotedString(sanitized)
        }
        return encodedWords(for: sanitized).joined(separator: "\r\n ")
    }

    /// Encodes one mailbox as `phrase <addr-spec>`, or just the addr-spec
    /// if there's no display name.
    public static func encodeAddress(_ address: EmailAddress) -> String {
        guard let name = address.displayName, !name.isEmpty else {
            return address.address
        }
        return "\(encodePhrase(name)) <\(address.address)>"
    }

    /// Encodes a comma-separated mailbox list for `To:`/`Cc:`/`Reply-To:`.
    public static func encodeAddressList(_ addresses: [EmailAddress]) -> String {
        addresses.map(encodeAddress).joined(separator: ", ")
    }

    // MARK: - Internals

    /// Strips CR/LF from header input to prevent header injection — a
    /// header value containing raw line breaks could otherwise be used to
    /// smuggle additional headers (or, in the worst case, a fake `Bcc:`)
    /// past the composer's denylist. Not explicitly named by the plan, but
    /// directly in the spirit of the Bug #1 fix.
    private static func sanitizeForHeader(_ text: String) -> String {
        guard text.contains("\r") || text.contains("\n") else { return text }
        return String(String.UnicodeScalarView(text.unicodeScalars.filter { $0 != "\r" && $0 != "\n" }))
    }

    private static func needsEncoding(_ text: String) -> Bool {
        !text.utf8.allSatisfy { $0 >= 0x20 && $0 < 0x7F }
    }

    private static func isPlainAtomsPhrase(_ text: String) -> Bool {
        guard !text.isEmpty else { return false }
        if text.hasPrefix(" ") || text.hasSuffix(" ") { return false }
        if text.contains("  ") { return false }
        for ch in text where ch != " " {
            if !atextChars.contains(ch) { return false }
        }
        return true
    }

    private static func quotedString(_ text: String) -> String {
        var escaped = ""
        escaped.reserveCapacity(text.count + 2)
        for ch in text {
            if ch == "\"" || ch == "\\" { escaped.append("\\") }
            escaped.append(ch)
        }
        return "\"\(escaped)\""
    }

    /// Splits `text` into base64 RFC 2047 encoded-words, never splitting a
    /// Unicode scalar's UTF-8 byte sequence across two words: each scalar
    /// is checked whole against the remaining budget before being
    /// appended, so a chunk boundary can only ever fall between scalars.
    private static func encodedWords(for text: String) -> [String] {
        var words: [String] = []
        var currentBytes: [UInt8] = []
        currentBytes.reserveCapacity(maxPayloadBytesPerWord)

        func flush() {
            guard !currentBytes.isEmpty else { return }
            let b64 = Data(currentBytes).base64EncodedString()
            words.append("=?utf-8?B?\(b64)?=")
            currentBytes.removeAll(keepingCapacity: true)
        }

        for scalar in text.unicodeScalars {
            let scalarBytes = Array(String(scalar).utf8)
            if currentBytes.count + scalarBytes.count > maxPayloadBytesPerWord {
                flush()
            }
            currentBytes.append(contentsOf: scalarBytes)
        }
        flush()

        return words.isEmpty ? ["=?utf-8?B??="] : words
    }
}
