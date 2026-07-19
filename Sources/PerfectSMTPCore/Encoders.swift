//
//  Encoders.swift
//  PerfectSMTPCore
//
//  Base64 (76-column wrap) and quoted-printable content-transfer
//  encoders. See Documentation/swift6-nio-rewrite-plan.md §4.7's
//  charset/encoding default: UTF-8 always; quoted-printable for
//  non-ASCII text/plain and text/html parts, 7bit for pure-ASCII parts,
//  base64 for attachments/inline images.
//

import Foundation

public enum Encoders {
    /// Base64-encodes `data` and hard-wraps the result at `lineLength`
    /// characters (default 76, the traditional MIME limit), joined by
    /// CRLF. No trailing CRLF is appended — callers place this between
    /// MIME boundary markers, which supply their own separators.
    public static func base64Wrapped(_ data: Data, lineLength: Int = 76) -> String {
        let full = data.base64EncodedString()
        guard !full.isEmpty else { return "" }
        var lines: [Substring] = []
        var idx = full.startIndex
        while idx < full.endIndex {
            let end = full.index(idx, offsetBy: lineLength, limitedBy: full.endIndex) ?? full.endIndex
            lines.append(full[idx..<end])
            idx = end
        }
        return lines.joined(separator: "\r\n")
    }

    /// Quoted-printable encodes `text` per RFC 2045 §6.7: octets outside
    /// printable ASCII (33-126, plus space/tab except when trailing at
    /// end-of-line) are escaped as `=XX`; soft line breaks (`=\r\n`) are
    /// inserted so no output line exceeds `lineLength` characters. Line
    /// endings in `text` (bare `\n`, `\r`, or `\r\n`) are normalized to
    /// hard CRLF breaks in the output — quoted-printable never encodes an
    /// intentional line break itself, only Same-line content.
    public static func quotedPrintable(_ text: String, lineLength: Int = 76) -> String {
        let normalized = text
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
        let lines = normalized.components(separatedBy: "\n")
        return lines.map { encodeLineQP($0, lineLength: lineLength) }.joined(separator: "\r\n")
    }

    private static func encodeLineQP(_ line: String, lineLength: Int) -> String {
        let bytes = Array(line.utf8)
        var result = ""
        var col = 0
        for (i, byte) in bytes.enumerated() {
            let isLastByte = i == bytes.count - 1
            let token: String
            switch byte {
            case 0x09, 0x20: // tab, space — literal unless trailing at end of line
                token = isLastByte ? hexEscape(byte) : String(UnicodeScalar(byte))
            case 0x3D, 0x00...0x08, 0x0A...0x1F, 0x7F...0xFF:
                // '=' always escaped; controls and non-ASCII always escaped.
                token = hexEscape(byte)
            default:
                token = String(UnicodeScalar(byte))
            }
            // Reserve one column for the soft-break '=' itself.
            if col + token.count > lineLength - 1 {
                result += "=\r\n"
                col = 0
            }
            result += token
            col += token.count
        }
        return result
    }

    private static func hexEscape(_ byte: UInt8) -> String {
        let hex = String(byte, radix: 16, uppercase: true)
        return "=" + (hex.count < 2 ? "0" + hex : hex)
    }
}
