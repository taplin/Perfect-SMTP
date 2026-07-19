//
//  TestHelpers.swift
//  PerfectSMTPCoreTests
//

import Foundation
@testable import PerfectSMTPCore

/// A tiny, test-only mutable box for injecting deterministic MIME
/// boundaries into `MIMEComposer` (which otherwise generates random UUID-
/// based boundaries). Mirrors this ecosystem's established
/// `nonisolated(unsafe)`-style mock pattern (see Perfect-FileMaker's test
/// suite) — contained to a single-threaded synchronous test, never shared
/// across concurrent tasks.
final class SequentialBoundaries: @unchecked Sendable {
    private let values: [String]
    private var index = 0

    init(_ values: [String]) {
        self.values = values
    }

    func next() -> String {
        defer { index += 1 }
        return index < values.count ? values[index] : "overflow-boundary-\(index)"
    }
}

/// Decodes an RFC 2047 encoded-word header value (possibly folded across
/// multiple `=?utf-8?B?...?=` words joined by `"\r\n "`) back into its
/// original text, for round-trip assertions. Deliberately independent of
/// `HeaderEncoder`'s own implementation — this is a from-scratch decoder
/// so the round-trip test can't pass merely because both sides share a bug.
func decodeRFC2047(_ header: String) -> String {
    var payload = Data()
    for word in header.components(separatedBy: "\r\n ") {
        guard word.hasPrefix("=?utf-8?B?") || word.hasPrefix("=?UTF-8?B?"),
              word.hasSuffix("?=")
        else { continue }
        let start = word.index(word.startIndex, offsetBy: 10)
        let end = word.index(word.endIndex, offsetBy: -2)
        guard start <= end, let decoded = Data(base64Encoded: String(word[start..<end])) else { continue }
        payload.append(decoded)
    }
    return String(decoding: payload, as: UTF8.self)
}
