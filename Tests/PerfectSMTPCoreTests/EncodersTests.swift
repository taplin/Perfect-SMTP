//
//  EncodersTests.swift
//  PerfectSMTPCoreTests
//

import Foundation
import Testing
@testable import PerfectSMTPCore

struct EncodersTests {

    // MARK: - base64Wrapped: 76-column wrap

    @Test func base64WrapAt76ColumnsAndRoundTrips() {
        let data = Data((0..<200).map { UInt8($0 % 256) })
        let wrapped = Encoders.base64Wrapped(data)
        let lines = wrapped.components(separatedBy: "\r\n")

        for line in lines.dropLast() {
            #expect(line.count == 76)
        }
        #expect((lines.last?.count ?? 0) <= 76)

        let rejoined = lines.joined()
        #expect(Data(base64Encoded: rejoined) == data)
    }

    @Test func base64WrapOfEmptyDataIsEmptyString() {
        #expect(Encoders.base64Wrapped(Data()) == "")
    }

    @Test func base64WrapOfShortDataIsSingleUnwrappedLine() {
        let data = Data("hi".utf8)
        #expect(Encoders.base64Wrapped(data) == "aGk=")
    }

    // MARK: - quotedPrintable

    @Test func quotedPrintableEscapesNonASCIIAndEqualsSign() {
        let encoded = Encoders.quotedPrintable("Caf\u{e9} costs 100% = great")
        #expect(encoded.contains("=C3=A9")) // é in UTF-8 is 0xC3 0xA9
        #expect(encoded.contains("=3D")) // literal '=' must always be escaped
        #expect(!encoded.contains("\u{e9}")) // raw non-ASCII must never appear literally
    }

    @Test func quotedPrintableLeavesPureASCIIMostlyUnescaped() {
        let encoded = Encoders.quotedPrintable("hello world")
        #expect(encoded == "hello world")
    }

    @Test func quotedPrintableEscapesTrailingWhitespaceOnly() {
        // Trailing space/tab before a line break must be escaped (else
        // many mail clients/transports strip it); mid-line space/tab must
        // not be.
        let encoded = Encoders.quotedPrintable("a b \nc")
        let lines = encoded.components(separatedBy: "\r\n")
        #expect(lines[0] == "a b=20")
        #expect(lines[1] == "c")
    }

    @Test func quotedPrintableWrapsLongLinesWithSoftBreaks() {
        let text = String(repeating: "a", count: 200)
        let encoded = Encoders.quotedPrintable(text)
        for line in encoded.components(separatedBy: "\r\n") {
            #expect(line.count <= 76)
        }
        // Soft-broken segments end in '=' (the break marker) except the
        // final segment.
        let segments = encoded.components(separatedBy: "\r\n")
        for segment in segments.dropLast() {
            #expect(segment.hasSuffix("="))
        }
    }
}
