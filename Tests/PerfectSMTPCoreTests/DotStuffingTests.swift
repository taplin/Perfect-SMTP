//
//  DotStuffingTests.swift
//  PerfectSMTPCoreTests
//
//  RFC 5321 §4.5.2 transparency: leading-dot doubling, terminal `.\r\n`.
//

import Testing
@testable import PerfectSMTPCore

struct DotStuffingTests {

    @Test func doublesLeadingDotsAndAppendsTerminator() {
        let input = Array("Hello\r\n.World\r\n..Test\r\nEnd".utf8)
        let output = String(decoding: DotStuffing.encode(input), as: UTF8.self)
        #expect(output == "Hello\r\n..World\r\n...Test\r\nEnd\r\n.\r\n")
    }

    @Test func doesNotTouchDotsNotAtLineStart() {
        let input = Array("a.b.c\r\n".utf8)
        let output = String(decoding: DotStuffing.encode(input), as: UTF8.self)
        #expect(output == "a.b.c\r\n.\r\n")
    }

    @Test func doesNotDoubleTrailingCRLFBeforeTerminator() {
        let input = Array("Hello\r\n".utf8)
        let output = String(decoding: DotStuffing.encode(input), as: UTF8.self)
        #expect(output == "Hello\r\n.\r\n")
    }

    @Test func addsMissingTrailingCRLFBeforeTerminator() {
        let input = Array("Hello".utf8) // no trailing CRLF at all
        let output = String(decoding: DotStuffing.encode(input), as: UTF8.self)
        #expect(output == "Hello\r\n.\r\n")
    }

    @Test func onlyLeadingDotOfEachLineIsDoubledNotEveryDot() {
        let input = Array(".a.b.c\r\n".utf8)
        let output = String(decoding: DotStuffing.encode(input), as: UTF8.self)
        #expect(output == "..a.b.c\r\n.\r\n")
    }
}
