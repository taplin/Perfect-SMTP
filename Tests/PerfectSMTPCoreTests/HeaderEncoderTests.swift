//
//  HeaderEncoderTests.swift
//  PerfectSMTPCoreTests
//
//  RFC 2047 correctness — Bug #2's actual fix. See
//  Documentation/swift6-nio-rewrite-plan.md §4.7/§5.
//

import Foundation
import Testing
@testable import PerfectSMTPCore

struct HeaderEncoderTests {

    // MARK: - Plain ASCII phrases

    @Test func plainAsciiPhraseIsEmittedBare() {
        #expect(HeaderEncoder.encodePhrase("Jane Doe") == "Jane Doe")
    }

    @Test func asciiPhraseWithCommaUsesQuotedStringNotEncodedWord() {
        let encoded = HeaderEncoder.encodePhrase("Smith, John")
        #expect(encoded == "\"Smith, John\"")
        #expect(!encoded.contains("=?"))
    }

    @Test func quotedStringEscapesBackslashAndQuote() {
        let encoded = HeaderEncoder.encodePhrase("Say \"hi\", \\friend\\")
        #expect(encoded == "\"Say \\\"hi\\\", \\\\friend\\\\\"")
    }

    // MARK: - Non-ASCII phrases -> encoded-word, never quoted-string

    @Test func nonAsciiPhraseIsBareEncodedWord() {
        let encoded = HeaderEncoder.encodePhrase("Rësumé")
        #expect(encoded.hasPrefix("=?utf-8?B?"))
        #expect(encoded.hasSuffix("?="))
        #expect(!encoded.hasPrefix("\""))
        #expect(decodeRFC2047(encoded) == "Rësumé")
    }

    @Test func displayNameMixingQuotesAndNonASCIIUsesEncodedWordOnly() {
        // Required test from plan §4.7: a display name mixing quotes and
        // non-ASCII content must use exactly one mechanism (encoded-word),
        // never a quoted-string wrapped around an encoded-word.
        let name = "\"Rëy\" Smith"
        let encoded = HeaderEncoder.encodePhrase(name)
        #expect(encoded.hasPrefix("=?utf-8?B?"))
        #expect(!encoded.hasPrefix("\"=?"))
        #expect(decodeRFC2047(encoded) == name)
    }

    @Test func encodedWordsNeverAppearInsideQuotedString() {
        let quoted = HeaderEncoder.encodePhrase("Smith, John")
        #expect(!quoted.contains("=?"))

        let encoded = HeaderEncoder.encodePhrase("Jos\u{e9}")
        #expect(!encoded.hasPrefix("\""))
    }

    // MARK: - Folding on character boundaries (never split a UTF-8 sequence)

    @Test func longNonASCIITextFoldsAcrossMultipleEncodedWordsWithoutCorruption() {
        // Each "€" is a 3-byte UTF-8 sequence. 40 of them = 120 bytes,
        // comfortably over one encoded-word's ~45-byte payload budget, so
        // this must fold into multiple words.
        let text = String(repeating: "\u{20AC}", count: 40)
        let encoded = HeaderEncoder.encodeUnstructured(text)
        let words = encoded.components(separatedBy: "\r\n ")
        #expect(words.count > 1)
        for word in words {
            #expect(word.hasPrefix("=?utf-8?B?"))
            #expect(word.hasSuffix("?="))
        }
        #expect(decodeRFC2047(encoded) == text)
    }

    @Test func foldingNeverSplitsAMultiByteScalarAcrossWords() {
        // A payload size chosen so a byte-oriented (not scalar-boundary)
        // fold would land mid-character: 15 "€" (3 bytes each) = 45 bytes,
        // exactly the per-word budget, followed by one more "€" that must
        // start a fresh word rather than being split.
        let text = String(repeating: "\u{20AC}", count: 16)
        let encoded = HeaderEncoder.encodeUnstructured(text)
        #expect(decodeRFC2047(encoded) == text)
        // Every word must itself be valid, independently-decodable base64
        // (i.e. never truncated mid-scalar) — Data(base64Encoded:) returns
        // nil for corrupt/truncated payloads.
        for word in encoded.components(separatedBy: "\r\n ") {
            let start = word.index(word.startIndex, offsetBy: 10)
            let end = word.index(word.endIndex, offsetBy: -2)
            #expect(Data(base64Encoded: String(word[start..<end])) != nil)
        }
    }

    // MARK: - Unstructured header values (Subject)

    @Test func asciiSubjectIsUnmodified() {
        #expect(HeaderEncoder.encodeUnstructured("Quarterly report") == "Quarterly report")
    }

    @Test func nonAsciiSubjectIsGenuinelyEncodedNotFakeQP() {
        let encoded = HeaderEncoder.encodeUnstructured("Rësúmé")
        // The old, broken implementation emitted this exact unescaped,
        // never-actually-encoded pattern. Assert it is NOT produced.
        #expect(encoded != "=?utf-8?Q?Rësúmé?=")
        #expect(encoded.hasPrefix("=?utf-8?B?"))
        #expect(decodeRFC2047(encoded) == "Rësúmé")
    }

    @Test func headerInjectionAttemptIsSanitized() {
        let encoded = HeaderEncoder.encodeUnstructured("Subject\r\nBcc: evil@example.com")
        #expect(!encoded.contains("\r"))
        #expect(!encoded.contains("\n"))
    }

    // MARK: - Address / address-list encoding

    @Test func addressWithoutDisplayNameIsJustTheAddrSpec() {
        let address = EmailAddress(address: "user@example.com")
        #expect(HeaderEncoder.encodeAddress(address) == "user@example.com")
    }

    @Test func addressWithPlainDisplayName() {
        let address = EmailAddress(displayName: "Jane Doe", address: "jane@example.com")
        #expect(HeaderEncoder.encodeAddress(address) == "Jane Doe <jane@example.com>")
    }

    @Test func addressListJoinsWithCommaSpace() {
        let list = [
            EmailAddress(address: "a@example.com"),
            EmailAddress(displayName: "B", address: "b@example.com"),
        ]
        #expect(HeaderEncoder.encodeAddressList(list) == "a@example.com, B <b@example.com>")
    }
}
