//
//  DKIMCanonicalizationTests.swift
//  PerfectSMTPCoreTests
//
//  RFC 6376 §3.4 canonicalization -- hand-verifiable against the RFC's
//  own rules (and, for the body cases, its own §3.4.5 worked example and
//  §3.4.3/§3.4.4's published empty-body hash constants), independent of
//  the signing/crypto layer. See Documentation/swift6-nio-rewrite-plan.md
//  §4.6 ("Get this byte-exact -- DKIM verification is unforgiving of
//  canonicalization bugs, this is the single easiest place to introduce a
//  subtle, hard-to-detect signing bug.").
//

import Crypto
import Foundation
import Testing
@testable import PerfectSMTPCore

struct DKIMCanonicalizationTests {

    // MARK: - Header canonicalization

    @Test func simpleHeaderReproducesNameColonSpaceValueExactly() {
        let result = DKIMCanonicalization.canonicalizeHeader(name: "From", value: "  Joe   SixPack  ", mode: .simple)
        // §3.4.1: "does not change header fields in any way ... presented
        // exactly as they are in the message" -- unchanged whitespace,
        // unchanged case.
        #expect(result == "From:   Joe   SixPack  \r\n")
    }

    @Test func relaxedHeaderLowercasesNameAndCollapsesAndTrimsWhitespace() {
        let result = DKIMCanonicalization.canonicalizeHeader(name: "From", value: "  Joe   SixPack  ", mode: .relaxed)
        #expect(result == "from:Joe SixPack\r\n")
    }

    @Test func relaxedHeaderUnfoldsAContinuationLineThenCollapsesTheJoinedWhitespace() {
        // A folded value the way `HeaderEncoder` actually produces one
        // (RFC 2047 continuation-word folding uses "\r\n " joins) --
        // representative of this signer's real input shape, not the raw
        // wire text. Hand-verified against RFC 6376 §3.4.2's algorithm:
        // unfold ("\r\n" before WSP is dropped, the WSP itself kept) then
        // collapse WSP runs to one SP, then trim.
        //   raw value (after "B: " template): "Y\t\r\n\tZ  "
        //   unfold -> "Y\t\tZ  "  (CRLF dropped, the two adjacent tabs remain)
        //   collapse -> " Y Z "  (colon-adjacent space from the template,
        //                         "Y", collapsed tabs -> one SP, "Z",
        //                         collapsed trailing spaces -> one SP)
        //   trim -> "Y Z"
        let result = DKIMCanonicalization.canonicalizeHeader(name: "B", value: "Y\t\r\n\tZ  ", mode: .relaxed)
        #expect(result == "b:Y Z\r\n")
    }

    @Test func relaxedHeaderLeavesASingleExistingSpaceUnchanged() {
        // Collapsing only ever *reduces* multi-character whitespace runs;
        // a lone single space that was already "a single SP" is left
        // exactly as-is, never stripped from the middle of a value.
        let result = DKIMCanonicalization.canonicalizeHeader(name: "Subject", value: "Is dinner ready?", mode: .relaxed)
        #expect(result == "subject:Is dinner ready?\r\n")
    }

    @Test func simpleHeaderPreservesAFoldedValueVerbatim() {
        let result = DKIMCanonicalization.canonicalizeHeader(name: "B", value: "Y\t\r\n\tZ  ", mode: .simple)
        #expect(result == "B: Y\t\r\n\tZ  \r\n")
    }

    // MARK: - Body canonicalization: RFC 6376 §3.4.5's own worked example

    /// The RFC's own body, reconstructed byte-for-byte from §3.4.5
    /// Example 1's bracketed notation:
    ///   <SP> C <SP><CRLF>
    ///   D <SP><HTAB><SP> E <CRLF>
    ///   <CRLF>
    ///   <CRLF>
    /// = " C \r\n" + "D \t E\r\n" + "\r\n" + "\r\n"
    private static let rfcExampleBody = Array(" C \r\nD \t E\r\n\r\n\r\n".utf8)

    @Test func relaxedBodyMatchesRFCWorkedExample() {
        // RFC 6376 §3.4.5 Example 1's published relaxed-canonicalized
        // body: " C\r\nD E\r\n" -- internal WSP runs collapsed, trailing
        // blank lines removed.
        let result = DKIMCanonicalization.canonicalizeBody(Self.rfcExampleBody, mode: .relaxed)
        #expect(String(decoding: result, as: UTF8.self) == " C\r\nD E\r\n")
    }

    @Test func simpleBodyMatchesRFCWorkedExample() {
        // RFC 6376 §3.4.5 Example 2's published simple-canonicalized body:
        // " C \r\nD \t E\r\n" -- whitespace inside the body is untouched,
        // only the trailing blank lines collapse to the single required
        // trailing CRLF.
        let result = DKIMCanonicalization.canonicalizeBody(Self.rfcExampleBody, mode: .simple)
        #expect(String(decoding: result, as: UTF8.self) == " C \r\nD \t E\r\n")
    }

    // MARK: - Body canonicalization: empty-body edge cases (§3.4.3/§3.4.4)

    @Test func simpleEmptyBodyCanonicalizesToASingleCRLFWithTheRFCsPublishedHash() {
        let result = DKIMCanonicalization.canonicalizeBody([], mode: .simple)
        #expect(result == [0x0D, 0x0A])
        let hash = Data(SHA256.hash(data: Data(result))).base64EncodedString()
        // RFC 6376 §3.4.3's own published SHA-256 of the canonicalized
        // empty body.
        #expect(hash == "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=")
    }

    @Test func relaxedEmptyBodyCanonicalizesToZeroBytesNotACRLF() {
        // The single easiest place to get this wrong (plan §4.6): unlike
        // `simple`, an empty (or all-blank-lines) body canonicalizes to a
        // *null input* under `relaxed`, not a CRLF.
        let result = DKIMCanonicalization.canonicalizeBody([], mode: .relaxed)
        #expect(result.isEmpty)
        let hash = Data(SHA256.hash(data: Data(result))).base64EncodedString()
        // RFC 6376 §3.4.4's own published SHA-256 of the canonicalized
        // (null) empty body -- this is just SHA-256("").
        #expect(hash == "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")
    }

    @Test func relaxedBodyOfOnlyBlankLinesAlsoCanonicalizesToZeroBytes() {
        // A body that is *entirely* blank lines is, per §3.4.4b ("ignore
        // all empty lines at the end of the message body"), indistinguishable
        // from an empty body once every line in it is "at the end".
        let result = DKIMCanonicalization.canonicalizeBody(Array("\r\n\r\n\r\n".utf8), mode: .relaxed)
        #expect(result.isEmpty)
    }

    @Test func simpleBodyWithNoTrailingCRLFGetsOneAdded() {
        let result = DKIMCanonicalization.canonicalizeBody(Array("abc".utf8), mode: .simple)
        #expect(String(decoding: result, as: UTF8.self) == "abc\r\n")
    }

    @Test func relaxedBodyWithNoTrailingCRLFGetsOneAdded() {
        let result = DKIMCanonicalization.canonicalizeBody(Array("abc".utf8), mode: .relaxed)
        #expect(String(decoding: result, as: UTF8.self) == "abc\r\n")
    }
}
