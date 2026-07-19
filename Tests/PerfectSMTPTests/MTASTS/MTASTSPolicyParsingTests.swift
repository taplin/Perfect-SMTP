//
//  MTASTSPolicyParsingTests.swift
//  PerfectSMTPTests
//
//  Plan §9 Phase 4: `MTASTSPolicyParser.parse(_:)` unit tests -- valid
//  policies (each mode), malformed policies (fail safe, don't crash/throw),
//  matching this codebase's existing style for a pure, no-network parsing
//  function (`DKIMSignerTests`/`HeaderEncoderTests`'s style, adapted for
//  swift-testing's `@Test`/`#expect`).
//

import Testing
@testable import PerfectSMTP

struct MTASTSPolicyParsingTests {

    // MARK: - Valid policies, each mode

    @Test func parsesAWellFormedEnforcePolicy() throws {
        let text = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.mail.example.com\nmax_age: 604800\n"
        let policy = try #require(MTASTSPolicyParser.parse(text))
        #expect(policy.mode == .enforce)
        #expect(policy.mxPatterns == ["mail.example.com", "*.mail.example.com"])
        #expect(policy.maxAge == .seconds(604_800))
    }

    @Test func parsesAWellFormedTestingPolicy() throws {
        let text = "version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 86400\n"
        let policy = try #require(MTASTSPolicyParser.parse(text))
        #expect(policy.mode == .testing)
    }

    @Test func parsesAWellFormedNonePolicy() throws {
        let text = "version: STSv1\nmode: none\nmax_age: 3600\n"
        let policy = try #require(MTASTSPolicyParser.parse(text))
        #expect(policy.mode == .none)
        #expect(policy.mxPatterns.isEmpty)
    }

    @Test func toleratesCRLFLineEndingsAndTrailingWhitespace() throws {
        let text = "version: STSv1\r\nmode: enforce  \r\nmx: mail.example.com\r\nmax_age: 604800\r\n"
        let policy = try #require(MTASTSPolicyParser.parse(text))
        #expect(policy.mode == .enforce)
        #expect(policy.mxPatterns == ["mail.example.com"])
    }

    @Test func ignoresUnrecognizedKeysForForwardCompatibility() throws {
        let text = "version: STSv1\nmode: testing\nmax_age: 3600\nsome_future_key: some_future_value\n"
        let policy = try #require(MTASTSPolicyParser.parse(text))
        #expect(policy.mode == .testing)
    }

    @Test func ignoresBlankAndColonlessLinesRatherThanFailingTheWholeParse() throws {
        let text = "version: STSv1\n\nmode: testing\nthis line has no colon\nmax_age: 3600\n"
        let policy = try #require(MTASTSPolicyParser.parse(text))
        #expect(policy.mode == .testing)
    }

    // MARK: - Malformed policies: fail safe (nil, never throw/crash)

    @Test func missingVersionFailsSafe() {
        let text = "mode: enforce\nmx: mail.example.com\nmax_age: 604800\n"
        #expect(MTASTSPolicyParser.parse(text) == nil)
    }

    @Test func wrongVersionFailsSafe() {
        let text = "version: STSv2\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n"
        #expect(MTASTSPolicyParser.parse(text) == nil)
    }

    @Test func missingModeFailsSafe() {
        let text = "version: STSv1\nmx: mail.example.com\nmax_age: 604800\n"
        #expect(MTASTSPolicyParser.parse(text) == nil)
    }

    @Test func unrecognizedModeValueFailsSafe() {
        let text = "version: STSv1\nmode: strict\nmx: mail.example.com\nmax_age: 604800\n"
        #expect(MTASTSPolicyParser.parse(text) == nil)
    }

    @Test func missingMaxAgeFailsSafe() {
        let text = "version: STSv1\nmode: enforce\nmx: mail.example.com\n"
        #expect(MTASTSPolicyParser.parse(text) == nil)
    }

    @Test func nonNumericMaxAgeFailsSafe() {
        let text = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: not-a-number\n"
        #expect(MTASTSPolicyParser.parse(text) == nil)
    }

    @Test func negativeMaxAgeFailsSafe() {
        let text = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: -1\n"
        #expect(MTASTSPolicyParser.parse(text) == nil)
    }

    @Test func maxAgeAboveTheRFC8461UpperBoundFailsSafe() {
        let text = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: \(MTASTSPolicyParser.maximumMaxAgeSeconds + 1)\n"
        #expect(MTASTSPolicyParser.parse(text) == nil)
    }

    @Test func maxAgeExactlyAtTheRFC8461UpperBoundIsAccepted() throws {
        let text = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: \(MTASTSPolicyParser.maximumMaxAgeSeconds)\n"
        #expect(MTASTSPolicyParser.parse(text) != nil)
    }

    @Test func emptyStringFailsSafe() {
        #expect(MTASTSPolicyParser.parse("") == nil)
    }

    @Test func completelyUnrelatedTextFailsSafeRatherThanCrashing() {
        let text = "<html><body>this is not a policy file at all, it's an error page</body></html>"
        #expect(MTASTSPolicyParser.parse(text) == nil)
    }

    @Test func enforceModeWithNoMxLinesStillParsesEmptyMxPatterns() throws {
        // Not itself a wire-format violation -- `MTASTSPolicyParser` parses
        // the file as written; `DirectMXTransport`'s own `matchedHosts`
        // computation is what correctly treats an empty pattern list as
        // "no candidate host" for `enforce` mode (see
        // `DirectMXMTASTSEnforceTests`), not a rejection at parse time.
        let text = "version: STSv1\nmode: enforce\nmax_age: 604800\n"
        let policy = try #require(MTASTSPolicyParser.parse(text))
        #expect(policy.mxPatterns.isEmpty)
    }
}
