//
//  MXPatternMatcherTests.swift
//  PerfectSMTPTests
//
//  Plan §9 Phase 4: RFC 8461 §4.1's `mx:` pattern-matching rule, including
//  the "wildcard matches exactly one label" edge cases the RFC is precise
//  (and easy to get wrong) about.
//

import Testing
@testable import PerfectSMTP

struct MXPatternMatcherTests {

    @Test func exactPatternMatchesTheIdenticalHostname() {
        #expect(MXPatternMatcher.matches(pattern: "mail.example.com", host: "mail.example.com"))
    }

    @Test func exactPatternDoesNotMatchADifferentHostname() {
        #expect(!MXPatternMatcher.matches(pattern: "mail.example.com", host: "smtp.example.com"))
    }

    @Test func exactPatternMatchIsCaseInsensitive() {
        #expect(MXPatternMatcher.matches(pattern: "Mail.Example.COM", host: "mail.example.com"))
    }

    @Test func wildcardMatchesExactlyOneLabel() {
        #expect(MXPatternMatcher.matches(pattern: "*.mail.example.com", host: "mta1.mail.example.com"))
    }

    /// RFC 8461 §4.1's key precision: the wildcard covers exactly one
    /// label, never more -- `mta1.mta2` (two labels) must not satisfy
    /// `*.mail.example.com`.
    @Test func wildcardDoesNotMatchTwoLabelsCoveringMoreThanOne() {
        #expect(!MXPatternMatcher.matches(pattern: "*.mail.example.com", host: "mta1.mta2.mail.example.com"))
    }

    /// The wildcard requires a non-empty label -- it cannot match zero
    /// labels, so the bare suffix itself must not match.
    @Test func wildcardDoesNotMatchTheBareSuffixWithNoLabelAtAll() {
        #expect(!MXPatternMatcher.matches(pattern: "*.mail.example.com", host: "mail.example.com"))
    }

    @Test func wildcardDoesNotMatchAnUnrelatedDomain() {
        #expect(!MXPatternMatcher.matches(pattern: "*.mail.example.com", host: "mta1.mail.other.com"))
    }

    @Test func wildcardMatchIsCaseInsensitive() {
        #expect(MXPatternMatcher.matches(pattern: "*.MAIL.example.com", host: "mta1.mail.EXAMPLE.com"))
    }

    @Test func aBareWildcardWithEmptySuffixNeverMatches() {
        #expect(!MXPatternMatcher.matches(pattern: "*.", host: "anything.com"))
    }

    @Test func trailingDotOnEitherSideIsIgnored() {
        #expect(MXPatternMatcher.matches(pattern: "mail.example.com.", host: "mail.example.com"))
        #expect(MXPatternMatcher.matches(pattern: "mail.example.com", host: "mail.example.com."))
        #expect(MXPatternMatcher.matches(pattern: "*.mail.example.com.", host: "mta1.mail.example.com"))
    }

    @Test func aHostSharingOnlyATextualSuffixNotADotDelimitedLabelSuffixDoesNotMatch() {
        // "notmail.example.com" contains "mail.example.com" as a raw
        // *substring* but is not `*.mail.example.com` under label-aware
        // matching (its one leading label is "notmail", not something
        // ending in a "mail" label followed by a dot) -- must not match.
        #expect(!MXPatternMatcher.matches(pattern: "*.mail.example.com", host: "notmail.example.com"))
    }
}
