//
//  SMTPEnvelopeTests.swift
//  PerfectSMTPCoreTests
//

import Testing
@testable import PerfectSMTPCore

struct SMTPEnvelopeTests {

    @Test func nullReversePathSerializesToExactlyMailFromEmptyAngleBrackets() throws {
        // Required test, plan §4.7/§5, RFC 5321 §4.5.5.
        #expect(try ReversePath.null.mailFromCommand == "MAIL FROM:<>")
    }

    @Test func addressReversePathSerializesWithAddress() throws {
        #expect(try ReversePath.address("bounce@example.com").mailFromCommand == "MAIL FROM:<bounce@example.com>")
    }

    @Test func envelopeRecipientsCarriesArbitraryAddrSpecs() throws {
        let envelope = try SMTPEnvelope(mailFrom: .null, recipients: ["a@example.com", "b@example.com"])
        #expect(envelope.recipients == ["a@example.com", "b@example.com"])
        #expect(try envelope.mailFrom.mailFromCommand == "MAIL FROM:<>")
    }

    // MARK: - Milestone review finding #5: MAIL FROM / RCPT TO command injection

    @Test func mailFromCommandInjectionAttemptThrows() {
        // Repro from the security review: RFC 5321 §4.1.2's addr-spec
        // grammar forbids CR/LF in a mailbox — this is SMTP *command*
        // injection, not just header injection.
        let injected = ReversePath.address("victim@example.com>\r\nRCPT TO:<attacker@evil.com")
        #expect(throws: HeaderEncoder.HeaderInjectionError.self) {
            _ = try injected.mailFromCommand
        }
    }

    @Test func envelopeRecipientsRejectsInjectionAttempt() {
        #expect(throws: HeaderEncoder.HeaderInjectionError.self) {
            _ = try SMTPEnvelope(
                mailFrom: .null,
                recipients: ["user@example.com", "victim@example.com>\r\nRCPT TO:<attacker@evil.com"]
            )
        }
    }

    // MARK: - FIX #2 (milestone review, security pass, CWE-88): sendmail/
    // postfix argument-injection via a leading `-` in an address. Confirmed
    // independently by three of the four reviews -- `LocalMTATransport`
    // passes `ReversePath.address`/`SMTPEnvelope.recipients` entries as bare
    // `Process.arguments` elements, and a `getopt`-style argv parser treats
    // any argument starting with `-` as a flag, not a literal address (the
    // CVE-2016-10033/10045-class vulnerability). Layer 1 of the two-layer
    // defense: reject at construction time, before the value ever reaches a
    // transport. Layer 2 (a `"--"` end-of-options separator in the
    // constructed argv) is tested in `LocalMTATransportTests.swift`.

    @Test func mailFromLeadingHyphenAddressThrows() {
        let leadingHyphen = ReversePath.address("-oQ/tmp/evilqueue@example.com")
        #expect(throws: HeaderEncoder.HeaderInjectionError.self) {
            _ = try leadingHyphen.mailFromCommand
        }
    }

    @Test func envelopeRecipientsRejectsLeadingHyphenAddress() {
        #expect(throws: HeaderEncoder.HeaderInjectionError.self) {
            _ = try SMTPEnvelope(
                mailFrom: .null,
                recipients: ["user@example.com", "-C/tmp/attacker.cf"]
            )
        }
    }

    @Test func leadingHyphenIsRejectedEvenWithoutAnyControlCharacters() {
        // Specifically distinct from the control-character injection check
        // above: a leading `-` is an entirely ordinary, printable,
        // control-character-free string. It must still be rejected on its
        // own, not only when combined with a control-character injection
        // attempt.
        let leadingHyphenOnly = ReversePath.address("-innocuous-looking-but-starts-with-a-dash@example.com")
        #expect(throws: HeaderEncoder.HeaderInjectionError.self) {
            _ = try leadingHyphenOnly.mailFromCommand
        }
    }
}
