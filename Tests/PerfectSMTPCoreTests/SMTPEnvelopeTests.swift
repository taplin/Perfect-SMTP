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
}
