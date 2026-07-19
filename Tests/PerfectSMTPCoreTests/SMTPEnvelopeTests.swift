//
//  SMTPEnvelopeTests.swift
//  PerfectSMTPCoreTests
//

import Testing
@testable import PerfectSMTPCore

struct SMTPEnvelopeTests {

    @Test func nullReversePathSerializesToExactlyMailFromEmptyAngleBrackets() {
        // Required test, plan §4.7/§5, RFC 5321 §4.5.5.
        #expect(ReversePath.null.mailFromCommand == "MAIL FROM:<>")
    }

    @Test func addressReversePathSerializesWithAddress() {
        #expect(ReversePath.address("bounce@example.com").mailFromCommand == "MAIL FROM:<bounce@example.com>")
    }

    @Test func envelopeRecipientsCarriesArbitraryAddrSpecs() {
        let envelope = SMTPEnvelope(mailFrom: .null, recipients: ["a@example.com", "b@example.com"])
        #expect(envelope.recipients == ["a@example.com", "b@example.com"])
        #expect(envelope.mailFrom.mailFromCommand == "MAIL FROM:<>")
    }
}
