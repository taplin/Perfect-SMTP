//
//  BugRegressionTests.swift
//  PerfectSMTPCoreTests
//
//  First-class, named regressions for the two bugs this rewrite fixes
//  structurally (Documentation/swift6-nio-rewrite-plan.md §1, §4.7, §5):
//    Bug #1 — Bcc header leak.
//    Bug #2 — fake quoted-printable subject encoding.
//

import Foundation
import Testing
@testable import PerfectSMTPCore

struct BugRegressionTests {

    // MARK: - Bug #1: Bcc header leak

    @Test func bug1_bccAddressLivesOnlyInEnvelopeRecipientsNeverInAnyHeader() throws {
        let bccAddress = "hidden@example.com"

        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.subject = "Quarterly update"
        message.textBody = "hello"
        message.date = Date(timeIntervalSince1970: 1_700_000_000)
        message.messageID = "<fixed@example.com>"

        // EmailMessage has no `bcc` field at all — the caller-facing
        // `send(bcc:)` parameter (Phase 1) is what would place the Bcc
        // address here, directly in the envelope, never in the message.
        let envelope = SMTPEnvelope(
            mailFrom: .address("ops@example.com"),
            recipients: ["user@dest.com", bccAddress]
        )

        #expect(envelope.recipients.contains(bccAddress))

        let composed = try MIMEComposer(message).compose()
        let serialized = String(decoding: composed.serialized(), as: UTF8.self)

        #expect(!serialized.contains(bccAddress))
        #expect(!composed.headers.contains { $0.name.caseInsensitiveCompare("Bcc") == .orderedSame })
    }

    @Test func bug1_extraHeadersCannotReintroduceBccByName() {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello"
        message.extraHeaders = [("Bcc", "hidden@example.com")]

        #expect(throws: MIMEComposer.ComposerError.forbiddenHeader("Bcc")) {
            _ = try MIMEComposer(message).compose()
        }
    }

    @Test func bug1_extraHeadersDenylistIsCaseInsensitive() {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello"
        message.extraHeaders = [("bCC", "hidden@example.com")]

        #expect(throws: MIMEComposer.ComposerError.forbiddenHeader("bCC")) {
            _ = try MIMEComposer(message).compose()
        }
    }

    @Test(arguments: ["To", "Cc", "From", "Return-Path", "Sender"])
    func bug1_otherRoutingCriticalHeadersAreAlsoDenied(name: String) {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello"
        message.extraHeaders = [(name, "someone@example.com")]

        #expect(throws: MIMEComposer.ComposerError.forbiddenHeader(name)) {
            _ = try MIMEComposer(message).compose()
        }
    }

    // MARK: - Bug #2: fake quoted-printable subject encoding

    @Test func bug2_nonASCIISubjectIsGenuinelyEncodedNotFakeQP() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.subject = "Rësúmé"
        message.textBody = "hi"

        let composed = try MIMEComposer(message).compose()
        let subjectHeader = try #require(composed.headers.first { $0.name == "Subject" }?.value)

        // The old implementation's fallback branch emitted this exact
        // pattern: labeled quoted-printable but never actually encoded.
        // Assert it is not produced.
        #expect(subjectHeader != "=?utf-8?Q?Rësúmé?=")
        #expect(!subjectHeader.contains("é")) // no raw non-ASCII survives unescaped
        #expect(subjectHeader.hasPrefix("=?utf-8?B?"))
    }

    @Test func bug2_nonASCIISubjectRoundTripsCorrectly() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.subject = "Rësúmé — 中文 — emoji \u{1F600}"
        message.textBody = "hi"

        let composed = try MIMEComposer(message).compose()
        let subjectHeader = try #require(composed.headers.first { $0.name == "Subject" }?.value)

        #expect(decodeRFC2047(subjectHeader) == "Rësúmé — 中文 — emoji \u{1F600}")
    }

    @Test func bug2_asciiSubjectIsUnaffected() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.subject = "Quarterly update"
        message.textBody = "hi"

        let composed = try MIMEComposer(message).compose()
        let subjectHeader = try #require(composed.headers.first { $0.name == "Subject" }?.value)
        #expect(subjectHeader == "Quarterly update")
    }
}
