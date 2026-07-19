//
//  MIMEComposerTests.swift
//  PerfectSMTPCoreTests
//
//  Golden fixtures for the multipart shape from plan §4.7:
//    multipart/mixed [ multipart/related [ multipart/alternative [
//      text/plain, text/html ], inline CID images ], attachments ]
//  with empty layers collapsed.
//

import Foundation
import Testing
@testable import PerfectSMTPCore

private let fixedDate = Date(timeIntervalSince1970: 1_700_000_000) // 2023-11-14T22:13:20Z

struct MIMEComposerTests {

    // MARK: - Golden fixture: single leaf (no alternative/related/mixed)

    @Test func singlePlainTextBodyIsNotWrappedInAnyMultipart() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.subject = "Hello"
        message.textBody = "hello world"
        message.date = fixedDate
        message.messageID = "<fixed@example.com>"

        let composed = try MIMEComposer(message).compose()

        #expect(header(composed, "Content-Type") == "text/plain; charset=utf-8")
        #expect(header(composed, "Content-Transfer-Encoding") == "7bit")
        #expect(String(decoding: composed.body, as: UTF8.self) == "hello world")
        #expect(!String(decoding: composed.body, as: UTF8.self).contains("multipart"))
    }

    // MARK: - Golden fixture: multipart/alternative only

    @Test func textAndHtmlBodyProducesExactAlternativeStructure() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.subject = "Hello"
        message.textBody = "hello"
        message.htmlBody = "<p>hello</p>"
        message.date = fixedDate
        message.messageID = "<fixed@example.com>"

        let boundaries = SequentialBoundaries(["ALT"])
        let composed = try MIMEComposer(message, boundaryGenerator: boundaries.next).compose()

        #expect(header(composed, "Content-Type") == "multipart/alternative; boundary=\"ALT\"")

        let expectedBody =
            "--ALT\r\n" +
            "Content-Type: text/plain; charset=utf-8\r\n" +
            "Content-Transfer-Encoding: 7bit\r\n\r\n" +
            "hello\r\n" +
            "--ALT\r\n" +
            "Content-Type: text/html; charset=utf-8\r\n" +
            "Content-Transfer-Encoding: 7bit\r\n\r\n" +
            "<p>hello</p>\r\n" +
            "--ALT--\r\n"
        #expect(String(decoding: composed.body, as: UTF8.self) == expectedBody)
    }

    // MARK: - Golden fixture: multipart/mixed with a single body + one attachment (no related)

    @Test func textBodyPlusAttachmentProducesExactMixedStructureWithNoRelated() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hi"
        message.attachments = [Attachment(filename: "a.txt", contentType: "text/plain", data: Data("hi".utf8))]
        message.date = fixedDate
        message.messageID = "<fixed@example.com>"

        let boundaries = SequentialBoundaries(["MIX"])
        let composed = try MIMEComposer(message, boundaryGenerator: boundaries.next).compose()

        #expect(header(composed, "Content-Type") == "multipart/mixed; boundary=\"MIX\"")

        let expectedBody =
            "--MIX\r\n" +
            "Content-Type: text/plain; charset=utf-8\r\n" +
            "Content-Transfer-Encoding: 7bit\r\n\r\n" +
            "hi\r\n" +
            "--MIX\r\n" +
            "Content-Type: text/plain; name=\"a.txt\"\r\n" +
            "Content-Transfer-Encoding: base64\r\n" +
            "Content-Disposition: attachment; filename=\"a.txt\"\r\n\r\n" +
            "aGk=\r\n" +
            "--MIX--\r\n"
        #expect(String(decoding: composed.body, as: UTF8.self) == expectedBody)
        // No related layer since there are no inline images.
        #expect(!String(decoding: composed.body, as: UTF8.self).contains("multipart/related"))
    }

    // MARK: - Golden fixture: full nesting, mixed[related[alternative[...],inline],attachments]

    @Test func fullNestingProducesMixedContainingRelatedContainingAlternative() throws {
        var message = EmailMessage(from: EmailAddress(displayName: "Ops", address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.subject = "Test"
        message.textBody = "hello"
        message.htmlBody = "<p>hello</p>"
        message.inlineImages = [
            InlineResource(contentID: "img1", contentType: "image/png", data: Data([0, 1, 2])),
        ]
        message.attachments = [
            Attachment(filename: "a.txt", contentType: "text/plain", data: Data("hi".utf8)),
        ]
        message.date = fixedDate
        message.messageID = "<fixed@example.com>"

        let boundaries = SequentialBoundaries(["ALT", "REL", "MIX"])
        let composed = try MIMEComposer(message, boundaryGenerator: boundaries.next).compose()
        let body = String(decoding: composed.body, as: UTF8.self)

        #expect(header(composed, "Content-Type") == "multipart/mixed; boundary=\"MIX\"")

        // Structural nesting order: MIX opens, then REL nested inside it,
        // then ALT nested inside REL, then the inline image inside REL
        // (after the alternative), then the attachment inside MIX (after
        // the related group), then both closing boundaries in the right
        // order.
        let mixOpen = try #require(body.range(of: "--MIX\r\n"))
        let relatedHeader = try #require(body.range(of: "Content-Type: multipart/related; boundary=\"REL\""))
        let altHeader = try #require(body.range(of: "Content-Type: multipart/alternative; boundary=\"ALT\""))
        let altClose = try #require(body.range(of: "--ALT--\r\n"))
        let inlineID = try #require(body.range(of: "Content-ID: <img1>"))
        let relClose = try #require(body.range(of: "--REL--\r\n"))
        let attachmentDisposition = try #require(body.range(of: "Content-Disposition: attachment; filename=\"a.txt\""))
        let mixClose = try #require(body.range(of: "--MIX--\r\n"))

        #expect(mixOpen.lowerBound < relatedHeader.lowerBound)
        #expect(relatedHeader.lowerBound < altHeader.lowerBound)
        #expect(altHeader.lowerBound < altClose.lowerBound)
        #expect(altClose.lowerBound < inlineID.lowerBound)
        #expect(inlineID.lowerBound < relClose.lowerBound)
        #expect(relClose.lowerBound < attachmentDisposition.lowerBound)
        #expect(attachmentDisposition.lowerBound < mixClose.lowerBound)

        #expect(body.contains("hello"))
        #expect(body.contains("<p>hello</p>"))
        #expect(body.contains("AAEC")) // base64 of the inline image bytes [0,1,2]
        #expect(body.contains("aGk=")) // base64 of the attachment "hi"
    }

    // MARK: - Layer collapsing

    @Test func noInlineImagesDropsRelatedLayer() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello"
        message.htmlBody = "<p>hello</p>"
        message.attachments = [Attachment(filename: "a.txt", contentType: "text/plain", data: Data("hi".utf8))]

        let composed = try MIMEComposer(message).compose()
        let body = String(decoding: composed.body, as: UTF8.self)
        #expect(!body.contains("multipart/related"))
        #expect(body.contains("multipart/alternative"))
    }

    @Test func noAttachmentsDropsMixedLayer() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello"
        message.inlineImages = [InlineResource(contentID: "img1", contentType: "image/png", data: Data([0, 1]))]

        let composed = try MIMEComposer(message).compose()
        #expect(header(composed, "Content-Type")?.hasPrefix("multipart/related") == true)
        let body = String(decoding: composed.body, as: UTF8.self)
        #expect(!body.contains("multipart/mixed"))
    }

    @Test func singleBodyDropsAlternativeLayer() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hello only"

        let composed = try MIMEComposer(message).compose()
        #expect(header(composed, "Content-Type") == "text/plain; charset=utf-8")
        #expect(!String(decoding: composed.body, as: UTF8.self).contains("multipart"))
    }

    // MARK: - Non-ASCII body uses quoted-printable, ASCII uses 7bit

    @Test func nonASCIITextBodyUsesQuotedPrintable() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "Caf\u{e9}"

        let composed = try MIMEComposer(message).compose()
        #expect(header(composed, "Content-Transfer-Encoding") == "quoted-printable")
        #expect(String(decoding: composed.body, as: UTF8.self) == "Caf=C3=A9")
    }

    // MARK: - Date / Message-ID auto-synthesis

    @Test func dateAndMessageIDAreAutoSynthesizedWhenNil() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hi"
        // date/messageID intentionally left nil.

        let composed = try MIMEComposer(message).compose()
        let dateHeader = try #require(header(composed, "Date"))
        let messageIDHeader = try #require(header(composed, "Message-ID"))

        #expect(!dateHeader.isEmpty)
        #expect(messageIDHeader.hasPrefix("<"))
        #expect(messageIDHeader.hasSuffix("@example.com>")) // scoped to from's domain, see doc comment
    }

    @Test func explicitDateAndMessageIDAreNotOverwritten() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hi"
        message.date = fixedDate
        message.messageID = "<explicit-id@caller.example>"

        let composed = try MIMEComposer(message).compose()
        #expect(header(composed, "Message-ID") == "<explicit-id@caller.example>")
        #expect(header(composed, "Date") == MIMEComposer.rfc5322DateString(fixedDate))
    }

    // MARK: - Validation errors

    @Test func missingBodyThrows() {
        let message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        #expect(throws: MIMEComposer.ComposerError.missingBody) {
            _ = try MIMEComposer(message).compose()
        }
    }

    @Test func headerValueWithEmbeddedNewlineThrows() {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hi"
        message.extraHeaders = [("X-Custom", "line1\nline2")]
        #expect(throws: MIMEComposer.ComposerError.invalidHeaderValue("X-Custom")) {
            _ = try MIMEComposer(message).compose()
        }
    }
}

private func header(_ message: RFC5322Message, _ name: String) -> String? {
    message.headers.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.value
}
