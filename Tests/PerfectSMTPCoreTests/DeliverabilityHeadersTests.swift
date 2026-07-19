//
//  DeliverabilityHeadersTests.swift
//  PerfectSMTPCoreTests
//
//  Phase 5, Part 1: List-Unsubscribe/-Post (RFC 8058) and
//  Precedence/Auto-Submitted (RFC 3834-adjacent) header emission. See
//  Documentation/swift6-nio-rewrite-plan.md §7/§9's Phase 5 bullet.
//

import Foundation
import Testing
@testable import PerfectSMTPCore

struct DeliverabilityHeadersTests {

    // MARK: - List-Unsubscribe / List-Unsubscribe-Post

    @Test func bothMailtoAndURLPresentProduceOneCommaSeparatedHeader() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(mailto: "unsub@example.com", url: "https://example.com/unsub?id=123")

        let composed = try MIMEComposer(message).compose()
        let header = try #require(composed.headers.first { $0.name == "List-Unsubscribe" }?.value)
        #expect(header == "<mailto:unsub@example.com>, <https://example.com/unsub?id=123>")
    }

    @Test func onlyMailtoPresentEmitsJustTheMailtoEntry() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(mailto: "unsub@example.com")

        let composed = try MIMEComposer(message).compose()
        let header = try #require(composed.headers.first { $0.name == "List-Unsubscribe" }?.value)
        #expect(header == "<mailto:unsub@example.com>")
        #expect(!composed.headers.contains { $0.name == "List-Unsubscribe-Post" })
    }

    @Test func onlyURLPresentEmitsJustTheURLEntry() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(url: "https://example.com/unsub?id=123")

        let composed = try MIMEComposer(message).compose()
        let header = try #require(composed.headers.first { $0.name == "List-Unsubscribe" }?.value)
        #expect(header == "<https://example.com/unsub?id=123>")
    }

    @Test func neitherMailtoNorURLPresentEmitsNoHeaderAtAll() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe()

        let composed = try MIMEComposer(message).compose()
        #expect(!composed.headers.contains { $0.name == "List-Unsubscribe" })
        #expect(!composed.headers.contains { $0.name == "List-Unsubscribe-Post" })
    }

    @Test func postOneClickTrueWithURLEmitsTheFixedLiteralHeader() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(
            mailto: "unsub@example.com",
            url: "https://example.com/unsub?id=123",
            postOneClick: true
        )

        let composed = try MIMEComposer(message).compose()
        let header = try #require(composed.headers.first { $0.name == "List-Unsubscribe-Post" }?.value)
        #expect(header == "List-Unsubscribe=One-Click")
    }

    @Test func postOneClickFalseNeverEmitsTheDashPostHeader() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(
            mailto: "unsub@example.com",
            url: "https://example.com/unsub?id=123",
            postOneClick: false
        )

        let composed = try MIMEComposer(message).compose()
        #expect(!composed.headers.contains { $0.name == "List-Unsubscribe-Post" })
    }

    @Test func postOneClickTrueWithNoURLThrowsRatherThanSilentlyOmitting() {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(mailto: "unsub@example.com", postOneClick: true)

        #expect(throws: MIMEComposer.ComposerError.postOneClickRequiresURL) {
            _ = try MIMEComposer(message).compose()
        }
    }

    // MARK: - CRLF-injection rejection (extends Phase 0's bug-regression style)

    @Test func mailtoCRLFInjectionAttemptIsRejected() {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(mailto: "unsub@example.com\r\nBcc: attacker@evil.com")

        #expect(throws: MIMEComposer.ComposerError.invalidHeaderValue("listUnsubscribe.mailto")) {
            _ = try MIMEComposer(message).compose()
        }
    }

    @Test func urlCRLFInjectionAttemptIsRejected() {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(url: "https://example.com/unsub\r\nBcc: attacker@evil.com")

        #expect(throws: MIMEComposer.ComposerError.invalidHeaderValue("listUnsubscribe.url")) {
            _ = try MIMEComposer(message).compose()
        }
    }

    @Test func injectionAttemptNeverProducesASerializedLiveBccHeader() {
        // The stronger, end-to-end assertion (matching BugRegressionTests'
        // own style): composition throws before anything is serialized, so
        // there's no live message to inspect at all -- the old Bcc-leak
        // bug's defining characteristic was that composition *succeeded*.
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.listUnsubscribe = ListUnsubscribe(mailto: "unsub@example.com\r\nBcc: attacker@evil.com")

        #expect(throws: (any Error).self) {
            _ = try MIMEComposer(message).compose()
        }
    }

    // MARK: - Precedence / Auto-Submitted

    @Test(arguments: [Precedence.bulk, .list, .junk])
    func eachPrecedenceValueEmitsItsRawValue(precedence: Precedence) throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.precedence = precedence

        let composed = try MIMEComposer(message).compose()
        let header = try #require(composed.headers.first { $0.name == "Precedence" }?.value)
        #expect(header == precedence.rawValue)
    }

    @Test(arguments: [AutoSubmitted.autoGenerated, .autoReplied, .autoNotified])
    func eachAutoSubmittedValueEmitsItsRawValue(autoSubmitted: AutoSubmitted) throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.autoSubmitted = autoSubmitted

        let composed = try MIMEComposer(message).compose()
        let header = try #require(composed.headers.first { $0.name == "Auto-Submitted" }?.value)
        #expect(header == autoSubmitted.rawValue)
    }

    @Test func precedenceAndAutoSubmittedBothSetTogetherEmitBothHeaders() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"
        message.precedence = .bulk
        message.autoSubmitted = .autoGenerated

        let composed = try MIMEComposer(message).compose()
        #expect(composed.headers.first { $0.name == "Precedence" }?.value == "bulk")
        #expect(composed.headers.first { $0.name == "Auto-Submitted" }?.value == "auto-generated")
    }

    @Test func neitherPrecedenceNorAutoSubmittedSetEmitsNeitherHeader() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.to = [EmailAddress(address: "user@dest.com")]
        message.textBody = "hello"

        let composed = try MIMEComposer(message).compose()
        #expect(!composed.headers.contains { $0.name == "Precedence" })
        #expect(!composed.headers.contains { $0.name == "Auto-Submitted" })
    }
}
