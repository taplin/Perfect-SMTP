//
//  SMTPReplyTests.swift
//  PerfectSMTPCoreTests
//
//  Enhanced-status parser and the 2/3/4/5yz classifier, including the
//  421-vs-greylist correction (plan §4.8/§5).
//

import Testing
@testable import PerfectSMTPCore

struct SMTPReplyTests {

    // MARK: - EnhancedStatusCode parsing

    @Test func parsesWellFormedToken() {
        let code = EnhancedStatusCode(parsing: "5.1.1")
        #expect(code == EnhancedStatusCode(clazz: 5, subject: 1, detail: 1))
    }

    @Test func rejectsMalformedTokens() {
        #expect(EnhancedStatusCode(parsing: "not-a-code") == nil)
        #expect(EnhancedStatusCode(parsing: "5.1") == nil)
        #expect(EnhancedStatusCode(parsing: "5.1.1.1") == nil)
    }

    @Test func replyDerivesEnhancedStatusFromLeadingTokenOfFirstLine() {
        let reply = SMTPReply(code: 550, lines: ["5.1.1 User unknown", "further detail"])
        #expect(reply.enhancedStatus == EnhancedStatusCode(clazz: 5, subject: 1, detail: 1))
    }

    @Test func replyHasNoEnhancedStatusWhenNotPresent() {
        let reply = SMTPReply(code: 250, lines: ["OK"])
        #expect(reply.enhancedStatus == nil)
    }

    // MARK: - replyClass: mechanical 2/3/4/5yz grouping

    @Test(arguments: [
        (250, ReplyClass.positiveCompletion),
        (211, ReplyClass.positiveCompletion),
        (354, ReplyClass.positiveIntermediate),
        (450, ReplyClass.transientNegative),
        (421, ReplyClass.transientNegative),
        (550, ReplyClass.permanentNegative),
        (999, ReplyClass.unknown),
    ])
    func replyClassIsMechanicallyDerivedFromCode(code: Int, expected: ReplyClass) {
        #expect(SMTPReply(code: code, lines: ["x"]).replyClass == expected)
    }

    // MARK: - SMTPError.classify: the 421-vs-greylist correction

    @Test func code421ClassifiesAsServiceUnavailableNotGreylisted() {
        let reply = SMTPReply(code: 421, lines: ["Service not available, closing channel"])
        guard case .serviceUnavailable(let r) = SMTPError.classify(reply) else {
            Issue.record("421 must classify as .serviceUnavailable, not .greylisted")
            return
        }
        #expect(r.code == 421)
    }

    @Test(arguments: [450, 451, 452])
    func greylistCodesClassifyAsGreylisted(code: Int) {
        let reply = SMTPReply(code: code, lines: ["try again later"])
        guard case .greylisted(let r) = SMTPError.classify(reply) else {
            Issue.record("\(code) must classify as .greylisted")
            return
        }
        #expect(r.code == code)
    }

    @Test func otherTransientCodesClassifyAsGenericTransientFailure() {
        let reply = SMTPReply(code: 432, lines: ["mailbox busy"])
        guard case .transientFailure(let r) = SMTPError.classify(reply) else {
            Issue.record("432 must classify as generic .transientFailure")
            return
        }
        #expect(r.code == 432)
    }

    @Test func permanentCodesClassifyAsPermanentFailure() {
        let reply = SMTPReply(code: 550, lines: ["5.1.1 no such user"])
        guard case .permanentFailure(let r) = SMTPError.classify(reply) else {
            Issue.record("550 must classify as .permanentFailure")
            return
        }
        #expect(r.code == 550)
    }
}
