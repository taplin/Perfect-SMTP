//
//  PerfectSMTPStubTests.swift
//  PerfectSMTPTests
//
//  Phase 0's `PerfectSMTP` target is a re-export stub over
//  `PerfectSMTPCore` (see Sources/PerfectSMTP/PerfectSMTP.swift) — this
//  confirms the two-target split is real and buildable/testable, not just
//  a Package.swift declaration. Channel handlers, the connection pool, and
//  `SMTPMailer` land in Phase 1.
//

import Foundation
import Testing
import PerfectSMTP

struct PerfectSMTPStubTests {

    @Test func coreTypesAreVisibleThroughTheReExport() throws {
        var message = EmailMessage(from: EmailAddress(address: "ops@example.com"))
        message.textBody = "hi"

        let composed = try MIMEComposer(message).compose()
        #expect(!composed.headers.isEmpty)
        #expect(ReversePath.null.mailFromCommand == "MAIL FROM:<>")
    }
}
