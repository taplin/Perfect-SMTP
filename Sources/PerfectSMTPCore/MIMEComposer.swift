//
//  MIMEComposer.swift
//  PerfectSMTPCore
//
//  Builds the multipart shape from plan §4.7:
//    multipart/mixed [ multipart/related [ multipart/alternative [
//      text/plain, text/html ], inline CID images ], attachments ]
//  with empty layers collapsed (no attachments -> drop mixed; no inline
//  images -> drop related; single body -> drop alternative).
//

import Foundation

/// Internal MIME tree node. Not part of the public API — composition
/// collapses this into a flat `RFC5322Message` (top-level headers +
/// serialized body).
private struct MIMEPart {
    enum Body {
        case leaf([UInt8])
        indirect case multipart(boundary: String, parts: [MIMEPart])
    }
    var headers: [(name: String, value: String)]
    var body: Body
}

public struct MIMEComposer: Sendable {
    public enum ComposerError: Error, Sendable, Equatable {
        /// Neither `textBody` nor `htmlBody` was set — there is nothing to
        /// send as the primary content.
        case missingBody
        /// `extraHeaders` contained a name on `forbiddenExtraHeaderNames`
        /// — the reintroduction vector the Bug #1 fix closes.
        case forbiddenHeader(String)
        /// A header value (from `extraHeaders` or elsewhere) contained a
        /// raw CR or LF that survived sanitization — should not happen in
        /// practice since `sanitizeForHeader`-style stripping is applied
        /// upstream, but composition fails loudly rather than silently
        /// emitting a malformed header.
        case invalidHeaderValue(String)
    }

    /// Case-insensitive denylist of header names `extraHeaders` may never
    /// use — envelope/routing-critical names, and names this composer
    /// already manages itself. Per plan §4.7: "strip/reject `Bcc`, `To`,
    /// `Cc`, `From`, `Return-Path`, and other envelope/routing-critical
    /// header names at composition time." This composer rejects (throws)
    /// rather than silently stripping, so a caller that tries to smuggle
    /// one of these back in gets a hard failure, not a quietly-dropped
    /// header.
    public static let forbiddenExtraHeaderNames: Set<String> = [
        "bcc", "to", "cc", "from", "sender", "reply-to", "return-path",
        "received", "message-id", "date", "mime-version", "content-type",
        "content-transfer-encoding", "content-disposition", "dkim-signature",
    ]

    public let message: EmailMessage
    public let charset: String
    private let messageIDDomain: String?
    private let boundaryGenerator: @Sendable () -> String
    private let now: @Sendable () -> Date

    /// - Parameters:
    ///   - messageIDDomain: Domain used to scope an auto-synthesized
    ///     `Message-ID` when `message.messageID` is nil. Phase 0 has no
    ///     DKIM `d=`/envelope-from to scope to yet (that's wired up in
    ///     Phase 1/2), so when this is left nil the composer falls back to
    ///     the domain portion of `message.from.address` — the closest
    ///     "coherent" domain actually available at this phase. Callers
    ///     (and later phases) may override explicitly.
    ///   - boundaryGenerator: Produces MIME boundary strings; overridable
    ///     for deterministic golden-fixture tests.
    ///   - charset: Overrides `message.charset` when non-nil. `EmailMessage`
    ///     already carries its own `charset` field (plan §4.7, mirroring
    ///     Lasso's per-send `-characterSet`), which is what's actually used
    ///     for encoding text parts when this parameter is left nil — the
    ///     default. This parameter exists to match the plan §4.9 two-phase
    ///     API sketch (`MIMEComposer(msg, charset: "utf-8").compose()`)
    ///     while keeping `message.charset` as the single source of truth
    ///     for the common case where a caller doesn't need to override it
    ///     independently of the message itself.
    public init(
        _ message: EmailMessage,
        charset: String? = nil,
        messageIDDomain: String? = nil,
        boundaryGenerator: @escaping @Sendable () -> String = MIMEComposer.defaultBoundaryGenerator,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.message = message
        self.charset = charset ?? message.charset
        self.messageIDDomain = messageIDDomain
        self.boundaryGenerator = boundaryGenerator
        self.now = now
    }

    public static func defaultBoundaryGenerator() -> String {
        "perfect-smtp-\(UUID().uuidString)"
    }

    /// Routes a caller-controlled string through `HeaderEncoder`'s shared
    /// `rejectHeaderInjection`, re-surfacing any control-character rejection
    /// as this composer's own `ComposerError.invalidHeaderValue` — the
    /// single call site every one of the milestone review's newly-covered
    /// fields (`extraHeaders` names, `messageID`, `inReplyTo`, `references`,
    /// attachment/inline `Content-Type`) goes through, so the fail-loud
    /// discipline stays centralized in `HeaderEncoder` rather than being
    /// re-implemented per field here.
    private static func requireNoInjection(_ value: String, field: String) throws {
        do {
            _ = try HeaderEncoder.rejectHeaderInjection(value, field: field)
        } catch is HeaderEncoder.HeaderInjectionError {
            throw ComposerError.invalidHeaderValue(field)
        }
    }

    public func compose() throws -> RFC5322Message {
        for (name, value) in message.extraHeaders {
            // Milestone review finding: the name was never checked for
            // CR/LF, only the value — a mangled name like
            // "X-Foo\r\nBcc" passed both the (name-based) denylist check
            // and the (CR/LF-free) value check, a total bypass of the
            // denylist that exists specifically to prevent this. Checked
            // first, before the denylist lookup, so a mangled name is
            // caught regardless of what it lowercases to.
            try Self.requireNoInjection(name, field: name)
            if Self.forbiddenExtraHeaderNames.contains(name.lowercased()) {
                throw ComposerError.forbiddenHeader(name)
            }
            try Self.requireNoInjection(value, field: name)
        }
        guard message.textBody != nil || message.htmlBody != nil else {
            throw ComposerError.missingBody
        }

        let top = try buildTopLevelPart()

        var headers: [(name: String, value: String)] = []
        headers.append(("From", try HeaderEncoder.encodeAddress(message.from)))
        if let sender = message.sender {
            headers.append(("Sender", try HeaderEncoder.encodeAddress(sender)))
        }
        if !message.replyTo.isEmpty {
            headers.append(("Reply-To", try HeaderEncoder.encodeAddressList(message.replyTo)))
        }
        if !message.to.isEmpty {
            headers.append(("To", try HeaderEncoder.encodeAddressList(message.to)))
        }
        if !message.cc.isEmpty {
            headers.append(("Cc", try HeaderEncoder.encodeAddressList(message.cc)))
        }

        headers.append(("Date", Self.rfc5322DateString(message.date ?? now())))
        if let messageID = message.messageID {
            // Only the caller-supplied case needs validating — the
            // synthesized fallback is a UUID plus a domain already
            // validated above via the "From" header's `encodeAddress`
            // call, so it can't carry an injection payload.
            try Self.requireNoInjection(messageID, field: "messageID")
            headers.append(("Message-ID", messageID))
        } else {
            headers.append(("Message-ID", synthesizeMessageID()))
        }

        if let inReplyTo = message.inReplyTo {
            try Self.requireNoInjection(inReplyTo, field: "inReplyTo")
            headers.append(("In-Reply-To", inReplyTo))
        }
        if !message.references.isEmpty {
            for reference in message.references {
                try Self.requireNoInjection(reference, field: "references")
            }
            headers.append(("References", message.references.joined(separator: " ")))
        }

        headers.append(("Subject", HeaderEncoder.encodeUnstructured(message.subject)))
        headers.append(contentsOf: Self.priorityHeaders(message.priority))

        headers.append(("MIME-Version", "1.0"))
        headers.append(contentsOf: top.headers)
        headers.append(contentsOf: message.extraHeaders)

        let body: [UInt8]
        switch top.body {
        case .leaf(let bytes):
            body = bytes
        case .multipart(let boundary, let parts):
            body = Self.serializeMultipart(boundary: boundary, parts: parts)
        }

        return RFC5322Message(headers: headers, body: body)
    }

    // MARK: - Tree construction

    private func buildTopLevelPart() throws -> MIMEPart {
        var bodyParts: [MIMEPart] = []
        if let text = message.textBody {
            bodyParts.append(textLeaf(text, subtype: "plain"))
        }
        if let html = message.htmlBody {
            bodyParts.append(textLeaf(html, subtype: "html"))
        }

        let alternativeOrSingle: MIMEPart
        if bodyParts.count > 1 {
            let boundary = boundaryGenerator()
            alternativeOrSingle = MIMEPart(
                headers: [("Content-Type", "multipart/alternative; boundary=\"\(boundary)\"")],
                body: .multipart(boundary: boundary, parts: bodyParts)
            )
        } else {
            alternativeOrSingle = bodyParts[0]
        }

        let relatedOrSingle: MIMEPart
        if !message.inlineImages.isEmpty {
            let boundary = boundaryGenerator()
            var parts = [alternativeOrSingle]
            parts.append(contentsOf: try message.inlineImages.map(inlineLeaf))
            relatedOrSingle = MIMEPart(
                headers: [("Content-Type", "multipart/related; boundary=\"\(boundary)\"")],
                body: .multipart(boundary: boundary, parts: parts)
            )
        } else {
            relatedOrSingle = alternativeOrSingle
        }

        if !message.attachments.isEmpty {
            let boundary = boundaryGenerator()
            var parts = [relatedOrSingle]
            parts.append(contentsOf: try message.attachments.map(attachmentLeaf))
            return MIMEPart(
                headers: [("Content-Type", "multipart/mixed; boundary=\"\(boundary)\"")],
                body: .multipart(boundary: boundary, parts: parts)
            )
        }
        return relatedOrSingle
    }

    private func textLeaf(_ text: String, subtype: String) -> MIMEPart {
        let isASCII = text.utf8.allSatisfy { $0 < 0x80 }
        let cte: String
        let bodyString: String
        if isASCII {
            cte = "7bit"
            bodyString = normalizeLineEndings(text)
        } else {
            cte = "quoted-printable"
            bodyString = Encoders.quotedPrintable(text)
        }
        return MIMEPart(
            headers: [
                ("Content-Type", "text/\(subtype); charset=\(charset)"),
                ("Content-Transfer-Encoding", cte),
            ],
            body: .leaf(Array(bodyString.utf8))
        )
    }

    private func attachmentLeaf(_ attachment: Attachment) throws -> MIMEPart {
        // Milestone review finding: `contentType` was interpolated raw
        // into this part's own Content-Type header line — a value like
        // "text/plain\r\nX-Injected-CT: yes" injected an extra header
        // line inside the attachment's own part.
        try Self.requireNoInjection(attachment.contentType, field: "attachment.contentType")
        let disposition = attachment.disposition ?? message.defaultDisposition
        let name = sanitizedFilename(attachment.filename)
        return MIMEPart(
            headers: [
                ("Content-Type", "\(attachment.contentType); name=\"\(quotedParam(name))\""),
                ("Content-Transfer-Encoding", "base64"),
                ("Content-Disposition", "\(disposition.rawValue); filename=\"\(quotedParam(name))\""),
            ],
            body: .leaf(Array(Encoders.base64Wrapped(attachment.data).utf8))
        )
    }

    private func inlineLeaf(_ resource: InlineResource) throws -> MIMEPart {
        try Self.requireNoInjection(resource.contentType, field: "inlineResource.contentType")
        var headers: [(name: String, value: String)] = []
        if let filename = resource.filename {
            let name = sanitizedFilename(filename)
            headers.append(("Content-Type", "\(resource.contentType); name=\"\(quotedParam(name))\""))
            headers.append(("Content-Transfer-Encoding", "base64"))
            headers.append(("Content-ID", "<\(resource.contentID)>"))
            headers.append(("Content-Disposition", "inline; filename=\"\(quotedParam(name))\""))
        } else {
            headers.append(("Content-Type", resource.contentType))
            headers.append(("Content-Transfer-Encoding", "base64"))
            headers.append(("Content-ID", "<\(resource.contentID)>"))
            headers.append(("Content-Disposition", "inline"))
        }
        return MIMEPart(headers: headers, body: .leaf(Array(Encoders.base64Wrapped(resource.data).utf8)))
    }

    // MARK: - Serialization

    private static func serializeMultipart(boundary: String, parts: [MIMEPart]) -> [UInt8] {
        var out = [UInt8]()
        for part in parts {
            out.append(contentsOf: Array("--\(boundary)\r\n".utf8))
            for (name, value) in part.headers {
                out.append(contentsOf: Array("\(name): \(value)\r\n".utf8))
            }
            out.append(contentsOf: Array("\r\n".utf8))
            switch part.body {
            case .leaf(let bytes):
                out.append(contentsOf: bytes)
            case .multipart(let innerBoundary, let innerParts):
                out.append(contentsOf: serializeMultipart(boundary: innerBoundary, parts: innerParts))
            }
            out.append(contentsOf: Array("\r\n".utf8))
        }
        out.append(contentsOf: Array("--\(boundary)--\r\n".utf8))
        return out
    }

    // MARK: - Helpers

    private func normalizeLineEndings(_ text: String) -> String {
        text
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
            .replacingOccurrences(of: "\n", with: "\r\n")
    }

    /// Strips control characters (including CR/LF) from a caller-supplied
    /// filename before it's embedded in a quoted header parameter —
    /// defensive against header injection via an attacker-controlled
    /// upload filename. Non-ASCII filenames are passed through as raw
    /// UTF-8 inside the quoted-string; full RFC 2231 parameter-value
    /// continuation/encoding is not implemented in Phase 0 (see report).
    ///
    /// Also hardened against path traversal (milestone review finding):
    /// a filename like "../../../../etc/passwd" previously passed straight
    /// through into `Content-Disposition: attachment; filename="..."`.
    /// Basename the string — keep only the component after the last path
    /// separator (`/` or `\`, covering both POSIX and Windows-style
    /// caller input, including stripping a leading drive letter as a side
    /// effect of basenaming) — then strip any remaining leading dots.
    private func sanitizedFilename(_ name: String) -> String {
        let controlFree = String(
            String.UnicodeScalarView(name.unicodeScalars.filter { $0.value >= 0x20 && $0.value != 0x7F })
        )
        let lastSeparator = controlFree.lastIndex(where: { $0 == "/" || $0 == "\\" })
        let base = lastSeparator.map { String(controlFree[controlFree.index(after: $0)...]) } ?? controlFree
        let noLeadingDots = String(base.drop(while: { $0 == "." }))
        return noLeadingDots.isEmpty ? "_" : noLeadingDots
    }

    private func quotedParam(_ value: String) -> String {
        value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
    }

    private func synthesizeMessageID() -> String {
        let domain = messageIDDomain ?? Self.domain(from: message.from.address)
        return "<\(UUID().uuidString)@\(domain)>"
    }

    private static func domain(from address: String) -> String {
        guard let atIndex = address.lastIndex(of: "@") else { return "localhost.invalid" }
        let domainPart = address[address.index(after: atIndex)...]
        return domainPart.isEmpty ? "localhost.invalid" : String(domainPart)
    }

    private static func priorityHeaders(_ priority: Priority) -> [(name: String, value: String)] {
        switch priority {
        case .normal: return []
        case .high: return [("X-Priority", "1"), ("Importance", "High")]
        case .low: return [("X-Priority", "5"), ("Importance", "Low")]
        }
    }

    /// RFC 5322 §3.3 date-time string, hand-rolled (no `DateFormatter`) so
    /// this stays free of any shared, non-`Sendable` global formatter
    /// state and formats identically on Linux and Darwin. Always uses
    /// English day/month names regardless of the running locale, per RFC
    /// 5322's fixed vocabulary — a `Locale.current`-driven `DateFormatter`
    /// (as the original implementation used) would silently localize these
    /// and break the header on non-English systems.
    public static func rfc5322DateString(_ date: Date, timeZone: TimeZone = .current) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        let comps = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second, .weekday], from: date)

        let dayNames = ["", "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
        let monthNames = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        let weekday = dayNames[comps.weekday ?? 1]
        let month = monthNames[comps.month ?? 1]

        let offsetSeconds = timeZone.secondsFromGMT(for: date)
        let sign = offsetSeconds >= 0 ? "+" : "-"
        let absOffset = abs(offsetSeconds)

        return "\(weekday), \(pad2(comps.day ?? 1)) \(month) \(pad4(comps.year ?? 1970)) " +
            "\(pad2(comps.hour ?? 0)):\(pad2(comps.minute ?? 0)):\(pad2(comps.second ?? 0)) " +
            "\(sign)\(pad2(absOffset / 3600))\(pad2((absOffset % 3600) / 60))"
    }

    private static func pad2(_ n: Int) -> String { n < 10 ? "0\(n)" : "\(n)" }
    private static func pad4(_ n: Int) -> String {
        let s = "\(n)"
        return s.count >= 4 ? s : String(repeating: "0", count: 4 - s.count) + s
    }
}
