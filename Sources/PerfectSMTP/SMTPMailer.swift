//
//  SMTPMailer.swift
//  PerfectSMTP
//
//  Public API (plan §4.9, minus the AsyncSequence-based streaming-send
//  overload, which is Phase 5 scope). Generic over `any SMTPTransport`;
//  the two-phase compose/sign/send pipeline
//  (`MIMEComposer` -> optional `MessageSigner` -> `transport.send`) is the
//  mailer's actual internal implementation, not just a sketch -- `send`
//  is sugar over it.
//

import NIOCore

public struct SMTPMailer: Sendable {
    public struct Configuration: Sendable {
        /// Caps in-flight batch-send tasks independent of (and typically
        /// larger than) any transport's own connection-pool cap (plan
        /// §4.9's corrected bounded-batch fan-out).
        public var maxInFlightBatchSends: Int
        public init(maxInFlightBatchSends: Int = 16) {
            self.maxInFlightBatchSends = maxInFlightBatchSends
        }
    }

    private let transport: any SMTPTransport
    /// Pluggable, optional signing step -- the seam Phase 2's `DKIMSigner`
    /// will conform to (see `PerfectSMTPCore/MessageSigner.swift`). `nil`
    /// means "no DKIM step": the composed `RFC5322Message` is serialized
    /// straight into `SignedMessage.rfc5322` with no signing at all, which
    /// is what makes Phase 1 a fully working mailer on its own.
    private let signer: (any MessageSigner)?
    private let configuration: Configuration

    public init(transport: any SMTPTransport, signer: (any MessageSigner)? = nil, configuration: Configuration = .init()) {
        self.transport = transport
        self.signer = signer
        self.configuration = configuration
    }

    /// Single-message send. `bcc` is supplied separately, never on
    /// `EmailMessage` (Phase 0's structural Bcc-leak fix) -- these
    /// addresses only ever become extra `SMTPEnvelope.recipients` entries,
    /// never a serialized header.
    public func send(
        _ message: EmailMessage,
        bcc: [String] = [],
        envelopeFrom: ReversePath
    ) async throws -> [DeliveryResult] {
        let signed = try composeAndSign(message)
        let recipients = message.to.map(\.address) + message.cc.map(\.address) + bcc
        let envelope = try SMTPEnvelope(mailFrom: envelopeFrom, recipients: recipients, size: signed.estimatedSize)
        return try await transport.send(envelope, signed)
    }

    /// Batch send: one message per `EmailMessage`, each using its own
    /// `to`/`cc` as recipients and a `.null` reverse-path is *not* assumed
    /// -- callers needing a specific envelope-from per message should use
    /// `send(_:bcc:envelopeFrom:)` directly in a loop with their own
    /// concurrency control; this overload exists for the common case of
    /// sending the same shape of message (e.g. a templated batch) to many
    /// independent recipients, each already fully composed as its own
    /// `EmailMessage`, from a shared `envelopeFrom`.
    ///
    /// Uses the sliding-window task-group pattern (plan §4.9's corrected
    /// bounded-batch fan-out): primes `configuration.maxInFlightBatchSends`
    /// children, then adds one new child each time one completes, capping
    /// in-flight tasks independent of the transport's own connection cap
    /// -- never a naive `for msg in messages { group.addTask { ... } }`,
    /// which would launch every child eagerly regardless of capacity.
    public func send(_ messages: [EmailMessage], envelopeFrom: ReversePath) async throws -> [DeliveryResult] {
        guard !messages.isEmpty else { return [] }
        let maxInFlight = max(1, configuration.maxInFlightBatchSends)

        return try await withThrowingTaskGroup(of: (Int, [DeliveryResult]).self) { group in
            var results = [[DeliveryResult]](repeating: [], count: messages.count)
            var nextIndex = 0

            func addNextTask() {
                guard nextIndex < messages.count else { return }
                let index = nextIndex
                let message = messages[index]
                nextIndex += 1
                group.addTask {
                    let sent = try await self.send(message, envelopeFrom: envelopeFrom)
                    return (index, sent)
                }
            }

            let primeCount = min(maxInFlight, messages.count)
            for _ in 0..<primeCount { addNextTask() }

            while let (index, sent) = try await group.next() {
                results[index] = sent
                addNextTask()
            }

            return results.flatMap { $0 }
        }
    }

    // MARK: - Two-phase compose/sign/send (plan §4.9)

    /// Composes `message` and, when a signer is configured, signs it --
    /// the mailer's internal implementation of §4.9's two-phase sketch:
    /// `MIMEComposer(msg, charset:).compose()` -> optional
    /// `signer.sign(...)` -> `transport.send(envelope, signed)`.
    public func composeAndSign(_ message: EmailMessage) throws -> SignedMessage {
        let composed = try MIMEComposer(message).compose()
        let finalMessage: RFC5322Message
        if let signer {
            finalMessage = try signer.sign(composed)
        } else {
            finalMessage = composed
        }
        return SignedMessage(rfc5322: finalMessage.serialized())
    }
}
