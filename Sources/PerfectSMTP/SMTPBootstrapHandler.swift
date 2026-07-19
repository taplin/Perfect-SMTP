//
//  SMTPBootstrapHandler.swift
//  PerfectSMTP
//
//  Phase A of the two-phase channel lifecycle (plan §4.3): connection
//  establishment, optional implicit TLS (port 465), and — for STARTTLS —
//  the negotiate-and-upgrade dance. Kept intentionally small and low-level:
//  the STARTTLS security invariant needs byte-precise control over the
//  inbound cumulation buffer at the exact moment of upgrade, which is more
//  ergonomic with an explicit `ChannelDuplexHandler` than with an
//  already-running `NIOAsyncChannel`.
//
//  At most one outstanding reply-correlation at a time (an explicit
//  single-request state machine, never a queue) — bootstrap commands
//  (greeting wait, EHLO, STARTTLS) are never pipelined.
//
//  Once bootstrap completes, this handler removes itself from the pipeline
//  and the caller wraps the now-clean `Channel` via
//  `NIOAsyncChannel(wrappingChannelSynchronously:)` for Phase B (see
//  `SMTPConnection.swift`). Per plan §4.3 step 7, the post-bootstrap EHLO
//  (whether this is the very first EHLO, or the STARTTLS-mandated re-issue
//  with capabilities reset) is deliberately **not** sent by this handler —
//  it is Phase B's first command, issued as plain async/await code once the
//  `NIOAsyncChannel` wrapping is complete. This handler's only EHLO
//  round-trip is the narrow pre-STARTTLS one needed to discover whether the
//  server advertises STARTTLS at all, before deciding whether to attempt
//  the upgrade.
//

import NIOCore
import NIOPosix
import NIOSSL
import NIOTLS

/// How a connection secures its transport.
public enum TLSMode: Sendable, Hashable {
    /// No TLS at all — a plaintext relay on a trusted network (plan §3's
    /// "self-hosted/internal MTA... possibly with no AUTH at all").
    case none
    /// Explicit upgrade via the `STARTTLS` command (typically port 587).
    /// Treated as mandatory once requested: if the server's pre-TLS EHLO
    /// doesn't advertise `STARTTLS`, bootstrap fails with
    /// `.starttlsRequired` rather than silently continuing in plaintext.
    case startTLS
    /// TLS from the first byte (typically port 465).
    case implicit
}

/// The async, `Sendable`-safe entry point for Phase A. Connects, performs
/// optional implicit TLS / the STARTTLS dance, and hands back a
/// pipeline-clean `NIOAsyncChannel<SMTPReply, SMTPCommand>` ready for Phase
/// B.
public enum SMTPBootstrap {
    public static func connect(
        host: String,
        port: Int,
        tls: TLSMode,
        connectTimeout: TimeAmount = .seconds(30),
        tlsConfiguration: TLSConfiguration = .makeClientConfiguration(),
        group: any EventLoopGroup
    ) async throws -> NIOAsyncChannel<SMTPReply, SMTPCommand> {
        let promise = group.next().makePromise(of: NIOAsyncChannel<SMTPReply, SMTPCommand>.self)

        let bootstrap = ClientBootstrap(group: group)
            .channelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: 1)
            .connectTimeout(connectTimeout)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    // The decoder is created here (not inside the handler)
                    // so `SMTPBootstrapHandler` can hold the same reference
                    // for its STARTTLS residual-bytes check (plan §4.3 step
                    // 3) without needing any pipeline-lookup API — a plain
                    // captured class reference, resolved once at
                    // construction time.
                    let decoder = SMTPResponseDecoder()
                    try channel.pipeline.syncOperations.addHandler(
                        ByteToMessageHandler(decoder), name: Names.decoder
                    )
                    try channel.pipeline.syncOperations.addHandler(SMTPCommandEncoder(), name: Names.encoder)
                    if tls == .implicit {
                        let sslHandler = try Self.makeSSLHandler(host: host, configuration: tlsConfiguration)
                        try channel.pipeline.syncOperations.addHandler(sslHandler, position: .first)
                    }
                    let handler = SMTPBootstrapHandler(
                        tls: tls,
                        host: host,
                        tlsConfiguration: tlsConfiguration,
                        readyPromise: promise,
                        initialDecoder: decoder
                    )
                    try channel.pipeline.syncOperations.addHandler(handler)
                }
            }

        do {
            _ = try await bootstrap.connect(host: host, port: port).get()
            return try await promise.futureResult.get()
        } catch {
            promise.fail(error)
            throw error
        }
    }

    enum Names {
        static let decoder = "smtp-bootstrap-decoder"
        static let encoder = "smtp-command-encoder"
    }

    static func makeSSLHandler(host: String, configuration: TLSConfiguration) throws -> NIOSSLClientHandler {
        let context = try NIOSSLContext(configuration: configuration)
        do {
            return try NIOSSLClientHandler(context: context, serverHostname: host)
        } catch {
            // `host` failed SNI hostname validation (e.g. it's a bare IP
            // address, which NIOSSL's SNI validator rejects outright per
            // RFC 6066 §3) -- fall back to no SNI rather than failing the
            // whole connection over a cosmetic handshake extension.
            return try NIOSSLClientHandler(context: context, serverHostname: nil)
        }
    }
}

/// Phase A's explicit state machine. `@unchecked Sendable`: constructed on,
/// and every callback dispatched on, its channel's single event loop —
/// never touched concurrently, matching this codebase's other
/// event-loop-confined handler precedents (e.g. PerfectNIO's
/// `WebSocketUpgradeRouter`).
final class SMTPBootstrapHandler: ChannelDuplexHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = SMTPReply
    typealias OutboundIn = Never
    typealias OutboundOut = SMTPCommand

    private enum State: Equatable {
        case awaitingGreeting
        case awaitingPreTLSEHLOReply
        case awaitingStartTLSReply
        /// Between "decided to upgrade" and "TLS handshake confirmed
        /// complete". Any inbound reply or error surfacing here — other
        /// than the TLS handshake-completed user event itself — is treated
        /// as `.starttlsInjection`: nothing else should legitimately
        /// produce channel activity in this fenced window.
        case upgrading
        case finished
        case failed
    }

    private let tls: TLSMode
    private let host: String
    private let tlsConfiguration: TLSConfiguration
    private let readyPromise: EventLoopPromise<NIOAsyncChannel<SMTPReply, SMTPCommand>>
    /// The pre-upgrade decoder — same reference `ByteToMessageHandler` was
    /// constructed with in the channel initializer. Queried, never
    /// swapped: the post-upgrade decoder is Phase B's concern, not this
    /// handler's.
    private let initialDecoder: SMTPResponseDecoder

    private var state: State = .awaitingGreeting

    init(
        tls: TLSMode,
        host: String,
        tlsConfiguration: TLSConfiguration,
        readyPromise: EventLoopPromise<NIOAsyncChannel<SMTPReply, SMTPCommand>>,
        initialDecoder: SMTPResponseDecoder
    ) {
        self.tls = tls
        self.host = host
        self.tlsConfiguration = tlsConfiguration
        self.readyPromise = readyPromise
        self.initialDecoder = initialDecoder
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let reply = Self.unwrapInboundIn(data)
        switch state {
        case .awaitingGreeting:
            handleGreeting(reply, context: context)
        case .awaitingPreTLSEHLOReply:
            handlePreTLSEHLOReply(reply, context: context)
        case .awaitingStartTLSReply:
            handleStartTLSReply(reply, context: context)
        case .upgrading, .finished, .failed:
            // Unsolicited reply: no promise/state was waiting for this.
            // During `.upgrading` specifically this is exactly the
            // CVE-2026-41319-class injection this handler exists to catch.
            // In `.finished`/`.failed` it's simply a stray event on a
            // handler that should already be gone/inert; fail closed.
            fail(context: context, .starttlsInjection)
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let tlsEvent = event as? TLSUserEvent, case .handshakeCompleted = tlsEvent {
            guard state == .upgrading else {
                // A handshake-completed event outside the upgrade window
                // (e.g. implicit TLS, where we never entered `.upgrading`
                // at all) is expected and ignored -- the greeting/EHLO flow
                // handles readiness in that mode.
                context.fireUserInboundEventTriggered(event)
                return
            }
            let boundContext = NIOLoopBoundBox(context, eventLoop: context.eventLoop)
            context.channel.setOption(ChannelOptions.autoRead, value: true).whenComplete { [weak self] result in
                guard let self else { return }
                switch result {
                case .failure(let error):
                    self.fail(context: boundContext.value, .connectionFailed(error))
                case .success:
                    self.finish(context: boundContext.value)
                }
            }
            return
        }
        context.fireUserInboundEventTriggered(event)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        guard state == .upgrading else {
            fail(context: context, .connectionFailed(error))
            return
        }
        // Any error surfacing in the fenced upgrade window -- whether the
        // decoder's own `residualBytesOnRemoval` (same-buffer injection) or
        // NIOSSL failing to parse injected plaintext as a TLS record
        // (separate-buffer injection) -- is the same underlying violation.
        fail(context: context, .starttlsInjection)
    }

    // MARK: - State transitions

    private func handleGreeting(_ reply: SMTPReply, context: ChannelHandlerContext) {
        guard reply.replyClass == .positiveCompletion else {
            fail(context: context, SMTPError.classify(reply))
            return
        }
        switch tls {
        case .none, .implicit:
            finish(context: context)
        case .startTLS:
            state = .awaitingPreTLSEHLOReply
            writeLine(context: context, "EHLO \(Self.probeHostname)")
        }
    }

    private func handlePreTLSEHLOReply(_ reply: SMTPReply, context: ChannelHandlerContext) {
        guard reply.replyClass == .positiveCompletion else {
            fail(context: context, SMTPError.classify(reply))
            return
        }
        let capabilities = Capabilities(parsingEHLOLines: reply.lines)
        guard capabilities.startTLS else {
            fail(context: context, .starttlsRequired)
            return
        }
        state = .awaitingStartTLSReply
        writeLine(context: context, "STARTTLS")
        // Step 2: fence immediately upon writing STARTTLS, closing the
        // TOCTOU gap between the residual-bytes assertion below and the
        // actual decoder swap -- the event loop must not service another
        // read in between.
        let boundContext = NIOLoopBoundBox(context, eventLoop: context.eventLoop)
        context.channel.setOption(ChannelOptions.autoRead, value: false).whenFailure { [weak self] error in
            self?.fail(context: boundContext.value, .connectionFailed(error))
        }
    }

    private func handleStartTLSReply(_ reply: SMTPReply, context: ChannelHandlerContext) {
        guard reply.code == 220 else {
            fail(context: context, SMTPError.classify(reply))
            return
        }
        // Step 3: residual-bytes assertion on the buffer that produced this
        // 220 -- catches bytes injected into the *same* read as the 220.
        guard !initialDecoder.hasResidualBytesAfterLastReply else {
            fail(context: context, .starttlsInjection)
            return
        }
        performTLSUpgrade(context: context)
    }

    private func performTLSUpgrade(context: ChannelHandlerContext) {
        state = .upgrading
        // Step 4: remove the plaintext decoder. Its `decodeLast` override
        // re-validates no residual bytes remain and throws
        // `.residualBytesOnRemoval` otherwise, surfacing via `errorCaught`
        // above -- defense-in-depth alongside the check just performed.
        let boundContext = NIOLoopBoundBox(context, eventLoop: context.eventLoop)
        context.pipeline.removeHandler(name: SMTPBootstrap.Names.decoder).whenComplete { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error):
                self.fail(context: boundContext.value, .connectionFailed(error))
            case .success:
                self.insertTLSAndFreshDecoder(context: boundContext.value)
            }
        }
    }

    private func insertTLSAndFreshDecoder(context: ChannelHandlerContext) {
        guard state == .upgrading else { return }
        do {
            // Step 5: NIOSSLClientHandler at `.first`.
            let sslHandler = try SMTPBootstrap.makeSSLHandler(host: host, configuration: tlsConfiguration)
            try context.pipeline.syncOperations.addHandler(sslHandler, position: .first)
            // Step 6: a fresh decoder above it. `autoRead` stays `false`
            // until the handshake-completed event fires (handled in
            // `userInboundEventTriggered`) -- any plaintext bytes injected
            // before then reach `sslHandler` as bogus TLS record data and
            // fail the handshake, surfacing via `errorCaught` above.
            try context.pipeline.syncOperations.addHandler(
                ByteToMessageHandler(SMTPResponseDecoder()),
                name: SMTPBootstrap.Names.decoder,
                position: .after(sslHandler)
            )
        } catch {
            fail(context: context, .connectionFailed(error))
        }
    }

    private func finish(context: ChannelHandlerContext) {
        guard state != .finished, state != .failed else { return }
        state = .finished
        let boundContext = NIOLoopBoundBox(context, eventLoop: context.eventLoop)
        context.pipeline.syncOperations.removeHandler(context: context).whenComplete { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error):
                self.readyPromise.fail(error)
            case .success:
                do {
                    let asyncChannel = try NIOAsyncChannel<SMTPReply, SMTPCommand>(
                        wrappingChannelSynchronously: boundContext.value.channel
                    )
                    self.readyPromise.succeed(asyncChannel)
                } catch {
                    self.readyPromise.fail(error)
                }
            }
        }
    }

    private func fail(context: ChannelHandlerContext, _ error: SMTPError) {
        guard state != .finished, state != .failed else { return }
        state = .failed
        context.close(promise: nil)
        readyPromise.fail(error)
    }

    private func writeLine(context: ChannelHandlerContext, _ line: String) {
        context.writeAndFlush(Self.wrapOutboundOut(.line(line)), promise: nil)
    }

    /// The EHLO identity used for the narrow pre-STARTTLS capability probe
    /// only. Phase B's real EHLO (issued post-bootstrap) uses the caller's
    /// actual configured EHLO hostname (plan §7's "no configurable
    /// EHLO/HELO hostname" gap) -- this probe's own identity doesn't matter
    /// since its only purpose is discovering whether STARTTLS is
    /// advertised, and its capabilities are discarded, never reused past
    /// the upgrade.
    private static let probeHostname = "localhost"
}
