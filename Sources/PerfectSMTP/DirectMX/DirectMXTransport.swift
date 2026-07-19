//
//  DirectMXTransport.swift
//  PerfectSMTP
//
//  Plan §3/§4.2/§9 Phase 3: Perfect-SMTP being its own terminal MTA --
//  direct-to-recipient delivery via MX resolution, no relay. Builds
//  directly on the Phase-3a `DNSResolver` (via the `MXResolving` seam) and
//  reuses `SMTPConnectionPool` as-is (not a second pool *type* -- see the
//  file-level note on `makeDialer` below for why its existing
//  `Key { host, port, tls }` shape and `withConnection(to:_:)` API already
//  fit a multi-destination direct-MX pool with no relay-specific
//  assumptions to work around), keyed here by resolved MX exchange
//  hostname (or, for the implicit-MX fallback, the destination domain
//  itself) instead of one fixed relay host.
//

import Foundation
import NIOCore

/// Configuration for one `DirectMXTransport` instance. Applies uniformly to
/// every destination this transport connects to -- there is no per-domain
/// override surface in this phase (e.g. a domain known to require TLS vs.
/// one that doesn't; that policy layer is Phase 4's MTA-STS/DANE scope, not
/// this one).
///
/// **Security (FIX #2, milestone security review): this transport must not
/// be exposed to untrusted recipient input without SSRF-class address
/// filtering enabled** -- `allowPrivateAddresses` defaults to `false`
/// (filtering on) specifically because `DirectMXTransport` resolves and
/// dials whatever MX/A/AAAA records a destination domain publishes. A
/// caller that lets an untrusted party influence the recipient domain (a
/// web app's "share via email" feature, a future Lasso `email_send`
/// adapter, etc.) would otherwise let an attacker publish a record
/// pointing at `127.0.0.1`, an RFC 1918 address, or other internal
/// infrastructure and have this transport open a real TCP connection and
/// run a full SMTP conversation against it. Leave `allowPrivateAddresses`
/// at its default unless the caller's own equivalent protection is already
/// in place, or this is a deliberate internal-relay-testing use case.
public struct DirectMXConfig: Sendable {
    /// The port dialed on every resolved MX host. 25 (not 587/465) is
    /// correct here: this transport speaks MTA-to-MTA delivery, the
    /// universal port every receiving MX host listens on, not
    /// client-submission.
    public var port: Int
    /// TLS policy applied to every direct-MX connection this transport
    /// makes. **Deliberately `.none` by default** -- a documented judgment
    /// call, not an oversight: `TLSMode.startTLS` in this codebase is
    /// mandatory-once-requested (`SMTPBootstrapHandler` hard-fails with
    /// `.starttlsRequired` if the peer's EHLO doesn't advertise it), which
    /// is the wrong default for direct-MX delivery -- unlike a relay a
    /// caller chose and configured, a direct-MX transport connects to
    /// whatever MX host a domain happens to publish, and a meaningful
    /// fraction of real-world MX hosts still don't advertise STARTTLS at
    /// all. Defaulting to `.startTLS` here would silently turn "the
    /// receiver doesn't support TLS" into "this domain is
    /// undeliverable-by-this-transport", which is worse than the
    /// unencrypted-hop status quo most direct-sending MTAs actually
    /// operate under today. True opportunistic TLS (upgrade when
    /// advertised, fall back to plaintext when not, harden via MTA-STS/DANE
    /// policy) is explicitly Phase 4's scope (plan §9) -- this phase
    /// supports whichever single `TLSMode` a caller configures uniformly,
    /// same as `RelayTransport`, and a caller who wants mandatory STARTTLS
    /// against every direct-MX destination can already get that by setting
    /// `tls = .startTLS` here, accepting that domains without STARTTLS
    /// become undeliverable until Phase 4 lands.
    public var tls: TLSMode
    public var ehloHostname: String
    /// **Direct-MX-specific note (not a Phase-1 concern):** `RelayTransport`
    /// owns one pool per configured relay, so `maxTotal` is naturally a cap
    /// on connections to that single destination. `DirectMXTransport`
    /// shares **one** pool instance across every distinct destination
    /// domain/MX host in a batch (see this type's own doc comment), so
    /// `maxTotal` here is a hard global cap across *all* domains combined,
    /// not per-domain -- a caller doing meaningful batch volume across many
    /// domains should likely raise it above the Phase-1 default (32).
    public var pool: SMTPConnectionPool.Configuration
    public var connectTimeout: TimeAmount
    public var replyTimeout: Duration
    public var dataTerminationTimeout: Duration
    /// FIX #2 (milestone security review): SSRF-class filtering is
    /// default-**on** -- every resolved `DNSAddress` is checked against
    /// `DNSAddress.isRoutable` (private/loopback/link-local/unique-local/
    /// CGNAT ranges, see that property's doc comment) before this
    /// transport ever dials it, and an address that fails the check is
    /// dropped rather than connected to. Set `true` only for a deliberate
    /// internal-relay-testing use case (e.g. a test harness or an
    /// intentionally internal-only deployment) -- see this type's own doc
    /// comment for the attack this default protects against.
    public var allowPrivateAddresses: Bool

    public init(
        port: Int = 25,
        tls: TLSMode = .none,
        ehloHostname: String = "localhost",
        pool: SMTPConnectionPool.Configuration = .init(),
        connectTimeout: TimeAmount = .seconds(30),
        replyTimeout: Duration = .seconds(300),
        dataTerminationTimeout: Duration = .seconds(600),
        allowPrivateAddresses: Bool = false
    ) {
        self.port = port
        self.tls = tls
        self.ehloHostname = ehloHostname
        self.pool = pool
        self.connectTimeout = connectTimeout
        self.replyTimeout = replyTimeout
        self.dataTerminationTimeout = dataTerminationTimeout
        self.allowPrivateAddresses = allowPrivateAddresses
    }
}

/// Errors specific to MX-resolution/host-fallback bookkeeping (as opposed
/// to `SMTPError`, which classifies SMTP-level replies, or
/// `DirectMXRetryQueueError`, which classifies retry-queue bookkeeping
/// failures).
public enum DirectMXError: Error, Sendable, Equatable {
    /// Every MX host resolved for a domain (or, for the implicit-MX
    /// fallback, the domain itself) failed to connect. Carried alongside
    /// the last host's actual underlying error in the common path (see
    /// `DirectMXTransport.deliverToDomain`) -- this case is the fallback
    /// used only when there were no candidate hosts to even try.
    case noUsableMXHost(domain: String)
    /// A candidate host resolved to no usable A/AAAA address at all.
    case noUsableAddress(host: String)
    /// FIX #2 (milestone security review): every A/AAAA address resolved
    /// for `host` was filtered out as private/loopback/link-local/
    /// unique-local/CGNAT (see `DNSAddress.isRoutable`) -- distinct from
    /// `.noUsableAddress` (which means the resolver returned nothing at
    /// all) specifically so this is diagnosable as "this host published an
    /// address this transport refuses to dial" rather than a mysterious
    /// connection failure indistinguishable from a genuine DNS/network
    /// problem. Never thrown when `DirectMXConfig.allowPrivateAddresses`
    /// is `true`.
    case allResolvedAddressesFilteredAsPrivate(host: String)
}

/// A `SMTPTransport` that resolves MX records itself and delivers directly
/// to the destination's own mail exchanger(s) -- no relay in front. Per-
/// recipient delivery: `envelope.recipients` is grouped by destination
/// domain (MX resolution and connection pooling both happen at the domain
/// level), each domain's MX hosts are resolved and attempted independently,
/// and one `DeliveryResult` is produced per recipient reflecting that
/// recipient's own domain's outcome -- a failure delivering to one
/// recipient's domain never affects delivery to a different recipient's
/// domain in the same call (enforced by running each domain's delivery as
/// its own child task and never letting one child's outcome influence
/// another's).
public final class DirectMXTransport: SMTPTransport, Sendable {
    private let resolver: any MXResolving
    private let pool: SMTPConnectionPool
    private let config: DirectMXConfig
    private let retryQueueConfiguration: DirectMXRetryQueue.Configuration
    private let retryQueue: DirectMXRetryQueue

    /// - Parameters:
    ///   - resolver: Anything conforming to `MXResolving` -- a real
    ///     `DNSResolver` in production, a fake in tests (see
    ///     `MXResolving.swift`'s doc comment for why this seam exists).
    ///   - config: Applies uniformly to every destination -- see
    ///     `DirectMXConfig`'s doc comments, especially `tls`'s default.
    ///   - group: The `EventLoopGroup` both the connection pool and every
    ///     dialed connection run on.
    ///   - retryQueueConfiguration: Backoff durations and the retry
    ///     ceiling/expiry policy for this transport's owned
    ///     `DirectMXRetryQueue` -- see that type's `Configuration` doc
    ///     comments.
    ///   - onTerminalRetryOutcome: Forwarded to the owned
    ///     `DirectMXRetryQueue` -- see that type's `init` doc comment for
    ///     why this is the only way a caller observes a *background*
    ///     retry's final outcome.
    public convenience init(
        resolver: any MXResolving,
        config: DirectMXConfig = .init(),
        group: any EventLoopGroup,
        retryQueueConfiguration: DirectMXRetryQueue.Configuration = .init(),
        onTerminalRetryOutcome: (@Sendable (DeliveryResult) async -> Void)? = nil
    ) {
        self.init(
            resolver: resolver, config: config, group: group,
            retryQueueConfiguration: retryQueueConfiguration, onTerminalRetryOutcome: onTerminalRetryOutcome,
            dialer: Self.makeDialer(resolver: resolver, config: config, group: group, retryQueueConfiguration: retryQueueConfiguration)
        )
    }

    /// Test/internal-only initializer: overrides the pool's dialer entirely
    /// (bypassing real DNS-driven address resolution and real socket
    /// connects), matching `SMTPConnectionPool`'s own test-dialer seam
    /// (`SMTPConnectionPoolTests`) -- lets MX-host-fallback / circuit-
    /// breaker tests script exactly which pool `Key` (i.e. which MX host)
    /// succeeds or fails, using `ConnectionHarness`-backed in-memory
    /// connections for the ones that should succeed.
    init(
        resolver: any MXResolving,
        config: DirectMXConfig = .init(),
        group: any EventLoopGroup,
        retryQueueConfiguration: DirectMXRetryQueue.Configuration = .init(),
        onTerminalRetryOutcome: (@Sendable (DeliveryResult) async -> Void)? = nil,
        dialer: @escaping @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection
    ) {
        self.resolver = resolver
        self.config = config
        self.retryQueueConfiguration = retryQueueConfiguration
        let pool = SMTPConnectionPool(configuration: config.pool, group: group, dialer: dialer)
        self.pool = pool
        // Deliberately built from local `let`s (`resolver`/`config`/`pool`/
        // `retryQueueConfiguration`), never from `self.<property>` -- this
        // closure is constructed before every one of `self`'s stored
        // properties is set, and capturing `self` itself here (even
        // weakly) would need those properties already initialized. Using
        // the local values `performDelivery` needs sidesteps the ordering
        // question entirely: `performDelivery` is a `static` function that
        // takes everything explicitly, so nothing here ever touches `self`.
        self.retryQueue = DirectMXRetryQueue(
            configuration: retryQueueConfiguration,
            redeliver: { envelope, message in
                await Self.performDelivery(
                    envelope: envelope, message: message, resolver: resolver, pool: pool,
                    config: config, retryQueueConfiguration: retryQueueConfiguration
                )
            },
            onTerminalOutcome: onTerminalRetryOutcome
        )
    }

    public func send(_ envelope: SMTPEnvelope, _ message: SignedMessage) async throws -> [DeliveryResult] {
        let results = await Self.performDelivery(
            envelope: envelope, message: message, resolver: resolver, pool: pool,
            config: config, retryQueueConfiguration: retryQueueConfiguration
        )
        await enqueueRetries(from: results, mailFrom: envelope.mailFrom, message: message)
        return results
    }

    public func shutdown() async {
        await retryQueue.shutdown()
        await pool.shutdown()
    }

    /// Exposed for callers/tests that want visibility into what this
    /// transport's owned retry queue is still holding, without wiring up
    /// `onTerminalRetryOutcome`.
    public func pendingRetryEntries() async -> [DirectMXRetryQueue.Entry] {
        await retryQueue.pendingEntriesSnapshot()
    }

    /// One retry-queue entry per recipient that came back `.queuedForRetry`
    /// from this call -- see `DirectMXRetryQueue.Entry.recipients`'s doc
    /// comment for why per-recipient (not batched-by-transaction) is the
    /// deliberate granularity. `.ambiguous` results are never passed
    /// through to `DirectMXRetryQueue.enqueue` as anything other than a
    /// guaranteed no-op (that guard lives on the queue itself, per that
    /// type's doc comment) -- this loop doesn't need its own `.ambiguous`
    /// check to uphold that invariant, but the `guard case .queuedForRetry`
    /// below means it never even reaches the queue's own guard for any
    /// other outcome either.
    private func enqueueRetries(from results: [DeliveryResult], mailFrom: ReversePath, message: SignedMessage) async {
        for result in results {
            guard case .queuedForRetry = result.outcome else { continue }
            await retryQueue.enqueue(recipients: [result.recipient], mailFrom: mailFrom, message: message, outcome: result.outcome)
        }
    }

    // MARK: - Delivery (static: no `self` capture needed, callable from `init`'s `redeliver` closure and from `send`)

    /// Groups `envelope.recipients` by destination domain and attempts
    /// each domain's delivery independently and concurrently (one child
    /// task per domain) -- a failure for one domain can never affect
    /// another's outcome, since each domain's `deliverToDomain` call
    /// catches every failure mode of its own and always returns data,
    /// never throws.
    private static func performDelivery(
        envelope: SMTPEnvelope, message: SignedMessage, resolver: any MXResolving, pool: SMTPConnectionPool,
        config: DirectMXConfig, retryQueueConfiguration: DirectMXRetryQueue.Configuration
    ) async -> [DeliveryResult] {
        let grouped = Dictionary(grouping: envelope.recipients, by: domain(of:))
        guard !grouped.isEmpty else { return [] }

        return await withTaskGroup(of: [DeliveryResult].self) { group in
            for (domain, recipients) in grouped {
                group.addTask {
                    await deliverToDomain(
                        domain, recipients: recipients, mailFrom: envelope.mailFrom, message: message,
                        resolver: resolver, pool: pool, config: config, retryQueueConfiguration: retryQueueConfiguration
                    )
                }
            }
            var all: [DeliveryResult] = []
            for await results in group { all.append(contentsOf: results) }
            return all
        }
    }

    /// Resolves `domain`'s MX hosts, then attempts them in the resolver's
    /// returned preference/shuffle order, falling to the next host **only**
    /// on a connection-level failure (a dial failure, a circuit-open pool
    /// rejection, a mid-conversation disconnect) -- never on a message-
    /// level rejection from a host that did accept the connection (a `550`
    /// from the actual, connected, correct MX host is a real rejection for
    /// this domain, not a reason to try a different host; see
    /// `attemptOnHost`, which is what actually enforces this distinction by
    /// catching and *returning* (not rethrowing) `SMTPError`-classified
    /// rejections).
    private static func deliverToDomain(
        _ domain: String, recipients: [String], mailFrom: ReversePath, message: SignedMessage,
        resolver: any MXResolving, pool: SMTPConnectionPool, config: DirectMXConfig,
        retryQueueConfiguration: DirectMXRetryQueue.Configuration
    ) async -> [DeliveryResult] {
        let hosts: [String]
        do {
            hosts = try await resolveMXHosts(domain: domain, resolver: resolver)
        } catch let resolveError as DNSResolver.ResolveError {
            let outcome = classify(resolveError: resolveError, domain: domain, retryQueueConfiguration: retryQueueConfiguration)
            return recipients.map { DeliveryResult(recipient: $0, outcome: outcome) }
        } catch {
            return recipients.map { DeliveryResult(recipient: $0, outcome: .failed(error)) }
        }

        var lastError: any Error = DirectMXError.noUsableMXHost(domain: domain)
        for host in hosts {
            let key = SMTPConnectionPool.Key(host: host, port: config.port, tls: config.tls)
            do {
                return try await attemptOnHost(
                    key: key, recipients: recipients, mailFrom: mailFrom, message: message,
                    pool: pool, retryQueueConfiguration: retryQueueConfiguration
                )
            } catch {
                lastError = error
                continue
            }
        }
        return recipients.map { DeliveryResult(recipient: $0, outcome: .failed(lastError)) }
    }

    /// Checks out (dialing if needed) a pooled connection to `key` and runs
    /// one full mail transaction against it. A message-level rejection
    /// (`SMTPError`, thrown by `SMTPConnection.sendMessage` only when
    /// `MAIL FROM` itself is rejected -- individual `RCPT`/`DATA`-phase
    /// rejections are already returned as per-recipient `DeliveryResult`
    /// data by `sendMessage`, never thrown) is caught here and turned into
    /// normally-*returned* per-recipient outcomes instead of being
    /// rethrown -- this is what makes `deliverToDomain`'s host-fallback
    /// loop treat it as "handled" rather than "this host failed, try the
    /// next one." Any other thrown error (a dial failure inside
    /// `pool.withConnection`, `SMTPError.circuitOpen`, a mid-conversation
    /// `SMTPConnectionError`) propagates unchanged, which is exactly what
    /// signals "connection failure, fall back" to the caller.
    ///
    /// FIX (milestone architecture + SMTP-protocol reviews, converged on
    /// the same root cause): "handled, don't fall back to another host"
    /// and "the connection itself is still healthy" are **not** the same
    /// question -- a mid-DATA disconnect (`.ambiguous`) or a `421`
    /// ("closing the transmission channel," RFC 5321 §4.2.1) both return
    /// normally from this method (correctly -- neither should trigger
    /// MX-host fallback) but must **not** be treated as `healthy: true` by
    /// the pool, or a host that's flaky specifically in that window would
    /// never trip the circuit breaker. `isHealthy:` (passed to
    /// `pool.withConnection` below) is what closes that gap -- see
    /// `SMTPConnectionPool.deliveryResultsIndicateHealthyConnection`'s doc
    /// comment.
    private static func attemptOnHost(
        key: SMTPConnectionPool.Key, recipients: [String], mailFrom: ReversePath, message: SignedMessage,
        pool: SMTPConnectionPool, retryQueueConfiguration: DirectMXRetryQueue.Configuration
    ) async throws -> [DeliveryResult] {
        try await pool.withConnection(to: key, isHealthy: SMTPConnectionPool.deliveryResultsIndicateHealthyConnection) { connection in
            let envelope = try SMTPEnvelope(mailFrom: mailFrom, recipients: recipients, size: message.estimatedSize)
            do {
                return try await connection.sendMessage(envelope, message)
            } catch let error as SMTPError {
                let outcome = classify(smtpError: error, retryQueueConfiguration: retryQueueConfiguration)
                return recipients.map { DeliveryResult(recipient: $0, outcome: outcome) }
            }
        }
    }

    // MARK: - MX resolution helpers

    /// Resolves `domain`'s MX exchange hostnames, in the resolver's
    /// preference/shuffle order, falling back to the RFC 5321 §5.1
    /// implicit-MX behavior (treat the domain's own A/AAAA records as its
    /// MX) when there are no MX records at all -- `DNSResolver` itself
    /// deliberately leaves this fallback decision to this caller (see that
    /// type's doc comment on `resolveMX(domain:)`). No special A/AAAA
    /// lookup happens *here* for that fallback: returning `[domain]` as
    /// the sole candidate host is sufficient, because `makeDialer`'s own
    /// dialer resolves whatever hostname it's asked to connect to via
    /// `resolver.resolveAddresses(hostname:)` regardless of whether that
    /// hostname came from an MX record or is the domain itself -- if the
    /// domain genuinely has no A/AAAA either, that surfaces naturally as a
    /// dial failure on this one candidate host, handled the same as any
    /// other host-level failure.
    ///
    /// `.nullMX` (RFC 7505) is deliberately **not** caught here -- it
    /// propagates to `deliverToDomain`'s caller, which hard-fails the whole
    /// domain via `classify(resolveError:domain:)` without ever reaching
    /// this fallback. That is the entire point of null-MX.
    private static func resolveMXHosts(domain: String, resolver: any MXResolving) async throws -> [String] {
        do {
            let records = try await resolver.resolveMX(domain: domain)
            return records.map(\.exchange)
        } catch DNSResolver.ResolveError.noRecordsFound {
            return [domain]
        }
    }

    /// - Parameters:
    ///   - retryQueueConfiguration: Threaded through only for `.timeout`/
    ///     `.serverFailure`/`.noNameserversConfigured` (see that `case`'s
    ///     comment below) -- everything else this method classifies is
    ///     permanent and never touches a backoff policy at all.
    private static func classify(
        resolveError: DNSResolver.ResolveError, domain: String, retryQueueConfiguration: DirectMXRetryQueue.Configuration
    ) -> DeliveryResult.Outcome {
        switch resolveError {
        case .nullMX:
            // RFC 7505: an explicit, authoritative "this domain does not
            // accept email at all" -- hard-fail permanently, never fall
            // through to A/AAAA. 556 5.1.10 is the RFC-conventional code
            // for exactly this condition.
            return .permanentlyFailed(SMTPReply(code: 556, lines: ["5.1.10 Domain \(domain) does not accept email (null MX record, RFC 7505)"]))
        case .noRecordsFound:
            // Only reachable here if the RFC 5321 §5.1 implicit-MX
            // fallback itself later fails to resolve any A/AAAA for
            // `domain` either -- `resolveMXHosts` intercepts a
            // `.noRecordsFound` MX lookup and falls through to the
            // address-fallback path (returning `[domain]`) instead of
            // rethrowing it, so in the common case this specific branch of
            // `classify` is unreachable; the "no MX and no A/AAAA at all"
            // outcome instead surfaces through `deliverToDomain`'s ordinary
            // host-fallback-exhausted path as `.failed`, not here. Kept for
            // exhaustiveness / defense-in-depth in case that call site's
            // behavior changes.
            return .permanentlyFailed(SMTPReply(code: 550, lines: ["5.1.2 Domain \(domain) has no MX records"]))
        case .timeout, .serverFailure, .noNameserversConfigured:
            // Milestone review finding (architecture + SMTP-protocol
            // reviews, independently flagged): a genuine DNS-*infrastructure*
            // problem (a resolver that didn't answer in time, an
            // authoritative server returning SERVFAIL/REFUSED, or this
            // process having no nameservers configured at all) is plausibly
            // transient -- a network blip, a resolver restart -- and says
            // nothing about whether `domain` itself accepts mail. Treating
            // it as immediately, permanently `.failed` (the previous
            // behavior) discarded that distinction; routed through the
            // retry queue instead, via a synthesized `SMTPReply` (RFC 3463
            // enhanced status `4.4.3`, "directory server failure" -- the
            // conventional code real MTAs use for exactly this: a
            // temporary DNS lookup failure) so `retryQueueConfiguration`'s
            // already-configured backoff machinery classifies it uniformly
            // with every other transient outcome (a `450`-class reply
            // lands on the same conservative `greylist` backoff duration
            // Phase 1's own RCPT/DATA-phase rejections use for an
            // equivalent-severity failure).
            let reply = SMTPReply(code: 450, lines: ["4.4.3 Temporary DNS resolution failure for \(domain) (\(resolveError))"])
            return retryQueueConfiguration.classify(reply, attempt: 1)
        case .malformedResponse, .cnameLoop:
            // Unlike the infrastructure failures above, these indicate the
            // *queried* nameserver actually responded but with something
            // this codec can't safely use (a malformed wire-format message,
            // or a CNAME chain that couldn't be safely followed to
            // completion) -- not obviously transient the way a timeout or
            // SERVFAIL is, so left exactly as before: `.failed`, not
            // auto-retried, not guessed to be permanent either.
            return .failed(resolveError)
        }
    }

    /// Classifies an `SMTPError` thrown by `SMTPConnection.sendMessage`
    /// (always a `MAIL FROM`-level rejection in practice -- see
    /// `attemptOnHost`'s doc comment) into a `DeliveryResult.Outcome`,
    /// using `retryQueueConfiguration`'s real backoff durations rather than
    /// any hardcoded placeholder, so a `MAIL FROM`-level `421`/greylist
    /// rejection gets the exact same configured backoff a `RCPT`-level one
    /// would. This is only symmetric with `RCPT`/`DATA`-phase outcomes
    /// (classified inside `SMTPConnection.outcomeFor` itself, not here)
    /// because `makeDialer` passes this same `retryQueueConfiguration
    /// .backoff` policy to every `SMTPConnection` it dials -- see that
    /// method's comment and `SMTPConnection.backoffPolicy`'s doc comment.
    private static func classify(smtpError: SMTPError, retryQueueConfiguration: DirectMXRetryQueue.Configuration) -> DeliveryResult.Outcome {
        switch smtpError {
        case .permanentFailure(let reply):
            return .permanentlyFailed(reply)
        case .transientFailure(let reply), .greylisted(let reply), .serviceUnavailable(let reply):
            return retryQueueConfiguration.classify(reply, attempt: 1)
        case .sizeExceeded:
            // No `SMTPReply` survives past `classifyMailFromFailure`'s
            // `552` -> `.sizeExceeded` mapping to attach here -- the
            // message is simply too large for this destination; retrying
            // won't change that, so this is permanent.
            return .permanentlyFailed(SMTPReply(code: 552, lines: ["5.3.4 Message size exceeds server limit"]))
        case .authenticationFailed(let reply):
            // `DirectMXTransport` never authenticates (direct-MX delivery
            // has no relay credentials to present) -- unreachable in
            // practice; handled defensively rather than assumed impossible.
            return .permanentlyFailed(reply)
        case .ambiguousDelivery(let reply):
            // Never queued for retry -- `DirectMXRetryQueue.enqueue`'s own
            // guard only ever schedules `.queuedForRetry`, so returning
            // `.ambiguous` here is sufficient on its own to guarantee this
            // never gets auto-retried.
            return .ambiguous(reply)
        case .starttlsRequired, .starttlsInjection, .tlsPolicyViolation, .circuitOpen, .connectionFailed:
            // None of these are reply-classified rejections from a
            // connected peer -- they're connection/policy-level failures
            // that, in practice, are thrown by the pool's own dial path or
            // STARTTLS bootstrap (inside `pool.withConnection`'s dialer),
            // never by `SMTPConnection.sendMessage` itself, so
            // `attemptOnHost`'s `catch let error as SMTPError` should never
            // actually observe one of these cases. Handled defensively --
            // `.failed` is the correct "not reply-classified" bucket
            // regardless of how it got here.
            return .failed(smtpError)
        }
    }

    /// The production dialer: resolves `key.host`'s A/AAAA addresses via
    /// `resolver` (real DNS in production), then tries connecting to each
    /// returned address in turn (first success wins) -- a second, finer-
    /// grained fallback layer underneath `deliverToDomain`'s MX-host-level
    /// fallback, for hosts that themselves have multiple A/AAAA records.
    ///
    /// **Why this reuses `SMTPConnectionPool` rather than a second pool
    /// type:** the plan called for "a second connection pool... reuse
    /// `SMTPConnectionPool` directly if its existing `Key`/`withConnection`
    /// shape already fits." It does: `Key { host, port, tls }` has no
    /// relay-specific assumption baked in (it's already exactly "one
    /// destination, keyed by where to connect and how to secure it"), and
    /// the one piece that genuinely differs between `RelayTransport` and
    /// `DirectMXTransport` -- *how a `Key` turns into a live connection* --
    /// is precisely the seam `SMTPConnectionPool` already exposes via its
    /// internal `dialer` closure (originally added, per that type's own
    /// comments, purely as a test seam for Phase 1, but it turns out to be
    /// exactly the right production seam here too: a direct-MX dialer that
    /// resolves-then-connects instead of a relay dialer that just
    /// connects). Circuit breaking, idle eviction, and the reentrancy-safe
    /// checkout/waiter machinery are all identically correct for "many
    /// destination hosts" as they are for "one configured relay host" --
    /// none of it assumes a single fixed destination anywhere in
    /// `SMTPConnectionPool.swift`. So this is a second pool *instance*
    /// (`DirectMXTransport` owns its own, separate from any
    /// `RelayTransport` a caller might also have), not a second pool
    /// *implementation*.
    private static func makeDialer(
        resolver: any MXResolving, config: DirectMXConfig, group: any EventLoopGroup,
        retryQueueConfiguration: DirectMXRetryQueue.Configuration
    ) -> @Sendable (SMTPConnectionPool.Key) async throws -> SMTPConnection {
        { key in
            let resolvedAddresses = try await resolver.resolveAddresses(hostname: key.host)
            // FIX #2 (milestone security review, SSRF-class filtering):
            // drop every address in a private/loopback/link-local/
            // unique-local/CGNAT range before ever dialing it -- see
            // `DNSAddress.isRoutable`'s doc comment for the exact ranges
            // and `DirectMXConfig.allowPrivateAddresses`'s doc comment for
            // the attack this protects against and the documented
            // opt-out.
            let addresses = config.allowPrivateAddresses ? resolvedAddresses : resolvedAddresses.filter(\.isRoutable)
            guard !addresses.isEmpty else {
                // Distinguish "the resolver returned nothing at all" from
                // "every candidate was filtered as private/reserved" --
                // the latter is a real, actionable security-relevant
                // outcome (this host published an address this transport
                // refuses to dial), not a mysterious connection failure.
                if !config.allowPrivateAddresses, !resolvedAddresses.isEmpty {
                    throw DirectMXError.allResolvedAddressesFilteredAsPrivate(host: key.host)
                }
                throw DirectMXError.noUsableAddress(host: key.host)
            }
            var lastError: any Error = DirectMXError.noUsableAddress(host: key.host)
            for address in addresses {
                do {
                    let socketAddress = try SocketAddress(ipAddress: address.description, port: key.port)
                    let asyncChannel = try await SMTPBootstrap.connect(
                        to: socketAddress, sniHostname: key.host, tls: key.tls,
                        connectTimeout: config.connectTimeout, group: group
                    )
                    let connection = SMTPConnection(
                        asyncChannel: asyncChannel, ehloHostname: config.ehloHostname,
                        replyTimeout: config.replyTimeout, dataTerminationTimeout: config.dataTerminationTimeout,
                        // Same configured backoff policy this transport's
                        // retry queue itself uses (see
                        // `DirectMXRetryQueue.Configuration.backoff`'s doc
                        // comment) -- a RCPT/DATA-phase rejection
                        // classified inside `SMTPConnection.outcomeFor` and
                        // a MAIL-FROM-phase rejection classified by
                        // `DirectMXTransport.classify(smtpError:...)` get
                        // identical backoff durations for identical reply
                        // codes.
                        backoffPolicy: retryQueueConfiguration.backoff
                    )
                    try await connection.negotiateCapabilities()
                    return connection
                } catch {
                    lastError = error
                    continue
                }
            }
            throw lastError
        }
    }

    /// Extracts the domain (the part after the last unescaped `@`) from an
    /// `addr-spec` string, lowercased for grouping (DNS names are
    /// case-insensitive; the recipient string itself, used verbatim in
    /// `RCPT TO`, is never mutated). Deliberately a plain
    /// last-`@`-occurrence split, not a full RFC 5321 `addr-spec`-grammar-
    /// aware parse (which would need to understand quoted local parts that
    /// can themselves contain `@`) -- matching this codebase's existing
    /// scoping discipline elsewhere (e.g. `SMTPEnvelope`'s own recipient
    /// validation only checks for header-injection characters, not full
    /// grammar conformance).
    private static func domain(of recipient: String) -> String {
        guard let atIndex = recipient.lastIndex(of: "@") else { return recipient.lowercased() }
        return String(recipient[recipient.index(after: atIndex)...]).lowercased()
    }
}
