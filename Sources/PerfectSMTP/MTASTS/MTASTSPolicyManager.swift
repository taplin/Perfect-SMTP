//
//  MTASTSPolicyManager.swift
//  PerfectSMTP
//
//  Plan §9 Phase 4: discovery (`_mta-sts.<domain>` TXT lookup) + fetch
//  (HTTPS GET of the well-known policy file) + parse + cache, wired
//  together as one actor so `DirectMXTransport` has a single
//  `policy(for:)` call to make per destination domain.
//
//  **Scope boundary -- in-memory only, deliberately (stated explicitly, not
//  silently omitted, matching this codebase's established precedent --
//  see `DirectMXRetryQueue.swift`'s own header comment for the exact same
//  pattern applied to its retry-entry cache): this is a library, not a
//  standalone daemon.** Every cached policy lives only in this actor's own
//  `cache` dictionary, for the lifetime of the process. A caller wanting
//  durable policy-cache persistence across process restarts (so every
//  domain doesn't re-fetch its policy on the first send after a restart)
//  must build that themselves on top of this API. Nothing here reads or
//  writes disk, a database, or any other durable store.
//

import Foundation

/// The seam `DirectMXTransport` depends on -- `MTASTSPolicyManager` in
/// production, a fake in tests that don't want real DNS/HTTPS involved at
/// all (mirroring `MXResolving`'s role for `DNSResolver`).
public protocol MTASTSPolicyProviding: Sendable {
    /// Returns the current usable policy for `domain`, or `nil` if this
    /// domain has no usable MTA-STS policy right now -- no TXT-record
    /// discovery signal, an HTTPS fetch failure with nothing usable cached,
    /// or a policy file that failed to parse. Never throws: per RFC 8461
    /// §3.3 and plan §9 Phase 4's explicit instruction, every failure
    /// mode here degrades to "treat this domain as policy-less" rather than
    /// surfacing as an error `DirectMXTransport` would have to specially
    /// handle -- MTA-STS is opportunistic-by-nature at the discovery layer,
    /// even though `enforce`/`testing` policies (once successfully
    /// obtained) are not.
    func policy(for domain: String) async -> MTASTSPolicy?
}

/// Errors specific to this actor's own discovery/fetch/parse pipeline (as
/// opposed to `TXTResolving`/`MTASTSHTTPFetching`'s own lower-level errors,
/// which this type catches and folds into one of these instead of letting
/// callers reach into transport-specific failure detail they don't need).
enum MTASTSDiscoveryError: Error, Sendable, Equatable {
    /// No `_mta-sts.<domain>` TXT record advertising `v=STSv1` was found
    /// (RFC 8461 §3.1) -- the ordinary, expected outcome for the vast
    /// majority of domains, which simply don't publish MTA-STS at all.
    case noSTSv1DiscoveryRecord
    /// The HTTPS fetch itself failed: a network/TLS error, or a non-200
    /// status code (RFC 8461 §3.3).
    case fetchFailed
    /// The response's `Content-Type` wasn't `text/plain` (RFC 8461 §3.2).
    case invalidContentType
    /// The response body didn't parse as a valid policy file
    /// (`MTASTSPolicyParser.parse(_:)` returned `nil`).
    case malformedPolicy
}

/// Discovers, fetches, parses, and caches MTA-STS policies per destination
/// domain (RFC 8461). Concurrency-safe by construction (an actor, per this
/// codebase's established shape for stateful, checkout-style components --
/// mirrors `SMTPConnectionPool`/`DirectMXRetryQueue`'s own precedent).
public actor MTASTSPolicyManager: MTASTSPolicyProviding {
    private struct CachedPolicy {
        let policy: MTASTSPolicy
        let expiresAt: Date
    }

    /// FIX #2 / FIX #4 (milestone architecture + security review, both
    /// resolved the same way `DirectMXRetryQueue.Configuration` resolved
    /// the equivalent-shaped problems for that actor's own cache -- see
    /// that type's `maxAge`/`maxTotalEntries` doc comments for the
    /// established precedent this mirrors).
    public struct Configuration: Sendable {
        /// FIX #2 (milestone architecture review, BLOCKING): how long past
        /// a cached policy's own `expiresAt` (`CachedPolicy.expiresAt`,
        /// `now()` at fetch time plus that policy's own RFC 8461 §3.2
        /// `max_age`) this manager will still trust and apply it after a
        /// *subsequent* discovery/fetch/parse failure, before instead
        /// reverting the domain to policy-less.
        ///
        /// **This is this library's own explicit, reviewed policy
        /// decision, not an RFC 8461 requirement** -- RFC 8461 itself
        /// specifies no shape for it (see `policy(for:)`'s doc comment for
        /// the actual RFC text this behavior is grounded in, and why the
        /// previous doc comment's "§5.1 anti-flapping" citation was wrong).
        /// Named and recorded here the same way this codebase's DANE-
        /// deferral decision was recorded in
        /// `Documentation/swift6-nio-rewrite-plan.md` §9's Phase 4 bullet
        /// (see that document's corresponding entry for this decision).
        ///
        /// Default 5 days (432,000s) -- deliberately matching
        /// `DirectMXRetryQueue.Configuration.maxAge`'s own default and
        /// rationale (conventional MTA give-up windows, e.g. Postfix's
        /// `maximal_queue_lifetime` default) for consistency across this
        /// codebase's two "how long do we keep trusting stale state"
        /// decisions, not because RFC 8461 mentions this number anywhere.
        /// A domain that has been unreachable (DNS or HTTPS) for 5
        /// straight days is past the point where "assume the old policy
        /// still applies" is a reasonable default; a domain that
        /// legitimately decommissioned MTA-STS during that window instead
        /// reverts to policy-less and delivery can proceed against
        /// whatever its current, real MX hosts are.
        public var staleCacheCeiling: Duration
        /// FIX #4 (MEDIUM security, milestone security review): a hard
        /// ceiling on how many distinct domains' policies this actor will
        /// cache at once -- mirroring
        /// `DirectMXRetryQueue.Configuration.maxTotalEntries`'s identical
        /// concern (a long-lived process with no cap here would grow this
        /// dictionary unboundedly, one entry per distinct domain ever
        /// queried, for the lifetime of the process). Default 10,000,
        /// matching `maxTotalEntries`'s own default for the same
        /// consistency reason `staleCacheCeiling` matches `maxAge`.
        ///
        /// Eviction policy when a new entry would exceed this cap: evict
        /// the cached entry with the earliest `expiresAt` first -- a
        /// cheap, O(n) approximation of LRU (no separate access-order
        /// bookkeeping needed) that fits this actor's existing shape.
        /// "Earliest `expiresAt`" is a reasonable proxy for "least
        /// recently useful" here specifically because every cache write
        /// sets `expiresAt` to a fresh `now() + max_age` -- a domain that
        /// hasn't been re-fetched (i.e., re-queried) in a while is exactly
        /// the one whose `expiresAt` has drifted furthest into the past
        /// relative to its peers.
        public var maxCacheEntries: Int

        public init(
            staleCacheCeiling: Duration = .seconds(5 * 24 * 3600),
            maxCacheEntries: Int = 10_000
        ) {
            self.staleCacheCeiling = staleCacheCeiling
            self.maxCacheEntries = maxCacheEntries
        }
    }

    private var cache: [String: CachedPolicy] = [:]
    private let dnsResolver: any TXTResolving
    private let httpFetcher: any MTASTSHTTPFetching
    private let configuration: Configuration
    /// Injectable purely for deterministic cache-expiry tests (mirroring
    /// this codebase's other "inject the clock" test seams, e.g.
    /// `SMTPConnectionPool`'s own `ContinuousClock` field) -- production
    /// always uses `Date.init` (the real wall clock).
    private let now: @Sendable () -> Date

    public init(
        dnsResolver: any TXTResolving,
        httpFetcher: any MTASTSHTTPFetching = URLSessionMTASTSFetcher(),
        configuration: Configuration = .init()
    ) {
        self.init(dnsResolver: dnsResolver, httpFetcher: httpFetcher, configuration: configuration, now: Date.init)
    }

    /// Test/internal-only initializer: overrides the clock so cache-expiry
    /// tests don't need real `Task.sleep` waits proportional to a
    /// realistic `max_age`.
    init(
        dnsResolver: any TXTResolving, httpFetcher: any MTASTSHTTPFetching,
        configuration: Configuration = .init(), now: @escaping @Sendable () -> Date
    ) {
        self.dnsResolver = dnsResolver
        self.httpFetcher = httpFetcher
        self.configuration = configuration
        self.now = now
    }

    /// - Parameter domain: The destination domain (not the MX exchange
    ///   hostname) -- RFC 8461 §3.1's discovery/fetch hostnames
    ///   (`_mta-sts.<domain>`, `mta-sts.<domain>`) are both derived from the
    ///   recipient domain, never from a resolved MX hostname.
    public func policy(for domain: String) async -> MTASTSPolicy? {
        let currentTime = now()
        // Fast path: a still-valid cached policy is used directly, with no
        // discovery/fetch at all (plan §9 Phase 4's "cache... so you're not
        // fetching on every single send" requirement) -- this is the only
        // branch that guarantees zero calls to `dnsResolver`/`httpFetcher`.
        if let cached = cache[domain], cached.expiresAt > currentTime {
            return cached.policy
        }

        do {
            let policy = try await fetchAndParsePolicy(domain: domain)
            let expiresAt = currentTime.addingTimeInterval(policy.maxAge.timeIntervalValue)
            insertIntoCache(domain: domain, policy: policy, expiresAt: expiresAt)
            return policy
        } catch {
            // FIX #2 (milestone architecture review, BLOCKING -- corrected
            // citation): RFC 8461 §3.3 (fetched and verified directly
            // against the published RFC text, not assumed), not a
            // nonexistent "§5.1 anti-flapping" rule (no such text exists
            // anywhere in RFC 8461):
            //
            //   "If a valid TXT record is found but no policy can be
            //   fetched via HTTPS (for any reason), and there is no valid
            //   (non-expired) previously cached policy, senders MUST
            //   continue with delivery as though the domain has not
            //   implemented MTA-STS. Conversely, if no 'live' policy can be
            //   discovered via DNS or fetched via HTTPS, but a valid
            //   (non-expired) policy exists in the sender's cache, the
            //   sender MUST apply that cached policy."
            //
            // The RFC's own fallback is explicitly gated on the cached
            // policy being "valid (non-expired)" -- not indefinitely stale.
            // This actor's cache-lookup fast path above already only ever
            // returns a policy while `expiresAt > currentTime` (i.e.,
            // genuinely non-expired) with zero network calls; this `catch`
            // branch is reached only once that's no longer true (the
            // policy's own `max_age` has elapsed and a refresh was
            // attempted). Falling back to the stale cached policy here
            // even briefly past its own expiry is a **local, explicit,
            // reviewed extension** beyond the RFC's literal text (bounded
            // by `configuration.staleCacheCeiling`, not indefinite) --
            // see that property's doc comment for the full reasoning and
            // why an unbounded version of this fallback is a real
            // availability bug: a domain that legitimately decommissions
            // MTA-STS (removes its `_mta-sts` TXT record and well-known
            // policy file, e.g. after a hosting/DNS migration) would
            // otherwise have this sender continue enforcing its old,
            // abandoned `enforce` policy forever, since a DNS discovery
            // failure is folded into the very same fallback path as an
            // HTTPS fetch failure. Past the ceiling, a fetch failure
            // reverts the domain to policy-less, exactly matching RFC
            // 8461 §3.3's literal "non-expired" gating -- no cached
            // `enforce`/`testing` constraint outlives its own `max_age`
            // by more than `staleCacheCeiling`.
            guard let cached = cache[domain] else { return nil }
            let staleSince = currentTime.timeIntervalSince(cached.expiresAt)
            guard staleSince <= configuration.staleCacheCeiling.timeIntervalValue else {
                cache.removeValue(forKey: domain)
                return nil
            }
            return cached.policy
        }
    }

    /// FIX #4 (MEDIUM security, milestone security review): enforces
    /// `configuration.maxCacheEntries` on every cache write -- see that
    /// property's doc comment for the eviction policy (earliest
    /// `expiresAt` first) and rationale. A write that merely refreshes an
    /// already-cached domain never counts against the cap (it's not a new
    /// entry), so this only ever evicts when a genuinely new domain would
    /// push `cache.count` past the configured limit.
    private func insertIntoCache(domain: String, policy: MTASTSPolicy, expiresAt: Date) {
        if cache[domain] == nil, cache.count >= configuration.maxCacheEntries {
            if let oldestDomain = cache.min(by: { $0.value.expiresAt < $1.value.expiresAt })?.key {
                cache.removeValue(forKey: oldestDomain)
            }
        }
        cache[domain] = CachedPolicy(policy: policy, expiresAt: expiresAt)
    }

    /// Discovery (RFC 8461 §3.1) + fetch (§3.2) + parse, as one throwing
    /// operation -- any failure at any stage is folded into an
    /// `MTASTSDiscoveryError`, caught by `policy(for:)`'s caller above.
    private func fetchAndParsePolicy(domain: String) async throws -> MTASTSPolicy {
        let discoveryRecords: [String]
        do {
            discoveryRecords = try await dnsResolver.resolveTXT(name: "_mta-sts.\(domain)")
        } catch {
            throw MTASTSDiscoveryError.noSTSv1DiscoveryRecord
        }
        guard discoveryRecords.contains(where: { $0.hasPrefix("v=STSv1") }) else {
            throw MTASTSDiscoveryError.noSTSv1DiscoveryRecord
        }

        // RFC 8461 §3.2: always `https://mta-sts.<domain>/.well-known/mta-sts.txt`,
        // never derived from a resolved MX hostname or affected by any
        // caller-configured port.
        guard let url = URL(string: "https://mta-sts.\(domain)/.well-known/mta-sts.txt") else {
            throw MTASTSDiscoveryError.fetchFailed
        }

        let response: MTASTSHTTPResponse
        do {
            response = try await httpFetcher.fetch(url: url)
        } catch {
            throw MTASTSDiscoveryError.fetchFailed
        }
        guard response.statusCode == 200 else { throw MTASTSDiscoveryError.fetchFailed }
        guard let contentType = response.contentType,
              contentType.lowercased().hasPrefix("text/plain")
        else { throw MTASTSDiscoveryError.invalidContentType }

        let text = String(decoding: response.body, as: UTF8.self)
        guard let policy = MTASTSPolicyParser.parse(text) else { throw MTASTSDiscoveryError.malformedPolicy }
        return policy
    }
}
