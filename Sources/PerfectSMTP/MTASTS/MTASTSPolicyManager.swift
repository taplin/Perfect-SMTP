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
    /// §3.3/§5.1 and plan §9 Phase 4's explicit instruction, every failure
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

    private var cache: [String: CachedPolicy] = [:]
    private let dnsResolver: any TXTResolving
    private let httpFetcher: any MTASTSHTTPFetching
    /// Injectable purely for deterministic cache-expiry tests (mirroring
    /// this codebase's other "inject the clock" test seams, e.g.
    /// `SMTPConnectionPool`'s own `ContinuousClock` field) -- production
    /// always uses `Date.init` (the real wall clock).
    private let now: @Sendable () -> Date

    public init(
        dnsResolver: any TXTResolving,
        httpFetcher: any MTASTSHTTPFetching = URLSessionMTASTSFetcher()
    ) {
        self.init(dnsResolver: dnsResolver, httpFetcher: httpFetcher, now: Date.init)
    }

    /// Test/internal-only initializer: overrides the clock so cache-expiry
    /// tests don't need real `Task.sleep` waits proportional to a
    /// realistic `max_age`.
    init(dnsResolver: any TXTResolving, httpFetcher: any MTASTSHTTPFetching, now: @escaping @Sendable () -> Date) {
        self.dnsResolver = dnsResolver
        self.httpFetcher = httpFetcher
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
            cache[domain] = CachedPolicy(policy: policy, expiresAt: currentTime.addingTimeInterval(policy.maxAge.timeIntervalValue))
            return policy
        } catch {
            // RFC 8461 §5.1: a transient fetch failure shouldn't
            // immediately drop enforcement. This is deliberately not
            // restricted to "only if the stale entry hasn't technically
            // expired yet" -- once a domain has successfully published a
            // policy, the most recent one is still the best information
            // available on a fetch failure, whether that failure happens
            // one second or one month past the policy's own `max_age`; the
            // alternative (silently reverting to policy-less the moment a
            // single refresh attempt fails) is exactly the flapping this
            // guidance exists to prevent. Only when there is no prior
            // policy at all does a fetch failure mean "no MTA-STS policy."
            return cache[domain]?.policy
        }
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
