//
//  MTASTSPolicyManagerStalenessAndCapacityTests.swift
//  PerfectSMTPTests
//
//  Milestone architecture + security review, Phase 4 fix pass:
//
//  FIX #2 (BLOCKING architecture issue): `MTASTSPolicyManager.policy(for:)`'s
//  stale-cache fallback (a fetch failure re-uses the last successfully
//  fetched policy) previously had no expiry ceiling at all -- a domain that
//  legitimately decommissioned MTA-STS would have this sender continue
//  enforcing its old, abandoned policy forever. `Configuration
//  .staleCacheCeiling` bounds that; these tests exercise both sides of the
//  boundary: still-within-ceiling (fall back to the stale policy) and
//  past-the-ceiling (revert to policy-less).
//
//  FIX #4 (MEDIUM security): `MTASTSPolicyManager`'s cache previously had no
//  size cap at all, unlike the established `DirectMXRetryQueue
//  .Configuration.maxTotalEntries` precedent for exactly this concern.
//  `Configuration.maxCacheEntries` caps it, evicting the entry with the
//  earliest `expiresAt` first.
//
//  Both use the same `init(dnsResolver:httpFetcher:configuration:now:)`
//  test-only clock-injection overload `MTASTSPolicyManagerCacheTests`
//  already established, for the same determinism reason.
//

import Foundation
import Testing
@testable import PerfectSMTP

struct MTASTSPolicyManagerStalenessAndCapacityTests {
    private let discoveryTXT = ["v=STSv1; id=1"]
    /// `max_age: 1` -- the cached entry expires almost immediately after
    /// being fetched, so a short, test-controlled clock advance is enough
    /// to reach "expired, refresh attempted, refresh fails" without
    /// needing an unrealistically long-lived fixture.
    private let shortPolicyBody = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 1\n"

    // MARK: - FIX #2: staleness ceiling

    @Test func aFetchFailureWithinTheStaleCacheCeilingStillFallsBackToTheCachedPolicy() async throws {
        let dns = FakeTXTResolver(records: ["_mta-sts.example.com": discoveryTXT])
        let http = FakeMTASTSHTTPFetcher(response: mtaSTSPolicyResponse(shortPolicyBody))
        let clock = MutableClock()
        let manager = MTASTSPolicyManager(
            dnsResolver: dns, httpFetcher: http,
            configuration: .init(staleCacheCeiling: 5),
            now: clock.now
        )

        let first = await manager.policy(for: "example.com")
        #expect(first?.mode == .enforce)

        // `max_age: 1` has elapsed; advance 3s further -- 3s past the
        // policy's own expiry, still comfortably inside the 5s
        // `staleCacheCeiling` configured above.
        clock.advance(by: 4)
        await http.setFailure(.init(label: "simulated transient fetch failure"))

        let second = await manager.policy(for: "example.com")
        #expect(second?.mode == .enforce, "a fetch failure still within the staleness ceiling must keep applying the last-known policy")
    }

    @Test func aFetchFailurePastTheStaleCacheCeilingRevertsTheDomainToPolicyLess() async throws {
        let dns = FakeTXTResolver(records: ["_mta-sts.example.com": discoveryTXT])
        let http = FakeMTASTSHTTPFetcher(response: mtaSTSPolicyResponse(shortPolicyBody))
        let clock = MutableClock()
        let manager = MTASTSPolicyManager(
            dnsResolver: dns, httpFetcher: http,
            configuration: .init(staleCacheCeiling: 5),
            now: clock.now
        )

        let first = await manager.policy(for: "example.com")
        #expect(first?.mode == .enforce)

        // `max_age: 1` has elapsed; advance 20s further -- well past the
        // 5s `staleCacheCeiling` configured above (the policy is now
        // stale-past-ceiling, not merely stale).
        clock.advance(by: 21)
        await http.setFailure(.init(label: "simulated permanent fetch failure -- e.g. the domain decommissioned MTA-STS"))

        let second = await manager.policy(for: "example.com")
        let failureMessage =
            """
            FIX #2 regression: a fetch failure past the staleness ceiling must revert the domain to policy-less \
            (no MX-pattern constraint, no mandatory TLS) rather than continuing to enforce the stale policy \
            forever -- this is exactly the scenario of a domain that legitimately decommissioned MTA-STS
            """
        #expect(second == nil, "\(failureMessage)")

        // A subsequent lookup must attempt a fresh discovery/fetch again
        // (the stale entry was actually evicted, not just skipped once) --
        // proves this isn't a one-shot fluke of the specific `catch`
        // branch taken above.
        await http.setResponse(mtaSTSPolicyResponse(shortPolicyBody))
        let third = await manager.policy(for: "example.com")
        #expect(third?.mode == .enforce, "a later successful fetch must still be able to re-populate the cache normally")
    }

    // MARK: - FIX #4: cache size cap

    @Test func cacheSizeIsCappedAndEvictsTheEarliestExpiringEntryFirst() async throws {
        let dns = FakeTXTResolver(records: [
            "_mta-sts.a.example": discoveryTXT,
            "_mta-sts.b.example": discoveryTXT,
            "_mta-sts.c.example": discoveryTXT,
        ])
        // A generous `max_age` (1000s) -- once populated, none of these
        // three entries expire on their own during this test; only the
        // capacity-driven eviction below should ever remove one.
        let longPolicyBody = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 1000\n"
        let http = FakeMTASTSHTTPFetcher(response: mtaSTSPolicyResponse(longPolicyBody))
        let clock = MutableClock()
        let manager = MTASTSPolicyManager(
            dnsResolver: dns, httpFetcher: http,
            configuration: .init(maxCacheEntries: 2),
            now: clock.now
        )

        // Fetch "a.example" first (earliest `expiresAt`), then "b.example"
        // a second later, then "c.example" a second after that -- gives
        // each entry a distinct, strictly increasing `expiresAt` so the
        // eviction-order assertion below is unambiguous.
        let a1 = await manager.policy(for: "a.example")
        #expect(a1?.mode == .enforce)
        clock.advance(by: 1)
        let b1 = await manager.policy(for: "b.example")
        #expect(b1?.mode == .enforce)
        clock.advance(by: 1)
        // Cache is now at its configured cap (2 entries: a, b). Fetching a
        // third, previously-uncached domain must evict the entry with the
        // earliest `expiresAt` -- "a.example" -- to make room.
        let c1 = await manager.policy(for: "c.example")
        #expect(c1?.mode == .enforce)

        #expect(await dns.callCount == 3)
        #expect(await http.callCount == 3)

        // "b.example" and "c.example" must still be cache-resident (no
        // re-fetch needed) ...
        _ = await manager.policy(for: "b.example")
        _ = await manager.policy(for: "c.example")
        #expect(await dns.callCount == 3, "b.example/c.example must still have been served from cache, not re-fetched")
        #expect(await http.callCount == 3, "b.example/c.example must still have been served from cache, not re-fetched")

        // ... but "a.example" must have been evicted -- a lookup for it
        // must trigger a genuinely fresh discovery/fetch.
        _ = await manager.policy(for: "a.example")
        #expect(await dns.callCount == 4, "a.example must have been evicted from the cache once maxCacheEntries was exceeded, forcing a fresh discovery lookup")
        #expect(await http.callCount == 4, "a.example must have been evicted from the cache once maxCacheEntries was exceeded, forcing a fresh fetch")
    }
}
