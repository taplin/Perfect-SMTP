//
//  MTASTSPolicyManagerCacheTests.swift
//  PerfectSMTPTests
//
//  Plan §9 Phase 4: `MTASTSPolicyManager`'s discovery/fetch/parse/cache
//  pipeline, using the `TXTResolving`/`MTASTSHTTPFetching` protocol seams
//  (`FakeTXTResolver`/`FakeMTASTSHTTPFetcher`, `MTASTSTestFakes.swift`) so
//  no real DNS or network access is ever needed -- mirroring
//  `DirectMXTransportTests`' use of `FakeMXResolver` for the same reason.
//
//  Cache-expiry determinism uses the `init(dnsResolver:httpFetcher:now:)`
//  test-only clock-injection overload (package-internal, reached via
//  `@testable import`) rather than real `Task.sleep` waits proportional to
//  a realistic `max_age` -- mirroring `SMTPConnectionPool`'s own injected-
//  clock precedent for the same reason (fast, deterministic tests).
//

import Foundation
import Testing
@testable import PerfectSMTP

struct MTASTSPolicyManagerCacheTests {
    private let discoveryTXT = ["v=STSv1; id=1"]
    private let policyBody = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 100\n"

    @Test func aSecondPolicyLookupWithinMaxAgeDoesNotReFetch() async throws {
        let dns = FakeTXTResolver(records: ["_mta-sts.example.com": discoveryTXT])
        let http = FakeMTASTSHTTPFetcher(response: mtaSTSPolicyResponse(policyBody))
        let manager = MTASTSPolicyManager(dnsResolver: dns, httpFetcher: http)

        let first = await manager.policy(for: "example.com")
        let second = await manager.policy(for: "example.com")

        #expect(first?.mode == .enforce)
        #expect(second?.mode == .enforce)
        #expect(await dns.callCount == 1)
        #expect(await http.callCount == 1)
    }

    @Test func aFetchFailureWithAStillCachedPolicyContinuesUsingTheCache() async throws {
        let dns = FakeTXTResolver(records: ["_mta-sts.example.com": discoveryTXT])
        let http = FakeMTASTSHTTPFetcher(response: mtaSTSPolicyResponse(policyBody))
        // A 1-second `max_age` (well below the parsed policy's own,
        // irrelevant here) and a clock this test fully controls -- primes
        // the cache with a first, successful fetch, then advances past
        // that entry's expiry and flips the fetcher to fail, so the second
        // `policy(for:)` call is forced to attempt (and fail) a refresh.
        let shortPolicyBody = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 1\n"
        await http.setResponse(mtaSTSPolicyResponse(shortPolicyBody))
        let clock = MutableClock()
        let manager = MTASTSPolicyManager(dnsResolver: dns, httpFetcher: http, now: clock.now)

        let first = await manager.policy(for: "example.com")
        #expect(first?.mode == .enforce)
        #expect(await http.callCount == 1)

        // Advance well past the 1-second `max_age` and make the next fetch
        // attempt fail outright.
        clock.advance(by: 10)
        await http.setFailure(.init(label: "simulated network failure"))

        let second = await manager.policy(for: "example.com")
        #expect(second?.mode == .enforce, "expected the stale-but-only-known policy to still be returned despite the fetch failure")
        #expect(await http.callCount == 2, "a refresh attempt must have been made (and failed) -- this is what proves the fallback, not the fast no-refetch path")
    }

    @Test func aFetchFailureWithNoCacheAtAllTreatsTheDomainAsPolicyLess() async throws {
        let dns = FakeTXTResolver(records: ["_mta-sts.example.com": discoveryTXT])
        let http = FakeMTASTSHTTPFetcher(failure: .init(label: "simulated network failure"))
        let manager = MTASTSPolicyManager(dnsResolver: dns, httpFetcher: http)

        let policy = await manager.policy(for: "example.com")
        #expect(policy == nil)
    }

    @Test func noSTSv1DiscoveryTXTRecordTreatsTheDomainAsPolicyLessWithoutEverFetchingHTTPS() async throws {
        let dns = FakeTXTResolver() // no records registered for any name
        let http = FakeMTASTSHTTPFetcher(response: mtaSTSPolicyResponse(policyBody))
        let manager = MTASTSPolicyManager(dnsResolver: dns, httpFetcher: http)

        let policy = await manager.policy(for: "nomtasts.example.com")
        #expect(policy == nil)
        #expect(await http.callCount == 0, "the HTTPS fetch must never even be attempted when discovery finds no v=STSv1 record")
    }

    @Test func aNon200StatusTreatsTheDomainAsPolicyLess() async throws {
        let dns = FakeTXTResolver(records: ["_mta-sts.example.com": discoveryTXT])
        let http = FakeMTASTSHTTPFetcher(response: MTASTSHTTPResponse(statusCode: 404, contentType: "text/plain", body: []))
        let manager = MTASTSPolicyManager(dnsResolver: dns, httpFetcher: http)

        let policy = await manager.policy(for: "example.com")
        #expect(policy == nil)
    }

    @Test func aWrongContentTypeTreatsTheDomainAsPolicyLess() async throws {
        let dns = FakeTXTResolver(records: ["_mta-sts.example.com": discoveryTXT])
        let http = FakeMTASTSHTTPFetcher(response: MTASTSHTTPResponse(statusCode: 200, contentType: "text/html", body: Array(policyBody.utf8)))
        let manager = MTASTSPolicyManager(dnsResolver: dns, httpFetcher: http)

        let policy = await manager.policy(for: "example.com")
        #expect(policy == nil)
    }

    @Test func aMalformedPolicyBodyTreatsTheDomainAsPolicyLessRatherThanCrashing() async throws {
        let dns = FakeTXTResolver(records: ["_mta-sts.example.com": discoveryTXT])
        let http = FakeMTASTSHTTPFetcher(response: mtaSTSPolicyResponse("this is not a valid policy file"))
        let manager = MTASTSPolicyManager(dnsResolver: dns, httpFetcher: http)

        let policy = await manager.policy(for: "example.com")
        #expect(policy == nil)
    }

    @Test func differentDomainsAreCachedIndependently() async throws {
        let dns = FakeTXTResolver(records: [
            "_mta-sts.a.example": ["v=STSv1; id=1"],
            "_mta-sts.b.example": ["v=STSv1; id=1"],
        ])
        let http = FakeMTASTSHTTPFetcher(response: mtaSTSPolicyResponse(policyBody))
        let manager = MTASTSPolicyManager(dnsResolver: dns, httpFetcher: http)

        _ = await manager.policy(for: "a.example")
        _ = await manager.policy(for: "b.example")
        _ = await manager.policy(for: "a.example")
        _ = await manager.policy(for: "b.example")

        #expect(await dns.callCount == 2)
        #expect(await http.callCount == 2)
    }
}

/// A test-controlled `Date` source: starts at a fixed instant and only
/// moves forward when `advance(by:)` is called -- gives
/// `MTASTSPolicyManagerCacheTests` deterministic control over cache expiry
/// without real `Task.sleep` waits.
final class MutableClock: @unchecked Sendable {
    private let lock = NSLock()
    private var current: Date

    init(startingAt start: Date = Date(timeIntervalSince1970: 1_700_000_000)) {
        self.current = start
    }

    func advance(by seconds: TimeInterval) {
        lock.lock()
        current = current.addingTimeInterval(seconds)
        lock.unlock()
    }

    func now() -> Date {
        lock.lock()
        defer { lock.unlock() }
        return current
    }
}
