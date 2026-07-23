//
//  MTASTSPolicyManagerProtocolReviewFixesTests.swift
//  PerfectSMTPTests
//
//  Regression coverage for the non-blocking MTA-STS/protocol reviewer
//  findings fixed in this pass (branch `smtp-phase4-tls-policy`, commit
//  after `83f6ebf`) -- the two BLOCKING findings from the same review
//  (circuit-breaker plaintext-downgrade laundering, unconstrained HTTP
//  redirects) were already fixed and tested prior to this pass; see
//  `MTASTSHTTPFetcherRedirectTests.swift` for the redirect coverage.
//
//  FIX A: RFC 8461 §3.1 MUST -- "exactly one" discovery TXT record.
//  FIX B: RFC 8461 §3.1 -- `id`-based cache invalidation.
//  FIX C: RFC 8461 §3.3 SHOULD -- a response-size cap on the policy fetch.
//  FIX D: SSRF-class address filtering on the MTA-STS HTTPS fetch target,
//  mirroring `DirectMXTransport.makeDialer`'s identical treatment of the
//  direct-MX dial path.
//
//  Uses the same `TXTResolving`/`MTASTSHTTPFetching` fakes and clock-
//  injection test initializer `MTASTSPolicyManagerCacheTests.swift`
//  established, plus this pass's own `FakeMTASTSAddressResolver` and
//  `FakeTXTResolver.setRecords(_:for:)` additions (`MTASTSTestFakes.swift`).
//

import Foundation
import Testing
@testable import PerfectSMTP

struct MTASTSPolicyManagerProtocolReviewFixesTests {
    private let policyBody = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 100\n"

    // MARK: - FIX A: exactly one discovery TXT record

    @Test func twoDiscoveryTXTRecordsAreTreatedAsAmbiguousEvenIfBothAreValidSTSv1Strings() async throws {
        // RFC 8461 §3.1: "If the number of resulting records is not one ...
        // senders MUST assume the recipient domain does not have an
        // available MTA-STS Policy." Two records, each individually a
        // syntactically valid `v=STSv1; id=...` string, must still be
        // rejected as ambiguous -- this is not "pick the first one".
        let dns = FakeTXTResolver(records: [
            "_mta-sts.example.com": ["v=STSv1; id=1", "v=STSv1; id=2"],
        ])
        let http = FakeMTASTSHTTPFetcher(response: mtaSTSPolicyResponse(policyBody))
        let manager = MTASTSPolicyManager(dnsResolver: dns, httpFetcher: http)

        let policy = await manager.policy(for: "example.com")

        #expect(policy == nil, "two discovery TXT records must be treated as ambiguous / no usable policy, not resolved to a policy")
        #expect(await http.callCount == 0, "the HTTPS fetch must never be attempted once discovery is ambiguous")
    }

    // MARK: - FIX B: id-based cache invalidation

    @Test func aChangedDiscoveryIDAfterTheRecheckIntervalElapsesForcesAFreshFetchDespiteAStillValidCache() async throws {
        let dns = FakeTXTResolver(records: ["_mta-sts.example.com": ["v=STSv1; id=1"]])
        // A generous `max_age` (1000s) -- the cache entry must still be
        // well within its own `max_age` validity window when the id-change
        // is detected, proving this is FIX B's id recheck kicking in, not
        // an ordinary `max_age` expiry forcing the same refetch anyway.
        let longPolicyBody = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 1000\n"
        let updatedPolicyBody = "version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 1000\n"
        let http = FakeMTASTSHTTPFetcher(response: mtaSTSPolicyResponse(longPolicyBody))
        let clock = MutableClock()
        let manager = MTASTSPolicyManager(
            dnsResolver: dns, httpFetcher: http,
            configuration: .init(idRecheckInterval: 60),
            now: clock.now
        )

        let first = await manager.policy(for: "example.com")
        #expect(first?.mode == .enforce)
        #expect(await http.callCount == 1)

        // Still comfortably within the 1000s `max_age`, but past the 60s
        // `idRecheckInterval` -- a lookup for "example.com" now must at
        // least re-verify the TXT record's `id`, even though the cached
        // policy itself hasn't expired.
        clock.advance(by: 61)
        await dns.setRecords(["v=STSv1; id=2"], for: "_mta-sts.example.com")
        await http.setResponse(mtaSTSPolicyResponse(updatedPolicyBody))

        let second = await manager.policy(for: "example.com")

        #expect(
            second?.mode == .testing,
            "a changed discovery id, detected on the recheck cadence, must force a fresh fetch rather than continuing to serve the stale-but-still-max_age-valid cached policy"
        )
        #expect(await http.callCount == 2, "the id change must have triggered a genuinely fresh HTTPS fetch")
    }

    @Test func anUnchangedDiscoveryIDAfterTheRecheckIntervalElapsesContinuesServingTheCacheWithoutRefetching() async throws {
        let dns = FakeTXTResolver(records: ["_mta-sts.example.com": ["v=STSv1; id=1"]])
        let longPolicyBody = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 1000\n"
        let http = FakeMTASTSHTTPFetcher(response: mtaSTSPolicyResponse(longPolicyBody))
        let clock = MutableClock()
        let manager = MTASTSPolicyManager(
            dnsResolver: dns, httpFetcher: http,
            configuration: .init(idRecheckInterval: 60),
            now: clock.now
        )

        let first = await manager.policy(for: "example.com")
        #expect(first?.mode == .enforce)
        #expect(await dns.callCount == 1)
        #expect(await http.callCount == 1)

        // Past the recheck interval, but the domain's id hasn't changed --
        // this must cost one more TXT lookup (the recheck itself) but
        // *not* a second HTTPS fetch.
        clock.advance(by: 61)
        let second = await manager.policy(for: "example.com")

        #expect(second?.mode == .enforce)
        #expect(await dns.callCount == 2, "the recheck cadence must have triggered exactly one fresh TXT lookup")
        #expect(await http.callCount == 1, "an unchanged id must not trigger a second HTTPS fetch")
    }

    @Test func aStillWithinRecheckIntervalLookupNeverTouchesDNSOrHTTPSAtAll() async throws {
        let dns = FakeTXTResolver(records: ["_mta-sts.example.com": ["v=STSv1; id=1"]])
        let longPolicyBody = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 1000\n"
        let http = FakeMTASTSHTTPFetcher(response: mtaSTSPolicyResponse(longPolicyBody))
        let clock = MutableClock()
        let manager = MTASTSPolicyManager(
            dnsResolver: dns, httpFetcher: http,
            configuration: .init(idRecheckInterval: 60),
            now: clock.now
        )

        _ = await manager.policy(for: "example.com")
        clock.advance(by: 5) // well under the 60s idRecheckInterval
        _ = await manager.policy(for: "example.com")

        #expect(await dns.callCount == 1, "a lookup still within idRecheckInterval must be the pure zero-network fast path")
        #expect(await http.callCount == 1)
    }

    // MARK: - FIX C: response size cap

    @Test func aResponseLargerThanTheCapIsTreatedAsAFetchFailure() async throws {
        let dns = FakeTXTResolver(records: ["_mta-sts.example.com": ["v=STSv1; id=1"]])
        // A body that parses as a perfectly well-formed policy but pads
        // past the 64KB cap with a long run of `mx:` lines -- proves the
        // cap is enforced independently of whether the (oversized) body
        // would otherwise have parsed successfully.
        var oversizedBody = "version: STSv1\nmode: enforce\nmax_age: 100\n"
        while oversizedBody.utf8.count <= 64 * 1024 {
            oversizedBody += "mx: mail.example.com\n"
        }
        let http = FakeMTASTSHTTPFetcher(response: mtaSTSPolicyResponse(oversizedBody))
        let manager = MTASTSPolicyManager(dnsResolver: dns, httpFetcher: http)

        let policy = await manager.policy(for: "example.com")

        #expect(policy == nil, "a response body over the 64KB cap must be treated as a fetch failure, never parsed/cached/acted upon")
    }

    @Test func aResponseAtExactlyTheCapIsStillAccepted() async throws {
        // Boundary check: exactly at the cap must not be rejected --
        // `MTASTSPolicyManager.maximumPolicyResponseSizeBytes` is an
        // inclusive ceiling (`<=`), matching `SMTPBootstrap
        // .maximumReplyBufferSize`'s own precedent.
        var body = "version: STSv1\nmode: enforce\nmax_age: 100\n"
        while body.utf8.count < 64 * 1024 {
            body += "#"
        }
        #expect(body.utf8.count == 64 * 1024)

        let dns = FakeTXTResolver(records: ["_mta-sts.example.com": ["v=STSv1; id=1"]])
        let http = FakeMTASTSHTTPFetcher(response: mtaSTSPolicyResponse(body))
        let manager = MTASTSPolicyManager(dnsResolver: dns, httpFetcher: http)

        let policy = await manager.policy(for: "example.com")

        #expect(policy?.mode == .enforce, "a response body exactly at the 64KB cap must still be accepted")
    }

    // MARK: - FIX D: SSRF-class address filtering on the HTTPS fetch target

    @Test func aFetchTargetResolvingOnlyToAPrivateAddressIsRefusedRatherThanAttempted() async throws {
        let dns = FakeTXTResolver(records: ["_mta-sts.example.com": ["v=STSv1; id=1"]])
        let http = FakeMTASTSHTTPFetcher(response: mtaSTSPolicyResponse(policyBody))
        let addressResolver = FakeMTASTSAddressResolver(addresses: [
            "mta-sts.example.com": [.v4([127, 0, 0, 1])],
        ])
        let manager = MTASTSPolicyManager(
            dnsResolver: dns, httpFetcher: http, addressResolver: addressResolver
        )

        let policy = await manager.policy(for: "example.com")

        #expect(policy == nil, "a fetch target that resolves only to a private/loopback address must be refused, not attempted")
        #expect(await http.callCount == 0, "the HTTPS fetch must never even be attempted once every resolved address is filtered as private")
    }

    @Test func aFetchTargetResolvingToARoutableAddressProceedsNormally() async throws {
        let dns = FakeTXTResolver(records: ["_mta-sts.example.com": ["v=STSv1; id=1"]])
        let http = FakeMTASTSHTTPFetcher(response: mtaSTSPolicyResponse(policyBody))
        let addressResolver = FakeMTASTSAddressResolver(addresses: [
            "mta-sts.example.com": [.v4([93, 184, 216, 34])],
        ])
        let manager = MTASTSPolicyManager(
            dnsResolver: dns, httpFetcher: http, addressResolver: addressResolver
        )

        let policy = await manager.policy(for: "example.com")

        #expect(policy?.mode == .enforce, "a fetch target resolving to a public address must proceed normally")
        #expect(await http.callCount == 1)
    }

    @Test func withNoAddressResolverConfiguredThePrivateAddressCheckIsSkippedEntirely() async throws {
        // The default, purely-additive-opt-in shape (mirroring
        // `DirectMXTransport.mtaSTSPolicyProvider`'s own default `nil`):
        // no `addressResolver` means no new network dependency and no
        // behavior change from FIX D.
        let dns = FakeTXTResolver(records: ["_mta-sts.example.com": ["v=STSv1; id=1"]])
        let http = FakeMTASTSHTTPFetcher(response: mtaSTSPolicyResponse(policyBody))
        let manager = MTASTSPolicyManager(dnsResolver: dns, httpFetcher: http)

        let policy = await manager.policy(for: "example.com")

        #expect(policy?.mode == .enforce)
        #expect(await http.callCount == 1)
    }

    @Test func allowPrivateAddressesOptsBackIntoFetchingAPrivateOnlyTarget() async throws {
        let dns = FakeTXTResolver(records: ["_mta-sts.example.com": ["v=STSv1; id=1"]])
        let http = FakeMTASTSHTTPFetcher(response: mtaSTSPolicyResponse(policyBody))
        let addressResolver = FakeMTASTSAddressResolver(addresses: [
            "mta-sts.example.com": [.v4([127, 0, 0, 1])],
        ])
        let manager = MTASTSPolicyManager(
            dnsResolver: dns, httpFetcher: http, addressResolver: addressResolver,
            configuration: .init(allowPrivateAddresses: true)
        )

        let policy = await manager.policy(for: "example.com")

        #expect(policy?.mode == .enforce, "allowPrivateAddresses must opt back into attempting the fetch even against a private-only target, mirroring DirectMXConfig's identical escape hatch")
        #expect(await http.callCount == 1)
    }
}
