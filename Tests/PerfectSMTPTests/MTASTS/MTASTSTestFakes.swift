//
//  MTASTSTestFakes.swift
//  PerfectSMTPTests
//
//  Plan §9 Phase 4: scripted `TXTResolving`/`MTASTSHTTPFetching` fakes,
//  mirroring `FakeMXResolver.swift`'s established pattern -- exact-match
//  lookups against dictionaries/scripts set up by the test, plus call-count
//  tracking so `MTASTSPolicyManagerCacheTests` can assert on how many times
//  the DNS/HTTPS layers were actually invoked (the whole point of the
//  caching behavior under test). Actors, not lock-guarded classes -- both
//  protocol methods are already `async`, so an actor is the natural,
//  Swift-6-strict-concurrency-clean way to hold this fake's mutable
//  call-count/script state (matching this codebase's own established
//  preference for actors over manual locking elsewhere, e.g.
//  `SMTPConnectionPool`/`DirectMXRetryQueue`).
//

import Foundation
@testable import PerfectSMTP

/// A fully scripted `TXTResolving` fake. Unregistered names throw
/// `.noRecordsFound` by default, matching a real resolver's NODATA/NXDOMAIN
/// behavior for a name that simply doesn't publish the record being asked
/// about.
actor FakeTXTResolver: TXTResolving {
    private var recordsByName: [String: [String]]
    private(set) var callCount = 0

    init(records: [String: [String]] = [:]) {
        self.recordsByName = records
    }

    func resolveTXT(name: String) async throws -> [String] {
        callCount += 1
        guard let records = recordsByName[name] else { throw DNSResolver.ResolveError.noRecordsFound }
        return records
    }

    /// FIX B (protocol review) regression coverage: lets a test simulate a
    /// domain republishing its discovery TXT record (a fresh `id=`,
    /// simulating a real MTA-STS policy update) *after* the manager under
    /// test has already cached a policy fetched under the old `id` --
    /// needed since `MTASTSPolicyManager.Configuration.idRecheckInterval`'s
    /// whole point is comparing a fresh lookup against what was cached
    /// earlier, which requires the same fake resolver instance to answer
    /// differently across two calls.
    func setRecords(_ records: [String], for name: String) {
        recordsByName[name] = records
    }
}

/// A fully scripted `MTASTSHTTPFetching` fake: either a fixed response or a
/// fixed error, plus call-count tracking. An actor so a test can flip it
/// from success to failure (`setResponse`/`setFailure`) between two
/// `MTASTSPolicyManager.policy(for:)` calls -- needed for the "fetch
/// failure with a still-cached policy falls back to the cache" test, which
/// must succeed once, then fail, against the *same* fetcher instance.
actor FakeMTASTSHTTPFetcher: MTASTSHTTPFetching {
    struct FetchFailure: Error, Sendable, Equatable {
        let label: String
    }

    private(set) var callCount = 0
    private var response: MTASTSHTTPResponse?
    private var failure: FetchFailure?

    init(response: MTASTSHTTPResponse) {
        self.response = response
    }

    init(failure: FetchFailure) {
        self.failure = failure
    }

    func setResponse(_ response: MTASTSHTTPResponse) {
        self.response = response
        self.failure = nil
    }

    func setFailure(_ failure: FetchFailure) {
        self.failure = failure
        self.response = nil
    }

    func fetch(url: URL) async throws -> MTASTSHTTPResponse {
        callCount += 1
        if let failure { throw failure }
        guard let response else { throw FetchFailure(label: "no response or failure configured") }
        return response
    }
}

/// Convenience for building a well-formed, successful MTA-STS policy-file
/// HTTP response in tests.
func mtaSTSPolicyResponse(_ body: String, contentType: String = "text/plain") -> MTASTSHTTPResponse {
    MTASTSHTTPResponse(statusCode: 200, contentType: contentType, body: Array(body.utf8))
}

/// FIX D (protocol review) regression coverage: a fully scripted
/// `MTASTSAddressResolving` fake, mirroring `FakeTXTResolver`'s exact-match-
/// against-a-dictionary shape -- unregistered hostnames throw
/// `.noRecordsFound`, matching a real resolver's NXDOMAIN/NODATA behavior.
actor FakeMTASTSAddressResolver: MTASTSAddressResolving {
    private let addressesByHostname: [String: [DNSAddress]]
    private(set) var callCount = 0

    init(addresses: [String: [DNSAddress]] = [:]) {
        self.addressesByHostname = addresses
    }

    func resolveAddresses(hostname: String) async throws -> [DNSAddress] {
        callCount += 1
        guard let addresses = addressesByHostname[hostname] else { throw DNSResolver.ResolveError.noRecordsFound }
        return addresses
    }
}
