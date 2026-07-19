//
//  MTASTSHTTPFetching.swift
//  PerfectSMTP
//
//  Plan §9 Phase 4: the HTTPS fetch step of MTA-STS policy discovery (RFC
//  8461 §3.2 -- `GET https://mta-sts.<domain>/.well-known/mta-sts.txt`).
//
//  **Uses `Foundation.URLSession`, deliberately, not a hand-rolled or
//  NIO-based HTTP client** -- this matches this ecosystem's established
//  convention for simple, one-shot request/response HTTPS calls (Perfect-
//  FileMaker moved *off* PerfectCURL specifically to async/await
//  `URLSession` for exactly this kind of need; see
//  `Documentation/swift6-nio-rewrite-plan.md` §2's own citation of that
//  precedent). Building a second HTTP stack on top of swift-nio purely for
//  one GET request per (cache-miss) domain would be exactly the kind of
//  disproportionate engineering this plan's Phase 4 brief warns against --
//  MTA-STS's own fetch step has no pipelining, connection-pooling, or
//  streaming-body requirement that would justify it.
//
//  The fetch itself uses normal, fully-verified TLS: `URLSession`'s default
//  server-trust evaluation is never overridden or disabled anywhere in this
//  file -- an MTA-STS policy fetched over a connection with an invalid/
//  unverified certificate would be worse than useless (an attacker who can
//  MITM the HTTPS fetch could simply serve a permissive fake policy, or no
//  policy at all).
//
//  `MTASTSHTTPFetching` is the test seam (mirroring `MXResolving`'s and
//  `TXTResolving`'s pattern) that lets `MTASTSPolicyManagerCacheTests`
//  script fetch outcomes (success, 404, wrong content-type, network error)
//  without making a real network call.
//

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// One HTTPS response, reduced to exactly what MTA-STS policy fetching
/// needs (RFC 8461 §3.3: status code, `Content-Type`, and the body) --
/// deliberately not `URLResponse`/`Data` directly, so the test seam below
/// doesn't require a real `URLSession` round-trip to construct a fixture.
public struct MTASTSHTTPResponse: Sendable {
    public let statusCode: Int
    public let contentType: String?
    public let body: [UInt8]

    public init(statusCode: Int, contentType: String?, body: [UInt8]) {
        self.statusCode = statusCode
        self.contentType = contentType
        self.body = body
    }
}

/// The seam `MTASTSPolicyManager` fetches through -- `URLSessionMTASTSFetcher`
/// in production, a scripted fake in tests.
public protocol MTASTSHTTPFetching: Sendable {
    /// - Throws: Any error means "this fetch failed" as far as
    ///   `MTASTSPolicyManager` is concerned (network error, TLS failure,
    ///   timeout, DNS-for-the-HTTPS-hostname failure, etc.) -- it does not
    ///   need to distinguish failure modes beyond what `MTASTSHTTPResponse`
    ///   itself already communicates for a completed HTTP exchange (status
    ///   code, content type).
    func fetch(url: URL) async throws -> MTASTSHTTPResponse
}

/// Errors specific to this fetcher's own plumbing (as opposed to
/// `MTASTSDiscoveryError`, which classifies the higher-level discovery/
/// fetch/parse outcome `MTASTSPolicyManager` cares about).
public enum MTASTSHTTPFetchError: Error, Sendable, Equatable {
    /// `URLSession`'s response wasn't an `HTTPURLResponse` at all -- not
    /// expected for an `https://` URL in practice, handled defensively
    /// rather than force-cast.
    case notAnHTTPResponse
}

/// The production `MTASTSHTTPFetching` implementation: a plain `URLSession`
/// GET, default (fully-verified) TLS trust evaluation, no caching layer of
/// its own (`MTASTSPolicyManager` is the cache; asking `URLSession` to also
/// cache per HTTP semantics would just be a second, uncoordinated cache
/// with its own, RFC-9111-shaped expiry rules layered underneath the one
/// that actually matters here, RFC 8461 §3.2's `max_age`).
public struct URLSessionMTASTSFetcher: MTASTSHTTPFetching {
    private let session: URLSession

    public init(session: URLSession = .shared) {
        self.session = session
    }

    public func fetch(url: URL) async throws -> MTASTSHTTPResponse {
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw MTASTSHTTPFetchError.notAnHTTPResponse
        }
        return MTASTSHTTPResponse(
            statusCode: http.statusCode,
            contentType: http.value(forHTTPHeaderField: "Content-Type"),
            body: Array(data)
        )
    }
}
