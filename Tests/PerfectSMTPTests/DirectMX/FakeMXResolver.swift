//
//  FakeMXResolver.swift
//  PerfectSMTPTests
//
//  `DNSResolver` is a concrete `struct` with no test seam of its own for
//  DirectMXTransport-level tests (which care about MX-fallback/null-MX/
//  retry-queue behavior, not DNS wire encoding -- that's already covered
//  exhaustively by `DNSResolverMXOrderingTests`/`DNSResolverCNAMEFollowingTests`/
//  etc.). `MXResolving` (`Sources/PerfectSMTP/DirectMX/MXResolving.swift`)
//  is the protocol seam added specifically so this fake can stand in for a
//  real resolver in `DirectMXTransport` tests.
//

@testable import PerfectSMTP

/// A fully scripted `MXResolving` fake: exact-match domain/hostname lookups
/// against dictionaries set up by the test, no wildcard/pattern matching.
/// Unregistered domains/hostnames throw `.noRecordsFound` by default
/// (matching a real resolver's NODATA/NXDOMAIN behavior for something that
/// simply isn't configured) unless a specific error is registered instead.
struct FakeMXResolver: MXResolving {
    private let mxRecordsByDomain: [String: [DNSResolver.MXRecord]]
    private let mxErrorsByDomain: [String: DNSResolver.ResolveError]
    private let addressesByHostname: [String: [DNSAddress]]
    /// Optional call-tracking hook, so a test can assert
    /// `resolveAddresses(hostname:)` was (or, critically for the null-MX
    /// test, was **not**) ever invoked -- e.g. proving the RFC 5321 §5.1
    /// implicit-MX fallback was never attempted for a null-MX domain.
    private let onResolveAddresses: (@Sendable (String) -> Void)?

    init(
        mxRecords: [String: [DNSResolver.MXRecord]] = [:],
        mxErrors: [String: DNSResolver.ResolveError] = [:],
        addresses: [String: [DNSAddress]] = [:],
        onResolveAddresses: (@Sendable (String) -> Void)? = nil
    ) {
        self.mxRecordsByDomain = mxRecords
        self.mxErrorsByDomain = mxErrors
        self.addressesByHostname = addresses
        self.onResolveAddresses = onResolveAddresses
    }

    func resolveMX(domain: String) async throws -> [DNSResolver.MXRecord] {
        if let error = mxErrorsByDomain[domain] { throw error }
        if let records = mxRecordsByDomain[domain] { return records }
        throw DNSResolver.ResolveError.noRecordsFound
    }

    func resolveAddresses(hostname: String) async throws -> [DNSAddress] {
        onResolveAddresses?(hostname)
        if let addresses = addressesByHostname[hostname] { return addresses }
        throw DNSResolver.ResolveError.noRecordsFound
    }
}
