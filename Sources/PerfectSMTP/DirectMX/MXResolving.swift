//
//  MXResolving.swift
//  PerfectSMTP
//
//  Plan §9 Phase 3: `DNSResolver` (built in the first half of this phase,
//  commit 19cfa91) is a concrete `struct`, not a protocol -- there was no
//  way to inject a fake resolver into `DirectMXTransport`'s tests without
//  either standing up a real fake DNS server (`FakeDNSServer`, already used
//  by `DNSResolver`'s own tests, but disproportionate for transport-level
//  MX-fallback/null-MX/retry-queue tests that don't care about wire
//  encoding at all) or introducing a small protocol seam here. This is that
//  seam -- flagged explicitly per this task's own instructions as a
//  reasonable, expected addition Phase 3a's implementer didn't know Phase
//  3b would need, not scope creep.
//
//  The two methods below are copied verbatim (same names, same signatures)
//  from `DNSResolver`'s own public API, so `extension DNSResolver:
//  MXResolving {}` is a free conformance -- no adapter/wrapper type needed.
//

/// The subset of `DNSResolver`'s public surface `DirectMXTransport` depends
/// on, extracted as a protocol so tests can inject a fake resolver instead
/// of a real one. See each method's doc comment on `DNSResolver` itself for
/// the exact contract (null-MX hard-fail, the RFC 5321 §5.1 implicit-MX
/// fallback left to the caller, A+AAAA combining, etc.) -- this protocol
/// adds no new semantics of its own.
public protocol MXResolving: Sendable {
    func resolveMX(domain: String) async throws -> [DNSResolver.MXRecord]
    func resolveAddresses(hostname: String) async throws -> [DNSAddress]
}

extension DNSResolver: MXResolving {}
