//
//  TXTResolving.swift
//  PerfectSMTP
//
//  Plan §9 Phase 4: the same protocol-seam pattern
//  `Sources/PerfectSMTP/DirectMX/MXResolving.swift` established for Phase 3
//  -- `DNSResolver` is a concrete `struct`, so a small protocol carrying
//  only the one method `MTASTSPolicyManager` actually needs is what lets
//  tests inject a fake TXT resolver instead of standing up a real
//  `FakeDNSServer` (disproportionate for policy-manager-level discovery/
//  caching tests that don't care about DNS wire encoding at all -- that's
//  already covered exhaustively by `DNSWireFormatTests`).
//
//  Deliberately its own protocol, not folded into `MXResolving`:
//  `MXResolving` is specifically "the subset of `DNSResolver` `DirectMXTransport`
//  depends on" (see that file's header comment) -- TXT lookup has nothing to
//  do with MX/A/AAAA resolution or direct-MX delivery, it's MTA-STS's own
//  concern, so it gets its own narrow seam rather than widening an existing
//  one to cover an unrelated need.
//

/// The subset of `DNSResolver`'s public surface `MTASTSPolicyManager`
/// depends on. See `DNSResolver.resolveTXT(name:)`'s doc comment for the
/// exact contract -- this protocol adds no new semantics of its own.
public protocol TXTResolving: Sendable {
    func resolveTXT(name: String) async throws -> [String]
}

extension DNSResolver: TXTResolving {}
