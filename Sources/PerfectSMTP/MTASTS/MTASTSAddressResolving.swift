//
//  MTASTSAddressResolving.swift
//  PerfectSMTP
//
//  FIX D (protocol/MTA-STS follow-up review, option (a)): the seam
//  `MTASTSPolicyManager` uses to apply the same SSRF-class address
//  filtering to the MTA-STS HTTPS fetch target that `DirectMXTransport
//  .makeDialer` already applies to every resolved MX/A/AAAA address on the
//  direct-MX dial path (see that method's own comment and
//  `DirectMXConfig`'s doc comment for the full threat model this mirrors:
//  "a caller that lets an untrusted party influence the recipient domain").
//
//  Deliberately its own tiny protocol -- not folded into `TXTResolving`
//  (that seam is specifically "just TXT lookup", see its own header
//  comment) and not `MXResolving` either (that protocol's `resolveMX(
//  domain:)` requirement has nothing to do with MTA-STS and would force
//  every fake conforming to this one to also implement an unrelated MX
//  lookup). Same shape as `MXResolving.resolveAddresses(hostname:)`
//  ("copied verbatim" per that file's own header comment about the
//  original `TXTResolving`/`MXResolving` split) -- `DNSResolver` already
//  implements this method (it's `MXResolving`'s), so `extension
//  DNSResolver: MTASTSAddressResolving {}` below is a free conformance,
//  exactly like `TXTResolving`'s and `MXResolving`'s own extensions.
//

/// The subset of `DNSResolver`'s public surface `MTASTSPolicyManager` needs
/// to pre-check the MTA-STS HTTPS fetch target (`mta-sts.<domain>`) against
/// `DNSAddress.isRoutable` before ever attempting the fetch. See
/// `MTASTSPolicyManager.init`'s `addressResolver` parameter doc comment for
/// why this is a separate, optional dependency rather than folded into the
/// existing `dnsResolver: any TXTResolving` parameter.
public protocol MTASTSAddressResolving: Sendable {
    func resolveAddresses(hostname: String) async throws -> [DNSAddress]
}

extension DNSResolver: MTASTSAddressResolving {}
