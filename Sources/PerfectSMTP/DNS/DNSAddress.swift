//
//  DNSAddress.swift
//  PerfectSMTP
//
//  Plan §9 Phase 3: the `IPAddress` return type sketched in the phase
//  brief, named `DNSAddress` here to avoid colliding with any
//  `Foundation`/platform type of a similar name. A deliberately minimal
//  value type over raw address bytes -- not a wrapper around NIOCore's
//  `SocketAddress`, because `SocketAddress` always carries a port and a
//  resolved-hostname string that make no sense for a bare A/AAAA record;
//  the transport-layer consumer (`DirectMXTransport`) is expected to
//  combine one of these with a port via
//  `SocketAddress(ipAddress: address.description, port: ...)` once it knows
//  which port it's connecting on -- that composition is a transport
//  decision, not this resolver's.
//

/// A raw IPv4 or IPv6 address, as decoded from an A/AAAA resource record.
/// No port, no hostname -- just the address bytes plus a
/// `CustomStringConvertible` rendering suitable for feeding straight into
/// `NIOCore.SocketAddress(ipAddress:port:)`.
public enum DNSAddress: Sendable, Hashable {
    /// Exactly 4 bytes, network byte order (as they appeared in the A
    /// record's RDATA).
    case v4([UInt8])
    /// Exactly 16 bytes, network byte order (as they appeared in the AAAA
    /// record's RDATA).
    case v6([UInt8])
}

extension DNSAddress {
    /// FIX #2 (plan §9 Phase 3 milestone security review, SSRF-class
    /// filtering): `false` for any address in a private, loopback,
    /// link-local, unique-local, or carrier-grade-NAT range -- the ranges
    /// a caller resolving an *untrusted* hostname (e.g. `DirectMXTransport`
    /// resolving a recipient-controlled domain's MX/A/AAAA records) must
    /// not blindly dial into. See `DirectMXConfig.allowPrivateAddresses`
    /// for where this is applied and its documented opt-out.
    ///
    /// Covers, at minimum: RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`,
    /// `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local
    /// (`169.254.0.0/16` -- which includes the cloud-metadata
    /// `169.254.169.254` -- and `fe80::/10`), IPv6 unique-local
    /// (`fc00::/7`), RFC 6598 carrier-grade NAT (`100.64.0.0/10`), and the
    /// IPv6 unspecified address (`::`, never a sensible dial target
    /// either way). Also unwraps an IPv4-mapped IPv6 address
    /// (`::ffff:a.b.c.d`, RFC 4291 §2.5.5.2) and evaluates the *embedded*
    /// IPv4 address against the same IPv4 ranges -- without this, an
    /// attacker could trivially bypass every IPv4 check above by
    /// publishing an AAAA record for `::ffff:127.0.0.1` instead of an A
    /// record for `127.0.0.1`, since that's the literal address that
    /// would be handed to `SocketAddress(ipAddress:port:)` and dialed.
    public var isRoutable: Bool {
        switch self {
        case .v4(let bytes):
            return Self.isRoutableIPv4(bytes)
        case .v6(let bytes):
            guard bytes.count == 16 else { return true } // defensive; DNSWireFormat guarantees exactly 16
            if bytes[0..<10].allSatisfy({ $0 == 0 }), bytes[10] == 0xFF, bytes[11] == 0xFF {
                return Self.isRoutableIPv4(Array(bytes[12..<16]))
            }
            return Self.isRoutableIPv6(bytes)
        }
    }

    private static func isRoutableIPv4(_ bytes: [UInt8]) -> Bool {
        guard bytes.count == 4 else { return true } // defensive; DNSWireFormat guarantees exactly 4
        if bytes[0] == 127 { return false } // 127.0.0.0/8 -- loopback
        if bytes[0] == 10 { return false } // 10.0.0.0/8 -- RFC 1918
        if bytes[0] == 172, (16...31).contains(bytes[1]) { return false } // 172.16.0.0/12 -- RFC 1918
        if bytes[0] == 192, bytes[1] == 168 { return false } // 192.168.0.0/16 -- RFC 1918
        if bytes[0] == 169, bytes[1] == 254 { return false } // 169.254.0.0/16 -- link-local (incl. 169.254.169.254 cloud metadata)
        if bytes[0] == 100, (64...127).contains(bytes[1]) { return false } // 100.64.0.0/10 -- RFC 6598 CGNAT
        return true
    }

    private static func isRoutableIPv6(_ bytes: [UInt8]) -> Bool {
        guard bytes.count == 16 else { return true } // defensive; DNSWireFormat guarantees exactly 16
        if bytes.allSatisfy({ $0 == 0 }) { return false } // :: -- unspecified
        if bytes[0..<15].allSatisfy({ $0 == 0 }), bytes[15] == 1 { return false } // ::1 -- loopback
        if bytes[0] == 0xFE, (bytes[1] & 0xC0) == 0x80 { return false } // fe80::/10 -- link-local
        if (bytes[0] & 0xFE) == 0xFC { return false } // fc00::/7 -- unique-local
        return true
    }
}

extension DNSAddress: CustomStringConvertible {
    /// Dotted-quad for `.v4` (`"93.184.216.34"`), full (uncompressed,
    /// lowercase-hex) colon-hextet form for `.v6`
    /// (`"2606:2800:220:1:248:1893:25c8:1946"`). The uncompressed `.v6`
    /// form is deliberately not RFC 5952-canonical (no `::` run
    /// compression) -- it's unambiguous and trivially correct to produce
    /// without a compression-run-finding algorithm, and `SocketAddress`'s
    /// own parser accepts uncompressed input just as readily as compressed.
    public var description: String {
        switch self {
        case .v4(let bytes):
            return bytes.map(String.init).joined(separator: ".")
        case .v6(let bytes):
            var hextets: [String] = []
            hextets.reserveCapacity(8)
            var index = 0
            while index < 16 {
                let value = UInt16(bytes[index]) << 8 | UInt16(bytes[index + 1])
                hextets.append(String(value, radix: 16))
                index += 2
            }
            return hextets.joined(separator: ":")
        }
    }
}
