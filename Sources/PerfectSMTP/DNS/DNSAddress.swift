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
