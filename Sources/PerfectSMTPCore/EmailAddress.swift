//
//  EmailAddress.swift
//  PerfectSMTPCore
//
//  Value types only — Foundation, no NIO. See
//  Documentation/swift6-nio-rewrite-plan.md §4.7.
//

/// A single RFC 5322 mailbox: an optional display-name phrase plus the
/// addr-spec, always stored separately so header encoding (RFC 2047
/// encoded-words vs. quoted-string vs. bare atoms) can be applied
/// correctly to the display name without ever touching the address.
public struct EmailAddress: Sendable, Hashable {
    /// The human-readable name, e.g. "Jane Doe". Never includes the
    /// surrounding `<...>` — that's added by the header encoder.
    public var displayName: String?
    /// The addr-spec, e.g. "jane@example.com". Stored verbatim; this
    /// library does not validate mailbox syntax in Phase 0.
    public var address: String

    public init(displayName: String? = nil, address: String) {
        self.displayName = displayName
        self.address = address
    }
}
