//
//  DNSWireFormat.swift
//  PerfectSMTP
//
//  Plan §9 Phase 3 / §4.2: a minimal RFC 1035 §4 wire-format codec — just
//  enough of the DNS message format to send an MX/A/AAAA query and decode a
//  response. Deliberately narrow: only the record types `DNSResolver`
//  actually needs (A, AAAA, MX, CNAME) are decoded into a typed
//  representation; every other record type is skipped over using its
//  generic RR header (name/type/class/ttl/RDLENGTH) without attempting to
//  interpret its RDATA. No DNSSEC (RRSIG/DNSKEY/etc.), no EDNS0 (OPT), no
//  zone-transfer types — out of scope per the plan's explicit "no DNSSEC
//  validation" carve-out.
//
//  This file has zero NIO dependency by design (pure `[UInt8]` in, pure
//  value types out) so the codec can be unit-tested with hand-crafted byte
//  fixtures with no channel, event loop, or network involved — see
//  `Tests/PerfectSMTPTests/DNS/DNSWireFormatTests.swift`. `DNSTransport.swift`
//  is the only place this module touches `ByteBuffer`/NIO, converting at the
//  boundary.
//

/// Errors specific to malformed wire-format bytes — distinct from
/// `DNSResolver.ResolveError`, which is the resolver's caller-facing
/// classification. `DNSResolver` catches these and maps them to
/// `.malformedResponse`.
public enum DNSWireError: Error, Sendable, Equatable {
    /// Fewer bytes were available than the format requires at this point
    /// (a short header, a label/RDATA that runs past the end of the
    /// message, etc).
    case truncated
    /// A label length byte's top two bits were `01` or `10` — reserved by
    /// RFC 1035 §4.1.4 for future use (and, in practice, for EDNS0
    /// extended-label mechanisms this codec doesn't implement). Not the
    /// `11` (pointer) or `00` (plain-length) forms this codec handles.
    case unsupportedLabelForm
    /// A compression pointer (RFC 1035 §4.1.4) targets an offset already
    /// visited while decoding the *same* name, or the total number of
    /// pointer jumps for one name exceeded `DNSMessage.maximumPointerJumps`.
    /// This is the guard against the classic malicious-pointer-loop
    /// DNS-parser DoS (a pointer chain `A -> B -> A` would otherwise
    /// recurse/loop forever) — every name decode tracks the set of offsets
    /// it has already jumped to, and separately caps the total number of
    /// jumps, so a loop (or a very long non-repeating chain) is rejected
    /// deterministically rather than hanging.
    case compressionPointerLoop
    /// A compression pointer targets an offset outside the message.
    case malformedPointer
    /// A decoded name exceeded `DNSMessage.maximumLabelsPerName` labels —
    /// defense-in-depth against a message built from many minimal-length
    /// labels, independent of the pointer-loop guard above.
    case nameTooLong
    /// An A/AAAA record's RDATA wasn't exactly 4/16 bytes.
    case invalidAddressRecordLength
    /// An MX record's RDATA was too short to contain even a preference
    /// field and a (possibly root) exchange name.
    case invalidMXRecordData
    /// A query name label was empty or exceeded 63 bytes (RFC 1035 §2.3.4).
    case invalidLabel
}

/// The DNS record types `DNSResolver` understands. RFC 1035 §3.2.2 (A, CNAME),
/// §3.3.9 (MX), RFC 3596 (AAAA). Any other on-the-wire TYPE value decodes into
/// `DNSResourceRecord.RDATA.other` rather than one of this enum's cases.
public enum DNSRecordType: UInt16, Sendable, Equatable {
    case a = 1
    case cname = 5
    case mx = 15
    case aaaa = 28
}

/// The 12-byte DNS message header (RFC 1035 §4.1.1), decoded field-by-field.
public struct DNSHeader: Sendable, Equatable {
    public var id: UInt16
    /// `QR`: `false` for a query, `true` for a response.
    public var isResponse: Bool
    /// `OPCODE`, 4 bits. Always `0` (standard query) for anything this
    /// codec generates; decoded from responses for completeness only.
    public var opcode: UInt8
    /// `AA`: the responding server is authoritative for the queried name.
    public var authoritative: Bool
    /// `TC`: the response was truncated because it didn't fit in a UDP
    /// datagram (RFC 1035 §4.2.2) — `DNSResolver` retries over TCP when
    /// this is set.
    public var truncated: Bool
    /// `RD`: recursion desired (set by the querier).
    public var recursionDesired: Bool
    /// `RA`: recursion available (set by the responder).
    public var recursionAvailable: Bool
    /// `RCODE`, 4 bits. `0` = NOERROR, `3` = NXDOMAIN, others are server-side
    /// failures — `DNSResolver` maps a non-{0,3} RCODE to `.serverFailure`.
    public var responseCode: UInt8
    public var questionCount: UInt16
    public var answerCount: UInt16
    public var authorityCount: UInt16
    public var additionalCount: UInt16
}

/// One entry in the question section (RFC 1035 §4.1.2).
public struct DNSQuestion: Sendable, Equatable {
    public var name: String
    public var type: UInt16
    public var qclass: UInt16
}

/// A resource record's decoded RDATA. Only the four types `DNSResolver`
/// needs are given a typed case; everything else is preserved as raw bytes
/// so a caller could in principle still inspect it, though nothing in this
/// package does.
public enum DNSRDATA: Sendable, Equatable {
    case a(DNSAddress)
    case aaaa(DNSAddress)
    /// RFC 1035 §3.3.9: `preference` (lower = more preferred, RFC 5321
    /// §5.1) and `exchange` (the mail server hostname, name-decompressed
    /// against the whole message).
    case mx(preference: UInt16, exchange: String)
    /// RFC 1035 §3.3.1, name-decompressed. `DNSResolver` follows this when
    /// resolving A/AAAA for a hostname that's actually an alias.
    case cname(String)
    case other(raw: [UInt8])
}

/// One resource record (RFC 1035 §4.1.3): the common name/type/class/ttl
/// header plus typed RDATA.
public struct DNSResourceRecord: Sendable, Equatable {
    public var name: String
    public var type: UInt16
    public var recordClass: UInt16
    public var ttl: UInt32
    public var rdata: DNSRDATA
}

/// A fully decoded (or, via `encodeQuery`, about-to-be-encoded) DNS message.
public struct DNSMessage: Sendable, Equatable {
    public var header: DNSHeader
    public var questions: [DNSQuestion]
    public var answers: [DNSResourceRecord]
    public var authority: [DNSResourceRecord]
    public var additional: [DNSResourceRecord]

    /// Cap on the number of compression-pointer jumps followed while
    /// decoding a single name. RFC 1035 places no explicit limit, but a
    /// message can be at most 65535 bytes (UDP/TCP length fields are both
    /// `UInt16`), so any *acyclic* pointer chain is inherently bounded by
    /// message size; this cap exists purely as the malicious-loop defense
    /// described on `DNSWireError.compressionPointerLoop` — generous enough
    /// that no real-world compressed name (a handful of jumps at most)
    /// could ever approach it.
    static let maximumPointerJumps = 128

    /// Cap on the number of labels in one decoded name — defense-in-depth
    /// against a message built from many single-byte labels (RFC 1035
    /// §2.3.4 already limits a real name to 255 octets / effectively far
    /// fewer labels than this).
    static let maximumLabelsPerName = 128

    // MARK: - Encoding (queries only)

    /// Encodes a standard (`OPCODE=0`), recursion-desired query for
    /// `(name, type, IN)` with the given 16-bit transaction `id`.
    ///
    /// - Throws: `DNSWireError.invalidLabel` if `name` has a label that's
    ///   empty or longer than 63 bytes (RFC 1035 §2.3.4).
    public static func encodeQuery(id: UInt16, name: String, type: DNSRecordType) throws -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(16 + name.utf8.count)
        appendUInt16(id, to: &bytes)
        bytes.append(0x01) // QR=0, OPCODE=0, AA=0, TC=0, RD=1
        bytes.append(0x00) // RA=0, Z=0, RCODE=0
        appendUInt16(1, to: &bytes) // QDCOUNT
        appendUInt16(0, to: &bytes) // ANCOUNT
        appendUInt16(0, to: &bytes) // NSCOUNT
        appendUInt16(0, to: &bytes) // ARCOUNT
        try encodeName(name, into: &bytes)
        appendUInt16(type.rawValue, to: &bytes)
        appendUInt16(1, to: &bytes) // QCLASS = IN
        return bytes
    }

    private static func encodeName(_ name: String, into bytes: inout [UInt8]) throws {
        let trimmed = name.hasSuffix(".") ? String(name.dropLast()) : name
        guard !trimmed.isEmpty else {
            bytes.append(0)
            return
        }
        for label in trimmed.split(separator: ".", omittingEmptySubsequences: false) {
            let labelBytes = Array(label.utf8)
            guard (1...63).contains(labelBytes.count) else { throw DNSWireError.invalidLabel }
            bytes.append(UInt8(labelBytes.count))
            bytes.append(contentsOf: labelBytes)
        }
        bytes.append(0)
    }

    private static func appendUInt16(_ value: UInt16, to bytes: inout [UInt8]) {
        bytes.append(UInt8(value >> 8))
        bytes.append(UInt8(value & 0xFF))
    }

    // MARK: - Decoding

    public static func decode(_ bytes: [UInt8]) throws -> DNSMessage {
        guard bytes.count >= 12 else { throw DNSWireError.truncated }

        let id = readUInt16(bytes, at: 0)
        let flags1 = bytes[2]
        let flags2 = bytes[3]
        let header = DNSHeader(
            id: id,
            isResponse: flags1 & 0x80 != 0,
            opcode: (flags1 >> 3) & 0x0F,
            authoritative: flags1 & 0x04 != 0,
            truncated: flags1 & 0x02 != 0,
            recursionDesired: flags1 & 0x01 != 0,
            recursionAvailable: flags2 & 0x80 != 0,
            responseCode: flags2 & 0x0F,
            questionCount: readUInt16(bytes, at: 4),
            answerCount: readUInt16(bytes, at: 6),
            authorityCount: readUInt16(bytes, at: 8),
            additionalCount: readUInt16(bytes, at: 10)
        )

        var offset = 12
        var questions: [DNSQuestion] = []
        questions.reserveCapacity(Int(header.questionCount))
        for _ in 0..<header.questionCount {
            let (name, afterName) = try decodeName(bytes, at: offset)
            offset = afterName
            guard offset + 4 <= bytes.count else { throw DNSWireError.truncated }
            let qtype = readUInt16(bytes, at: offset)
            let qclass = readUInt16(bytes, at: offset + 2)
            offset += 4
            questions.append(DNSQuestion(name: name, type: qtype, qclass: qclass))
        }

        func decodeSection(_ count: UInt16) throws -> [DNSResourceRecord] {
            var records: [DNSResourceRecord] = []
            records.reserveCapacity(Int(count))
            for _ in 0..<count {
                let (record, next) = try decodeResourceRecord(bytes, at: offset)
                offset = next
                records.append(record)
            }
            return records
        }

        let answers = try decodeSection(header.answerCount)
        let authority = try decodeSection(header.authorityCount)
        let additional = try decodeSection(header.additionalCount)

        return DNSMessage(
            header: header, questions: questions, answers: answers, authority: authority, additional: additional
        )
    }

    private static func decodeResourceRecord(
        _ bytes: [UInt8], at offset: Int
    ) throws -> (record: DNSResourceRecord, nextOffset: Int) {
        let (name, afterName) = try decodeName(bytes, at: offset)
        var pos = afterName
        guard pos + 10 <= bytes.count else { throw DNSWireError.truncated }
        let type = readUInt16(bytes, at: pos)
        let recordClass = readUInt16(bytes, at: pos + 2)
        let ttl = readUInt32(bytes, at: pos + 4)
        let rdlength = Int(readUInt16(bytes, at: pos + 8))
        pos += 10
        guard pos + rdlength <= bytes.count else { throw DNSWireError.truncated }
        let rdataStart = pos
        let rdataEnd = pos + rdlength

        let rdata: DNSRDATA
        switch type {
        case DNSRecordType.a.rawValue:
            guard rdlength == 4 else { throw DNSWireError.invalidAddressRecordLength }
            rdata = .a(DNSAddress.v4(Array(bytes[rdataStart..<rdataEnd])))
        case DNSRecordType.aaaa.rawValue:
            guard rdlength == 16 else { throw DNSWireError.invalidAddressRecordLength }
            rdata = .aaaa(DNSAddress.v6(Array(bytes[rdataStart..<rdataEnd])))
        case DNSRecordType.mx.rawValue:
            guard rdlength >= 3 else { throw DNSWireError.invalidMXRecordData }
            let preference = readUInt16(bytes, at: rdataStart)
            let (exchange, _) = try decodeName(bytes, at: rdataStart + 2)
            rdata = .mx(preference: preference, exchange: exchange)
        case DNSRecordType.cname.rawValue:
            let (target, _) = try decodeName(bytes, at: rdataStart)
            rdata = .cname(target)
        default:
            rdata = .other(raw: Array(bytes[rdataStart..<rdataEnd]))
        }

        let record = DNSResourceRecord(name: name, type: type, recordClass: recordClass, ttl: ttl, rdata: rdata)
        // `rdataEnd` (derived from RDLENGTH), not wherever the RDATA's own
        // internal name-decode happened to stop -- RDLENGTH is authoritative
        // for how many bytes this record occupies on the wire, regardless
        // of what's semantically inside it. This is what lets an unknown
        // record type (`.other`) be skipped correctly without this codec
        // knowing anything about its internal structure.
        return (record, rdataEnd)
    }

    /// Decodes one domain name starting at `offset`, following RFC 1035
    /// §4.1.4 compression pointers as needed, and returns the name plus the
    /// offset of the first byte *after* this name's on-the-wire
    /// representation (i.e. after a pointer's 2 bytes, not after whatever
    /// the pointer jumped to — this is what lets the caller resume
    /// sequential parsing correctly).
    ///
    /// Bounded against the classic malicious-compression-pointer-loop
    /// DNS-parser DoS two independent ways: a `visited` set of offsets
    /// already jumped to (an exact loop like `A -> B -> A` is caught the
    /// moment `A` is revisited) and a hard cap (`maximumPointerJumps`) on
    /// the total number of jumps for one name (belt-and-suspenders against
    /// any non-repeating-but-still-pathological chain).
    static func decodeName(_ bytes: [UInt8], at startOffset: Int) throws -> (name: String, nextOffset: Int) {
        var offset = startOffset
        var labels: [String] = []
        var visitedPointers = Set<Int>()
        var jumps = 0
        var firstJumpNextOffset: Int?

        while true {
            guard offset < bytes.count else { throw DNSWireError.truncated }
            let lengthByte = bytes[offset]

            if lengthByte == 0 {
                offset += 1
                if firstJumpNextOffset == nil { firstJumpNextOffset = offset }
                break
            }

            switch lengthByte & 0xC0 {
            case 0xC0: // compression pointer
                guard offset + 1 < bytes.count else { throw DNSWireError.truncated }
                let pointer = (Int(lengthByte & 0x3F) << 8) | Int(bytes[offset + 1])
                if firstJumpNextOffset == nil { firstJumpNextOffset = offset + 2 }
                jumps += 1
                guard jumps <= maximumPointerJumps else { throw DNSWireError.compressionPointerLoop }
                guard visitedPointers.insert(pointer).inserted else { throw DNSWireError.compressionPointerLoop }
                guard pointer < bytes.count else { throw DNSWireError.malformedPointer }
                offset = pointer
            case 0x00: // ordinary label
                let labelLength = Int(lengthByte)
                offset += 1
                guard offset + labelLength <= bytes.count else { throw DNSWireError.truncated }
                labels.append(String(decoding: bytes[offset..<offset + labelLength], as: UTF8.self))
                offset += labelLength
                guard labels.count <= maximumLabelsPerName else { throw DNSWireError.nameTooLong }
            default: // 0x40 / 0x80 -- reserved/EDNS0 extended label forms, unsupported
                throw DNSWireError.unsupportedLabelForm
            }
        }

        let name = labels.joined(separator: ".")
        return (name, firstJumpNextOffset ?? offset)
    }

    private static func readUInt16(_ bytes: [UInt8], at offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }

    private static func readUInt32(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        UInt32(bytes[offset]) << 24 | UInt32(bytes[offset + 1]) << 16
            | UInt32(bytes[offset + 2]) << 8 | UInt32(bytes[offset + 3])
    }
}
