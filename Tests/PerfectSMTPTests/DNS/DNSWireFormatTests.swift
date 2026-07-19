//
//  DNSWireFormatTests.swift
//  PerfectSMTPTests
//
//  Pure byte-in/value-out codec tests -- no network, no NIO channel, no
//  event loop. Fixtures are real bytes captured from a live nameserver (see
//  `DNSTestFixtures.swift`'s header comment for how) plus one hand-crafted
//  malicious-compression-pointer-loop fixture that no real server would
//  ever send.
//

import Testing
@testable import PerfectSMTP

struct DNSWireFormatTests {

    // MARK: - Query encoding

    @Test func encodeQueryMatchesARealCapturedQuery() throws {
        let encoded = try DNSMessage.encodeQuery(id: DNSTestFixtures.exampleComAQueryID, name: "example.com", type: .a)
        #expect(encoded == DNSTestFixtures.exampleComAQuery)
    }

    @Test func encodeQueryTrimsATrailingDotToTheSameBytes() throws {
        let withDot = try DNSMessage.encodeQuery(id: 1, name: "example.com.", type: .a)
        let withoutDot = try DNSMessage.encodeQuery(id: 1, name: "example.com", type: .a)
        #expect(withDot == withoutDot)
    }

    @Test func encodeQueryRejectsAnOverlongLabel() {
        let label65 = String(repeating: "a", count: 65)
        #expect(throws: DNSWireError.invalidLabel) {
            try DNSMessage.encodeQuery(id: 1, name: "\(label65).com", type: .a)
        }
    }

    // MARK: - A/AAAA decode with real compression

    @Test func decodesARecordsWithNameCompression() throws {
        let message = try DNSMessage.decode(DNSTestFixtures.exampleComAResponse)
        #expect(message.header.id == DNSTestFixtures.exampleComAQueryID)
        #expect(message.header.isResponse)
        #expect(!message.header.truncated)
        #expect(message.header.responseCode == 0)
        #expect(message.questions.count == 1)
        #expect(message.questions[0].name == "example.com")
        #expect(message.answers.count == 2)
        for answer in message.answers {
            // Every answer's owner name is compressed (0xc00c, pointing back
            // at the question's "example.com") -- decoding must resolve it
            // to the same string as the question, not leave it truncated or
            // garbled.
            #expect(answer.name == "example.com")
            guard case .a(let address) = answer.rdata else {
                Issue.record("expected an A record, got \(answer.rdata)")
                continue
            }
            #expect(address.description.split(separator: ".").count == 4)
        }
        let addresses = message.answers.compactMap { record -> DNSAddress? in
            guard case .a(let address) = record.rdata else { return nil }
            return address
        }
        #expect(Set(addresses.map(\.description)) == ["104.20.23.154", "172.66.147.243"])
    }

    @Test func decodesAAAARecordsWithNameCompression() throws {
        let message = try DNSMessage.decode(DNSTestFixtures.exampleComAAAAResponse)
        #expect(message.header.id == DNSTestFixtures.exampleComAAAAQueryID)
        #expect(message.answers.count == 2)
        let addresses = message.answers.compactMap { record -> DNSAddress? in
            guard case .aaaa(let address) = record.rdata else { return nil }
            return address
        }
        #expect(addresses.count == 2)
        #expect(Set(addresses.map(\.description)) == [
            "2606:4700:10:0:0:0:ac42:93f3", "2606:4700:10:0:0:0:6814:179a",
        ])
    }

    // MARK: - MX decode: real null-MX, and real compression inside RDATA

    @Test func decodesTheRealRFC7505NullMXRecord() throws {
        let message = try DNSMessage.decode(DNSTestFixtures.exampleComNullMXResponse)
        #expect(message.answers.count == 1)
        guard case .mx(let preference, let exchange) = message.answers[0].rdata else {
            Issue.record("expected an MX record")
            return
        }
        #expect(preference == 0)
        #expect(exchange.isEmpty) // the DNS root, decoded as the empty-label name
    }

    @Test func decodesAnMXRecordWhoseExchangeIsCompressedMidRDATA() throws {
        let message = try DNSMessage.decode(DNSTestFixtures.googleComMXResponse)
        #expect(message.answers.count == 1)
        guard case .mx(let preference, let exchange) = message.answers[0].rdata else {
            Issue.record("expected an MX record")
            return
        }
        #expect(preference == 10)
        // "smtp" is a literal label; ".google.com" is reached via a
        // compression pointer back into the question section -- this is
        // what actually exercises pointer-following *inside* an RDATA
        // field (not just an owner-name pointer, the simpler case the
        // A/AAAA fixtures above cover).
        #expect(exchange == "smtp.google.com")
    }

    // MARK: - CNAME chain decode (real)

    @Test func decodesARealCNAMEChainAheadOfATerminalARecord() throws {
        let message = try DNSMessage.decode(DNSTestFixtures.wwwGithubComResponse)
        #expect(message.answers.count == 2)
        guard case .cname(let target) = message.answers[0].rdata else {
            Issue.record("expected the first answer to be a CNAME")
            return
        }
        #expect(target == "github.com")
        #expect(message.answers[0].name == "www.github.com")
        guard case .a(let address) = message.answers[1].rdata else {
            Issue.record("expected the second answer to be an A record")
            return
        }
        // The second record's owner name is itself reached via a
        // compression pointer into the *middle* of the question name
        // (skipping the "www" label) -- a different compression shape than
        // the whole-name-reuse the A/AAAA fixtures exercise.
        #expect(message.answers[1].name == "github.com")
        #expect(address.description.hasPrefix("140.82."))
    }

    // MARK: - Generic RR skipping (NXDOMAIN + a record type we don't decode, SOA)

    @Test func decodesNXDOMAINAndSkipsAnUnrecognizedAuthorityRecordType() throws {
        let message = try DNSMessage.decode(DNSTestFixtures.nxdomainResponse)
        #expect(message.header.responseCode == 3) // NXDOMAIN
        #expect(message.answers.isEmpty)
        #expect(message.authority.count == 1)
        guard case .other(let raw) = message.authority[0].rdata else {
            Issue.record("expected the SOA record to decode as .other (an unrecognized/skipped type)")
            return
        }
        #expect(!raw.isEmpty)
        // Decoding must have advanced past this record's RDATA correctly
        // (using RDLENGTH, not attempting to interpret SOA's internal
        // structure) -- the fact `decode(_:)` returned at all rather than
        // throwing `.truncated` already proves this, but assert the record
        // count is exactly 1 (not, say, mis-parsed into more/fewer records
        // by an offset error).
        #expect(message.authority[0].type == 6) // SOA
    }

    // MARK: - Malicious compression-pointer loop: bounded, not hung

    @Test func compressionPointerLoopIsRejectedRatherThanHanging() {
        // offset 0: pointer -> 2; offset 2: pointer -> 0. A direct 2-cycle.
        let maliciousBytes: [UInt8] = [0xC0, 0x02, 0xC0, 0x00]
        #expect(throws: DNSWireError.compressionPointerLoop) {
            _ = try DNSMessage.decodeName(maliciousBytes, at: 0)
        }
    }

    @Test func compressionPointerSelfLoopIsRejected() {
        // offset 0: pointer -> 0 (points at itself).
        let maliciousBytes: [UInt8] = [0xC0, 0x00]
        #expect(throws: DNSWireError.compressionPointerLoop) {
            _ = try DNSMessage.decodeName(maliciousBytes, at: 0)
        }
    }

    @Test func decodeNameFollowsALegitimateSinglePointerHop() throws {
        // offset 0: the label "a" then a pointer to offset 4.
        // offset 4: label "b" then the root terminator.
        let bytes: [UInt8] = [0x01, 0x61, 0xC0, 0x04, 0x01, 0x62, 0x00]
        let (name, next) = try DNSMessage.decodeName(bytes, at: 0)
        #expect(name == "a.b")
        // Sequential parsing must resume right after the 2-byte pointer,
        // not after wherever the pointer jumped to.
        #expect(next == 4)
    }

    @Test func decodeNameRejectsAPointerTargetingOutsideTheMessage() {
        let bytes: [UInt8] = [0xC0, 0xFF] // points at offset 255, message is 2 bytes long
        #expect(throws: DNSWireError.malformedPointer) {
            _ = try DNSMessage.decodeName(bytes, at: 0)
        }
    }

    @Test func decodeNameRejectsATruncatedLabel() {
        let bytes: [UInt8] = [0x05, 0x61, 0x62] // length byte claims 5, only 2 bytes follow
        #expect(throws: DNSWireError.truncated) {
            _ = try DNSMessage.decodeName(bytes, at: 0)
        }
    }

    @Test func decodeRejectsATruncatedHeader() {
        #expect(throws: DNSWireError.truncated) {
            _ = try DNSMessage.decode(Array(DNSTestFixtures.exampleComAResponse.prefix(8)))
        }
    }

    // MARK: - FIX #5 (milestone security review): a header claiming an
    // implausibly large record count, with a message far too short to
    // actually contain that many records, must fail fast on the first
    // record's truncation rather than the count field itself driving a
    // large speculative `reserveCapacity` allocation.

    @Test func decodeRejectsAHeaderClaimingTheMaximumAnswerCountWithNoActualRecords() {
        // A minimal 12-byte header claiming `answerCount = 65535` (the
        // field's `UInt16` max) followed by nothing else at all -- before
        // FIX #5, `reserveCapacity(Int(header.answerCount))` would trust
        // this field directly and speculatively allocate room for 65535
        // records before the first record-parse ever runs (and fails on
        // truncation, since there's no question section, let alone any
        // records, in these 12 bytes).
        var bytes = [UInt8](repeating: 0, count: 12)
        bytes[2] = 0x81 // flags: QR=1
        bytes[3] = 0x80
        // QDCOUNT = 0, ANCOUNT = 65535, NSCOUNT = 0, ARCOUNT = 0
        bytes[6] = 0xFF
        bytes[7] = 0xFF
        #expect(throws: DNSWireError.truncated) {
            _ = try DNSMessage.decode(bytes)
        }
    }

    // MARK: - FIX #4 (milestone security review): message-wide decompression
    // budget. The per-name defenses above (visited-offset set + the
    // 128-jump-per-name cap) are already proven sound -- this is the
    // *aggregate*, cross-RR budget: many RRs whose names all point at one
    // shared, near-maximal-length compression chain must not let that same
    // chain be re-walked, unbounded, once per RR.

    @Test func manyRecordsSharingOneExpensiveCompressionChainExceedTheAggregateBudget() {
        // A shared chain of `hopCount` pointer-only hops (each 2 bytes),
        // chained hop[0] -> hop[1] -> ... -> hop[hopCount-1] -> a 1-byte
        // root terminator. `hopCount` is deliberately just under the
        // *per-name* cap (`maximumPointerJumps == 128`, see
        // `DNSWireFormatTests.compressionPointerLoopIsRejectedRatherThanHanging`
        // above) so every individual RR's own name decode stays within its
        // own per-name budget -- this test is specifically about the
        // message-*wide* budget FIX #4 adds, not the pre-existing per-name
        // one, and must fail for that reason if the aggregate cap were
        // removed (proving it's actually load-bearing, not redundant with
        // the per-name cap).
        let hopCount = 127
        // Each RR's own name is a 2-byte pointer straight at the chain's
        // first hop, so decoding one RR's name costs exactly `hopCount`
        // jumps (the RR -> hop[0] jump, plus hop[0] -> hop[1] -> ... ->
        // hop[hopCount-1] -> terminator). `recordCount` is chosen so the
        // cumulative jump count (`recordCount * hopCount`) comfortably
        // exceeds `DNSMessage.maximumPointerJumpsPerMessage`
        // (`maximumPointerJumps * 32 == 4096`), guaranteeing the budget is
        // exhausted partway through decoding, not right at the edge.
        let recordCount = 40
        #expect(recordCount * hopCount > 4096)

        var bytes: [UInt8] = []
        bytes += [0x12, 0x34] // ID
        bytes += [0x81, 0x80] // flags: QR=1, RD=1, RA=1, RCODE=0
        bytes += [0x00, 0x01] // QDCOUNT = 1
        let ancountOffset = bytes.count
        bytes += [0x00, 0x00] // ANCOUNT -- patched once `recordCount` is known to fit UInt16
        bytes += [0x00, 0x00] // NSCOUNT = 0
        bytes += [0x00, 0x00] // ARCOUNT = 0

        // Question section: root name, QTYPE=A, QCLASS=IN.
        bytes += [0x00, 0x00, 0x01, 0x00, 0x01]

        // `recordCount` minimal A records placed immediately after the
        // question section -- `decode(_:)` walks sections purely
        // sequentially with no gaps, so this (not the shared chain below)
        // is what it actually reads as the answer section. Each record's
        // name is a 2-byte compression pointer, patched below once the
        // shared chain's start offset is known; the placeholder written
        // here is overwritten before `decode(_:)` ever runs.
        var recordNamePointerOffsets: [Int] = []
        for _ in 0..<recordCount {
            recordNamePointerOffsets.append(bytes.count)
            bytes += [0x00, 0x00] // NAME -- placeholder, patched below
            bytes += [0x00, 0x01] // TYPE = A
            bytes += [0x00, 0x01] // CLASS = IN
            bytes += [0x00, 0x00, 0x00, 0x00] // TTL = 0
            bytes += [0x00, 0x04] // RDLENGTH = 4
            bytes += [0x00, 0x00, 0x00, 0x00] // RDATA (never actually reached once the budget trips partway through)
        }
        bytes[ancountOffset] = UInt8(recordCount >> 8)
        bytes[ancountOffset + 1] = UInt8(recordCount & 0xFF)

        // The shared chain lives at the *tail* of the message, past every
        // record `decode(_:)` will actually walk over -- compression
        // pointers may point anywhere in the message, forward or
        // backward, so every record's NAME field above (already emitted,
        // earlier in the byte stream) points forward into this region.
        // Laid out as `hopCount` placeholder 2-byte slots followed by a
        // 1-byte root terminator, then patched with real pointer values
        // once every offset is known.
        let chainStart = bytes.count
        let hopOffsets = (0..<hopCount).map { chainStart + $0 * 2 }
        bytes += [UInt8](repeating: 0, count: hopCount * 2)
        let terminatorOffset = bytes.count
        bytes.append(0x00)
        for i in 0..<hopCount {
            let target = (i + 1 < hopCount) ? hopOffsets[i + 1] : terminatorOffset
            let pointer = pointerBytes(to: target)
            bytes[hopOffsets[i]] = pointer[0]
            bytes[hopOffsets[i] + 1] = pointer[1]
        }
        for nameOffset in recordNamePointerOffsets {
            let pointer = pointerBytes(to: hopOffsets[0])
            bytes[nameOffset] = pointer[0]
            bytes[nameOffset + 1] = pointer[1]
        }

        #expect(throws: DNSWireError.decompressionBudgetExceeded) {
            _ = try DNSMessage.decode(bytes)
        }
    }

    /// RFC 1035 §4.1.4 two-byte compression pointer encoding for `offset`
    /// (top two bits `11`, remaining 14 bits the target offset).
    private func pointerBytes(to offset: Int) -> [UInt8] {
        [UInt8(0xC0 | (offset >> 8)), UInt8(offset & 0xFF)]
    }
}
