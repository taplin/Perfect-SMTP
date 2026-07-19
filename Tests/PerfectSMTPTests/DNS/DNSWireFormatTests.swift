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
}
