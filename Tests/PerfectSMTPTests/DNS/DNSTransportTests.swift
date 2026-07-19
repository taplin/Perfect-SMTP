//
//  DNSTransportTests.swift
//  PerfectSMTPTests
//
//  Live-socket (not `EmbeddedChannel`) tests against `FakeDNSServer`,
//  covering exactly the behaviors that can't be exercised as pure
//  byte-in/value-out unit tests: TCP fallback on a truncated UDP response,
//  a wrong-transaction-ID reply being rejected rather than accepted as the
//  answer, and UDP loss triggering the retry/timeout path. All three run
//  against `127.0.0.1` with short timeouts, so this suite stays fast.
//

import NIOCore
import NIOPosix
import Testing
@testable import PerfectSMTP

struct DNSTransportTests {

    @Test func truncatedUDPResponseTriggersASuccessfulTCPRetry() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { Task { try? await group.shutdownGracefully() } }

        let key = FakeDNSServer.scriptKey(name: "large.example.test", type: .a)
        let fullResponse = TestDNSMessageBuilder.response(
            id: 0, qname: "large.example.test", qtype: 1,
            records: [aRecord(owner: "large.example.test", address: [10, 0, 0, 1])]
        )
        let server = try await FakeDNSServer.start(
            group: group,
            udpResponses: [
                key: .init(TestDNSMessageBuilder.truncatedStub(id: 0, qname: "large.example.test", qtype: 1)),
            ],
            tcpResponses: [key: fullResponse]
        )
        defer { Task { await server.shutdown() } }

        let resolver = DNSResolver(nameservers: [server.nameserver], group: group, queryTimeout: .seconds(2))
        let message = try await resolver.query(name: "large.example.test", type: .a)

        #expect(!message.header.truncated, "the message returned to the caller should be the full TCP response, not the truncated UDP stub")
        #expect(message.answers.count == 1)
        guard case .a(let address) = message.answers[0].rdata else {
            Issue.record("expected an A record from the TCP fallback response")
            return
        }
        #expect(address.description == "10.0.0.1")
    }

    @Test func aResponseWithTheWrongTransactionIDIsIgnoredUntilTheCorrectOneArrives() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { Task { try? await group.shutdownGracefully() } }

        let key = FakeDNSServer.scriptKey(name: "spoofed.example.test", type: .a)
        let response = TestDNSMessageBuilder.response(
            id: 0, qname: "spoofed.example.test", qtype: 1,
            records: [aRecord(owner: "spoofed.example.test", address: [10, 0, 0, 2])]
        )
        let server = try await FakeDNSServer.start(
            group: group,
            udpResponses: [key: .init(response, precededByWrongID: true)]
        )
        defer { Task { await server.shutdown() } }

        let resolver = DNSResolver(nameservers: [server.nameserver], group: group, queryTimeout: .seconds(2))
        // The server sends a wrong-ID decoy immediately before the real
        // reply for every query -- if the resolver ever accepted the first
        // (wrong-ID) datagram, this would either throw a decode/validation
        // error or return the decoy's content. Getting back exactly the
        // correct, real answer proves the mismatched reply was rejected
        // and the wait continued.
        let message = try await resolver.query(name: "spoofed.example.test", type: .a)
        #expect(message.answers.count == 1)
        guard case .a(let address) = message.answers[0].rdata else {
            Issue.record("expected an A record")
            return
        }
        #expect(address.description == "10.0.0.2")
    }

    @Test func aQueryWithNoScriptedResponseTimesOutRatherThanHanging() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { Task { try? await group.shutdownGracefully() } }

        // No canned response at all for this name -- every UDP attempt is
        // silently dropped by the fake server, exactly as a lost packet
        // would be on a real network.
        let server = try await FakeDNSServer.start(group: group, udpResponses: [:])
        defer { Task { await server.shutdown() } }

        let resolver = DNSResolver(nameservers: [server.nameserver], group: group, queryTimeout: .milliseconds(150))
        await #expect(throws: DNSResolver.ResolveError.timeout) {
            _ = try await resolver.query(name: "silent.example.test", type: .a)
        }
    }

    // MARK: - Fixture helper

    private func aRecord(owner: String, address: [UInt8], ttl: UInt32 = 60) -> [UInt8] {
        var bytes = TestDNSMessageBuilder.name(owner)
        bytes.append(0x00); bytes.append(0x01) // TYPE=A
        bytes.append(0x00); bytes.append(0x01) // CLASS=IN
        bytes.append(UInt8((ttl >> 24) & 0xFF)); bytes.append(UInt8((ttl >> 16) & 0xFF))
        bytes.append(UInt8((ttl >> 8) & 0xFF)); bytes.append(UInt8(ttl & 0xFF))
        bytes.append(0x00); bytes.append(0x04) // RDLENGTH=4
        bytes.append(contentsOf: address)
        return bytes
    }
}
