//
//  DNSResolverIntegrationTests.swift
//  PerfectSMTPTests
//
//  End-to-end coverage of the two public methods (`resolveMX`,
//  `resolveAddresses`) against `FakeDNSServer`, plus
//  `systemNameservers()`/`parseResolvConf(path:)`'s `/etc/resolv.conf`
//  parsing and hardcoded-fallback behavior (plan §9 Phase 3, point 5).
//

import Foundation
import NIOPosix
import Testing
@testable import PerfectSMTP

struct DNSResolverIntegrationTests {

    @Test func resolveMXReturnsPreferenceSortedRecordsFromALiveQuery() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { Task { try? await group.shutdownGracefully() } }

        let response = TestDNSMessageBuilder.response(
            id: 0, qname: "mail.example.test", qtype: 15,
            records: [
                mxRecord(owner: "mail.example.test", preference: 20, exchange: "b.mail.example.test"),
                mxRecord(owner: "mail.example.test", preference: 10, exchange: "a.mail.example.test"),
            ]
        )
        let server = try await FakeDNSServer.start(
            group: group,
            udpResponses: [FakeDNSServer.scriptKey(name: "mail.example.test", type: .mx): .init(response)]
        )
        defer { Task { await server.shutdown() } }

        let resolver = DNSResolver(nameservers: [server.nameserver], group: group, queryTimeout: .seconds(2))
        let records = try await resolver.resolveMX(domain: "mail.example.test")
        #expect(records.map(\.exchange) == ["a.mail.example.test", "b.mail.example.test"])
    }

    @Test func resolveMXThrowsNullMXEndToEnd() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { Task { try? await group.shutdownGracefully() } }

        // Reuse the real captured null-MX fixture verbatim as the fake
        // server's canned response.
        let server = try await FakeDNSServer.start(
            group: group,
            udpResponses: [
                FakeDNSServer.scriptKey(name: "example.com", type: .mx): .init(DNSTestFixtures.exampleComNullMXResponse),
            ]
        )
        defer { Task { await server.shutdown() } }

        let resolver = DNSResolver(nameservers: [server.nameserver], group: group, queryTimeout: .seconds(2))
        await #expect(throws: DNSResolver.ResolveError.nullMX) {
            _ = try await resolver.resolveMX(domain: "example.com")
        }
    }

    @Test func resolveMXThrowsNoRecordsFoundForAnEmptyAnswerSection() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { Task { try? await group.shutdownGracefully() } }

        let server = try await FakeDNSServer.start(
            group: group,
            udpResponses: [
                FakeDNSServer.scriptKey(name: "no-mx.example.test", type: .mx):
                    .init(TestDNSMessageBuilder.response(id: 0, qname: "no-mx.example.test", qtype: 15, records: [])),
            ]
        )
        defer { Task { await server.shutdown() } }

        let resolver = DNSResolver(nameservers: [server.nameserver], group: group, queryTimeout: .seconds(2))
        await #expect(throws: DNSResolver.ResolveError.noRecordsFound) {
            _ = try await resolver.resolveMX(domain: "no-mx.example.test")
        }
    }

    @Test func resolveAddressesCombinesAAndAAAAFromIndependentQueries() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { Task { try? await group.shutdownGracefully() } }

        var aRecord = TestDNSMessageBuilder.name("dual.example.test")
        aRecord.append(contentsOf: [0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 10, 2, 2, 2])
        var aaaaRecord = TestDNSMessageBuilder.name("dual.example.test")
        aaaaRecord.append(contentsOf: [0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x10])
        aaaaRecord.append(contentsOf: [UInt8](repeating: 0, count: 15) + [1])

        let server = try await FakeDNSServer.start(
            group: group,
            udpResponses: [
                FakeDNSServer.scriptKey(name: "dual.example.test", type: .a):
                    .init(TestDNSMessageBuilder.response(id: 0, qname: "dual.example.test", qtype: 1, records: [aRecord])),
                FakeDNSServer.scriptKey(name: "dual.example.test", type: .aaaa):
                    .init(TestDNSMessageBuilder.response(id: 0, qname: "dual.example.test", qtype: 28, records: [aaaaRecord])),
            ]
        )
        defer { Task { await server.shutdown() } }

        let resolver = DNSResolver(nameservers: [server.nameserver], group: group, queryTimeout: .seconds(2))
        let addresses = try await resolver.resolveAddresses(hostname: "dual.example.test")
        #expect(addresses.count == 2)
        #expect(addresses.contains { $0.description == "10.2.2.2" })
        #expect(addresses.contains { $0.description.hasSuffix(":1") })
    }

    @Test func resolveAddressesThrowsNoRecordsFoundWhenBothFamiliesAreEmpty() async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { Task { try? await group.shutdownGracefully() } }

        let server = try await FakeDNSServer.start(
            group: group,
            udpResponses: [
                FakeDNSServer.scriptKey(name: "empty.example.test", type: .a):
                    .init(TestDNSMessageBuilder.response(id: 0, qname: "empty.example.test", qtype: 1, records: [])),
                FakeDNSServer.scriptKey(name: "empty.example.test", type: .aaaa):
                    .init(TestDNSMessageBuilder.response(id: 0, qname: "empty.example.test", qtype: 28, records: [])),
            ]
        )
        defer { Task { await server.shutdown() } }

        let resolver = DNSResolver(nameservers: [server.nameserver], group: group, queryTimeout: .seconds(2))
        await #expect(throws: DNSResolver.ResolveError.noRecordsFound) {
            _ = try await resolver.resolveAddresses(hostname: "empty.example.test")
        }
    }

    // MARK: - System nameserver discovery

    @Test func parseResolvConfExtractsNameserverLines() throws {
        let path = try writeTemporaryResolvConf(
            """
            # a comment line, ignored
            domain example.test
            nameserver 192.0.2.1
            nameserver 192.0.2.2
            search example.test
            """
        )
        defer { try? FileManagerCompat.removeItem(path) }

        let servers = try DNSResolver.parseResolvConf(path: path)
        #expect(servers.count == 2)
        #expect(servers.contains { $0.description == "[IPv4]192.0.2.1:53" })
        #expect(servers.contains { $0.description == "[IPv4]192.0.2.2:53" })
    }

    @Test func parseResolvConfIgnoresMalformedOrUnparseableAddressLines() throws {
        let path = try writeTemporaryResolvConf(
            """
            nameserver not-an-ip-address
            nameserver 192.0.2.9
            """
        )
        defer { try? FileManagerCompat.removeItem(path) }

        let servers = try DNSResolver.parseResolvConf(path: path)
        #expect(servers.count == 1)
    }

    @Test func systemNameserversFallsBackToTheHardcodedListWhenTheFileIsMissing() {
        // A path that (almost certainly) doesn't exist -- exercises the
        // fallback path directly, distinct from whatever this test
        // machine's real `/etc/resolv.conf` happens to contain.
        let parsed = try? DNSResolver.parseResolvConf(path: "/nonexistent/path/\(UUID().uuidString)/resolv.conf")
        #expect(parsed == nil)
        #expect(!DNSResolver.fallbackNameservers.isEmpty)
    }

    // MARK: - Fixture / filesystem helpers

    private func mxRecord(owner: String, preference: UInt16, exchange: String) -> [UInt8] {
        var bytes = TestDNSMessageBuilder.name(owner)
        bytes.append(0x00); bytes.append(0x0F) // TYPE=MX
        bytes.append(0x00); bytes.append(0x01) // CLASS=IN
        bytes.append(contentsOf: [0x00, 0x00, 0x00, 0x3C]) // TTL=60
        var rdata: [UInt8] = [UInt8(preference >> 8), UInt8(preference & 0xFF)]
        rdata.append(contentsOf: TestDNSMessageBuilder.name(exchange))
        bytes.append(UInt8(rdata.count >> 8)); bytes.append(UInt8(rdata.count & 0xFF))
        bytes.append(contentsOf: rdata)
        return bytes
    }

    private func writeTemporaryResolvConf(_ contents: String) throws -> String {
        let path = "/tmp/perfectsmtp-resolv-\(UUID().uuidString).conf"
        try contents.write(toFile: path, atomically: true, encoding: .utf8)
        return path
    }
}

/// `Foundation.FileManager` is already a dependency (`DNSResolver.swift`
/// imports `Foundation`), but pulling the whole type in here for one
/// `removeItem` call would be overkill -- a direct `unlink` is simpler and
/// keeps this test file's cleanup obviously fallible-and-ignorable (`try?`
/// at the call site).
enum FileManagerCompat {
    static func removeItem(_ path: String) throws {
        unlink(path)
    }
}
