//
//  DNSAddressRoutabilityTests.swift
//  PerfectSMTPTests
//
//  FIX #2 (plan §9 Phase 3 milestone security review): `DNSAddress
//  .isRoutable` is the SSRF-class filter `DirectMXTransport.makeDialer`
//  applies to every resolved address before dialing it. Pure value-type
//  tests -- no network, no NIO channel, no resolver involved -- covering
//  every range the review named "at minimum," plus the IPv4-mapped-IPv6
//  bypass this implementation additionally closes.
//

import Testing
@testable import PerfectSMTP

struct DNSAddressRoutabilityTests {
    // MARK: - IPv4: RFC 1918 private ranges

    @Test func rfc1918TenSlashEightIsNotRoutable() {
        #expect(!DNSAddress.v4([10, 0, 0, 1]).isRoutable)
        #expect(!DNSAddress.v4([10, 255, 255, 255]).isRoutable)
    }

    @Test func rfc1918OneSevenTwoSlashTwelveIsNotRoutable() {
        #expect(!DNSAddress.v4([172, 16, 0, 1]).isRoutable)
        #expect(!DNSAddress.v4([172, 31, 255, 255]).isRoutable)
        // Outside the /12 range (172.16.0.0-172.31.255.255) -- must remain routable.
        #expect(DNSAddress.v4([172, 15, 255, 255]).isRoutable)
        #expect(DNSAddress.v4([172, 32, 0, 0]).isRoutable)
    }

    @Test func rfc1918OneNineTwoOneSixEightIsNotRoutable() {
        #expect(!DNSAddress.v4([192, 168, 0, 1]).isRoutable)
        #expect(!DNSAddress.v4([192, 168, 255, 255]).isRoutable)
    }

    // MARK: - IPv4: loopback

    @Test func ipv4LoopbackIsNotRoutable() {
        #expect(!DNSAddress.v4([127, 0, 0, 1]).isRoutable)
        #expect(!DNSAddress.v4([127, 255, 255, 255]).isRoutable)
    }

    // MARK: - IPv4: link-local, including the cloud-metadata address

    @Test func ipv4LinkLocalIsNotRoutable() {
        #expect(!DNSAddress.v4([169, 254, 0, 1]).isRoutable)
    }

    @Test func cloudMetadataAddressIsNotRoutable() {
        #expect(!DNSAddress.v4([169, 254, 169, 254]).isRoutable)
    }

    // MARK: - IPv4: RFC 6598 carrier-grade NAT

    @Test func rfc6598CGNATIsNotRoutable() {
        #expect(!DNSAddress.v4([100, 64, 0, 1]).isRoutable)
        #expect(!DNSAddress.v4([100, 127, 255, 255]).isRoutable)
        // Outside the /10 range -- must remain routable.
        #expect(DNSAddress.v4([100, 63, 255, 255]).isRoutable)
        #expect(DNSAddress.v4([100, 128, 0, 0]).isRoutable)
    }

    // MARK: - IPv4: ordinary public addresses remain routable

    @Test func ordinaryPublicIPv4AddressesRemainRoutable() {
        #expect(DNSAddress.v4([8, 8, 8, 8]).isRoutable)
        #expect(DNSAddress.v4([93, 184, 216, 34]).isRoutable)
        #expect(DNSAddress.v4([1, 1, 1, 1]).isRoutable)
    }

    // MARK: - IPv6: loopback, unspecified, link-local, unique-local

    @Test func ipv6LoopbackIsNotRoutable() {
        let loopback: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        #expect(!DNSAddress.v6(loopback).isRoutable)
    }

    @Test func ipv6UnspecifiedIsNotRoutable() {
        let unspecified = [UInt8](repeating: 0, count: 16)
        #expect(!DNSAddress.v6(unspecified).isRoutable)
    }

    @Test func ipv6LinkLocalIsNotRoutable() {
        // fe80::1
        var bytes = [UInt8](repeating: 0, count: 16)
        bytes[0] = 0xFE
        bytes[1] = 0x80
        bytes[15] = 1
        #expect(!DNSAddress.v6(bytes).isRoutable)
    }

    @Test func ipv6UniqueLocalIsNotRoutable() {
        // fc00::1 and fd00::1 -- both within fc00::/7.
        var fcBytes = [UInt8](repeating: 0, count: 16)
        fcBytes[0] = 0xFC
        fcBytes[15] = 1
        #expect(!DNSAddress.v6(fcBytes).isRoutable)

        var fdBytes = [UInt8](repeating: 0, count: 16)
        fdBytes[0] = 0xFD
        fdBytes[15] = 1
        #expect(!DNSAddress.v6(fdBytes).isRoutable)
    }

    @Test func ordinaryPublicIPv6AddressRemainsRoutable() {
        // 2606:4700:10::6814:179a (a real, public Cloudflare address).
        let bytes: [UInt8] = [0x26, 0x06, 0x47, 0x00, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0x68, 0x14, 0x17, 0x9A]
        #expect(DNSAddress.v6(bytes).isRoutable)
    }

    // MARK: - IPv6: IPv4-mapped bypass (`::ffff:a.b.c.d`)

    @Test func ipv4MappedIPv6EncodingOfALoopbackAddressIsNotRoutable() {
        // ::ffff:127.0.0.1 -- the classic SSRF-filter bypass: an AAAA
        // record carrying a filtered IPv4 address inside an IPv6 wrapper.
        var bytes = [UInt8](repeating: 0, count: 16)
        bytes[10] = 0xFF
        bytes[11] = 0xFF
        bytes[12] = 127
        bytes[13] = 0
        bytes[14] = 0
        bytes[15] = 1
        #expect(!DNSAddress.v6(bytes).isRoutable)
    }

    @Test func ipv4MappedIPv6EncodingOfAPublicAddressRemainsRoutable() {
        // ::ffff:8.8.8.8
        var bytes = [UInt8](repeating: 0, count: 16)
        bytes[10] = 0xFF
        bytes[11] = 0xFF
        bytes[12] = 8
        bytes[13] = 8
        bytes[14] = 8
        bytes[15] = 8
        #expect(DNSAddress.v6(bytes).isRoutable)
    }
}
