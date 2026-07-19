//
//  DNSAddressExtractionTests.swift
//  PerfectSMTPTests
//
//  `DNSResolver.extractAddresses(from:type:)` is the pure per-message half
//  of CNAME-chain following: given one decoded response, pull out either
//  the terminal address records of the queried type, or (if none) the next
//  CNAME hop to follow. Tested here directly against the real
//  `www.github.com` CNAME-then-A fixture, with no network or live resolver
//  involved. The actual multi-query chain-following loop (and its
//  cycle/hop-count guard) is exercised end-to-end against a local fake
//  server in `DNSResolverCNAMEFollowingTests`.
//

import Testing
@testable import PerfectSMTP

struct DNSAddressExtractionTests {

    @Test func extractsTheTerminalARecordFromARealCNAMEChain() throws {
        let message = try DNSMessage.decode(DNSTestFixtures.wwwGithubComResponse)
        let (addresses, cnameTarget) = DNSResolver.extractAddresses(from: message, type: .a)
        #expect(addresses.count == 1)
        #expect(addresses[0].description.hasPrefix("140.82."))
        // A terminal address record was found, so there's nothing further
        // to chase -- `cnameTarget` must be nil even though a CNAME record
        // was present in the answer section.
        #expect(cnameTarget == nil)
    }

    @Test func extractsOnlyTheCNAMETargetWhenTheQueriedTypeHasNoTerminalRecord() throws {
        // The same real chain, but queried for AAAA -- the response only
        // ever contains an A record at the end, so this must report "no
        // addresses of this type, but here's the CNAME hop to follow next"
        // rather than silently returning nothing useful.
        let message = try DNSMessage.decode(DNSTestFixtures.wwwGithubComResponse)
        let (addresses, cnameTarget) = DNSResolver.extractAddresses(from: message, type: .aaaa)
        #expect(addresses.isEmpty)
        #expect(cnameTarget == "github.com")
    }

    @Test func extractsMultipleAddressesOfTheQueriedTypeFromAFlatAnswerSection() throws {
        let message = try DNSMessage.decode(DNSTestFixtures.exampleComAResponse)
        let (addresses, cnameTarget) = DNSResolver.extractAddresses(from: message, type: .a)
        #expect(addresses.count == 2)
        #expect(cnameTarget == nil)
    }

    @Test func reportsNoAddressesAndNoCNAMEForAnEmptyAnswerSection() throws {
        let message = try DNSMessage.decode(DNSTestFixtures.nxdomainResponse)
        let (addresses, cnameTarget) = DNSResolver.extractAddresses(from: message, type: .a)
        #expect(addresses.isEmpty)
        #expect(cnameTarget == nil)
    }
}
