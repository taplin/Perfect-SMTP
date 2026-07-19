# Perfect - SMTP [简体中文](README.zh_CN.md)

<p align="center">
    <a href="http://perfect.org/get-involved.html" target="_blank">
        <img src="http://perfect.org/assets/github/perfect_github_2_0_0.jpg" alt="Get Involed with Perfect!" width="854" />
    </a>
</p>

<p align="center">
    <a href="https://github.com/PerfectlySoft/Perfect" target="_blank">
        <img src="http://www.perfect.org/github/Perfect_GH_button_1_Star.jpg" alt="Star Perfect On Github" />
    </a>
    <a href="http://stackoverflow.com/questions/tagged/perfect" target="_blank">
        <img src="http://www.perfect.org/github/perfect_gh_button_2_SO.jpg" alt="Stack Overflow" />
    </a>
    <a href="https://twitter.com/perfectlysoft" target="_blank">
        <img src="http://www.perfect.org/github/Perfect_GH_button_3_twit.jpg" alt="Follow Perfect on Twitter" />
    </a>
    <a href="http://perfect.ly" target="_blank">
        <img src="http://www.perfect.org/github/Perfect_GH_button_4_slack.jpg" alt="Join the Perfect Slack" />
    </a>
</p>

<p align="center">
    <a href="https://www.swift.org/" target="_blank">
        <img src="https://img.shields.io/badge/Swift-6.2-orange.svg?style=flat" alt="Swift 6.2">
    </a>
    <a href="https://developer.apple.com/macos/" target="_blank">
        <img src="https://img.shields.io/badge/Platforms-macOS%2026%2B-lightgray.svg?style=flat" alt="Platforms macOS 26+">
    </a>
    <a href="LICENSE" target="_blank">
        <img src="https://img.shields.io/badge/License-Apache%202.0-lightgrey.svg?style=flat" alt="License Apache 2.0">
    </a>
    <a href="http://twitter.com/PerfectlySoft" target="_blank">
        <img src="https://img.shields.io/badge/Twitter-@PerfectlySoft-blue.svg?style=flat" alt="PerfectlySoft Twitter">
    </a>
</p>

Perfect-SMTP is a from-scratch Swift 6.2 / SwiftNIO SMTP client. It is not a
wrapper around libcurl or any other mail library — it drives the SMTP wire
protocol itself, including its own STARTTLS state machine, connection
pooling, DKIM signing, and MTA-STS policy enforcement.

It ships three delivery strategies (relay through an existing SMTP host,
hand off to a local MTA like Postfix/sendmail, or resolve MX records and
deliver directly), so you can pick the one that matches how you already
operate mail, or let Perfect-SMTP be the terminal MTA itself.

> This is a complete rewrite of the pre-2026 libcurl-based Perfect-SMTP. If
> you used the old `EMail`/`SMTPClient`/`Recipient` API, see
> [Migrating from the old Perfect-SMTP](Documentation/user-guide.md#migrating-from-the-old-perfect-smtp)
> in the user guide — this is not a drop-in upgrade.

## Features

- **Hand-rolled SMTP client on SwiftNIO** — its own STARTTLS upgrade
  sequence with byte-precise buffer discipline against injection/downgrade
  attacks, connection pooling with circuit breaking, and PIPELINING support.
- **DKIM signing** (RFC 6376) — RSA-SHA256 and Ed25519-SHA256 (RFC 8463),
  including dual-signing, with automatic oversigning of security-sensitive
  headers and a DMARC-alignment lint.
- **Three delivery strategies** — `RelayTransport` (an ESP or existing SMTP
  relay), `LocalMTATransport` (hand off to `sendmail`/Postfix on the same
  host), and `DirectMXTransport` (resolve MX records and deliver directly,
  with its own retry queue and circuit breaker).
- **MTA-STS** (RFC 8461) policy discovery, caching, and enforcement for
  direct-MX delivery, plus opportunistic STARTTLS by default.
- **SASL authentication** — `PLAIN`, `LOGIN`, and `XOAUTH2` (required by
  Gmail/Workspace, increasingly required by Microsoft 365).
- **Deliverability headers** — `List-Unsubscribe`/`List-Unsubscribe-Post`
  (RFC 8058), `Precedence`, `Auto-Submitted` — the headers Gmail and Yahoo
  have required for bulk senders since November 2025.
- **Bulk/list-server ready** — a bounded-concurrency batch `send` and an
  `AsyncSequence`-based streaming `send` for sending to millions of
  recipients without materializing them all in memory.
- **Structured delivery results** — every send returns a per-recipient
  outcome (delivered, queued for retry, permanently failed, expired,
  ambiguous, or a transport-level failure) instead of a single pass/fail.

For anything beyond the basics below, see the
**[full user guide](Documentation/user-guide.md)**.

## Requirements

- Swift 6.2 toolchain (`swift-tools-version: 6.2`, `.swiftLanguageMode(.v6)`)
- macOS 26 or later (`Package.swift` declares `platforms: [.macOS(.v26)]`)

## Installation

Add the package to your `Package.swift`:

```swift
.package(url: "https://github.com/PerfectlySoft/Perfect-SMTP.git", from: "6.0.0")
```

and depend on the `PerfectSMTP` product (it re-exports `PerfectSMTPCore`,
which you only need directly if you want to compose/sign messages without
sending them):

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "PerfectSMTP", package: "Perfect-SMTP"),
    ]
)
```

## Quick start

Send one email through an existing SMTP relay (a corporate MTA or an ESP
like SendGrid/Postmark/SES):

```swift
import PerfectSMTP
import NIOPosix

let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)

let transport = RelayTransport(
    config: RelayConfig(
        host: "smtp.example.com",
        port: 587,
        tls: .startTLS,
        auth: .plain(username: "postmaster@example.com", password: "secret")
    ),
    group: group
)
let mailer = SMTPMailer(transport: transport)

var message = EmailMessage(from: EmailAddress(displayName: "Ops", address: "ops@example.com"))
message.to = [EmailAddress(address: "user@dest.com")]
message.subject = "Hello from Perfect-SMTP"
message.textBody = "Hi there!"

let results = try await mailer.send(message, envelopeFrom: .address("ops@example.com"))
for result in results {
    print(result.recipient, result.outcome)
}

try await group.shutdownGracefully()
```

That's it for the basic case. For DKIM signing, direct-MX delivery,
authentication options, bulk sending, and deliverability headers, see the
**[user guide](Documentation/user-guide.md)**.

## Testing

```
swift test
```

All 323 tests run with no external services and no environment variables —
this includes tests that open real loopback sockets (a STARTTLS handshake
and a full DirectMX delivery each run against an in-process fake SMTP
server on `127.0.0.1`), but nothing here talks to the real network or a
real mail server.

Note: the original rewrite plan (`Documentation/swift6-nio-rewrite-plan.md`
§4.1/§5) describes an additional `SMTP_TESTS=1`-gated live-integration tier
against a MailHog/smtp4dev CI service container. That tier was never built —
there is no such environment variable referenced anywhere in `Tests/`, and
this repository has no CI workflow files at all. If you need to verify
against a real SMTP server, point a `RelayTransport` or `DirectMXTransport`
at a local MailHog/smtp4dev instance yourself; see
[Testing your integration](Documentation/user-guide.md#testing-your-integration)
in the user guide.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
