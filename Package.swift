// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "PerfectSMTP",
    platforms: [
        .macOS(.v26),
    ],
    products: [
        .library(name: "PerfectSMTPCore", targets: ["PerfectSMTPCore"]),
        .library(name: "PerfectSMTP", targets: ["PerfectSMTP"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.27.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
    ],
    targets: [
        // Foundation only. No NIO import — value types, MIME builder, RFC 2047
        // header encoder, dot-stuffing/QP/base64 encoders, reply/error/result
        // model. This boundary is a deliberate compile-time enforcement that
        // MIME composition can never reach into a live channel (see
        // Documentation/swift6-nio-rewrite-plan.md §4.1).
        .target(
            name: "PerfectSMTPCore",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "PerfectSMTPCoreTests",
            dependencies: ["PerfectSMTPCore"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        // Transport layer target. Phase 0 ships only a re-export stub;
        // channel handlers, the protocol state machine, the connection-pool
        // actor, Transport strategies, and SMTPMailer's public API land in
        // Phase 1. The NIO/NIOSSL/Logging dependencies are declared now so
        // Phase 1 can start immediately without a Package.swift churn.
        .target(
            name: "PerfectSMTP",
            dependencies: [
                "PerfectSMTPCore",
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "Logging", package: "swift-log"),
            ],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "PerfectSMTPTests",
            dependencies: ["PerfectSMTP"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
