// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "SkerryFormat",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "SkerryFormat", targets: ["SkerryFormat"]),
    ],
    targets: [
        // The format library compiles optimized even in debug: the memory-hard KDF is
        // unusably slow at -Onone.
        .target(
            name: "SkerryFormat",
            swiftSettings: [.unsafeFlags(["-O"], .when(configuration: .debug))]
        ),
        .testTarget(name: "SkerryFormatTests", dependencies: ["SkerryFormat"]),
    ]
)
