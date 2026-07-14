// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "SkerryFormat",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "SkerryFormat", targets: ["SkerryFormat"]),
    ],
    targets: [
        .target(name: "SkerryFormat"),
        .testTarget(name: "SkerryFormatTests", dependencies: ["SkerryFormat"]),
    ]
)
