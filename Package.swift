// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "HTTPSignature",
    platforms: [.macOS(.v15)],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "HTTPSignature",

            targets: ["HTTPSignature"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0"..<"4.0.0"),
        .package(
            url: "https://github.com/apple/swift-asn1.git", .upToNextMajor(from: "1.0.0")),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "HTTPSignature",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ]),
        .testTarget(
            name: "HTTPSignatureTests",
            dependencies: [
                "HTTPSignature",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ]
        ),
    ]
)
