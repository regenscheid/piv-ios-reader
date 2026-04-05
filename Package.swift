// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PIVReader",
    platforms: [.iOS(.v16)],
    products: [
        .library(name: "PIVLib", targets: ["PIVLib"]),
    ],
    dependencies: [
        // OpenSSL for AES-CMAC, ECDH (CryptoKit doesn't have these)
        // https://github.com/krzyzanowskim/OpenSSL
        .package(url: "https://github.com/krzyzanowskim/OpenSSL.git", from: "3.2.0"),
    ],
    targets: [
        .target(
            name: "PIVLib",
            dependencies: [
                .product(name: "OpenSSL", package: "OpenSSL"),
            ],
            path: "PIVReader",
            exclude: ["Info.plist", "PIVReader.entitlements", "Assets.xcassets"]
        ),
    ]
)
