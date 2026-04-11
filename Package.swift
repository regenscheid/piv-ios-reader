// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PIVReader",
    platforms: [.iOS(.v16)],
    products: [
        .library(name: "PIVLib", targets: ["PIVLib"]),
    ],
    dependencies: [
        // X.509 certificate and CMS/PKCS#7 parsing
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "PIVLib",
            dependencies: [
                .product(name: "X509", package: "swift-certificates"),
            ],
            path: "PIVReader",
            exclude: ["Info.plist", "PIVReader.entitlements", "Assets.xcassets"]
        ),
    ]
)
