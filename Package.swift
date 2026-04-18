// swift-tools-version:5.9

import PackageDescription

let package = Package(
    name: "CypheraKmip",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
    ],
    products: [
        .library(
            name: "CypheraKmip",
            targets: ["CypheraKmip"]
        ),
    ],
    targets: [
        .target(
            name: "CypheraKmip",
            path: "Sources/CypheraKmip"
        ),
        .testTarget(
            name: "CypheraKmipTests",
            dependencies: ["CypheraKmip"],
            path: "Tests/CypheraKmipTests"
        ),
    ]
)
