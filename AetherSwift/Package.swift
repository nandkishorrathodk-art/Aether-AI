// swift-tools-version: 5.9
// Aether AI - Swift Package
// Native macOS and iOS applications

import PackageDescription

let package = Package(
    name: "AetherAI",
    defaultLocalization: "en",
    platforms: [
        .macOS(.v13),  // macOS Ventura and later
        .iOS(.v16)     // iOS 16 and later
    ],
    products: [
        .library(
            name: "AetherCore",
            targets: ["AetherCore"]
        ),
        .library(
            name: "AetherAPI",
            targets: ["AetherAPI"]
        )
    ],
    dependencies: [
        // Networking
        .package(url: "https://github.com/Alamofire/Alamofire.git", from: "5.8.0"),
        
        // WebSocket
        .package(url: "https://github.com/daltoniam/Starscream.git", from: "4.0.0"),
        
        // JSON parsing
        .package(url: "https://github.com/SwiftyJSON/SwiftyJSON.git", from: "5.0.0"),
        
        // Keychain
        .package(url: "https://github.com/kishikawakatsumi/KeychainAccess.git", from: "4.2.0")
    ],
    targets: [
        // Core functionality
        .target(
            name: "AetherCore",
            dependencies: [
                "SwiftyJSON",
                "KeychainAccess"
            ],
            path: "Shared/Core"
        ),
        
        // API client
        .target(
            name: "AetherAPI",
            dependencies: [
                "AetherCore",
                "Alamofire",
                "Starscream",
                "SwiftyJSON"
            ],
            path: "Shared/API"
        ),
        
        // Tests
        .testTarget(
            name: "AetherTests",
            dependencies: ["AetherCore", "AetherAPI"]
        )
    ]
)
