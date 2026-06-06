// swift-tools-version: 6.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

// import PackageDescription

// let package = Package(
//     name: "swiftServer",
//     targets: [
//         // Targets are the basic building blocks of a package, defining a module or a test suite.
//         // Targets can depend on other targets in this package and products from dependencies.
//         .executableTarget(
//             name: "swiftServer"),
//     ]
// )

// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "swiftServer",
    platforms: [
        .macOS(.v14) // Required for advanced concurrency features
    ],
    dependencies: [
        // Pulls in the Apple-ecosystem approved lightweight HTTP server framework
        .package(url: "https://github.com/hummingbird-project/hummingbird.git", from: "2.0.0")
    ],
    targets: [
        .executableTarget(
            name: "swiftServer",
            dependencies: [
                .product(name: "Hummingbird", package: "hummingbird")
            ]
        )
    ]
)
