// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "inkyImager",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "inkyImager", targets: ["inkyImager"]),
        .executable(name: "inkyImagerHelper", targets: ["inkyImagerHelper"]),
    ],
    targets: [
        .target(name: "CXZ", publicHeadersPath: "include",
                cSettings: [.unsafeFlags(["-I/opt/homebrew/opt/xz/include"])],
                linkerSettings: [.linkedLibrary("lzma")]),
        .target(name: "ImagerCore", dependencies: ["CXZ"],
                linkerSettings: [.linkedFramework("IOKit")]),
        .executableTarget(name: "inkyImager", dependencies: ["ImagerCore"]),
        .executableTarget(name: "inkyImagerHelper", dependencies: ["ImagerCore"]),
        .testTarget(name: "ImagerCoreTests", dependencies: ["ImagerCore"]),
    ],
    swiftLanguageModes: [.v5]
)
