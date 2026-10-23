// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "inkyImager",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "inkyImager", targets: ["inkyImager"]),
        .executable(name: "inkyImagerHelper", targets: ["inkyImagerHelper"]),
        .executable(name: "inkyMaintenance", targets: ["inkyMaintenance"]),
    ],
    targets: [
        .target(name: "CAuthOpen", publicHeadersPath: "include"),
        .target(name: "CXZ", publicHeadersPath: "include",
                cSettings: [.unsafeFlags(["-I/opt/homebrew/opt/xz/include"])],
                linkerSettings: [.linkedLibrary("lzma")]),
        .target(name: "ImagerCore", dependencies: ["CXZ", "CAuthOpen"],
                linkerSettings: [.linkedFramework("IOKit")]),
        .executableTarget(name: "inkyImager", dependencies: ["ImagerCore"]),
        .executableTarget(name: "inkyImagerHelper", dependencies: ["ImagerCore"]),
        .executableTarget(name: "inkyMaintenance", dependencies: ["ImagerCore"]),
        .testTarget(name: "ImagerCoreTests", dependencies: ["ImagerCore", "CAuthOpen"]),
    ],
    swiftLanguageModes: [.v5]
)
