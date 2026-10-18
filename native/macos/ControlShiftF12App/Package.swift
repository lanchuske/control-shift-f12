// swift-tools-version: 5.9
// Application identifier: ai.lanchuske.control-shift-f12.macos-host
// Reviewed AppKit diagnostics host; no bundle or build product is tracked.

import PackageDescription

let package = Package(
    name: "ControlShiftF12App",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "ControlShiftF12App", targets: ["ControlShiftF12App"]),
    ],
    targets: [
        .executableTarget(name: "ControlShiftF12App"),
        .testTarget(
            name: "ControlShiftF12AppTests",
            dependencies: ["ControlShiftF12App"]
        ),
    ]
)
