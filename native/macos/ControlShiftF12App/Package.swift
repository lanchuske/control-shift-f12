// swift-tools-version: 5.9
// Application identifier: ai.lanchuske.control-shift-f12.macos-host
// Non-shipping manifest: no target source is present in this change.

import PackageDescription

let package = Package(
    name: "ControlShiftF12App",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "ControlShiftF12App", targets: ["ControlShiftF12App"]),
    ],
    targets: [
        .executableTarget(name: "ControlShiftF12App"),
    ]
)
