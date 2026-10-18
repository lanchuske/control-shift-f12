# Control Shift F12 AppKit host manifest

`Package.swift` and the admitted Swift source are a non-shipping AppKit
diagnostics projection host. Its intended bundle identifier is
`ai.lanchuske.control-shift-f12.macos-host`. The target has XCTest evidence for
its projection and owned-child lifetime; it is not a product bundle, signed
application, installer, or release artifact.

It uses AppKit and the fixed argument-array, anonymous-inherited-pipe boundary
described in [the native host record](../../README.md). It launches only the
bundle resource `seamless-input` with `control --ui-stdio`, exposes only local
diagnostic refresh, and does not create a socket, browser surface, terminal
fallback, shell command, layout action, or sharing capability.
