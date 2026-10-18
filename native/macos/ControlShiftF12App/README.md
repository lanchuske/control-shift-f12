# Control Shift F12 AppKit host manifest

`Package.swift` is a non-shipping AppKit host declaration. Its intended bundle
identifier is `ai.lanchuske.control-shift-f12.macos-host`. It contains no Swift
source and must not be built or launched until the parent/child boundary has a
reviewed typed adapter and the host-specific tests exist.

When implementation is admitted, it uses AppKit and the argument-array,
anonymous-inherited-pipe boundary described in [the native host
record](../../README.md). It does not create a socket, a browser surface, a
terminal fallback, or a shell command.
