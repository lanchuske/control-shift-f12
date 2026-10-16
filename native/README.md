# Native host boundary

## Status

This directory records **non-shipping manifests only**. It does not contain a
native host implementation, build output, socket, pairing path, display map,
or user-interface fallback. The Rust executable remains the only owner of
runtime, pairing, operational-session, inventory, layout, input and clipboard
state.

The detailed parent/child boundary is
[the architecture record](../docs/architecture/native-host-boundary.md).

## Supported build matrix for this boundary

| Host | Required build environment | Current evidence | Decision when unavailable |
| --- | --- | --- | --- |
| macOS AppKit | macOS 27.0.1 with Xcode 27.0 (build 27A266a), capable of evaluating the Swift 5.9 package manifest | Verified on the local planning Mac on 2026-10-16; no host was built or launched | Block the native-host build. Do not substitute a terminal, web, or CLI surface. |
| Windows WinForms | .NET 8 WindowsDesktop SDK (`net8.0-windows`), MSVC Build Tools, and a matching Windows SDK for the Rust engine | **Not verified.** No Windows host/toolchain probe or build has been performed. | Block the native-host build. Do not substitute a terminal, web, or CLI surface. |

The macOS observation is a development-host fact, not a released compatibility
promise. A shipping support matrix requires host builds and platform QA.

## Boundary that future hosts must implement

The existing foundations channel remains:

```text
[absolute path to seamless-input, "control", "--stdio"]
```

Written as a command for documentation only, that is
`seamless-input control --stdio`. It is not a native-host fallback. The
reserved native projection channel is:

```text
[absolute path to seamless-input, "control", "--ui-stdio"]
```

Written as a command for documentation only, that is
`seamless-input control --ui-stdio`; the host must still use this exact
argument vector, not a shell command. This option does not yet exist and no
host may launch it until a separately reviewed entrypoint and platform tests
are admitted.

The native host must use its platform's argument-array process API. It must not
invoke a shell, interpolate a command string, or accept a user-supplied binary
path. Standard input and standard output are one anonymous inherited pipe pair
owned by that host and child; standard error is retained locally for host-only
failure reporting. Neither process creates a listener or a public/named
control endpoint.

The child environment is rebuilt from an allowlist rather than copied whole:

| Platform | Allowed names |
| --- | --- |
| macOS | `HOME`, `PATH`, `TMPDIR` |
| Windows | `SystemRoot`, `WINDIR`, `TEMP`, `TMP`, `LOCALAPPDATA`, `USERPROFILE`, `PATH` |

Any other inherited variable is omitted. The eventual adapter may add a
parent-created, single-use launch authorization only after the Rust control
contract has an independently reviewed representation for it; this manifest
does not claim such an authorization exists today.

The pipe uses the existing control framing only: a non-zero four-byte
big-endian length followed by JSON, with each frame bounded by
`MAX_FRAME_BYTES = 256 KiB`. Hosts may send only typed, locally initiated
requests accepted by that engine. They must not create a second parser or a
network route.

On normal window termination, process exit, or pipe failure, the host sends no
foundations shutdown command. It stops accepting UI actions, clears its
projection, cancels the platform reader, closes its owned standard-stream
endpoints, then waits/reaps or terminates/reaps the child. Pipe closure never
licenses leaving a child process running.

## Deliberate non-goals in this change

- No Swift or C# host source has been added.
- No host has been compiled, launched, signed, installed, or shipped.
- No local or remote network endpoint has been added.
- No pairing, SAS, inventory, topology, input, clipboard, diagnostic data, or
  runtime capability is exposed to a host.
