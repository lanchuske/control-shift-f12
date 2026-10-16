# Native host and engine-child boundary

## Status and ownership

This is a non-shipping design boundary for future signed native presentation
hosts. The Rust `seamless-input` executable remains the sole owner of all
runtime, pairing, operational-session, inventory, layout, input and clipboard
state. This document adds no runtime behavior.

The planned native owner, inherited-pipe lifetime, platform-specific reader
cancellation, main-thread handoff, and pre-enable test matrix are recorded in
[the process-pipe adapter design](native-host-process-pipe-adapter.md). That
record is design-only and does not admit native source or a process launch.

The current internal control engine is reached only through:

```text
seamless-input control --stdio
```

That spelling is intentional: the executable exposes a `control` subcommand
with a required `--stdio` flag. There is no `--control-stdio` flag.

## Parent-created child process

The existing foundations control channel is deliberately separate from the
reserved native UI channel:

| Channel | Argument vector | Rule |
| --- | --- | --- |
| Foundations control | `[absolute path to seamless-input, "control", "--stdio"]` | Preserves its existing control-engine behavior; it is not a native-host fallback. |
| Native UI projection | `[absolute path to seamless-input, "control", "--ui-stdio"]` | The Rust-only adapter entrypoint is admitted; no native host source is admitted until its own target-platform owner/tests are admitted. |

Written as documentation commands, those are `seamless-input control --stdio`
and `seamless-input control --ui-stdio` respectively. The latter is a reserved
future channel, not a currently executable host interface.

When the native UI channel is admitted, each future AppKit or WinForms host
starts exactly one child using this platform-native argument vector:

```text
[absolute path to seamless-input, "control", "--ui-stdio"]
```

The path comes from signed-package resources selected by the local host, not
from a UI field, discovery record, environment variable, or remote message.
The host does not use a shell, command string, terminal parser, browser view,
or secondary launcher. It cannot fall back to `--stdio`, the TUI, or any other
argument vector.

The host creates anonymous inherited standard-input and standard-output pipes
before spawn. It gives the child no inherited listening socket, no named or
public control pipe, and no capability to accept a second control client. The
host owns those handles and closes both on cancellation, exit, or child fault.

The child environment is rebuilt from a fixed allowlist:

| macOS | Windows |
| --- | --- |
| `HOME`, `PATH`, `TMPDIR` | `SystemRoot`, `WINDIR`, `TEMP`, `TMP`, `LOCALAPPDATA`, `USERPROFILE`, `PATH` |

Every other variable is omitted. Future work may add a parent-created,
single-use typed launch authorization only after the Rust control contract
models and reviews it. It cannot be represented by arbitrary host input.

## Framed control protocol

The host and child use the existing `apps/seamless-input/src/control_api.rs`
protocol and no other channel:

1. A frame begins with a four-byte unsigned big-endian byte length.
2. The length must be non-zero and no larger than `MAX_FRAME_BYTES` (256 KiB).
3. The payload is one typed JSON request, response, or local engine event.
4. A malformed, incomplete, oversized, or unexpected frame closes the local
   control exchange. It never retries through a network, legacy command, or
   manual address path.

No native host may parse human CLI output or create an alternative request
framing format. Future typed UI requests retain the existing bounded framing
and request-ID idempotence.

### Child-to-host transient SAS frame

The only permitted serialization of `SasDisplayView` is one bounded JSON value
on the existing inherited **child stdout to host** pipe. It is not a V01 wire
record and is not accepted by `read_request` on child stdin. A future reviewed
adapter must reject it on every host-to-child request and must not re-export it
to another process, pipe, log, cache or response.

The value has exactly the following common fields; unknown fields reject:

| Field | Requirement |
| --- | --- |
| `v` | JSON integer exactly `1` |
| `kind` | ASCII exactly `sas_display_v1` |
| `attempt_binding` | nonzero JSON `u64`; adapter-local, ephemeral and non-secret; it is **not** the raw V01 attempt/session/transcript value |
| `generation` | nonzero JSON `u64`, strictly increasing for that `attempt_binding` |
| `current` | JSON boolean |

For `current: true`, the only additional fields are `remaining_ms`,
`code_groups`, and optional `details_suffix`. `remaining_ms` is an integer in
`1..=30000`. `code_groups` has `1..=8` printable-ASCII strings, each
`1..=32` bytes; the reviewed SAS presentation contract, not the host, defines
their exact alphabet and grouping. `details_suffix`, if present, is a
semantic token exactly `attempt-current` or `expires-soon`; the token carries
no raw attempt substring, code group, locator, IP address, hostname or port.
No other ASCII text, including a code-group substring, `192.168.1.4`,
`host:443`, or an illustrative “attempt ending …” phrase, is accepted. When no
suffix is needed, the field is omitted; JSON `null` is not accepted.
For `current: false`, there are no additional fields: it is a terminal
invalidation, not a new status frame.

The host renders a `current: true` frame only if its `(attempt_binding,
generation)` is newer than the rendered one for that binding. It records no
history: a `current: false` frame for an active binding must have a strictly
higher generation, immediately clears the screen and makes that binding
terminal. A later `current: true` frame for the terminal binding, a stale or
duplicate generation, invalidation without an active view, an unknown field,
or an out-of-bounds field is rejected and clears the visible view. This local
framing serialization is permitted only as transient inherited-pipe bytes; it
does not make the view serializable for persistence, logs, copying, caching,
telemetry, host-to-child requests or any re-export.

On the host-to-child side, the JSON request envelope's own top-level `v` and
`id` retain their existing meaning, but its `args` tree is recursively closed
over every `sas_display_v1` shape. The adapter rejects a request command named
`sas_display_v1`, the literal kind value `sas_display_v1`, or any nested args
key named `v`, `kind`, `attempt_binding`, `generation`, `current`,
`remaining_ms`, `code_groups`, or `details_suffix`. This deliberately prevents
a host from sending a complete frame, a partial frame, timing metadata, or a
re-exported SAS value back to the engine. A future host command needing one of
those generic names must receive a separately reviewed schema rather than
weakening this exclusion.

## Lifecycle and capability boundary

The host may render only a redacted typed projection supplied by a future
reviewed adapter. It does not retain discovery addresses, certificates,
identity keys, exporter material, durable receipts, raw layout drafts, or
input/clipboard capabilities.

The sole presentation exception is an ephemeral `SasDisplayView` for a current
bootstrap or V01 confirmation screen. It is non-serializable, not persistible,
not loggable and not copyable; it is neither a request field nor a host-side
capability. The host may render it only while the exact attempt is current, and
must clear/drop it on every terminal state or timeout. It must reject any cache,
history, clipboard, drag payload, share sheet, notification, title, tooltip,
help, crash report, diagnostic/support export or analytics use. An optional
details suffix exists only if needed by reviewed UX, has the same lifetime, and
is one of the restricted semantic tokens defined above; it contains neither the
code nor a locator.

The focused confirmation control may expose its grouped code to the current
local assistive technology, but code and suffix must not enter a global
announcement, window title, unfocused accessibility label, or accessibility
cache/history. This boundary cannot prevent a local user, permitted screen
capture, or trusted assistive technology from observing content visibly shown
on that user's screen; it prohibits only product-controlled retention and
secondary disclosure.

Closing a GUI has no shutdown command on the host-to-child path. It stops
accepting local actions, clears the visible projection, cancels its
platform-specific reader, closes the owned standard-stream endpoints, waits a
bounded interval, and then terminates/reaps its owned child if necessary. A
host cannot leave a detached engine or claim a running engine after its pipe
closes. Its exact host-to-child request allowlist remains the separately
reviewed typed UI commands; it does not use the foundations `shutdown` command.

This boundary does not create a relationship, session, layout, cursor crossing,
input, clipboard operation, or diagnostic success state. Those require their
separate reviewed runtime contracts.
