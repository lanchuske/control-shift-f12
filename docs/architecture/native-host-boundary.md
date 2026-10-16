# Native host and engine-child boundary

## Status and ownership

This is a non-shipping design boundary for future signed native presentation
hosts. The Rust `seamless-input` executable remains the sole owner of all
runtime, pairing, operational-session, inventory, layout, input and clipboard
state. This document adds no runtime behavior.

The current internal control engine is reached only through:

```text
seamless-input control --stdio
```

That spelling is intentional: the executable exposes a `control` subcommand
with a required `--stdio` flag. There is no `--control-stdio` flag.

## Parent-created child process

Each future AppKit or WinForms host starts exactly one engine child using a
platform-native argument vector:

```text
[absolute path to seamless-input, "control", "--stdio"]
```

The path comes from signed-package resources selected by the local host, not
from a UI field, discovery record, environment variable, or remote message.
The host does not use a shell, command string, terminal parser, browser view,
or secondary launcher.

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

## Lifecycle and capability boundary

The host may render only a redacted typed projection supplied by a future
reviewed adapter. It does not retain discovery addresses, certificates,
identity keys, exporter material, SAS values, durable receipts, raw layout
drafts, or input/clipboard capabilities.

Closing a GUI sends the existing shutdown request while the inherited pipe is
healthy, closes the pipes, and reaps the child. If shutdown fails, the host
still terminates and reaps its child. A host cannot leave a detached engine or
claim a running engine after its pipe closes.

This boundary does not create a relationship, session, layout, cursor crossing,
input, clipboard operation, or diagnostic success state. Those require their
separate reviewed runtime contracts.
