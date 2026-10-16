# Native host / process-pipe adapter design

## Status, scope, and admission gate

This is a reviewed **design-only** record for Tasks 6 and 7. It does not add
AppKit, WinForms, process, pipe, network, or product source. In particular, it
does not make either manifest under `native/` shippable.

The candidate contains a bounded Rust `UiStdioAdapter` and a
`TimedRequestReader` abstraction. It does **not** yet contain an implementation
of an inherited-pipe reader, an AppKit host, or a WinForms host. Moreover,
`main.rs` currently routes `seamless-input control --stdio` to the foundations
`control_engine::run_stdio`, not to `ui_stdio_adapter::run_stdio`. The reserved
native UI vector is instead `seamless-input control --ui-stdio`; it does not
exist yet. A native host remains blocked until a separately reviewed entrypoint
adds that distinct routing while preserving foundations `--stdio` behavior.

No implementation may use this document as authority to launch a process.
Native source is admitted only after all pre-enable tests in
[Required evidence before native source](#required-evidence-before-native-source)
are present and passing on the actual target operating system.

This record refines, rather than replaces, the
[native host boundary](native-host-boundary.md). Where a detail conflicts, the
stricter requirement wins.

## Fixed child-launch boundary

Each host has exactly one child owner for one visible local application
session. Its only launch target is the signed package resource selected by the
host, with this exact argument array:

```text
[absolute path to seamless-input, "control", "--ui-stdio"]
```

The host must use its native argument-array process API. It must not invoke a
shell, command interpreter, terminal, script, secondary launcher, user-entered
path, environment-selected executable, browser view, URL scheme, socket, or
named/public pipe. The fixed executable path is resolved inside the installed
package before launching; a missing, non-regular, or out-of-package target is
a local failure and does not fall back to another executable.

`control --stdio` is not an alternate host launch vector: it remains the
foundations channel. The TUI is likewise a technical fallback, not a host
substitute.

The child gets only these three inherited standard streams:

| Child stream | Endpoint | Purpose | Prohibited use |
| --- | --- | --- | --- |
| stdin | host-owned anonymous pipe writer | Host-to-child framed, allowlisted requests | SAS, shell commands, URLs, locators, credentials, input/clipboard/transport requests |
| stdout | host-owned anonymous pipe reader | Child-to-host typed projection, diagnostics, responses, and transient SAS display frames | Human CLI parsing, a second child, or any re-export |
| stderr | host-owned local diagnostic reader | Bounded, redacted local failure classification only | UI report body, logs, telemetry, support export, request channel, or SAS carrier |

All other inheritable handles/file descriptors are closed before exec/spawn. No
network listener, socket, named pipe, file mapping, inherited terminal, or
additional standard handle is granted. The child environment is rebuilt from
the allowlist in [native-host-boundary.md](native-host-boundary.md), not copied
from the user session.

The host owns the process and every parent pipe endpoint. It closes the parent
end of stdin/stdout/stderr when it stops or faults; it never transfers those
handles to a second host, helper, or restarted child.

## Framing and direction

Both stdin and stdout use the existing `control_api` frame: a non-zero,
four-byte unsigned big-endian byte length followed by a single UTF-8 typed JSON
payload. Every payload, including stderr-derived failure metadata if such
metadata is represented at all, remains bounded by
`MAX_FRAME_BYTES = 256 KiB`. The host does not implement a line protocol,
partial-frame recovery, text scraping, alternate framing, or legacy CLI
fallback.

The typed adapter's direction is closed:

| Direction | Allowed values |
| --- | --- |
| Host → child | `ui.refresh` and `ui.confirm_v01` only, using the existing request envelope and idempotent request IDs |
| Child → host | `ui_snapshot_v1`, `ui_diagnostics_v1`, `ui_response_v1`, and the transient `sas_display_v1` frame only |

Malformed, zero-length, truncated, oversized, unknown-version, unknown-field,
wrong-direction, or invalid-JSON frames are terminal local pipe failures. The
host closes the exchange, clears every projected state, and reports only a
non-sensitive local failure class. It does not retry by sending a manual
address, discovering a replacement process, reusing a request, or opening a
network route.

`sas_display_v1` has the exact bounded schema, one-way rule, recursive
host-request rejection, and terminal-generation semantics defined in
[native-host-boundary.md](native-host-boundary.md#child-to-host-transient-sas-frame).
It is the only permitted transient presentation serialization of a SAS code.

## Owner, lifetime, cancellation, and timeouts

The host creates a single `PipeSession` owner before spawn. It owns: the child
process handle, the three parent pipe endpoints, the immutable installed path,
the bounded framed reader/writer, a host-local monotonic clock, and the UI
projection generation. It does not own runtime, pairing, trust, input,
clipboard, discovery locators, receipts, or layout state.

Normal close is ordered as follows:

1. Stop accepting UI actions and clear the visible SAS immediately.
2. Cancel the platform reader, close every parent pipe endpoint, and wait a
   bounded platform-native interval for the child to exit.
3. If it has not exited, terminate only that owned child, wait/reap it, then
   discard the `PipeSession`.

A write failure, read failure, malformed frame, EOF, child exit, application
termination, app deactivation that ends the session, or timeout follows the
same clear-and-reap path. There is no foundations shutdown command on the
host-to-child path: its exact allowlist remains `ui.refresh` and
`ui.confirm_v01`. Closing pipes and owning/reaping the child never permits a
detached child, background reader, or a UI that still claims the engine is
running.

The engine adapter owns the authoritative monotonic deadline and emits the
terminal `sas_display_v1 current:false` frame. The host additionally has a
local monotonic presentation timer derived from `remaining_ms`; it is only an
early-clear safety fence and can never extend a code's lifetime. The host
clears its display at the earliest of local timer expiry, terminal frame, pipe
failure, child exit, attempt/generation change, window/session closure,
permission/revocation projection, or explicit local mismatch. A local timer
does not synthesize a positive confirmation and does not modify the engine.

### Platform-specific reader cancellation is intentionally not unified

`TimedRequestReader` requires a synchronously cancelable, deadline-aware
reader. It is an engine contract, not proof that a portable native reader has
been built. The host implementations must be reviewed independently:

| Platform | Required resolution before source is enabled | What this document does **not** assume |
| --- | --- | --- |
| macOS AppKit | Select and test one Apple-supported anonymous-pipe ownership model that can cancel a blocked read, close the writer/reader in the documented order, join/reap, and hand results to AppKit's main queue. | That closing a descriptor from another thread always interrupts a blocked `read`, or that a detached Dispatch/Swift task cannot outlive the session. |
| Windows WinForms | Select and test one Windows-native anonymous-pipe ownership model with a cancellable outstanding read, explicit handle lifetime, bounded process wait/reap, and handoff to the WinForms UI thread. | That a synchronous anonymous-pipe `ReadFile` is cancellable by an arbitrary close, or that `CancelIoEx` applies without the required handle/I/O setup. |

Neither platform may use a detached reader. The chosen implementation must
prove that a stdout write failure, a blocked stdin read, and process exit all
return control to the owning `PipeSession`, cancel/join the reader, and release
handles before a restart. A common Rust trait does not erase these operating
system differences.

## UI projection and main-thread handoff

Pipe work is off the UI thread. It decodes and validates a complete typed frame
before it creates an immutable redacted projection. It then schedules that
projection onto the platform's main UI executor:

- AppKit: the AppKit main thread / main dispatch queue.
- WinForms: the owning control/form UI thread through its normal marshaling
  mechanism.

No I/O callback mutates controls directly. Every scheduled update carries the
current `PipeSession` and projection generation; the main thread drops an
update from a closed session, stale generation, or terminal SAS binding. It may
coalesce ordinary snapshots and diagnostics while preserving their newest
generation, but it must never coalesce away a terminal SAS invalidation. UI
events only create the two allowlisted typed requests; they never invoke a
runtime command, process API, shell, socket, clipboard operation, or input
operation.

The host renders no optimistic running, paired, sharing, input, clipboard, or
layout-ready state. It renders only the current redacted projection. A missing,
duplicate, stale, malformed, or non-PASS runtime observation disables actions
as the controller already requires.

## Local SAS presentation and accessibility

SAS display is a short-lived main-thread view, not host state. The host keeps
only the currently rendered frame long enough to compare its binding and
generation and to schedule its local expiry clear. It must clear the code and
suffix from controls, accessibility labels/cache, selection/focus state,
notifications, titles, tooltips, help, diagnostics, crash reports, clipboard,
drag/share payloads, logs, telemetry, screenshots it creates, and restart
state at every terminal condition listed above.

The focused local confirmation control may expose the grouped code to the
current local assistive technology, as required by the established SAS boundary.
It must not announce it globally or retain it in an accessibility history. This
does not claim that an operating system, permitted screen recording, a local
person, or a trusted accessibility client cannot observe a visibly focused
code; native source must state that limitation truthfully in its accessibility
review.

## Exit, restart, and recovery

Process exit or pipe failure is a terminal UI state for the owning session. The
host clears projection, SAS, pending request state, focus/confirmation state,
and any stderr buffer before showing a generic retry affordance. It neither
trusts a partial last frame nor treats a process still present in an OS process
list as healthy.

A retry may create a new `PipeSession` only after the prior session's reader
is cancelled/joined, endpoints are closed, and the child is reaped. It starts
with no projected runtime state, no SAS, no replay cache, no request IDs, and
no local confirmation carried from the previous session. The retry cannot
resume, extend, or confirm the previous V01 attempt.

## Required evidence before native source

The non-shipping static guard remains in force until every listed evidence item
is implemented and reviewed. A macOS-only result never enables Windows, and a
simulated pipe never proves the target platform.

| Area | Required automated evidence | Required target evidence / failure result |
| --- | --- | --- |
| Engine admission | Test that the exact child vector routes to the reviewed typed adapter, with one shared monotonic epoch; foundations `control_engine` is rejected for a UI host. | Review confirms no argument or environment fallback. |
| Launch boundary | Mutation tests reject shell text, relative/user/environment paths, extra arguments, inherited handles, named/public pipes, and non-allowlisted environment entries. | Package-resource path failures remain local and launch nothing else. |
| Framing | Fuzz/mutation tests cover zero, truncated, oversized, invalid JSON, unknown schema, wrong direction, and partial writes/reads at the 256 KiB boundary. | Both platforms close/clear/reap; no retry route. |
| Host allowlist | Integration tests reject every host request except `ui.refresh` and `ui.confirm_v01`, including recursive SAS shapes and request-ID conflicts/replays. | Host cannot cause input, clipboard, transport, discovery, or layout authority. |
| SAS lifetime | Tests cover current display, duplicate/stale frame, terminal invalidation, local expiry without traffic, backward clock, child exit, UI close, and restart. | Code/suffix clears immediately and cannot appear in history, logs, clipboard, notification, title, tooltip, accessibility cache, or next session. |
| macOS pipe owner | AppKit-targeted test exercises a blocked read, cancellation, child exit, stdout write failure, bounded wait, reaping, and main-thread handoff. | No detached task or descriptor leak; UI is never updated off main. |
| Windows pipe owner | WinForms/Windows-targeted test exercises the selected cancellable-read strategy, blocked read, child exit, stdout write failure, bounded wait, reaping, and UI-thread handoff. | No blocked worker, handle leak, or UI-thread violation. |
| Restart | Integration test crashes/exits child mid-frame and after a SAS display, then retries. | New session has no old request ID, projection, SAS, confirmation, or timer. |
| Accessibility | Platform UI tests verify keyboard-only operation, focus order, semantic status, focused SAS exposure, and terminal clearing. | No global SAS announcement/history; documented OS visibility limits remain visible to reviewers. |
| Physical QA | Signed package tests on a real Mac and a real Windows target measure start/stop/restart, permission loss, process cleanup, memory/CPU, and no-network-endpoint behavior. | Record PASS/FAIL/NOT MEASURED separately; no stable release claim from a harness-only pass. |

Until this evidence exists, manifests remain declarations only; no native host
source, build, launch, signing, packaging, or release is permitted.

## Non-goals

This design does not add a GUI, native source, process spawning code, an IPC
implementation, networking, transport, discovery, pairing, a layout save,
input sharing, clipboard sharing, a CI workflow, or a publication path. It
does not resolve the separately paused post-V01 operational-layout protocol.
