# Desktop functional-parity plan and admission gate

## Decision and status

Control Shift F12 is a desktop product. Its primary experience must be a
functional macOS AppKit application and a functional Windows WinForms
application. The TUI is a technical fallback for development and support; it
is not the primary user flow or evidence that either desktop application is
ready.

This document remains the parity admission plan. One non-shipping macOS AppKit
diagnostics projection source and XCTest target are now guarded/admitted; they
do not add a product GUI, full desktop flow, pairing endpoint, layout save,
runtime capability, CI, or release. The structural native guard remains active.

## Chosen control-channel separation

The eventual native child mode is `seamless-input control --ui-stdio`, launched
through a native argument array, never a shell. It is the dedicated inherited
stdio projection channel for the reviewed typed `UiStdioAdapter`.

`seamless-input control --stdio` remains the foundations control channel with
its current behavior. `seamless-input tui` remains a technical fallback. A
desktop app must never fall back from `--ui-stdio` to `--stdio`, TUI, a shell,
or a network endpoint.

`--ui-stdio` has a separately admitted Rust-only entrypoint. Native host source
remains blocked except for the guarded macOS diagnostics projection owner and
its XCTest target. The pipe/cancellation rules remain those in [the
host-process design](native-host-process-pipe-adapter.md).

## Functional parity surface

Both desktop apps expose the same human workflow. “Expose” means the person
can see current state, understand why an action is unavailable, act locally
where a reviewed contract permits it, and recover without a terminal. It never
means the UI invents protocol facts or bypasses permissions/firewall policy.

| Stage | Native desktop capability | Required honest boundary |
| --- | --- | --- |
| Nearby | Explicit find/stop action and neutral compatible/fresh handles | Discovery is untrusted. Stale, incompatible, missing, or policy-blocked entries return to the catalogue; no silent substitution or manual-address fallback. |
| New relationship | Bootstrap progress and visible double local confirmation | Bootstrap SAS is separate from V01; a locally verified durable receipt is required before confirmed state. No sharing follows bootstrap. |
| Confirmed relationship | Current confirmed-computers list and explicit selection | Only active local receipt/pin state is selectable; missing/prepared/revoked is not presented as confirmed. |
| V01 compare | Same grouped code on both screens, remaining-time state, explicit local match/mismatch | `SasDisplayView` is current-only and child-to-host-only. One machine cannot approve the other; expiry/reset/revoke clears it. |
| Device/session | Stable header and details for runtime, permissions, discovery, sessions, capability | Missing, duplicate, stale, malformed, non-PASS, or terminal facts never render as ready/running and disable dependent actions. |
| Displays | Measured inventory, quality markers, proportional map, drag and keyboard cardinal placement | A map is a local draft. Inventory generation changes invalidate it; no cursor/input/clipboard capability follows map editing. |
| Layout review | Native review, accept/reject, and clear waiting/blocked state | A proposal is **not a saved topology**. V01 closes before payloads: save requires a separate authenticated application-session lifecycle. |
| Permission/firewall | macOS Accessibility guidance; Windows private-network guidance | Never collect a password, silently elevate, create a rule, enable public networks, or treat consent as trust. |
| Runtime/recovery | Start/stop/retry state and current diagnostics | Pipe/process/session failure clears projection, SAS, pending approval and actions. A retry is a fresh session. |
| Diagnostics | Compact semantic result and selectable redacted detail | PASS/FAIL/NOT MEASURED is current and structured; diagnostics grant no authority or stale success. |

The detailed interaction contract is [the native setup UX specification](../native-setup-ux-specification.md).

## Action-gate schema

Presented state is a projection, never action authority. A disabled or visible
control must not be treated as an engine command, and every future enabled
control needs the typed gate below. “Future schema” names a review target; it
does not add a current host-to-child command. The current host-to-child
allowlist remains exactly `ui.refresh`, `ui.start_discovery`,
`ui.stop_discovery`, and `ui.confirm_v01`. The discovery actions are only
local browsing-state transitions until a separately reviewed engine owner
publishes candidates.

| User action | Future typed gate and engine owner | Required presented state / preconditions | Allowed effect | Fail-closed rejection and no fallback | Current status |
| --- | --- | --- | --- | --- | --- |
| `Find nearby` | `ui.discovery.begin`; discovery/admission owner | Explicit local gesture; app projection current; no selected attempt | Opens one bounded local discovery-consent window | Missing/stale runtime, duplicate window, or policy denial rejects; no manual address, legacy command, socket, or background retry | Fenced: G4, schema not implemented. |
| `Stop looking` | `ui.discovery.stop`; discovery/admission owner | Own current discovery-window generation | Closes only that local window and clears untrusted catalogue projection | Generation mismatch or absent window rejects; cannot stop/alter another process or preserve a candidate | Fenced: G4, schema not implemented. |
| `Select nearby computer` | `ui.discovery.select`; discovery/admission owner | Current compatible opaque handle in the selected catalogue generation; browsing stopped atomically | Binds one local candidate selection for the next reviewed bootstrap gate | Stale/missing/incompatible/replaced handle rejects; no identity inference or silent substitution | Fenced: G4, schema not implemented. |
| `Begin bootstrap` | `ui.bootstrap.begin`; durable-pairing bootstrap owner | One current selected candidate, explicit local gesture, no active bootstrap/V01 attempt | Starts only the separately reviewed bootstrap state machine | Any unavailable receipt/identity/protocol fact rejects; no V01, layout, sharing, manual-address, or retained-connection fallback | Fenced: G4; frozen bootstrap contract absent. |
| `Confirm bootstrap code` | `ui.bootstrap.confirm { matches: bool }`; bootstrap owner | Current bootstrap attempt, local SAS display, local unexpired deadline | Records one local match/mismatch decision for that bootstrap attempt | Missing/stale/expired code, duplicate, remote-only approval, or mismatch rejects/clears; no V01 confirmation reuse | Fenced: G4, schema not implemented. |
| `Begin V01` | `ui.v01.begin`; operational-session owner | Explicit selection of locally verified active durable receipt/pin; no terminal fence; fresh local gesture | Creates one fresh V01 connection/attempt only | Prepared/revoked/missing receipt, candidate drift, or unavailable session rejects; no bootstrap, discovery, or legacy fallback | Fenced: G4/G5; V01 UI admission not wired. |
| `Confirm V01 code` | Existing typed `ui.confirm_v01 { matches: bool }`; UI controller plus operational-session owner | One current engine-authored V01 SAS, exact live attempt, before authoritative deadline, one local gesture | Records only this local comparison choice; the remote peer must decide independently | Missing/stale/duplicate/late/malformed state rejects and clears; no remote confirmation, timeout extension, or authority grant | Adapter schema exists, but fenced until G1 plus operational integration. |
| `Move display` | `ui.layout.move_cardinal { display, direction, alignment }`; future local layout-draft owner | Current measured inventory generation; local arrangement state; geometry valid before and after move | Changes only an in-memory local draft by a cardinal edge | Invalid/diagonal/overlap/stale-generation move rejects; no save, transport, input, or clipboard effect | Fenced: G5, schema not implemented. |
| `Reset layout` | `ui.layout.reset_draft`; future local layout-draft owner | Current local draft tied to current inventory generation | Restores only the local default draft | Missing/stale inventory or absent draft rejects; no durable deletion or remote mutation | Fenced: G5, schema not implemented. |
| `Review layout` | `ui.layout.propose`; future authenticated application-session owner | Valid canonical local draft; both inventories current; separately admitted post-V01 session | Produces a review-only proposal for the other local UI | No authenticated lifecycle, changed inventory, ambiguity, or failed canonical validation rejects; no map save or V01-payload reuse | Explicitly fenced: G6. |
| `Start sharing` | `ui.runtime.start`; future runtime capability owner | Bilaterally durable saved layout, current runtime PASS, active permissions, separate sharing consent/capability gate | Starts only reviewed runtime capability after all gates | Any missing layout proof, permission, session, or capability rejects; no input/clipboard enablement from map/V01/UI state | Explicitly fenced: G7. |
| `Stop sharing` | `ui.runtime.stop`; future runtime capability owner | Current locally owned runtime capability | Releases local sharing state and returns control locally | Missing/terminal state is idempotent local-safe; cannot revive a session, mutate trust, or act remotely | Fenced: G7; emergency/local recovery remains separately reviewed. |
| `Retry` | `ui.session.retry`; owning failed-stage controller | The current projection contains a retryable, non-terminal, local failure class and no active child/session | Starts a fresh attempt for that same stage only | Terminal/revoked/ambiguous/stale failure rejects; no reuse of SAS, request ID, candidate, layout draft, or hidden fallback | Fenced until each owning stage is admitted. |

The host may render these controls and their unavailable explanations, but it
must not send any future schema before that schema, its owner, and the adapter
allowlist are independently reviewed. Layout review/save/share are therefore
not merely visually disabled: they have no admitted host-to-child authority.

## Two native design systems

The common character is a calm equipment panel: one quiet vertical workflow
and one memorable visual element, the proportional display topology. It is not
a browser dashboard, a terminal transcription, or a field of rounded SaaS
cards. System colors, conventional controls, and disciplined whitespace carry
the rest.

| Token | AppKit | WinForms | Shared meaning |
| --- | --- | --- | --- |
| Surface | `windowBackgroundColor` | `SystemColors.Window` | Plain working surface, not a tinted dashboard. |
| Topology field | `underPageBackgroundColor` | `ControlLightLight` | Quiet canvas behind measured monitor rectangles. |
| Ready | system green | `Color.ForestGreen` | A locally verified completed fact only. |
| Attention | system orange | `Color.DarkOrange` | Human confirmation or retryable interruption. |
| Blocked | system red | `Color.Firebrick` | A condition that prevents progress. |
| Selection | current accent color | user accent / `Highlight` | Keyboard and pointer selection, never decoration. |
| Type | SF Pro/San Francisco system font | Segoe UI system font | Semibold title; normal body; monospaced only in a selectable details disclosure. |

### AppKit: composed equipment panel

Use an `NSWindow` with a stable header, `NSOutlineView` or `NSTableView` for
nearby/confirmed devices, `NSButton` actions, native sheets for interruption,
and an `NSView` topology canvas. Align all prose and controls to one left
edge; the lower action row stays fixed while the topology receives remaining
height. The map has thin measured rectangles, quiet fills, and a single
connection thread only when the underlying state permits its meaning.

```text
┌ Control Shift F12 ───────────────────────────────────────────────────┐
│ Arrange the screens                                                    │
│ Geometry measured on both computers · layout not saved                 │
│                                                                        │
│              ┌──────── Mac ────────┐                                  │
│              │ 1512 × 982 · 2×     │                                  │
│              └─────────────────────┘                                  │
│                         ┌──── Windows 1 ────┬── Windows 2 ──┐          │
│                         │ 1920 × 1080 ·100% │ 2560×1440·125%│          │
│                         └───────────────────┴───────────────┘          │
│                                                                        │
│ Displays must touch by an edge.                    [Review layout]    │
└──────────────────────────────────────────────────────────────────────┘
```

### WinForms: direct desktop control surface

Use a standard `Form`, `ListView`/`DataGridView`, `Button`, `StatusStrip`,
`ErrorProvider`, and a double-buffered custom `Control` only for the topology
canvas. Preserve the same vertical hierarchy but use WinForms' familiar action
alignment and error presentation rather than imitating macOS sheets or
spacing. The map remains the visual anchor; ordinary state is plain text,
status strip, and native focus.

```text
+-----------------------------------------------------------------------+
| Control Shift F12                                                     |
| Find and confirm another computer on this private network             |
| [Find nearby computers]                                               |
|                                                                       |
| Nearby computers                              Seen        Action     |
|   Nearby computer 1                           now         [Continue] |
|                                                                       |
| Discovery does not confirm who owns a computer.                      |
| [Cancel]                                                   [Refresh]  |
+-----------------------------------------------------------------------+
```

### Accessibility, focus, and motion

Both systems expose sentence-case accessible names and help text, visible
focus, predictable tab order, keyboard equivalents for map cardinal movement,
and plain error copy. Focus enters the main task, never a hidden diagnostic.
The focused local SAS confirmation control may expose its grouped code to local
assistive technology; code/suffix never appears in a title, notification,
global announcement, history, clipboard, or accessibility cache. Respect
reduced motion: only an explicit state transition may animate, for 120–180 ms.

### Anti-generic critique

No gradient, web-card grid, pill metric, all-caps eyebrow, ornamental
monospace label, or repeated soft shadow is admitted. Those patterns would
make state look like marketing telemetry and obscure the safety difference
between “nearby”, “confirmed”, “proposal”, and “saved”. The topology is the
single expressive visual because it represents measured geometry; everything
else should look like an intentional native control surface.

## Admission sequence

| Gate | Deliverable | Proof before advance | Failure result |
| --- | --- | --- | --- |
| G0 | This channel decision in boundary docs and guard | `control --stdio` remains covered; the one guarded AppKit diagnostics source is the only tracked native source; no product bundle/build artifact | Keep all unadmitted native surfaces non-shipping. |
| G1 | Rust-only `control --ui-stdio` entrypoint | Bounded frames, strict direction, stdout closure with stdin held open exits boundedly, no listener/socket/process-spawn authority | Exit/clear; no fallback. |
| G2 | AppKit and WinForms pipe owners | Per-OS cancellation/join/reap, timeout, stderr redaction, restart, main-thread handoff, no extra inherited/public handles | Failed platform remains disabled. |
| G3 | Native projection, SAS, state, permissions, recovery, diagnostics | Visual/accessibility plus stale/malformed/terminal adversarial tests on each OS | Render blocked, never optimistic success. |
| G4 | Discovery/bootstrap and V01 screens | Privacy, candidate replacement, expiry, replay, downgrade, receipt, and bilateral-local-consent proof | Return safely to catalogue. |
| G5 | Inventory/map draft and review | Measured geometry, canonical draft, cardinal validation, generation invalidation, keyboard tests | Keep proposal local and unsaved. |
| G6 | Durable layout | Separately reviewed authenticated application-session lifecycle and bilateral durable commit/recovery proof | No map-save control or saved status. |
| G7 | Sharing and release | Real target permissions, lifecycle, emergency recovery, install/uninstall, resource, and bidirectional physical QA | Input/clipboard stay local/off; preview or hold. |

## Acceptance record

Record PASS, FAIL, or NOT MEASURED for each platform independently: first
launch/lifecycle; discovery privacy; bootstrap/V01 double confirmation; SAS
clearing; current device/session/diagnostic truth; accessibility; permission
and firewall guidance; inventory/map draft; durable map save; and bidirectional
input/clipboard. A harness green result is not proof of both target systems.

## Open protocol boundaries

1. V01 terminates its sole stream and excludes application payloads. Layout
   proposal, durable save certificate, zero-CAS evidence, and acknowledgement
   require a separate authenticated application-session lifecycle before G6.
2. The bootstrap SAS/receipt transition lacks a frozen interoperability record
   in this worktree. Its code format, deadline, durable transition, and wire
   evidence must be fixed before G4 claims conformance.
3. The guided desktop flow has no manual-address fallback. If a technical flow
   remains, it must not be reachable as a fallback from the native journey.

## Non-goals

This plan does not implement AppKit, WinForms, `control --ui-stdio`, a pipe
reader, networking, pairing, layout persistence, sharing, CI, signing,
publication, or physical QA. It does not lift the non-shipping guard.
