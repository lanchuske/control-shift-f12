# Native setup UX specification — Control Shift F12

**Status:** proposed product and interaction specification. It is not an
implementation plan, wire protocol, release approval, or evidence that either
native application exists. The implementation remains blocked until the
operational-session V01 reference and its independent security review admit a
real session.

This document describes the first-run setup experience on macOS AppKit and
Windows WinForms. Its job is deliberately modest: help a person find a nearby
machine, compare the same short code on both screens, describe displays
accurately, and jointly save a screen arrangement. It must never imply that a
LAN announcement is an identity claim or that arranging displays permits
remote input.

## Product boundary

The setup flow has four independently gated layers:

1. **Nearby** is an untrusted, consent-scoped LAN locator catalogue.
2. **Confirm** is a mutually visible short-authentication-string (SAS) and two
   local user decisions, bound to the candidate connection.
3. **Arrange** is a proposal preview, not a saved topology.
4. **Ready** exists only after the two peers have atomically committed the
   proposal through an admitted operational session.

The V01 reference is authoritative for the session binding, lease promotion,
revocation, exact ALPN and no-downgrade behavior:
[operational-session-interoperability.md](operational-session-interoperability.md).
It expressly excludes UI, display inventory, topology and input. This UX must
consume a future reviewed implementation of that contract; it must not invent
an alternative socket, exporter, retry, pairing fallback, or capability path.

Until the final commit is acknowledged by both peers, all input remains local,
clipboard sharing remains off, and no cursor edge is active.

## Native visual system

The visual character is a **calm equipment panel**, not a web dashboard. The
display map is the memorable element: real monitor rectangles on a quiet field
with a single, precise connection thread between the two computers. Controls
remain conventional and native.

| Token | macOS AppKit | Windows WinForms | Purpose |
| --- | --- | --- | --- |
| Window surface | `windowBackgroundColor` | `SystemColors.Window` | Standard host surface; no custom gradient. |
| Canvas | `underPageBackgroundColor` | `ControlLightLight` | Neutral field behind display geometry. |
| Ready | system green | `Color.ForestGreen` | A completed local, verified condition only. |
| Attention | system orange | `Color.DarkOrange` | A pending human confirmation or retryable interruption. |
| Blocked | system red | `Color.Firebrick` | A condition that stops the flow. |
| Selection | control accent color | user accent / `Highlight` | Keyboard and pointer selection. |

Use the platform system font at the normal application size: SF Pro/San
Francisco on macOS and Segoe UI on Windows. Title text is one step larger and
semibold; status and explanation use normal weight; protocol facts use a
selectable monospaced field only in the details disclosure. Do not make a
monospaced diagnostic report the primary interface. Labels use sentence case.

The window is a single-column flow: a stable header with current state, one
main task surface, and a persistent lower action row. Width is 680–760 logical
points/pixels, with a compact layout below 560. The display map owns the extra
height; a list or error never overlays it. Respect system reduced-motion: the
only motion is a 120–180 ms state transition after an explicit action.

Every action is keyboard reachable, exposes a native accessible name and help
text, and has a visible focus ring. AppKit uses `NSOutlineView`/`NSTableView`,
`NSButton`, `NSView` canvas and native sheets. WinForms uses `DataGridView` or
`ListView`, `Button`, standard error provider/status strip and a custom
double-buffered `Control` only for the monitor canvas. Neither platform gets a
browser view, hidden terminal, custom credential prompt, nor an elevation flow.

## State model and language

The application renders a local state snapshot. Remote network text cannot
select a state, set a button label, or render as a trusted device name.

| State | Header | Primary action | What remains disabled |
| --- | --- | --- | --- |
| `not_started` | “Set up another computer” | “Find nearby computers” | confirmation, map save, remote control |
| `browsing` | “Looking nearby” | “Stop looking” | confirmation, map save, remote control |
| `candidate_selected` | “Check the code on both computers” | “Continue” | map save, remote control |
| `sas_pending` | “Confirm the same code” | “This code matches” | map save, remote control |
| `session_preflight` | “Securing this connection” | none, Cancel remains | map save, remote control |
| `inventory_pending` | “Reading displays” | “Try again” when safe | map edit/save, remote control |
| `arranging` | “Arrange the screens” | “Send layout for review” | remote control |
| `proposal_waiting` | “Waiting for confirmation on the other computer” | “Cancel proposal” | map editing/save, remote control |
| `proposal_review` | “Review the same layout” | “Accept layout” / “Reject layout” | remote control |
| `commit_pending` | “Saving on both computers” | none, Cancel if contract allows | remote control |
| `ready_local_only` | “Layout saved” | “Start sharing” only after a separate input gate | none implied by this document |
| `blocked` | specific failure title | safe recovery action | all capability actions |

Use direct, stable copy. For example: “The code changed. Compare the new code
on both computers before continuing.” Never say a peer is *trusted*, *paired*,
or *ready* merely because it appeared on the LAN or a code was generated.

## Screen 1: nearby catalogue

Opening discovery is an explicit local gesture and starts a bounded consent
window. The list is a catalogue of **untrusted nearby signals**, not a device
directory. It can show a neutral local handle (for example “Nearby computer
1”), protocol compatibility, freshness (“seen just now” / “no longer nearby”),
and a network reachability result only after a reviewed session attempt. It
must not show a friendly name, address, certificate, display count, or identity
as if discovery authenticated it.

```
┌ Control Shift F12 ────────────────────────────────────────────────────┐
│ Set up another computer                                                │
│ Find and confirm a computer on this private network.                   │
│                                                                         │
│ Nearby computers                                        [Stop looking] │
│ ┌───────────────────────────────────────────────────────────────────┐ │
│ │ ○  Nearby computer 1                         Seen just now   [›] │ │
│ │ ○  Nearby computer 2                         Needs update    [›] │ │
│ │   No other compatible computers found.                           │ │
│ └───────────────────────────────────────────────────────────────────┘ │
│ Discovery does not confirm who owns a computer.                         │
│                                                                         │
│ [Cancel]                                                     [Refresh] │
└───────────────────────────────────────────────────────────────────────┘
```

Selecting an item freezes its local handle and stops browsing before any
candidate session begins. A stale, expired, incompatible or removed item goes
back to the catalogue with an explanation. Refresh uses a new local snapshot;
it never silently switches to a different candidate. Empty state: “No
compatible computers are visible. Check that both are on the same private
network, then try again.” A policy/firewall problem is shown as an OS/network
condition with a link to platform help; it is never bypassed or auto-elevated.

## Screen 2: same code, two confirmations

After the reviewed operational session reaches its SAS stage, each application
renders the same human-comparable short code, its expiration and an attempt
identifier suffix in details. The SAS is supplied by the reviewed session
contract; this document neither derives nor serializes it. Both people must
compare it visually and choose an explicit local decision. Pressing Continue
on one device cannot act for the other.

```
┌ Check the code on both computers ─────────────────────────────────────┐
│                                                                         │
│          42 71 68                                                      │
│                                                                         │
│ Does this match the code on the other computer?                         │
│ This code expires in 01:43.                                            │
│                                                                         │
│ [It does not match]                         [This code matches]        │
│                                                                         │
│ Details ▸  Attempt ending 3F7A · connection is not active yet          │
└───────────────────────────────────────────────────────────────────────┘
```

The code is deliberately short, grouped for verbal comparison and large enough
to read at distance; its exact alphabet/length comes from security review.
Never replace this with a QR-only flow. A code mismatch, expiry, candidate
change, TLS/session reset, cancellation, suspend/reconnect, or revocation
clears the code and both local confirmations. The next attempt starts at the
nearby catalogue; there is no resume, code reuse or downgrade to legacy pairing.

## Screen 3: display inventory with quality, not invented certainty

Once the operational session admits inventory exchange, each machine measures
its own displays and identifies the provenance of every value. The UI presents
logical size and scale by default; a details disclosure may show framebuffer
pixels, orientation, effective DPI and physical millimetres only when the
platform returned them. Unknown is shown as “Not reported by this computer,”
not guessed from resolution.

```
┌ Arrange the screens ──────────────────────────────────────────────────┐
│ MacBook Pro · 1 display                         Windows · 2 displays  │
│ ┌─────────────────────┐                         ┌──────────┬────────┐ │
│ │ Built-in display     │                         │ Display 1│Display2│ │
│ │ 1512 × 982 logical   │                         │1920×1080 │2560×1440│ │
│ │ 2× scale · landscape │                         │100%      │125%    │ │
│ └─────────────────────┘                         └──────────┴────────┘ │
│ Data quality: geometry measured · physical size not reported           │
│                                                                         │
│ [Show details]                                        [Try again]       │
└───────────────────────────────────────────────────────────────────────┘
```

Inventory refresh creates a new local generation. If either generation changes
while arranging, the proposal is invalidated and the map returns to read-only
with “Displays changed. Review the new layout.” No display identity is assumed
stable solely from a runtime index. Mirror groups, rotation and physical-size
quality are displayed only when present in the reviewed inventory schema.

## Screen 4: proportional shared map

The map puts every display on a common logical-coordinate canvas. Rectangles
are proportional to measured logical width and height; their captions retain
the scale and orientation. A checkerboard is prohibited: it implies equal-size
screens and hides the data quality distinction. The selected display gets the
native selection color plus a 2-pixel outline; other displays use quiet neutral
fills and owner captions.

```
┌ Arrange the screens ──────────────────────────────────────────────────┐
│ Drag a display beside another. Edges must touch; displays cannot overlap.│
│                                                                         │
│          Mac                                                          │
│       ┌───────────────┐                                               │
│       │ Built-in      │                                               │
│       │ 1512 × 982 ·2×│                                               │
│       └───────────────┘                                               │
│                       ┌──────────────────────┬────────────┐           │
│                       │ Windows display 1    │ display 2  │           │
│                       │ 1920 × 1080 · 100%   │2560×1440   │           │
│                       └──────────────────────┴────────────┘           │
│                                                                         │
│ Layout revision 7 · both inventories current                           │
│ [Reset layout]                               [Send layout for review] │
└───────────────────────────────────────────────────────────────────────┘
```

Dragging snaps only to valid cardinal edges. During drag, an accessible live
region says “Windows display 1 to the right of Built-in display” and keyboard
controls offer Move left/right/up/down plus a numeric alignment offset. The
map provides magnification and pan when its bounds do not fit. It never
silently rescales an edge crossing to make an invalid arrangement valid.

The initiating UI creates a canonical proposal containing only reviewed,
bounded inventory references, geometry, orientation/scale interpretation and
the base layout revision. It is then sent **through the admitted operational
session**, not discovery or pairing. The sender locks the map read-only while
waiting; any inventory or session change rejects it.

## Screen 5: bilateral preview and atomic commit

The other computer sees the same proportional geometry and canonical revision,
but not a trusted claim about who arranged it. Both sides label the proposal as
pending until the secure session reports the same proposal digest and both
explicit approvals exist.

```
┌ Review layout from the other computer ─────────────────────────────────┐
│ The same arrangement is shown on both computers.                        │
│                                                                         │
│        [ proportional display map, read only ]                          │
│                                                                         │
│ Revision 7 → proposed revision 8                                       │
│ Your displays are current · other computer confirmed its inventory      │
│                                                                         │
│ [Reject layout]                                        [Accept layout] │
└───────────────────────────────────────────────────────────────────────┘
```

Acceptance is durable only when the session's reviewed atomic commit reports
success to both sides. A local success without remote acknowledgement is
“Saving interrupted,” not “Layout saved.” On rejection, timeout, peer reset,
revocation, generation mismatch, CAS/revision conflict or write failure, both
surfaces discard the proposal and keep the last committed layout. Retry returns
to a fresh inventory snapshot; it never applies a stale proposal.

`Layout saved` does not activate cursor crossing. A distinct capability gate,
outside this document, must verify the final operational lease and user
permission before it enables input. The UI therefore separates “Layout saved”
from any future “Start sharing” control and keeps that control unavailable
unless the runtime reports a separately admitted, live capability.

## Error and recovery matrix

| Condition | User-facing result | Recovery | Security rule |
| --- | --- | --- | --- |
| No LAN candidates | Empty catalogue | Refresh or cancel | no direct fallback is offered implicitly |
| Candidate disappears | “That computer is no longer nearby” | Back to catalogue | selected handle is revoked |
| Code differs/expired | “Do not continue” | Start a fresh attempt | discard both approvals and SAS |
| Session preflight fails | “Could not secure this connection” | Back to catalogue | no legacy/retry ALPN fallback |
| Inventory incomplete | quality-specific explanation | retry measurement or cancel | do not invent orientation/size |
| Inventory changes | “Displays changed” | read new inventory | reject proposal |
| Layout conflict | “A newer layout was saved” | refresh and review | CAS/revision failure wins |
| Remote rejects/cancels | “The other computer did not accept this layout” | keep current layout | no partial local commit |
| Permission revoked | “Sharing is stopped” | follow OS permission guidance | release local control; no automatic re-enable |

## Accessibility and platform behavior

- AppKit: use VoiceOver labels for each monitor with owner, display number,
  logical dimensions, scale, orientation and relation. The canvas has a full
  keyboard equivalent; drag is never the only arrangement mechanism.
- WinForms: expose monitor controls through UI Automation with the same data,
  use `AccessibleName`/`AccessibleDescription`, high-contrast system colors,
  200% DPI layout and no text drawn only into an inaccessible bitmap.
- Both: actionable errors receive focus once; passive status changes do not
  steal focus. Copyable details redact network addresses and raw identity data.
- Both: cancellation is always available while there is no irreversible commit.
  Closing the window is a cancel, clears volatile SAS/proposal state and leaves
  all capabilities off.

## Acceptance evidence required before release

This specification is not test evidence. A future implementation must add and
pass:

1. deterministic state-model tests for each state/error/revocation transition;
2. native accessibility and keyboard tests on AppKit and WinForms;
3. protocol integration tests proving untrusted discovery cannot bypass V01,
   SAS cancellation invalidates both sides, and stale inventory/proposals cannot
   commit;
4. geometry tests for unequal scale, portrait rotation, mirror/unknown values,
   multi-display arrangements, conflicts and reconnect;
5. physical Mac↔Windows QA showing the same SAS, mutual layout preview and
   commit, with input still disabled until its independent gate; and
6. visual review at normal, high-contrast and 200% scaling states.

No check may call a green discovery test, a rendered map, or a local saved file
proof that remote control is safe or enabled.

## Design self-review

The tempting generic treatment would be a dark dashboard full of symmetrical
status cards. This specification instead makes the user's actual spatial task —
the proportional display map — the visual center, while retaining AppKit and
WinForms conventions for every decision and error. Color is semantic rather
than branding decoration, and the only prominent number is the SAS that needs
human comparison. That keeps security state legible without turning protocol
details into the product interface.
