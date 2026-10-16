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
4. **Ready** exists only after a reviewed durable prepare/commit transaction
   has durably resolved the proposal as committed on both peers.

The V01 reference is authoritative for the session binding, lease promotion,
revocation, exact ALPN and no-downgrade behavior:
[operational-session-interoperability.md](operational-session-interoperability.md).
It expressly excludes UI, display inventory, topology and input. This UX must
consume a future reviewed implementation of that contract; it must not invent
an alternative socket, exporter, retry, pairing fallback, or capability path.

Until the final commit is acknowledged by both peers, all input remains local,
clipboard sharing remains off, and no cursor edge is active.

### Two distinct bootstrap paths

A LAN candidate is not a durable peer. There are therefore two intentionally
separate journeys:

1. **New relationship.** A person selects an untrusted LAN locator and enters
   the separately reviewed *durable pairing bootstrap*. Its typed states are
   `BOOTSTRAP_CONNECTING`, `BOOTSTRAP_SAS_PENDING`,
   `BOOTSTRAP_RECEIPT_PREPARED`, and terminal `BOOTSTRAP_ABORTED`. Its own
   fresh bootstrap SAS is shown and explicitly confirmed on both peers before
   either peer prepares a receipt. That SAS has its own bootstrap attempt and
   deadline; it is neither displayed as nor convertible into the V01 SAS.
   After mutual confirmation, each peer durably verifies its own prepared
   receipt, including its local identity/pin/revision binding, before entering
   `CONFIRMED_RELATIONSHIP`. A peer with a missing, prepared-only, unverifiable
   or revoked receipt remains outside that state. The pairing bootstrap has no
   input, clipboard, topology or operational V01 capability. A discovery result
   never becomes a V01 candidate merely because its display name, address or
   bootstrap SAS looked right.
2. **Existing relationship.** Only a locally verified, active durable receipt
   can appear in the “confirmed computers” list. Selecting that receipt starts
   a fresh V01 connection with its pinned leaves. The UI treats that gesture as
   **V01 connection selection** and begins the single V01 deadline below.

The two flows may share native components and visual language, but their
attempts, short codes, confirmations and cancellation state are never reused
or translated. In particular, a bootstrap pairing confirmation cannot satisfy
an operational-session confirmation. A cancelled, rejected, expired or failed
bootstrap is terminal for that locator: it returns to the untrusted catalogue,
destroys its bootstrap attempt and cannot fall back to a manual address,
legacy pairing or a retained candidate connection. A revoked durable receipt
returns to the catalogue and requires the reviewed bootstrap again.

### V01 deadline shown honestly

The previous example countdown is replaced by the V01 absolute monotonic
deadline: **at most 30 seconds from V01 connection selection**. There is one
deadline shared by connection creation, TLS, preflight, SAS comparison and the
two user-confirmation gestures. A UI refresh, network read, dialog pause or
repaint cannot extend it. Both surfaces receive only the remaining duration
from their own current V01 session state; they show “Less than a minute
remaining” until it is 10 seconds or less, then a terse seconds countdown. The
exact displayed second is advisory, never a clock-synchronization claim.

At expiry, both local state machines terminally cancel: they clear the SAS and
all confirmation affordances, discard the volatile attempt/session/nonces and
return to the last safe screen. An implementation must not use the old
`01:43`-style visual timer, keep waiting for the other person, or reconnect to
extend the same attempt. A fresh attempt requires a new V01 connection and
fresh V01 values as required by the reference.

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
| `candidate_selected` | “Secure this confirmed computer” | “Continue” | map save, remote control |
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
renders the same human-comparable short code, the remaining V01 deadline and
an attempt identifier suffix in details. The SAS is supplied by the reviewed
session contract; this document neither derives nor serializes it. Both people
must compare it visually and choose an explicit local decision. Pressing
Continue on one device cannot act for the other.

```
┌ Check the code on both computers ─────────────────────────────────────┐
│                                                                         │
│          42 71 68                                                      │
│                                                                         │
│ Does this match the code on the other computer?                         │
│ Finish this check before the secure connection expires.                 │
│                                                                         │
│ [It does not match]                         [This code matches]        │
│                                                                         │
│ Details ▸  Attempt ending 3F7A · connection is not active yet          │
└───────────────────────────────────────────────────────────────────────┘
```

The code is deliberately short, grouped for verbal comparison and large enough
to read at distance; its exact alphabet/length comes from security review.
Never replace this with a QR-only flow. A code mismatch, V01 deadline expiry,
candidate change, TLS/session reset, cancellation, suspend/reconnect, or
revocation clears the code and both local confirmations. The next attempt
starts from the confirmed durable relationship (or, if no receipt exists, the
nearby catalogue); there is no resume, code reuse or downgrade to legacy
pairing.

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

### Frozen layout proposal contract (design input, not an enabled wire)

The future application-payload addendum must use the following exact logical
schema before the UI is implemented. It is a canonical `CSF12E01` TLV object
named `control-shift-f12-layout-proposal-v1`; tags are ascending and unique,
integers are unsigned big-endian, decimal coordinates are forbidden, and its
SHA-256 digest is the `proposal_digest`. No currently shipped component may
emit or accept it. This schema adds no cryptographic primitive: it is carried
only by the separately reviewed application layer *after* V01 mutual confirm.

| Tag | Field | Bound / source / rejection rule |
| ---: | --- | --- |
| 1 | `schema_version` | `u64`, exactly `1`; no fallback or negotiation. |
| 2 | `v01_attempt` | exactly 32 volatile bytes from this live V01 attempt; never persisted, logged, displayed or put in discovery. |
| 3 | `preconfirm_transcript_hash` | exactly 32 bytes from this same V01 preconfirm transcript. |
| 4 | `authority_commitment_hash` | exactly 32 bytes from this same V01 bilateral durable commitment. |
| 5 | `role_a_leaf_hash` | exactly 32 bytes; must match live V01 role A. |
| 6 | `role_b_leaf_hash` | exactly 32 bytes; must match live V01 role B. |
| 7 | `base_layout_revision` | nonzero `u64`, loaded only after reviewed recovery establishes the last mutually resolved committed record. |
| 8 | `proposed_layout_revision` | `base + 1`; any other value rejects. |
| 9 | `inventory_a` | one canonical `layout-inventory-v1` object, at most 32 displays. |
| 10 | `inventory_b` | one canonical `layout-inventory-v1` object, at most 32 displays. |
| 11 | `placements` | one canonical array of 1–64 `layout-placement-v1` objects, sorted by display reference. |

Each `layout-inventory-v1` has: owner leaf hash (tag 1, bytes32), inventory
generation (tag 2, nonzero `u64`), descriptor array (tag 3, 1–32 entries) and
the exact pre-measured inventory digest (tag 4, bytes32). A descriptor has a
scoped display reference `(owner leaf hash, inventory generation, runtime
index)` — never a global display ID — plus logical bounds in fixed-point
1/1024 units, scale numerator/denominator (each 1–16, denominator nonzero),
rotation in `{0,90,180,270}` or explicit `unknown`, physical-size quality enum,
and only the optional fields that the measurement source actually supplied.
Each dimension is positive and at most 100,000 logical units; coordinates are
within ±1,000,000; unknown physical size/DPI/mirror state is encoded as
`unavailable`, not a made-up value. The receiver rejects noncanonical ordering,
duplicate runtime indexes within an inventory, unknown tags, fractional values,
or a digest that is not an exact hash of the canonical descriptor sequence.

Each `layout-placement-v1` is `(scoped display reference, x, y, width, height,
rotation)`. It must correspond once and only once to the inventory descriptors,
restate their measured size/rotation, stay within the geometry bounds, have no
overlap, and touch at least one other display on a cardinal edge. The UI may
show alignment offsets, but cannot rewrite measured size or rotation to make a
proposal valid. Presentation labels and device names are never part of the
canonical object or digest.

Both peers independently recompute `proposal_digest = SHA-256(exact canonical
proposal bytes)`. The later application-layer confirmation binds the full
tuple `(v01_attempt, preconfirm_transcript_hash, authority_commitment_hash,
proposal_digest, base_layout_revision, proposed_layout_revision,
inventory_a.generation, inventory_b.generation)`. A proposal with values from
different V01 attempts, different authority commitments, or any stale inventory
generation is rejected before a preview or persistence write. This makes the
two maps the same proposal rather than two similar-looking local drawings.

Persisted committed layout records retain only `schema_version`,
`proposal_digest`, `proposed_layout_revision`, both inventory
digests/generations and placements. They never retain `v01_attempt`, SAS,
nonces, exporter data or confirmation material. Their durable update is **not**
described as an impossible cross-machine atomic write. It uses the reviewed
prepare/commit/abort transaction below.

### Durable layout transaction, certificate and crash recovery

The future layout authority implementation has four idempotent operations,
all scoped by `(role-A leaf, role-B leaf, proposal_digest, base_layout_revision,
proposed_layout_revision)` and guarded by the active V01 session binding. It
does **not** call a pair of independent writes “atomic.” No `CommitLayout` CAS
is allowed before both sides verify and durably persist the same bilateral
**commit certificate**.

#### Commit certificate V1

`control-shift-f12-layout-commit-certificate-v1` is a canonical, immutable
`CSF12E01` TLV object. It is created only after both peers have locally approved
the same proposal and each has prepared that exact digest. Its ordered fields
are:

| Tag | Field | Exact requirement |
| ---: | --- | --- |
| 1 | `certificate_version` | `u64` exactly `1` |
| 2 | `proposal_digest` | bytes32 of the exact canonical proposal |
| 3 | `role_a_leaf_hash` | bytes32, matches active V01 role A |
| 4 | `role_b_leaf_hash` | bytes32, matches active V01 role B |
| 5 | `receipt_epoch_a` | nonzero `u64`, current active durable receipt epoch for A |
| 6 | `receipt_epoch_b` | nonzero `u64`, current active durable receipt epoch for B |
| 7 | `v01_attempt` | bytes32 of this still-active V01 attempt; volatile, never exported to UI/logs/backups |
| 8 | `preconfirm_transcript_hash` | bytes32 from this V01 attempt |
| 9 | `authority_commitment_hash` | bytes32 from this V01 attempt |
| 10 | `base_layout_revision` | nonzero `u64` |
| 11 | `proposed_layout_revision` | exactly `base + 1` |
| 12 | `inventory_generation_a` | nonzero `u64`, exact proposal inventory A generation |
| 13 | `inventory_generation_b` | nonzero `u64`, exact proposal inventory B generation |
| 14 | `signature_algorithm` | ASCII exactly `ed25519` |
| 15 | `approval_a_signature` | exactly 64-byte Ed25519 signature by role A |
| 16 | `approval_b_signature` | exactly 64-byte Ed25519 signature by role B |

The **unsigned certificate bytes** are the exact canonical object containing
tags 1–14 only. Let `M` be the ASCII domain separator
`CSF12 layout commit certificate v1\0` concatenated with those unsigned bytes.
`approval_a_signature` is Ed25519 verification over `M` with the live role-A
leaf public key; `approval_b_signature` is the same verification with the live
role-B leaf public key. The leaf hashes, roles, signature algorithm and both
signatures are all inside the certificate, so a role swap, a signature copied
from another certificate, or a signature using the wrong leaf rejects. Ed25519
and the strict leaf profile are existing project precedents; no new primitive is
introduced. The verification keys are obtained from the authenticated V01
connection and checked against the active receipt pins before persistence.

There is deliberately **no cross-host `expires_at_monotonic_ms` field**. A
monotonic clock is local and cannot make a meaningful durable distributed
expiry. The certificate is valid only while its receipt epochs are active and
equal to current local receipt records, both inventory generations remain
current, the final V01 lease is active, the V01
attempt/transcript/commitment bindings match, and both Ed25519 approvals verify.
These guards are checked atomically with local state immediately before **both**
prepare and commit CAS operations. Revocation, identity/receipt epoch change,
inventory generation change or V01 terminal state fences the certificate,
purges its prepared record, and makes commit impossible.

1. `PrepareLayout` validates the proposal and all certificate preconditions,
   writes an immutable local **prepared** record containing the certificate
   digest, and persists the verified certificate. Repeating the same valid
   prepare returns that record; a different proposal/certificate for the same
   base revision rejects.
2. `CommitLayout` re-runs every certificate guard in the same local durable
   transaction as its CAS from base to proposed revision. It accepts only the
   exact persisted valid certificate and marks the matching prepared record
   committed. Repetition is idempotent only for the exact digest/revision.
3. `AbortLayout` is legal only while neither local store has committed that
   certificate. It marks the exact uncommitted prepared record aborted and
   removes its placement payload. It cannot roll back a committed layout.
4. `RecoverLayout` loads local records and a certificate digest only. It never
   infers approval from a prepared record. V01 is terminal after a crash or
   restart, so recovery cannot use the old certificate to complete a remote
   commit. If no local commit occurred, it may purge/abort the local prepared
   record. If a local CAS occurred, it remains fenced and reports
   `LAYOUT_RECOVERY_PENDING`; a new explicitly specified protocol with fresh
   authentication, fresh bilateral approvals and per-peer local deadlines is
   required before any later resolution.

The sender and receiver each prepare locally first. Only then may the reviewed
post-V01 application contract exchange prepared acknowledgements and create the
certificate. Both certificate copies are verified/persisted before either CAS.
If a crash happens after prepare on either side, or after the first peer commits
but before the other responds, the user-facing state is **“Layout saving was
interrupted”**, never `LAYOUT_COMMITTED`. The local UI is read-only for that
proposal and does not enable sharing.

After any unilateral CAS, recovery is conservatively fenced. It cannot finish
the old certificate because that V01 attempt is terminal; it cannot create a
newer proposal revision, reuse the revision, reinterpret prepared as approval,
or abort a side that has already committed. A reconnect always loads the latest
receipts, layout revisions and fence state, creates a new V01 attempt and never
carries SAS/approval/certificate authority into it. A future resolution protocol
must define fresh authentication, two new local approvals, per-peer local
deadlines and how it proves/repairs the old revision without weakening the
fence. A prepared record and certificate are internal recovery artifacts, not
layout data a user can edit, export or restore from a shared backup.

## Screen 5: bilateral preview and durable resolution

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

Acceptance is durable only when the reviewed prepare/commit transaction resolves
the exact digest as committed on both sides. A local prepare, one-sided commit,
or local success without remote resolution is “Layout saving was interrupted,”
not “Layout saved.” On rejection, timeout, peer reset, revocation, generation
mismatch, CAS/revision conflict or write failure, both surfaces discard the
editable proposal and keep the last committed layout. Retry returns to a fresh
inventory snapshot; it never applies a stale proposal.

`Layout saved` does not activate cursor crossing. A distinct capability gate,
outside this document, must verify the final operational lease and user
permission before it enables input. The UI therefore separates “Layout saved”
from any future “Start sharing” control and keeps that control unavailable
unless the runtime reports a separately admitted, live capability.

### Cancellation, revocation and reconnect state machine

The implementation shall expose the following state machine as a single local
source of truth. Remote bytes may report a terminal event, but cannot create a
new local approval or advance a state without the local V01/session checks.

```text
UNTRUSTED_CATALOGUE
  -- local select --> BOOTSTRAP_CONNECTING
  -- local cancel/expiry --> UNTRUSTED_CATALOGUE

BOOTSTRAP_CONNECTING
  -- fresh bootstrap SAS --> BOOTSTRAP_SAS_PENDING
  -- cancel/failure/expiry --> UNTRUSTED_CATALOGUE

BOOTSTRAP_SAS_PENDING
  -- two explicit bootstrap approvals --> BOOTSTRAP_RECEIPT_PREPARED
  -- decline/failure/revoke --> UNTRUSTED_CATALOGUE

BOOTSTRAP_RECEIPT_PREPARED
  -- locally verified durable receipt --> CONFIRMED_RELATIONSHIP
  -- missing/invalid/revoked receipt --> UNTRUSTED_CATALOGUE

CONFIRMED_RELATIONSHIP
  -- local V01 connection selection --> V01_PENDING (deadline <= 30s)
  -- receipt/identity revoke or epoch change --> PURGE_TO_UNTRUSTED

PURGE_TO_UNTRUSTED
  -- peer-scoped receipt/layout/inventory purge complete --> UNTRUSTED_CATALOGUE

V01_PENDING
  -- mutual V01 confirm --> INVENTORY_CURRENT
  -- permission revoke --> CONFIRMED_RELATIONSHIP (capability remains off)
  -- receipt/identity revoke --> PURGE_TO_UNTRUSTED
  -- lease expiry/timeout/reset/disappear --> CONFIRMED_RELATIONSHIP

INVENTORY_CURRENT
  -- local edit --> PROPOSAL_LOCAL
  -- permission revoke --> CONFIRMED_RELATIONSHIP (capability remains off)
  -- receipt/identity revoke --> PURGE_TO_UNTRUSTED
  -- inventory generation change / lease expiry / reset --> CONFIRMED_RELATIONSHIP

PROPOSAL_LOCAL / PROPOSAL_REMOTE_REVIEW
  -- both valid approvals --> LAYOUT_PREPARE_PENDING
  -- cancel/reject/timeout/reset/disappear/revoke --> INVENTORY_CURRENT

LAYOUT_PREPARE_PENDING
  -- exact immutable prepares on both peers --> LAYOUT_COMMIT_PENDING
  -- cancel/reject before CAS --> purge prepared, then INVENTORY_CURRENT
  -- permission revoke / lease expiry / inventory change before CAS --> purge prepared, then CONFIRMED_RELATIONSHIP
  -- receipt/identity revoke before CAS --> purge prepared and peer scope, then UNTRUSTED_CATALOGUE
  -- remote revoke/identity/inventory race at CAS --> fence, capability off, LAYOUT_RECOVERY_PENDING

LAYOUT_COMMIT_PENDING
  -- exact durable resolution on both peers --> LAYOUT_COMMITTED
  -- crash/acknowledgement loss / remote TOCTOU revoke --> fence, capability off, LAYOUT_RECOVERY_PENDING
  -- abort only before any commit --> INVENTORY_CURRENT

LAYOUT_RECOVERY_PENDING
  -- no local CAS --> purge local prepared/certificate, then CONFIRMED_RELATIONSHIP
  -- local CAS / missing or fenced certificate --> remain fenced, capability off
  -- new recovery protocol with fresh authentication + both approvals --> outside this specification

LAYOUT_COMMITTED
  -- permission revoke --> CONFIRMED_RELATIONSHIP (capability off; layout retained)
  -- inventory/lease expiry --> CONFIRMED_RELATIONSHIP
  -- receipt/identity revoke --> purge peer scope, then UNTRUSTED_CATALOGUE
  -- separate capability gate only --> outside this specification
```

`V01_PENDING` is terminal for its volatile values: every timeout, local Cancel,
SAS mismatch, stream reset, peer disappearance or endpoint loss clears the
attempt, session ID, nonces, preconfirm hash, confirmation choices and unsaved
proposal. A **permission revoke** is local capability loss: it returns to the
confirmed relationship and keeps remote control off, but does not erase a valid
receipt. A **receipt/identity revoke** is trust loss: it triggers the peer-scoped
purge and returns to `UNTRUSTED_CATALOGUE`. The UI must not show “Try again” as
if it retained a confirmation; its action creates a fresh V01 connection from
`CONFIRMED_RELATIONSHIP`.

Every V01 preflight failure takes this same route: clear volatile V01 state,
retain the last locally verified durable receipt without changing it, and return
to `CONFIRMED_RELATIONSHIP`. The only exception is a receipt/pin/revocation or
identity failure, which first purges that relationship and returns to
`UNTRUSTED_CATALOGUE`. The UI never chooses a different candidate, legacy
address, alternative ALPN or bootstrap shortcut as a preflight retry.

`PROPOSAL_LOCAL` and `PROPOSAL_REMOTE_REVIEW` hold no durable approval. A
close-window event is Cancel. A remote Cancel/Reject is terminal for that
proposal but preserves the last committed layout. If a peer disappears before
prepare, the visible result is “The other computer is unavailable; this layout
was not saved,” and the local editable draft is discarded rather than queued.
Before CAS, timeout, lease expiry, inventory change or local cancellation purges
the prepared certificate and returns to the safe state shown above. A remote
revocation is inherently TOCTOU: it can race the final local CAS even after the
last guard check. Therefore any post-prepare uncertainty, including a remote
revocation report, is `LAYOUT_RECOVERY_PENDING`, remote control stays off, and
the prior layout cannot be presented as newly ready. A reconnect starts a fresh
V01 attempt from `CONFIRMED_RELATIONSHIP`, but a fenced prior certificate stays
fenced; the fresh attempt cannot reuse its revision or approvals.

## Error and recovery matrix

| Condition | User-facing result | Recovery | Security rule |
| --- | --- | --- | --- |
| No LAN candidates | Empty catalogue | Refresh or cancel | no direct fallback is offered implicitly |
| Candidate disappears | “That computer is no longer nearby” | Back to catalogue | selected handle is revoked |
| Code differs/expired | “Do not continue” | Start a fresh attempt | discard both approvals and SAS |
| Session preflight fails | “Could not secure this connection” | Return to the confirmed relationship; start a fresh V01 attempt | no candidate switch, address/legacy/ALPN fallback |
| Inventory incomplete | quality-specific explanation | retry measurement or cancel | do not invent orientation/size |
| Inventory changes before CAS | “Displays changed” | purge prepared record; read new inventory | reject proposal |
| Inventory/receipt change racing CAS | “Layout saving was interrupted” | fence, keep capability off | never report newly ready |
| Layout conflict | “A newer layout was saved” | refresh and review | CAS/revision failure wins |
| Remote rejects/cancels | “The other computer did not accept this layout” | keep current layout | no partial local commit |
| Permission revoked | “Sharing is stopped” | follow OS permission guidance | release local control; retain valid receipt/layout; no automatic re-enable |
| Receipt or identity revoked | “This computer is no longer confirmed” | peer-scope purge then catalogue | never retain/revive layout or trust |

## Data minimization, retention and deletion

Discovery locators, bootstrap attempts, V01 attempts, SAS values, TLS/exporter
material, confirmation choices and uncommitted placement drafts are volatile.
They must be zeroized or dropped at their terminal transition and never enter
logs, diagnostics, crash reports, analytics, shared backups, clipboard or
support exports. A diagnostic report may say `layout: pending` or
`layout: committed revision 8`, but never include a peer address, SAS, attempt,
display geometry, layout digest or raw identity material.

A committed layout is correlatable data: its relative geometry, paired leaf
scope, inventory generations/digests and display descriptors can describe a
person's equipment. It is stored only in the current user’s protected local
application storage, encrypted at rest when the platform secure-storage
boundary supports it, with owner-only filesystem permissions otherwise. It is
never copied to shared configuration, cloud sync, roaming profiles, generic
backups, installer logs or diagnostics by this feature. Any platform that
cannot meet those storage conditions keeps arrangement disabled rather than
falling back to a public/local-text file.

The interface provides **Forget this computer and its layout**. It explains that
the action removes the local durable receipt, committed/prepared layouts,
inventory cache, local names and retained diagnostics for that peer; it is a
local action and asks for confirmation. The underlying deletion order is:

1. revoke/disable capability and terminally cancel active V01/bootstrap work;
2. remove prepared and committed layout records plus inventory cache for the
   scoped leaf pair;
3. delete the durable receipt/pin according to its reviewed receipt lifecycle;
4. clear UI/diagnostic caches and schedule secure-storage deletion; and
5. show “Forgotten on this computer” without asserting deletion on the remote
   computer.

Receipt revocation, unpair, identity rotation/change and policy-required
identity removal invoke the same purge for every matching peer scope before a
new relationship can be displayed. A failed deletion is a blocked local
privacy state: discovery may remain visible, but the prior relationship and
layout cannot be used or resurrected. A future backup/restore feature requires
its own encrypted, per-user, consented design; it is not implied here.

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

## Documentary mutation matrix

Before implementation, a future static contract verifier and its fixtures must
exercise these mutations against canonical bytes and state transitions. This is
a required design test matrix, not a claim that runtime tests exist today.

| Mutation | Required result / stage |
| --- | --- |
| LAN advertisement substitutes a durable receipt or leaf | rejected in `UNTRUSTED_CATALOGUE`, before V01 selection |
| Bootstrap receipt missing/invalid after two bootstrap approvals | rejected in `BOOTSTRAP_RECEIPT_PREPARED`; cannot enter `CONFIRMED_RELATIONSHIP` |
| Bootstrap confirmation reused as operational confirmation | rejected before `V01_PENDING` can reach `INVENTORY_CURRENT` |
| Bootstrap cancellation retried through legacy/manual address | terminal bootstrap failure; return to `UNTRUSTED_CATALOGUE` |
| V01 deadline altered to 31 seconds or a per-read timer | rejected at schedule validation; both sides cancel at deadline |
| Old SAS/attempt/preconfirm hash substituted after reconnect | rejected before user confirmation or layout preview |
| Layout schema version `0`/`2`, unknown tag or unsorted tag | canonical decode rejects before digest |
| Mixed A inventory from one attempt and B inventory from another | binding tuple rejects before preview |
| Runtime display index reused with another owner/generation | scoped-reference validation rejects before preview |
| Descriptor size/rotation changed after its inventory digest | inventory digest mismatch rejects before preview |
| Placement overlaps, omits a display, duplicates one, or loses cardinal touch | geometry validation rejects before approval |
| Base revision stale or proposed revision not `base + 1` | CAS/revision validation rejects before durable write |
| Missing/mismatched certificate, wrong signature/role, one approval, receipt epoch or V01 binding | rejected before persistence and again atomically before each CAS |
| Certificate inventory generation/revocation/V01 lease terminal after prepare | certificate fenced, prepared payload purged, CAS rejected |
| Crash/restart after prepare A/B or between commit write 1 and write 2 | old V01 is terminal; no completion from certificate; post-CAS state remains fenced/capability-off |
| One-sided acceptance, remote cancellation or acknowledgement loss | neither UI reports saved; no partial success |
| Revocation, endpoint drop or inventory generation change during commit | pre-CAS purge or post-CAS fence; capability off, no replay on reconnect |
| Revoke/unpair/identity change leaves layout/inventory cache or diagnostic copy | deletion check fails closed; relationship remains unusable |

The static verifier must mutate the actual canonical proposal bytes and framed
state fixture, recompute framing where necessary, and assert the named stage.
Text-only grep or a generic early assertion is not evidence that a specific
layout check executes.

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
7. the documentary mutation matrix above implemented as executable, independently
   maintained fixture tests before the application protocol or UI is enabled.

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
