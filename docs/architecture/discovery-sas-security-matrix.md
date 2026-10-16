# LAN discovery and same-code confirmation: security design/test matrix

Status: preparatory, docs-only design. It neither changes discovery nor adds a
wire, UI host, pairing endpoint, capability, release, or transport behavior.

This matrix translates the product requirement — both machines visibly show the
same short code and each person confirms it locally — into checks against the
existing frozen V01 and native-setup boundaries. It does not make discovery an
identity system and does not propose a replacement protocol.

## Existing boundaries used by this matrix

- The native setup specification defines nearby LAN records as untrusted and
  separates bootstrap confirmation from an operational V01 confirmation.
  It requires two explicit local decisions for a fresh, display-safe SAS.
- The V01 reference fixes a 30-second absolute deadline shared by connection,
  TLS, preflight, SAS comparison, and both local confirmations. It forbids
  downgrade, retry of the same attempt, manual code transcription, QR-only
  confirmation, and automatic confirmation.
- V01 begins only from a locally verified active durable receipt. Its selected
  live TLS connection checks the active pin; its final lease is revocable and
  has no input, clipboard, topology, inventory, or UI authority.
- The native-host boundary permits rendering a redacted projection only. A host
  does not keep locators, addresses, certificates, identity keys, SAS material,
  durable receipts, or transport authority.

Sources: [native setup UX](../native-setup-ux-specification.md),
[V01 interoperability reference](../operational-session-interoperability.md),
[native host boundary](native-host-boundary.md), and the older
[MVP specification](mvp-specification.md). The MVP is cited only to identify
the unresolved manual-address conflict; it is not used as authority for the
new guided flow.

## Security model

### Discovery is a privacy-preserving catalogue, not trust

Discovery may show only a neutral local handle, compatibility and freshness.
It must not present a device name, IP address, port, certificate, display
count, account, or identity as verified. A local selection freezes one opaque
handle and stops browsing; refresh creates a new local catalogue snapshot and
may not silently switch the selection. A stale, incompatible, missing or
policy-blocked record returns to the catalogue with a local explanation.

No advertisement can substitute for a durable receipt, a TLS leaf, an active
pin, an admission commitment, or V01 selection. A discovery failure is not a
reason to follow a manual-address, legacy pairing, alternate ALPN, QR, or
retained connection fallback within the native guided flow.

### Visible same-code confirmation

There are two deliberately non-interchangeable code stages:

1. A new relationship uses the separately reviewed bootstrap SAS. Both people
   compare the code and confirm locally before a receipt is prepared; a
   locally verified active durable receipt is still required before the
   relationship becomes confirmed.
2. An existing confirmed relationship creates a fresh V01 connection. Only the
   reviewed V01 session supplies the V01 SAS, its remaining-duration view and
   its details suffix. Each person explicitly chooses match or mismatch on
   their own device.

The UI must not derive, serialize, relay, auto-fill, copy, log, reuse or turn
one code into the other. It must not make an affirmative click on one computer
act for the other. The code clears on mismatch, cancel, candidate change,
deadline expiry, reconnect/reset, peer disappearance, endpoint loss, receipt
revoke, identity change, or permission loss. A new V01 attempt needs fresh
connection-scoped values; repaint, sleep, a dialog, discovery refresh and a
network read cannot extend its 30-second deadline.

### Ephemeral `SasDisplayView` presentation boundary

`SasDisplayView` is a deliberately narrow, current-screen-only presentation
value produced by the reviewed engine adapter for an active bootstrap or V01
attempt. It is not a wire object, a durable receipt field, or a host capability.
It may carry only the grouped human-comparison code, the current remaining-time
view, and an optional details suffix **only if needed** by the reviewed UX. It
does not carry a locator, identity, certificate, raw transcript, exporter,
receipt, approval, layout data, or any authority.

`SasDisplayView` is non-serializable, not persistible, not loggable and not
copyable. A host may hold it only while that exact confirmation screen is
visible and current; it must drop it, clear the visible control and invalidate
any view reference on every terminal state, timeout, mismatch, cancel,
candidate/attempt change, reset, disappearance, revoke, identity change or
permission loss. It must reject a request to put the view in a cache, history,
clipboard, drag payload, share sheet, notification, window title, crash report,
diagnostic/support export, tooltip, help text or analytics event. The details
suffix follows the same lifetime and must not contain the code or a locator.

Accessibility is part of the visible local screen, not a side channel. The
current focused confirmation control may expose the grouped code to the local
assistive technology that is reading that control, but the application must not
put the code or suffix in a global announcement, window title, notification,
unfocused accessibility label, or accessibility cache/history. This cannot
hide pixels or focused accessible content from a local person, screen capture,
a trusted accessibility client, or an operating-system feature permitted by the
current user. The boundary truthfully limits the product's own retention and
secondary disclosure; it does not claim a secure-screen facility that macOS or
Windows has not provided to this application.

## Design and adversarial test matrix

| Area | Required invariant | Test / mutation evidence | Required failure result |
| --- | --- | --- | --- |
| LAN privacy | Catalogue contains no verified identity or network locator | Inject friendly name, address, port, certificate, display count or receipt-like field | Redacted projection rejects it; no V01 selection |
| Discovery selection | A user selects one current compatible opaque handle locally | Replace selected handle during refresh; use stale/gone/incompatible entry | Reject transition; return to browsing without implicit substitution |
| Discovery identity conflict | Advertisement never proves a durable peer | Substitute advertisement leaf/receipt for the active store tuple | Reject before bootstrap/V01; no trust promotion |
| Bootstrap/V01 separation | Bootstrap SAS cannot satisfy V01 confirmation | Reuse bootstrap code/approval in a V01 state | Reject before `V01_PENDING -> INVENTORY_CURRENT` |
| SAS provenance | V01 code is supplied only by an active reviewed V01 attempt | Feed code without matching live lease/attempt/transcript | Reject; clear volatile values |
| SAS display boundary | `SasDisplayView` is current-only and cannot become host history | Attempt serialize/persist/log/copy/cache; inject it into title, notification, diagnostics, analytics, tooltip, accessibility cache/history or a stale screen | Reject/suppress; clear the display at the next terminal state or timeout |
| Both-screen visibility | Each display renders the same grouped code from its own V01 session | Mutate one code group, reorder groups, or present an old code | Local mismatch/cancel; no receipt, inventory or capability advance |
| Double local confirmation | Each side needs its own explicit approval | Deliver remote approve before local approve; duplicate/replay approval | Remote fact alone cannot advance; duplicate rejects/fences |
| Deadline | One monotonic deadline is <= 30 seconds | Change to 31 seconds; per-read timer; confirm at deadline; pause/repaint | Terminal cancel, clear SAS/approvals; fresh attempt required |
| Replay | Attempt, transcript and confirmation bind one selected TLS connection | Replay old confirmation/SAS after reconnect or new candidate | Reject before confirmation or preview; no fallback |
| Downgrade | Exact `csf12-operational/1`, wire v1 and receipt v2 only | Offer pairing ALPN, version 0/2, manual address or legacy command | Terminal reject; no retry/downgrade |
| Durable trust scope | Only an active local receipt/pin enables V01 selection | Missing, prepared-only, revoked, rotated, or epoch-mismatched receipt | Purge scope/return to catalogue; no reuse of layout or capability |
| Permission loss | Permission is not trust | Revoke local OS permission while receipt remains active | Capability off; retain receipt; never auto-reenable |
| Recovery | Ambiguous remote state is never inferred as success | Timeout, reset, endpoint loss, crash or acknowledgement loss | Clear volatile V01 state; later layout work remains fenced per its own contract |
| Host boundary | Host is projection-only | Place raw SAS/locator/certificate/receipt in host request or cache | Reject at typed boundary; no host transport authority |

## Durable trust and recovery scope

The persisted relationship is limited to the separately reviewed receipt/pin
life cycle. Discovery entries, bootstrap attempts, V01 attempts, SAS values,
TLS/exporter values, local approvals and raw locators are volatile. A receipt
or identity revoke performs a peer-scoped purge and returns the user to the
untrusted catalogue; it does not revive a previous code, session, inventory,
layout, or sharing capability. Permission revocation is different: it turns a
local capability off while preserving a valid receipt, and it cannot be
automatically re-enabled.

## Explicit layout boundary

This matrix intentionally does **not** use the closed V01 boundary for a
post-confirm layout exchange. The current V01 reference explicitly excludes
application payloads and terminates the one allowed stream after its six
records. A layout proposal, commit certificate, zero-CAS evidence or map-save
acknowledgement therefore needs a separately frozen and reviewed authenticated
application-session lifecycle before it can be implemented. Until that choice
exists, a successful visible same-code confirmation may prove only the V01
session defined by the reference; it cannot imply layout saved, cursor crossing,
input, clipboard or sharing readiness.

## Real ambiguities / decisions required before implementation

1. The existing legacy MVP documentation allows a manual-address fallback when
   discovery is unavailable, while the later native guided-setup specification
   forbids such fallback for a cancelled bootstrap. Product/protocol ownership
   must decide whether manual address remains a separate non-guided product
   flow, or is removed entirely. This matrix does not choose one.
2. The V01 reference explicitly excludes application payloads and closes its
   only stream. A future layout or post-confirm application layer must define
   its own authenticated transport lifecycle, key/lease material exposure and
   recovery semantics; this document does not invent it.
3. The reviewed bootstrap SAS contract is referenced by the native setup
   specification but is not present as a frozen interoperability document in
   this worktree. Its exact word/code alphabet, expiry and durable receipt
   transition require that authoritative contract before implementation tests
   can claim conformance.

## Completion evidence for a future implementation

Before any product flow is enabled, tests must mutate actual framed/canonical
inputs and typed state — not only prose or UI labels — for every row above.
Required later evidence includes independent protocol review, platform host
accessibility checks, and physical two-machine verification that both displays
show the same code and that each local confirmation is independently required.
