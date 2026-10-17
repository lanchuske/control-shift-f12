# Product pairing admission adapter

## Status and purpose

This document is the product-facing boundary that was deliberately absent from
the discovery and provisional-transport slices.  It specifies the sole engine
owner that may turn an explicit local pairing gesture into a durable pairing-v2
admission.  It does **not** grant input, clipboard, screen-layout, update, or
runtime-session authority.

The adapter is internal to the Rust engine.  AppKit and WinForms receive only
redacted projections and return fixed local gestures over their inherited local
IPC pipes.  They never receive discovery addresses, certificates, rendezvous
tokens, pending records, a QUIC connection, or a durable-store capability.

## Owner and prerequisites

`ProductPairingAdapter` is created once by the engine process with:

1. one explicit local discovery-consent lease;
2. one `AdmissionAuthorityStore` rooted in the platform-private product state;
3. one engine-owned local device identity and certificate/key source;
4. one bounded provisional-listener lease; and
5. the private pairing-v2 endpoint and replay owner.

The adapter rejects construction if any prerequisite is unavailable.  It has no
fallback to the legacy CLI pairing path, no caller-supplied endpoint/config,
and no mutable global trust/pin API.

### Discovery publication and listener lease

The existing `GuidedMdns` type is browse-only.  Product pairing therefore also
needs a separate engine-owned `PairingAdvertisementLease`, not a UI-owned mDNS
publisher.  The lease starts only after the user explicitly opens the pairing
screen and before discovery is shown.  It binds one `ProvisionalEndpoint` on a
bounded local port, publishes only the currently valid rendezvous identifier,
protocol version and a pairable bit, and withdraws publication before dropping
the endpoint.

The advertisement contains no friendly name, certificate, durable-peer data,
SAS, device capability, layout, or active-session claim.  Its listener accepts
only the strict pairing-v2 channel; it cannot hand a raw connection to input,
clipboard, runtime-session or legacy-pairing code.  The lease expires and
withdraws on every pairing-window close, timeout, cancellation, endpoint fault
or completed attempt.  Browsing must not start a listener and advertising must
not select or trust another device.

## Pairing state machine

Only the following transition sequence is allowed.  Any error, timeout,
window close, discovery removal, local rejection, remote rejection, TLS
violation, or durable-store failure closes the provisional channel, cancels the
pending attempt when one exists, clears the native projection, and returns to
`browsing` or `closed` with a redacted reason.

```text
browsing
  -> selected-untrusted
  -> provisional-channel
  -> sas-awaiting-local-confirmation
  -> sas-awaiting-remote-confirmation
  -> durable-admission-committing
  -> admitted-metadata-only
```

Selection is made solely with a current `ConsentCatalog` handle.  The adapter
looks up its corresponding locator privately, verifies its still-current
version/rendezvous/address bounds, then consumes it.  A locator is never an
identity, an authentication result, or a durable peer.

The provisional endpoint may attempt only the selected locator's bounded
address set and the frozen pairing-v2 ALPN/schedule.  The selected connection
must create a pairing-v2 `VerificationPrompt`.  Its exact four words, attempt
binding and transcript generation become a single redacted `ui_pairing_v1`
projection.  The candidate display handle is opaque and scoped to this local
adapter generation.

Each device independently emits exactly one local decision for the current
attempt/transcript/generation.  A decision is invalid if it is stale,
duplicated, mismatched, expired, or is not from the currently displayed local
projection.  `matches: false` is terminal.  A valid local affirmative decision
does not admit anything; it merely permits the protocol's reciprocal
confirmation schedule to continue.

Only a live `HandshakeCompletePendingAuthority` produced by the selected
channel after both protocol confirmations can cross into
`AdmissionAuthorityStore::commit_sealed_foundation`.  The move-only authority
and store compare current pending/revocation state again at the commit
boundary.  No raw completion evidence is serialised, cached, or surfaced to
the desktop hosts.

## Redacted IPC contract

The typed pairing IPC schema is frozen ahead of its engine owner. In the
current `UiStdioAdapter`, valid `ui.select_candidate` and `ui.approve_sas`
requests return `ui_response_v1` with `ok: false` and `error: "invalid_state"`.
They do not change the snapshot, select a candidate, start a listener, approve
an attempt, or create an admission. The discovery commands retain only their
existing local browsing-state transitions. Tasks admitting the discovery
lease and pairing owner must separately wire any effect.

`PairingFrame` is a validated, child-to-host value type. No current adapter
path emits it. Once a reviewed owner supplies the current prompt, its only
admitted shape is the fixed schema below. Fields not listed are rejected.

```json
{
  "v": 1,
  "kind": "ui_pairing_v1",
  "generation": 1,
  "phase": "awaiting_local_confirmation",
  "candidate_handle": "opaque-local-handle",
  "verification_words": ["four", "lowercase", "words", "only"]
}
```

The complete host command allowlist and exact argument objects are:

```text
ui.refresh          {}
ui.start_discovery  {}
ui.stop_discovery   {}
ui.select_candidate { handle: string }
ui.approve_sas      { generation: unsigned integer, matches: boolean }
ui.confirm_v01      { matches: boolean }
```

Every argument must be an object with exactly the listed keys. Handles are
1–64 ASCII bytes containing only letters, digits, hyphen or underscore;
generation is a nonzero `u64`. Nested objects/arrays in typed scalar fields,
unknown keys at any depth (including address, identity, certificate, SAS,
capability and layout material), incorrect types and out-of-range values
return `invalid_request` without echoing their contents. An unknown command
returns `invalid_command`. V01 remains a distinct local comparison command;
its arguments cannot contain a pairing generation or code.

The pairing frame has exactly `v`, `kind`, `generation`, `phase`,
`candidate_handle` and `verification_words`. Version is exactly 1, kind is
exactly `ui_pairing_v1`, generation is nonzero, and the sole admitted phase is
`awaiting_local_confirmation`. Its handle follows the same opaque bounds;
words are exactly four nonempty lowercase ASCII strings, each at most 16
bytes. These are display validation rules, not verification of a current
protocol prompt, deadline, dictionary or transcript. The engine owner must
establish those facts before emission; a host cannot manufacture them.

The ordinary `ui_snapshot_v1` envelope remains exactly `{ v, kind, snapshot }`.
Its snapshot contains only `schema_version`, `generation`, `state`,
`diagnostics`, `candidates`, `confirmed`, `inventory`, `layout` and
`capabilities` using the existing redacted types. No bootstrap words or V01
code is included. `ui_response_v1` contains exactly `{ v, kind, id, ok }` on
success and additionally `error` on rejection; it never echoes arguments.
Existing `ui_diagnostics_v1` and transient `sas_display_v1` V01 frames remain
unchanged and are not pairing frames.

Requests retain the existing bounded request-id replay semantics: an identical
request replays its deterministic result, a different request with the same
id returns `request_id_conflict`, and the 256-entry replay limit still applies.
No arbitrary command dispatch exists. Native hosts keep sharing and layout
controls disabled until their separate runtime gates are admitted; even a
current durable relationship is not authority to enable them.

## Post-admission boundary

A successful admission exposes only a redacted durable relationship identity
and its current revision.  It does not start a data session or make any
capability active.  Mouse/keyboard, clipboard, layout synchronization,
automatic-update policy and connection telemetry each require their own
authenticated runtime contract and current-session proof.  No discovery state,
old receipt, or successful test fixture may be presented as such proof.

## Mandatory verification before implementation is enabled

The implementation must retain tests proving:

- discovery selection cannot reveal or alter an address, identity, certificate
  or durable record through desktop IPC;
- stale/removed/expired handles, duplicate decisions and one-sided approval do
  not create a pending or durable admission;
- rejection, timeout, malformed/extra protocol input, endpoint loss and every
  durable-write boundary fail closed and clear the projection;
- a successful durable commit requires the same live sealed authority, current
  transcript and current revocation generation on each side;
- Windows and macOS hosts reject projections with extra fields or sensitive
  data, and leave sharing controls disabled before a separate runtime gate;
- real Mac-to-Windows and Windows-to-Mac QA records pairing, rejection,
  re-open, recovery and resource cleanup as PASS/FAIL/NOT MEASURED.

An independent security review of the implemented delta is required before the
feature is enabled in an unsigned candidate.  Signing, publishing and
deployment remain outside this document and require Darío's explicit approval.
