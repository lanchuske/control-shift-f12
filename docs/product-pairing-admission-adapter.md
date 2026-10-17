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

The adapter emits only the fixed schema below.  Fields not listed are rejected
by both engine and native hosts.

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

The only pairing requests accepted from a native host are:

```text
ui.select_candidate { handle }
ui.approve_sas     { generation, matches }
```

They have bounded typed fields, normal request-id replay semantics, and no
arbitrary command dispatch.  Native hosts disable every sharing and layout
control until a later, separately bounded relationship projection says a
durable admission is current.

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
