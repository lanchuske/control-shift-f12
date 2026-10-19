# Product V01 session owner

## Decision

A confirmed G4 relationship is durable pairing metadata, not a live sharing
capability. The next product increment is a sealed V01 owner that proves a
fresh mutually authenticated operational session and obtains two independent
local approvals. It must still leave inventory, layout, input, and clipboard
disabled.

This increment is required before the application-session, layout, and sharing
protocols can be designed. It must not reuse the bootstrap connection or treat
the durable receipt alone as a live session.

## Blocking fact in the current implementation

`RealG4Backend` currently creates its pairing endpoint with
`ProvisionalEndpoint::bind_ephemeral`. The durable admission therefore pins a
certificate whose private key disappears when the pairing endpoint is dropped.
That receipt cannot authenticate a later V01 connection. Enabling the existing
UI capability flags would be both incorrect and insecure.

The product owner must instead create one persistent, owner-only G4 identity
before opening either pairing or V01. The transport crate owns the private key.
The app crate may receive only opaque endpoint/session handles and redacted
events.

## Scope

This increment provides:

1. a persistent G4 identity stored below the existing private product-state
   root, with fail-closed ACL and reparse/symlink validation;
2. pairing endpoints and V01 endpoints derived from that same identity;
3. a separate, bounded operational advertisement containing only a random
   locator, protocol version, and port;
4. selection of one current operational locator for one confirmed opaque
   relationship;
5. the frozen `csf12-operational/1` six-record exchange;
6. one transient V01 code on each local screen and one local decision per side;
7. a redacted terminal result: verified for the current live attempt, rejected,
   expired, revoked, or remote outcome unknown.

It does not provide inventory exchange, layout proposal/save, input injection,
clipboard transfer, background reconnect, or a general-purpose authenticated
stream. A successful V01 connection closes after the frozen transcript and
returns to `confirmed_relationship`; the UI reports that sharing is still
unavailable.

## Authority and privacy boundaries

- The native host can request `ui.v01.begin` with one current opaque
  relationship handle and can answer the already typed `ui.confirm_v01`
  prompt. It cannot provide an address, port, certificate, pin, attempt,
  transcript, code, deadline, or capability.
- The engine maps the opaque relationship to one current durable admission and
  one current operational locator. Neither mapping crosses the pipe.
- The transport crate owns the certificate and private key. No public method
  returns private key bytes.
- A V01 prompt is emitted only from a live `OperationalAttempt` after strict
  TLS, pin, durable snapshot, preflight lease, and transcript validation.
- Local approval is single-use and bound to the exact preconfirm transcript and
  commitment. Replays, duplicate decisions, stale generations, and decisions
  after the absolute deadline fail closed.
- Restart never resumes a volatile V01 attempt. A durable receipt may authorize
  a fresh attempt only after fresh locator selection and a new local gesture.
- Any identity load, ACL, discovery, endpoint, store, parser, consent, timeout,
  or shutdown error leaves every operational capability disabled.

## Product state

The persistent identity lives at `g4-identity/identity-v1.json` below the state
root used by `RealG4Backend`. Its certificate fingerprint must equal the local
fingerprint committed into every new G4 durable admission. Existing admissions
created with an ephemeral identity are incompatible and remain metadata-only;
they are never silently migrated. The UI requires forgetting and re-pairing
such a relationship.

The stored JSON contains a schema version, the DER certificate, and the
platform-protected PKCS#8 private key. Creation uses an atomic replace in an
owner-only directory. On Windows, inherited broad ACEs are rejected or reduced
only on this identity directory; ACLs outside the state root are never changed.
On macOS, symlinks and non-owner access bits are rejected.

## Discovery

Operational discovery is distinct from pairing discovery. Its service type and
TXT schema are versioned separately and contain only:

- a fresh 16-byte random locator encoded as lowercase hex;
- `v=1`;
- the OS-assigned UDP port.

It contains no relationship handle, certificate fingerprint, device name,
display information, receipt revision, or sharing claim. The browser keeps a
bounded, expiring catalogue. The engine attempts candidates privately and
accepts only the endpoint whose live certificate pin and authority view match
the selected durable admission. A forged or stale advertisement cannot select
another durable peer.

## UI states

`ui.v01.begin` is accepted only from `confirmed_relationship`. While the V01
owner connects and validates preflight, the snapshot remains capability-off.
When the owner reaches local consent, the existing child-only `sas_display_v1`
frame carries the current code and remaining duration. The ordinary snapshot
never contains the code.

After both local approvals and the terminal V01 transcript, the owner emits a
redacted `V01Verified` event. This event proves only that the frozen V01 attempt
completed. It does not set `CapabilityView` fields and does not transition to
`inventory_current`, because the V01 wire explicitly carries no inventory.

## Acceptance criteria

- Two isolated processes can pair using one persistent identity per side,
  restart, discover an operational endpoint, display the same V01 code, require
  two independent approvals, and complete V01.
- The certificate fingerprint used by V01 equals the fingerprint in the
  selected durable admission on each side.
- One-sided approval, mismatch, timeout, duplicate decision, stale locator,
  wrong pin, wrong receipt revision, identity replacement, extra QUIC stream,
  malformed record, process restart, or endpoint loss cannot emit
  `V01Verified` or enable a capability.
- The native projection contains no locator, address, port, certificate, pin,
  attempt, transcript, commitment, key, or durable record.
- Existing ephemeral-identity relationships stay unavailable and explain that
  re-pairing is required.
- All targeted Rust tests pass on macOS ARM, macOS Intel, and Windows. Physical
  Mac-to-Windows and Windows-to-Mac verification remains a separate approved QA
  window.

## Explicitly deferred protocols

The next three increments require their own frozen documents and reviews:

1. authenticated application-session lifecycle plus bounded inventory exchange;
2. bilateral durable layout commit and recovery;
3. runtime sharing capability, input/clipboard data plane, emergency release,
   and reconnect semantics.

No implementation may bridge these gaps by keeping the closed V01 stream,
exporting its connection, or interpreting V01 success as sharing readiness.
