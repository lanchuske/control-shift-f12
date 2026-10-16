# Operational-session interoperability reference V01

**Status:** frozen, test-only protocol reference. It is not runtime code, an
admission capability, release approval, or permission to enable Control Shift
F12. A separately written parser and an independent security/protocol review
are required before any implementation consumes this document or its fixture.

This reference starts **after** a peer has a durable, locally verified
admission receipt. It defines a fresh, mutually confirmed QUIC/TLS session
binding for that receipt. It explicitly excludes **input, clipboard, topology**,
display inventory, UI placement, and application payloads. A successful V01
session therefore authorizes none of those things.

## Preflight and boundaries

The current pairing transport uses `csf12-pair/2`. This reference uses the new
ALPN `csf12-operational/1`, not `csf12-pair/2`. It is not wire-compatible with
the pairing or provisional transport channels. A peer that does not negotiate
this exact ASCII ALPN must fail the attempt; it must not retry with
`csf12-pair/2`, a legacy ALPN, a different spelling/case, or a lower version.
No downgrade is permitted.

The only cryptographic primitives used here are the project precedents already
used in the frozen pairing references: TLS 1.3 with mutual Ed25519 identity
certificates, SHA-256, HKDF-SHA256 and HMAC-SHA256, plus the established
`CSF12E01` canonical TLV encoding. This document introduces new domain
separation strings and values, but no new primitive. Any implementation that
cannot obtain an exporter from the selected TLS connection, the actual leaf DER
from that connection, or the listed durable tuple must reject the attempt.

The test oracle is
`crates/transport/tests/fixtures/pairing-v2/operational-session-v01.json`,
checked by `scripts/test-operational-session-reference.py`. The fixture contains
synthetic public identities and deterministic test entropy only; it is never a
source of product keys or authority.

## Transport profile

Each V01 attempt creates a fresh QUIC connection with TLS 1.3 and mutual
certificate authentication. The implementation MUST use the project’s strict
Ed25519 certificate profile, take each peer leaf DER from the selected live
connection, and compare `SHA256(actual DER)` to the expected durable peer
fingerprint before any record is processed.

The negotiated ALPN MUST be exactly `csf12-operational/1`. TLS 0-RTT is
forbidden. TLS resumption and session tickets are forbidden. An implementation
must not send or accept application bytes before full TLS authentication and
ALPN verification; a resumed or 0-RTT connection is a terminal rejection even
if its certificates otherwise match.

Exactly one client-initiated bidirectional QUIC stream carries the V01 records.
No unordered streams, unidirectional streams, additional bidirectional streams,
or application datagrams are permitted. The initiator is role A: it is the lower
lexicographic 32-byte SHA-256 leaf fingerprint. Equal fingerprints are invalid.
QUIC client/server direction is not a role claim.

The opening stream, TLS handshake, each awaited record, and each user-confirmed
step share one absolute monotonic deadline of **30 seconds** from connection
selection. No per-read timeout can extend it. Every record payload is nonempty
and at most 4,096 bytes; a receiver allocates only after checking the declared
length. At most four records and 16,384 payload bytes are accepted per attempt.

## Durable authority tuple

Before opening V01 the local store must load the exact active pin and admission
receipt that it owns. The canonical `operational-authority-tuple-v1` has the
following ordered, mandatory fields. Integers are unsigned 64-bit big-endian;
digests are exactly 32 bytes.

| Tag | Field | Source and rejection rule |
|---:|---|---|
| 1 | `peer_fingerprint_sha256` | Active durable pin; equals the actual remote leaf hash. |
| 2 | `suite` | Durable receipt suite; exact ASCII `x25519-hkdf-sha256-ed25519-v1`. |
| 3 | `protocol_version` | Durable receipt protocol version; exact `1`. |
| 4 | `policy_revision` | Store policy revision, equal to the receipt. |
| 5 | `identity_generation` | Store identity generation, equal to the receipt. |
| 6 | `revocation_generation` | Store generation, equal to receipt and active-pin record. |
| 7 | `receipt_revision` | Durable receipt revision, equal to the stored receipt. |
| 8 | `admission_attempt_sha256` | Exact 32-byte admission attempt identifier. |

The tuple is accepted only if the pin is active, all eight fields equal the
current stored record, and no revocation guard is active. A missing record,
CAS/revision mismatch, tombstone, pending revocation, receipt duplication,
identity rotation, policy change, or storage failure is terminal. The local
connection ID and local connection generation are never sent, never compared
across peers and never substitute for a durable field.

## Canonical record and exporter encoding

All payloads use the established canonical TLV bytes:

`CSF12E01 | kind_len:u8 | kind:ASCII | field_count:u16be | fields...`

Each field is `tag:u16be | value_type:u8 | length:u32be | value`, with tags in
strictly increasing order, exactly the declared field set, no duplicate,
unknown, omitted or trailing field. Type `1` is one unsigned u64 exactly eight
bytes, type `2` bytes and type `3` UTF-8/ASCII where stated. All digest fields
are bytes32; all nonces are bytes32; the session ID is bytes16.

The exporter output is exactly 32 bytes from the selected TLS connection:

```text
label   = "EXPORTER-ControlShiftF12-OperationalSession-v1"
context = CanonicalTLV("operational-session-exporter-context-v1", [
  1: exact ASCII ALPN,
  2: role-A actual leaf SHA-256,
  3: role-B actual leaf SHA-256,
  4: SHA-256(exact operational-authority-tuple-v1 bytes),
  5: nonce-A bytes32,
  6: nonce-B bytes32,
  7: exact eight wire-magic bytes,
  8: wire-version u64,
])
```

The role leaf hashes are ordered A then B, not network client/server order. The
label, context, output length, nonces, leaf hashes, tuple hash, magic and
version are all mandatory. A local precomputed exporter, an exporter from a
different connection, or an exporter generated before TLS authentication is
invalid.

The confirmation key is derived only after the exporter is obtained:

```text
context_hash = SHA256(context)
prk          = HMAC-SHA256(key=context_hash, data=exporter_output)
K_confirm    = HMAC-SHA256(key=prk,
                 data="CSF12 operational session confirm key v1\\0" ||
                      context_hash || 0x01)
```

This is the one-block HKDF-SHA256 Extract/Expand form used for this fixed
32-byte key. The exporter output, `prk`, `K_confirm`, nonces and HMACs are
secrets: they must be zeroized on terminal state and never persisted or logged.

## Wire records, transcript and mutual confirmation

Every stream record is exactly:

`magic:8 | version:u16be | type:u8 | direction:u8 | sequence:u32be | length:u32be | payload`

The magic bytes are `CSF12S1\0`, version is `1`, direction `1` is A→B and `2`
is B→A. The header is 20 bytes. A wrong magic, version, type, direction,
sequence, length, partial frame presented as complete, trailing bytes or payload
over 4,096 bytes is terminal before state changes.

The exact schedule is `Open A→B`, `Accept B→A`, `Confirm A→B`, `Confirm B→A`,
with sequences 0, 1, 2 and 3. A sender half-closes only after its Confirm;
success requires both verifies and both FINs. The payload schemas are:

| Type | Kind | Exact fields in tag order |
|---:|---|---|
| 1 | `operational-session-open-v1` | attempt(1 bytes32), role(2 ASCII `A`), session_id(3 bytes16), nonce_a(4 bytes32), tuple_hash(5 bytes32), context_hash(6 bytes32) |
| 2 | `operational-session-accept-v1` | attempt(1 bytes32), role(2 ASCII `B`), session_id(3 bytes16), nonce_b(4 bytes32), open_hash(5 bytes32), tuple_hash(6 bytes32), context_hash(7 bytes32) |
| 3 | `operational-session-confirm-v1` | attempt(1 bytes32), role(2 ASCII `A`/`B`), session_id(3 bytes16), prior_record_hash(4 bytes32), confirmation(5 bytes32) |

`open_hash` is SHA-256 of the exact Open payload. Confirm A’s
`prior_record_hash` is SHA-256 of the exact Accept payload. Confirm B’s is
SHA-256 of the exact Confirm-A payload. Each confirmation is:

```text
HMAC-SHA256(K_confirm,
  "CSF12 operational session confirm v1\\0" || role || attempt || session_id ||
  prior_record_hash)
```

The transcript is SHA-256 of this exact byte sequence: domain
`CSF12-operational-session-transcript-v1\0`; u16be ALPN length; ALPN ASCII
bytes; u32be authority tuple byte length; exact authority tuple bytes; u32be
record count (=4); then, in schedule order, u32be record length followed by
each exact complete record. It is for display and future audit only; it creates
no input, clipboard or topology capability.

Both sides must show the same transcript-derived short code and obtain explicit
local confirmation for the current attempt, current transcript and current
durable tuple before sending their Confirm. This reference does not define UI
rendering or code-word mapping; an implementation must use the already reviewed
SAS presentation contract, and fail closed if it cannot bind the user gesture to
all three values. There is no default approval, QR, manual code transcription,
or automatic confirmation.

## Terminal behavior, revocation and reconnect

Type `4` is reserved. A future authenticated `Close` record needs its own
versioned fixture and exact reason schema. Until that addendum is frozen, V01
implementers MUST treat type `4` and every other unknown type as protocol
errors, including after bilateral confirmation.

Every malformed, reordered, duplicate, replayed, unauthenticated, stale,
timed-out, transport-extra or early-FIN input must trigger `RESET_STREAM` and
`STOP_SENDING` with application error `0x43534612`, discard in-memory secrets
and leave the active durable pin unchanged. A local decline is a normal terminal
abort that sends no operational payload; it does not retry or downgrade.

Revocation, identity generation change, policy revision change, receipt change,
endpoint drop or connection close invalidate an active V01 attempt immediately.
No reconnection resumes an attempt, reuses a session ID, nonce, exporter,
transcript, confirmation or TLS ticket. Reconnect starts a new TLS connection,
fresh nonces/session ID and a fresh four-record V01 flow after reloading and
comparing the entire durable tuple. A stale or revoked durable tuple requires
fresh pairing, not a recovery path.

## Negative cases and implementation gate

The fixture names these mandatory negative mutations:
`alpn-downgrade`, `wire-version-downgrade`, `magic-substitution`,
`type-substitution`, `direction-substitution`, `sequence-replay`,
`payload-trailing`, `payload-oversize`, `tuple-revision-substitution`,
`tuple-revocation-substitution`, `observed-leaf-substitution`,
`exporter-label-substitution`, `exporter-context-substitution`,
`exporter-cross-connection-substitution`, `nonce-substitution`,
`open-hash-substitution`, `confirm-mac-substitution`, `one-sided-confirm`,
`early-fin`, `extra-stream`, `zero-rtt`, `resumption-ticket`,
`reconnect-reuse`, and `post-revocation-reconnect`.

Each must fail closed in a future independently written parser. The static
fixture verifier proves only that frozen bytes and declared mutations stay
internally consistent. It does not prove TLS exporter behavior, QUIC semantics,
storage atomicity, native UI behavior, network policy, hardware key security,
or Mac–Windows interoperability. Independent security/protocol review is a
hard gate before implementation; production enablement additionally requires
native macOS/Windows and physical LAN evidence.
