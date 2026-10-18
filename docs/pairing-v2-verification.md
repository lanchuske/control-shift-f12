# Pairing v2: isolated verification slice

Internal review input only. **Not full phase-2 completion and not release GO.**
Base foundations: `983c174dec8d988f9f694b0098a86c6495f02240`.
Design SHA-256: `f790167ddfb2f295e1a3c2c129d6f48e46bd58bc10c984e5f41bb190e7b0fa07`.
Independent reference: `03d6148fc68969099ada11c3d7c3bd6e99514ce2`, with reviewed
interoperability addendum `f991802da3aaec74b61afcf7bd9ed7d9dac06e3c`.

## Isolation

All new modules are behind the opt-in `pairing-v2-experimental` feature, disabled
by default and not enabled by the application. They import no network, identity
store, pending store, input/clipboard runtime or native UI. There is no signer,
issuer, connection opener, persistence/promotion operation or operational
pairing coordinator here. `PendingStore::promote` remains unconditionally denied.
Existing control pairing commands still return `not_available_in_foundations`.

Verification success means the supplied evidence satisfies the specific
function's checks. It does **not** prove local human approval, selected-candidate
freshness, a completed live handshake, durable local finalization, recovery
eligibility, peer liveness, an active pin, or permission to share input.

## Implemented contracts

- Bounded canonical TLV encoding/decoding with exact field count, tags, order,
  types and consumption; no unknown/duplicate/trailing fields. Frame cap 16 KiB.
- Ed25519 certificate profile using maintained X.509, ASN.1, curve and signature
  libraries: bounded complete DER, canonical header roundtrip, v3 self-issued
  leaf, matching Ed25519 inner/outer/SPKI algorithms with absent parameters,
  exact key/signature sizes, self-signature, validity, duplicate/malformed and
  unsupported critical extension rejection, unknown-extension rejection even
  when noncritical, mandatory non-CA/basic-constraints, mandatory KeyUsage with
  digitalSignature set and keyCertSign/crlSign clear, mandatory product URI SAN.
  Other parser-recognized noncritical extensions remain permitted; this is not
  a three-OID allowlist. Presence requires `basic && usage && san` independently.
  Keys and signature
  points must be canonical, non-small-order and torsion-free. Certificate DER
  fingerprint and its 16-byte NodeId prefix are checked separately.
- The parser initially accepted a nonminimal DER length. A real failing test
  caught it; canonical library-encoded headers are now compared recursively,
  including constructed context tags and extension payloads. This is not a
  substitute for a complete adversarial DER corpus/fuzz audit.
- CandidateHello addendum-1 decoder, 4 KiB cap, exact byte lengths and types,
  NFC/control-safe name, OS enum, bounded unique sorted suite-vector grammar,
  expiration field bound. Connection binding checks exact encoded candidate
  hash, full claimed/TLS fingerprint, ASCII connection grammar and generation.
  Rust types prevent boolean/negative/non-integer generations. This is a pure
  binding check, not an actual TLS observation or a freshness registry.
- Detached recomputation of C, attempt ID, commitments and T from the V01
  messages; X25519 low-order/all-zero rejection; specified SHA-256 HKDF and
  independent confirmation keys; key-proof signatures/MACs; exact four-word
  44-bit MSB-first SAS mapping with checksum-pinned English asset. Secret key
  containers use `Zeroizing` and do not implement Debug or serialize.
- Signed approvals, live MAC checks, P, legal finalization phase/role pairs,
  complete seven-record FC verification and locally recomputed FC hash. Every
  protocol/suite/wordlist/attempt/T/role-map/full-fingerprint binding is checked.
  The supplied expected context is not an authenticated-candidate capability.
  `live: None` explicitly checks durable signed evidence only, not live MACs.
- Addendum V11 RecoveryProof codec uses raw bytes32 attempt/FC hashes, not text.
  JSON conversion accepts only exactly 64 lowercase hex characters. Signature
  checks bind role, both nonces, exporter, generations and durable-state marker;
  the expected-challenge verifier expires at `now >= deadline`, rejects a
  tombstone and consumes the context through an injected shared registry after
  successful signature verification. See the registry contract below; it is
  process-local, not a durable/global operational registry.

### Recovery replay registry contract (round 2)

`RecoverySignatureVerifier::new(fields, deadline, Arc<RecoveryReplayRegistry>)`
requires registry injection: constructing a verifier never implicitly constructs
or resets a registry. All verifiers in one verification scope must share the
same Arc. The registry uses a mutex-protected set; signature verification occurs
before the atomic check-and-insert. Invalid signatures, malformed evidence,
expiration and a caller-supplied tombstone do not consume entries. Concurrent
valid proofs for the same context have exactly one successful caller.

The key is an exact pair `(Ed25519 signer public key, canonical RecoveryProof
body bytes)`, not a partial attempt ID, an ambiguous concatenation, or signature
bytes. The canonical body includes domain, attempt ID, FC hash, role, both
nonces, TLS exporter, identity generation, revocation generation and the durable
state marker. Deadline is intentionally not part of the key: recreating a
verifier with a later deadline cannot reopen the consumed context. All original
reference wire bytes and signature encodings are unchanged.

The registry retains up to 1024 consumed entries without eviction, cleanup or
reset APIs. Capacity exhaustion and mutex poisoning fail closed. This is only
an internal shared-memory verification facility. Separate registries/processes
and process restart do **not** share consumption. A scope owner must not create
a new registry to reopen a challenge or bypass capacity. Durable, globally
consistent consumption plus authoritative generation/revocation tombstones and
crash/restart reconciliation are mandatory **before operational use or release**.
The supplied clock, key, challenge and tombstone boolean remain expected inputs,
not proof of actual transport provenance or authoritative persisted state.

## Fixture migration and provenance

Nine JSON files in `crates/transport/tests/fixtures/pairing-v2` are byte-identical
to the named files at reference commit `f991802...`, checked with immutable Git
object reads. Tests consume JSON directly; they do not execute Python reference
code as an oracle. The checked-in wordlist has SHA-256
`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`.
All certificate/key/nonce values in tests are synthetic and never loaded into
product identity stores.

V01's candidate hashes remain synthetic placeholders. The detached transcript
function can reproduce them for interoperability, but they are **not** accepted
as evidence of the separate CandidateHello binding. No live transcript builder
connects these two APIs. V11's old textual `attempt`/`fc` form was deliberately
replaced, not accepted through a compatibility branch. The current fixture still
has short synthetic nonce/exporter values; fixed 256-bit challenge generation
and TLS exporter acquisition belong to the future operational coordinator.

Implemented fixture coverage: V01 cryptographic messages/evidence, V02 codec,
V03/V04 SAS/asset, V05 legal certificate plus independent negative mutations,
V10 phase/role checks through V01 messages, V11 proof and replay across verifiers
sharing one registry, INTEROP-V01 CandidateHello/binding/strict hex. V13 is retained as
reference input but a new legacy negotiation engine is not implemented.

## Baseline evidence (ca0343e, 2026-10-16, aarch64 macOS, offline)

Final runs: default workspace **219 passed, 2 preexisting ignored**; experimental
workspace **232 passed, the same 2 ignored**. Experimental all-target clippy with
warnings denied, formatting and whitespace checks passed. No ignored tests were
added. Fixture parity was checked against immutable `f991802...` Git objects.

Thirteen new tests include table-driven checks for all FC bindings and required
records, re-signed/re-MACed changes to 12 approval fields and 30 finalization
fields, 10 recovery fields, candidate substitutions, invalid connection grammar,
NFC/bidi/control cases, malformed suite lists, DER/profile mutations, wrong
NodeId, signature/tag forgery, expiration, tombstones and one-use verification.
Positive fixtures first failed against typed stubs. The addendum migration also
first failed with the old signed text representation before switching to bytes32.

Twenty production mutants were run separately and each caused an assertion
failure for the intended acceptance/output defect, then was restored:

| Mutants | Killing test |
| --- | --- |
| Omit each of seven FC prefix bindings independently | `every_fc_binding_and_required_signed_record_is_enforced` |
| Omit candidate hash, TLS leaf, connection ID or generation independently | `candidate_addendum_bytes_bind_every_field_connection_generation_and_tls_leaf` |
| Skip canonical DER header check; skip certificate self-signature | `certificate_profile_rejects_correctly_signed_wrong_algorithms_usage_san_and_noncanonical_der` |
| Skip commitment check | `detached_commitments_and_key_derivation_match_v01_without_candidate_admission` |
| Reverse SAS bit/index order | `four_words_match_external_v03_and_asset_digest_is_enforced` |
| Skip live MAC; skip identity signature verification | `valid_bodies_with_forged_signatures_or_tags_are_not_bilateral_consent` |
| Skip approval body binding; skip finalization body binding | `signed_and_maced_changed_approval_and_finalization_bindings_are_rejected` |
| Do not consume recovery verifier | `recovery_signature_matches_external_v11_and_is_one_use` |

Verification commands (default suite retains the feature-off boundary):

```text
cargo test --workspace --offline --quiet
cargo test --workspace --features seamless-transport/pairing-v2-experimental --offline --quiet
cargo clippy --workspace --all-targets --features seamless-transport/pairing-v2-experimental --offline -- -D warnings
cargo fmt --all -- --check
```

## Round-2 correction evidence (2026-10-16, aarch64 macOS, offline)

The initial negative certificate test failed against the old validator for a
properly re-signed Ed25519 certificate missing KeyUsage. After requiring usage,
the same test independently failed for a properly re-signed unknown noncritical
extension. Both retain a positive legal certificate using the same synthetic
key. Recovery tests first failed because reconstruction accepted a consumed
proof and 16 concurrent independent verifier instances all succeeded. They now
share an injected registry and require exactly one winner.

Additional tests cover every distinct context component (including signer),
replay with a renewed deadline, invalid-signature/expired/tombstoned attempts
not consuming a valid proof, full registry with no eviction and poisoned-lock
fail-closed behavior. No frozen JSON fixture was modified.

Twelve isolated production mutants were run and restored. Each failed an
assertion for its expected defect (not a compile failure):

| Mutant | Killing assertion |
| --- | --- |
| Remove mandatory `usage` presence | Correctly signed certificate without KeyUsage rejected |
| Accept unknown noncritical extension | Correctly signed unknown extension rejected |
| Omit each of eight variable RecoveryProof context fields from replay key, separately | Distinct correctly signed context must not collide (indexes 0–7) |
| Omit signer from replay key | Distinct signer context must not collide (index 8) |
| Skip shared registry consumption | Original proof rejected after first success across instances |

Final restored-tree verification: default workspace **219 passed, 2 preexisting
ignored**; experimental workspace **237 passed, the same 2 ignored** (16 fixture
integration tests plus two registry guard unit tests). All-target clippy with
warnings denied passed both default and experimental configurations. Formatting
and `git diff --check` passed. The experimental module is still disabled by
default and no admission/promotion behavior was changed.

## Required next work before any connection to product behavior

Independent review of this slice comes first. The rest of phase 2 is not implied
by passing primitive tests: no sender, live commitment-before-reveal state
machine, simultaneous initiation resolution, CandidateHello-to-Hello binding,
UI-generation/approval gate, 300-second attempt/30-second phase clocks,
socket/token-bucket/candidate limits, nonce registry, role-specific durable
journal prerequisites, post-crash reconciliation, or global replay/tombstone
integration has been implemented. An FC check alone must never stand in for
these conditions. No recovery proof may be issued before durable local FC and
own role evidence are verified. Product policy/no-downgrade must be enforced by
that future coordinator; the detached parser merely rejects incompatible v2
version/suite/dictionary/intent/timeout fields and has no legacy fallback.

Also pending: external cryptographic review, full adversarial certificate
corpus/fuzzing (including canonical SET/primitive encodings), key lifecycle and
secure-erasure review, real Windows/macOS identity storage, actual TLS exporter
and mutual-leaf binding, transport fault schedules, native UI and real-device
interop. Full Windows build still requires the absent MSVC headers used by ring.
No signing, CI dispatch, push, merge, deployment or publication was performed.
