# Phase 3 — isolated pairing state and durable evidence

Internal implementation for review, **not release or operational GO**.
Base: `945047a0ac1824ac990c29c4259efa97f2d2131c`.
Design SHA256: `f790167ddfb2f295e1a3c2c129d6f48e46bd58bc10c984e5f41bb190e7b0fa07`.
Reference addendum: `f991802…`; independently reviewed E2E reference:
`d015f9230d6c322f026daedba24d9e93de96296a`.

`pairing-v2-experimental` remains default-off; no application enables it.
No network adapter, native UI, signer/emitter, active-pin promotion, input,
clipboard, packaging or legacy auto-pin path was added. PendingStore promotion
still unconditionally denies. Windows persistence remains UnsupportedPlatform.

## Delivered components and interfaces

| Component | Responsibility and boundary |
| --- | --- |
| `coordinator_limits.rs / PairingLimits` | Pure consent-window gate. Global/source token buckets 20/min burst 5 and 5/min burst 2; connections 8/2; CandidateHello read deadline 2 seconds; freshness <=30 seconds; one selected attempt; overall 300 seconds and phase 30 seconds. Clock rollback poisons the instance. Closing/reopening does not reset buckets or consumed connection IDs. |
| `session.rs / BoundHello` | Exact CandidateBinding hash, connection ID/generation, TLS fingerprint, certificate/NodeId and CandidateHello→Hello field binding. Only the approved singleton [SUITE], with exact Hello equality; no multisuite negotiation or legacy fallback. |
| `SasSession` | Full-fingerprint role ordering; only the connection initiated by A. Both commitments before any reveal; reveal/commitment and local ephemeral-key equality; both identity proofs before SAS. Local approval requires current explicit confirm(attempt,T,ui-generation,true,time). Signed/MACed approvals from both roles produce P. |
| `journal.rs / Finalizer` | Ready A/B → Commit A → CommitAck B → Complete A. Local A Commit, local B Ack and each full FC are NeedsDurability barriers. Further frames reject while a barrier is outstanding. persist(store,CAS,clock) must succeed before advancement. Failure/ambiguity/stale CAS freezes the instance and drops keys. |
| `PendingStore` extension | Owner-only directory-FD anchored Unix storage under the existing cross-process lock. Pending and public signed journals remain physically separate from active pins. Every operation validates ALL references, including unrelated attempts. |
| `reconcile_pairing / RecoveryJournal` | Precommit/no journal is tombstoned. Valid own-role evidence returns RecoveryOnly, never Paired. complete_signed appends only exact remaining Ack/Complete evidence to the immutable prefix; no new human approval or signing. |
| `recovery_authority.rs` | Typed authoritative-context port; absence/mismatch/error fail closed. Exact expected role, FC, remote accepted generations, both challenges/exporter before consumption. PendingStore supplies only LOCAL CAS/generations and durable exact-proof consumption. |

These are **offline components**, not a composed operational listener/controller.
The future adapter must own one gate for its lifetime, check it and bound frames
before expensive crypto, select only on a local gesture, bind fresh nonces to
the actual selected connection, and cancel on window/connection closure.
Low-level constructors must not become unrestricted application actions.
Composition and actual TLS provenance are NOT claimed tested here.
Discovery UI/catalogue (20-item cap), native prompts and real socket allocation
are absent; the pure connected-candidate gate has a stricter eight-connection cap.
Internal non-evicting caps: 256 source buckets and 1024 consumed connection IDs.
Exhaustion fails closed, not a silent reset during a ceremony.

## State, clocks and retry

1. Exactly bound selected Hellos establish C/attempt and immutable roles.
2. Commit A+B → reveal A+B → strict proofs A+B → four-word SAS.
3. Remote signed approval alone is insufficient. Local Coincide must match
   attempt, T and current UI generation before local signed approval is accepted.
4. Bilateral approvals → P → both Ready → durable own Commit/A or Ack/B →
   durable full FC. FC hash remains absent until the final write.
5. Cancel, changed duplicate, invalid proof/order, mismatch or rollback terminates
   the in-memory attempt and drops zeroizing private/session keys. Identical
   pre-finalization duplicates are idempotent, never extend deadlines.
   Finalization duplicates conservatively abort; durable reconciliation may
   follow, never a resumption of the old SAS.
6. SAS expires at 300 seconds. Before both proofs network phases are <=30 seconds;
   human comparison uses the remaining overall window. Finalization network
   phases are <=30 seconds; the overall deadline is rechecked before the first
   own-role durable boundary, including immediately before writing.

Clocks are observations injected by a future trusted adapter, not real OS clock
reads inside these modules. Retry requires explicit new selection/connection ID,
fresh Hellos/blinds/private keys. This slice generates no randomness/nonces.
Durably cancelled attempt IDs cannot be reused.

## Durable journal, CAS and restart

Ledger schema 1 gains feature-gated journals/recoveries fields, absent when empty.
Default-feature builds reject nonempty experimental fields as unknown; no
downgrade/migration silently discards evidence.

- Revision-qualified journal filename: journal-<revision>-<attempt>.json.
  Write bytes → file fsync → rename → directory fsync; then publish its
  digest/reference through a ledger write with the same durability sequence.
- Every journal read checks owner/type/link count/mode/no-follow, <=64KiB size,
  SHA256 digest, exact pending/attempt, strict JSON fields, certificate profiles,
  roles, signed approvals and every ordered finalization record. Full journals
  reconstruct and verify the byte-exact FC.
- Initial journal requires A's Commit or B's Ack. Replacement preserves ALL
  fields and signed prefix, including the original retention clock, and appends
  only the records needed for full FC. It cannot extend retention by rewriting
  timestamps.
- No write publishes trust. Old files are removed only AFTER durable ledger
  publication. Cancel/revoke/rotate first persist tombstones, then remove records
  and journals. Interrupted cleanup can leave quarantined unreferenced files;
  they never become authoritative. Corruption causes no broad automatic cleanup.
- Unknown clock, UTC rollback, same-boot monotonic rollback, or UTC age >=24h
  discards via durable tombstone; same-boot monotonic age >=24h also discards.
  Changed boot requires nonzero boot ID and trustworthy nondecreasing UTC.
  No native clock-trust provider is installed. Corrupt referenced evidence fails
  closed without CAS advancement or cleanup.
- Recovery consumption requires an actual local FULL FC with the opposite peer
  role: a context claim alone cannot replace that evidence. Complete canonical
  proof body + signer is retained, revalidated on every read, never evicted,
  consumed atomically under ledger lock/CAS. Local revoke/rotation invalidates
  pending versions. Capacity exhaustion fails closed.

## Authoritative recovery context — mandatory remaining gate

No production RecoveryAuthority provider is installed. A future independently
reviewed provider must populate expected context AFTER own-role full FC
durability, from a previously accepted remote-generation record and a fresh
dedicated recovery TLS connection. Bind role/certificate/FC/challenge ID,
both nonces/exporter/deadline/revision. Compare and consume that context atomically
with exact-proof consumption; persist consumed challenge IDs/tombstones and never
reissue old challenges. NEVER derive remote generations from local counters.
The test adapter supplies remote generations 91/73, different from local
generations; it is NOT the production/global authority.

The operational-context validator requires 32-byte random challenge nonces
(as the design specifies) and currently 32-byte exporter output. The reviewed
E2E fixture intentionally has shorter synthetic nonce/exporter byte strings.
They are consumed UNCHANGED by the generic reference-compatible verifier,
including both roles, but do not pass the stricter operational-context port.
This is no wire-format change or proof of real-channel interop. Exporter output
length/derivation and context population require adapter review and independent
operational vectors before any connection is enabled.
complete_signed is an offline evidence append, not authorization to open a
connection or emit a response. Neither it nor the generic signature verifier
grants promotion.

## Frozen fixture and TDD evidence

E2E fixture is byte-identical to reference commit d015f923…:
SHA256 `dca4177693614ef450b9a3a96e8f3a21a36fafdb5027119a8bdf385073f8fbc3`.
Previous phase-2 JSON fixtures are unchanged. Both roles consume actual
CandidateHello→Hello→commit/reveal→proofs→SAS→approvals/P→FC and byte-exact
RecoveryProofs. V01 placeholder CandidateHello hashes reject in the binder.

Observed RED→GREEN steps: new resource/session/journal APIs; absent signed
restart completion; expiry between Commit validation and write; missing local
FC enforcement; explicit cancel; leftover referenced journal after tombstone;
initially absent process fault hooks. Compile errors for new APIs are not
presented as behavioral failures. Additional negatives cover changed, duplicate,
reordered messages, legacy/multisuite offers, UI generation, role ordering,
MAC/signature corruption, stale CAS, clocks, unrelated-record corruption and
two-process one-winner recovery consumption.

### Actual subprocess-cut/error schedules: 192

Fault hooks exist only in the unit-test executable, never library/application
builds. A child arms its hook AFTER setup, then exits without unwinding (91) or
returns injected I/O error (92). Parent reopening validates the whole manifest,
exact visible revision, recovery-only/discard outcome and promotion denial.

- 128: A/B × own-role journal/full FC × journal/ledger writes × before/after
  write, file fsync, rename, directory fsync × process cut/error.
- 64: cancel/revoke/rotate/recovery consumption × those eight ledger boundaries
  × process cut/error.

These are real subprocess terminations and injected I/O errors around actual
filesystem calls. NOT power loss, disk/controller cache durability, native
Windows ACL/reparse-point behavior, actual clocks or TLS network evidence.
Unlink/initialization-specific process cuts are not claimed by these 192 cases.

### Mutation sensitivity: 18 individually restored

All produced the expected assertion failure, not merely compile failure:

| Weakened control | Failing test filter |
| --- | --- |
| Candidate singleton suite | coordinator_never_negotiates |
| Candidate hash in Hello | reviewed_e2e_candidates |
| Both commitments before reveal | reveal_before_both |
| Reveal commitment match | changed_commit_reveal |
| Explicit local UI consent | one_sided_local |
| UI generation | reveal_before_both |
| 300-second attempt deadline | cancellation_is_terminal |
| A own Commit durability barrier | each_role_requires |
| B own Ack durability barrier | each_role_requires |
| 2-second CandidateHello deadline | exact_candidate_deadlines |
| Eight-connection cap | sockets_are_bounded |
| Source burst 2→3 | source_and_global_buckets |
| Clock check immediately before persist | expiry_between_commit |
| Validate all journal references | corrupt_journal_a |
| Real local durable FC required | authoritative_claim |
| Persist consumed RecoveryProof | accepted_remote_generations |
| Exact authoritative expected body | absent_or_changed_authority |
| Exact durable journal prefix | completed_journal_must_extend |

## Verification / handoff

### Round 2 coverage repair over 39bf613

No production behavior or cryptography changed. Three independently named
integration tests exercise `verify_authoritative_recovery` with lengths
**0, 1, 31, 33 and 256** for each of challenger_nonce, responder_nonce and
tls_exporter (15 cases). Each case changes the authoritative expected context
and canonical signed body together, then signs with the correct synthetic peer
key. An unrelated signature/context mismatch cannot hide a missing size guard.
The empty case is constructed through the canonical codec because the generic
RecoveryFields builder already rejects empty fields.

Every case requires exactly `Err(Invalid)`, unchanged StoreVersion/pending
record, and byte-identical snapshots of ALL files in both pending and tombstone
directories, including the full FC journal and consumption ledger. The fixture
starts with no consumed proof. Existing 32-byte valid-path tests remain green.
Short reference fixtures remain exclusive to the generic verifier; no exception
or fixture rewrite was added to the operational port.

Three separate mutants remove index 4, 5 or 6 from the persisted-proof size
checks. Each corresponding matrix becomes assertion RED at length 1 with actual
`Ok(())` versus expected `Err(Invalid)`; production was restored byte-for-byte
before final verification. [Round 2 captured outputs](qa/pairing-v2-phase3-r2-mutants.json).

Commands (aarch64 Cargo; offline):

```text
cargo test --workspace --offline
cargo test --workspace --features seamless-transport/pairing-v2-experimental --offline
cargo clippy --workspace --all-targets --offline -- -D warnings
cargo clippy --workspace --all-targets --features seamless-transport/pairing-v2-experimental --offline -- -D warnings
cargo fmt --all -- --check
git diff --check
```

Fresh final round-2 runs on the isolated macOS/aarch64 worktree:

- Default workspace: **219 passed, 0 failed, 2 existing ignored subprocess helpers**.
- Experimental workspace: **272 passed, 0 failed, the same 2 ignored helpers**.
- Both full-workspace/all-target clippy modes: exit 0 with warnings denied.
- Formatting and diff whitespace checks: exit 0.
- Original slice: 18/18 individual mutants, expected assertion RED and restored.
  Raw captured outputs: [mutation evidence](qa/pairing-v2-phase3-mutants.json).
- Round 2: 3/3 field-size mutants, expected assertion RED and restored before
  these final runs; 15 invalid-length cases pass with no durable mutation.
- 192 real subprocess-cut/injected-error schedules pass as nested test cases;
  they are not added to the 272 top-level test count.
- Reference git-object and copied E2E fixture SHA256 match exactly.

Next: independent security/code review of this isolated commit, including
non-operational composition boundaries and the authoritative-context port.
External crypto audit, reviewed persistent context provider, independent
real-channel vectors, native Windows secure storage and real macOS/Windows
interop remain mandatory before any release decision.
