# Durable Admission Handoff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` or `executing-plans` task by task. Do not wire product UI or runtime sharing until every task and the independent security review pass.

**Goal:** Allow a completed bilateral transport handshake to become durable metadata that survives normal provisional-endpoint cleanup, without weakening cancellation, revocation, crash recovery, or the default-off runtime boundary.

**Architecture:** Keep the current protocol freeze and revocation guard. Publish a guarded `AwaitingHandoff` receipt first, then make exactly one short consent-scope ownership election. Only the winner may publish `StoreOwned` plus its active pin under the ledger lock. Endpoint drop remains cancellation before that election and becomes transport-only cleanup after it. Every durable reader accepts only a current `StoreOwned` receipt.

**Tech Stack:** Rust, existing `PendingStore` transactional manifest, `AdmissionRevoker`, `ConsentScope`, Tokio/QUIC test fixtures, private filesystem test hooks.

**Design input:** `.superpowers/sdd/2026-10-17-control-shift-f12-complete-desktop-delivery/durable-handoff-design-review.md`.

## Invariants

- A receipt alone never proves completed admission.
- The exact guard token, attempt, peer, staged revision and final revision bind ownership; missing or unknown ownership fails closed.
- No endpoint, stream, QUIC configuration, network locator, input, clipboard or session authority crosses the handoff boundary.
- No mutex is held across filesystem I/O or an await.
- A crash before final `StoreOwned` publication cannot become success after restart.
- A matching final `StoreOwned` publication cannot be revoked merely because endpoint cleanup or guard cleanup occurs later.
- Existing explicit durable revoke and identity rotation always invalidate completed metadata.

---

### Task 1: Add an explicit durable ownership schema and fail-closed reads

**Files:**
- Modify: `crates/transport/src/pairing_pending.rs`
- Modify: `crates/transport/tests/pairing_pending.rs`
- Modify: `crates/transport/src/pairing_v2/admission_authority.rs`

**Interfaces:** Add a private serialized ownership state to each experimental admission receipt:

```rust
enum AdmissionOwnership {
    AwaitingHandoff { guard_token: [u8; 32], staged_revision: u64 },
    StoreOwned { guard_token: [u8; 32], staged_revision: u64, handoff_revision: u64 },
}
```

- [ ] Write manifest-validation tests for zero/repeated tokens, unordered revisions, ownership/receipt mismatch, unknown/absent ownership, and old schema reopening.
- [ ] Change `AdmissionReceiptRecord` and manifest validation so every new production record names an ownership state; no serde default may mean `StoreOwned`.
- [ ] Change `admission_state`, `current_operational_snapshot`, preflight acquisition and final-lease currentness to require a matching current `StoreOwned` receipt and active pin.
- [ ] Keep test-only synthetic receipts explicit about their ownership state; they must not expose a production bypass.
- [ ] Run `cargo test -p seamless-transport --features pairing-v2-experimental pairing_pending` and the focused admission-authority tests. Commit only this schema/read boundary.

### Task 2: Preserve a private, move-only consent handoff witness

**Files:**
- Modify: `crates/transport/src/pairing_v2/provisional_tls.rs`
- Modify: `crates/transport/src/pairing_v2/provisional_tls/handshake_io.rs`
- Modify: `crates/transport/src/pairing_v2/provisional_tls/tests.rs`

**Interfaces:** Introduce a crate-private `FrozenAdmissionHandoff` obtained only while freezing `HandshakeCompletePendingAuthority`. It retains the exact `Arc<ConsentScope>` and exact guard identity, but no networking object or token getter.

- [ ] Write compile-fail coverage that the handoff is non-Clone, non-serializable, privately constructed, unavailable from a receipt/attempt ID, and cannot become runtime authority.
- [ ] Preserve watcher priority: a queued ingress violation still wins over freeze and cannot yield a handoff witness.
- [ ] Add `ConsentPhase::TransferredToStore`; before transfer endpoint drop takes/revokes the guard, while after transfer it only closes provisional transport.
- [ ] Implement a consuming, exact-token claim method under the consent mutex. It must reject `Revoked`, wrong token, non-frozen scope and stale guard; it may not do filesystem work under that mutex.
- [ ] Run focused provisional TLS tests including drop-before-freeze, late-input rejection and handoff type boundaries. Commit only private witness/scope plumbing.

### Task 3: Implement two-stage guarded store finalization and recovery

**Files:**
- Modify: `crates/transport/src/pairing_pending.rs`
- Modify: `crates/transport/src/pairing_v2/admission_authority.rs`
- Modify: `crates/transport/src/private_fs.rs`
- Modify: `crates/transport/src/private_fs_windows.rs`
- Test: `crates/transport/tests/pairing_pending.rs`
- Test: `crates/transport/src/pairing_v2/admission_authority.rs`

**Interfaces:** Replace the current single `commit_sealed_admission` completion path for live evidence with one consuming operation:

```rust
// Crate-private. It returns only ordinary metadata after final durable ownership.
async fn commit_sealed_foundation(
    &self,
    expected: StoreVersion,
    authority: HandshakeCompletePendingAuthority,
) -> Result<PromotionReceipt, StoreError>;
```

- [ ] Add a first locked publication: consume pending state and record `AwaitingHandoff`, but do not add an active pin or claim operational eligibility.
- [ ] Under ledger lock, briefly claim the exact frozen guard from the consent scope. If endpoint drop already won, leave the staged receipt non-eligible and return a fail-closed outcome.
- [ ] Add a second locked manifest publication with matching `StoreOwned` ownership and active pin. The returned relationship revision must be the final publication revision.
- [ ] Make sidecar deletion exact-token cleanup after final publication. A cleanup failure or uncertain publish must return no normal success; reconciliation determines the actual durable result under the ledger lock.
- [ ] Refactor guard reconciliation to make one locked ownership decision. A matching final ownership record performs cleanup only; staged/missing/mismatched state follows conservative revoke or quarantine behavior.
- [ ] Add deterministic hooks at staging save, pre-claim, post-claim, final save and guard unlink; do not add a general production bypass.
- [ ] Run the focused persistence/reconciliation suites on Unix and Windows-capable backend tests. Commit only storage/authority finalization.

### Task 4: Prove races, crashes and bilateral boundary behavior

**Files:**
- Modify: `crates/transport/src/pairing_v2/provisional_tls/tests.rs`
- Modify: `crates/transport/src/pairing_v2/admission_authority.rs`
- Modify: `crates/transport/tests/pairing_pending.rs`
- Modify: `scripts/test-admission-authority-contract.py`

- [ ] Preserve the old test proving that endpoint drop during pre-transfer save yields `Revoked`.
- [ ] Add a separate real QUIC acceptance test: both local confirmations, finalization, endpoint destruction, same-process reopen and fresh-process reconciliation preserve only metadata.
- [ ] Add deterministic races for drop before claim, drop versus claim, crash/cancellation after claim before final save, final save before cleanup, cleanup failure, explicit durable revoke versus finalization, and two-process reconciliation versus finalization.
- [ ] Assert no unfinished/staged record produces an operational snapshot, preflight lease or active pin.
- [ ] Add wrong-root, token mismatch, swapped receipt, corrupt ownership, old schema, stale generation/policy and duplicate attempt cases.
- [ ] Run the full feature suite, contract script, `cargo fmt --check`, and strict clippy. Commit tests plus any minimal fixes.

### Task 5: Independent security review before product bridge resume

**Files:**
- Review the exact Task 1–4 diff and test evidence.
- Modify if required: `docs/bilateral-handshake-boundary.md`, `docs/product-pairing-admission-adapter.md`.

- [ ] Review that old/missing receipts never default to success; endpoint drop cannot revoke post-transfer ownership; and exact-token cleanup cannot erase newer guard material.
- [ ] Review all durable readers, not only `reconcile`, for the `StoreOwned` predicate.
- [ ] Verify no runtime capability, network locator or host-facing authority was added.
- [ ] Only after GO, resume Task 3 of `2026-10-17-control-shift-f12-complete-desktop-delivery.md` and add its adapter-level bilateral, replay, expiry and projection coverage.

## Verification matrix

| State | Expected durable outcome |
| --- | --- |
| Drop before freeze or claim | Cancel/revoke; no active pin |
| Staged receipt, guard still endpoint-owned | Never eligible |
| Claim then crash before final publication | Fail closed/revoke or quarantine; never promoted |
| Final StoreOwned publication then endpoint drop | Metadata remains; endpoint only closes transport |
| Final publication then cleanup failure | No ordinary success until locked reconciliation verifies final ownership |
| Later durable revoke or rotation | Historical receipt inactive; no lease or pin |

No native UI, product adapter, listener, sharing, signing, publishing or deployment is enabled by this plan.
