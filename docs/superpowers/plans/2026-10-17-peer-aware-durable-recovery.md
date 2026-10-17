# Peer-Aware Durable Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `executing-plans` task by task with review checkpoints.

**Goal:** Resolve interrupted bilateral durable admission only with authenticated evidence from both peers, without treating a local intermediate receipt as a usable relationship.

**Architecture:** Retain current local receipts as non-operational metadata. A fresh mutual-TLS recovery exchange compares an exact transaction id, both receipt hashes, peer pin, and all generations. It either atomically confirms the same pair at both peers or aborts only the exact pair.

**Tech Stack:** Rust, Tokio, Quinn mutual TLS, sealed `PendingStore` ledger, pairing-v2 framing.

**Spec:** `docs/superpowers/plans/2026-10-17-task4-crash-matrix.md`

## Global Constraints

- Recovery cannot enable input, clipboard, topology, discovery, UI, or an operational session.
- A timeout, mismatch, duplicate, malformed record, or stale generation exact-aborts only its transaction.
- No signing, publishing, deployment, or release action is in scope.

### Task 1: Classify recovery eligibility

**Files:**

- Modify: `crates/transport/src/pairing_pending.rs`
- Modify: `crates/transport/src/pairing_v2/admission_authority.rs`
- Test: `crates/transport/src/pairing_pending.rs`

- [ ] Write failing tests for `BilateralRecoveryDisposition::{Confirmed, NeedsPeerRecovery, AbortExact}`. A `StoreOwnedAwaitingPeer` and a local-only `BilateralConfirmed` record must be `NeedsPeerRecovery` and must fail `operational_admission_snapshot`.
- [ ] Run: `"$TASK_CARGO" test -p seamless-transport --features pairing-v2-experimental recovery_disposition -- --nocapture`; expect RED because the disposition API does not exist.
- [ ] Implement a crate-private `recovery_disposition(attempt)` that validates the immutable receipt and returns metadata only; do not modify `operational_admission_snapshot`.
- [ ] Re-run the focused test and the serial suite: `"$TASK_CARGO" test -p seamless-transport --features pairing-v2-experimental -- --test-threads=1`.
- [ ] Commit: `git add crates/transport/src/pairing_pending.rs crates/transport/src/pairing_v2/admission_authority.rs && git commit -m "feat: classify durable bilateral recovery"`.

### Task 2: Exchange authenticated recovery evidence

**Files:**

- Create: `crates/transport/src/pairing_v2/recovery.rs`
- Modify: `crates/transport/src/pairing_v2/mod.rs`
- Modify: `crates/transport/src/pairing_v2/provisional_tls.rs`
- Test: `crates/transport/src/pairing_v2/provisional_tls/tests.rs`

- [ ] Write a two-process failing test for `recover_exact_pair`: it must exchange `{ transaction_id, local_receipt_hash, peer_receipt_hash, identity_generation, revocation_generation, policy_revision }` and return no proof when any field changes.
- [ ] Run: `"$TASK_CARGO" test -p seamless-transport --features pairing-v2-experimental exact_peer_recovery -- --nocapture`; expect RED because no recovery exchange exists.
- [ ] Implement one bounded mutual-TLS request/response exchange with crate-private constructors. Reject extra streams, duplicate records, malformed frames, mismatches, and deadline expiry.
- [ ] Run the focused test on macOS and Windows, using the isolated Windows checkout command from the session handoff document.
- [ ] Commit: `git add crates/transport/src/pairing_v2 && git commit -m "feat: authenticate exact bilateral recovery"`.

### Task 3: Complete or exact-abort interrupted records

**Files:**

- Modify: `crates/transport/src/pairing_pending.rs`
- Modify: `crates/transport/src/pairing_v2/admission_authority.rs`
- Test: `crates/transport/src/pairing_v2/provisional_tls/tests.rs`

- [ ] Write red subprocess tests for `StoreOwnedBeforeRelease`, `LeftFinalized`, and `LeftConfirmed`. Each must prove no operational snapshot and a clean same-peer retry after an exact abort.
- [ ] Implement recovery so both validated peers write the same confirmation, or both independently exact-abort their own immutable transaction on failure.
- [ ] Verify `task4_` on macOS and Windows, then run the serial suite. Record unrelated baseline failures separately.
- [ ] Commit: `git add crates/transport/src/pairing_pending.rs crates/transport/src/pairing_v2/admission_authority.rs crates/transport/src/pairing_v2/provisional_tls/tests.rs && git commit -m "feat: resolve interrupted bilateral admissions exactly"`.

## Review checklist

- Recovery produces no runtime authority.
- Each stored transition binds the transaction, both receipt hashes, pin, and generations.
- A later same-peer transaction cannot be removed by an earlier failed recovery.
- Every new crash row has recorded Mac and Windows evidence.
