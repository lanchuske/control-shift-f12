# Bilateral Durable Admission Protocol Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a completed pairing become operational only after both machines durably publish, authenticate, and acknowledge the same admission transaction; a crash, timeout, replay, or one-sided failure must leave neither side operational.

**Architecture:** Replace the current one-sided `StoreOwned` activation boundary with a transaction-scoped two-party protocol. Each peer writes a non-operational durable receipt, exchanges authenticated confirmation frames over the already authenticated pairing channel, and only then atomically marks its own receipt `BilateralConfirmed` and exposes an operational snapshot. Exact transaction IDs and guard tokens scope abort and recovery so an old attempt cannot affect a newer relationship with the same peer.

**Tech Stack:** Rust, Tokio, QUIC pairing-v2 transport, serde JSON durable ledger, existing `PendingStore`, native macOS and Windows Rust test runners.

**Spec:** `docs/superpowers/plans/2026-10-17-control-shift-f12-complete-desktop-delivery.md`; this plan replaces its one-sided durable-admission assumptions before desktop pairing UI can be enabled.

## Global Constraints

- Keep `HandshakeCompletePendingAuthority`, `SealedPromotionEvidence`, revokers, and frozen handoffs non-serializable and crate-private.
- Do not expose mouse, keyboard, clipboard, operational capability, or an active snapshot before mutual durable confirmation.
- Derive transaction identifiers from ordered identities, transcript, suite, policy revision, and both attempt IDs with domain separation; never accept a caller-supplied identifier.
- Accept only an explicit authenticated finalization mini-protocol after freeze. Any unknown, replayed, cross-transcript, malformed, or late frame fails closed.
- Never hold a ledger lock, consent mutex, or filesystem lock across an await, network operation, or remote acknowledgement.
- Abort, timeout, revocation, and recovery act only on an exact transaction ID, attempt, and guard token; never revoke by peer alone.
- Preserve current CRLF wordlist normalization and rejection rules; do not weaken SAS, transcript, certificate pin, or watcher validation.
- No signing, publication, deployment, remote-input enablement, or product UI capability is part of this plan.

---

## File structure

- `crates/transport/src/pairing_pending.rs`: durable transaction schema, ledger validation, inactive local publication, exact abort/recovery, and operational-snapshot eligibility.
- `crates/transport/src/pairing_v2/admission_authority.rs`: transaction-bound sealed commit coordinator and public-to-pairing-v2 internal receipt types.
- `crates/transport/src/pairing_v2/provisional_tls/handshake_io.rs`: fixed authenticated finalization frame grammar, freeze/watcher state machine, and exact confirmation transport.
- `crates/transport/src/pairing_v2/provisional_tls/tests.rs`: real QUIC endpoint tests for bilateral success, order independence, error compensation, crash/restart, replay, and stale attempt isolation.
- `crates/transport/src/pairing_v2/admission_authority.rs` test module and `crates/transport/src/pairing_pending.rs` test module: ledger-only malformed-state and recovery tests.

### Task 1: Define inactive bilateral transaction state

**Files:**
- Modify: `crates/transport/src/pairing_pending.rs:47-106`
- Test: `crates/transport/src/pairing_pending.rs` test module

**Interfaces:**
- Produces `BilateralTransactionId([u8; 32])`, `BilateralAdmissionState::{Prepared, StoreOwnedAwaitingPeer, BilateralConfirmed, Aborted}`, and a transaction record carried by each admission receipt.
- Consumed by every task below; `current_operational_snapshot` may return a value only for `BilateralConfirmed`.

- [ ] **Step 1: Write failing ledger tests**

```rust
#[test]
fn store_owned_awaiting_peer_is_never_operational() {
    let store = seeded_store_with_state(BilateralAdmissionState::StoreOwnedAwaitingPeer);
    assert_eq!(store.operational_admission_snapshot(ATTEMPT), Err(StoreError::Invalid));
}

#[test]
fn transaction_id_changes_when_either_attempt_or_transcript_changes() {
    assert_ne!(derive_transaction_id(&fields(ATTEMPT_A, ATTEMPT_B, TX_1)),
               derive_transaction_id(&fields(ATTEMPT_A, ATTEMPT_B, TX_2)));
}
```

- [ ] **Step 2: Run the two tests and verify RED**

Run: `cargo test -p seamless-transport --features pairing-v2-experimental bilateral_admission_state -- --nocapture`

Expected: compilation failure because the transaction types and inactive-state gate do not exist.

- [ ] **Step 3: Implement the minimal schema and derivation**

```rust
pub(crate) struct BilateralTransactionId([u8; 32]);

enum BilateralAdmissionState {
    Prepared,
    StoreOwnedAwaitingPeer,
    BilateralConfirmed,
    Aborted,
}

fn derive_transaction_id(fields: &TransactionFields) -> BilateralTransactionId {
    // SHA-256("control-shift-f12/admission-v1" || canonical ordered fields)
}
```

Store both local and peer receipt hashes, the exact guard token, policy/identity/revocation generations, and the transaction ID. Validate non-zero fields and reject unknown serde fields.

- [ ] **Step 4: Make operational eligibility require exact bilateral confirmation**

Change `current_operational_snapshot` so it additionally requires `BilateralConfirmed`, matching local transaction ID, receipt hashes, generation/policy fields, and exact active pin.

- [ ] **Step 5: Run focused tests and commit**

Run: `cargo test -p seamless-transport --features pairing-v2-experimental pairing_pending::tests -- --nocapture`

Commit: `feat: add inactive bilateral admission transaction state`

### Task 2: Publish and abort transaction records exactly

**Files:**
- Modify: `crates/transport/src/pairing_pending.rs:963-1045,1660-1735`
- Test: `crates/transport/src/pairing_pending.rs` test module

**Interfaces:**
- Consumes Task 1 state and transaction ID.
- Produces `publish_local_bilateral_receipt`, `confirm_bilateral_receipt`, and `abort_bilateral_transaction` with exact transaction/attempt/token arguments.

- [ ] **Step 1: Write failing tests for local-only publication and stale aborts**

```rust
#[test]
fn local_publication_is_inactive_until_matching_peer_ack() { /* publish; assert no snapshot */ }

#[test]
fn delayed_abort_cannot_revoke_later_transaction_for_same_peer() { /* old abort; new receipt stays */ }

#[test]
fn confirm_rejects_wrong_transaction_or_peer_receipt_hash() { /* each mismatch is Invalid */ }
```

- [ ] **Step 2: Verify RED**

Run: `cargo test -p seamless-transport --features pairing-v2-experimental local_publication_is_inactive -- --exact`

Expected: missing API or an operational snapshot appears too early.

- [ ] **Step 3: Implement short lock-held ledger transitions**

`publish_local_bilateral_receipt` writes `StoreOwnedAwaitingPeer` and an inactive transaction pin in one ledger save. `confirm_bilateral_receipt` checks exact local/peer transaction and receipt hashes before changing only that record to `BilateralConfirmed` and installing the active pin. `abort_bilateral_transaction` removes only matching transaction data and tombstones only that attempt; it must not increment a peer-wide revocation generation.

- [ ] **Step 4: Add recovery tests**

Test restart after local publication, timeout before ACK, ACK loss after both publications, and exact abort versus a newer same-peer attempt.

- [ ] **Step 5: Verify and commit**

Run: `cargo test -p seamless-transport --features pairing-v2-experimental pairing_pending::tests -- --nocapture`

Commit: `feat: keep bilateral admission inactive until exact confirmation`

### Task 3: Add the authenticated finalization mini-protocol

**Files:**
- Modify: `crates/transport/src/pairing_v2/provisional_tls/handshake_io.rs:115-285`
- Test: `crates/transport/src/pairing_v2/provisional_tls/tests.rs`

**Interfaces:**
- Consumes frozen handshake transcript, both attempt IDs, certificate pins, and Task 1 transaction ID.
- Produces `FinalizationChannel::exchange_local_receipt` and an authenticated `PeerFinalizationReceipt` bound to the transaction.

- [ ] **Step 1: Write failing wire tests**

```rust
#[tokio::test]
async fn finalization_rejects_replayed_or_cross_transcript_receipt() { /* real endpoints */ }

#[tokio::test]
async fn finalization_rejects_unknown_frame_after_freeze() { /* real endpoints */ }
```

- [ ] **Step 2: Verify RED**

Run: `cargo test -p seamless-transport --features pairing-v2-experimental finalization_rejects -- --nocapture`

Expected: no finalization grammar exists.

- [ ] **Step 3: Implement a fixed frame grammar**

Define only `LocalPublished { transaction_id, receipt_hash, generations }`, `PeerAck { transaction_id, local_hash, peer_hash }`, and `Abort { transaction_id, reason_code }`. Authenticate every frame using the handshake-derived binding; reject duplicates, unknown fields, wrong ordering, cross-transaction values, and late frames. Do not accept generic control traffic.

- [ ] **Step 4: Preserve fail-closed watcher behavior**

The watcher may permit only this typed bounded sequence during finalization. Timeout, shutdown, malformed framing, or unexpected input returns `Invalid`; no path treats a closed connection as confirmation.

- [ ] **Step 5: Verify and commit**

Run: `cargo test -p seamless-transport --features pairing-v2-experimental provisional_tls::tests::finalization -- --nocapture`

Commit: `feat: exchange authenticated bilateral finalization receipts`

### Task 4: Coordinate concurrent bilateral publication and compensation

**Files:**
- Modify: `crates/transport/src/pairing_v2/admission_authority.rs:200-250,316-470`
- Test: `crates/transport/src/pairing_v2/provisional_tls/tests.rs`

**Interfaces:**
- Consumes Tasks 1–3.
- Produces `commit_bilateral_foundation(left, right)` for paired test endpoints and a production internal coordinator that returns success only after both local/remote confirmations.

- [ ] **Step 1: Write failing endpoint tests**

```rust
#[tokio::test]
async fn bilateral_commit_requires_both_stores_confirmed_before_any_snapshot() { /* A+B stores */ }

#[tokio::test]
async fn failure_after_one_local_publication_aborts_exactly_that_transaction() { /* inject B failure */ }
```

- [ ] **Step 2: Verify RED**

Run: `cargo test -p seamless-transport --features pairing-v2-experimental bilateral_commit_requires_both -- --exact`

Expected: current one-sided `commit_sealed_foundation` activates a snapshot too early.

- [ ] **Step 3: Implement the coordinator without locks across await**

Freeze both live authorities concurrently. Publish each local receipt as inactive. Exchange receipt hashes and acknowledgements. Finalize each local ledger only after verified peer ACK. On any error, send best-effort typed abort and run exact local abort; retain inactive recoverable metadata only when crash semantics require it.

- [ ] **Step 4: Add fault and recovery matrix**

Add real-endpoint tests for failure before/after each local publication, before/after each ACK, restart at every durable boundary, simultaneous abort/retry, delayed old abort versus new transaction, policy/identity rotation, and peer disconnect. Assert neither store returns an operational snapshot until both confirmations succeed.

- [ ] **Step 5: Verify and commit**

Run: `cargo test -p seamless-transport --features pairing-v2-experimental bilateral_commit -- --nocapture`

Commit: `feat: coordinate exact bilateral durable admission`

### Task 5: Cross-platform evidence and regression gates

**Files:**
- Modify: `crates/transport/src/pairing_v2/provisional_tls/tests.rs`
- Modify: `.gitattributes` only if a new immutable protocol vector needs binary preservation

**Interfaces:**
- Consumes Tasks 1–4.
- Produces an explicit PASS/FAIL/NOT MEASURED record for native macOS and Windows protocol coverage.

- [ ] **Step 1: Add deterministic stress and mutation-sensitive tests**

Run every bilateral success/failure boundary at least ten times with real QUIC endpoints. Add targeted mutations for transaction-ID domain separation, receipt hash swaps, state activation, and exact-abort identity.

- [ ] **Step 2: Run native macOS checks**

Run:
`cargo test -p seamless-transport --features pairing-v2-experimental pairing_v2:: --lib -- --nocapture`

Record exact failures separately from this feature if pre-existing fault workers still fail.

- [ ] **Step 3: Run native Windows checks**

Run the same command in a clean Windows checkout and repeat the bilateral exact suite ten times. Confirm `.gitattributes` leaves the BIP39 asset LF; also confirm CRLF canonicalization still works with a pre-existing dirty checkout.

- [ ] **Step 4: Independent security review and commit**

Require an independent reviewer to validate wire grammar, durable state transitions, recovery/abort scope, and all negative tests. Commit only the evidence/fixture changes needed for stable cross-platform execution: `test: verify bilateral admission protocol on macos and windows`.

## Follow-on desktop delivery gate

Only after Tasks 1–5 have an independent GO may the existing desktop plan enable pair selection in AppKit/WinForms. The next implementation order remains: native host lifecycle, UI bridge, visible discovery, bilateral confirmation screen, draggable display map, synchronized sharing preferences, connection/diagnostics panel, unsigned installation, then physical bidirectional QA. Every UI action remains disabled with clear copy until its corresponding motor contract is verified.

## Self-review

- The plan preserves every security requirement from the review: explicit inactive states, domain-separated IDs, authenticated receipts, exact abort, no locks across awaits, and fail-closed finalization.
- It covers the actual current defect: current one-sided activation and order-dependent freeze; it does not weaken watchers or rely on timing.
- It leaves the requested desktop product scope intact and makes bilateral protocol a prerequisite rather than a substitute for UI, installation, or physical QA.
- No placeholders remain; every task names files, concrete interfaces, red/green command, and a commit boundary.
