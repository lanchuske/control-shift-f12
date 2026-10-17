# Task 5: Task 4 crash/restart matrix

Scope: test harness and recovery requirements for the bilateral durable
admission coordinator. This phase does not add operational activation, UI,
sharing, discovery, or wire capabilities.

## Boundaries

| Boundary | Durable state at forced process death | Required restart result |
| --- | --- | --- |
| `Prepared` | pending record plus exact live reservation | no active snapshot or pin; stale pending/guard is reconciled exactly; fresh same-peer retry is possible |
| `Staged` | reciprocal `AwaitingHandoff` receipts | no active snapshot or pin; only the matching guards/receipts are cleaned; fresh retry is possible |
| `ProofVerified` | staged receipts and authenticated in-memory proof | proof is not durable authority; restart follows the staged rule |
| `Frozen` | staged receipts and frozen exact reservations | no peer-wide revoke; restart removes only the matching transaction/sidecar |
| `StoreOwnedBeforeRelease` | local `StoreOwnedAwaitingPeer` plus an unreleased guard | no ordinary success or operational snapshot; resolver performs exact sidecar reconciliation |
| `LeftFinalized` | one local store-owned publication | no unilateral active relationship; both sides remain ineligible and later retry is unaffected |
| `LeftConfirmed` | one local confirmed write while peer is incomplete | no unilateral active relationship; reconciliation is exact and fail-closed |

## Harness order

1. A subprocess constructs both real provisional endpoints and performs the
   bilateral handshake.
2. A test-only pause emits an immutable checkpoint marker only after the real
   transition has completed; the worker then exits without Rust destructors.
3. The parent reopens both ledgers, asserts no operational snapshot/active pin,
   resolves exact guards, and proves a fresh same-peer attempt is unblocked.
4. Add boundaries in order: `Prepared`, `Staged`, `ProofVerified`, `Frozen`,
   `StoreOwnedBeforeRelease`, `LeftFinalized`, `LeftConfirmed`.

## Design finding: post-publication recovery

The `LeftFinalized` probe was deliberately attempted and showed that a local
`StoreOwnedAwaitingPeer` receipt is currently treated as promoted by the
single-store reconciler. Deleting every unconfirmed store-owned receipt on
reopen is not safe: the existing manifest fault and operational tests rely on
the durable receipt while the live bilateral coordinator completes or an
explicit peer-aware recovery decides its outcome.

Therefore the remaining `StoreOwnedBeforeRelease`, `LeftFinalized`, and
`LeftConfirmed` crash cases require a peer-aware recovery/commit-ack protocol,
not a local-only cleanup rule. Keep the current runner tests green and do not
claim those three rows covered until that protocol has a separate design,
red tests, independent review, and both-platform evidence.

The production coordinator gets no test bypass. Any new seam is `cfg(test)`,
append-only, and cannot alter a transition or manufacture a proof.
