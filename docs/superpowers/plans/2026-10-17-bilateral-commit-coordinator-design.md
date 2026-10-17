# Bilateral durable commit coordinator — review note

## Boundary

`PreparedBilateralCommit` is crate-private, move-only, and exists only
between a completed pairing authority and the coordinated durable transition.
Production preparation *consumes* `HandshakeCompletePendingAuthority` into
this type, so the raw authority is unavailable after preparation. It must not
implement `Clone`, `Copy`, `Serialize`, `Deserialize`, `Debug`, or expose raw
token, pin, capability, handoff, authority, or receipt getters. The
coordinator may use it only through narrow once-only methods: stage an
inactive record, exchange the Task 3 proof, freeze the same reservation,
finalize exactly, confirm exactly, or exact-abort.

It owns one local authority, its `PendingRecord`, the canonical prepared
receipt, and the exact transaction/guard values needed for local cleanup. It
never contains a runtime or operational capability.

## Live-reservation state machine

Inside production preparation, `ConsentScope::reserve_live(revoker)` moves
the active scope into one private reservation. It returns a crate-private,
move-only `PreparedAdmissionHandoff` owned by `PreparedBilateralCommit`; it
holds the *armed exact* revoker and opaque token while the scope remains live.
This low-level scope operation is test-only outside the preparation boundary.
`PreparedAdmissionHandoff` must not implement `Clone`, `Copy`, `Serialize`,
`Deserialize`, or `Debug`, and it has no raw token, pin, or capability getter.

Only the `PreparedBilateralCommit` that owns that handoff may derive the
`AwaitingHandoff` receipt used for staging. This binds staged ownership to the
same reservation without letting callers copy or substitute a token. It stages
once; repeated stage/exchange/freeze/finalize calls fail closed. Its private
phase machine is:

`Prepared → Staged → ProofVerified → Frozen → Finalized → Confirmed`, with
`Aborted` reachable only through exact cleanup. `ProofVerified` contains the
non-forgeable authenticated Task 3 peer proof, not a boolean or a test flag.
`freeze_once` requires that stored real proof, and `finalize_once` accepts
only the `Frozen` phase produced from it. Dropping the endpoint while this
state is live exact-revokes the reservation and its staged receipt. A stale
prepared commit whose endpoint was dropped is therefore unable to finalize
after a fresh same-peer retry. A standalone reservation test proves only that
the fresh record remains staged; paired proof/freeze/finalize is covered by
the coordinator's real two-endpoint test and is never modeled as unilateral
promotion.

## Safe order

1. Preflight both live authorities concurrently, without a store lock.
2. Derive both canonical `PreparedBilateralCommit` values and verify their
   transaction IDs agree before either store changes. Each owns an
   `AwaitingHandoff` receipt with a `Prepared` bilateral record, while its
   authenticated pairing channel is still live.
3. Stage A then B with short synchronous store calls. The durable checkpoint
   is `AwaitingHandoff + Prepared`; neither side has a pin, snapshot, or
   operational preflight lease.
4. Exchange the Task 3 authenticated proofs over the still-live pairing
   channels. A close, timeout, malformed frame, or mismatch is an error.
5. Freeze both authorities concurrently only after proofs verify. Then
   finalize A then B as `StoreOwnedAwaitingPeer`, using the move-only handoff
   for each exact local receipt.
6. Confirm A then B using that side's exact attempt, transaction ID, local
   receipt hash, and peer proof hash. A coordinator success requires both
   confirmations.
7. On every error after a stage, exact-abort only that local transaction using
   its attempt, transaction ID, and guard token. Do not revoke a peer or
   touch a different attempt. The best-effort remote abort is never treated
   as confirmation.

No ledger, consent, or filesystem lock may be held across a pairing await.
The endpoint remains under its watcher until the finalization exchange is
complete; a coordinator never converts a transport closure into proof.

## Checkpoints required by the test seam

The test-only seam is a passive, append-only observer around the same private
production core; it is neither a production bypass nor an alternate storage
transition. It records immutable checkpoints only after actual durable or
transport transitions: preflight, A staged, B staged, Task 3 proof verified,
both freezes, A finalized, B finalized, A confirmed, B confirmed, and exact
aborts. An injected fault can fire only after its recorded boundary.

Endpoint-fault variants own and actually drop the real provisional endpoint
and watcher at the named preflight or staging boundary. They must not simulate
transport loss by changing a store enum. The success test must demonstrate
that Task 3 precedes either freeze, then inspect both durable records as
reciprocal `BilateralConfirmed` records with the same transaction ID and
opposite receipt hashes. For every injection both stores must have no active
pin or snapshot, and a fresh same-peer attempt must prepare and finalize
normally despite stale cleanup from the failed coordinator.
