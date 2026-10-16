# Provisional transport boundary implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: executing-plans, task-by-task TDD. This assigned implementer executes inline; parent owns independent review.

**Goal:** Consume only the reviewed dc3750b CandidateRequest/framing/ALPN/exporter/replay contract against real QUIC while keeping unreviewed handshake envelopes and recovery disabled.

**Architecture:** Default-off transport modules separate bounded framing, immutable observed-connection binding and strict provisional TLS configuration. Provisional channels are not PeerSession or admission. The typed setup controller closes at HandshakeEnvelopePending; no application publisher or handshake emitter is connected.

**Tech Stack:** Existing Rust, quinn 0.11/rustls 0.23/ring, strict phase2 certificate validator, canonical TLV codec, tokio. No new crypto or dependencies.

**Spec:** reference worktree tools/pairing_reference_v2/TRANSPORT-INTEROPERABILITY.md and vectors/transport-v01-operational.json at dc3750b; design f790167d. Parent narrowed phase5 explicitly: do not invent type3 envelopes, bilateral stream order or shared connection IDs/generations. recovery-authority/1 MUST NOT consume/persist/emit.

## Constraints

- ALPN exactly `csf12-pair/2`; exporter label exactly `EXPORTER-ControlShiftF12-Pairing-v2`, 32 bytes, exact frozen canonical context.
- Frame magic `CSF12P2\0`, u16be version2, u8 type, u32be length; limits1024/4096/16384. Complete-frame trailing bytes reject; stream adapter requires one record and EOF, one absolute deadline, no unbounded allocation.
- Actual leaf DER comes from selected QUIC connection, never the CandidateHello claim. Local opaque connection ID and local generation remain local; no symmetric exporter assumption.
- Fresh connections/scopes after restart; no durable recovery bootstrap or protocol and no authority data imported into consumer fixture.
- Feature off, no application advertising/listening/legacy fallback/active trust/input/clipboard. Windows app remains unsupported until separate persistence gate. No push/merge/CI/sign/publish.

## Task 1 — exact request and bounded framing

Create `crates/transport/src/pairing_v2/operational_wire.rs`, tests `pairing_v2_operational_wire.rs`, fixture containing only reviewed transport fields (explicitly excluding recovery_authority).

Interfaces: `CandidateRequest::decode/encode`, `FrameKind`, `TransportFrame::encode/decode`, `read_record<R: AsyncRead + Unpin>(reader, deadline)`; malformed/oversize records return Invalid before body allocation/state.

- [x] Tests first: fixture request/frame byte equality, version bool rejected, ALPN mismatch, 15/17-byte fields; all truncation positions and trailing-byte/second-frame rejection; limits by type; fragmented stream produces no partial success and premature EOF/drop reject.
  `assert_eq!(TransportFrame::decode(&fixture_frame)?.encode()?, fixture_frame);`
- [x] Run `cargo test -p seamless-transport --features pairing-v2-experimental --offline --test pairing_v2_operational_wire` RED; implement only approved grammar; rerun GREEN.
- [x] Keep type3 payload opaque at frame layer; no invented signature/MAC envelope. Include in the final verified slice commit.

## Task 2 — observed channel binding and strict real TLS

Create `operational_binding.rs` and `provisional_tls.rs`; tests `pairing_v2_provisional.rs`. Export only feature-gated types.

Interfaces: immutable validated request/hello context prepares exact exporter bytes; `LocalBinding` derives frozen digest/replay token from supplied exporter output (fixture-level primitive, not an admission capability). Shared mutex replay registry consumes after all validation; capacity/poison fail closed. `ProvisionalChannel` reads exact negotiated ALPN, actual peer leaf and real exporter from its owned quinn Connection; no caller-supplied leaf/exporter. Strict TLS config uses existing Ed25519 profile and real TLS CertificateVerify, one certificate per peer, mutual provisional client cert, no active pins.

- [x] Tests first: frozen context/binding/token literal equality, each binding substitution changes/rejects; invalid request/hello never consumes registry; two instances and concurrency one winner.
- [x] Test strict certificate rejection and exact ALPN on real loopback QUIC; independently recompute real exporter via quinn and compare, verify a repeated selected-connection binding is rejected. Test frame fragmentation/drop/oversize on actual streams and two-process loopback.
- [x] Implement only enough to satisfy these tests. Keep immutable local connection ownership/generation and prohibit reusing a consumed channel binding. No Hello hash replacement.
- [x] Mutants for observed leaf, nonce/rendezvous, ALPN, exporter label/context, replay consumption, frame bounds/trailing must RED; restore and include in the final verified slice commit.

## Task 3 — truthful closed UI boundary and verification

Update `apps/seamless-input/src/guided_setup.rs`, typed fixture/tests and docs. No live app connection yet because stream choreography and type3 envelopes are not frozen.

- [x] Change tests first to expect `HandshakeEnvelopePending` after valid selection, zero authenticated sessions and all admission flags false. Confirm `compare_match` remains InvalidState, restart does not use recovery, default feature remains absent.
- [x] Rename the closed gate/status and document that approved local transport primitives are available but E2E first pairing is not implemented in this narrowed slice.
- [x] Full default+experimental workspace (including existing192 fault schedules), clippy both, fmt/diff; record raw mutants and explicit lack of new operational FC/crash claims.
- [x] Commit cleanly, hand off exact SHAs/evidence and independently reviewed bilateral-envelope dependency. Preserve worktree and all no-release gates.

## Execution outcome

Restricted slice completed inline. Full first-pair operational phase5 is not
completed: type3/bilateral choreography stays blocked. No later reference was
consumed. See `docs/provisional-transport-boundary.md` and its raw QA evidence.
Fresh baseline had 292 experimental passes; final has 308. Thirteen mutants
were individually restored and killed by assertions; both full suites/clippy
modes and formatting passed. The final commit preserves this isolated branch
for parent-owned independent review; no integration or publication is requested.
