# Bilateral operational handshake implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: executing-plans, inline TDD. The parent owns independent review and further authorization.

**Goal:** Consume exactly49e7137 on the sealed75b2ebc transport, reaching durable quarantined handshake completion while authority/promotion/admission remain blocked.

**Architecture:** Independent Rust raw-ingress guards enforce candidate/control ordering before the crypto coordinator mutates. A single owned QUIC/TLS connection supplies both actual identities and one shared exporter; all streams remain private. The coordinator signs fresh messages with its installed identity, pauses for transcript-bound local confirmation, and uses existing PendingStore/journal CAS before finalization emission.

**Tech Stack:** Existing Rust/quinn/rustls/ring, canonical codec, DerivedKeys/EvidenceContext/SasSession and Unix PendingStore. No reference Python import or new cryptographic primitive.

**Spec:** Git object49e7137d4448f3bfef30b5f1de08dc0e7fdc1365: tools/pairing_reference_v2/HANDSHAKE-INTEROPERABILITY.md, reference.py and vectors/handshake-v01-operational.json. Existing design f790167d and finalizer/journal durability rules apply.

## Global constraints

- Default-off feature; no RecoveryAuthority provider, active trust persistence, promotion, admission, input, clipboard, UI, push, merge, CI, sign or publication.
- Parent clarified one QUIC/TLS connection per attempt. Both candidate bidi streams live there; requester B may be QUIC server. Never use a second connection/exporter.
- Exact candidate sequence: A request, B response, B response FIN; B request, A response, A response FIN. Late candidate events also abort.
- Control magic CSF12H2\\0; version2; 20-byte header; type1..11; direction1/2; u32be global sequence; nonempty payload<=16384.
- All raw ingress errors latch terminal abort and derive RESET_STREAM+STOP_SENDING0x43534612. Authenticated Cancel is distinct and does not acquire protocol-error actions on later input.
-17-message schedule frozen by fixture, then bilateral half-close. No state revival after success/error/cancel.
- Actual observed leaves must independently match CandidateHello and canonical Hello. Hello retains SHA256(CandidateHello), never local-binding hash.
- Shared exporter label EXPORTER-ControlShiftF12-Handshake-v2, exact canonical context. Local connection IDs/generations remain local.
- Before local Commit/CommitAck/Complete emission, existing journal persist/CAS/flush must succeed. Failure emits none; pending evidence remains quarantined/tombstoned according to existing rules.
- Native inventory gate: parent independently reproduced exact75b2ebc test binary PASS on active-display m2-24gb; zero-display failures on sleeping-display hosts were diagnosed separately. Do not change the native test.

## Task1 — frozen oracle and raw fail-stop framing

Files: tests/fixtures/pairing-v2/handshake-v01-49e7137.json (exact test-only JSON), src/pairing_v2/handshake_wire.rs and its tests.
Interfaces: internal Envelope{kind:u8,direction:u8,sequence:u32,payload:Vec<u8>}; WireGuard::receive_bytes(raw,validate) owns decode, validates payload before sequence advance; half_close(role); CandidateGuard raw request/response/FIN ingress. Guards expose terminal status/actions, never admission.

- [x] Test all17 envelopes decode/re-encode byte-for-byte against external JSON; literal independent header parser cross-check.
  `assert_eq!(Envelope::decode(&raw)?.encode()?, raw);`
- [x] Test each truncation, trailing byte, oversized length, type/direction/version mutation poisons raw ingress; valid later bytes cannot revive it.
  `assert!(!guard.receive_bytes(&bad, |_| true)); assert_eq!(guard.actions(), ERROR_ACTIONS);`
- [x] Test exact global candidate schedule, wrong requester/responder, duplicate/earlyFIN, completed-state extra events and no revival.
- [x] Run RED using failing stubs, implement bounded internal codec/guards, rerun GREEN. Record fixture SHA and provenance, never consume fixture in shipping code.

## Task2 — general crypto coordinator, not fixture equality

Files: src/pairing_v2/handshake_binding.rs, handshake_evidence.rs and handshake_machine.rs; minimal private helper changes in primitives/session/evidence as needed; test-only deterministic material.
Interfaces: coordinator owns observed certificates, role, canonical candidate records, local signing key and fresh entropy; receive_bytes delegates fail-stop parsing then phase validation; local outbound evidence is built from runtime transcript. VerificationView binds attempt/T/generation and four words; explicit confirm(view,matches) gates local Approval.

- [x] Compare frozen fixture commitments, transcript, proof/approval/finalization signatures/MACs and FC, using fixture secrets only in tests.
- [x] Reject swapped observed leaves, wrong certificate, changed Hello candidate hash, reveal before both commitments, signature/MAC/role/attempt/T/counter substitutions.
- [x] Require explicit local confirmation after both proofs. False/stale/wrong-generation confirmation aborts; neither one-sided approval nor fixture equality authorizes input.
- [x] Implement signed/MACed Cancel exactly cancel-body-v1/wire-cancel-v1 after proofs; early/invalid Cancel is protocol error.
- [x] Run tests RED→GREEN and keep every primitive from the frozen canonical contract.

## Task3 — controlled QUIC adapter with sealed ownership

Files: src/pairing_v2/provisional_tls.rs and private handshake I/O child; no public raw connection getter.
Interfaces: owned channel creates handshake driver bound to its private connection, local generation, scope and process replay owner; bounded raw ingress buffers and transport error sink are internal. A typed confirmation channel reports/accepts only the current verification view.

- [x] Real loopback tests perform the exact two candidate stream schedule and single A control stream. Check actual endpoint leaves and real exporter on both endpoints using identical shared context.
- [x] Substitute a second TLS channel/exporter and reject; selected channel capability is not injectable.
- [x] Fragment at every header boundary and representative body boundaries; trailing/oversize/drop/early FIN/extra stream/wrong role/order/replay cause both RESET and STOP with exact error code.
- [x] Implement serialized send/receive phases and authenticated Cancel without inventing ACKs, outer envelopes or stream roles. No simultaneous duplicate handshake can consume the same selected capability.

## Task4 — durability before emission and safe terminal

Files: handshake coordinator/driver plus private journal adapter using existing pairing_pending.rs and journal.rs; test fault hooks confined to test builds.
Interfaces: PendingStore version/prepare/persist_pairing_journal govern all local generations/CAS/tombstones. Completion type HandshakeCompletePendingAuthority has no conversion to active trust or PeerSession.

- [x] For each local finalization emission, inject failure before/after journal write/flush/manifest publish and before/after stream write. Assert no emission unless required durable record validates.
- [x] Child-process crash schedules reopen stores and require fresh SAS when no authoritative recovery provider exists; never resurrect input/admission.
- [x] Preserve signed evidence after irreversible finalization boundaries; pre-finalization abort cancels pending safely. Corruption/CAS/tombstone mismatch fails closed with no cleanup.
- [x] Assert both FCs+both FINs required for safe terminal and any later non-Cancel event changes to terminal protocol failure.

## Task5 — independent bytes, two processes, adversaries and handoff

Files: integration tests and docs/qa/bilateral-handshake evidence.
- [x] Run Rust independent parser against all49e fixture bytes, comparing independently decoded header schedule and crypto outputs; no shipping reference import.
- [x] Run two separate OS processes with fresh identities/keys and scripted local confirmation; prove same SAS, exact FC and PendingAuthority-only completion.
- [x] Executed mutants remove individual observed-leaf, nonce, candidate-hash, sequence, Cancel-MAC, signer-identity, durability, RESET, STOP and postcompletion monitor checks; 11/11 RED for intended assertions, restored. Exporter/confirmation are covered by vectors and negatives, not claimed as separate executed mutants.
- [x] Run default/experimental workspace, both clippy modes, fmt/diff; default 219 PASS / 1 native-display FAIL / 2 ignored; experimental 348 PASS / 1 same FAIL / 4 ignored. Both clippy modes, fmt/diff PASS. Native failure preserved, not waived into green; parent baseline awake-display evidence separate.
- [x] Preserve this delta in a local commit with exact evidence/gaps for independent review; no next phase or integration. See `docs/qa/bilateral-handshake-evidence.json` and `docs/bilateral-handshake-boundary.md`.
