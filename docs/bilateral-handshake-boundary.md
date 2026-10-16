# Experimental bilateral handshake boundary

This delta consumes the reviewed **49e7137d4448f3bfef30b5f1de08dc0e7fdc1365** wire on the sealed **75b2ebc** transport. It is an internal implementation candidate, not release approval. The default feature is unchanged/off. The application/controller gate remains fail-closed until independent review; native UI is not connected.

## Inputs and ownership

`ProvisionalChannel::handshake(self, HandshakeConfig, &PendingStore, confirm)` consumes one non-Clone channel minted by `ProvisionalEndpoint`. It cannot adopt a caller's `quinn::Connection`, TLS config, replay registry, observed leaf, exporter, connection ID or generation. Both logical candidate requesters and the single A-initiated control stream use that same private connection. Role A is the lower full-certificate fingerprint, independently of which endpoint is the QUIC client.

The installed local certificate/key is obtained from the same strict TLS configuration; the remote DER comes from QUIC's actual peer identity. Both are checked against CandidateHello and canonical Hello. TLS remains 1.3, mutual certificate possession, exact Ed25519 profile and ALPN, with no 0-RTT/resumption/tickets. Possession is not user identity approval. The process-owned replay registry is mandatory and not injectable.

An invariant also checks the connection's stable ID against the sealed owner metadata before candidate I/O and subsequent local state advancement. A test-only second-TLS substitution rejects before SAS or store mutation; exporters with the same label/context differ between those independent connections. No public exporter substitution port exists.

The transport budget permits two concurrent bidi streams per initiator: A's still-open candidate request half and A's control stream require this. Every stream outside the reviewed schedule is rejected. Keepalive allows a human to use the five-minute overall window without turning idle transport into implicit approval. Completed candidate exchange must have elapsed less than 30 seconds; individual network phases have 30-second timeouts, so an incomplete exchange can retain resources longer than 30 seconds. The overall attempt is bounded to 300 seconds. OS `Instant` provides monotonic elapsed time; each run has a random process-local epoch in its journal. This epoch is **not a claim to expose the OS boot UUID**, and it cannot authorize recovery.

## Exact wire, user decision and terminal state

The candidate sequence is A request / B response / B response FIN, then B request / A response / A response FIN. No requester FIN requirement was invented. Its receive half remains watched; any extra DATA rejects the attempt. The single shared exporter uses `EXPORTER-ControlShiftF12-Handshake-v2` and the frozen canonical context. Connection IDs and generations are local metadata, not a claimed shared wire field. Hello retains the exact CandidateHello SHA-256, never a local-binding digest.

The raw control parser checks the 20-byte header and the exact 17-event global schedule before applying phase-specific canonical decoding and cryptographic checks. It then requires both FC records and both FINs. Commitments precede reveals; key proofs precede the four-word SAS and the user gesture. `VerificationPrompt` contains names, full fingerprints, attempt, transcript, UI generation and four words. The callback must return the same attempt/transcript/generation. There is no default approval, QR, legacy fallback or manual-word transcription in this path.

An authenticated signed/MACed Cancel is distinct from a protocol error. Every other rejection invokes real `RESET_STREAM` and `STOP_SENDING` with `0x43534612`, closes the attempt and cannot revive it. The pure guards and live transport both reject duplicates, replay, wrong order/direction, early FIN, malformed/oversized/trailing records and downgrade. Bounded fragment assembly is allowed; a fragment presented as a complete raw record is not.

`HandshakeCompletePendingAuthority` has a private constructor and retains the sealed connection/request half. A private task continues watching late candidate DATA and extra streams. `is_protocol_valid()` becomes false after violation or connection closure; `durable_fc_hash()` then returns None. This is **not** an authenticated application session. The durable journal may remain as historical quarantined evidence even when the live result becomes invalid. Dropping the result closes the channel. The two-process harness holds each endpoint alive until the other process finishes via an out-of-band test acknowledgement; this acknowledgement is not pairing wire.

The default-off admission foundation consumes that pending authority through a
single watcher-owned freeze transition before durable publication. The watcher
gives queued request DATA and extra streams priority over the freeze request. If
a violation wins, publication is rejected. If freeze wins, it closes pairing
QUIC and returns move-only `FrozenPromotionEvidence` with no channel, stream or
runtime capability; only then may the transactional manifest be written. This
watcher decision is the protocol linearization point. It holds no synchronous
or asynchronous lock across filesystem I/O, so a store stall cannot deadlock or
starve violation detection. A post-freeze peer send is transport-rejected, not
an unobserved protocol event. Durable `PromotionReceipt` remains metadata only
and cannot authorize input, clipboard, topology or a session.

## Durability and failure

After both signed approvals, `PendingStore::prepare` creates only physically separate pending evidence. The existing CAS/revision/identity-generation/tombstone checks govern each write. Before returning local Commit, CommitAck or Complete bytes to the I/O adapter, the role-specific `Finalizer` must persist and flush its journal and manifest. Storage failure latches failure and returns no bytes to emit. No retry refreshes a failed CAS behind the caller's back.

Ordinary precommit abort discards pending via the original expected version. Once a local durable decision exists, evidence stays quarantined. A storage failure or conflicting/corrupt manifest causes no cleanup. Process death/outer future cancellation may leave inert pending evidence for explicit reconciliation; this does not confer trust. A fresh retry creates fresh nonces, ephemeral keys and a new SAS. This driver never loads a RecoveryAuthority, never invokes a recovery shortcut and never promotes a peer. A secure Windows `PendingStore` backend is present, but its exact native MSVC behavior remains unmeasured in this evidence set; every platform remains fail-closed.

Session and emitter share one reference-counted `DerivedKeys` allocation, whose secret arrays are zeroizing. The emitter reference lives only through the bounded control attempt, including authenticated Cancel, and is cleared on terminal state. No secret keys/exporter bytes are written to the journal or logs.

## Evidence and limits

The test-only external JSON is copied byte-for-byte, not imported as product code:

`crates/transport/tests/fixtures/pairing-v2/handshake-v01-49e7137.json`

SHA-256: `4402bf351399c094e68ee3f6fbe747c54c47da43c254e233048e9ee753ad1438`.

An independently written Rust header/parser and general crypto implementation reproduce all 17 Python-reference records. Synthetic deterministic private keys exist only in tests. Live tests create fresh identities and ephemeral material, run real QUIC/TLS/exporters over loopback, compare both SAS/transcripts and FC, and use two separate OS processes.

Fault evidence is deliberately separated:

- 96 subprocess schedules inject I/O error or real process exit at eight actual write/fsync/rename/directory-fsync boundaries, separately for journal and manifest, before role A Commit, role B CommitAck and role A Complete. They assert no bytes are returned for emission. These are actual filesystem fault/crash tests, not simulated state transitions.
- Separate subprocess deaths before and after the real QUIC `write_all` boundary test the local emission window. “After write” means handed to QUIC; it does not prove delivery to the remote process.
- The loopback mutation matrix exercises fragmentation and malformed/reordered/duplicate/early-close records. These are not packet-loss, real-LAN interference or power-loss durability measurements.
- RESET and STOP are also observed independently on real streams while the connection stays open, so connection-close does not mask a missing action.

Pending gates: independent security/code review of this exact delta; external cryptographic audit; native macOS/Windows interop; real LAN and OS permission/network-policy behavior; exact native Windows persistence validation; UI integration; authoritative recovery and a separately authorized admission/promotion phase. No active trust, input or clipboard was implemented here.

The parent supplied separate baseline evidence: exact 75b2ebc display-probe binary passed on m2-24gb with an active graphical display; failures on sleeping-display hosts were a host-state condition. This is external baseline evidence, not a new native-display measurement by this delta.
