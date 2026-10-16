# Guided operational boundaries implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement task-by-task. The assigned implementer works inline; independent review is coordinated by the parent task.

**Goal:** Compose consent-gated discovery, an OS monotonic clock and a typed private UI/control surface without enabling an undefined pairing wire protocol.

**Architecture:** Experimental modules are default-off. A bounded discovery catalogue owns its consent window, locators and opaque local handles. The application controller owns the OS clock and typed commands; selecting a locator reaches an explicit closed transport-contract gate, never legacy pairing or runtime admission.

**Tech Stack:** Existing Rust workspace, mdns-sd 0.21, std::time::Instant, serde, current private inherited-pipe IPC. No new cryptographic primitive or downloaded dependency.

**Spec:** pairing-topology-ui-design.md SHA256 f790167d…; phase3 e357669; parent phase4 narrowing: discovery/clock/typed UI and fail-closed composition allowed; wire emission/ALPN/framing/exporter and recovery bootstrap disabled pending independent addendum.

## Global constraints

- Default feature off: pairing-v2-experimental.
- No active pins, admission, input, clipboard, native UI or automatic legacy fallback.
- Windows operational open fails UnsupportedPlatform before creating any discovery backend.
- Discovery metadata contains opaque fresh per-window rendezvous token, protocol version and pairable flag only; no friendly name, identity certificate, display inventory, SAS or secrets.
- Application catalogue <=20 locators, <=8 addresses per locator, 30-second local freshness, <=32 events drained per poll, <=300-second consent window.
- Missing reviewed listener contract means application advertisement/connection/emission remain disabled; browsing may be explicitly requested during consent. Standalone discovery publisher tests are synthetic fixtures, not an enabled product listener.
- Existing PeerEndpoint and legacy pairing code are untouched.

## Task 1 — bounded consent-owned discovery

**Files:** create crates/discovery/src/guided.rs and tests/guided.rs; modify discovery Cargo.toml/lib.rs for the default-off feature.

**Interfaces:** ConsentCatalog::open(now_ms), observe(Advertisement,now_ms), remove(instance,now_ms), candidates(now_ms), select(CandidateHandle,now_ms), close(now_ms). CandidateHandle contains local window generation and monotonically allocated sequence; SelectedLocator is not identity/admission. GuidedMdns starts browsing only after explicit construction by an opened controller, drains at most 32 events per poll, and stops/shuts down on close/drop. No legacy PeerCache is reused because it is unbounded.

- [x] Write tests first: closed observe/select reject; 21st locator rejects; ninth address rejects; expiry exactly 30 seconds; duplicate refresh keeps one handle; window rollover/rollback invalidate old handles; malformed/private metadata rejected.
  Assertion example: assert!(catalog.select(old_handle,30_000).is_err()).
- [x] Run cargo test -p seamless-discovery --features pairing-v2-experimental --offline --test guided and observe RED before implementation.
- [x] Implement bounds and scoped real mDNS adapter using the installed locked library's APIs; no discovery name/identity lookup.
- [x] Run tests and a real synthetic loopback mDNS round-trip; verify withdraw/drop and no advertisement in browse-only mode. Expose daemon asynchronous errors as unavailable, not health success.
- [x] Commit independently after tests; document mdns-sd internal DNS cache as a dependency boundary (no claimed hard heap cap).

## Task 2 — monotonic clock and typed UI model

**Files:** create apps/seamless-input/src/guided_setup.rs and tests/guided_setup.rs; add application experimental feature propagation and module export.

**Interfaces:** trait SetupClock { fn now_ms(&self)->Result<u64,SetupError>; }; OsSetupClock based on one immutable Instant origin. Typed SetupCommand and SetupSnapshot use serde deny_unknown_fields with explicit errors. Controller commands OpenDiscovery, Refresh, CloseDiscovery, Select, Cancel, CompareMatch are local gestures; no peer bytes can impersonate them. Backend construction is injected for tests; real default is browse-only GuidedMdns.

- [x] Write tests first: construction/snapshot causes no network; explicit open starts one backend; close/cancel/drop/clock rollback destroy it; retry increments generation; selected handle never becomes an authenticated identity; invalid/stale commands cannot reach transport.
  Assertion example: assert_eq!(snapshot.authenticated_sessions,0).
- [x] Add a real OsSetupClock monotonic test without fabricated wall-clock/boot evidence. Recovery wall-clock/boot provider remains unavailable.
- [x] Implement minimal controller and typed view model with pairing_transport=contract_pending, promotion/input/clipboard=false. Only anonymous locator metadata is exposed until authenticated CandidateHello exists.
- [x] Test Unix default and injectable fake backend. On Windows, OpenDiscovery returns UnsupportedPlatform before factory execution.

## Task 3 — private IPC composition and closed transport gate

**Files:** modify apps/seamless-input/src/control_engine.rs; create tests/guided_control_stdio.rs and a frozen typed contract fixture; update docs.

**Interfaces:** feature-gated command pairing.v2 with strictly typed args. Existing request-ID conflict/replay handling remains authoritative. Typed snapshots/events preserve zero authenticated sessions. Select validates freshness/current consent then returns OperationalContractPending; no ALPN, CandidateRequest frame, exporter or generation-bootstrap message is guessed.

- [x] Write child-process tests first for typed snapshot, invalid args/redaction, stale selection, confirm-before-SAS, request replay and no legacy fallback. Default feature retains the existing frozen foundations contract.
- [x] Implement dispatch to the controller; EOF/shutdown drops discovery resources. No NativeSupervisor/IdentityStore writer is introduced.
- [x] Mutate consent/freshness/capacity/generation/transport gate checks separately; require expected assertion RED and restore every change.
- [x] Run default workspace, application experimental workspace (including transport phase3 fault schedules), clippy both modes, fmt and diff checks.
- [x] Commit cleanly; hand off evidence and unresolved gates. No push/merge/CI/sign/publication.

## Explicit blocked dependencies (not implementation discretion)

An independent addendum must freeze CandidateRequest and application framing,
pairing/recovery ALPN values, TLS exporter label/context/output derivation and
the authenticated bootstrap of remote generation expectations. Existing signed
Hello and FC contain no remote generation announcement; treating a first
RecoveryProof as its own expected-generation source would be circular TOFU.
Until those artifacts are reviewed, no live QUIC emitter, durable production
RecoveryAuthority provider or end-to-end operational pairing claim is allowed.
The provider must later atomically consume its durable challenge context with
the phase3 PendingStore proof consumption; separate unsynchronized ledgers are
not an acceptable substitute. Windows secure persistence is a separate agent's
scope and is not modified here.
