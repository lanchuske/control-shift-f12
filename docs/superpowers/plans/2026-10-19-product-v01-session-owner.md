# Product V01 Session Owner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a sealed product owner for fresh V01 verification after G4 pairing while keeping inventory, layout, input, and clipboard unavailable.

**Architecture:** The transport crate owns a persistent G4 identity and all provisional/V01 endpoints. The app crate coordinates redacted operational discovery and single-use UI consent through opaque handles; successful V01 completion emits metadata only and never exports a connection or enables a capability.

**Tech Stack:** Rust 2024, Tokio, Quinn/rustls, rcgen, platform-private filesystem helpers, mDNS, serde, existing `ui_stdio_v1` framing.

**Spec:** `docs/architecture/product-v01-session-owner.md`

## Global Constraints

- The private key never leaves `seamless-transport` and is never serializable, loggable, or projected over UI IPC.
- Pairing and V01 use the same persistent leaf identity; existing ephemeral-identity admissions are not migrated.
- The only V01 wire is `csf12-operational/1`; no pairing/legacy downgrade or connection export is allowed.
- V01 has one absolute 30-second attempt deadline and one local decision per side.
- V01 success enables no inventory, layout, input, clipboard, or sharing capability.
- Every failure clears volatile state and keeps `CapabilityView::all_disabled()`.
- Tests are written and observed failing before production changes.
- No signing, release, physical QA, or runner/LMCP mutation belongs to this plan.

---

### Task 1: Persistent sealed G4 identity

**Files:**
- Create: `crates/transport/src/pairing_v2/product_identity.rs`
- Modify: `crates/transport/src/pairing_v2/mod.rs`
- Test: `crates/transport/src/pairing_v2/product_identity.rs`

**Interfaces:**
- Produces: `pub struct ProductIdentity` with `open_or_create(root: &Path) -> Result<Self, ProductIdentityError>`, `fingerprint(&self) -> [u8; 32]`, `bind_pairing(&self, SocketAddr) -> Result<ProvisionalEndpoint, Invalid>`, and feature-gated `bind_operational(&self, SocketAddr) -> Result<ProductOperationalEndpoint, Invalid>`.
- The type exposes no certificate or private-key accessor and implements neither `Clone`, `Serialize`, nor `Deserialize`.

- [ ] **Step 1: Write failing identity persistence and privacy tests**

  Add unit tests that open a temporary owner-only root twice, assert an identical nonzero fingerprint, assert the identity file is not group/world accessible on Unix, reject a symlink identity path, and use compile-fail documentation to prove no `private_key`/serialization API exists.

- [ ] **Step 2: Run the focused tests and verify RED**

  Run: `~/.cargo/bin/cargo test -p seamless-transport --features pairing-v2-g4, pairing-v2-operational-experimental product_identity -- --nocapture`

  Expected: compilation fails because `product_identity` and `ProductIdentity` do not exist.

- [ ] **Step 3: Implement the minimal sealed store**

  Store exactly `{version:1, certificate_der, protected_private_key_der}` in `identity-v1.json`. Generate one Ed25519 key and the strict `urn:control-shift-f12:identity` leaf profile. Reuse the repository's platform-private directory/file primitives; validate owner-only state and reject symlink/reparse substitution before every load or creation. Construct endpoints internally from cloned protected bytes only after successful validation.

- [ ] **Step 4: Run the focused tests and transport suite**

  Run the Step 2 command, then `~/.cargo/bin/cargo test -p seamless-transport --features pairing-v2-g4, pairing-v2-operational-experimental`.

  Expected: all tests pass.

- [ ] **Step 5: Commit**

  ```bash
  git add crates/transport/src/pairing_v2/product_identity.rs crates/transport/src/pairing_v2/mod.rs
  git commit -m "feat(transport): persist sealed G4 identity"
  ```

### Task 2: Make G4 admissions use the persistent identity

**Files:**
- Modify: `apps/seamless-input/src/g4_pairing.rs`
- Modify: `apps/seamless-input/src/product_pairing_adapter.rs`
- Test: `apps/seamless-input/tests/g4_two_processes.rs`

**Interfaces:**
- Consumes: `ProductIdentity::open_or_create` and `ProductIdentity::bind_pairing` from Task 1.
- Produces: `RealG4Backend` owns one `Arc<ProductIdentity>` for its lifetime; every new provisional endpoint is created from it.

- [ ] **Step 1: Write a failing restart identity test**

  Extend the deterministic two-process helper to pair two roots, stop both backends, reopen them, and assert through a test-only redacted fingerprint probe that each reopened backend has the same local fingerprint committed during pairing. Also assert that replacing either identity file makes the old relationship incompatible rather than silently usable.

- [ ] **Step 2: Run the test and verify RED**

  Run: `~/.cargo/bin/cargo test -p seamless-input --features pairing-v2-g4,g4-test-helper --test g4_two_processes persistent_identity_survives_pairing_restart -- --exact --nocapture`

  Expected: the test fails because `RealG4Backend` still calls `ProvisionalEndpoint::bind_ephemeral`.

- [ ] **Step 3: Wire the persistent identity**

  Open `g4-identity` beside `g4-admission` in `RealG4Backend::open_with_initial_snapshot`, retain it in the backend, and replace `bind_ephemeral` with `identity.bind_pairing`. Map identity/store failures to `SetupError::Unavailable`; never fall back to an ephemeral identity.

- [ ] **Step 4: Verify the focused and existing G4 tests**

  Run the Step 2 command and then:

  ```bash
  ~/.cargo/bin/cargo test -p seamless-input --features pairing-v2-g4,g4-test-helper --test g4_two_processes
  ~/.cargo/bin/cargo test -p seamless-input --features pairing-v2-g4 --test ui_stdio_adapter
  ```

  Expected: all deterministic tests pass; the mDNS physical test remains a separate environment check.

- [ ] **Step 5: Commit**

  ```bash
  git add apps/seamless-input/src/g4_pairing.rs apps/seamless-input/src/product_pairing_adapter.rs apps/seamless-input/tests/g4_two_processes.rs
  git commit -m "fix(g4): retain pairing identity for operational verification"
  ```

### Task 3: Bounded operational locator catalogue

**Files:**
- Create: `apps/seamless-input/src/product_operational_discovery.rs`
- Modify: `apps/seamless-input/src/lib.rs`
- Modify: `crates/discovery/src/lib.rs`
- Test: `apps/seamless-input/tests/product_operational_discovery.rs`

**Interfaces:**
- Produces: `OperationalAdvertisementLease::start(port: u16)`, `OperationalCatalogue::open(now_ms: u64)`, `poll(now_ms)`, and `select_once(handle, now_ms) -> SelectedOperationalLocator`.
- `SelectedOperationalLocator` is move-only and readable only by the V01 coordinator; UI sees `RelationshipHandle` only.

- [ ] **Step 1: Write failing privacy, expiry, and replay tests**

  Cover exact service/version parsing, random opaque handles, TTL expiry, selection once, candidate replacement, self-filtering, bounded address count, unknown TXT rejection, and prove serialized UI frames contain none of `address`, `port`, `certificate`, `pin`, `locator`, or `receipt`.

- [ ] **Step 2: Run the new test and verify RED**

  Run: `~/.cargo/bin/cargo test -p seamless-input --features pairing-v2-g4, pairing-v2-operational-experimental --test product_operational_discovery -- --nocapture`

  Expected: compilation fails because the operational discovery types do not exist.

- [ ] **Step 3: Implement the bounded catalogue and lease**

  Use a service type distinct from pairing discovery, TXT exactly `v=1`, a fresh 16-byte locator, the OS-assigned port, the existing address/TTL caps, and single-use opaque handles scoped to a catalogue generation. The selected locator must not implement `Clone`, `Serialize`, or `Deserialize`.

- [ ] **Step 4: Run discovery and repository contract tests**

  Run the Step 2 command plus `./scripts/check-public-repository.sh`.

  Expected: all tests pass and no private/evidence material is tracked.

- [ ] **Step 5: Commit**

  ```bash
  git add apps/seamless-input/src/product_operational_discovery.rs apps/seamless-input/src/lib.rs crates/discovery/src/lib.rs apps/seamless-input/tests/product_operational_discovery.rs
  git commit -m "feat(g4): add private operational locator catalogue"
  ```

### Task 4: Sealed product V01 coordinator

**Files:**
- Create: `crates/transport/src/pairing_v2/product_operational.rs`
- Modify: `crates/transport/src/pairing_v2/mod.rs`
- Modify: `crates/transport/src/pairing_v2/operational_session.rs`
- Test: `crates/transport/src/pairing_v2/product_operational.rs`

**Interfaces:**
- Consumes: persistent identity, selected private locator, opaque durable relationship lookup, and the existing sealed `OperationalAttempt`.
- Produces: `ProductOperationalAttempt::connect`/`accept`, `prompt() -> OperationalPrompt { words, remaining_ms }`, `decide(matches)`, and terminal `OperationalOutcome::{Verified,Rejected,Expired,Revoked,RemoteOutcomeUnknown}`.
- No API exposes `OperationalChannel`, `OperationalAttempt`, QUIC streams, exporter bytes, transcript hashes, commitments, pins, addresses, or durable attempts.

- [ ] **Step 1: Write failing two-endpoint consent tests**

  Create two persistent identities and real admission stores, establish matching durable admissions with the existing test authority, then assert: same four display words; two independent approvals required; mismatch/one-sided/late/duplicate decisions fail; restart cannot resume; pin/revision/identity changes fail; success returns only `Verified` and closes the endpoint.

- [ ] **Step 2: Run the focused tests and verify RED**

  Run: `~/.cargo/bin/cargo test -p seamless-transport --features pairing-v2-g4,pairing-v2-operational-experimental product_operational -- --nocapture`

  Expected: compilation fails because the product coordinator does not exist and `LocalOperationalConsent` has no production constructor.

- [ ] **Step 3: Implement the single-use consent bridge**

  Keep `OperationalAttempt` crate-private. Let it provide the coordinator a redacted prompt derived from the exact preconfirm/commitment tuple and accept a decision only through a private one-shot channel owned by that attempt. Construct `LocalOperationalConsent` only after a current affirmative local decision. Close/reset on every other terminal path and zeroize transient bindings.

- [ ] **Step 4: Run operational mutation and transport suites**

  Run the Step 2 command, the complete transport suite with both features, and `python3 scripts/test-operational-session-reference.py`.

  Expected: all tests and the frozen reference pass.

- [ ] **Step 5: Commit**

  ```bash
  git add crates/transport/src/pairing_v2/product_operational.rs crates/transport/src/pairing_v2/mod.rs crates/transport/src/pairing_v2/operational_session.rs
  git commit -m "feat(transport): own sealed product V01 attempts"
  ```

### Task 5: Redacted UI V01 integration

**Files:**
- Modify: `apps/seamless-input/src/g4_pairing.rs`
- Modify: `apps/seamless-input/src/ui_stdio_adapter.rs`
- Modify: `apps/seamless-input/src/ui_controller.rs`
- Modify: `apps/seamless-input/src/ui_contract.rs`
- Test: `apps/seamless-input/tests/ui_stdio_adapter.rs`
- Test: `apps/seamless-input/tests/g4_two_processes.rs`

**Interfaces:**
- Adds host request `ui.v01.begin { relationship: RelationshipHandle }`.
- Adds engine event `V01Ready { generation, words, remaining_ms }` and terminal redacted outcomes.
- Reuses `ui.confirm_v01 { matches: bool }` and `sas_display_v1`; no sensitive field is added to `ui_snapshot_v1`.

- [ ] **Step 1: Write failing request/state/privacy tests**

  Assert exact argument shape, confirmed-state requirement, current relationship lookup, replay behavior, one active attempt, child-only SAS, absolute expiry, duplicate/stale decision rejection, terminal invalidation frame, no sensitive strings in snapshots/diagnostics/errors, and capabilities disabled before and after `Verified`.

- [ ] **Step 2: Run focused tests and verify RED**

  Run: `~/.cargo/bin/cargo test -p seamless-input --features pairing-v2-g4,pairing-v2-operational-experimental,g4-test-helper --test ui_stdio_adapter product_v01 -- --nocapture`

  Expected: tests fail because `ui.v01.begin` is not in the allowlist and the G4 worker owns no V01 attempt.

- [ ] **Step 3: Wire commands and redacted events**

  Extend strict decoding with exactly one relationship field, route begin/decision to the worker, emit the existing transient SAS frame, and clear it on every terminal path. Represent successful completion as a verified-current diagnostic while retaining `ConfirmedRelationship`, `RelationshipState::Unavailable`, no inventory, and `CapabilityView::all_disabled()`.

- [ ] **Step 4: Run adapter and deterministic two-process tests**

  Run the Step 2 command without the name filter, then the deterministic G4 two-process suite. Verify the exact JSON frame allowlists for both valid and rejected requests.

- [ ] **Step 5: Commit**

  ```bash
  git add apps/seamless-input/src/g4_pairing.rs apps/seamless-input/src/ui_stdio_adapter.rs apps/seamless-input/src/ui_controller.rs apps/seamless-input/src/ui_contract.rs apps/seamless-input/tests/ui_stdio_adapter.rs apps/seamless-input/tests/g4_two_processes.rs
  git commit -m "feat(ui): verify fresh V01 sessions after pairing"
  ```

### Task 6: Cross-platform verification and documentation

**Files:**
- Modify: `docs/architecture/desktop-functional-parity-gate.md`
- Modify: `docs/architecture/discovery-sas-security-matrix.md`
- Modify: `docs/qa/physical-qa-matrix.md`
- Test: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes the completed product V01 behavior from Tasks 1-5.
- Produces CI coverage and a physical-QA checklist that still marks inventory, layout, input, and clipboard `NOT MEASURED`/unavailable.

- [ ] **Step 1: Update architecture status and QA matrix**

  Mark only V01 verification implemented. Record that the closed V01 connection cannot carry application payloads and that successful V01 remains capability-off. Add Mac-to-Windows and Windows-to-Mac rows for restart, same-code visibility, two local approvals, mismatch, expiry, cleanup, and zero lingering processes.

- [ ] **Step 2: Run formatting, lint, tests, and repository guards**

  ```bash
  ~/.cargo/bin/cargo fmt --all -- --check
  ~/.cargo/bin/cargo clippy --workspace --all-targets --features pairing-v2-g4,pairing-v2-operational-experimental -- -D warnings
  ~/.cargo/bin/cargo test --workspace --features pairing-v2-g4,pairing-v2-operational-experimental
  python3 scripts/test-operational-session-reference.py
  ./scripts/check-public-repository.sh
  ./scripts/check-installer-contract.sh
  ```

  Expected: every command passes. Environment-only mDNS or Accessibility gaps must be reported separately and cannot be relabelled PASS.

- [ ] **Step 3: Inspect the complete diff for authority leaks**

  Run `git diff --check origin/main...HEAD` and search the diff for private keys, raw addresses, pins, attempts, transcript/commitment values, broad ACL changes, fallback ALPNs, exported QUIC connections, and capability enablement. Remove any such leak rather than documenting an exception.

- [ ] **Step 4: Commit**

  ```bash
  git add docs/architecture/desktop-functional-parity-gate.md docs/architecture/discovery-sas-security-matrix.md docs/qa/physical-qa-matrix.md .github/workflows/ci.yml
  git commit -m "docs(qa): gate product V01 across desktop targets"
  ```

- [ ] **Step 5: Request independent review before unsigned physical QA**

  Open a PR with the exact source SHA and CI run IDs. Require an independent security/protocol review of identity persistence, locator privacy, consent binding, shutdown, and fail-closed behavior. Do not sign, publish, install, or begin physical QA until Darío and the LMCP coordinator open the corresponding windows.
