# Control Shift F12 Complete Desktop Delivery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver two native desktop applications that can safely discover, pair, arrange and operate a Mac–Windows relationship, then prove the complete workflow on the physical target machines.

**Architecture:** The Rust engine owns discovery, provisional transport, bilateral verification, durable admission and runtime authority. AppKit and WinForms own only native presentation and explicit local gestures through the inherited `--ui-stdio` pipe. Each capability is gated separately: discovery never means trust, a durable relationship never means active sharing, and a layout draft never means a saved topology.

**Tech Stack:** Rust/Tokio/QUIC/mDNS, AppKit/Swift/XCTest, WinForms/.NET 8/xUnit, typed length-prefixed JSON over inherited stdio.

**Spec:** `docs/architecture/desktop-functional-parity-gate.md`, `docs/product-pairing-admission-adapter.md`, and `docs/native-setup-ux-specification.md`.

## Global Constraints

- The product name is **Control Shift F12**; legacy terminal flows remain internal support tools only.
- The desktop hosts never display addresses, certificates, keys, raw receipt data, network locators, or secrets.
- Desktop hosts never fall back to a shell, TUI, legacy pairing command, manual address, or network control endpoint.
- Discovery and SAS confirmation do not enable mouse/keyboard, clipboard, layout saving, or automatic updates.
- Pairing requires the same four-word display and an independent local confirmation on both computers.
- Mouse/keyboard, clipboard and automatic updates default on only after a durable bilateral relationship and their own runtime gate; either participant may turn each off.
- Windows firewall guidance is private-network only; no silent elevation, public-network rule, password prompt, or automatic rule creation.
- No signing, publishing, deployment, or release creation without Darío’s explicit authorization.
- Every release claim requires physical Mac-to-Windows and Windows-to-Mac evidence recorded as PASS, FAIL, or NOT MEASURED.

---

### Task 1: Freeze the product pairing IPC contract

**Files:**
- Modify: `apps/seamless-input/src/ui_stdio_adapter.rs`
- Modify: `apps/seamless-input/tests/ui_stdio_adapter.rs`
- Modify: `docs/product-pairing-admission-adapter.md`

**Interfaces:**
- Consumes: `ui.start_discovery`, `ui.stop_discovery`, `ui.select_candidate { handle }`, and `ui.approve_sas { generation, matches }`.
- Produces: exact `ui_snapshot_v1`, `ui_pairing_v1`, and `ui_response_v1` frames with no unlisted fields.

- [ ] **Step 1: Write the failing request-schema tests**

```rust
let rejected = adapter.handle_host_request_at(
    1,
    &request("select-extra", "ui.select_candidate", json!({"handle":"nearby-1","address":"192.0.2.4"})),
);
assert!(rejected.iter().any(|f| matches!(f, ChildFrame::Response(r) if !r.ok)));
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run: `cargo test -p seamless-input --test ui_stdio_adapter select_extra`

Expected: FAIL because the product pairing commands and projection do not exist yet.

- [ ] **Step 3: Add the smallest typed schema**

```rust
enum HostCommand {
    Refresh,
    StartDiscovery,
    StopDiscovery,
    SelectCandidate { handle: String },
    ApproveSas { generation: u64, matches: bool },
    ConfirmV01 { matches: bool },
}
```

Reject unknown keys, empty/oversized handles, zero generations, replay conflicts and every nested field that resembles an address, identity, certificate, SAS, capability or layout.

- [ ] **Step 4: Verify the adapter contract**

Run: `cargo test -p seamless-input --test ui_stdio_adapter && cargo test -p seamless-input --test ui_contract`

Expected: PASS; every command and response remains redacted and request-id replay stays deterministic.

- [ ] **Step 5: Commit the contract**

```bash
git add apps/seamless-input/src/ui_stdio_adapter.rs apps/seamless-input/tests/ui_stdio_adapter.rs docs/product-pairing-admission-adapter.md
git commit -m "feat: add typed desktop pairing IPC"
```

### Task 2: Add the engine-owned discovery and listener lease

**Files:**
- Create: `apps/seamless-input/src/product_pairing_adapter.rs`
- Modify: `apps/seamless-input/src/guided_setup.rs`
- Modify: `apps/seamless-input/src/lib.rs`
- Test: `apps/seamless-input/tests/product_pairing_adapter.rs`

**Interfaces:**
- Consumes: an explicit current discovery-window generation and the engine-owned `ConsentCatalog`.
- Produces: `PairingAdvertisementLease`, which owns one bounded advertisement and provisional endpoint and returns only opaque handles.

- [ ] **Step 1: Write lease-expiry tests**

```rust
#[test]
fn closing_the_pairing_window_withdraws_publication_and_drops_the_listener() {
    let mut fixture = Fixture::new();
    let lease = fixture.open(10).unwrap();
    fixture.close(lease, 11).unwrap();
    assert!(!fixture.is_advertising());
    assert!(!fixture.has_provisional_listener());
}
```

- [ ] **Step 2: Run the test and verify it fails**

Run: `cargo test -p seamless-input --test product_pairing_adapter closing_the_pairing_window`

Expected: FAIL because there is no product pairing lease.

- [ ] **Step 3: Implement the lease as an engine-owned RAII value**

```rust
pub struct PairingAdvertisementLease {
    generation: u64,
    expires_at_ms: u64,
    endpoint: ProvisionalEndpoint,
    publication: EngineAdvertisement,
}
```

The publication may contain only rendezvous identifier, protocol version and pairable flag. Closing, timeout, cancellation, endpoint failure and completed attempt withdraw publication before endpoint drop.

- [ ] **Step 4: Run discovery and lease tests**

Run: `cargo test -p seamless-input --test product_pairing_adapter && cargo test -p seamless-discovery`

Expected: PASS; browsing alone cannot open a listener and no lease exposes a socket address through the UI projection.

- [ ] **Step 5: Commit the lease**

```bash
git add apps/seamless-input/src/product_pairing_adapter.rs apps/seamless-input/src/guided_setup.rs apps/seamless-input/src/lib.rs apps/seamless-input/tests/product_pairing_adapter.rs
git commit -m "feat: own desktop pairing advertisement lease"
```

### Task 3: Bridge candidate selection to bilateral verification

**Files:**
- Modify: `apps/seamless-input/src/product_pairing_adapter.rs`
- Modify: `apps/seamless-input/src/ui_stdio_adapter.rs`
- Modify: `crates/transport/src/pairing_v2/provisional_tls/handshake_io.rs`
- Test: `apps/seamless-input/tests/product_pairing_adapter.rs`
- Test: `crates/transport/src/pairing_v2/provisional_tls/tests.rs`

**Interfaces:**
- Consumes: one current opaque candidate handle and a valid owned lease.
- Produces: `ui_pairing_v1 { generation, phase, candidate_handle, verification_words }` and a move-only pending authority.

- [ ] **Step 1: Write the one-sided-confirmation test**

```rust
#[tokio::test]
async fn one_local_sas_approval_never_commits_a_relationship() {
    let mut pair = Fixture::paired_attempt().await;
    pair.approve_local(true).unwrap();
    assert!(pair.durable_records().is_empty());
    assert!(pair.pending_attempt_exists());
}
```

- [ ] **Step 2: Run it and verify it fails**

Run: `cargo test -p seamless-transport --features pairing-v2-experimental one_local_sas_approval_never_commits_a_relationship`

Expected: FAIL until the product bridge owns the two independent decisions.

- [ ] **Step 3: Implement fail-closed state transitions**

```rust
enum PairingPhase {
    Browsing,
    SelectedUntrusted,
    AwaitingLocalConfirmation,
    AwaitingRemoteConfirmation,
    CommittingDurableAdmission,
    AdmittedMetadataOnly,
}
```

Only an exact current transcript, unexpired generation, and independent affirmative decisions on both endpoints may pass a live `HandshakeCompletePendingAuthority` to `AdmissionAuthorityStore::commit_sealed_foundation`.

- [ ] **Step 4: Verify replay, expiry and rejection**

Run: `cargo test -p seamless-transport --features pairing-v2-experimental && cargo test -p seamless-input --test product_pairing_adapter`

Expected: PASS; mismatch, duplicate choice, stale handle, endpoint loss and durable-store failure cancel the pending attempt and clear the projection.

- [ ] **Step 5: Commit the bridge**

```bash
git add apps/seamless-input/src/product_pairing_adapter.rs apps/seamless-input/src/ui_stdio_adapter.rs crates/transport/src/pairing_v2/provisional_tls apps/seamless-input/tests/product_pairing_adapter.rs
git commit -m "feat: gate durable pairing on bilateral confirmation"
```

### Task 4: Complete native pairing screens in AppKit and WinForms

**Files:**
- Modify: `native/macos/ControlShiftF12App/Sources/ControlShiftF12App/main.swift`
- Modify: `native/macos/ControlShiftF12App/Tests/ControlShiftF12AppTests/ControlShiftF12AppTests.swift`
- Modify: `native/windows/ControlShiftF12App/WindowsUiChildOwner.cs`
- Modify: `native/windows/ControlShiftF12App/DesktopShellForm.cs`
- Modify: `native/windows/ControlShiftF12App.Tests/PairingBridgeStateTests.cs`

**Interfaces:**
- Consumes: exact redacted candidate and `ui_pairing_v1` frames.
- Produces: native selection and local confirmation gestures; all sharing controls remain disabled until a later runtime projection.

- [ ] **Step 1: Write native host tests**

```swift
XCTAssertEqual(controller.pairing?.verificationWords, ["ember", "ocean", "violet", "copper"])
XCTAssertFalse(controller.shell.inputSharingEnabled)
```

```csharp
Assert.Equal(new[] { "ember", "ocean", "violet", "copper" }, state.VerificationWords);
Assert.False(state.InputSharingEnabled);
```

- [ ] **Step 2: Run both focused suites and verify the gaps**

Run: `swift test --package-path native/macos/ControlShiftF12App` and `dotnet test native/windows/ControlShiftF12App.Tests/ControlShiftF12App.Tests.csproj`

Expected: the tests initially fail wherever a host lacks the fixed select/approve frame owner.

- [ ] **Step 3: Implement native controls without presentation authority**

Mac uses AppKit table selection, native button focus and local sheet confirmation. Windows uses `ListView`, `Button`, `StatusStrip`, and `ErrorProvider`. Both render matching words only in the focused local confirmation view, clear them on any terminal frame, and send only fixed typed requests.

- [ ] **Step 4: Verify native boundaries**

Run: `swift test --package-path native/macos/ControlShiftF12App && dotnet test native/windows/ControlShiftF12App.Tests/ControlShiftF12App.Tests.csproj && python3 scripts/test-native-ui-contract.py`

Expected: PASS; malformed or extra fields terminate the child projection and no visible action grants sharing.

- [ ] **Step 5: Commit the native pairing journey**

```bash
git add native/macos native/windows scripts/test-native-ui-contract.py
git commit -m "feat: add native bilateral pairing journey"
```

### Task 5: Implement measured inventory and local display-map drafting

**Files:**
- Modify: `apps/seamless-input/src/ui_contract.rs`
- Modify: `apps/seamless-input/src/ui_controller.rs`
- Modify: `apps/seamless-input/tests/ui_contract.rs`
- Modify: `native/macos/ControlShiftF12App/Sources/ControlShiftF12App/main.swift`
- Modify: `native/windows/ControlShiftF12App/DesktopShellForm.cs`

**Interfaces:**
- Consumes: a current measured inventory generation for each confirmed computer.
- Produces: local-only draft cards, cardinal move commands, snap validation and explicit unsaved state.

- [ ] **Step 1: Write draft invalidation tests**

```rust
assert_eq!(controller.apply_local_at(4, UiCommand::MoveDisplay { display: 1, direction: Direction::Below }), Ok(()));
controller.on_runtime_at(5, UiRuntimeEvent::InventoryChanged { generation: 2 });
assert_eq!(controller.snapshot().layout.state, LayoutState::NotConfigured);
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run: `cargo test -p seamless-input ui_controller::tests::inventory_change`

Expected: FAIL until a local draft carries an inventory generation.

- [ ] **Step 3: Implement draft-only map behavior**

Measured rectangles use resolution, scale and orientation; physical size is optional. Dragging snaps only to cardinal edges without overlap. Keyboard cardinal movement follows the same validator. A changed inventory clears the draft. No draft writes remote state, starts transport or enables sharing.

- [ ] **Step 4: Verify map behavior**

Run: `cargo test -p seamless-input --test ui_contract && swift test --package-path native/macos/ControlShiftF12App && dotnet test native/windows/ControlShiftF12App.Tests/ControlShiftF12App.Tests.csproj`

Expected: PASS; invalid, diagonal, overlapping or stale layouts are blocked locally.

- [ ] **Step 5: Commit the map draft**

```bash
git add apps/seamless-input/src/ui_contract.rs apps/seamless-input/src/ui_controller.rs apps/seamless-input/tests/ui_contract.rs native/macos native/windows
git commit -m "feat: add native local display map drafts"
```

### Task 6: Add authenticated layout agreement and synchronized preferences

**Files:**
- Create: `crates/transport/src/pairing_v2/application_session.rs`
- Modify: `crates/transport/src/pairing_v2/mod.rs`
- Modify: `apps/seamless-input/src/ui_controller.rs`
- Test: `crates/transport/src/pairing_v2/application_session_tests.rs`
- Test: `apps/seamless-input/tests/ui_stdio_adapter.rs`

**Interfaces:**
- Consumes: active durable relationship, fresh application session and canonical local map proposal.
- Produces: bilateral committed layout revision plus synchronized `input`, `clipboard`, `wallpaper_preview`, and `automatic_updates` preferences.

- [ ] **Step 1: Write two-sided commit tests**

```rust
#[test]
fn one_sided_layout_acceptance_never_marks_a_layout_saved() {
    let mut session = Fixture::authenticated_session();
    session.accept_local_layout().unwrap();
    assert_eq!(session.layout_status(), LayoutStatus::WaitingForRemote);
    assert!(session.saved_layout().is_none());
}
```

- [ ] **Step 2: Run and verify failure**

Run: `cargo test -p seamless-transport application_session::one_sided_layout_acceptance`

Expected: FAIL because the authenticated application-session lifecycle does not exist.

- [ ] **Step 3: Implement a distinct post-V01 application session**

The session cannot reuse V01 payloads. It binds canonical map bytes and one preferences revision to the active durable relationship. Both endpoints must acknowledge the same revision. Before that, status remains `WaitingForRemote` and runtime capabilities remain false.

- [ ] **Step 4: Verify synchronized preferences**

Run: `cargo test -p seamless-transport application_session && cargo test -p seamless-input --test ui_stdio_adapter`

Expected: PASS; either participant can disable a preference, stale revisions reject, and all defaults remain inactive before durable agreement.

- [ ] **Step 5: Commit agreement lifecycle**

```bash
git add crates/transport/src/pairing_v2/application_session.rs crates/transport/src/pairing_v2/mod.rs crates/transport/src/pairing_v2/application_session_tests.rs apps/seamless-input/src/ui_controller.rs apps/seamless-input/tests/ui_stdio_adapter.rs
git commit -m "feat: commit shared layout and preferences bilaterally"
```

### Task 7: Add truthful connection, permission and recovery surfaces

**Files:**
- Modify: `apps/seamless-input/src/diagnostics.rs`
- Modify: `apps/seamless-input/src/ui_projection.rs`
- Modify: `native/macos/ControlShiftF12App/Sources/ControlShiftF12App/main.swift`
- Modify: `native/windows/ControlShiftF12App/DesktopShellForm.cs`
- Test: `apps/seamless-input/tests/ui_stdio_adapter.rs`

**Interfaces:**
- Consumes: current authenticated transport samples and platform-local permissions.
- Produces: quality label, current latency/loss/transfer samples, bounded data-limit status, and redacted selectable technical detail.

- [ ] **Step 1: Write non-inference tests**

```rust
let view = project_connection(None, 10);
assert_eq!(view.quality, ConnectionQuality::NotConnected);
assert_eq!(view.latency_ms, None);
assert_eq!(view.transfer_bytes_per_second, None);
```

- [ ] **Step 2: Run and verify failure**

Run: `cargo test -p seamless-input --test ui_stdio_adapter connection_quality`

Expected: FAIL until a current authenticated-sample projection exists.

- [ ] **Step 3: Implement current-only telemetry and guidance**

Use `Not measured` for absent/stale samples. macOS guides the user to Accessibility settings. Windows explains the private-network firewall consent by visible product name. Neither platform silently elevates, changes public-network policy, or treats a diagnostic PASS as an active relationship.

- [ ] **Step 4: Verify recovery and accessibility**

Run: `cargo test -p seamless-input --test ui_stdio_adapter && swift test --package-path native/macos/ControlShiftF12App && dotnet test native/windows/ControlShiftF12App.Tests/ControlShiftF12App.Tests.csproj`

Expected: PASS; child failure clears connection, code, candidates and enabled controls before retry offers a fresh session.

- [ ] **Step 5: Commit truthful status**

```bash
git add apps/seamless-input/src/diagnostics.rs apps/seamless-input/src/ui_projection.rs apps/seamless-input/tests/ui_stdio_adapter.rs native/macos native/windows
git commit -m "feat: show current connection and recovery state"
```

### Task 8: Integrate, validate and run physical Mac–Windows QA

**Files:**
- Modify: `.github/workflows/control-shift-f12-macos.yml`
- Modify: `.github/workflows/control-shift-f12-windows.yml`
- Create: `docs/qa/control-shift-f12-physical-mac-windows.md`
- Create: `docs/qa/control-shift-f12-resource-measurements.md`

**Interfaces:**
- Consumes: unsigned Mac and Windows candidate installers produced from the same reviewed commit.
- Produces: PASS/FAIL/NOT MEASURED evidence for the target builds, not an inferred release result.

- [ ] **Step 1: Add CI assertions for both native hosts**

```yaml
- name: Test native host
  run: dotnet test native/windows/ControlShiftF12App.Tests/ControlShiftF12App.Tests.csproj --configuration Release
```

Mac runs the Swift suite and Windows runs the xUnit suite; both run Rust contract tests. No job signs, publishes, creates releases or uploads a public artifact.

- [ ] **Step 2: Run the unsigned candidate builds**

Run: the repository’s Mac and Windows unsigned-candidate workflow targets.

Expected: PASS only for build and automated checks; physical behavior remains NOT MEASURED.

- [ ] **Step 3: Execute the two-machine checklist**

Record separate outcomes for: install/first launch, discovery privacy, reject/accept pairing, code expiry, reopen, current diagnostics, display-map draft, bilateral layout save, preferences on/off from either machine, mouse/keyboard in both directions, clipboard in both directions, emergency recovery, firewall/private-network guidance, uninstall/cleanup, CPU, memory and latency.

- [ ] **Step 4: Record evidence without overclaiming**

Use a table with `platform`, `build`, `scenario`, `result`, `observed behavior`, and `gap`. Mark every unperformed item `NOT MEASURED`; do not replace it with green harness output.

- [ ] **Step 5: Commit evidence and request release authorization separately**

```bash
git add .github/workflows docs/qa
git commit -m "test: record Control Shift F12 physical QA"
```

Do not sign, publish, deploy or create a release in this task. After evidence is complete, request Darío’s explicit approval for any release action.

## Execution Order and Gates

1. Tasks 1–3: engine-only pairing bridge; stop on a security NO-GO.
2. Task 4: native pairing UI only after its engine frames are admitted.
3. Task 5: local measured map draft; no remote save yet.
4. Task 6: authenticated layout/preferences agreement; no input or clipboard before the runtime owner.
5. Task 7: current-only operational UI and recovery.
6. Task 8: integration, unsigned candidates and physical QA; release remains a separate authorization.

## Self-Review

- Spec coverage: discovery, bilateral confirmation, durable admission, desktop parity, display arrangement, synchronized controls, connection telemetry, permissions, recovery, CI and physical QA map to Tasks 1–8.
- Capability boundaries: every task preserves the distinction between nearby, durable relationship, draft map, committed map and active sharing.
- No release leakage: Task 8 prohibits signing, publishing and deployment and requires an explicit approval after evidence.
- Type consistency: native hosts consume only `ui_snapshot_v1` and `ui_pairing_v1`; the adapter alone accepts typed gestures; transport owns durable and application-session commits.

## Execution Handoff

Execute Tasks 1–8 in order. Do not merge a later task around an unresolved review or a failed security/physical gate.
