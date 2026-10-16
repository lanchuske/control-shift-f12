# Native Desktop Pairing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver native macOS and Windows applications that discover each other, display and confirm the same verification code, arrange displays, synchronize sharing preferences, and prove a bidirectional physical session before release.

**Architecture:** The desktop hosts remain narrow local child-process owners. The Rust engine owns discovery, provisional transport, verification evidence, durable admission and runtime authority. A typed redacted projection supplies only presentation-safe facts to AppKit and WinForms; neither host sees addresses, secrets or raw trust material.

**Tech Stack:** Rust/Tokio/QUIC and `pairing_v2`, mDNS locator, Swift AppKit, C# WinForms/.NET 8, XCTest, xUnit.

**Spec:** `docs/architecture/desktop-functional-parity-gate.md`

## Global Constraints

- The public name is `Control Shift F12`; legacy names are internal only.
- TUI and CLI are not user-facing pairing or layout flows.
- Discovery is not trust, and neither discovery nor a SAS may enable input or clipboard.
- Both computers show the same four-word SAS and each user confirms locally.
- Mouse/keyboard, clipboard and automatic updates default on only after a durable bilateral relationship; either participant can disable them.
- No signing, publishing or deployment without Darío’s explicit authorization.
- Every release claim requires real macOS-to-Windows physical QA evidence.

---

### Task 1: Engine-owned provisional pairing bridge

**Files:**
- Modify: `apps/seamless-input/src/ui_stdio_adapter.rs`
- Modify: `apps/seamless-input/src/guided_setup.rs`
- Modify: `apps/seamless-input/tests/ui_stdio_adapter.rs`
- Test: `apps/seamless-input/tests/guided_setup.rs`

**Interfaces:**
- Consumes: opaque candidate handles from `SetupController` and V2 verification prompts.
- Produces: redacted `ui_pairing_v1` events with `candidate_handle`, four `words`, generation and bilateral-confirmation phase.

- [ ] **Step 1: Write a failing adapter test**

```rust
#[test]
fn pairing_projection_never_contains_address_or_identity_material() {
    let frame = adapter.begin_selected_candidate("opaque-handle").unwrap();
    assert_eq!(frame.kind, "ui_pairing_v1");
    assert!(!frame.json().contains("address"));
    assert!(!frame.json().contains("certificate"));
}
```

- [ ] **Step 2: Run it and verify it fails**

Run: `cargo test -p seamless-input --test ui_stdio_adapter pairing_projection_never_contains_address_or_identity_material`

Expected: FAIL because `begin_selected_candidate` does not exist.

- [ ] **Step 3: Implement the minimal typed request and projection**

```rust
enum HostCommand { SelectCandidate { handle: String }, ApproveSas { matches: bool } }
struct PairingProjection { generation: u64, handle: String, words: [String; 4], phase: PairingPhase }
```

Reject extra request fields, stale handles, raw endpoints and all projections that are not exactly schema version 1.

- [ ] **Step 4: Run adapter and guided-setup tests**

Run: `cargo test -p seamless-input --test ui_stdio_adapter && cargo test -p seamless-input --features pairing-v2-experimental --test guided_setup`

Expected: PASS; no test enables input, clipboard, durable peer storage or legacy pairing.

- [ ] **Step 5: Commit**

```bash
git add apps/seamless-input/src/ui_stdio_adapter.rs apps/seamless-input/src/guided_setup.rs apps/seamless-input/tests
git commit -m "feat: project bilateral pairing verification safely"
```

### Task 2: Durable admission only after bilateral SAS

**Files:**
- Modify: `crates/transport/src/pairing_v2/provisional_tls/handshake_io.rs`
- Modify: `apps/seamless-input/src/guided_setup.rs`
- Test: `crates/transport/src/pairing_v2/provisional_tls/tests.rs`

**Interfaces:**
- Consumes: two matching local approval decisions and a live provisional channel.
- Produces: durable admission result or a terminal redacted failure; never partial peer visibility.

- [ ] **Step 1: Write a failing test for one-sided approval**

```rust
#[tokio::test]
async fn one_sided_sas_approval_cannot_create_a_durable_admission() {
    let result = fixture().approve_local_only().await;
    assert!(result.is_err());
    assert!(fixture().pending_store_is_empty());
}
```

- [ ] **Step 2: Run it and verify it fails**

Run: `cargo test -p seamless-transport --features pairing-v2-experimental one_sided_sas_approval_cannot_create_a_durable_admission`

Expected: FAIL until the bridge owns both decisions.

- [ ] **Step 3: Implement exact bilateral gate**

```rust
if !local_decision.matches || !remote_decision.matches {
    machine.cancel_local(store, clock)?;
    return Err(BridgeError::VerificationRejected);
}
let result = machine.promote_after_both_approved(store, clock)?;
```

The method must cancel the pending attempt on timeout, disconnect, rejection or persistence error.

- [ ] **Step 4: Run transport tests**

Run: `cargo test -p seamless-transport --features pairing-v2-experimental`

Expected: PASS, including replay, timeout and mismatched-SAS tests.

- [ ] **Step 5: Commit**

```bash
git add crates/transport/src/pairing_v2 apps/seamless-input/src/guided_setup.rs
git commit -m "feat: gate durable pairing on bilateral verification"
```

### Task 3: Bind the pairing projection to both desktop hosts

**Files:**
- Modify: `native/macos/ControlShiftF12App/Sources/ControlShiftF12App/main.swift`
- Modify: `native/windows/ControlShiftF12App.Core/UiChildSession.cs`
- Modify: `native/windows/ControlShiftF12App/WindowsUiChildOwner.cs`
- Modify: `native/windows/ControlShiftF12App/DesktopShellForm.cs`
- Test: `native/macos/ControlShiftF12App/Tests/ControlShiftF12AppTests/ControlShiftF12AppTests.swift`
- Test: `native/windows/ControlShiftF12App.Tests/PairingBridgeStateTests.cs`

**Interfaces:**
- Consumes: exact `ui_pairing_v1` projection.
- Produces: a four-word read-only code and local Approve / Reject actions while all sharing controls remain disabled.

- [ ] **Step 1: Write failing host tests**

```swift
XCTAssertFalse(host.sharingEnabled)
XCTAssertEqual(host.verificationWords, ["ember", "ocean", "violet", "copper"])
```

```csharp
Assert.False(view.InputEnabled);
Assert.Equal(new[] { "ember", "ocean", "violet", "copper" }, view.VerificationWords);
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `swift test --package-path native/macos/ControlShiftF12App` and `dotnet test native/windows/ControlShiftF12App.Tests/ControlShiftF12App.Tests.csproj`

Expected: FAIL because the hosts currently admit only snapshots and diagnostics.

- [ ] **Step 3: Implement fixed host requests**

```text
ui.select_candidate { handle }
ui.approve_sas { matches: true|false }
```

Use fixed schemas, bounded payloads, no arbitrary engine methods, no raw endpoint display, and terminal invalidation on unexpected frames.

- [ ] **Step 4: Run local tests and architecture guard**

Run: `swift test --package-path native/macos/ControlShiftF12App`; `dotnet test native/windows/ControlShiftF12App.Tests/ControlShiftF12App.Tests.csproj`; `python3 scripts/test-native-ui-contract.py`

Expected: PASS; confirmation does not enable sharing until a current durable relationship projection arrives.

- [ ] **Step 5: Commit**

```bash
git add native/macos native/windows scripts/test-native-ui-contract.py
git commit -m "feat: display bilateral pairing verification natively"
```

### Task 4: Screen map and synchronized preferences

**Files:**
- Modify: `apps/seamless-input/src/ui_controller.rs`
- Modify: `apps/seamless-input/src/ui_contract.rs`
- Modify: `native/macos/ControlShiftF12App/Sources/ControlShiftF12App/main.swift`
- Modify: `native/windows/ControlShiftF12App/DesktopShellForm.cs`
- Test: `apps/seamless-input/tests/ui_stdio_adapter.rs`

**Interfaces:**
- Consumes: durable relationship plus current display inventory.
- Produces: a draft layout, bilateral save proposal, and synchronized preferences.

- [ ] **Step 1: Write failing engine tests**

```rust
assert_eq!(controller.apply_local_at(1, UiCommand::MoveDisplay { .. }), Err(UiError::InvalidState));
assert_eq!(controller.snapshot().capabilities.input_enabled, false);
```

- [ ] **Step 2: Run failing test**

Run: `cargo test -p seamless-input ui_controller`

Expected: FAIL until inventory and durable-relationship fixtures are supplied.

- [ ] **Step 3: Implement proposal-only layout**

Allow drag/snap only in local draft state. Send an exact layout proposal to the peer; mark it active only after both sides acknowledge the same generation. Reflect input, clipboard and auto-update preferences from one authoritative synchronized version; rejection restores the previous active version.

- [ ] **Step 4: Test and commit**

Run: `cargo test -p seamless-input && python3 scripts/test-native-ui-contract.py`

Expected: PASS with no input activation from a draft map.

```bash
git add apps/seamless-input native/macos native/windows
git commit -m "feat: add confirmed shared layout and preferences"
```

### Task 5: Connection panel, diagnostics and physical QA

**Files:**
- Modify: `apps/seamless-input/src/diagnostics.rs`
- Modify: `native/macos/ControlShiftF12App/Sources/ControlShiftF12App/main.swift`
- Modify: `native/windows/ControlShiftF12App/DesktopShellForm.cs`
- Create: `docs/qa/control-shift-f12-mac-windows-physical.md`

**Interfaces:**
- Consumes: current authenticated session telemetry.
- Produces: quality label, latency, loss, transfer rate, data limit state and a redacted copyable diagnostic report.

- [ ] **Step 1: Write failing diagnostics tests**

```rust
assert_eq!(connection_view.authenticated_sessions, 0);
assert_eq!(connection_view.quality, Quality::NotConnected);
```

- [ ] **Step 2: Implement truthful telemetry projection**

Use `Not measured` unless the active authenticated transport supplied a bounded current sample. Do not infer quality from discovery, an old session or a test harness.

- [ ] **Step 3: Execute physical QA checklist**

Test Mac-to-Windows and Windows-to-Mac cursor transfer, keyboard, clipboard on/off, emergency recovery, re-open, layout persistence, rejection, firewall/private-network guidance, latency and memory. Record PASS/FAIL/NOT MEASURED with platform, exact builds and timestamps.

- [ ] **Step 4: Commit evidence only after real test**

```bash
git add apps/seamless-input native/macos native/windows docs/qa
git commit -m "test: record physical desktop pairing QA"
```

## Self-Review

- Spec coverage: Tasks 1–3 cover discovery, bilateral confirmation and native UI; Task 4 covers the shared display map and defaults; Task 5 covers connection, diagnostics and physical QA.
- No-placeholder scan: every task names source, test target, interface and expected evidence.
- Type consistency: the engine emits a redacted `ui_pairing_v1` event, both hosts consume it, and only Task 2 can create durable admission.

## Execution Handoff

Plan saved to `docs/superpowers/plans/2026-10-16-native-desktop-pairing.md`. Inline execution will proceed task-by-task, starting with the engine bridge and its failing tests.
