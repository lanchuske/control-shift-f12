# Control Shift F12 desktop product journey implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver matching, functional native macOS and Windows desktop applications for pairing, bilateral confirmation, display arrangement, connection health, and protected diagnostics.

**Architecture:** Rust remains authoritative. AppKit and WinForms are native local projections that own one reviewed inherited-pipe child. A stage becomes interactive only when its typed engine command, adversarial tests, platform lifecycle proof, and physical evidence have passed.

**Tech Stack:** Rust, AppKit/Swift, .NET 8 WinForms, XCTest, .NET test projects.

**Spec:** `docs/architecture/desktop-functional-parity-gate.md`, `docs/native-setup-ux-specification.md`, `docs/architecture/native-host-process-pipe-adapter.md`.

## Global Constraints

- Control Shift F12 is the visible name; the TUI remains technical fallback only.
- Hosts use only the installed `control --ui-stdio` child and an argument array: never a shell, socket, manual address, legacy channel, or user-selected executable.
- Stale, malformed, duplicate, terminal, or non-PASS facts clear dependent UI.
- Pairing requires two local decisions over the same current code. No peer can decide for the other.
- A display map starts as a local draft. Save/share stays disabled until a separately reviewed authenticated application session commits it bilaterally.
- Never sign, package, publish, mutate a firewall, or claim physical QA PASS during this plan.

---

### Task 1: Establish a reviewed lifecycle owner on each platform

**Files:**
- Modify: `scripts/test-native-ui-contract.py`
- Create: `native/windows/ControlShiftF12App/ChildSession.cs`
- Create: `native/windows/ControlShiftF12App.Tests/ChildSessionTests.cs`
- Modify: `native/macos/ControlShiftF12App/Sources/ControlShiftF12App/main.swift`
- Modify: `native/macos/ControlShiftF12App/Tests/ControlShiftF12AppTests/ControlShiftF12AppTests.swift`

**Interfaces:**
- Produces terminal lifecycle state that clears the projection before closing streams and reaping the owned child.

- [ ] **Step 1: Write failing target lifecycle tests**

```csharp
[Fact]
public async Task Eof_clears_projection_and_reaps_owned_child()
{
    var child = new RecordingChildProcess();
    var session = new ChildSession(child);
    await session.ReceiveAsync(ValidDiagnosticsFrame());
    await session.ReceiveAsync(ChildEvent.EndOfFile);
    Assert.True(session.IsTerminal);
    Assert.Null(session.CurrentProjection);
    Assert.Equal(1, child.ReapCalls);
}
```

```swift
func testRestartWaitsForThePreviousOwnedChildToReap() {
    let child = SlowRecordingChild()
    let session = ChildLifecycle(child: child)
    session.close()
    XCTAssertTrue(session.isClosed)
    XCTAssertEqual(child.reapAttempts, 2)
}
```

- [ ] **Step 2: Verify RED**

```text
dotnet test native/windows/ControlShiftF12App.Tests/ControlShiftF12App.Tests.csproj --filter Eof_clears
swift test --package-path native/macos/ControlShiftF12App --filter RestartWaits
```

- [ ] **Step 3: Implement the narrow owner**

Windows uses `ProcessStartInfo.ArgumentList` only with `control`, `--ui-stdio`, redirects standard streams, rebuilds the allowlisted environment, and reaps only the owned process. macOS retains equivalent fail-closed behavior.

- [ ] **Step 4: Verify GREEN**

```text
python3 scripts/test-native-ui-contract.py
swift test --package-path native/macos/ControlShiftF12App
dotnet test native/windows/ControlShiftF12App.Tests/ControlShiftF12App.Tests.csproj
```

- [ ] **Step 5: Commit**

```text
feat: establish native child lifecycle owners
```

### Task 2: Build the truthful native shell and diagnostics

**Files:**
- Create: `native/windows/ControlShiftF12App/Program.cs`
- Create: `native/windows/ControlShiftF12App/MainForm.cs`
- Create: `native/windows/ControlShiftF12App.Tests/MainFormStateTests.cs`
- Modify: `native/macos/ControlShiftF12App/Sources/ControlShiftF12App/main.swift`
- Modify: `native/macos/ControlShiftF12App/Tests/ControlShiftF12AppTests/ControlShiftF12AppTests.swift`

**Interfaces:**
- Consumes only current `ui_diagnostics_v1`.
- Produces native header, semantic diagnostics rows, technical-details disclosure, and disabled product-journey navigation.

- [ ] **Step 1: Write failing state tests**

```csharp
[Fact]
public void Terminal_session_disables_product_actions()
{
    var state = MainFormState.FromTerminalFailure();
    Assert.Equal("The local engine stopped", state.StatusText);
    Assert.False(state.CanRefresh);
    Assert.False(state.CanPair);
    Assert.False(state.CanShare);
}
```

```swift
func testTechnicalDetailsRedactLocatorsAndCodes() {
    let details = TechnicalDetails.from(runtime: .currentPass, rows: [.displaysPass])
    XCTAssertFalse(details.selectableText.contains("192.168."))
    XCTAssertFalse(details.selectableText.localizedCaseInsensitiveContains("code"))
}
```

- [ ] **Step 2: Verify RED**

```text
dotnet test native/windows/ControlShiftF12App.Tests/ControlShiftF12App.Tests.csproj --filter Terminal_session
swift test --package-path native/macos/ControlShiftF12App --filter TechnicalDetails
```

- [ ] **Step 3: Implement the smallest AppKit/WinForms shell**

Use conventional controls and focus order. Pairing, map save, sharing, and auto-update display unavailable explanations until their commands are admitted. Connection health is `Not measured` absent current samples.

- [ ] **Step 4: Verify GREEN**

```text
swift test --package-path native/macos/ControlShiftF12App
dotnet test native/windows/ControlShiftF12App.Tests/ControlShiftF12App.Tests.csproj
dotnet build native/windows/ControlShiftF12App/ControlShiftF12App.csproj
```

- [ ] **Step 5: Commit**

```text
feat: add truthful native desktop shells
```

### Task 3: Admit discovery and bilateral bootstrap

**Files:**
- Modify: `apps/seamless-input/src/ui_contract.rs`
- Modify: `apps/seamless-input/src/ui_stdio_adapter.rs`
- Create: `apps/seamless-input/tests/ui_bootstrap_flow.rs`
- Modify: `native/macos/ControlShiftF12App/Sources/ControlShiftF12App/main.swift`
- Modify: `native/windows/ControlShiftF12App/MainForm.cs`

**Interfaces:**
- Adds only reviewed `ui.discovery.begin`, `ui.discovery.stop`, `ui.discovery.select`, `ui.bootstrap.begin`, and `ui.bootstrap.confirm { matches: bool }`.
- Produces an untrusted nearby catalogue and a current-only local code.

- [ ] **Step 1: Write the failing engine test**

```rust
#[test]
fn bootstrap_mismatch_clears_candidate_and_never_enables_sharing() {
    let mut adapter = adapter_with_selected_candidate();
    adapter.begin_bootstrap().unwrap();
    let outcome = adapter.confirm_bootstrap(false).unwrap();
    assert!(outcome.catalogue_is_visible());
    assert!(!outcome.input_enabled());
    assert!(!outcome.clipboard_enabled());
}
```

- [ ] **Step 2: Verify RED**

```text
cargo test -p seamless-input --test ui_bootstrap_flow bootstrap_mismatch
```

- [ ] **Step 3: Implement the minimal typed transition**

Reject manual-address fallback, retained candidate connection, layout payload, and every input/clipboard request. Expiry, mismatch, duplicate decision, and replacement clear the attempt.

- [ ] **Step 4: Verify GREEN**

```text
cargo test -p seamless-input --test ui_bootstrap_flow
swift test --package-path native/macos/ControlShiftF12App
dotnet test native/windows/ControlShiftF12App.Tests/ControlShiftF12App.Tests.csproj
```

- [ ] **Step 5: Commit**

```text
feat: add bilateral bootstrap journey
```

### Task 4: Add measured display inventory and local map drafting

**Files:**
- Modify: `apps/seamless-input/src/ui_contract.rs`
- Modify: `apps/seamless-input/src/ui_stdio_adapter.rs`
- Create: `apps/seamless-input/tests/ui_layout_draft.rs`
- Modify: `native/macos/ControlShiftF12App/Sources/ControlShiftF12App/main.swift`
- Modify: `native/windows/ControlShiftF12App/MainForm.cs`

**Interfaces:**
- Adds `ui.layout.move_cardinal { display, direction, alignment }` and `ui.layout.reset_draft` for current measured inventory only.
- Produces proportional, unsaved local rectangles.

- [ ] **Step 1: Write the failing engine test**

```rust
#[test]
fn inventory_generation_change_discards_unsaved_layout_draft() {
    let mut adapter = adapter_with_two_measured_displays();
    adapter.move_cardinal("display-2", Direction::Below, Alignment::Center).unwrap();
    adapter.observe_inventory(next_inventory_generation());
    assert_eq!(adapter.layout_state(), LayoutState::NotConfigured);
}
```

- [ ] **Step 2: Verify RED**

```text
cargo test -p seamless-input --test ui_layout_draft inventory_generation_change
```

- [ ] **Step 3: Implement draft behavior**

Both maps use measured proportions and keyboard cardinal movement. Preview wallpaper is a local visual preference, never identity proof. Review/save remains disabled.

- [ ] **Step 4: Verify GREEN**

```text
cargo test -p seamless-input --test ui_layout_draft
swift test --package-path native/macos/ControlShiftF12App
dotnet test native/windows/ControlShiftF12App.Tests/ControlShiftF12App.Tests.csproj
```

- [ ] **Step 5: Commit**

```text
feat: add measured local display draft
```

### Task 5: Add bilateral layout commit and synchronized sharing preferences

**Files:**
- Modify: `crates/transport/src/pairing_v2/operational_session.rs`
- Modify: `crates/transport/tests/pairing_v2_session.rs`
- Modify: `apps/seamless-input/src/ui_contract.rs`
- Create: `apps/seamless-input/tests/ui_layout_commit.rs`
- Modify: `native/macos/ControlShiftF12App/Sources/ControlShiftF12App/main.swift`
- Modify: `native/windows/ControlShiftF12App/MainForm.cs`

**Interfaces:**
- Uses a reviewed application session separate from V01.
- Produces proposal, bilateral accept/reject, durable commit, and synchronized sharing preference state.

- [ ] **Step 1: Write the failing durable-commit test**

```rust
#[test]
fn unilateral_layout_acceptance_never_marks_the_layout_saved() {
    let mut session = authenticated_application_session();
    session.propose(valid_layout()).unwrap();
    session.accept_local().unwrap();
    assert_eq!(session.layout_status(), LayoutStatus::WaitingForPeer);
}
```

- [ ] **Step 2: Verify RED**

```text
cargo test -p transport --test pairing_v2_session unilateral_layout_acceptance
```

- [ ] **Step 3: Implement the separate durable session**

Never reuse V01 payloads. A pending or local-only setting remains disabled; sharing activates only after durable bilateral proof.

- [ ] **Step 4: Verify GREEN**

```text
cargo test -p transport --test pairing_v2_session
cargo test -p seamless-input --test ui_layout_commit
swift test --package-path native/macos/ControlShiftF12App
dotnet test native/windows/ControlShiftF12App.Tests/ControlShiftF12App.Tests.csproj
```

- [ ] **Step 5: Commit**

```text
feat: add bilateral layout commit
```

### Task 6: Add connection health, limits, technical details, and physical evidence

**Files:**
- Modify: `apps/seamless-input/src/ui_projection.rs`
- Create: `apps/seamless-input/tests/ui_connection_health.rs`
- Modify: `native/macos/ControlShiftF12App/Sources/ControlShiftF12App/main.swift`
- Modify: `native/windows/ControlShiftF12App/MainForm.cs`
- Create: `docs/qa/native-desktop-journey-evidence.md`
- Modify: `docs/qa/physical-qa-matrix.md`

**Interfaces:**
- Produces current status, latency, loss, throughput, data use, local limit state, and redacted protected details.
- Missing/stale samples render `Not measured`.

- [ ] **Step 1: Write the failing projection test**

```rust
#[test]
fn stale_connection_metric_renders_not_measured_not_excellent() {
    let view = ConnectionHealthView::from_sample(stale_sample());
    assert_eq!(view.summary, HealthSummary::NotMeasured);
    assert!(view.latency_ms.is_none());
}
```

- [ ] **Step 2: Verify RED**

```text
cargo test -p seamless-input --test ui_connection_health stale_connection_metric
```

- [ ] **Step 3: Implement the redacted projection and native details views**

Protect report content; do not export raw logs, locators, codes, certificates, or identity material. Auto-update stays display-only until its own review.

- [ ] **Step 4: Run target evidence and record only observed results**

```text
python3 scripts/test-native-ui-contract.py
git diff --check
```

Record each macOS, Windows, and bidirectional physical check as PASS, FAIL, or NOT MEASURED; no unit/CI result substitutes for target evidence.

- [ ] **Step 5: Commit**

```text
test: record native desktop journey evidence
```

## Self-review

- Every screen in the approved user journey corresponds to an engine-owned capability or an explicit unavailable explanation.
- The plan puts lifecycle and truthful local state before discovery, pairing, layout, sharing, update delivery, and network metrics.
- Durable save and shared settings cannot become active after a unilateral local action.
- The final record distinguishes built, tested locally, target-validated, and physically measured behavior.
