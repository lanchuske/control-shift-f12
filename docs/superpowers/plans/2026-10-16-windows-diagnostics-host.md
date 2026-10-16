# Windows Diagnostics Host Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `executing-plans` to implement task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Deliver a non-shipping WinForms diagnostics host that starts only the fixed local `control --ui-stdio` child, renders current redacted diagnostics, and closes its owned child cleanly.

**Architecture:** The form owns exactly one child process and anonymous standard streams. A small decoder validates the existing typed child projection before a `BeginInvoke` update reaches WinForms controls. The first scope is diagnostics only: no discovery, pairing, layout, input, clipboard, firewall mutation, or network fallback.

**Tech Stack:** .NET 8 WinForms, `System.Diagnostics.Process`, anonymous redirected standard streams, xUnit or a dependency-free test project, existing Rust `seamless-input control --ui-stdio` contract.

**Spec:** `docs/architecture/native-host-process-pipe-adapter.md`, `docs/architecture/desktop-functional-parity-gate.md`, and `docs/native-setup-ux-specification.md`.

## Global Constraints

- The visible name is **Control Shift F12**; Seamless Input is legacy-only.
- The host uses an argument array, never a shell, command string, socket, named pipe, or terminal fallback.
- The host may send only `ui.refresh`; confirmation stays disabled until the separately reviewed V01 flow exists.
- Child output is bounded to the existing 256 KiB frame limit; unknown or malformed data is terminal and clears the projection.
- The child environment is rebuilt from `SystemRoot`, `WINDIR`, `TEMP`, `TMP`, `LOCALAPPDATA`, `USERPROFILE`, and `PATH` only.
- The host is non-shipping: no signing, packaging, publication, input sharing, clipboard sharing, pairing, layout save, or firewall mutation.

---

### Task 1: Make the WinForms project testable

**Files:**
- Create: `native/windows/ControlShiftF12App.Core/ControlShiftF12App.Core.csproj`
- Create: `native/windows/ControlShiftF12App.Core/DiagnosticsProjection.cs`
- Create: `native/windows/ControlShiftF12App.Tests/ControlShiftF12App.Tests.csproj`
- Create: `native/windows/ControlShiftF12App.Tests/WindowsDiagnosticsProjectionTests.cs`

**Interfaces:**
- Produces `DiagnosticsProjection.TryParse(string json, out DiagnosticsProjection projection)`.
- A valid projection has only redacted diagnostic rows and a non-optimistic runtime status.

- [ ] **Step 1: Write a failing projection test**

```csharp
[Fact]
public void Unknown_frame_is_rejected_without_a_projection()
{
    Assert.False(DiagnosticsProjection.TryParse("{\"v\":1,\"kind\":\"unknown\"}", out _));
}
```

- [ ] **Step 2: Run it to verify it fails because the type is absent**

Run: `dotnet test native/windows/ControlShiftF12App.Tests/ControlShiftF12App.Tests.csproj`

- [ ] **Step 3: Add the smallest shared projection model**

Create `DiagnosticsProjection.cs` in the Core project so the test project does not need a WinForms entry point. It must deserialize only `ui_diagnostics_v1` and bounded row fields, returning `false` for unknown kinds, unknown fields, non-current values, or more than 32 rows.

- [ ] **Step 4: Rerun the test and commit**

Run: `dotnet test native/windows/ControlShiftF12App.Tests/ControlShiftF12App.Tests.csproj`

Commit: `feat: add Windows diagnostics projection contract`

### Task 2: Add a fail-closed child-session owner

**Files:**
- Create: `native/windows/ControlShiftF12App/ChildSession.cs`
- Create: `native/windows/ControlShiftF12App.Tests/ChildSessionTests.cs`

**Interfaces:**
- Consumes an immutable installed executable path and `IChildProcess` test seam.
- Produces `StartAsync`, `RefreshAsync`, and `CloseAsync`; all terminal paths clear projection before child reaping.

- [ ] **Step 1: Write a failing child-exit test**

```csharp
[Fact]
public async Task Child_exit_clears_projection_and_disposes_the_owned_session()
{
    var child = new RecordingChildProcess();
    var session = new ChildSession(child);
    await session.StartAsync();
    child.Exit();
    Assert.True(session.IsTerminal);
    Assert.Null(session.CurrentProjection);
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `dotnet test native/windows/ControlShiftF12App.Tests/ControlShiftF12App.Tests.csproj --filter Child_exit`

- [ ] **Step 3: Implement the narrow owner**

Use `ProcessStartInfo.ArgumentList` with exactly `control` and `--ui-stdio`; redirect standard streams; rebuild the allowlisted environment; reject missing/out-of-package executable paths. On EOF, malformed frame, write failure, exit, or close: disable actions, clear projection, close parent streams, wait briefly, then terminate/reap only the owned child.

- [ ] **Step 4: Rerun the focused and complete unit suite, then commit**

Run: `dotnet test native/windows/ControlShiftF12App.Tests/ControlShiftF12App.Tests.csproj`

Commit: `feat: add fail-closed Windows child session`

### Task 3: Create the native diagnostics window

**Files:**
- Create: `native/windows/ControlShiftF12App/Program.cs`
- Create: `native/windows/ControlShiftF12App/MainForm.cs`
- Create: `native/windows/ControlShiftF12App.Tests/MainFormStateTests.cs`

**Interfaces:**
- Consumes `ChildSession` events only.
- Produces a stable state header, Refresh action, semantic diagnostics list, and a disabled-by-default confirmation surface.

- [ ] **Step 1: Write a failing form-state test**

```csharp
[Fact]
public void Terminal_session_disables_refresh_and_shows_a_plain_local_error()
{
    var state = MainFormState.FromTerminalFailure();
    Assert.False(state.CanRefresh);
    Assert.Equal("Connection to the local engine ended", state.StatusText);
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `dotnet test native/windows/ControlShiftF12App.Tests/ControlShiftF12App.Tests.csproj --filter Terminal_session`

- [ ] **Step 3: Implement the minimal WinForms surface**

Use Segoe UI, standard controls, a single-column layout, a semantic status strip, a selectable read-only diagnostics list, visible focus order, and an explicit local error/retry state. Do not render a terminal, raw protocol text, SAS, peer identity, or a green ready state from stale/malformed data.

- [ ] **Step 4: Build and run tests on Windows, then commit**

Run: `dotnet test native/windows/ControlShiftF12App.Tests/ControlShiftF12App.Tests.csproj && dotnet build native/windows/ControlShiftF12App/ControlShiftF12App.csproj`

Commit: `feat: add Windows native diagnostics window`

### Task 4: Validate target-platform lifecycle evidence

**Files:**
- Modify: `native/windows/ControlShiftF12App/README.md`
- Create: `docs/qa/windows-native-host-evidence.md`

**Interfaces:**
- Consumes the target build output and a test-only bundled child fixture.
- Produces PASS/FAIL/NOT MEASURED evidence for start, refresh, EOF, close/reap, keyboard focus, and no public endpoint.

- [ ] **Step 1: Write the target smoke assertion before running it**

```text
Given a fixture child that emits one valid diagnostics frame, the form renders rows;
after child EOF, it clears rows and no child process remains.
```

- [ ] **Step 2: Run the smoke on the Windows target and record its raw outcome**

Run: the reviewed fixture command from the Windows checkout; do not use a shipping installer.

- [ ] **Step 3: Document only observed facts**

Write PASS, FAIL, or NOT MEASURED for lifecycle, UI state, focus order, and cleanup. Keep pairing, confirmation, display map, sharing, permissions, firewall, and physical Mac-Windows QA as NOT MEASURED.

- [ ] **Step 4: Verify the repository and commit the evidence**

Run: `git diff --check` and the full Windows test/build commands.

Commit: `test: record Windows diagnostics host evidence`

## Self-review

- The plan deliberately implements only the allowed diagnostics projection; it does not claim discovery, pairing, SAS confirmation, display-map save, or sharing capability.
- Each task has a failing test, a specific verification step, and a distinct commit boundary.
- No task adds a shell, network endpoint, elevation request, or user-provided executable path.
