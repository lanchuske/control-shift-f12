# Task 7 implementer report — Windows user-session adapter

## Outcome

Implemented `seamless-input-platform-windows` behind the shared platform
traits, without services, drivers, elevation, firewall changes, or SSH.

## Delivered

- Current-user low-level keyboard and mouse hooks on a dedicated Win32 message
  thread, with injected-event filtering and local/remote suppression control.
- `SendInput` injection for virtual-desktop absolute pointer movement, five
  mouse buttons, horizontal/vertical wheel input, physical scan codes, and
  modifiers.
- Physical USB HID usage to Windows scan-code mapping, including extended
  keys, so normal key routing does not depend on the active keyboard layout.
- Emergency chord handling and deterministic release of all modifiers and
  buttons on emergency return, desktop loss, or shutdown.
- Secure-desktop refusal through input-desktop inspection. Higher-integrity
  injection fails closed when Windows rejects `SendInput`; the application
  never attempts elevation or UIAccess bypass.
- Multi-monitor enumeration with per-monitor DPI and logical-coordinate
  conversion, including negative virtual-desktop origins.
- Text and PNG clipboard polling/writes with Win32 sequence numbers, 200 ms
  debounce, SHA-256 loop suppression, shared size limits, and no content logs.

## TDD evidence

- RED: the initial target-aware integration test failed because the Windows
  adapter modules and types did not exist.
- RED: hook mapping tests failed because raw keyboard/mouse hook mapping was
  absent.
- RED: desktop-transition cleanup test failed because `refresh_session` was
  absent.
- GREEN: 13 adapter behavior tests pass on macOS using platform-neutral fake
  backends. They cover hooks, pointer normalization, buttons, both wheel axes,
  scan codes/layout independence, emergency cleanup, desktop-transition
  cleanup, display scaling, clipboard debounce/dedupe, bounds, and safe
  refusal.

## Verification

- PASS — `cargo test --workspace` on the M4.
- PASS — `cargo fmt --all -- --check`.
- PASS — `cargo clippy --workspace --all-targets -- -D warnings` on the M4.
- PASS — Windows production code and Windows-target tests compile with
  `cargo check -p seamless-input-platform-windows --tests --target
  x86_64-pc-windows-gnu`.
- PASS — Windows-target clippy with warnings denied.
- NO MEDIDO — execution of the tests on a native Windows runner.
- NO MEDIDO — unelevated dedicated-window integration test on Windows.
- NO MEDIDO — physical keyboard/mouse/clipboard smoke test on Windows.

The three NO MEDIDO rows require Windows CI or the later authorized physical QA
run. They are not represented as passing evidence.

## Commit

`1241296 feat(windows): add input and clipboard peer adapter`
