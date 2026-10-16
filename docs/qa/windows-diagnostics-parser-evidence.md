# Windows diagnostics parser evidence

**Date:** 2026-10-16

**Target:** Windows 11 Pro, version 10.0.26300, build 26300.

**Scope:** The non-shipping `ControlShiftF12App.Core` diagnostics parser and
its declared `ControlShiftF12App.Tests` project. This is not evidence for a
WinForms host, a child process, pairing, display layout, input, clipboard,
firewall, signing, packaging, or Mac-Windows physical interoperability.

## Command

```text
dotnet test --list-tests --no-restore
dotnet test --no-restore
```

## Observed outcome

- The Windows test runner discovered seven tests.
- Result: **PASS — 7 passed, 0 failed, 0 skipped.**
- The executed adversarial cases rejected: unknown frame kind, duplicate JSON
  field, UTF-8 payload above 256 KiB, negative generation, injected sensitive
  root field, invalid diagnostic enum, and more than 32 rows.

## Evidence boundary

The parser receives a string only after its caller has the framed child output.
It bounds that string again before JSON parsing and returns no projection on an
invalid frame. The repository guard additionally limits Windows native source
to this parser and its tests; it does not admit a WinForms window, process
owner, pipe, network endpoint, or user action.

## Remaining measurements

| Area | Status |
| --- | --- |
| Windows parser contract | PASS |
| WinForms host build and visible launch | NOT MEASURED |
| Windows child pipe lifecycle and cleanup | NOT MEASURED |
| Accessibility/focus order | NOT MEASURED |
| Pairing, layout, input, clipboard | NOT MEASURED |
| Physical Mac–Windows QA | NOT MEASURED |
