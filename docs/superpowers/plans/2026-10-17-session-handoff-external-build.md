# Session handoff: external build storage

## Intent

Resume Control Shift F12 without consuming the internal system disk. This is a
local handoff only: do not sign, publish, deploy, or push a release from this
checkpoint.

## Repository checkpoint

- Worktree: `/Users/lanchu/Documents/Codex/seamless-input/.worktrees/candidate-native-host-pipe`
- Branch: `candidate/native-host-pipe`
- Baseline commit: `562d6ab` (`fix: abort cancelled bilateral commits exactly`)
- The worktree intentionally contains uncommitted Task 5 crash-recovery work:
  - `crates/transport/src/pairing_pending.rs`
  - `crates/transport/src/pairing_v2/admission_authority.rs`
  - `crates/transport/src/pairing_v2/provisional_tls/tests.rs`
  - `docs/superpowers/plans/2026-10-17-task4-crash-matrix.md`

Preserve those files. Do not reset, clean, or discard them on resume.

## External build storage

Cargo is persistently configured to build on the external volume:

```toml
# /Users/lanchu/.cargo/config.toml
[build]
target-dir = "/Volumes/LMCP/ControlShiftF12/cargo-target"
```

For explicit commands, use:

```sh
export TASK_CARGO=/Users/lanchu/.rustup/toolchains/stable-aarch64-apple-darwin/bin/cargo
export RUSTC=/Users/lanchu/.rustup/toolchains/stable-aarch64-apple-darwin/bin/rustc
export CARGO_TARGET_DIR=/Volumes/LMCP/ControlShiftF12/cargo-target
```

The default `cargo` executable currently fails with `bad CPU type in executable`;
use `TASK_CARGO` above until that environment issue is separately repaired.

The former in-worktree target cache was moved, not deleted, to:

`/Volumes/LMCP/ControlShiftF12/archived-target-candidate-native-host-pipe-20261017`

Do not remove that archive during the next session. Confirm the active target
directory before every large build:

```sh
"$TASK_CARGO" metadata --no-deps --format-version 1 | jq -r '.target_directory'
```

It must report `/Volumes/LMCP/ControlShiftF12/cargo-target`.

## Current verification boundary

Task 5 is testing recovery from a process death during each durable bilateral
admission phase.

Verified locally on macOS after the current uncommitted fix:

```sh
"$TASK_CARGO" test -p seamless-transport --features pairing-v2-experimental task4_ -- --nocapture
```

Result: Prepared, Staged, and the ambiguous legacy case pass; one intentional
test is ignored. The staged crash recovery bug was that a restart returned
`Revoked` instead of `Absent`. The pending fix recognizes a matching exact
`AwaitingHandoff` receipt and exact-aborts it, rather than using the legacy
ambiguous revocation fallback.

Windows is **NOT MEASURED** for this fix. The isolated Windows checkout built
and began the test run, but no completed result was captured. Resume with:

```sh
ssh windows 'powershell -NoProfile -Command "Set-Location C:\\Users\\lanch\\csf12-task5-staged; cargo test -p seamless-transport --features pairing-v2-experimental task4_ -- --nocapture"'
```

Do not treat a compilation or partial output as a Windows pass.

## Next work in order

1. Capture the full Windows result for the existing Task 5 test.
2. Finish actual subprocess kill/restart coverage for `ProofVerified`, `Frozen`,
   `StoreOwned`, one-finalize, and one-confirm boundaries.
3. Require each recovery case to leave no snapshot, pin, unilateral relation, or
   durable admission; the same peer must be able to retry cleanly.
4. Run an independent security review of the Task 5 changes, then commit only
   after the review and both platform results are recorded.
5. Continue the native desktop work only after the secure pairing engine passes
   its gates: WinForms host, AppKit parity, bilateral visual confirmation,
   draggable display map, synchronized sharing controls, connection panel, and
   physical Mac-to-Windows QA.

## Evidence vocabulary

- Implemented: local code exists.
- Tested locally: a complete recorded command passed on that platform.
- Validated by CI: not yet measured for this checkpoint.
- Physical Mac-Windows QA: not yet measured.

Never present local tests as integration, CI, release readiness, signed builds,
or physical QA.
