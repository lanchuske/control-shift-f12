# SeamlessInput MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a free, no-admin Mac/Windows peer mesh with a TUI for seamless mouse, keyboard, and text/PNG clipboard sharing.

**Architecture:** One Rust executable gives every machine the same peer role. mDNS discovers peers; PAKE pairing creates mutually pinned identities; QUIC/TLS carries input and clipboard frames; a pure topology engine routes the active pointer between cardinally adjacent displays.

**Tech Stack:** Rust stable, Tokio, Quinn/rustls, SPAKE2, rmp-serde, mdns-sd, sha2, arboard, clap, Ratatui, CoreGraphics, Windows APIs.

**Spec:** `docs/specs/seamless-input-mvp.md`

## Global Constraints

- Never request administrator elevation or write outside user-owned locations.
- Never create services, drivers, scheduled tasks, firewall rules, or policy changes.
- Never use or configure SSH; the application owns its QUIC/TLS channel.
- macOS and Windows only; normal signed-in user sessions only.
- macOS may request the minimum user-granted Accessibility and pasteboard
  consent required by the operating system, but never administrator elevation.
- Permission denial must degrade safely and remain reversible; never loop,
  nag, synthesize approval, or bypass the operating system prompt.
- Scope: pointer, keyboard, text clipboard, PNG clipboard.
- Frame limit 8 MiB; text limit 1 MiB; PNG limit 8 MiB.
- Disconnect releases all modifiers and returns control locally.
- Public MIT repository; no credentials or machine-specific data.

---

### Task 1: Public-ready workspace and CLI contract

**Files:**
- Create: `Cargo.toml`
- Create: `LICENSE`
- Create: `README.md`
- Create: `apps/seamless-input/Cargo.toml`
- Create: `apps/seamless-input/src/main.rs`
- Create: `apps/seamless-input/tests/cli.rs`

**Interfaces:**
- Produces exact commands `start`, `pair new`, `pair <code>`, `peers`, `unpair`, `tui`, `doctor`, and `config`.

- [ ] Write failing CLI snapshot tests for every command and for rejection of legacy `server` or `client` roles.
- [ ] Run `cargo test --workspace`; verify missing-command failures.
- [ ] Implement the Clap command tree, structured exit codes, and version output.
- [ ] Run fmt, clippy with warnings denied, and CLI tests; require PASS.
- [ ] Commit `feat: scaffold symmetric SeamlessInput CLI`.

### Task 2: Bounded protocol and pure topology engine

**Files:**
- Create: `crates/protocol/{Cargo.toml,src/lib.rs,tests/framing.rs}`
- Create: `crates/core/{Cargo.toml,src/lib.rs,src/topology.rs,src/control.rs,tests/topology.rs,tests/control.rs}`

**Interfaces:**
- Produces `Frame`, `InputEvent`, `Display`, `NodeId`, `Edge`, `Topology`, `Controller`, and `Action`.

- [ ] Write failing framing tests for round-trip, truncation, unknown version, 8 MiB limit, stale sequence, and duplicate sequence.
- [ ] Write failing topology tests for four cardinal edges, reciprocal edges, collision rejection, cycles, multiple displays, differing scale factors, and three-peer traversal.
- [ ] Write failing control tests for one active target, edge crossing, emergency return, disconnect, timeout, and modifier release.
- [ ] Implement length-prefixed MessagePack frames and a deterministic platform-free topology/controller.
- [ ] Run unit and property tests with 10,000 generated valid coordinates; require PASS.
- [ ] Commit `feat: add bounded protocol and peer topology`.

### Task 3: Discovery and simultaneous peer connection

**Files:**
- Create: `crates/discovery/{Cargo.toml,src/lib.rs,src/mdns.rs,tests/discovery.rs}`
- Create: `crates/transport/{Cargo.toml,src/lib.rs,src/quic.rs,tests/simultaneous.rs}`

**Interfaces:**
- Produces `Discovery::publish`, `Discovery::browse`, `PeerEndpoint::bind`, and one elected `PeerSession` per node pair.

- [ ] Write failing discovery tests for publish/browse, TTL expiry, duplicate advertisements, version mismatch, manual-address fallback, and privacy-safe TXT records.
- [ ] Write failing QUIC tests where both peers dial simultaneously and the lexicographically lower node ID retains the single canonical session.
- [ ] Implement mDNS service `_seamless-input._udp.local` and manual address resolution.
- [ ] Implement one user-level QUIC endpoint that both accepts and initiates connections, with heartbeat and bounded reconnect backoff.
- [ ] Run loopback and two-process tests with discovery disabled/enabled; require PASS.
- [ ] Commit `feat: discover peers and elect one QUIC session`.

### Task 4: Pairing and mutual identity

**Files:**
- Create: `crates/transport/src/identity.rs`
- Create: `crates/transport/src/pairing.rs`
- Create: `crates/transport/tests/pairing.rs`

**Interfaces:**
- Produces `IdentityStore`, `PairingCode`, `PairingSession`, pinned-peer records, and mutual TLS configuration.

- [ ] Write failing tests for six-word code entropy, five-minute expiry, one-time use, PAKE mismatch, replay, passive transcript resistance, pin mismatch, unpair, and owner-only identity files.
- [ ] Implement per-user Ed25519 identities and SPAKE2 pairing over a temporary QUIC stream.
- [ ] Persist only device public identity, friendly name, and certificate pin after pairing.
- [ ] Run pairing tests plus a two-process happy path and wrong-code path; require PASS.
- [ ] Commit `feat: pair peers with short-lived PAKE codes`.

### Task 5: Ratatui topology editor and atomic config

**Files:**
- Create: `apps/seamless-input/src/tui.rs`
- Create: `apps/seamless-input/src/config.rs`
- Create: `apps/seamless-input/tests/tui_snapshots.rs`
- Create: `apps/seamless-input/tests/config.rs`

**Interfaces:**
- Produces versioned `ConfigV1` and topology operations driven by arrows, Enter, Delete, S, and Q.

- [ ] Write snapshots for zero peers, unpaired discovery, horizontal, vertical, four-sided, multi-display, offline, and collision-error states at 80x24 and 120x40.
- [ ] Write config tests for atomic save, user-only paths, invalid-version rejection, crash-safe replacement, and no private key in config.
- [ ] Implement three panes: available peers, topology canvas, and contextual help.
- [ ] Implement atomic TOML persistence and live reload by the runtime.
- [ ] Run all snapshots and config tests; require PASS.
- [ ] Commit `feat: add peer discovery and topology TUI`.

### Task 6: macOS user-session adapter

**Files:**
- Create: `crates/platform-macos/{Cargo.toml,src/lib.rs,src/input.rs,src/displays.rs,src/clipboard.rs,tests/permissions.rs}`

**Interfaces:**
- Produces `MacInput`, `MacDisplays`, and `MacClipboard` behind shared platform traits.

- [ ] Write failing tests for Accessibility not-determined/denied/granted, one-shot prompt guidance, local pass-through, remote suppression, emergency chord, modifier cleanup, display scale mapping, clipboard consent denial, clipboard hash dedupe, and size rejection.
- [ ] Implement CoreGraphics event tap capture/injection for the current session only.
- [ ] Implement an explicit first-run permission explanation and safe degraded modes: discovery/pairing/topology remain available, input stays local when Accessibility is unavailable, and clipboard sync stays disabled when pasteboard access is unavailable.
- [ ] Implement display geometry and edge events.
- [ ] Implement text/PNG clipboard polling with change counts, 200 ms debounce, SHA-256 loop suppression, and no content logs.
- [ ] Run unit tests and an interactive non-admin permission/fail-safe smoke test.
- [ ] Commit `feat(macos): add input and clipboard peer adapter`.

### Task 7: Windows user-session adapter

**Files:**
- Create: `crates/platform-windows/{Cargo.toml,src/lib.rs,src/input.rs,src/displays.rs,src/clipboard.rs,tests/input_mapping.rs}`

**Interfaces:**
- Produces `WindowsInput`, `WindowsDisplays`, and `WindowsClipboard` behind the same platform traits.

- [ ] Write failing tests for hooks, absolute cursor mapping, buttons, wheel, scancodes, keyboard layouts, emergency chord, modifier cleanup, clipboard dedupe, and secure/elevated target refusal.
- [ ] Implement low-level user-session hooks and `SendInput` without drivers or elevation.
- [ ] Implement display geometry and edge events.
- [ ] Implement text/PNG clipboard synchronization with the shared bounds and hashes.
- [ ] Run Windows CI tests and an unelevated dedicated-window integration test.
- [ ] Commit `feat(windows): add input and clipboard peer adapter`.

### Task 8: Peer runtime, routing, and failure safety

**Files:**
- Create: `apps/seamless-input/src/runtime.rs`
- Create: `apps/seamless-input/src/peer.rs`
- Create: `crates/core/src/clipboard.rs`
- Create: `apps/seamless-input/tests/peer_mesh.rs`
- Create: `crates/core/tests/clipboard.rs`

**Interfaces:**
- Produces runtime routing, exclusive input lease, capability negotiation, and `ClipboardDeduper`.

- [ ] Write failing in-memory tests for two and three peers, topology routing, simultaneous reconnect, lease exclusion, stale input, peer disappearance, and safe local return.
- [ ] Write failing clipboard tests for text, PNG, malformed PNG, duplicate hashes, limits, loop prevention, and reconnect replay.
- [ ] Implement per-peer tasks and route only through the active reciprocal edge.
- [ ] Implement bounded clipboard offer/data exchange and suppress echoes by content hash.
- [ ] Run the workspace under paused Tokio time with forced disconnects; require PASS.
- [ ] Commit `feat: route input and clipboard across peer mesh`.

### Task 9: User-only installers, PATH, diagnostics, CI, and release

**Files:**
- Create: `scripts/install.sh`
- Create: `scripts/install.ps1`
- Create: `scripts/test-installers.py`
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/release.yml`
- Create: `docs/runbook.md`
- Create: `docs/evidence/e2e-template.md`
- Modify: `README.md`

**Interfaces:**
- Produces per-user installation, PATH update, `doctor`, checksummed binaries, and public release evidence.

- [ ] Write installer tests proving macOS uses `~/.local/bin`, Windows uses `%LOCALAPPDATA%\\SeamlessInput\\bin`, and only user shell/profile or user PATH is changed.
- [ ] Add negative tests that fail on elevation, system PATH, services, drivers, scheduled tasks, firewall commands, policy writes, SSH commands, or machine-specific values.
- [ ] Implement idempotent installers with preview, rollback, and explicit PATH refresh guidance.
- [ ] Implement `doctor` for permissions, discovery, QUIC reachability, pair pins, displays, clipboard, and enterprise blocks without evasion; distinguish user consent from administrator elevation.
- [ ] Add Mac arm64/x64 and Windows x64 CI/release builds, checksums, dependency/license audit, and secret scan.
- [ ] Run two-peer and mixed three-peer real E2E; record every acceptance row as PASS, FAIL, or NO MEDIDO.
- [ ] Create the public GitHub repository, push reviewed history, publish release assets, and verify clean per-user installation on both platforms.
- [ ] Commit `release: publish SeamlessInput MVP`.

## Self-review

- Coverage: symmetric roles, code pairing, LAN discovery, cardinal TUI, multi-peer
  Mac/Windows, cursor, keyboard, text/PNG clipboard, user PATH, public release,
  no-admin installation, and failure safety each have an implementation task.
- Placeholder scan: no deferred implementation placeholders are present.
- Type consistency: platform and runtime tasks consume the protocol/core traits
  defined before them; pairing identities are reused by QUIC sessions.
