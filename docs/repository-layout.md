# Repository layout

Control Shift F12 keeps its repository root deliberately small. Every entry at
the root is either a standard open-source entry point or required by the Rust
workspace and its automated checks.

## Root inventory

| Entry | Classification | Why it remains at the root |
| --- | --- | --- |
| `.github/` | Community and automation | Issue forms, pull-request guidance, CI, and release automation must be discoverable by GitHub. |
| `.gitignore` | Project configuration | Prevents build output and isolated worktrees from entering version control. |
| `CODE_OF_CONDUCT.md` | Community | GitHub and contributors expect the conduct policy at a standard location. |
| `CONTRIBUTING.md` | Community | GitHub surfaces this guide automatically to prospective contributors. |
| `Cargo.toml` | Required build entry point | Defines the Rust workspace and its members. |
| `Cargo.lock` | Reproducible application build | Pins the exact dependency graph used by this application. |
| `LICENSE` | Legal | Keeps the MIT license visible to users, package tools, and GitHub. |
| `README.md` | Product entry point | Acts as the public landing page, download guide, status report, and documentation index. |
| `SECURITY.md` | Security | GitHub surfaces private vulnerability-reporting instructions from this standard location. |
| `deny.toml` | Dependency policy | `cargo deny` reads the repository policy from this expected location in local checks and CI. |
| `apps/` | Product code | Contains the executable application. |
| `crates/` | Product code | Contains focused protocol, core, discovery, transport, and platform libraries. |
| `docs/` | Public documentation | Architecture, QA, community, and repository navigation. |
| `scripts/` | Development and installation | Public installer contracts and repository checks used locally and in CI. |

Moving the manifest, lockfile, dependency policy, license, security policy, or
community entry points into a cosmetic subfolder would make standard tools and
GitHub navigation worse, so these entries intentionally remain visible.

## Code map

- `apps/seamless-input/` — command-line application, supervisor, configuration,
  terminal UI, and product-level integration tests.
- `crates/protocol/` — bounded wire messages and framing.
- `crates/core/` — topology, routing, clipboard, leases, and recovery rules.
- `crates/discovery/` — local discovery and manual addressing.
- `crates/transport/` — pairing, identities, QUIC sessions, and reconnect logic.
- `crates/platform-macos/` — macOS input, clipboard, display, and permission adapter.
- `crates/platform-windows/` — Windows input, clipboard, display, and permission adapter.

## Documentation map

- `docs/architecture/` — public product boundaries and architecture.
- `docs/qa/` — release procedure and truthful physical-QA evidence.
- `docs/community/` — feedback and participation guidance.

Internal plans, agent reports, signing credentials, private repository names,
temporary QA output, and generated build files do not belong in this public
tree. The `scripts/check-public-repo.py` contract enforces that boundary.
