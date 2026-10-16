# Guided setup: isolated foundations

Internal phase-1 slice, not a release or security approval. Design baseline SHA-256:
`f790167ddfb2f295e1a3c2c129d6f48e46bd58bc10c984e5f41bb190e7b0fa07`.
The initial V01–V16 cryptographic reference received a separate NO-GO and is
**not** imported, implemented, or treated as trusted by this change. At handoff,
the coordinator reported independent internal GO for corrected reference commit
`03d6148fc68969099ada11c3d7c3bd6e99514ce2` (30/30 tests, mutants and regeneration).
That evidence was not rerun by this phase-1 implementation and those fixtures
remain unconsumed here. Internal GO is not release approval.

## Enabled scope

`seamless-input control --stdio` exposes a separate, bounded local control engine.
It never constructs the input/clipboard supervisor, opens a pairing listener,
discovers peers, or writes identity pins. Existing CLI commands are unchanged;
the new engine does not dispatch or fall back to them.

Messages use a four-byte unsigned big-endian byte length followed by UTF-8 JSON,
at most 256 KiB per message. Requests have exactly `v`, `id`, `command`, `args`.
Version is 1; ID is 1–64 ASCII letters/digits/underscore/hyphen; args is an object.
Supported commands are `snapshot`, `diagnostics.snapshot`, `inventory.refresh`,
and `shutdown`, each with empty args. Pairing, legacy, input and clipboard
commands return `not_available_in_foundations`. Errors never echo arguments.

One process owns a configured user root. EOF releases the process lock. A session
accepts at most 256 unique request IDs. Exact replays return the cached response
without repeated events; changed requests with an existing ID fail. Responses
precede associated events. Events carry a random engine ID and increasing `seq`.
There are no capture leases to release because this engine cannot acquire any.

Snapshots report this engine's authenticated sessions as zero, all capabilities
disabled, and unmeasured identity/permissions/policy as `not_measured`, never
implicitly successful. This is not a diagnostic snapshot of another running
legacy process.

## Display measurements and deliberate gaps

Every display returned by the existing read-only Mac/Windows adapter becomes a
separate descriptor. Logical origin/extent and backing scale are measured and
validated. Runtime indices are not claimed as stable IDs. Native/framebuffer
pixels, effective DPI, rotation, physical millimeters, primary and mirror groups
remain null until explicitly supported by OS collectors. No dimensions are
invented by multiplying logical size by scale. Physical-size quality is
`unavailable` and `layout_ready` remains false.

The descriptor digest is a SHA-256 change fingerprint of canonical schema-1 JSON,
not a signed layout consent digest or security transcript. It excludes collection
generation and normalizes enumeration order and negative-zero origins. Frozen
JSON fixtures cover this contract, not cryptographic pairing interoperability.

## Quarantined persistence

`PendingStore` is an isolated library foundation; no control command exposes it.
It stores inert attempt/peer-fingerprint metadata in `pairing-pending`, with a
separate authoritative ledger in `pairing-tombstones`. Active `peers.json` is
neither read nor written by it. `promote()` always returns
`VerificationUnavailable`; there is no caller-supplied `verified: true` escape.

On Unix, directory-FD anchored IO rejects symlinks under the trusted root,
non-owner files, group/world access, nonregular files and hardlinked files.
Directories use 0700 and files 0600. Operations lock, reload, validate and compare
the complete expected `(revision, identity_generation)` before atomic rename and
file/directory sync. Cancellation and candidate revocation durably tombstone
before file deletion. An orphan candidate after a failed ledger write is not
visible. Missing initialized ledger, corruption, unsupported schema, limits and
write/sync failures fail closed.

`revoke_candidate` only revokes quarantine entries; it does not unpair existing
legacy identities. `rotate_identity` advances a setup epoch and invalidates
pending entries; it does not rotate or inspect actual private keys. Integrating
real identity changes with that epoch is explicitly future work. SHA-256 detects
accidental mismatch between file and ledger; it does not defend against malicious
same-user modification of both or full-directory rollback. The trusted local
root and its ancestor path are caller-controlled; no peer chooses those paths.

Windows pending persistence returns `UnsupportedPlatform` before creating files.
It must not be enabled until owner-only ACL, reparse-point, atomic replacement,
locking and durability behavior has target tests. Windows control uses a local
session mutex; this is process coordination, not a persistent security boundary.

## Verification recorded on 2026-10-16

Environment: aarch64 macOS; Rust 1.99.0; offline dependency cache. Baseline was 192
passed and two preexisting ignored tests. Final phase-1 tree: **215 passed, two
ignored**, including 23 new tests (9 control, 4 inventory, 10 quarantine).

Executed commands:

```text
cargo test --workspace --offline --quiet
cargo clippy --workspace --all-targets --offline -- -D warnings
cargo fmt --all -- --check
cargo check -p seamless-input-core -p seamless-input-platform-windows --target x86_64-pc-windows-msvc --offline --quiet
```

TDD observed actual assertion failures before implementations for framing/control,
inventory conversion/refresh, quarantine CAS and lifecycle, process ownership,
and event sequencing. Three temporary production mutants were run individually,
each made its intended test fail, and all were restored:

| Mutant | Test that rejected it |
| --- | --- |
| Allow pending promotion | `quarantined_candidate_never_appears_in_active_pins` |
| Bypass expected-version comparison | `stale_writer_cannot_overwrite_a_durable_revoke_after_reopen` |
| Accept unknown/unsafe control commands | `unsafe_commands_never_fall_through_to_legacy_pairing_or_runtime` |

Fault cases include truncated/oversize framing, duplicate IDs with changed
payload, corruption, missing ledger, indirect paths, concurrent independent CAS
writers, restart after revocation and denied ledger writes. They do **not** claim
process-kill-at-every-fsync, hardware power-loss, complete mutation coverage,
cryptographic replay resistance, or end-to-end layout consent.

The core and existing Windows adapter cross-check passed. A standalone ignored
compile probe of the exact Windows mutex source also passed. Full Windows
workspace cross-check stopped in the existing `ring` C build because this Mac
lacks MSVC SDK headers (`assert.h`). Windows runtime, ACL storage and actual
Windows display measurements are **not measured**. No CI, remote execution,
signing, deployment or publication was performed.

## Next gate

Keep this branch isolated. Review the foundations and close native storage and
inventory gaps separately. Phase 2 may be recommended against corrected reference
`03d6148fc68969099ada11c3d7c3bd6e99514ce2` after phase-1 review; it is not started
in this delivery. Do not wire pending records into admission, invent new crypto,
enable legacy auto-pin, or consume the rejected fixture revision. Release remains
NO-GO pending external security audit and real-OS verification.
