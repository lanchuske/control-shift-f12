# Contributing to Control Shift F12

Thank you for helping build a small, safe software KVM for macOS and Windows.

## Find the right place

- Use [Discussions](https://github.com/lanchuske/control-shift-f12/discussions)
  for questions, compatibility reports, ideas, and design work.
- Use an [Issue](https://github.com/lanchuske/control-shift-f12/issues) for a
  reproducible defect or an agreed, in-scope change.
- Look for the `good first issue` label if this is your first contribution.
- Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

The MVP scope is mouse, keyboard, text/PNG clipboard, peer discovery and
pairing, cardinal display topology, diagnostics, and per-user installation.
Remote desktop, file transfer, screen capture, login/UAC control, privileged
services, drivers, policy changes, and policy bypass are out of scope. Propose
scope changes in a separate design Discussion.

## Set up a development checkout

You need Git, Python 3, and a current stable Rust toolchain with `rustfmt` and
`clippy`.

```text
git clone https://github.com/lanchuske/control-shift-f12.git
cd control-shift-f12
cargo build --workspace
```

The public product is named Control Shift F12. Some internal Rust packages,
commands, configuration paths, and release assets retain the original
`seamless-input` identifier for compatibility. Do not rename those identifiers
as part of an unrelated contribution.

See the [repository map](docs/repository-layout.md) before choosing a component.

## Make a focused change

1. Confirm an Issue exists or start a Discussion for a larger design.
2. Create a short-lived branch from `main`.
3. Add a focused test that fails before the correction when behavior changes.
4. Keep platform permission, privacy, and failure behavior explicit.
5. Open a small pull request and link its Issue or Discussion.

Pull requests must describe supported-platform impact and label evidence as
PASS, FAIL, or NOT MEASURED. A green simulator or unit test is not evidence of
physical Mac–Windows behavior.

## Verify before opening a pull request

Pull requests must include tests, permission/privacy impact, supported platform
impact, and honest evidence labeled PASS, FAIL, or NOT MEASURED. Run:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 scripts/test-installers.py
python3 scripts/check-public-repo.py
```

CI repeats these checks on Apple Silicon, Intel Mac, and Windows where
applicable. The [release and QA runbook](docs/qa/release-and-qa-runbook.md)
explains the stronger release gate.

Never attach keys, clipboard contents, usernames, network addresses, or stable
machine identifiers to Issues or diagnostic reports.
