# Contributing to SeamlessInput

Thank you for helping build a small, safe software KVM for macOS and Windows.

Use Discussions for questions, compatibility reports, ideas, and design work.
Use an Issue for a reproducible defect or an agreed, in-scope change. Report
vulnerabilities privately as described in `SECURITY.md`.

The MVP scope is mouse, keyboard, text/PNG clipboard, peer discovery and
pairing, cardinal display topology, diagnostics, and per-user installation.
Remote desktop, file transfer, screen capture, login/UAC control, privileged
services, drivers, policy changes, and policy bypass are out of scope. Propose
scope changes in a separate design Discussion.

Pull requests must include tests, permission/privacy impact, supported platform
impact, and honest evidence labeled PASS, FAIL, or NOT MEASURED. Run:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 scripts/test-installers.py
```

Never attach keys, clipboard contents, usernames, network addresses, or stable
machine identifiers to Issues or diagnostic reports.
