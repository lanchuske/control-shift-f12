# Task 9 implementer report

## Result

- **PASS:** macOS per-user installer contract, local-file and HTTPS asset paths,
  SHA-256 verification, rollback preservation, idempotent profile update,
  uninstall, and identity preservation.
- **PASS:** Windows installer static contract for the per-user LocalAppData
  location, user PATH only, HTTPS download, SHA-256 verification, rollback,
  idempotence, and uninstall preserving identities.
- **PASS:** negative installer scan rejects elevation, system PATH, services,
  drivers, scheduled tasks, firewall commands, policy writes, SSH, and common
  system installation locations.
- **PASS:** `doctor` and opt-in `doctor --report`; report tests inject sensitive
  environment values and prove the output omits them along with clipboard,
  key, username, address, and stable-machine fields.
- **PASS:** local Rust workspace tests, formatting, Clippy with warnings denied,
  installer tests, POSIX syntax check, and whitespace check.
- **PASS:** local CI/release workflow definitions, dependency/license policy,
  issue/PR templates, contributor/security/conduct docs, runbook, feedback
  guide, and E2E evidence template.
- **NOT MEASURED:** native execution of the PowerShell installer. A `pwsh`
  binary exists locally but is for an incompatible CPU architecture.
- **NOT MEASURED:** GitHub Actions on macOS arm64/x64 and Windows x64, dependency
  audit, secret scan, release asset generation, clean Windows install, physical
  two-peer/mixed-three-peer E2E, social-preview setting, Discussions category
  configuration, private-vulnerability setting, release publication, and public
  installation verification. These require remote/platform actions expressly
  excluded from this local task.

## Commands run

```text
python3 scripts/test-installers.py
cargo test --workspace --quiet
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
sh -n scripts/install.sh
python3 -m py_compile scripts/test-installers.py
git diff --check
```

The locally installed `shellcheck`, `actionlint`, and `pwsh` executables could
not run on this Apple Silicon host because those installations target an
incompatible CPU architecture. This is recorded as NOT MEASURED, not PASS.

No repository publication, release, remote setting, or physical E2E claim was
performed.
