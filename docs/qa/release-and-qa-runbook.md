# Release and QA runbook

This runbook records procedure; it is not evidence that a release or physical
end-to-end test occurred.

1. Run formatting, lint, workspace tests, installer contract tests, dependency
   and license audit, and secret scan.
2. Build macOS arm64, macOS x64, and Windows x64 from one reviewed tag.
3. Publish SHA-256 checksums beside every binary.
4. On clean non-admin accounts, install twice, open a new terminal, run
   `seamless-input doctor`, uninstall, and verify identities remain.
5. Copy the authoritative `docs/qa/physical-qa-matrix.md` and run the
   artifact-provenance, two-machine installation,
   safety-shortcut, pairing, bidirectional input, clipboard, crossing, and
   recovery checks on real hardware.
6. Complete every matrix row with PASS evidence, FAIL evidence plus an issue,
   or a reason for NOT MEASURED. A CI build is not physical-platform evidence.
7. Only after independent review and explicit publication approval, publish
   release assets and verify the public installation commands.

Never weaken permissions, open a firewall, install a service or driver, alter
policy, or use SSH to make a row pass.
