#!/usr/bin/env python3
"""Regression tests for the public release/version contract."""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.1.1"
TAG = f"v{VERSION}"
MAC_ASSET = f"Control-Shift-F12-{TAG}-universal.dmg"
WINDOWS_ASSET = f"Control-Shift-F12-{TAG}-windows-x64.exe"


class ReleaseContractTests(unittest.TestCase):
    def test_candidate_tag_matches_workspace_lock_and_release_gate(self):
        result = subprocess.run(
            ["python3", "scripts/check-release-contract.py", TAG],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"release contract passed for {TAG}", result.stdout.lower())

        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn('python3 scripts/check-release-contract.py "${GITHUB_REF_NAME}"', workflow)
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("python3 scripts/test-release-contract.py", ci)

    def test_readme_uses_current_candidate_and_vault_asset_names(self):
        readme = (ROOT / "README.md").read_text()
        self.assertIn("# Control Shift F12", readme)
        self.assertIn(f"Control Shift F12 {TAG} QA Preview", readme)
        self.assertIn(MAC_ASSET, readme)
        self.assertIn(WINDOWS_ASSET, readme)
        self.assertIn("SHA256SUMS", readme)
        self.assertNotIn("SeamlessInput v0.1.0 QA Preview", readme)

    def test_readme_has_durable_release_navigation_and_visible_first_run(self):
        readme = (ROOT / "README.md").read_text()
        self.assertIn(
            "https://github.com/lanchuske/control-shift-f12/releases",
            readme,
        )
        self.assertIn("first-run window", readme.lower())
        self.assertIn("accessibility", readme.lower())
        self.assertRegex(readme.lower(), r"installed\s+apps")


if __name__ == "__main__":
    unittest.main()
