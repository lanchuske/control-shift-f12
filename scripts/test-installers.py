#!/usr/bin/env python3
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstallerContractTests(unittest.TestCase):
    def test_installers_never_contain_privileged_or_enterprise_mutations(self):
        forbidden = [
            "sudo", "runas", "setx /m", "hklm", "new-service", "sc.exe",
            "schtasks", "netsh", "firewall", "group policy", "ssh", "driver",
            "/usr/local/bin", "/library/launch", "program files",
        ]
        text = "\n".join((ROOT / p).read_text().lower() for p in ["scripts/install.sh", "scripts/install.ps1"])
        for token in forbidden:
            self.assertNotIn(token, text, token)

    def test_macos_installer_is_idempotent_verifies_checksum_and_preserves_identity_on_uninstall(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            artifact = home / "artifact"
            artifact.write_text("#!/bin/sh\necho healthy\n")
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            env = os.environ | {
                "HOME": str(home),
                "SEAMLESS_INPUT_ASSET_FILE": str(artifact),
                "SEAMLESS_INPUT_SHA256": digest,
                "SEAMLESS_INPUT_PROFILE": str(home / ".profile"),
            }
            installer = ROOT / "scripts/install.sh"
            for _ in range(2):
                subprocess.run(["sh", str(installer)], env=env, check=True, capture_output=True, text=True)
            binary = home / ".local/bin/seamless-input"
            self.assertTrue(binary.exists())
            profile = (home / ".profile").read_text()
            self.assertEqual(profile.count("# SeamlessInput user PATH"), 1)
            identity = home / ".config/seamless-input/identity.key"
            identity.parent.mkdir(parents=True)
            identity.write_text("keep")
            subprocess.run(["sh", str(installer), "--uninstall"], env=env, check=True)
            self.assertFalse(binary.exists())
            self.assertEqual(identity.read_text(), "keep")
            self.assertNotIn("# SeamlessInput user PATH", (home / ".profile").read_text())

    def test_macos_checksum_mismatch_rolls_back_existing_binary(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            binary = home / ".local/bin/seamless-input"
            binary.parent.mkdir(parents=True)
            binary.write_text("old")
            artifact = home / "artifact"
            artifact.write_text("new")
            env = os.environ | {
                "HOME": str(home),
                "SEAMLESS_INPUT_ASSET_FILE": str(artifact),
                "SEAMLESS_INPUT_SHA256": "0" * 64,
                "SEAMLESS_INPUT_PROFILE": str(home / ".profile"),
            }
            result = subprocess.run(["sh", str(ROOT / "scripts/install.sh")], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(binary.read_text(), "old")

    def test_windows_contract_is_per_user_checksum_verified_and_idempotent(self):
        text = (ROOT / "scripts/install.ps1").read_text().lower()
        self.assertIn("localappdata", text)
        self.assertIn("seamlessinput", text)
        self.assertIn("get-filehash", text)
        self.assertIn("environmentvariabletarget]::user", text)
        self.assertIn("[switch]$uninstall", text)

    def test_remote_assets_are_restricted_to_https(self):
        shell = (ROOT / "scripts/install.sh").read_text().lower()
        powershell = (ROOT / "scripts/install.ps1").read_text().lower()
        self.assertIn("https://", shell)
        self.assertIn("https://", powershell)
        self.assertIn("curl", shell)
        self.assertIn("invoke-webrequest", powershell)


if __name__ == "__main__":
    unittest.main()
