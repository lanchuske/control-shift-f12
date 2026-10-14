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
    def trusted_environment(self, home, artifact):
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        attestation = home / "provenance.jsonl"
        attestation.write_text("test provenance bundle")
        tools = home / "tools"
        tools.mkdir()
        gh = tools / "gh"
        gh.write_text("#!/bin/sh\nexit 0\n")
        gh.chmod(0o755)
        return os.environ | {
            "HOME": str(home),
            "PATH": f"{tools}:{os.environ['PATH']}",
            "SEAMLESS_INPUT_ASSET_FILE": str(artifact),
            "SEAMLESS_INPUT_SHA256": digest,
            "SEAMLESS_INPUT_ATTESTATION_FILE": str(attestation),
        }

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
            env = self.trusted_environment(home, artifact) | {
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
            env = self.trusted_environment(home, artifact) | {
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

    def test_macos_zsh_install_updates_zprofile_by_default(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            artifact = home / "artifact"
            artifact.write_text("#!/bin/sh\necho healthy\n")
            env = self.trusted_environment(home, artifact) | {"SHELL": "/bin/zsh"}
            env.pop("SEAMLESS_INPUT_PROFILE", None)
            subprocess.run(
                ["sh", str(ROOT / "scripts/install.sh")],
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("# SeamlessInput user PATH", (home / ".zprofile").read_text())
            self.assertFalse((home / ".profile").exists())

    def test_failed_provenance_verification_preserves_existing_binary(self):
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            binary = home / ".local/bin/seamless-input"
            binary.parent.mkdir(parents=True)
            binary.write_text("old")
            artifact = home / "artifact"
            artifact.write_text("new")
            env = self.trusted_environment(home, artifact)
            (home / "tools/gh").write_text("#!/bin/sh\nexit 1\n")
            result = subprocess.run(
                ["sh", str(ROOT / "scripts/install.sh")],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(binary.read_text(), "old")

    def test_release_and_installers_require_independent_github_attestation(self):
        release = (ROOT / ".github/workflows/release.yml").read_text().lower()
        shell = (ROOT / "scripts/install.sh").read_text().lower()
        powershell = (ROOT / "scripts/install.ps1").read_text().lower()
        self.assertIn("attest-build-provenance", release)
        self.assertIn("id-token: write", release)
        self.assertIn("attestations: write", release)
        for text in (shell, powershell):
            self.assertIn("attestation", text)
            self.assertIn("gh", text)
            self.assertIn("lanchuske/seamless-input", text)

    def test_windows_identity_uses_dpapi_and_refuses_unprotected_keys(self):
        source = (ROOT / "crates/transport/src/identity.rs").read_text().lower()
        manifest = (ROOT / "crates/transport/Cargo.toml").read_text().lower()
        self.assertIn("cryptprotectdata", source)
        self.assertIn("cryptunprotectdata", source)
        self.assertIn("dpapi-current-user", source)
        self.assertIn("windows-sys", manifest)


if __name__ == "__main__":
    unittest.main()
