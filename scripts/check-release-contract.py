#!/usr/bin/env python3
"""Fail a release when its tag, workspace, CLI, or public assets drift."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_PACKAGES = {
    "seamless-input",
    "seamless-input-core",
    "seamless-input-platform-macos",
    "seamless-input-platform-windows",
    "seamless-input-protocol",
    "seamless-discovery",
    "seamless-transport",
}


def workspace_version() -> str:
    manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    match = re.search(
        r"(?ms)^\[workspace\.package\]\s*$.*?^version\s*=\s*\"([^\"]+)\"",
        manifest,
    )
    if not match:
        raise ValueError("Cargo.toml has no workspace package version")
    return match.group(1)


def locked_workspace_versions() -> dict[str, str]:
    lock = (ROOT / "Cargo.lock").read_text(encoding="utf-8")
    packages: dict[str, str] = {}
    for block in lock.split("[[package]]")[1:]:
        name = re.search(r'(?m)^name = "([^"]+)"$', block)
        version = re.search(r'(?m)^version = "([^"]+)"$', block)
        if name and version and name.group(1) in WORKSPACE_PACKAGES:
            packages[name.group(1)] = version.group(1)
    return packages


def check(tag: str) -> list[str]:
    errors: list[str] = []
    if not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        return [f"invalid release tag: {tag!r}"]

    version = workspace_version()
    if tag != f"v{version}":
        errors.append(f"tag {tag} does not match workspace version {version}")

    locked = locked_workspace_versions()
    missing = WORKSPACE_PACKAGES - locked.keys()
    if missing:
        errors.append(f"workspace packages missing from Cargo.lock: {', '.join(sorted(missing))}")
    drifted = {name: value for name, value in locked.items() if value != version}
    if drifted:
        detail = ", ".join(f"{name}={value}" for name, value in sorted(drifted.items()))
        errors.append(f"Cargo.lock workspace versions do not match {version}: {detail}")

    cli = (ROOT / "apps/seamless-input/src/main.rs").read_text(encoding="utf-8")
    cli_test = (ROOT / "apps/seamless-input/tests/cli.rs").read_text(encoding="utf-8")
    if '#[command(' not in cli or "version" not in cli:
        errors.append("CLI does not expose the Cargo package version")
    if 'env!("CARGO_PKG_VERSION")' not in cli_test:
        errors.append("CLI version test is not bound to the Cargo package version")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    expected_assets = {
        f"Control-Shift-F12-{tag}-universal.dmg",
        f"Control-Shift-F12-{tag}-windows-x64.exe",
        "SHA256SUMS",
    }
    for asset in expected_assets:
        if asset not in readme:
            errors.append(f"README does not reference release asset {asset}")
    if f"Control Shift F12 {tag} QA Preview" not in readme:
        errors.append(f"README does not identify {tag} as the QA Preview")

    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: check-release-contract.py vX.Y.Z", file=sys.stderr)
        return 2
    errors = check(argv[1])
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"Release contract passed for {argv[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
