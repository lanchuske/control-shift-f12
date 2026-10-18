#!/usr/bin/env python3
"""Validate the public repository's structure, links, and privacy boundary."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]

ALLOWED_ROOT_ENTRIES = {
    ".github",
    ".gitattributes",
    ".gitignore",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "Cargo.lock",
    "Cargo.toml",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "apps",
    "crates",
    "deny.toml",
    "docs",
    "native",
    "scripts",
}

PRIVATE_REFERENCES = {
    "colibird-ai",
    "lmcp-mac",
    "lmcp-win",
    "lmcp-vault",
}

FORBIDDEN_PATH_PARTS = {
    "superpowers",
    "implementer-report",
    "review-report",
}

MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [ROOT / item.decode() for item in result.stdout.split(b"\0") if item]


def check_root(errors: list[str]) -> None:
    actual = {
        path.name
        for path in ROOT.iterdir()
        if path.name not in {".git", ".worktrees", "target"}
    }
    unexpected = sorted(actual - ALLOWED_ROOT_ENTRIES)
    missing = sorted(ALLOWED_ROOT_ENTRIES - actual)
    if unexpected:
        errors.append(f"unexpected root entries: {', '.join(unexpected)}")
    if missing:
        errors.append(f"missing required root entries: {', '.join(missing)}")


def check_internal_artifacts(files: list[Path], errors: list[str]) -> None:
    for path in files:
        relative = path.relative_to(ROOT).as_posix().lower()
        if any(part in relative for part in FORBIDDEN_PATH_PARTS):
            errors.append(f"internal planning or report artifact is tracked: {relative}")


def check_public_text(files: list[Path], errors: list[str]) -> None:
    public_text = [
        path
        for path in files
        if path.suffix.lower() in {".md", ".yml", ".yaml"}
        and (path.parent == ROOT or "docs" in path.parts or ".github" in path.parts)
    ]
    for path in public_text:
        text = path.read_text(encoding="utf-8")
        lowered = text.lower()
        for reference in PRIVATE_REFERENCES:
            if reference in lowered:
                errors.append(
                    f"private operational reference {reference!r} in "
                    f"{path.relative_to(ROOT)}"
                )
        if "github.com/lanchuske/seamless-input" in lowered:
            errors.append(f"stale public repository URL in {path.relative_to(ROOT)}")


def check_markdown_links(files: list[Path], errors: list[str]) -> None:
    for path in files:
        if path.suffix.lower() != ".md":
            continue
        text = path.read_text(encoding="utf-8")
        for match in MARKDOWN_LINK.finditer(text):
            destination = match.group(1).strip().split()[0].strip("<>")
            if not destination or destination.startswith(("#", "mailto:")):
                continue
            if re.match(r"^[a-z][a-z0-9+.-]*://", destination, re.IGNORECASE):
                continue
            relative_target = unquote(destination.split("#", 1)[0].split("?", 1)[0])
            if not relative_target:
                continue
            target = (path.parent / relative_target).resolve()
            if ROOT not in target.parents and target != ROOT:
                errors.append(
                    f"relative link escapes repository in {path.relative_to(ROOT)}: "
                    f"{destination}"
                )
            elif not target.exists():
                errors.append(
                    f"broken relative link in {path.relative_to(ROOT)}: {destination}"
                )


def main() -> int:
    errors: list[str] = []
    files = tracked_files()
    check_root(errors)
    check_internal_artifacts(files, errors)
    check_public_text(files, errors)
    check_markdown_links(files, errors)

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(
        f"Public repository contract passed: {len(files)} tracked files, "
        f"{len(ALLOWED_ROOT_ENTRIES)} approved root entries."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
