#!/usr/bin/env python3
"""Static boundary checks for the non-shipping native hosts.

These checks deliberately inspect manifests and design records only.  They do
not launch a native host or turn the host boundary into a runtime path.
"""

from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
MACOS_MANIFEST = ROOT / "native/macos/ControlShiftF12App/Package.swift"
WINDOWS_MANIFEST = ROOT / "native/windows/ControlShiftF12App/ControlShiftF12App.csproj"
NATIVE_README = ROOT / "native/README.md"
BOUNDARY_RECORD = ROOT / "docs/architecture/native-host-boundary.md"
SAS_MATRIX = ROOT / "docs/architecture/discovery-sas-security-matrix.md"
NONSHIPPING_NATIVE_PATHS = frozenset(
    {
        "native/README.md",
        "native/macos/ControlShiftF12App/Package.swift",
        "native/macos/ControlShiftF12App/README.md",
        "native/windows/ControlShiftF12App/ControlShiftF12App.csproj",
        "native/windows/ControlShiftF12App/README.md",
    }
)
HOST_SOURCE_SUFFIXES = (".swift", ".cs", ".m", ".mm", ".h")
BUILD_OUTPUT_SUFFIXES = (
    ".dll",
    ".dylib",
    ".so",
    ".exe",
    ".a",
    ".lib",
    ".o",
    ".obj",
    ".pdb",
    ".nupkg",
    ".msi",
    ".pkg",
    ".dmg",
)
BUILD_OUTPUT_SEGMENTS = frozenset({".build", "bin", "obj", "DerivedData"})
HOST_BUNDLE_SUFFIXES = (".app", ".bundle", ".framework", ".xcarchive")


def is_nonshipping_native_path(path):
    """Only reviewable declarations may be tracked before adapter approval."""
    return path in NONSHIPPING_NATIVE_PATHS


def is_blocked_native_artifact(path):
    parts = path.split("/")
    if BUILD_OUTPUT_SEGMENTS.intersection(parts):
        return True
    if any(part.endswith(HOST_BUNDLE_SUFFIXES) for part in parts):
        return True
    if path.endswith(HOST_SOURCE_SUFFIXES) and not path.endswith("Package.swift"):
        return True
    return path.endswith(BUILD_OUTPUT_SUFFIXES)


def tracked_native_paths():
    result = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z", "native"],
        check=True,
        capture_output=True,
    )
    return {
        path.decode("utf-8")
        for path in result.stdout.split(b"\0")
        if path
    }


class NativeHostBoundaryTests(unittest.TestCase):
    def test_nonshipping_native_tree_has_only_reviewed_manifests_and_docs(self):
        tracked = tracked_native_paths()
        unexpected = sorted(tracked - NONSHIPPING_NATIVE_PATHS)
        self.assertEqual(
            unexpected,
            [],
            "adapter approval is required before tracking native host material",
        )
        self.assertEqual(tracked, NONSHIPPING_NATIVE_PATHS)
        blocked = sorted(path for path in tracked if is_blocked_native_artifact(path))
        self.assertEqual(blocked, [], "tracked host source or build output is forbidden")

    def test_nonshipping_gate_rejects_host_sources_bundles_and_build_outputs(self):
        prohibited = (
            "native/macos/ControlShiftF12App/Sources/App.swift",
            "native/windows/ControlShiftF12App/Program.cs",
            "native/macos/ControlShiftF12App/ControlShiftF12.app/Contents/MacOS/ControlShiftF12",
            "native/windows/ControlShiftF12App/bin/Release/ControlShiftF12App.exe",
            "native/windows/ControlShiftF12App/obj/Release/ControlShiftF12App.dll",
            "native/macos/ControlShiftF12App/.build/debug/ControlShiftF12App",
            "native/macos/ControlShiftF12App/ControlShiftF12.bundle/Contents/Info.plist",
        )
        for path in prohibited:
            self.assertFalse(is_nonshipping_native_path(path), path)
            self.assertTrue(is_blocked_native_artifact(path), path)

    def test_native_hosts_exist_and_do_not_create_a_control_network_endpoint(self):
        self.assertTrue(MACOS_MANIFEST.is_file())
        self.assertTrue(WINDOWS_MANIFEST.is_file())

        native_sources = []
        for suffix in ("*.swift", "*.cs", "*.csproj", "Package.swift"):
            native_sources.extend((ROOT / "native").rglob(suffix))
        native_text = "\n".join(path.read_text() for path in native_sources)
        forbidden = (
            "http://",
            "https://",
            "import Network",
            "import CFNetwork",
            "import WebKit",
            "import Darwin",
            "using System.Net",
            "System.Net.",
            "using System.IO.Pipes",
            "System.IO.Pipes.",
            "TcpListener",
            "TcpClient",
            "UdpClient",
            "Socket",
            "NetworkStream",
            "HttpClient",
            "HttpWebRequest",
            "WebClient",
            "NamedPipeServerStream",
            "NamedPipeClientStream",
            "NSURLConnection",
            "NWConnection",
            "NWListener",
            "NWBrowser",
            "CFSocket",
            "CFStream",
            "URLSession",
            "URLRequest",
            "URLComponents",
            "WebSocketTask",
            "ProcessStartInfo",
            "Process.Start",
            'Process.Start("cmd',
            "cmd.exe",
            "powershell",
            "pwsh",
            "CreateProcess",
            "NSTask",
            "Foundation.Process",
            "Process()",
            "posix_spawn",
            "popen(",
            "system(",
            '"/bin/sh"',
            '"/bin/zsh"',
        )
        for token in forbidden:
            self.assertNotIn(token, native_text, token)

    def test_hosts_are_declared_as_nonshipping_pipe_clients_of_the_existing_engine(self):
        macos_manifest = MACOS_MANIFEST.read_text()
        windows_manifest = WINDOWS_MANIFEST.read_text()
        native_readme = NATIVE_README.read_text()
        boundary_record = BOUNDARY_RECORD.read_text()
        control_api = (ROOT / "apps/seamless-input/src/control_api.rs").read_text()

        self.assertIn(".executableTarget", macos_manifest)
        self.assertIn(".macOS(.v13)", macos_manifest)
        self.assertNotIn(".package(", macos_manifest)
        self.assertIn("net8.0-windows", windows_manifest)
        self.assertIn("UseWindowsForms>true", windows_manifest)
        self.assertNotIn("PackageReference", windows_manifest)

        for text in (native_readme, boundary_record):
            self.assertIn("seamless-input control --stdio", text)
            self.assertIn("argument vector", text)
            self.assertIn("anonymous inherited", text)
            self.assertIn("MAX_FRAME_BYTES", text)
            self.assertIn("256 KiB", text)
            self.assertIn("allowlist", text)
            self.assertIn("non-shipping", text)
        self.assertIn("pub const MAX_FRAME_BYTES: usize = 256 * 1024", control_api)

    def test_sas_display_is_ephemeral_and_cannot_become_host_history(self):
        """The one visible secret has a narrow current-view-only exception."""
        matrix = SAS_MATRIX.read_text()
        boundary_record = BOUNDARY_RECORD.read_text()

        for text in (matrix, boundary_record):
            normalized = " ".join(text.split())
            self.assertIn("SasDisplayView", normalized)
            self.assertIn("non-serializable", normalized)
            self.assertIn("not persistible", normalized)
            self.assertIn("not loggable", normalized)
            self.assertIn("not copyable", normalized)
            self.assertIn("terminal", normalized)
            self.assertIn("timeout", normalized)

        self.assertIn("accessibility cache/history", matrix)
        self.assertIn("details suffix", matrix)


if __name__ == "__main__":
    unittest.main()
