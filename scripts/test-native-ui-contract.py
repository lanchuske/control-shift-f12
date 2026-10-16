#!/usr/bin/env python3
"""Static boundary checks for the non-shipping native hosts.

These checks deliberately inspect manifests and design records only.  They do
not launch a native host or turn the host boundary into a runtime path.
"""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MACOS_MANIFEST = ROOT / "native/macos/ControlShiftF12App/Package.swift"
WINDOWS_MANIFEST = ROOT / "native/windows/ControlShiftF12App/ControlShiftF12App.csproj"
NATIVE_README = ROOT / "native/README.md"
BOUNDARY_RECORD = ROOT / "docs/architecture/native-host-boundary.md"


class NativeHostBoundaryTests(unittest.TestCase):
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
            "TcpListener",
            "TcpClient",
            "UdpClient",
            "NetworkStream",
            "HttpClient",
            "HttpWebRequest",
            "WebClient",
            "NamedPipeServerStream",
            "NSURLConnection",
            "NWConnection",
            "URLSession",
            'Process.Start("cmd',
            "NSTask",
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


if __name__ == "__main__":
    unittest.main()
