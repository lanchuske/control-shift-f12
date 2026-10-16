#!/usr/bin/env python3
"""Static boundary checks for the admitted macOS diagnostics host.

The checks admit one reviewable AppKit source tree and its XCTest target. They
do not admit Windows source, bundles, build output, a network endpoint, or any
host capability beyond the fixed local child projection pipe.
"""

from pathlib import Path
import json
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
MACOS_MANIFEST = ROOT / "native/macos/ControlShiftF12App/Package.swift"
WINDOWS_MANIFEST = ROOT / "native/windows/ControlShiftF12App/ControlShiftF12App.csproj"
NATIVE_README = ROOT / "native/README.md"
BOUNDARY_RECORD = ROOT / "docs/architecture/native-host-boundary.md"
SAS_MATRIX = ROOT / "docs/architecture/discovery-sas-security-matrix.md"
HOST_PIPE_DESIGN = ROOT / "docs/architecture/native-host-process-pipe-adapter.md"
DESKTOP_PARITY_GATE = ROOT / "docs/architecture/desktop-functional-parity-gate.md"
SAS_FRAME_FIXTURE = ROOT / "docs/fixtures/sas-display-frame-v1.json"
NONSHIPPING_NATIVE_PATHS = frozenset(
    {
        "native/README.md",
        "native/macos/ControlShiftF12App/Package.swift",
        "native/macos/ControlShiftF12App/README.md",
        "native/windows/ControlShiftF12App/ControlShiftF12App.csproj",
        "native/windows/ControlShiftF12App/README.md",
    }
)
ADMITTED_MACOS_HOST_PATHS = frozenset(
    {
        "native/macos/ControlShiftF12App/Sources/ControlShiftF12App/main.swift",
        "native/macos/ControlShiftF12App/Tests/ControlShiftF12AppTests/ControlShiftF12AppTests.swift",
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
SAS_DETAILS_SUFFIX_TOKENS = frozenset({"attempt-current", "expires-soon"})
SAS_HOST_REQUEST_RESERVED_FIELDS = frozenset(
    {
        "v",
        "kind",
        "attempt_binding",
        "generation",
        "current",
        "remaining_ms",
        "code_groups",
        "details_suffix",
    }
)


def is_nonshipping_native_path(path):
    """Only the reviewed macOS diagnostics host may extend declarations."""
    return path in NONSHIPPING_NATIVE_PATHS | ADMITTED_MACOS_HOST_PATHS


def is_blocked_native_artifact(path):
    parts = path.split("/")
    if BUILD_OUTPUT_SEGMENTS.intersection(parts):
        return True
    if any(part.endswith(HOST_BUNDLE_SUFFIXES) for part in parts):
        return True
    if (
        path.endswith(HOST_SOURCE_SUFFIXES)
        and not path.endswith("Package.swift")
        and path not in ADMITTED_MACOS_HOST_PATHS
    ):
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


def is_u64(value):
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value <= (2**64 - 1)


def validate_sas_display_frame(frame):
    """Structural oracle for the docs-only child-to-host transient frame."""
    if not isinstance(frame, dict):
        return False
    common = {"v", "kind", "attempt_binding", "generation", "current"}
    if not common.issubset(frame):
        return False
    if frame["v"] != 1 or frame["kind"] != "sas_display_v1":
        return False
    if not is_u64(frame["attempt_binding"]) or not is_u64(frame["generation"]):
        return False
    if not isinstance(frame["current"], bool):
        return False
    if frame["current"]:
        allowed = common | {"remaining_ms", "code_groups", "details_suffix"}
        if set(frame) - allowed or not {"remaining_ms", "code_groups"}.issubset(frame):
            return False
        if not isinstance(frame["remaining_ms"], int) or isinstance(frame["remaining_ms"], bool):
            return False
        if not 1 <= frame["remaining_ms"] <= 30_000:
            return False
        groups = frame["code_groups"]
        if not isinstance(groups, list) or not 1 <= len(groups) <= 8:
            return False
        if any(
            not isinstance(group, str)
            or not 1 <= len(group) <= 32
            or not group.isascii()
            or not group.isprintable()
            for group in groups
        ):
            return False
        if "details_suffix" not in frame:
            return True
        suffix = frame["details_suffix"]
        return isinstance(suffix, str) and suffix in SAS_DETAILS_SUFFIX_TOKENS
    return set(frame) == common


def accepts_sas_display_sequence(frames):
    active = {}
    terminal = set()
    for frame in frames:
        if not validate_sas_display_frame(frame):
            return False
        binding = frame["attempt_binding"]
        generation = frame["generation"]
        if binding in terminal or generation <= active.get(binding, 0):
            return False
        if frame["current"]:
            active[binding] = generation
        else:
            if binding not in active:
                return False
            del active[binding]
            terminal.add(binding)
    return not active


def host_request_contains_sas(request):
    if not isinstance(request, dict):
        return True
    if request.get("command") == "sas_display_v1":
        return True
    def contains(value):
        if isinstance(value, dict):
            return any(
                key in SAS_HOST_REQUEST_RESERVED_FIELDS
                or child == "sas_display_v1"
                or contains(child)
                for key, child in value.items()
            )
        if isinstance(value, list):
            return any(contains(child) for child in value)
        return value == "sas_display_v1"

    return contains(request.get("args"))


class NativeHostBoundaryTests(unittest.TestCase):
    def test_native_tree_has_only_reviewed_manifests_docs_and_macos_diagnostics_host(self):
        tracked = tracked_native_paths()
        unexpected = sorted(tracked - (NONSHIPPING_NATIVE_PATHS | ADMITTED_MACOS_HOST_PATHS))
        self.assertEqual(
            unexpected,
            [],
            "only the approved macOS diagnostics host may be tracked",
        )
        self.assertEqual(tracked, NONSHIPPING_NATIVE_PATHS | ADMITTED_MACOS_HOST_PATHS)
        blocked = sorted(path for path in tracked if is_blocked_native_artifact(path))
        self.assertEqual(blocked, [], "tracked host source or build output is forbidden")

    def test_allowlist_rejects_other_host_sources_bundles_and_build_outputs(self):
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

    def test_macos_diagnostics_host_is_structurally_limited_to_the_fixed_child_pipe(self):
        """The sole admitted host cannot grow a shell, listener, or control surface."""
        source = (
            ROOT / "native/macos/ControlShiftF12App/Sources/ControlShiftF12App/main.swift"
        ).read_text()
        self.assertIn("import AppKit", source)
        self.assertIn('private static let childArguments = ["control", "--ui-stdio"]', source)
        self.assertIn("process.executableURL = executableURL", source)
        self.assertIn("process.arguments = Self.childArguments", source)
        self.assertIn("process.standardInput = inputPipe", source)
        self.assertIn("process.standardOutput = outputPipe", source)
        self.assertIn("process.standardError = errorPipe", source)
        self.assertIn("process.terminationHandler", source)
        self.assertIn("case .endOfFile, .pipeFailure, .termination", source)
        self.assertIn("controller.invalidate()", source)
        self.assertIn("self.refreshButton.isEnabled = self.diagnostics.presentation.refreshEnabled", source)
        self.assertEqual(source.count("Process()"), 1)
        self.assertEqual(source.count("kill(process.processIdentifier, SIGKILL)"), 1)
        self.assertIn("func refresh()", source)
        self.assertNotIn("func confirm", source)
        forbidden = (
            "ProcessInfo.processInfo.environment",
            "NSTask",
            "Task {",
            "URLSession",
            "NWConnection",
            "NWListener",
            "NWBrowser",
            "CFSocket",
            "CFStream",
            "Socket",
            "NSPasteboard",
            "CGEvent",
            "NSEvent.addGlobalMonitor",
            "NSEvent.addLocalMonitor",
            "Process.launchPath",
            "Process.arguments.append",
            "popen(",
            "system(",
            '"/bin/sh"',
        )
        for token in forbidden:
            self.assertNotIn(token, source, token)

    def test_native_hosts_exist_and_do_not_create_a_control_network_endpoint(self):
        self.assertTrue(MACOS_MANIFEST.is_file())
        self.assertTrue(WINDOWS_MANIFEST.is_file())

        native_sources = [
            ROOT / path
            for path in tracked_native_paths()
            if path.endswith((".swift", ".cs", ".csproj")) or path.endswith("Package.swift")
        ]
        native_text = "\n".join(path.read_text() for path in native_sources)
        forbidden = (
            "http://",
            "https://",
            "import Network",
            "import CFNetwork",
            "import WebKit",
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
            self.assertIn("seamless-input control --ui-stdio", text)
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

    def test_sas_display_fixture_is_one_way_bounded_and_terminal(self):
        """The local JSON exception is structured, bounded, and never a request."""
        fixture = json.loads(SAS_FRAME_FIXTURE.read_text())

        self.assertTrue(accepts_sas_display_sequence(fixture["valid_child_to_host"]))
        for frame in fixture["valid_child_to_host"]:
            self.assertLessEqual(len(json.dumps(frame).encode("utf-8")), 256 * 1024)
        for frame in fixture["invalid_child_to_host"]:
            self.assertFalse(validate_sas_display_frame(frame), frame)
        for sequence in fixture["invalid_sequences"]:
            self.assertFalse(accepts_sas_display_sequence(sequence), sequence)
        for request in fixture["valid_host_requests"]:
            self.assertFalse(host_request_contains_sas(request), request)
        for request in fixture["invalid_host_requests"]:
            self.assertTrue(host_request_contains_sas(request), request)

    def test_native_host_pipe_design_limits_native_source_to_diagnostics_host(self):
        """The host plan admits only the guarded diagnostics owner and safety gates."""
        design = HOST_PIPE_DESIGN.read_text()
        required = (
            "control_engine::run_stdio",
            "ui_stdio_adapter::run_stdio",
            "[absolute path to seamless-input, \"control\", \"--ui-stdio\"]",
            "seamless-input control --stdio",
            "seamless-input control --ui-stdio",
            "MAX_FRAME_BYTES = 256 KiB",
            "ui.refresh",
            "ui.confirm_v01",
            "terminal `sas_display_v1 current:false`",
            "Platform-specific reader cancellation is intentionally not unified",
            "only the guarded AppKit",
            "no additional native host source, product build,",
        )
        for invariant in required:
            self.assertIn(invariant, design)

    def test_native_host_pipe_design_never_adds_a_close_command(self):
        """Normal close is pipe/process ownership, not a foundations command."""
        design = HOST_PIPE_DESIGN.read_text()
        boundary = BOUNDARY_RECORD.read_text()
        native_readme = NATIVE_README.read_text()
        host_to_child = design.split("| Host → child |", 1)[1].split("\n", 1)[0]
        self.assertEqual(
            host_to_child,
            " `ui.refresh` and `ui.confirm_v01` only, using the existing request envelope and idempotent request IDs |",
        )
        for text in (design, boundary, native_readme):
            self.assertNotIn("send the existing typed shutdown request", text)
            self.assertNotIn("shutdown request when the pipe is usable", text)
        self.assertIn("no foundations shutdown command", design)
        self.assertIn("no shutdown command on the host-to-child path", boundary)
        self.assertIn("sends no\nfoundations shutdown command", native_readme)

    def test_desktop_parity_plan_reserves_a_separate_ui_stdio_channel(self):
        """Native UX must not repurpose the foundations control channel or TUI."""
        plan = DESKTOP_PARITY_GATE.read_text()
        for invariant in (
            "`seamless-input control --ui-stdio`",
            "`seamless-input control --stdio`",
            "TUI is a technical fallback",
            "AppKit",
            "WinForms",
            "separate authenticated application-session lifecycle",
            "not a saved topology",
        ):
            self.assertIn(invariant, plan)

    def test_desktop_parity_plan_maps_every_user_action_to_a_fenced_gate(self):
        """Presented desktop states do not themselves authorize user actions."""
        plan = DESKTOP_PARITY_GATE.read_text()
        self.assertIn("## Action-gate schema", plan)
        for column in (
            "Future typed gate and engine owner",
            "Required presented state / preconditions",
            "Allowed effect",
            "Fail-closed rejection and no fallback",
            "Current status",
            "allowlist remains exactly `ui.refresh` and `ui.confirm_v01`",
        ):
            self.assertIn(column, plan)
        for action in (
            "Find nearby",
            "Stop looking",
            "Select nearby computer",
            "Begin bootstrap",
            "Confirm bootstrap code",
            "Begin V01",
            "Confirm V01 code",
            "Move display",
            "Reset layout",
            "Review layout",
            "Start sharing",
            "Stop sharing",
            "Retry",
        ):
            self.assertIn(f"`{action}`", plan)

    def test_ui_stdio_entrypoint_has_only_the_guarded_macos_diagnostics_owner(self):
        """The child mode cannot admit a general native-host surface."""
        boundary = BOUNDARY_RECORD.read_text()
        pipe_design = HOST_PIPE_DESIGN.read_text()
        for text in (boundary, pipe_design):
            self.assertIn("`seamless-input control --ui-stdio`", text)
            self.assertIn("diagnostics", text)
            self.assertNotIn("WinForms host starts", text)
        self.assertIn("entrypoint is admitted", pipe_design)
        self.assertNotIn("`seamless-input control --stdio` is an alternate", boundary)

    def test_every_sas_field_and_literal_is_rejected_recursively_from_host_args(self):
        """A partial display shape is still an impermissible host re-export."""
        for field in SAS_HOST_REQUEST_RESERVED_FIELDS:
            request = {
                "v": 1,
                "id": "host-field",
                "command": "confirm",
                "args": {"nested": [{field: "untrusted"}]},
            }
            self.assertTrue(host_request_contains_sas(request), field)
        self.assertTrue(
            host_request_contains_sas(
                {
                    "v": 1,
                    "id": "host-literal",
                    "command": "confirm",
                    "args": {"nested": ["sas_display_v1"]},
                }
            )
        )


if __name__ == "__main__":
    unittest.main()
