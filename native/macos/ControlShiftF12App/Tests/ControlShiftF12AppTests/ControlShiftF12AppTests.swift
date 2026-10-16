import XCTest
@testable import ControlShiftF12App

final class ControlShiftF12AppTests: XCTestCase {
    func testDesktopShellStartsWithAllSharingAndLayoutActionsUnavailable() {
        let shell = MacDesktopShellPresentation.initial

        XCTAssertEqual(shell.title, "Set up another computer")
        XCTAssertEqual(shell.connectionStatus, "Not connected")
        XCTAssertFalse(shell.findNearbyEnabled)
        XCTAssertFalse(shell.confirmCodeEnabled)
        XCTAssertFalse(shell.inputSharingEnabled)
        XCTAssertFalse(shell.clipboardSharingEnabled)
        XCTAssertFalse(shell.automaticUpdatesEnabled)
        XCTAssertFalse(shell.saveLayoutEnabled)
    }

    func testPairingBridgeRequiresMatchingCodeAndBothConfirmationsBeforeAdmission() {
        var state = MacPairingBridgeState()
        state.beginVerification(
            candidate: "windows-studio",
            words: ["ember", "ocean", "violet", "copper"]
        )
        XCTAssertEqual(state.phase, .awaitingLocalConfirmation)
        XCTAssertEqual(state.selectedCandidate, "windows-studio")

        state.approveLocalDisplay(matches: true)
        XCTAssertEqual(state.phase, .awaitingRemoteConfirmation)
        state.acceptRemoteDisplay()
        XCTAssertEqual(state.phase, .readyForDurableAdmission)
    }

    func testPairingBridgeRejectsInvalidOrRejectedVerificationWithoutAdmission() {
        var rejected = MacPairingBridgeState()
        rejected.beginVerification(candidate: "windows-studio", words: ["ember", "ocean", "violet", "copper"])
        rejected.approveLocalDisplay(matches: false)
        rejected.acceptRemoteDisplay()

        var invalid = MacPairingBridgeState()
        invalid.beginVerification(candidate: "windows studio", words: ["one", "two", "three", "four"])

        XCTAssertEqual(rejected.phase, .browsing)
        XCTAssertEqual(invalid.phase, .browsing)
    }

    func testInitial_snapshot_enables_only_the_local_discovery_gesture() throws {
        let controller = DiagnosticsFrameController()
        let snapshot = """
        {"v":1,"kind":"ui_snapshot_v1","snapshot":{
          "schema_version":1,"generation":1,"state":"not_started",
          "candidates":[],"confirmed":[],"inventory":null,
          "layout":{"state":"not_configured"},
          "capabilities":{"input_enabled":false,"clipboard_enabled":false},
          "diagnostics":[]
        }}
        """.data(using: .utf8)!

        try controller.consume(lengthPrefixed: frame(snapshot))

        XCTAssertTrue(controller.shell.findNearbyEnabled)
        XCTAssertFalse(controller.shell.confirmCodeEnabled)
        XCTAssertFalse(controller.shell.inputSharingEnabled)
        XCTAssertFalse(controller.shell.clipboardSharingEnabled)
        XCTAssertFalse(controller.shell.saveLayoutEnabled)
    }

    func testStartDiscoverySendsOnlyTheDedicatedTypedRequestWhileOpen() {
        let child = RecordingChild()
        let lifecycle = ChildLifecycle(child: child)

        lifecycle.startDiscovery()
        lifecycle.close()
        lifecycle.startDiscovery()

        XCTAssertEqual(child.startDiscoveryCalls, 1)
    }

    func testStopDiscoverySendsOnlyTheDedicatedTypedRequestWhileOpen() {
        let child = RecordingChild()
        let lifecycle = ChildLifecycle(child: child)

        lifecycle.stopDiscovery()
        lifecycle.close()
        lifecycle.stopDiscovery()

        XCTAssertEqual(child.stopDiscoveryCalls, 1)
    }

    func testStartDiscoveryAcknowledgementIsAcceptedWithoutEnablingSharing() throws {
        let child = RecordingChild()
        let session = DiagnosticsSession(lifecycle: ChildLifecycle(child: child))
        let response = """
        {"v":1,"kind":"ui_response_v1","id":"mac-start-discovery","ok":true}
        """.data(using: .utf8)!

        try session.receive(.data(frame(response)))

        XCTAssertFalse(session.isTerminal)
        XCTAssertEqual(child.terminateCalls, 0)
    }

    func testStaleOrUnknownRuntimeProjectsNotRunningAndDisablesActions() {
        for runtime in [RuntimeStatus.stale, .unknown] {
            let presentation = DiagnosticsPresentation(
                runtime: runtime,
                rows: [.clipboardFault]
            )

            XCTAssertEqual(presentation.statusText, "Not running")
            XCTAssertTrue(presentation.refreshEnabled)
            XCTAssertFalse(presentation.showsSessionCount)
        }
    }

    func testClipboardFaultIsOneRedAccessibleDiagnosticRow() {
        let presentation = DiagnosticsPresentation(
            runtime: .currentPass,
            rows: [.clipboardFault, .displaysPass]
        )

        XCTAssertEqual(presentation.rows.count, 2)
        XCTAssertEqual(presentation.rows[0].title, "Clipboard")
        XCTAssertEqual(presentation.rows[0].statusText, "Unavailable")
        XCTAssertEqual(presentation.rows[0].tone, .blocked)
        XCTAssertEqual(presentation.rows[0].accessibilityLabel, "Clipboard: unavailable")
        XCTAssertFalse(presentation.rows[0].accessibilityLabel.contains("\n"))
    }

    func testDiagnosticsFrameProducesOneRowPerItemWithoutPackedReport() throws {
        let payload = """
        {"v":1,"kind":"ui_diagnostics_v1","generation":3,"rows":[
          {"id":"clipboard","label":"clipboard","state":"fail","detail":"fault","action":"retry","failure_code":"clipboard_fault"},
          {"id":"displays","label":"displays","state":"pass","detail":"ready","action":null,"failure_code":null}
        ]}
        """.data(using: .utf8)!
        let controller = DiagnosticsFrameController()

        try controller.consume(lengthPrefixed: frame(payload))

        XCTAssertEqual(controller.presentation.rows.count, 2)
        XCTAssertTrue(controller.presentation.rows.allSatisfy { !$0.accessibilityLabel.contains("\n") })
        XCTAssertFalse(controller.presentation.statusText.localizedCaseInsensitiveContains("session"))
    }

    func testAllowedSnapshotDiagnosticsAndResponseDoNotTerminateTheChildSession() throws {
        let child = RecordingChild()
        let session = DiagnosticsSession(lifecycle: ChildLifecycle(child: child))
        let snapshot = """
        {"v":1,"kind":"ui_snapshot_v1","snapshot":{
          "schema_version":1,"generation":1,"state":"not_started",
          "candidates":[],"confirmed":[],"inventory":null,
          "layout":{"state":"not_configured"},
          "capabilities":{"input_enabled":false,"clipboard_enabled":false},
          "diagnostics":[]
        }}
        """.data(using: .utf8)!

        try session.receive(.data(frame(snapshot)))
        try session.receive(.data(frame(diagnosticsPayload(generation: 2))))
        let response = """
        {"v":1,"kind":"ui_response_v1","id":"mac-refresh","ok":true}
        """.data(using: .utf8)!
        try session.receive(.data(frame(response)))

        XCTAssertFalse(session.isTerminal)
        XCTAssertFalse(session.presentation.rows.isEmpty)
        XCTAssertEqual(session.presentation.statusText, "Running")
        XCTAssertEqual(child.terminateCalls, 0)
    }

    func testSnapshotWithUnexpectedOrSensitiveStateTerminatesTheChildSession() throws {
        let child = RecordingChild()
        let session = DiagnosticsSession(lifecycle: ChildLifecycle(child: child))
        let snapshot = """
        {"v":1,"kind":"ui_snapshot_v1","snapshot":{
          "schema_version":1,"generation":1,"state":"not_started",
          "candidates":[],"confirmed":[],"inventory":null,
          "layout":{"state":"not_configured"},
          "capabilities":{"input_enabled":false,"clipboard_enabled":false},
          "diagnostics":[],"v01":{"code_groups":["secret"]}
        }}
        """.data(using: .utf8)!

        try session.receive(.data(frame(snapshot)))

        XCTAssertTrue(session.isTerminal)
        XCTAssertEqual(session.presentation.statusText, "Not running")
        XCTAssertEqual(child.terminateCalls, 1)
    }

    func testSnapshotWithNegativeGenerationTerminatesTheChildSession() throws {
        let child = RecordingChild()
        let session = DiagnosticsSession(lifecycle: ChildLifecycle(child: child))
        let snapshot = """
        {"v":1,"kind":"ui_snapshot_v1","snapshot":{
          "schema_version":1,"generation":-1,"state":"not_started",
          "candidates":[],"confirmed":[],"inventory":null,
          "layout":{"state":"not_configured"},
          "capabilities":{"input_enabled":false,"clipboard_enabled":false},
          "diagnostics":[]
        }}
        """.data(using: .utf8)!

        try session.receive(.data(frame(snapshot)))

        XCTAssertTrue(session.isTerminal)
        XCTAssertEqual(child.terminateCalls, 1)
    }

    func testResponseForAnyRequestOtherThanTheLocalRefreshTerminatesTheChildSession() throws {
        let child = RecordingChild()
        let session = DiagnosticsSession(lifecycle: ChildLifecycle(child: child))
        let response = """
        {"v":1,"kind":"ui_response_v1","id":"unexpected-response","ok":true}
        """.data(using: .utf8)!

        try session.receive(.data(frame(response)))

        XCTAssertTrue(session.isTerminal)
        XCTAssertEqual(session.presentation.statusText, "Not running")
        XCTAssertEqual(child.terminateCalls, 1)
    }

    func testStaleGenerationAndClosedSessionNeverUpdateTheMainThreadPresentation() throws {
        let controller = DiagnosticsFrameController()
        try controller.consume(lengthPrefixed: frame(diagnosticsPayload(generation: 4)))
        let current = controller.presentation

        try controller.consume(lengthPrefixed: frame(diagnosticsPayload(generation: 3)))
        XCTAssertEqual(controller.presentation, current)

        controller.close()
        try controller.consume(lengthPrefixed: frame(diagnosticsPayload(generation: 5)))
        XCTAssertEqual(controller.presentation, current)
    }

    func testCloseCancelsClosesAndReapsChildWithoutChangingGeneration() {
        let child = RecordingChild()
        let session = ChildLifecycle(child: child)
        let generation = session.generation

        session.close()

        XCTAssertTrue(child.inputClosed)
        XCTAssertTrue(child.outputClosed)
        XCTAssertTrue(child.errorClosed)
        XCTAssertTrue(child.terminated)
        XCTAssertTrue(child.reaped)
        XCTAssertEqual(session.generation, generation + 1)
        XCTAssertTrue(session.isClosed)
    }

    func testCloseEscalatesOnlyForTheOwnedChildWhenFirstBoundedReapFails() {
        let child = SlowRecordingChild()
        let session = ChildLifecycle(child: child)

        session.close()

        XCTAssertEqual(child.reapAttempts, 2)
        XCTAssertTrue(child.forceTerminated)
    }

    func testStdoutEOFAfterPassInvalidatesProjectionAndClosesChildExactlyOnce() throws {
        let child = RecordingChild()
        let lifecycle = ChildLifecycle(child: child)
        let session = DiagnosticsSession(lifecycle: lifecycle)

        try session.receive(.data(frame(diagnosticsPayload(generation: 1))))
        XCTAssertEqual(session.presentation.statusText, "Running")

        try session.receive(.endOfFile)
        try session.receive(.endOfFile)

        XCTAssertEqual(session.presentation.statusText, "Not running")
        XCTAssertFalse(session.presentation.refreshEnabled)
        XCTAssertTrue(session.isTerminal)
        XCTAssertEqual(child.terminateCalls, 1)
        XCTAssertEqual(child.reapCalls, 1)
    }

    func testTerminationAfterPassInvalidatesProjectionAndLateFrameIsInert() throws {
        let child = RecordingChild()
        let session = DiagnosticsSession(lifecycle: ChildLifecycle(child: child))

        try session.receive(.data(frame(diagnosticsPayload(generation: 1))))
        try session.receive(.termination)
        try session.receive(.data(frame(diagnosticsPayload(generation: 2))))

        XCTAssertEqual(session.presentation.statusText, "Not running")
        XCTAssertTrue(session.presentation.rows.isEmpty)
        XCTAssertFalse(session.presentation.refreshEnabled)
        XCTAssertEqual(child.terminateCalls, 1)
    }

    func testPartialOutputThenPipeFailureInvalidatesPriorPassAndRejectsLateCallback() throws {
        let child = RecordingChild()
        let session = DiagnosticsSession(lifecycle: ChildLifecycle(child: child))
        let complete = frame(diagnosticsPayload(generation: 1))

        try session.receive(.data(complete))
        try session.receive(.data(Data(complete.prefix(3))))
        try session.receive(.pipeFailure)
        try session.receive(.data(frame(diagnosticsPayload(generation: 2))))

        XCTAssertEqual(session.presentation.statusText, "Not running")
        XCTAssertTrue(session.presentation.rows.isEmpty)
        XCTAssertFalse(session.presentation.refreshEnabled)
        XCTAssertEqual(child.terminateCalls, 1)
    }

    private func frame(_ payload: Data) -> Data {
        var length = UInt32(payload.count).bigEndian
        var data = Data(bytes: &length, count: MemoryLayout<UInt32>.size)
        data.append(payload)
        return data
    }

    private func diagnosticsPayload(generation: Int) -> Data {
        """
        {"v":1,"kind":"ui_diagnostics_v1","generation":\(generation),"rows":[
          {"id":"runtime","label":"runtime","state":"pass","detail":"ready","action":null,"failure_code":null},
          {"id":"displays","label":"displays","state":"pass","detail":"ready","action":null,"failure_code":null}
        ]}
        """.data(using: .utf8)!
    }
}

private class RecordingChild: ChildLifecycleChild {
    var inputClosed = false
    var outputClosed = false
    var errorClosed = false
    var terminated = false
    var reaped = false
    var terminateCalls = 0
    var reapCalls = 0
    var startDiscoveryCalls = 0
    var stopDiscoveryCalls = 0

    func sendRefresh() throws {}
    func sendStartDiscovery() throws { startDiscoveryCalls += 1 }
    func sendStopDiscovery() throws { stopDiscoveryCalls += 1 }
    func closeInput() { inputClosed = true }
    func closeOutput() { outputClosed = true }
    func closeError() { errorClosed = true }
    func terminate() {
        terminated = true
        terminateCalls += 1
    }
    func forceTerminate() {}
    func reap(timeout: TimeInterval) -> Bool {
        reaped = true
        reapCalls += 1
        return true
    }
}

private final class SlowRecordingChild: RecordingChild {
    var forceTerminated = false
    var reapAttempts = 0

    override func forceTerminate() { forceTerminated = true }
    override func reap(timeout: TimeInterval) -> Bool {
        reapAttempts += 1
        return reapAttempts > 1
    }
}
