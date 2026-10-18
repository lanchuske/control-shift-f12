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

    func testPairingProjectionAcceptsOnlyRedactedFourWordDisplay() throws {
        let controller = DiagnosticsFrameController()
        let payload = """
        {"v":1,"kind":"ui_pairing_v1","generation":2,"phase":"awaiting_local_confirmation","candidate_handle":"windows-studio","verification_words":["ember","ocean","violet","copper"]}
        """.data(using: .utf8)!

        try controller.consume(lengthPrefixed: frame(payload))

        XCTAssertEqual(controller.pairing?.phase, .awaitingLocalConfirmation)
        XCTAssertEqual(controller.pairing?.verificationWords, ["ember", "ocean", "violet", "copper"])
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

    func testBrowsingSnapshotAcceptsOneCurrentRedactedCandidateWithoutEnablingSharing() {
        let controller = DiagnosticsFrameController()
        let snapshot = """
        {"v":1,"kind":"ui_snapshot_v1","snapshot":{
          "schema_version":1,"generation":2,"state":"browsing",
          "candidates":[{"handle":"windows-studio","compatibility":"compatible","freshness":"current"}],
          "confirmed":[],"inventory":null,
          "layout":{"state":"not_configured"},
          "capabilities":{"input_enabled":false,"clipboard_enabled":false},
          "diagnostics":[]
        }}
        """.data(using: .utf8)!

        XCTAssertNoThrow(try controller.consume(lengthPrefixed: frame(snapshot)))
        XCTAssertEqual(
            controller.nearbyCandidates,
            [NearbyCandidatePresentation(
                handle: "windows-studio",
                compatibility: "compatible",
                freshness: "current"
            )]
        )
        XCTAssertFalse(controller.shell.inputSharingEnabled)
        XCTAssertFalse(controller.shell.clipboardSharingEnabled)
    }

    func testStartDiscoverySendsOnlyTheDedicatedTypedRequestWhileOpen() {
        let child = RecordingChild()
        let lifecycle = ChildLifecycle(child: child)

        lifecycle.startDiscovery()
        try? lifecycle.close()
        lifecycle.startDiscovery()

        XCTAssertEqual(child.startDiscoveryCalls, 1)
    }

    func testStopDiscoverySendsOnlyTheDedicatedTypedRequestWhileOpen() {
        let child = RecordingChild()
        let lifecycle = ChildLifecycle(child: child)

        lifecycle.stopDiscovery()
        try? lifecycle.close()
        lifecycle.stopDiscovery()

        XCTAssertEqual(child.stopDiscoveryCalls, 1)
    }

    func testStartDiscoveryAcknowledgementIsAcceptedWithoutEnablingSharing() throws {
        let child = RecordingChild()
        let controller = DiagnosticsFrameController()
        let session = DiagnosticsSession(controller: controller, lifecycle: ChildLifecycle(child: child))
        let response = try acknowledgement(controller, command: "ui.start_discovery")

        try session.receive(.data(response))

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
        let controller = DiagnosticsFrameController()
        let session = DiagnosticsSession(controller: controller, lifecycle: ChildLifecycle(child: child))
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
        try session.receive(.data(try acknowledgement(controller, command: "ui.refresh")))

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

    func testProjectionGenerationIsGlobalAndStaleSnapshotsCannotRegressDiscovery() throws {
        let controller = DiagnosticsFrameController()
        try controller.consume(lengthPrefixed: frame(snapshotPayload(generation: 10, state: "browsing", candidate: "current-peer")))
        try controller.consume(lengthPrefixed: frame(diagnosticsPayload(generation: 11)))

        try controller.consume(lengthPrefixed: frame(snapshotPayload(generation: 10, state: "not_started")))
        try controller.consume(lengthPrefixed: frame(snapshotPayload(generation: 11, state: "not_started")))

        XCTAssertEqual(controller.shell, .browsing)
        XCTAssertEqual(controller.nearbyCandidates.map(\.handle), ["current-peer"])

        try controller.consume(lengthPrefixed: frame(snapshotPayload(generation: 12, state: "not_started")))
        XCTAssertEqual(controller.shell, .readyToDiscover)
        XCTAssertTrue(controller.nearbyCandidates.isEmpty)
    }

    func testPairingUsesTheSameGlobalGenerationAndIgnoresValidEqualOrOlderFrames() throws {
        let controller = DiagnosticsFrameController()
        try controller.consume(lengthPrefixed: frame(snapshotPayload(generation: 20, state: "not_started")))
        try controller.consume(lengthPrefixed: frame(diagnosticsPayload(generation: 21)))
        let equalPairing = """
        {"v":1,"kind":"ui_pairing_v1","generation":21,"phase":"awaiting_local_confirmation","candidate_handle":"stale-peer","verification_words":["ember","ocean","violet","copper"]}
        """.data(using: .utf8)!
        let olderPairing = """
        {"v":1,"kind":"ui_pairing_v1","generation":19,"phase":"awaiting_local_confirmation","candidate_handle":"older-peer","verification_words":["ember","ocean","violet","copper"]}
        """.data(using: .utf8)!
        let currentPairing = """
        {"v":1,"kind":"ui_pairing_v1","generation":22,"phase":"awaiting_local_confirmation","candidate_handle":"current-peer","verification_words":["ember","ocean","violet","copper"]}
        """.data(using: .utf8)!

        XCTAssertNoThrow(try controller.consume(lengthPrefixed: frame(equalPairing)))
        XCTAssertNoThrow(try controller.consume(lengthPrefixed: frame(olderPairing)))
        XCTAssertNil(controller.pairing)
        try controller.consume(lengthPrefixed: frame(currentPairing))
        XCTAssertEqual(controller.pairing?.selectedCandidate, "current-peer")
    }

    func testMalformedStaleSnapshotStillTerminatesInsteadOfHidingBehindGeneration() throws {
        let child = RecordingChild()
        let session = DiagnosticsSession(lifecycle: ChildLifecycle(child: child))
        try session.receive(.data(frame(snapshotPayload(generation: 10, state: "not_started"))))
        let unsafeStale = """
        {"v":1,"kind":"ui_snapshot_v1","snapshot":{
          "schema_version":1,"generation":9,"state":"not_started",
          "candidates":[],"confirmed":[],"inventory":null,
          "layout":{"state":"not_configured"},
          "capabilities":{"input_enabled":true,"clipboard_enabled":false},
          "diagnostics":[]
        }}
        """.data(using: .utf8)!

        try session.receive(.data(frame(unsafeStale)))

        XCTAssertTrue(session.isTerminal)
        XCTAssertEqual(child.terminateCalls, 1)
    }

    func testConcurrentCloseIsIdempotentAndReapsExactlyOnce() {
        let child = LockedRecordingChild()
        let lifecycle = ChildLifecycle(child: child)
        let group = DispatchGroup()
        for _ in 0..<8 {
            group.enter()
            DispatchQueue.global().async {
                try? lifecycle.close()
                group.leave()
            }
        }
        XCTAssertEqual(group.wait(timeout: .now() + 2), .success)
        XCTAssertEqual(child.counts, LockedRecordingChild.Counts(terminate: 1, reap: 1))
    }

    func testCloseCancelsClosesAndReapsChildWithoutChangingGeneration() {
        let child = RecordingChild()
        let session = ChildLifecycle(child: child)
        let generation = session.generation

        try? session.close()

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

        try? session.close()

        XCTAssertEqual(child.reapAttempts, 2)
        XCTAssertTrue(child.forceTerminated)
    }

    func testCloseReportsSecondReapFailureAfterCleaningEveryPipe() {
        let child = NeverReapedRecordingChild()
        let lifecycle = ChildLifecycle(child: child)

        XCTAssertThrowsError(try lifecycle.close())

        XCTAssertTrue(child.inputClosed)
        XCTAssertTrue(child.outputClosed)
        XCTAssertTrue(child.errorClosed)
        XCTAssertTrue(child.forceTerminated)
        XCTAssertEqual(child.reapAttempts, 2)
    }

    func testCloseWaitsForInflightTerminationCallbackAndClearsIt() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let script = "cat >/dev/null"
        let child = BundledChild(
            executableURL: URL(fileURLWithPath: "/bin/sh"),
            arguments: ["-c", script],
            requests: ChildRequestTracker()
        )
        let callbackFinished = expectation(description: "termination callback drained")
        child.observeTermination {
            Thread.sleep(forTimeInterval: 0.1)
            callbackFinished.fulfill()
        }
        try child.start()

        let lifecycle = ChildLifecycle(child: child)
        try lifecycle.close()

        wait(for: [callbackFinished], timeout: 0)
    }

    func testBundledChildDrainsMoreThanTwoMebibytesOfStderrBeforeStdout() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let payload = snapshotPayload(generation: 1, state: "not_started")
        let framed = frame(payload)
        let output = root.appendingPathComponent("projection.frame")
        try framed.write(to: output)
        let script = "head -c 2105344 /dev/zero >&2; cat '\(output.path)'; cat >/dev/null"
        let child = BundledChild(
            executableURL: URL(fileURLWithPath: "/bin/sh"),
            arguments: ["-c", script],
            requests: ChildRequestTracker()
        )
        let projection = expectation(description: "stdout projection after bounded stderr drain")
        child.observeOutput { event in
            if case .data(let data) = event, !data.isEmpty { projection.fulfill() }
        }

        try child.start()
        wait(for: [projection], timeout: 5)

        let lifecycle = ChildLifecycle(child: child)
        try lifecycle.close()
        XCTAssertTrue(lifecycle.isClosed)
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

    private func acknowledgement(_ controller: DiagnosticsFrameController, command: String) throws -> Data {
        let request = try controller.requests.frame(command: command)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: request.dropFirst(4)) as? [String: Any])
        let id = try XCTUnwrap(object["id"] as? String)
        return frame(try JSONSerialization.data(withJSONObject: ["v": 1, "kind": "ui_response_v1", "id": id, "ok": true]))
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

    private func snapshotPayload(generation: Int, state: String, candidate: String? = nil) -> Data {
        let candidates = candidate.map {
            "[{\"handle\":\"\($0)\",\"compatibility\":\"compatible\",\"freshness\":\"current\"}]"
        } ?? "[]"
        return """
        {"v":1,"kind":"ui_snapshot_v1","snapshot":{
          "schema_version":1,"generation":\(generation),"state":"\(state)",
          "candidates":\(candidates),"confirmed":[],"inventory":null,
          "layout":{"state":"not_configured"},
          "capabilities":{"input_enabled":false,"clipboard_enabled":false},
          "diagnostics":[]
        }}
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
    func sendSelectCandidate(_ handle: String) throws {}
    func sendApproveSas(generation: UInt64, matches: Bool) throws {}
    func sendCancelPairing(generation: UInt64) throws {}
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
    func clearTerminationHandler() {}
}

private class SlowRecordingChild: RecordingChild {
    var forceTerminated = false
    var reapAttempts = 0

    override func forceTerminate() { forceTerminated = true }
    override func reap(timeout: TimeInterval) -> Bool {
        reapAttempts += 1
        return reapAttempts > 1
    }
}

private final class LockedRecordingChild: ChildLifecycleChild {
    struct Counts: Equatable { let terminate: Int; let reap: Int }
    private let lock = NSLock()
    private var terminateCount = 0
    private var reapCount = 0
    var counts: Counts {
        lock.lock(); defer { lock.unlock() }
        return Counts(terminate: terminateCount, reap: reapCount)
    }
    func sendRefresh() throws {}
    func sendStartDiscovery() throws {}
    func sendStopDiscovery() throws {}
    func sendSelectCandidate(_ handle: String) throws {}
    func sendApproveSas(generation: UInt64, matches: Bool) throws {}
    func sendCancelPairing(generation: UInt64) throws {}
    func closeInput() {}
    func closeOutput() {}
    func closeError() {}
    func terminate() { lock.lock(); terminateCount += 1; lock.unlock() }
    func forceTerminate() {}
    func reap(timeout: TimeInterval) -> Bool {
        lock.lock(); reapCount += 1; lock.unlock()
        return true
    }
    func clearTerminationHandler() {}
}

private final class NeverReapedRecordingChild: SlowRecordingChild {
    override func reap(timeout: TimeInterval) -> Bool {
        reapAttempts += 1
        return false
    }
}
