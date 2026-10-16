import XCTest
@testable import ControlShiftF12App

final class ControlShiftF12AppTests: XCTestCase {
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

    private func frame(_ payload: Data) -> Data {
        var length = UInt32(payload.count).bigEndian
        var data = Data(bytes: &length, count: MemoryLayout<UInt32>.size)
        data.append(payload)
        return data
    }

    private func diagnosticsPayload(generation: Int) -> Data {
        """
        {"v":1,"kind":"ui_diagnostics_v1","generation":\(generation),"rows":[
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

    func sendRefresh() throws {}
    func closeInput() { inputClosed = true }
    func closeOutput() { outputClosed = true }
    func closeError() { errorClosed = true }
    func terminate() { terminated = true }
    func forceTerminate() {}
    func reap(timeout: TimeInterval) -> Bool {
        reaped = true
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
