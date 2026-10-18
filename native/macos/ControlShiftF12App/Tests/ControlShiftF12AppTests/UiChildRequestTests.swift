import AppKit
import Foundation
import Darwin
import XCTest
@testable import ControlShiftF12App

final class UiChildRequestTests: XCTestCase {
    func testRepeatedGesturesHaveFreshBoundedIDsAndSingleUseReplies() throws {
        let requests = ChildRequestTracker()
        let controller = DiagnosticsFrameController(requests: requests)
        var ids = Set<String>()
        for command in ["ui.start_discovery", "ui.stop_discovery", "ui.start_discovery", "ui.refresh", "ui.refresh"] {
            let frame = try requests.frame(command: command)
            let request = try object(frame)
            let id = try XCTUnwrap(request["id"] as? String)
            XCTAssertTrue(ids.insert(id).inserted)
            XCTAssertLessThanOrEqual(id.utf8.count, 64)
            XCTAssertEqual(request["command"] as? String, command)
            let response = try framed(["v": 1, "kind": "ui_response_v1", "id": id, "ok": true])
            XCTAssertNoThrow(try controller.consume(lengthPrefixed: response))
            XCTAssertThrowsError(try controller.consume(lengthPrefixed: response))
        }
    }

    func testPairingActionsContainOnlyOpaqueHandleAndBoundDecision() throws {
        let requests = ChildRequestTracker()
        let selected = try object(requests.frame(
            command: "ui.select_candidate", args: ["handle": "nearby-7"]
        ))
        XCTAssertEqual(selected["command"] as? String, "ui.select_candidate")
        XCTAssertEqual(selected["args"] as? [String: String], ["handle": "nearby-7"])

        let approved = try object(requests.frame(
            command: "ui.approve_sas", args: ["generation": UInt64(9), "matches": false]
        ))
        XCTAssertEqual(approved["command"] as? String, "ui.approve_sas")
        let args = try XCTUnwrap(approved["args"] as? [String: Any])
        XCTAssertEqual(args.count, 2)
        XCTAssertEqual(args["generation"] as? UInt64, 9)
        XCTAssertEqual(args["matches"] as? Bool, false)
    }

    func testCancelPairingCarriesOnlyTheCurrentNonzeroGeneration() throws {
        let requests = ChildRequestTracker()
        let cancelled = try object(requests.frame(
            command: "ui.cancel_pairing", args: ["generation": UInt64(9)]
        ))
        XCTAssertEqual(cancelled["command"] as? String, "ui.cancel_pairing")
        let args = try XCTUnwrap(cancelled["args"] as? [String: UInt64])
        XCTAssertEqual(args, ["generation": 9])
        XCTAssertThrowsError(try requests.frame(command: "ui.cancel_pairing", args: ["generation": UInt64(0)]))
        XCTAssertThrowsError(try requests.frame(command: "ui.cancel_pairing", args: ["generation": UInt64(9), "matches": true]))
    }

    func testG4TerminalSnapshotsEraseSasAndNeverEnableSharing() throws {
        for state in ["confirmed_relationship", "remote_outcome_unknown"] {
            let controller = DiagnosticsFrameController()
            try controller.consume(lengthPrefixed: framed([
                "v": 1, "kind": "ui_pairing_v1", "generation": 7,
                "phase": "awaiting_local_confirmation", "candidate_handle": "peer-1",
                "verification_words": ["ember", "ocean", "violet", "copper"],
            ]))
            XCTAssertNotNil(controller.pairing)
            try controller.consume(lengthPrefixed: snapshot(generation: 8, state: state))
            XCTAssertNil(controller.pairing)
            XCTAssertFalse(controller.shell.findNearbyEnabled)
            XCTAssertFalse(controller.shell.inputSharingEnabled)
            XCTAssertFalse(controller.shell.clipboardSharingEnabled)
            XCTAssertFalse(controller.shell.saveLayoutEnabled)
            XCTAssertEqual(controller.shell.connectionStatus, state == "confirmed_relationship"
                ? "Confirmed — sharing unavailable" : "Outcome unknown — quarantined")
        }
    }

    func testNonterminalRefreshPreservesOriginalSasUntilTerminalSnapshot() throws {
        let controller = DiagnosticsFrameController()
        try controller.consume(lengthPrefixed: framed([
            "v": 1, "kind": "ui_pairing_v1", "generation": 7,
            "phase": "awaiting_local_confirmation", "candidate_handle": "peer-1",
            "verification_words": ["ember", "ocean", "violet", "copper"],
        ]))
        try controller.consume(lengthPrefixed: snapshot(generation: 6, state: "browsing"))
        XCTAssertNotNil(controller.pairing)
        for (offset, state) in ["bootstrap_connecting", "bootstrap_sas_pending", "bootstrap_receipt_prepared", "browsing"].enumerated() {
            try controller.consume(lengthPrefixed: snapshot(generation: 8 + offset, state: state))
            XCTAssertEqual(controller.pairingGeneration, 7)
            XCTAssertEqual(controller.pairing?.verificationWords, ["ember", "ocean", "violet", "copper"])
        }
        try controller.consume(lengthPrefixed: snapshot(generation: 12, state: "not_started"))
        XCTAssertNil(controller.pairing)
        XCTAssertNil(controller.pairingGeneration)
    }

    func testG4RejectsOperationalRelationshipMetadata() throws {
        let controller = DiagnosticsFrameController()
        XCTAssertThrowsError(try controller.consume(lengthPrefixed: snapshot(
            generation: 1, state: "confirmed_relationship", relationshipState: "active"
        )))
    }

    func testNativePairingControlsSelectOnlyCurrentCandidatesAndBindDisplayedSas() throws {
        _ = NSApplication.shared
        let controller = DiagnosticsFrameController()
        var selected: [String] = []
        var decisions: [(UInt64, Bool)] = []
        var cancellations: [UInt64] = []
        let controls = MacPairingControls(controller: controller,
            select: { selected.append($0) }, approve: { decisions.append(($0, $1)) },
            cancel: { cancellations.append($0) })
        let browsing = try framed(["v": 1, "kind": "ui_snapshot_v1", "snapshot": [
            "schema_version": 1, "generation": 1, "state": "browsing", "diagnostics": [],
            "candidates": [["handle": "peer-1", "compatibility": "compatible", "freshness": "current"],
                           ["handle": "peer-stale", "compatibility": "compatible", "freshness": "stale"]],
            "confirmed": [], "inventory": NSNull(), "layout": ["state": "not_configured"],
            "capabilities": ["input_enabled": false, "clipboard_enabled": false],
        ]])
        try controller.consume(lengthPrefixed: browsing)
        controls.render()
        XCTAssertEqual(controls.candidates.itemTitles, ["peer-1"])
        controls.selectButton.performClick(nil)
        XCTAssertEqual(selected, ["peer-1"])

        try controller.consume(lengthPrefixed: pairing(generation: 7))
        controls.render()
        XCTAssertEqual(controls.words.stringValue, "ember  ocean  violet  copper")
        XCTAssertFalse(controls.selectButton.isEnabled)
        try controller.consume(lengthPrefixed: pairing(generation: 8))
        controls.matchButton.performClick(nil) // The displayed generation is now stale.
        XCTAssertTrue(decisions.isEmpty)
        controls.render()
        controls.mismatchButton.performClick(nil)
        XCTAssertEqual(decisions.count, 1)
        XCTAssertEqual(decisions.first?.0, 8)
        XCTAssertEqual(decisions.first?.1, false)

        try controller.consume(lengthPrefixed: pairing(generation: 9))
        controls.render()
        controls.matchButton.performClick(nil)
        controls.matchButton.performClick(nil)
        XCTAssertEqual(decisions.count, 2)
        XCTAssertEqual(decisions.last?.0, 9)
        XCTAssertEqual(decisions.last?.1, true)
        try controller.consume(lengthPrefixed: snapshot(generation: 10, state: "bootstrap_receipt_prepared"))
        controls.render()
        XCTAssertFalse(controls.matchButton.isEnabled)
        XCTAssertTrue(controls.cancelButton.isEnabled)
        controls.cancelButton.performClick(nil)
        XCTAssertEqual(cancellations, [9])
        controls.cancelButton.performClick(nil)
        XCTAssertEqual(cancellations, [9])
        try controller.consume(lengthPrefixed: pairing(generation: 11))
        controls.render()
        XCTAssertTrue(controls.matchButton.isEnabled)
        controls.cancelButton.performClick(nil)
        XCTAssertEqual(cancellations, [9, 11])
        try controller.consume(lengthPrefixed: snapshot(generation: 12, state: "remote_outcome_unknown"))
        controls.render()
        XCTAssertEqual(controls.words.stringValue, "")
        XCTAssertFalse(controls.cancelButton.isEnabled)
        XCTAssertFalse(controls.matchButton.isEnabled)
        XCTAssertFalse(controls.mismatchButton.isEnabled)
        XCTAssertFalse(controls.selectButton.isEnabled)
    }

    private func pairing(generation: Int, phase: String = "awaiting_local_confirmation") throws -> Data {
        try framed(["v": 1, "kind": "ui_pairing_v1", "generation": generation,
                    "phase": phase, "candidate_handle": "peer-1",
                    "verification_words": ["ember", "ocean", "violet", "copper"]])
    }

    private func snapshot(generation: Int, state: String, relationshipState: String = "unavailable") throws -> Data {
        try framed(["v": 1, "kind": "ui_snapshot_v1", "snapshot": [
            "schema_version": 1, "generation": generation, "state": state,
            "diagnostics": [], "candidates": [],
            "confirmed": state == "confirmed_relationship" ? [["handle": "peer-1", "state": relationshipState]] : [],
            "inventory": NSNull(), "layout": ["state": "not_configured"],
            "capabilities": ["input_enabled": false, "clipboard_enabled": false],
        ]])
    }

    func testRepeatedRealChildGesturesAdvanceEverySnapshot() throws {
        guard let executable = ProcessInfo.processInfo.environment["CSF12_TEST_ENGINE"] else {
            throw XCTSkip("Set CSF12_TEST_ENGINE to the built local engine")
        }
        let child = Process()
        child.executableURL = URL(fileURLWithPath: executable)
        child.arguments = ["control", "--ui-stdio"]
        let input = Pipe(), output = Pipe()
        child.standardInput = input
        child.standardOutput = output
        child.standardError = Pipe()
        try child.run()
        defer {
            try? input.fileHandleForWriting.close()
            if child.isRunning { child.terminate() }
            child.waitUntilExit()
        }
        let requests = ChildRequestTracker()
        let controller = DiagnosticsFrameController(requests: requests)
        var previous: UInt64 = 0
        for (command, state) in [
            ("ui.refresh", "not_started"), ("ui.start_discovery", "browsing"),
            ("ui.stop_discovery", "not_started"), ("ui.start_discovery", "browsing"),
            ("ui.refresh", "browsing"), ("ui.refresh", "browsing"),
        ] {
            let frame = try requests.frame(command: command)
            let id = try XCTUnwrap(try object(frame)["id"] as? String)
            try input.fileHandleForWriting.write(contentsOf: frame)
            var sawSnapshot = false
            var sawResponse = false
            for _ in 0..<8 {
                let response = try readFrame(output.fileHandleForReading)
                let value = try object(response)
                try controller.consume(lengthPrefixed: response)
                if let snapshot = value["snapshot"] as? [String: Any] {
                    let generation = try XCTUnwrap(snapshot["generation"] as? UInt64)
                    XCTAssertGreaterThan(generation, previous)
                    previous = generation
                    XCTAssertEqual(snapshot["state"] as? String, state)
                    let capabilities = try XCTUnwrap(snapshot["capabilities"] as? [String: Bool])
                    XCTAssertEqual(capabilities["input_enabled"], false)
                    XCTAssertEqual(capabilities["clipboard_enabled"], false)
                    sawSnapshot = true
                }
                if value["kind"] as? String == "ui_response_v1" {
                    XCTAssertEqual(value["id"] as? String, id)
                    XCTAssertTrue(sawSnapshot)
                    sawResponse = true
                    break
                }
            }
            XCTAssertTrue(sawResponse, "child response exceeded the bounded frame budget")
        }
    }

    private func object(_ frame: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: frame.dropFirst(4)) as? [String: Any])
    }

    private func framed(_ object: [String: Any]) throws -> Data {
        let payload = try JSONSerialization.data(withJSONObject: object)
        var length = UInt32(payload.count).bigEndian
        var result = Data(bytes: &length, count: 4)
        result.append(payload)
        return result
    }

    private func readFrame(_ handle: FileHandle) throws -> Data {
        func read(_ count: Int) throws -> Data {
            var result = Data()
            while result.count < count {
                var descriptor = pollfd(fd: handle.fileDescriptor, events: Int16(POLLIN), revents: 0)
                guard poll(&descriptor, 1, 5_000) > 0 else { throw NSError(domain: "ChildTimeout", code: 1) }
                let bytes = try XCTUnwrap(try handle.read(upToCount: count - result.count))
                guard !bytes.isEmpty else { throw NSError(domain: "ChildEOF", code: 1) }
                result.append(bytes)
            }
            return result
        }
        let prefix = try read(4)
        let length = prefix.reduce(0) { ($0 << 8) | Int($1) }
        guard (1...262_144).contains(length) else { throw NSError(domain: "ChildFrame", code: 1) }
        return prefix + (try read(length))
    }
}
