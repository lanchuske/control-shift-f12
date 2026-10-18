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
