import AppKit
import Darwin
import Foundation

private let maximumFrameBytes = 256 * 1024

enum RuntimeStatus: Equatable {
    case currentPass
    case stale
    case unknown
}

enum DiagnosticTone: Equatable {
    case ready
    case blocked
    case neutral
}

struct DiagnosticPresentationRow: Equatable {
    let title: String
    let statusText: String
    let tone: DiagnosticTone
    let accessibilityLabel: String
}

struct DiagnosticsPresentation: Equatable {
    let statusText: String
    let refreshEnabled: Bool
    let showsSessionCount: Bool
    let rows: [DiagnosticPresentationRow]

    init(runtime: RuntimeStatus, rows: [DiagnosticSourceRow], refreshEnabled: Bool = true) {
        statusText = runtime == .currentPass ? "Running" : "Not running"
        self.refreshEnabled = refreshEnabled
        // This diagnostics host renders only current local facts. It has no
        // relationship/session action or count surface.
        showsSessionCount = false
        self.rows = rows.map(DiagnosticPresentationRow.init)
    }
}

/// Local presentation state for the desktop journey. It intentionally keeps
/// pairing, sharing and persistence unavailable until the reviewed engine
/// session can provide current authoritative projections.
struct MacDesktopShellPresentation: Equatable {
    let title: String
    let connectionStatus: String
    let findNearbyEnabled: Bool
    let confirmCodeEnabled: Bool
    let inputSharingEnabled: Bool
    let clipboardSharingEnabled: Bool
    let automaticUpdatesEnabled: Bool
    let saveLayoutEnabled: Bool

    static let initial = Self(
        title: "Set up another computer",
        connectionStatus: "Not connected",
        findNearbyEnabled: false,
        confirmCodeEnabled: false,
        inputSharingEnabled: false,
        clipboardSharingEnabled: false,
        automaticUpdatesEnabled: false,
        saveLayoutEnabled: false
    )

    static let readyToDiscover = Self(
        title: "Set up another computer",
        connectionStatus: "Not connected",
        findNearbyEnabled: true,
        confirmCodeEnabled: false,
        inputSharingEnabled: false,
        clipboardSharingEnabled: false,
        automaticUpdatesEnabled: false,
        saveLayoutEnabled: false
    )

    static let browsing = Self(
        title: "Looking for nearby computers",
        connectionStatus: "Not connected",
        findNearbyEnabled: false,
        confirmCodeEnabled: false,
        inputSharingEnabled: false,
        clipboardSharingEnabled: false,
        automaticUpdatesEnabled: false,
        saveLayoutEnabled: false
    )
}

/// A deliberately minimal candidate summary. The native host may render this
/// while browsing, but it never contains an address, account, or session key.
struct NearbyCandidatePresentation: Equatable {
    let handle: String
    let compatibility: String
    let freshness: String

    var displayText: String {
        "\(handle) — \(compatibility.replacingOccurrences(of: "_", with: " ")), \(freshness)"
    }
}

/// Presentation-only bilateral pairing state. The transport supplies an
/// opaque candidate and a transient verification phrase; this state cannot
/// expose addresses or make durable admission happen on its own.
enum MacPairingBridgePhase: Equatable {
    case browsing
    case awaitingLocalConfirmation
    case awaitingRemoteConfirmation
    case readyForDurableAdmission
}

struct MacPairingBridgeState: Equatable {
    private(set) var phase: MacPairingBridgePhase = .browsing
    private(set) var selectedCandidate: String?
    private(set) var verificationWords: [String] = []

    mutating func beginVerification(candidate: String, words: [String]) {
        guard phase == .browsing, Self.validHandle(candidate), Self.validWords(words) else { return }
        selectedCandidate = candidate
        verificationWords = words
        phase = .awaitingLocalConfirmation
    }

    mutating func approveLocalDisplay(matches: Bool) {
        guard phase == .awaitingLocalConfirmation else { return }
        if matches {
            phase = .awaitingRemoteConfirmation
        } else {
            cancel()
        }
    }

    mutating func acceptRemoteDisplay() {
        guard phase == .awaitingRemoteConfirmation else { return }
        phase = .readyForDurableAdmission
    }

    mutating func cancel() {
        phase = .browsing
        selectedCandidate = nil
        verificationWords = []
    }

    private static func validHandle(_ value: String) -> Bool {
        !value.isEmpty && value.count <= 64 && value.allSatisfy {
            $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_")
        }
    }

    private static func validWords(_ words: [String]) -> Bool {
        words.count == 4 && words.allSatisfy {
            !$0.isEmpty && $0.count <= 24 && $0.allSatisfy { $0 >= "a" && $0 <= "z" }
        }
    }
}

struct DiagnosticSourceRow: Equatable {
    let id: String
    let label: String
    let state: String
    let detail: String

    static let clipboardFault = Self(
        id: "clipboard", label: "clipboard", state: "fail", detail: "fault"
    )
    static let displaysPass = Self(
        id: "displays", label: "displays", state: "pass", detail: "ready"
    )
}

extension DiagnosticPresentationRow {
    init(source: DiagnosticSourceRow) {
        let title = source.label.replacingOccurrences(of: "_", with: " ").capitalized
        let isFault = source.state == "fail"
        let statusText: String
        if isFault && source.detail == "fault" {
            statusText = "Unavailable"
        } else if isFault {
            statusText = "Needs attention"
        } else if source.state == "pass" {
            statusText = "Ready"
        } else {
            statusText = "Not measured"
        }
        self.init(
            title: title,
            statusText: statusText,
            tone: isFault ? .blocked : (source.state == "pass" ? .ready : .neutral),
            accessibilityLabel: "\(title): \(statusText.lowercased())"
        )
    }
}

private enum HostError: Error {
    case invalidFrame
    case notOnMainThread
}

private struct WireDiagnosticsFrame: Decodable {
    let v: Int
    let kind: String
    let generation: UInt64
    let rows: [WireDiagnosticRow]
}

private struct WireDiagnosticRow: Decodable {
    let id: String
    let label: String
    let state: String
    let detail: String
    let action: String?
    let failureCode: String?

    enum CodingKeys: String, CodingKey {
        case id, label, state, detail, action
        case failureCode = "failure_code"
    }
}

private struct SnapshotGenerationEnvelope: Decodable {
    let snapshot: SnapshotGeneration
}

private struct SnapshotGeneration: Decodable {
    let generation: UInt64
}

/// Bounded, single-use correlation for the gestures sent to one child.
final class ChildRequestTracker {
    private var nextID: UInt64 = 0
    private var pending = Set<String>()

    func frame(command: String, args: [String: Any] = [:]) throws -> Data {
        let empty = ["ui.refresh", "ui.start_discovery", "ui.stop_discovery"].contains(command)
            && args.isEmpty
        let select = command == "ui.select_candidate"
            && args.count == 1 && (args["handle"] as? String).map(Self.validHandle) == true
        let approval = command == "ui.approve_sas"
            && args.count == 2 && (args["generation"] as? UInt64).map { $0 > 0 } == true
            && args["matches"] is Bool
        guard (empty || select || approval),
              pending.count < 256, nextID < UInt64.max
        else { throw HostError.invalidFrame }
        nextID += 1
        let id = "mac-\(nextID)"
        let request: [String: Any] = ["v": 1, "id": id, "command": command, "args": args]
        let payload = try JSONSerialization.data(withJSONObject: request)
        guard payload.count > 0, payload.count <= maximumFrameBytes else { throw HostError.invalidFrame }
        var length = UInt32(payload.count).bigEndian
        var frame = Data(bytes: &length, count: 4)
        frame.append(payload)
        pending.insert(id)
        return frame
    }

    func acknowledge(_ id: String) -> Bool { pending.remove(id) != nil }

    private static func validHandle(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 64
            && value.utf8.allSatisfy { byte in
                (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90)
                    || (byte >= 97 && byte <= 122) || byte == 45 || byte == 95
            }
    }
}

/// Owns the redacted view state on the AppKit main thread.
final class DiagnosticsFrameController {
    let requests: ChildRequestTracker
    private(set) var presentation = DiagnosticsPresentation(runtime: .unknown, rows: [])
    private(set) var shell = MacDesktopShellPresentation.initial
    private(set) var pairing: MacPairingBridgeState?
    private(set) var nearbyCandidates: [NearbyCandidatePresentation] = []
    private var highestGeneration: UInt64 = 0
    private var isClosed = false

    init(requests: ChildRequestTracker = ChildRequestTracker()) {
        self.requests = requests
    }

    func consume(lengthPrefixed frame: Data) throws {
        guard Thread.isMainThread else { throw HostError.notOnMainThread }
        guard !isClosed else { return }
        let payload = try completePayload(from: frame)
        let object = try JSONSerialization.jsonObject(with: payload) as? [String: Any]
        guard let object, let kind = object["kind"] as? String else {
            throw HostError.invalidFrame
        }

        switch kind {
        case "ui_snapshot_v1":
            // The adapter publishes its baseline snapshot before the separate
            // diagnostics projection. This diagnostics-only host accepts only
            // that inert baseline, never identities, relationships, or SAS.
            try validateIgnoredSnapshot(object)
        case "ui_response_v1":
            // A response acknowledges one outstanding gesture exactly once.
            try validateIgnoredSuccessResponse(object)
        case "ui_diagnostics_v1":
            try consumeDiagnostics(payload: payload, object: object)
        case "ui_pairing_v1":
            try consumePairing(object)
        default:
            throw HostError.invalidFrame
        }
    }

    func close() {
        isClosed = true
    }

    func invalidate() {
        isClosed = true
        presentation = DiagnosticsPresentation(runtime: .unknown, rows: [], refreshEnabled: false)
        shell = .initial
        pairing = nil
        nearbyCandidates = []
    }

    private func completePayload(from frame: Data) throws -> Data {
        guard frame.count >= MemoryLayout<UInt32>.size else { throw HostError.invalidFrame }
        let length = bigEndianLength(frame.prefix(MemoryLayout<UInt32>.size))
        let payload = frame.dropFirst(MemoryLayout<UInt32>.size)
        guard length > 0, length <= maximumFrameBytes, payload.count == Int(length) else {
            throw HostError.invalidFrame
        }
        return Data(payload)
    }

    private func consumeDiagnostics(payload: Data, object: [String: Any]) throws {
        let rowKeys: Set<String> = ["id", "label", "state", "detail", "action", "failure_code"]
        guard let rawRows = object["rows"] as? [[String: Any]],
              Set(object.keys) == ["v", "kind", "generation", "rows"],
              rawRows.allSatisfy({ Set($0.keys) == rowKeys })
        else { throw HostError.invalidFrame }
        let decoded = try JSONDecoder().decode(WireDiagnosticsFrame.self, from: payload)
        guard decoded.v == 1, decoded.kind == "ui_diagnostics_v1" else {
            throw HostError.invalidFrame
        }
        guard decoded.rows.allSatisfy(isValid) else { throw HostError.invalidFrame }
        guard decoded.generation > highestGeneration else { return }

        highestGeneration = decoded.generation
        let rows = decoded.rows.map {
            DiagnosticSourceRow(id: $0.id, label: $0.label, state: $0.state, detail: $0.detail)
        }
        presentation = DiagnosticsPresentation(runtime: runtimeStatus(for: rows), rows: rows)
    }

    private func validateIgnoredSnapshot(_ object: [String: Any]) throws {
        let snapshotKeys: Set<String> = [
            "schema_version", "generation", "state", "diagnostics", "candidates",
            "confirmed", "inventory", "layout", "capabilities",
        ]
        guard Set(object.keys) == ["v", "kind", "snapshot"],
              let encoded = try? JSONSerialization.data(withJSONObject: object),
              let envelope = try? JSONDecoder().decode(SnapshotGenerationEnvelope.self, from: encoded),
              let version = object["v"] as? Int,
              version == 1,
              let snapshot = object["snapshot"] as? [String: Any],
              Set(snapshot.keys) == snapshotKeys,
              let schemaVersion = snapshot["schema_version"] as? Int,
              schemaVersion == 1,
              let state = snapshot["state"] as? String,
              ["not_started", "browsing"].contains(state),
              let diagnostics = snapshot["diagnostics"] as? [Any], diagnostics.isEmpty,
              let rawCandidates = snapshot["candidates"] as? [[String: Any]],
              let candidates = validatedCandidates(rawCandidates, while: state),
              let confirmed = snapshot["confirmed"] as? [Any], confirmed.isEmpty,
              snapshot["inventory"] is NSNull,
              let layout = snapshot["layout"] as? [String: Any],
              Set(layout.keys) == ["state"],
              layout["state"] as? String == "not_configured",
              let capabilities = snapshot["capabilities"] as? [String: Any],
              Set(capabilities.keys) == ["input_enabled", "clipboard_enabled"],
              capabilities["input_enabled"] as? Bool == false,
              capabilities["clipboard_enabled"] as? Bool == false
        else { throw HostError.invalidFrame }
        guard envelope.snapshot.generation > highestGeneration else { return }
        highestGeneration = envelope.snapshot.generation
        nearbyCandidates = candidates
        shell = state == "not_started" ? .readyToDiscover : .browsing
    }

    private func validatedCandidates(_ candidates: [[String: Any]], while state: String) -> [NearbyCandidatePresentation]? {
        guard candidates.count <= 32 else { return nil }
        if state == "not_started" && !candidates.isEmpty { return nil }
        var handles = Set<String>()
        var validated: [NearbyCandidatePresentation] = []
        for candidate in candidates {
            guard Set(candidate.keys) == ["handle", "compatibility", "freshness"],
                  let handle = candidate["handle"] as? String,
                  !handle.isEmpty, handle.count <= 64,
                  handle.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }),
                  handles.insert(handle).inserted,
                  let compatibility = candidate["compatibility"] as? String,
                  ["compatible", "needs_update", "incompatible"].contains(compatibility),
                  let freshness = candidate["freshness"] as? String,
                  ["current", "stale", "gone"].contains(freshness)
            else { return nil }
            validated.append(NearbyCandidatePresentation(
                handle: handle,
                compatibility: compatibility,
                freshness: freshness
            ))
        }
        return validated
    }

    private func validateIgnoredSuccessResponse(_ object: [String: Any]) throws {
        guard Set(object.keys) == ["v", "kind", "id", "ok"],
              let version = object["v"] as? Int,
              version == 1,
              let id = object["id"] as? String,
              let ok = object["ok"] as? Bool,
              ok, requests.acknowledge(id)
        else { throw HostError.invalidFrame }
    }

    private func consumePairing(_ object: [String: Any]) throws {
        guard Set(object.keys) == ["v", "kind", "generation", "phase", "candidate_handle", "verification_words"],
              object["v"] as? Int == 1,
              object["kind"] as? String == "ui_pairing_v1",
              let generation = object["generation"] as? UInt64,
              let candidate = object["candidate_handle"] as? String,
              let words = object["verification_words"] as? [String],
              let phase = object["phase"] as? String
        else { throw HostError.invalidFrame }
        var state = MacPairingBridgeState()
        state.beginVerification(candidate: candidate, words: words)
        guard state.phase == .awaitingLocalConfirmation else { throw HostError.invalidFrame }
        switch phase {
        case "awaiting_local_confirmation": break
        case "awaiting_remote_confirmation": state.approveLocalDisplay(matches: true)
        case "ready_for_durable_admission":
            state.approveLocalDisplay(matches: true)
            state.acceptRemoteDisplay()
        default: throw HostError.invalidFrame
        }
        guard generation > highestGeneration else { return }
        highestGeneration = generation
        pairing = state
    }

    private func isValid(_ row: WireDiagnosticRow) -> Bool {
        let validIDs = ["runtime", "input", "clipboard", "displays", "relationship", "session", "layout", "policy"]
        let validStates = ["pass", "fail", "unknown", "not_configured"]
        let validDetails = ["ready", "not_measured", "not_configured", "stale", "unavailable", "policy_blocked", "fault"]
        return validIDs.contains(row.id)
            && validIDs.contains(row.label)
            && validStates.contains(row.state)
            && validDetails.contains(row.detail)
            && row.action.map(["refresh", "review_local_permission", "review_private_network", "retry"].contains) != false
            && row.failureCode.map([
                "runtime_status_unavailable", "input_permission_denied", "clipboard_unavailable",
                "clipboard_fault", "displays_unavailable", "discovery_unavailable", "session_unavailable",
            ].contains) != false
    }

    private func runtimeStatus(for rows: [DiagnosticSourceRow]) -> RuntimeStatus {
        let runtimeRows = rows.filter { $0.id == "runtime" }
        guard runtimeRows.count == 1 else { return .unknown }
        return runtimeRows[0].state == "pass" ? .currentPass : .stale
    }
}

private func bigEndianLength(_ bytes: Data.SubSequence) -> UInt32 {
    bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
}

protocol ChildLifecycleChild: AnyObject {
    func sendRefresh() throws
    func sendStartDiscovery() throws
    func sendStopDiscovery() throws
    func sendSelectCandidate(_ handle: String) throws
    func sendApproveSas(generation: UInt64, matches: Bool) throws
    func closeInput()
    func closeOutput()
    func closeError()
    func terminate()
    func forceTerminate()
    func reap(timeout: TimeInterval) -> Bool
    func clearTerminationHandler()
}

enum ChildOutputEvent {
    case data(Data)
    case endOfFile
    case pipeFailure
    case termination
}

/// Generation makes queued output from a closed child inert before it reaches
/// an AppKit view. The host has no commands other than a redacted refresh.
final class ChildLifecycle {
    private let child: ChildLifecycleChild
    private let closeLock = NSLock()
    private var closeFailure: ChildLifecycleError?
    private(set) var generation: UInt64 = 1
    private(set) var isClosed = false

    init(child: ChildLifecycleChild) {
        self.child = child
    }

    func refresh() {
        guard !isClosed else { return }
        try? child.sendRefresh()
    }

    func startDiscovery() {
        guard !isClosed else { return }
        try? child.sendStartDiscovery()
    }

    func stopDiscovery() {
        guard !isClosed else { return }
        try? child.sendStopDiscovery()
    }

    func selectCandidate(_ handle: String) {
        guard !isClosed else { return }
        try? child.sendSelectCandidate(handle)
    }

    func approveSas(generation: UInt64, matches: Bool) {
        guard !isClosed else { return }
        try? child.sendApproveSas(generation: generation, matches: matches)
    }

    func close() throws {
        closeLock.lock()
        if isClosed {
            let failure = closeFailure
            closeLock.unlock()
            if let failure { throw failure }
            return
        }
        isClosed = true
        generation &+= 1
        child.closeInput()
        child.terminate()
        var reaped = child.reap(timeout: 0.25)
        if !reaped {
            child.forceTerminate()
            reaped = child.reap(timeout: 0.25)
        }
        child.clearTerminationHandler()
        child.closeOutput()
        child.closeError()
        if !reaped { closeFailure = .unreaped }
        let failure = closeFailure
        closeLock.unlock()
        if let failure { throw failure }
    }
}

enum ChildLifecycleError: Error {
    case unreaped
}

/// The sole terminal transition for one child generation. It is main-thread
/// owned so EOF, pipe faults, and process exit cannot leave a previous PASS
/// visible or race a queued output callback.
final class DiagnosticsSession {
    private let controller: DiagnosticsFrameController
    private let lifecycle: ChildLifecycle
    private let acceptedGeneration: UInt64
    private let accumulator = FrameAccumulator()
    private(set) var isTerminal = false

    var presentation: DiagnosticsPresentation { controller.presentation }

    init(
        controller: DiagnosticsFrameController = DiagnosticsFrameController(),
        lifecycle: ChildLifecycle
    ) {
        self.controller = controller
        self.lifecycle = lifecycle
        acceptedGeneration = lifecycle.generation
    }

    func receive(_ event: ChildOutputEvent) throws {
        precondition(Thread.isMainThread)
        guard !isTerminal, !lifecycle.isClosed, lifecycle.generation == acceptedGeneration else { return }
        switch event {
        case .data(let bytes):
            guard !bytes.isEmpty else {
                terminal()
                return
            }
            do {
                for frame in try accumulator.append(bytes) {
                    try controller.consume(lengthPrefixed: frame)
                }
            } catch {
                terminal()
            }
        case .endOfFile, .pipeFailure, .termination:
            terminal()
        }
    }

    private func terminal() {
        guard !isTerminal else { return }
        isTerminal = true
        controller.invalidate()
        try? lifecycle.close()
    }
}

/// The fixed local child projection process. The executable URL is derived
/// from the installed bundle, never from a user path, shell, or environment.
final class BundledChild: ChildLifecycleChild {
    private static let childArguments = ["control", "--ui-stdio"]

    private let executableURL: URL
    private let inputPipe = Pipe()
    private let outputPipe = Pipe()
    private let errorPipe = Pipe()
    private let process: Process
    private let requests: ChildRequestTracker
    private let outputDrainQueue = DispatchQueue(label: "control-shift-f12.stdout")
    private let errorDrainQueue = DispatchQueue(label: "control-shift-f12.stderr")
    private let terminationQueue = DispatchQueue(label: "control-shift-f12.termination")
    private var discardedErrorBytes: UInt64 = 0

    init?(bundle: Bundle = .main, requests: ChildRequestTracker) {
        self.requests = requests
        let candidate = bundle.bundleURL
            .appendingPathComponent("Contents/Resources/seamless-input", isDirectory: false)
        guard candidate.isFileURL,
              candidate.path.hasPrefix("/"),
              FileManager.default.isExecutableFile(atPath: candidate.path)
        else { return nil }
        executableURL = candidate
        process = Process()
        process.executableURL = executableURL
        process.arguments = Self.childArguments
        process.standardInput = inputPipe
        process.standardOutput = outputPipe
        process.standardError = errorPipe
    }

    init(executableURL: URL, arguments: [String], requests: ChildRequestTracker) {
        self.executableURL = executableURL
        self.requests = requests
        process = Process()
        process.executableURL = executableURL
        process.arguments = arguments
        process.standardInput = inputPipe
        process.standardOutput = outputPipe
        process.standardError = errorPipe
    }

    func start() throws {
        errorPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            guard let self else { return }
            self.errorDrainQueue.async { [weak self] in
                guard let self else { return }
                let data = handle.availableData
                self.countDiscardedErrorBytes(data.count)
            }
        }
        try process.run()
    }

    func sendRefresh() throws {
        try sendRequest(command: "ui.refresh")
    }

    func sendStartDiscovery() throws {
        try sendRequest(command: "ui.start_discovery")
    }

    func sendStopDiscovery() throws {
        try sendRequest(command: "ui.stop_discovery")
    }

    func sendSelectCandidate(_ handle: String) throws {
        try sendRequest(command: "ui.select_candidate", args: ["handle": handle])
    }

    func sendApproveSas(generation: UInt64, matches: Bool) throws {
        try sendRequest(
            command: "ui.approve_sas",
            args: ["generation": generation, "matches": matches]
        )
    }

    private func sendRequest(command: String, args: [String: Any] = [:]) throws {
        let frame = try requests.frame(command: command, args: args)
        try inputPipe.fileHandleForWriting.write(contentsOf: frame)
    }

    func closeInput() { try? inputPipe.fileHandleForWriting.close() }
    func closeOutput() {
        outputPipe.fileHandleForReading.readabilityHandler = nil
        outputDrainQueue.sync {}
        try? outputPipe.fileHandleForReading.close()
    }
    func closeError() {
        errorPipe.fileHandleForReading.readabilityHandler = nil
        errorDrainQueue.sync {
            let final = errorPipe.fileHandleForReading.availableData
            countDiscardedErrorBytes(final.count)
        }
        try? errorPipe.fileHandleForReading.close()
    }
    func terminate() {
        if process.isRunning { process.terminate() }
    }
    func forceTerminate() {
        if process.isRunning { kill(process.processIdentifier, SIGKILL) }
    }
    func reap(timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.01))
        }
        return !process.isRunning
    }

    func observeOutput(_ handler: @escaping (ChildOutputEvent) -> Void) {
        outputPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            self?.outputDrainQueue.async {
                let data = handle.availableData
                handler(data.isEmpty ? .endOfFile : .data(data))
            }
        }
    }

    func observeTermination(_ handler: @escaping () -> Void) {
        process.terminationHandler = { [weak self] _ in
            self?.terminationQueue.async { handler() }
        }
    }

    func clearTerminationHandler() {
        process.terminationHandler = nil
        terminationQueue.sync {}
    }

    private func countDiscardedErrorBytes(_ count: Int) {
        let (sum, overflow) = discardedErrorBytes.addingReportingOverflow(UInt64(count))
        discardedErrorBytes = overflow ? .max : sum
    }
}

private final class FrameAccumulator {
    private var buffered = Data()
    private let lock = NSLock()

    func append(_ data: Data) throws -> [Data] {
        lock.lock()
        defer { lock.unlock() }
        buffered.append(data)
        var frames: [Data] = []
        while buffered.count >= MemoryLayout<UInt32>.size {
            let length = bigEndianLength(buffered.prefix(MemoryLayout<UInt32>.size))
            guard length > 0, length <= maximumFrameBytes else { throw HostError.invalidFrame }
            let fullLength = MemoryLayout<UInt32>.size + Int(length)
            guard buffered.count >= fullLength else { break }
            frames.append(Data(buffered.prefix(fullLength)))
            buffered.removeFirst(fullLength)
        }
        guard buffered.count <= maximumFrameBytes + MemoryLayout<UInt32>.size else {
            throw HostError.invalidFrame
        }
        return frames
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSTableViewDataSource, NSTableViewDelegate {
    private let diagnostics = DiagnosticsFrameController()
    private var lifecycle: ChildLifecycle?
    private var session: DiagnosticsSession?
    private let statusLabel = NSTextField(labelWithString: "Not running")
    private let table = NSTableView()
    private let refreshButton = NSButton(title: "Refresh", target: nil, action: nil)
    private weak var journeyHeading: NSTextField?
    private weak var journeyStatus: NSTextField?
    private weak var pairingButton: NSButton?
    private weak var nearbyCandidatesLabel: NSTextField?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 900, height: 680),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Control Shift F12"
        let content = NSView()
        content.translatesAutoresizingMaskIntoConstraints = false
        window.contentView = content

        let title = NSTextField(labelWithString: "Control Shift F12")
        title.font = .systemFont(ofSize: 20, weight: .semibold)
        let detail = NSTextField(wrappingLabelWithString: "Pair computers, organize displays, and choose what to share. Remote control stays off until a verified session is ready.")
        detail.textColor = .secondaryLabelColor
        statusLabel.font = .systemFont(ofSize: 13, weight: .medium)
        refreshButton.target = self
        refreshButton.action = #selector(refreshDiagnostics)
        refreshButton.setAccessibilityLabel("Refresh diagnostics")

        let scroll = NSScrollView()
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("diagnostic"))
        column.title = "Diagnostic"
        table.addTableColumn(column)
        table.headerView = nil
        table.dataSource = self
        table.delegate = self
        scroll.documentView = table
        scroll.hasVerticalScroller = true

        let journey = desktopJourneyView()
        let stack = NSStackView(views: [title, detail, journey, statusLabel, scroll, refreshButton])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -24),
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 24),
            stack.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -24),
            scroll.widthAnchor.constraint(equalTo: stack.widthAnchor),
            scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 180),
        ])

        if let child = BundledChild(requests: diagnostics.requests), (try? child.start()) != nil {
            let lifecycle = ChildLifecycle(child: child)
            self.lifecycle = lifecycle
            let session = DiagnosticsSession(controller: diagnostics, lifecycle: lifecycle)
            self.session = session
            observe(child, lifecycle: lifecycle, session: session)
            lifecycle.refresh()
        }
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationWillTerminate(_ notification: Notification) {
        diagnostics.close()
        session = nil
        try? lifecycle?.close()
    }

    @objc private func refreshDiagnostics() {
        guard session?.presentation.refreshEnabled == true else { return }
        lifecycle?.refresh()
    }

    @objc private func startDiscovery() {
        if diagnostics.shell.findNearbyEnabled {
            lifecycle?.startDiscovery()
        } else if diagnostics.shell == .browsing {
            lifecycle?.stopDiscovery()
        }
    }

    private func updateJourney() {
        let shell = diagnostics.shell
        journeyHeading?.stringValue = shell.title
        journeyStatus?.stringValue = shell.connectionStatus
        pairingButton?.isEnabled = shell.findNearbyEnabled || shell == .browsing
        pairingButton?.title = shell == .browsing ? "Stop searching" : "Find nearby computers"
        if diagnostics.nearbyCandidates.isEmpty {
            nearbyCandidatesLabel?.stringValue = shell == .browsing
                ? "Searching for nearby computers…"
                : "No nearby computers found yet."
        } else {
            nearbyCandidatesLabel?.stringValue = diagnostics.nearbyCandidates
                .map(\.displayText)
                .joined(separator: "\n")
        }
    }

    private func desktopJourneyView() -> NSView {
        let presentation = MacDesktopShellPresentation.initial
        let heading = NSTextField(labelWithString: presentation.title)
        heading.font = .systemFont(ofSize: 15, weight: .semibold)
        journeyHeading = heading

        let status = NSTextField(labelWithString: presentation.connectionStatus)
        status.textColor = .secondaryLabelColor
        journeyStatus = status

        let pairing = NSButton(title: "Find nearby computers", target: self, action: #selector(startDiscovery))
        pairing.isEnabled = presentation.findNearbyEnabled
        pairing.setAccessibilityLabel("Find nearby computers")
        pairingButton = pairing

        let candidates = NSTextField(wrappingLabelWithString: "No nearby computers found yet.")
        candidates.textColor = .secondaryLabelColor
        candidates.setAccessibilityLabel("Nearby computers")
        nearbyCandidatesLabel = candidates

        let confirm = NSButton(title: "Confirm code on both computers", target: nil, action: nil)
        confirm.isEnabled = presentation.confirmCodeEnabled
        confirm.setAccessibilityLabel("Confirm code on both computers")

        let map = NSTextField(wrappingLabelWithString: "Display map — pair another computer to arrange screens by dragging them into their physical positions.")
        map.textColor = .secondaryLabelColor

        let input = checkBox(title: "Input sharing", enabled: presentation.inputSharingEnabled)
        let clipboard = checkBox(title: "Clipboard sharing", enabled: presentation.clipboardSharingEnabled)
        let updates = checkBox(title: "Automatic updates", enabled: presentation.automaticUpdatesEnabled)
        let save = NSButton(title: "Save shared layout", target: nil, action: nil)
        save.isEnabled = presentation.saveLayoutEnabled

        let options = NSStackView(views: [input, clipboard, updates, save])
        options.orientation = .horizontal
        options.spacing = 14

        let content = NSStackView(views: [heading, status, pairing, candidates, confirm, map, options])
        content.orientation = .vertical
        content.alignment = .leading
        content.spacing = 8
        content.edgeInsets = NSEdgeInsets(top: 14, left: 14, bottom: 14, right: 14)
        content.wantsLayer = true
        content.layer?.backgroundColor = NSColor.controlBackgroundColor.cgColor
        content.layer?.cornerRadius = 10
        return content
    }

    private func checkBox(title: String, enabled: Bool) -> NSButton {
        let box = NSButton(checkboxWithTitle: title, target: nil, action: nil)
        box.state = .on
        box.isEnabled = enabled
        return box
    }

    private func observe(_ child: BundledChild, lifecycle: ChildLifecycle, session: DiagnosticsSession) {
        let generation = lifecycle.generation
        let apply: (ChildOutputEvent) -> Void = { [weak self] event in
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                guard !lifecycle.isClosed, lifecycle.generation == generation else { return }
                try? session.receive(event)
                self.statusLabel.stringValue = self.diagnostics.presentation.statusText
                self.refreshButton.isEnabled = self.diagnostics.presentation.refreshEnabled
                self.updateJourney()
                self.table.reloadData()
            }
        }
        child.observeOutput(apply)
        child.observeTermination { apply(.termination) }
    }

    func numberOfRows(in tableView: NSTableView) -> Int {
        diagnostics.presentation.rows.count
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        let item = diagnostics.presentation.rows[row]
        let title = NSTextField(labelWithString: item.title)
        let status = NSTextField(labelWithString: item.statusText)
        status.textColor = item.tone == .blocked ? .systemRed : .secondaryLabelColor
        let rowView = NSTableCellView()
        let stack = NSStackView(views: [title, status])
        stack.orientation = .horizontal
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        rowView.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: rowView.leadingAnchor, constant: 8),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: rowView.trailingAnchor, constant: -8),
            stack.centerYAnchor.constraint(equalTo: rowView.centerYAnchor),
        ])
        rowView.setAccessibilityLabel(item.accessibilityLabel)
        return rowView
    }
}

@main
struct ControlShiftF12App {
    static func main() {
        let application = NSApplication.shared
        let delegate = AppDelegate()
        application.delegate = delegate
        application.setActivationPolicy(.regular)
        application.run()
    }
}
