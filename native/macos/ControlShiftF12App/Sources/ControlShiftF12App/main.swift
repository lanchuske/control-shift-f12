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

    init(runtime: RuntimeStatus, rows: [DiagnosticSourceRow]) {
        statusText = runtime == .currentPass ? "Running" : "Not running"
        refreshEnabled = true
        // This diagnostics host renders only current local facts. It has no
        // relationship/session action or count surface.
        showsSessionCount = false
        self.rows = rows.map(DiagnosticPresentationRow.init)
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

/// Owns the redacted diagnostics view state. Calls to `consume` must be made
/// on the AppKit main thread after a complete frame has been decoded.
final class DiagnosticsFrameController {
    private(set) var presentation = DiagnosticsPresentation(runtime: .unknown, rows: [])
    private var highestGeneration: UInt64 = 0
    private var isClosed = false

    func consume(lengthPrefixed frame: Data) throws {
        guard Thread.isMainThread else { throw HostError.notOnMainThread }
        guard !isClosed else { return }
        let payload = try completePayload(from: frame)
        let object = try strictObject(payload)
        guard Set(object.keys) == ["v", "kind", "generation", "rows"] else {
            throw HostError.invalidFrame
        }
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

    func close() {
        isClosed = true
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

    private func strictObject(_ payload: Data) throws -> [String: Any] {
        guard let object = try JSONSerialization.jsonObject(with: payload) as? [String: Any] else {
            throw HostError.invalidFrame
        }
        let rowKeys: Set<String> = ["id", "label", "state", "detail", "action", "failure_code"]
        guard let rows = object["rows"] as? [[String: Any]],
              rows.allSatisfy({ Set($0.keys) == rowKeys })
        else { throw HostError.invalidFrame }
        return object
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
    func closeInput()
    func closeOutput()
    func closeError()
    func terminate()
    func forceTerminate()
    func reap(timeout: TimeInterval) -> Bool
}

/// Generation makes queued output from a closed child inert before it reaches
/// an AppKit view. The host has no commands other than a redacted refresh.
final class ChildLifecycle {
    private let child: ChildLifecycleChild
    private(set) var generation: UInt64 = 1
    private(set) var isClosed = false

    init(child: ChildLifecycleChild) {
        self.child = child
    }

    func refresh() {
        guard !isClosed else { return }
        try? child.sendRefresh()
    }

    func close() {
        guard !isClosed else { return }
        isClosed = true
        generation &+= 1
        child.closeInput()
        child.closeOutput()
        child.closeError()
        child.terminate()
        if !child.reap(timeout: 0.25) {
            child.forceTerminate()
            _ = child.reap(timeout: 0.25)
        }
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

    init?(bundle: Bundle = .main) {
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

    func start() throws {
        try process.run()
    }

    func sendRefresh() throws {
        let request: [String: Any] = [
            "v": 1,
            "id": "mac-refresh",
            "command": "ui.refresh",
            "args": [:],
        ]
        let payload = try JSONSerialization.data(withJSONObject: request)
        guard payload.count > 0, payload.count <= maximumFrameBytes else { throw HostError.invalidFrame }
        var length = UInt32(payload.count).bigEndian
        var frame = Data(bytes: &length, count: MemoryLayout<UInt32>.size)
        frame.append(payload)
        try inputPipe.fileHandleForWriting.write(contentsOf: frame)
    }

    func closeInput() { try? inputPipe.fileHandleForWriting.close() }
    func closeOutput() { try? outputPipe.fileHandleForReading.close() }
    func closeError() { try? errorPipe.fileHandleForReading.close() }
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

    func observeOutput(_ handler: @escaping (Data) -> Void) {
        outputPipe.fileHandleForReading.readabilityHandler = { handle in
            handler(handle.availableData)
        }
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
    private var accumulator = FrameAccumulator()
    private let statusLabel = NSTextField(labelWithString: "Not running")
    private let table = NSTableView()

    func applicationDidFinishLaunching(_ notification: Notification) {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 700, height: 430),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Control Shift F12"
        let content = NSView()
        content.translatesAutoresizingMaskIntoConstraints = false
        window.contentView = content

        let title = NSTextField(labelWithString: "Device readiness")
        title.font = .systemFont(ofSize: 20, weight: .semibold)
        let detail = NSTextField(wrappingLabelWithString: "Local checks are shown individually. Remote control stays off.")
        detail.textColor = .secondaryLabelColor
        statusLabel.font = .systemFont(ofSize: 13, weight: .medium)
        let refresh = NSButton(title: "Refresh", target: self, action: #selector(refreshDiagnostics))
        refresh.setAccessibilityLabel("Refresh diagnostics")

        let scroll = NSScrollView()
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("diagnostic"))
        column.title = "Diagnostic"
        table.addTableColumn(column)
        table.headerView = nil
        table.dataSource = self
        table.delegate = self
        scroll.documentView = table
        scroll.hasVerticalScroller = true

        let stack = NSStackView(views: [title, detail, statusLabel, scroll, refresh])
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

        if let child = BundledChild(), (try? child.start()) != nil {
            let lifecycle = ChildLifecycle(child: child)
            self.lifecycle = lifecycle
            observe(child, lifecycle: lifecycle)
            lifecycle.refresh()
        }
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationWillTerminate(_ notification: Notification) {
        diagnostics.close()
        lifecycle?.close()
    }

    @objc private func refreshDiagnostics() {
        lifecycle?.refresh()
    }

    private func observe(_ child: BundledChild, lifecycle: ChildLifecycle) {
        let generation = lifecycle.generation
        child.observeOutput { [weak self] bytes in
            guard !bytes.isEmpty else { return }
            let frames = try? self?.accumulator.append(bytes)
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                guard !lifecycle.isClosed, lifecycle.generation == generation else { return }
                for frame in frames ?? [] {
                    try? self.diagnostics.consume(lengthPrefixed: frame)
                }
                self.statusLabel.stringValue = self.diagnostics.presentation.statusText
                self.table.reloadData()
            }
        }
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
