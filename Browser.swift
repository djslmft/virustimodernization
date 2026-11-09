import SwiftUI
import AppKit
import CryptoKit
import CoreMIDI
import IOKit

struct FactoryPreset: Identifiable {
    let id: Int
    let name: String
    let file: String
    let bank: Int
    let program: Int
    let format: String
    let sha256: String
    var isHardwareRAM: Bool { file.hasPrefix("Snow RAM/") }
    var canLoad: Bool { (isHardwareRAM || file.hasPrefix("Virus TI Snow Factory Backup/")) && format == "VirusTI_Singledump" }
}

struct ParameterRow: Identifiable {
    let id: Int
    let path: String
    let value: String
    let raw: String
}

enum PresetPacket {
    static func valid(_ bytes: [UInt8]) -> Bool {
        guard [267, 524].contains(bytes.count), Array(bytes.prefix(5)) == [240,0,32,51,1], bytes[6] == 16, bytes.last == 247,
              bytes.dropFirst().dropLast().allSatisfy({ $0 < 128 }) else { return false }
        guard bytes[5...264].reduce(0, { $0 + Int($1) }) & 127 == Int(bytes[265]) else { return false }
        return bytes.count == 267 || bytes[5...521].reduce(0, { $0 + Int($1) }) & 127 == Int(bytes[522])
    }
}

private final class SnowPanelMessages {
    private var sysEx: [UInt8] = []
    private var parameterPage: UInt8?
    private var controller: UInt8?
    private var programChange = false

    func receive(_ byte: UInt8, onChange: (UInt8, UInt8, Int) -> Void) {
        guard byte < 0xf8 else { return }
        if byte >= 0x80 {
            if byte == 0xf7, sysEx.count == 10,
               sysEx.starts(with:[0xf0, 0, 0x20, 0x33, 1, 0]),
               sysEx[7] == 64 {
                onChange(sysEx[6], sysEx[8], Int(sysEx[9]))
            }
            sysEx = byte == 0xf0 ? [byte] : []
            programChange = byte == 0xc0
            switch byte {
            case 0xb0: parameterPage = 0x70
            case 0xa0: parameterPage = 0x71
            default: parameterPage = nil
            }
            controller = nil
        } else if !sysEx.isEmpty {
            if sysEx.count < 10 { sysEx.append(byte) }
            else { sysEx.removeAll() }
        } else if programChange {
            onChange(0xc0, 0, Int(byte))
        } else if let parameterPage {
            if let controller {
                onChange(parameterPage, controller, Int(byte))
                self.controller = nil
            } else {
                controller = byte
            }
        }
    }
}

private final class SnowPanelMonitor {
    private var client = MIDIClientRef()
    private var port = MIDIPortRef()

    init?(onChange: @escaping (UInt8, UInt8, Int) -> Void) {
        let messages = SnowPanelMessages()
        let sources = (0..<MIDIGetNumberOfSources()).map(MIDIGetSource).filter { source in
            var name: Unmanaged<CFString>?
            return MIDIObjectGetStringProperty(source, kMIDIPropertyDisplayName, &name) == noErr
                && name?.takeRetainedValue() as String? == "Virus TI USB Plugin I/O"
        }
        guard sources.count == 1,
              MIDIClientCreate("Snow front panel" as CFString, nil, nil, &client) == noErr,
              MIDIInputPortCreateWithBlock(client, "Snow front-panel controls" as CFString, &port, { list, _ in
                  let offset = MemoryLayout<MIDIPacketList>.offset(of: \.packet)!
                  var packet = UnsafeRawPointer(list).advanced(by:offset).assumingMemoryBound(to:MIDIPacket.self)
                  for _ in 0..<list.pointee.numPackets {
                      let dataOffset = MemoryLayout<MIDIPacket>.offset(of: \.data)!
                      let bytes = UnsafeRawPointer(packet).advanced(by:dataOffset)
                          .assumingMemoryBound(to:UInt8.self)
                      for index in 0..<Int(packet.pointee.length) {
                          messages.receive(bytes[index], onChange:onChange)
                      }
                      packet = UnsafePointer(MIDIPacketNext(packet))
                  }
              }) == noErr,
              MIDIPortConnectSource(port, sources[0], nil) == noErr else { return nil }
    }

    deinit {
        if port != 0 { MIDIPortDispose(port) }
        if client != 0 { MIDIClientDispose(client) }
    }
}

@MainActor
final class BrowserModel: ObservableObject {
    @Published var selectedFactoryPreset: FactoryPreset?
    @Published var factory: [FactoryPreset] = []
    @Published private(set) var hardwareRAM: [FactoryPreset] = []
    var presetLibrary: [FactoryPreset] { hardwareRAM + factory }
    private var hardwareRAMFrames = Data()
    nonisolated static let snowRAMSoundCount = 512
    @Published private(set) var hardwareRAMProgress: Int?
    var readingHardwareRAM: Bool { hardwareRAMProgress != nil }
    var hardwareRAMProgressLabel: String {
        if ramReadProcess == nil { return "Cancelling Snow RAM read…" }
        return "\(hardwareRAMProgress ?? 0) of \(Self.snowRAMSoundCount) sounds read"
    }
    private var ramReadProcess: Process?
    private var attachedSnow: UInt64?
    private var lastUSBCheck: TimeInterval = 0
    @Published var rows: [ParameterRow] = []
    @Published var patchName = "No preset read"
    @Published var status = "Ready — no MIDI requests sent in this session"
    @Published var source = "No live read yet"
    @Published var busy = false
    @Published var resourceError = ""
    @Published var currentBank = 1
    @Published var currentProgram = 0
    @Published var editTarget: Int? {
        didSet {
            if oldValue != editTarget {
                if editTarget != 64 { stopUSBMonitor() }
                frontPanelValues.removeAll()
                softKnobValues.removeAll()
                patchRefreshPending = false
            }
        }
    }
    @Published var cutoffValue: Double = 0
    @Published var pendingPath: String?
    @Published var pendingValue = 0
    @Published var editable: [String:EditableParameter] = [:]
    @Published var undoChange: VerifiedEdit?
    @Published var followSnow = false {
        didSet {
            if followSnow { startPanelMonitor() }
            else {
                panelMonitor = nil
                stopUSBMonitor()
                frontPanelValues.removeAll()
                softKnobValues.removeAll()
                patchRefreshPending = false
            }
        }
    }
    @Published private var softKnobValues: [Int: Int] = [:]
    @Published private var frontPanelValues: [String: Int] = [:]
    private var panelMonitor: SnowPanelMonitor?
    private var usbMonitor: (process:Process, input:FileHandle, output:FileHandle)?
    private var frontPanelRevision = 0
    private var lastFrontPanelChange: TimeInterval = 0
    private var patchRefreshPending = false
    private static let softKnobCCs = [0, 1, 2, 3, 4, 6, 8, 9, 11, 12, 13, 14, 15, 16]
    private static let softKnobParameters = [
        42: "Filter 1/Resonance", 43: "Filter 2/Resonance",
        87: "Patch Distortion/Intensity", 105: "Arpeggiator/Mode",
        106: "Arpeggiator/Pattern", 107: "Arpeggiator/Clock",
        108: "Arpeggiator/NoteLength", 109: "Arpeggiator/Swing",
        110: "Arpeggiator/OctaveRange", 111: "Arpeggiator/HoldEnable"
    ]
    private var followingRead = false
    private var usingDirectUSB = false
    @Published var liveMode = true
    @Published var liveEditing = false
    private var livePath: String?
    private var liveSession: LiveEditSession?
    var packet: [UInt8] = []
    private var factoryFrames = Data()
    private var schema: [String: Any] = [:]

    private var rowsByPath: [String: ParameterRow] = [:]
    private lazy var panelParameters = Dictionary(grouping:editable.values) {
        $0.page * 128 + $0.controller
    }
    private lazy var parameterLabels: [String: [Int: String]] = {
        var lists: [String: [Int: String]] = [:]
        for list in schema["valueLists"] as? [[String:Any]] ?? [] {
            guard let name = list["name"] as? String else { continue }
            // The soft-knob lists sort by display index, with explicit values for reordered entries.
            let usesStoredValue = name == "Val Name Softknob Name" || name == "Val Name Softknob target"
            var labels: [Int: String] = [:]
            for entry in list["entries"] as? [[String:Any]] ?? [] {
                let indexText = (usesStoredValue ? entry["value"] : nil) ?? entry["index"]
                guard let index = Int(indexText as? String ?? ""), let text = entry["text"] as? String else { continue }
                labels[index] = text
            }
            lists[name] = labels
        }
        var labelsByPath: [String: [Int: String]] = [:]
        for parameter in schema["parameters"] as? [[String:Any]] ?? [] {
            guard let group = parameter["group"] as? String, let name = parameter["name"] as? String,
                  let list = parameter["valuelist"] as? String else { continue }
            labelsByPath[group + "/" + name] = lists[list]
        }
        return labelsByPath
    }()

    func rawValue(_ path:String) -> Int? { rowsByPath[path].flatMap { Int($0.raw) } }
    var frontPanelCutoff: Double { displayValue("Filter 1/Cutoff").map(Double.init) ?? cutoffValue }
    func mappedValue(_ path:String) -> String? { rowsByPath[path]?.value }

    func canEdit(_ path:String) -> Bool { (!busy || liveEditing && livePath == path) && editTarget != nil && editable[path]?.active(in:packet) == true }
    func softKnobControllerValue(slot: Int) -> Int? {
        guard let destination = rawValue("Soft Knobs/Destination \(slot)"),
              destination != 0, Self.softKnobCCs.indices.contains(destination) else { return nil }
        let controller = Self.softKnobCCs[destination]
        return softKnobValues[controller]
    }

    func displayValue(_ path:String) -> Int? {
        if path.hasPrefix("Softknobs/Softknob "), let slot = Int(path.suffix(1)),
           let destination = rawValue("Soft Knobs/Destination \(slot)") {
            if Self.softKnobCCs.indices.contains(destination), destination != 0 {
                return softKnobControllerValue(slot: slot)
            }
            if let target = Self.softKnobParameters[destination], let parameter = editable[target],
               let value = displayValue(target), parameter.maximum > parameter.minimum {
                return (value - parameter.minimum) * 127 / (parameter.maximum - parameter.minimum)
            }
            return nil
        }
        return pendingPath == path ? pendingValue : frontPanelValues[path] ?? rawValue(path)
    }
    func label(_ path:String, value:Int) -> String {
        parameterLabels[path]?[value] ?? String(value)
    }
    func stage(_ path:String, value:Int) {
        guard canEdit(path), let p = editable[path] else { return }
        pendingPath = path; pendingValue = min(p.maximum,max(p.minimum,value))
        if path == "Filter 1/Cutoff" { cutoffValue = Double(pendingValue) }
        if liveEditing && livePath == path {
            liveSession?.send(pendingValue)
            status = "Live: \(path) = \(label(path,value:pendingValue))"
        } else if liveMode {
            applyParameter(path,value:pendingValue)
        } else { status = "Draft: \(path) = \(label(path,value:pendingValue)). Apply to send." }
    }
    func discardDraft() { pendingPath = nil; cutoffValue = Double(rawValue("Filter 1/Cutoff") ?? 0) }
    func applyDraft() { if let path = pendingPath { applyParameter(path,value:pendingValue) } }
    func undo() { if let change = undoChange, editTarget == change.target { applyParameter(change.parameter,value:change.before,undoing:true) } }
    func applyParameter(_ path:String, value:Int, undoing:Bool=false) {
        guard canEdit(path), let target = editTarget, let parameter = editable[path], value >= parameter.minimum, value <= parameter.maximum else {
            status = "Read the selected current buffer first; this parameter must be active in the sound’s mode"; return
        }
        let digest = SHA256.hash(data:Data(packet)).map { String(format:"%02x",$0) }.joined()
        let command = usingDirectUSB ? "--usb-set-parameter" : "--set-parameter"
        perform(arguments:[command,String(target),path,String(value),String(packet[parameter.offset]),digest],
                bank:0,program:target,writingCutoff:true,editedPath:path,undoing:undoing,directUSB:usingDirectUSB)
    }

    func beginLive(_ path:String) {
        guard !busy, liveSession == nil, liveMode, canEdit(path), let target = editTarget, let parameter = editable[path],
              let helper = Bundle.main.url(forAuxiliaryExecutable:"virus-identity-probe") else { return }
        let before = Int(packet[parameter.offset])
        let previousUndo = undoChange
        let digest = SHA256.hash(data:Data(packet)).map { String(format:"%02x",$0) }.joined()
        frontPanelValues.removeAll()
        stopUSBMonitor()
        busy = true; liveEditing = true; livePath = path
        status = "Starting live \(path)…"
        let command = usingDirectUSB ? "--usb-live-edit" : "--live-edit"
        liveSession = LiveEditSession(helper:helper,arguments:[command,String(target),path,String(before),digest]) { [weak self] outcome in
            Task { @MainActor in
                guard let self else { return }
                defer {
                    self.liveSession = nil; self.livePath = nil; self.liveEditing = false; self.busy = false
                    if self.usingDirectUSB && self.followSnow { self.startPanelMonitor() }
                }
                do {
                    let data = try outcome.get()
                    let report = try JSONSerialization.jsonObject(with:data) as? [String:Any] ?? [:]
                    try self.accept(report,source:"Live gesture readback verified",bank:0,program:target)
                    let verified = report["parameterWriteVerified"] as? Bool ?? false
                    let updates = report["liveUpdatesSent"] as? Int ?? 0
                    if verified, let after = self.rawValue(path) {
                        self.undoChange = updates > 0 && after != before ? VerifiedEdit(target:target,parameter:path,before:before,after:after) : previousUndo
                        self.status = "\(path): \(self.label(path,value:after)) — live gesture verified (\(updates) updates)"
                        if report["liveInputError"] != nil || report["liveTimedOut"] as? Bool == true {
                            self.status += "; stream stopped — release and read again"
                            self.editTarget = nil
                        }
                    } else {
                        self.editTarget = nil; self.undoChange = nil
                        self.status = report["status"] as? String ?? "Live gesture was not verified; read again"
                    }
                } catch {
                    self.editTarget = nil; self.undoChange = nil
                    self.status = "Live edit failed: \(error.localizedDescription). Read the synth again."
                }
            }
        }
    }

    func finishLive() {
        guard liveEditing else { return }
        liveEditing = false
        status = "Verifying final live value…"
        liveSession?.end()
    }

    init() {
        do {
            guard let schemaURL = Bundle.main.url(forResource: "parameter-schema", withExtension: "json"),
                  let factoryURL = Bundle.main.url(forResource: "factory-presets", withExtension: "json") else {
                throw NSError(domain: "Browser", code: 1, userInfo: [NSLocalizedDescriptionKey: "Bundled catalogue files are missing"])
            }
            schema = try JSONSerialization.jsonObject(with: Data(contentsOf: schemaURL)) as? [String:Any] ?? [:]
            guard let editURL = Bundle.main.url(forResource:"editable-parameters",withExtension:"json") else {
                throw NSError(domain:"Browser",code:4,userInfo:[NSLocalizedDescriptionKey:"Editable parameter definitions are missing"])
            }
            let edits = try JSONDecoder().decode([EditableParameter].self,from:Data(contentsOf:editURL))
            editable = Dictionary(uniqueKeysWithValues:edits.map { ($0.id,$0) })
            let records = try JSONSerialization.jsonObject(with: Data(contentsOf: factoryURL)) as? [[String:Any]] ?? []
            if let framesURL = Bundle.main.url(forResource: "factory-audition", withExtension: "bin") {
                factoryFrames = try Data(contentsOf: framesURL)
            }
            factory = records.enumerated().map { index, item in
                FactoryPreset(id: index, name: item["name"] as? String ?? "", file: item["file"] as? String ?? "",
                              bank: item["bank"] as? Int ?? 0, program: item["program"] as? Int ?? 0, format: item["format"] as? String ?? "",
                              sha256: item["sha256"] as? String ?? "")
            }
        } catch { resourceError = error.localizedDescription }
    }

    @discardableResult
    private func accept(_ report: [String:Any], source: String, bank: Int, program: Int, onlyIfChanged: Bool = false) throws -> Bool {
        let frames = report["receivedSysExHex"] as? [String] ?? []
        let matches = frames.compactMap { string -> [UInt8]? in
            let tokens = string.split(separator: " ")
            let bytes = tokens.compactMap { UInt8($0, radix: 16) }
            guard tokens.count == bytes.count, PresetPacket.valid(bytes), Int(bytes[7]) == bank, Int(bytes[8]) == program else { return nil }
            return bytes
        }
        guard let bytes = matches.first else {
            let message = report["status"] as? String ?? "No valid matching preset returned"
            throw NSError(domain: "Browser", code: 2, userInfo: [NSLocalizedDescriptionKey: message])
        }
        if onlyIfChanged && bytes == packet { return false }
        if !onlyIfChanged || bytes[249...258] != packet.dropFirst(249).prefix(10) { softKnobValues.removeAll() }
        packet = bytes
        patchName = String(bytes: bytes[249...258], encoding: .ascii)?.trimmingCharacters(in: .whitespaces) ?? "Unnamed"
        self.source = source
        currentBank = bank; currentProgram = program
        editTarget = bank == 0 && [0,1,2,3,64].contains(program) ? program : nil
        cutoffValue = Double(bytes[49])
        pendingPath = nil
        decodeParameters(bytes)
        return true
    }

    private func decodeParameters(_ bytes: [UInt8]) {
        let messageID = bytes.count == 524 ? "VirusTI_Singledump" : "VirusC_Singledump"
        let message = (schema["messages"] as? [[String:Any]] ?? []).first { $0["id"] as? String == messageID }
        let decoded: [ParameterRow] = (message?["bytes"] as? [[String:Any]] ?? []).enumerated().compactMap { index, field in
            guard field["type"] as? String == "parameter", let path = field["content"] as? String,
                  let rawOffset = field["index"] as? String, let offset = Int(rawOffset), offset < bytes.count else { return nil }
            let value = Int(bytes[offset])
            return ParameterRow(id:index, path:path, value:label(path, value:value), raw:String(value))
        }
        rowsByPath = Dictionary(decoded.map { ($0.path, $0) }, uniquingKeysWith: { first, _ in first })
        rows = decoded
    }

    func read(bank: Int, program: Int) {
        perform(arguments: ["--read-preset", String(bank), String(program)], bank: bank, program: program, writingCutoff: false)
    }

    func readCurrent(target: Int) {
        if !busy && followSnow && target == 64 { panelMonitor = nil }
        perform(arguments: ["--read-current", String(target)], bank: 0, program: target, writingCutoff: false)
    }

    func readCurrentViaUSB(onCompletion: (() -> Void)? = nil) {
        perform(arguments:["--usb-read-current", "--json"], bank:0, program:64,
                writingCutoff:false, directUSB:true, onCompletion:onCompletion)
    }

    private func stopUSBMonitor() {
        guard let monitor = usbMonitor else { return }
        usbMonitor = nil
        try? monitor.input.close()
        monitor.process.waitUntilExit()
        monitor.output.readabilityHandler = nil
        try? monitor.output.close()
    }

    private func startPanelMonitor() {
        panelMonitor = nil
        stopUSBMonitor()
        let onChange: (UInt8, UInt8, Int) -> Void = { [weak self] page, controller, value in
            DispatchQueue.main.async { [weak self] in
                guard let self, self.followSnow, self.editTarget == 64,
                      (!self.busy || self.followingRead) else { return }
                // Single patch selection emitted 73/10. The 73/40 message also follows a read.
                if page == 0xc0 || (page == 0x73 && controller == 0x10) {
                    self.patchRefreshPending = true
                    self.lastFrontPanelChange = ProcessInfo.processInfo.systemUptime
                    return
                }
                guard self.pendingPath == nil else { return }
                if page == 0x70 && Self.softKnobCCs.dropFirst().contains(Int(controller)) {
                    let cc = Int(controller)
                    if self.softKnobValues[cc] != value { self.softKnobValues[cc] = value }
                }
                let address = Int(page) * 128 + Int(controller)
                let matches = self.panelParameters[address]?.filter {
                    ($0.minimum...$0.maximum).contains(value) && $0.active(in:self.packet)
                } ?? []
                guard matches.count == 1, let path = matches.first?.id else { return }
                guard self.displayValue(path) != value else { return }
                self.frontPanelRevision += 1
                self.lastFrontPanelChange = ProcessInfo.processInfo.systemUptime
                self.frontPanelValues[path] = value
            }
        }
        guard usingDirectUSB else {
            panelMonitor = SnowPanelMonitor(onChange:onChange)
            return
        }
        guard !busy, editTarget == 64,
              let helper = Bundle.main.url(forAuxiliaryExecutable:"virus-identity-probe") else { return }
        let process = Process()
        let input = Pipe()
        let output = Pipe()
        process.executableURL = helper
        process.arguments = ["--usb-monitor"]
        process.standardInput = input
        process.standardOutput = output
        let errors = Pipe()
        process.standardError = errors
        process.terminationHandler = { [weak self] exited in
            let error = String(decoding:errors.fileHandleForReading.readDataToEndOfFile(), as:UTF8.self)
                .trimmingCharacters(in:.whitespacesAndNewlines)
            DispatchQueue.main.async { [weak self] in
                guard let self, self.usbMonitor?.process === exited else { return }
                self.stopUSBMonitor()
                self.status = error.isEmpty ? "Follow Snow stopped. Read via USB to reconnect."
                    : "Follow Snow stopped: \(error)"
            }
        }
        let messages = SnowPanelMessages()
        output.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil }
            for byte in data { messages.receive(byte, onChange:onChange) }
        }
        do {
            try process.run()
            usbMonitor = (process, input.fileHandleForWriting, output.fileHandleForReading)
        } catch {
            output.fileHandleForReading.readabilityHandler = nil
            status = "Could not start Follow Snow over direct USB: \(error.localizedDescription)"
        }
    }

    private func connectedSnowID() -> UInt64? {
        guard let matching = IOServiceMatching("IOUSBHostDevice") else { return nil }
        let properties: [String:Int] = ["idVendor":0x133e, "idProduct":0x0815]
        (matching as NSMutableDictionary)["IOPropertyMatch"] = properties
        let service = IOServiceGetMatchingService(kIOMainPortDefault, matching)
        guard service != 0 else { return nil }
        defer { IOObjectRelease(service) }
        var id: UInt64 = 0
        return IORegistryEntryGetRegistryEntryID(service, &id) == KERN_SUCCESS ? id : nil
    }

    func checkUSBConnection() {
        let now = ProcessInfo.processInfo.systemUptime
        guard !busy, now - lastUSBCheck >= 2 else { return }
        lastUSBCheck = now
        let connected = connectedSnowID()
        guard connected != attachedSnow else { return }
        attachedSnow = connected
        if selectedFactoryPreset?.isHardwareRAM == true { selectedFactoryPreset = nil }
        hardwareRAM.removeAll()
        hardwareRAMFrames.removeAll()
        if usingDirectUSB { editTarget = nil; discardDraft(); undoChange = nil }
        guard let connected else { return }
        editTarget = nil
        readCurrentViaUSB { [weak self] in
            guard let self, self.connectedSnowID() == connected else { return }
            self.readHardwareRAM(deviceID:connected)
            if self.editTarget == 64 { self.followSnow = true }
        }
    }

    func cancelHardwareRAMRead() {
        guard let process = ramReadProcess else { return }
        ramReadProcess = nil
        if process.isRunning { process.terminate() }
        status = "Cancelling Snow RAM read…"
    }

    private func readHardwareRAM(deviceID: UInt64) {
        guard let helper = Bundle.main.url(forAuxiliaryExecutable:"virus-identity-probe") else { return }
        stopUSBMonitor()
        let process = Process()
        let output = Pipe()
        let errors = Pipe()
        process.executableURL = helper
        process.arguments = ["--usb-read-ram"]
        process.standardOutput = output
        process.standardError = errors
        errors.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil; return }
            let progress = String(decoding:data, as:UTF8.self).split(separator:"\n")
                .last(where: { $0.hasPrefix("RAM progress ") })
                .flatMap { Int($0.dropFirst("RAM progress ".count)) }
            guard let progress, (0...Self.snowRAMSoundCount).contains(progress) else { return }
            DispatchQueue.main.async { [weak self] in
                guard let self, self.ramReadProcess === process,
                      progress > (self.hardwareRAMProgress ?? 0) else { return }
                self.hardwareRAMProgress = progress
            }
        }
        do {
            try process.run()
        } catch {
            errors.fileHandleForReading.readabilityHandler = nil
            status = "Could not start Snow RAM read. \(error.localizedDescription)"
            return
        }
        ramReadProcess = process
        hardwareRAMProgress = 0
        busy = true
        status = "Reading custom RAM banks from the Snow…"
        Task {
            defer {
                ramReadProcess = nil
                hardwareRAMProgress = nil
                busy = false
                if followSnow && editTarget == 64 && connectedSnowID() == deviceID {
                    startPanelMonitor()
                }
            }
            let data = await Task.detached(priority:.utility) {
                let data = output.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                return data
            }.value
            guard ramReadProcess === process else {
                status = "Snow RAM read cancelled."
                return
            }
            guard process.terminationStatus == 0 else {
                status = "Could not read all Snow RAM sounds. Reconnect the Snow to try again."
                return
            }
            guard connectedSnowID() == deviceID, data.count == Self.snowRAMSoundCount * 524 else {
                status = "Snow RAM read did not return a complete library."
                return
            }
            var presets: [FactoryPreset] = []
            for slot in 0..<Self.snowRAMSoundCount {
                let frame = Array(data[(slot * 524)..<((slot + 1) * 524)])
                let bank = slot / 128 + 1
                let program = slot % 128
                guard PresetPacket.valid(frame), Int(frame[7]) == bank, Int(frame[8]) == program else {
                    status = "Snow RAM read returned an invalid preset."
                    return
                }
                let name = String(bytes:frame[249...258], encoding:.ascii)?.trimmingCharacters(in:.whitespaces) ?? "Unnamed"
                let hash = SHA256.hash(data:Data(frame)).map { String(format:"%02x",$0) }.joined()
                let firstRAMBank = bank * 2 - 1
                presets.append(FactoryPreset(id:factory.count + slot, name:name, file:"Snow RAM/RAM \(firstRAMBank)+\(firstRAMBank + 1)",
                                             bank:bank, program:program, format:"VirusTI_Singledump", sha256:hash))
            }
            hardwareRAMFrames = data
            hardwareRAM = presets
            status = "Read \(presets.count) custom RAM sounds from the Snow."
        }
    }

    func refreshFromSnow() {
        guard followSnow, editTarget == 64, !busy,
              patchRefreshPending || (pendingPath == nil && !frontPanelValues.isEmpty),
              ProcessInfo.processInfo.systemUptime - lastFrontPanelChange >= 0.35 else { return }
        patchRefreshPending = false
        let arguments = usingDirectUSB ? ["--usb-read-current", "--json"] : ["--read-current", "64"]
        perform(arguments:arguments, bank:0, program:64, writingCutoff:false,
                followingSnow:true, directUSB:usingDirectUSB)
    }

    func canLoadFactory(target: Int) -> Bool {
        target == 64 && editTarget == target && packet.count == 524 && !busy && pendingPath == nil
            && selectedFactoryPreset?.canLoad == true
    }

    func factoryFrame(_ preset: FactoryPreset) -> Data? {
        guard preset.canLoad else { return nil }
        let frames = preset.isHardwareRAM ? hardwareRAMFrames : factoryFrames
        let start = (preset.isHardwareRAM ? preset.id - factory.count : preset.id) * 524
        guard start >= 0, start + 524 <= frames.count else { return nil }
        let frame = frames.subdata(in: start..<(start + 524))
        guard PresetPacket.valid(Array(frame)), SHA256.hash(data: frame).map({ String(format: "%02x", $0) }).joined() == preset.sha256 else {
            return nil
        }
        return frame
    }

    func loadFactory(target: Int) {
        guard canLoadFactory(target: target), let preset = selectedFactoryPreset else { return }
        guard let frame = factoryFrame(preset) else {
            status = "Factory preset data failed validation"; return
        }
        let snapshot = SHA256.hash(data: Data(packet)).map { String(format: "%02x", $0) }.joined()
        let command = usingDirectUSB ? "--usb-load-factory-single" : "--load-factory-single"
        perform(arguments: [command, frame.base64EncodedString(), snapshot],
                bank: 0, program: target, writingCutoff: false, loadingFactory: preset.name, directUSB:usingDirectUSB)
    }

    func applyCutoff() {
        applyParameter("Filter 1/Cutoff",value:Int(cutoffValue))
    }

    private func perform(arguments: [String], bank: Int, program: Int, writingCutoff: Bool, editedPath:String?=nil, undoing:Bool=false, loadingFactory:String?=nil, followingSnow:Bool=false, directUSB:Bool=false, onCompletion: (() -> Void)? = nil) {
        guard !busy else { return }
        guard let helper = Bundle.main.url(forAuxiliaryExecutable: "virus-identity-probe") else {
            status = "The MIDI helper is missing from the app bundle"
            onCompletion?()
            return
        }
        stopUSBMonitor()
        let before = editedPath.flatMap { rawValue($0) }
        let revisionAtRead = frontPanelRevision
        followingRead = followingSnow
        if !followingSnow { frontPanelValues.removeAll() }
        if !writingCutoff && !followingSnow { undoChange = nil }
        busy = true
        if let loadingFactory {
            status = "Checking current sound before loading \(loadingFactory)…"
        } else if directUSB && !followingSnow && !writingCutoff {
            status = "Reading Single edit buffer over direct USB…"
        } else if !followingSnow {
            status = writingCutoff ? "Checking current sound, applying parameter, and reading back…" : "Reading bank \(bank), program \(program)…"
        }
        Task {
            let outcome = await Task.detached(priority: .userInitiated) { () -> Result<Data, Error> in
                do {
                    let process = Process(); let output = Pipe(); let errors = Pipe()
                    process.executableURL = helper; process.arguments = arguments
                    process.standardOutput = output; process.standardError = errors
                    try process.run()
                    // Drain stdout while the helper runs so a bounded large capture cannot fill its pipe.
                    let data = output.fileHandleForReading.readDataToEndOfFile()
                    process.waitUntilExit()
                    guard !data.isEmpty else {
                        let errorData = errors.fileHandleForReading.readDataToEndOfFile()
                        throw NSError(domain: "Browser", code: 3, userInfo: [NSLocalizedDescriptionKey: String(decoding: errorData, as: UTF8.self)])
                    }
                    return .success(data)
                } catch { return .failure(error) }
            }.value
            defer {
                followingRead = false
                busy = false
                onCompletion?()
                if !busy && followSnow && editTarget == 64 && usbMonitor == nil && panelMonitor == nil {
                    startPanelMonitor()
                }
            }
            if followingSnow && (!followSnow || editTarget != program) { return }
            do {
                let data = try outcome.get()
                let report = try JSONSerialization.jsonObject(with: data) as? [String:Any] ?? [:]
                if followingSnow {
                    if try accept(report, source:"Snow front panel sync", bank:bank, program:program, onlyIfChanged:true) {
                        undoChange = nil
                        status = "Synced from Snow — \(patchName), checksums verified"
                    }
                    if revisionAtRead == frontPanelRevision { frontPanelValues.removeAll() }
                    return
                }
                let readSource = directUSB ? "Direct USB read" : "Live read verified — \(Date().formatted(date: .omitted, time: .standard))"
                try accept(report, source:readSource, bank:bank, program:program)
                usingDirectUSB = directUSB

                if loadingFactory != nil {
                    status = report["status"] as? String ?? "Factory load result unavailable"
                    if report["factoryLoadVerified"] as? Bool != true { editTarget = nil }
                } else if writingCutoff {
                    let verified = report["parameterWriteVerified"] as? Bool ?? false
                    status = report["status"] as? String ?? "Edit result unavailable"
                    if !verified { editTarget = nil }
                    if verified, let path = editedPath, let old = before, let new = rawValue(path) {
                        undoChange = undoing ? nil : VerifiedEdit(target:program,parameter:path,before:old,after:new)
                        status = "\(path): \(label(path,value:new)) — verified by checksum-valid readback"
                    } else { undoChange = nil }
                } else {
                    let route = directUSB ? " over direct USB" : ""
                    status = "Read \(patchName)\(route) — \(packet.count) bytes, checksums verified"
                }
            } catch {
                editTarget = nil
                if followingSnow { undoChange = nil }
                status = followingSnow
                    ? "Follow Snow paused: \(error.localizedDescription). Read current sound to resume."
                    : "Operation failed: \(error.localizedDescription). Previous capture retained; read again before editing."
            }
        }
    }

    func export() {
        guard !packet.isEmpty else { return }
        let panel = NSSavePanel(); panel.nameFieldStringValue = "Virus-preset.syx"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try Data(packet).write(to: url, options: .atomic); status = "Exported \(url.lastPathComponent)" }
        catch { status = "Export failed: \(error.localizedDescription)" }
    }

    func verifyOfflineEditRules() {
        liveMode = false
        precondition(editable.count == 307)
        precondition(editable["Global Master/Mode"] == nil)
        var fixture = [UInt8](repeating: 0, count: 524)
        fixture[0..<7] = [0xf0, 0, 0x20, 0x33, 1, 0x10, 0x10]
        fixture[249...258] = Array("Test Patch".utf8)[...]
        fixture[523] = 0xf7
        func repair(_ bytes:inout [UInt8]) {
            bytes[265] = UInt8(bytes[5...264].reduce(0, { $0+Int($1) }) & 127)
            bytes[522] = UInt8(bytes[5...521].reduce(0, { $0+Int($1) }) & 127)
        }
        fixture[7] = 0; fixture[8] = 64; fixture[176] = 0; repair(&fixture)
        precondition(editable["Filter 1/Cutoff"]!.active(in:fixture))
        fixture[176] = 1; repair(&fixture)
        precondition(!editable["Filter 1/Cutoff"]!.active(in:fixture))
        fixture[176] = 0; fixture[296] = 0; fixture[155] = 0; repair(&fixture)
        precondition(editable["Oscillator 1/Shape"]!.active(in:fixture))
        precondition(editable["LFO 1/Rate"]!.active(in:fixture))
        fixture[296] = 1; fixture[155] = 1; repair(&fixture)
        precondition(!editable["Oscillator 1/Shape"]!.active(in:fixture))
        precondition(!editable["LFO 1/Rate"]!.active(in:fixture))
        fixture[169] = 1; repair(&fixture)
        precondition(!editable["Filter 2/Cutoff"]!.active(in:fixture))
        precondition(editable["Filter 2/Offset for FilterLink"]!.active(in:fixture))
        let matrixSource = editable["Assign Slot 1/Source"]!, matrixDestination = editable["Assign Slot 1/Destination 1"]!
        fixture[matrixSource.offset] = 0; repair(&fixture)
        precondition(!matrixDestination.active(in:fixture))
        fixture[matrixSource.offset] = 1; repair(&fixture)
        precondition(matrixDestination.active(in:fixture))
        let reverbSend = editable["Reverb/Send"]!, reverbTime = editable["Reverb/Time"]!
        fixture[reverbSend.offset] = 0; repair(&fixture)
        precondition(!reverbTime.active(in:fixture))
        fixture[reverbSend.offset] = 64; repair(&fixture)
        precondition(reverbTime.active(in:fixture))
        let delayClock = editable["Delay/Clock"]!, delayTime = editable["Delay/Time"]!
        fixture[editable["Delay/Type"]!.offset] = 0
        fixture[editable["Delay/Send"]!.offset] = 64
        fixture[editable["Delay/Mode"]!.offset] = 14
        fixture[delayClock.offset] = 5
        repair(&fixture)
        precondition(!delayClock.active(in:fixture) && !delayTime.active(in:fixture))
        fixture[editable["Delay/Mode"]!.offset] = 1
        repair(&fixture)
        precondition(delayClock.active(in:fixture) && !delayTime.active(in:fixture))
        fixture[delayClock.offset] = 0
        repair(&fixture)
        precondition(delayClock.active(in:fixture) && delayTime.active(in:fixture))
        let arpMode = editable["Arpeggiator/Mode"]!, arpLength = editable["Arpeggiator/NoteLength"]!
        fixture[arpMode.offset] = 0; repair(&fixture)
        precondition(!arpLength.active(in:fixture))
        fixture[arpMode.offset] = 1; repair(&fixture)
        precondition(arpLength.active(in:fixture))
        fixture[arpMode.offset] = 7; repair(&fixture)
        precondition(!arpLength.active(in:fixture))
        let report:[String:Any] = ["receivedSysExHex":[fixture.map { String(format:"%02X",$0) }.joined(separator:" ")]]
        try! accept(report,source:"Offline self-test fixture",bank:0,program:64)
        precondition(patchName == "Test Patch" && rows.count > 300)
        var corrupt = packet
        corrupt[30] ^= 1
        precondition(!PresetPacket.valid(corrupt))
        let unchanged = packet
        stage("Filter 1/Resonance",value:33)
        precondition(pendingPath == "Filter 1/Resonance" && pendingValue == 33 && packet == unchanged)
        discardDraft(); precondition(pendingPath == nil && packet == unchanged)
        print("PASS: 307 allowlisted edits, vocoder/oscillator/clock/link/matrix/reverb/arpeggiator guards, draft/discard leaves packet unchanged; no MIDI traffic")
    }
}

struct BrowserView: View {
    @ObservedObject var model: BrowserModel
    @State private var bank = 1
    @State private var program = 0
    @State private var parameterSearch = ""
    @State private var factorySearch = ""
    @State private var snowOnly = true
    @State private var selectedFactory: Int?
    @State private var currentMode = false
    @State private var selectedEditTarget = 64
    private var shownFactory: [FactoryPreset] {
        model.presetLibrary.filter { p in
            (!snowOnly || p.file.contains("Snow")) && (factorySearch.isEmpty || (p.name + " " + p.file).localizedCaseInsensitiveContains(factorySearch))
        }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Virus TI Browser").font(.largeTitle.bold())
                    Text("Apple Silicon preview · preset browser and current-sound editing").foregroundStyle(.secondary)
                }
                Spacer()
                Label("No preset-memory writes", systemImage: "lock.shield").foregroundStyle(.green)
            }
            if !model.resourceError.isEmpty { Text(model.resourceError).foregroundStyle(.red) }
            TabView {
                VStack(alignment: .leading, spacing: 12) {
                    HStack(spacing: 18) {
                        Picker("Source", selection: $currentMode) { Text("Stored").tag(false); Text("Current sound").tag(true) }
                            .pickerStyle(.segmented).frame(width: 230)
                        if currentMode {
                            Picker("Buffer", selection: $selectedEditTarget) {
                                Text("Single mode").tag(64)
                                ForEach(0..<4) { part in Text("Multi / Part \(part+1)").tag(part) }
                            }.frame(width: 190)
                        } else {
                            Stepper("Bank \(bank)", value: $bank, in: 1...127).frame(width: 120)
                            Stepper("Program \(program)", value: $program, in: 0...127).frame(width: 135)
                        }
                        Button(currentMode ? "Read current sound" : "Read from Snow") {
                            if !currentMode { model.read(bank: bank, program: program) }
                            else if selectedEditTarget == 64 { model.readCurrentViaUSB() }
                            else { model.readCurrent(target: selectedEditTarget) }
                        }.disabled(model.busy).keyboardShortcut("r", modifiers: .command)
                        if model.busy && !model.readingHardwareRAM { ProgressView().controlSize(.small) }
                        Spacer()
                        Button("Export .syx…") { model.export() }.disabled(model.packet.isEmpty || model.busy)
                    }
                    Text(currentMode ? "Choose the synth’s existing mode and part. This selector does not switch the synth’s mode. Read before editing." : "Bank/program use protocol numbering. Reading does not load the sound. The Stored view uses the CoreMIDI Plugin I/O port.")
                        .font(.caption).foregroundStyle(.secondary)
                    if currentMode {
                        GroupBox("Filter 1 cutoff · current edit buffer") {
                            VStack(alignment: .leading, spacing: 8) {
                                HStack {
                                    Slider(value: Binding(get:{model.frontPanelCutoff},set:{ value in
                                        if model.liveMode && !model.liveEditing { model.beginLive("Filter 1/Cutoff") }
                                        model.stage("Filter 1/Cutoff",value:Int(value))
                                    }), in: 0...127, step: 1, onEditingChanged:{ editing in
                                        if editing && model.liveMode { model.beginLive("Filter 1/Cutoff") }
                                        if !editing { model.finishLive() }
                                    })
                                    Text(String(Int(model.frontPanelCutoff))).monospacedDigit().frame(width: 35)
                                    if !model.liveMode { Button("Apply cutoff") { model.applyCutoff() } }
                                }.disabled((model.busy && !model.liveEditing) || model.editTarget != selectedEditTarget || model.packet.count <= 176 || model.packet[176] != 0)
                                Text(model.liveMode ? "Live cutoff updates while dragging and verifies on release. No Store command is sent." : "Apply changes the current sound only, then reads it back. No Store command is sent.")
                                    .font(.caption).foregroundStyle(.secondary)
                            }.padding(6)
                        }
                    }
                    Divider()
                    HStack {
                        Text(model.patchName).font(.title2.bold())
                        Text("Bank \(model.currentBank) · Program \(model.currentProgram)").foregroundStyle(.secondary)
                        Spacer()
                        Text("\(model.rows.count) mapped fields").foregroundStyle(.secondary)
                    }
                    Text(model.source).font(.caption).foregroundStyle(.secondary)
                    TextField("Filter decoded parameters", text: $parameterSearch).textFieldStyle(.roundedBorder)
                    Table(model.rows.filter { parameterSearch.isEmpty || $0.path.localizedCaseInsensitiveContains(parameterSearch) }) {
                        TableColumn("Parameter", value: \.path).width(min: 350, ideal: 520)
                        TableColumn("Mapped value", value: \.value)
                        TableColumn("Raw byte", value: \.raw).width(70)
                    }
                    Text("Conditional aliases are listed together. Numeric values are raw preset data; not every visibility rule or display conversion is implemented.")
                        .font(.caption).foregroundStyle(.secondary)
                }.padding().tabItem { Label("Hardware preset", systemImage: "pianokeys") }
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        TextField("Search preset names or collections", text: $factorySearch).textFieldStyle(.roundedBorder)
                        Toggle("Snow collections", isOn: $snowOnly).toggleStyle(.checkbox)
                    }
                    Text("\(shownFactory.count) matching records · \(model.presetLibrary.count) records across all collections. Sounds may be duplicated.")
                        .font(.caption).foregroundStyle(.secondary)
                    Table(Array(shownFactory.prefix(500)), selection: $selectedFactory) {
                        TableColumn("Preset", value: \.name).width(min: 140, ideal: 200)
                        TableColumn("Collection", value: \.file).width(min: 350, ideal: 600)
                        TableColumn("Program") { Text(String($0.program)) }.width(70)
                    }
                    Text("Showing up to 500 matches from Snow RAM and the factory catalogue. Selecting a row sends nothing to the synth.")
                        .font(.caption).foregroundStyle(.secondary)
                }.padding().tabItem { Label("Preset catalogue", systemImage: "square.stack") }
            }
            HStack {
                if let progress = model.hardwareRAMProgress {
                    ProgressView(value: Double(progress), total: Double(BrowserModel.snowRAMSoundCount)) {
                        Text("Reading custom Snow RAM")
                    } currentValueLabel: {
                        Text(model.hardwareRAMProgressLabel).monospacedDigit()
                    }.frame(width: 280)
                    Button("Cancel RAM Read") { model.cancelHardwareRAMRead() }
                } else {
                    Text(model.status).font(.callout).textSelection(.enabled)
                }
                Spacer()
                Text("Preview 0.7.2").font(.caption).foregroundStyle(.secondary)
            }
        }.padding(24).frame(minWidth: 1120, minHeight: 760)
            .onChange(of: currentMode) { _ in model.editTarget = nil }
            .onChange(of: selectedEditTarget) { _ in model.editTarget = nil }
    }
}

@main
struct VirusBrowserApp: App {
    init() {
        if CommandLine.arguments.contains("--self-test") {
            let model = BrowserModel()
            precondition(model.resourceError.isEmpty, model.resourceError)
            precondition(model.packet.isEmpty)
            let loadable = model.factory.filter(\.canLoad)
            precondition(!loadable.isEmpty)
            precondition(loadable.allSatisfy { model.factoryFrame($0) != nil })
            let original = try! OriginalUIData()
            let panel = SnowPanelMessages()
            var events: [[Int]] = []
            let bytes: [UInt8] = [0xb0, 9, 0x43, 0xc0, 0xf8, 4,
                                  0xf0, 0, 0x20, 0x33, 1, 0, 0x73, 64, 0x10, 1, 0xf7]
            for byte in bytes {
                panel.receive(byte) { page, controller, value in
                    events.append([Int(page), Int(controller), value])
                }
            }
            precondition(events == [[0x70, 9, 0x43], [0xc0, 0, 4], [0x73, 0x10, 1]])
            precondition(original.root["width"] as? Int == 907 && original.root["height"] as? Int == 513)
            precondition(!original.conditions.isEmpty)
            precondition((original.root["missingImages"] as? [String])?.isEmpty == true)
            print("PASS: local catalogue, Snow preset checksums, UI resources and MIDI parser; no MIDI traffic")
            model.verifyOfflineEditRules()
            exit(0)
        }
    }
    var body: some Scene {
        WindowGroup("Virus TI Browser 0.7.2") { MainInterface() }
            .defaultSize(width: 1180, height: 800)
    }
}
