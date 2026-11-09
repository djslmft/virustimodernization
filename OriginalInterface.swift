import AppKit
import SwiftUI

// Draws the supplied Snow editor layout; no original executable code is loaded.
final class OriginalUIData {
    let root: [String:Any]
    let resourceURL: URL
    let defaults: [String:Int]
    let parameters: [String:[String:Any]]
    let conditions: [String:[String:Any]]
    let valueLists: [String:[String:String]]
    let frame: [String:Any]
    init() throws {
        guard let url = Bundle.main.url(forResource: "layout", withExtension: "json", subdirectory: "original-ui") else {
            throw NSError(domain: "OriginalUI", code: 1, userInfo: [NSLocalizedDescriptionKey: "Original UI assets are missing"])
        }
        resourceURL = url.deletingLastPathComponent()
        root = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String:Any] ?? [:]
        defaults = root["defaults"] as? [String:Int] ?? [:]
        parameters = root["parameters"] as? [String:[String:Any]] ?? [:]
        conditions = root["conditions"] as? [String:[String:Any]] ?? [:]
        let lists = root["valueLists"] as? [String:[String:Any]] ?? [:]
        // Null entries in the original layout represent blank text fields.
        valueLists = lists.mapValues { $0.mapValues { $0 as? String ?? "" } }
        frame = root["frame"] as? [String:Any] ?? [:]
    }
}

@MainActor
final class OriginalCanvas: NSView {
    override var isFlipped: Bool { true }
    var model: BrowserModel?
    var data: OriginalUIData?
    // These are renderer states, not a claim that an original Access driver session exists.
    private var ui: [String:Int] = ["VirusControl/SelectedPage":3, "SystemStatus/Error":0,
                                  "Internal System Info/Display Welcome Page":0]
    private var images: [String:CGImage] = [:]
    private var sprites: [String:NSImage] = [:]
    private var hits: [(rect:NSRect, parameter:String, value:Int?, type:String)] = []
    private var tips: [NSView.ToolTipTag:(path:String, local:Bool, soundControl:Bool, unavailable:Bool)] = [:]
    private var dragStart: (point:NSPoint, value:Double, path:String, minimum:Int, maximum:Int, horizontal:Bool, inverse:Bool)?
    private var browserFiles: [Int:String] = [:]
    private var browserOffsets: [Int:Int] = [:]
    private var selectedPreset: [Int:Int] = [:]
    private var searchText = ""
    private var searchFocused = false
    private var searchSelectAll = false
    override var acceptsFirstResponder: Bool { true }
    private var scale: CGFloat { min(bounds.width / 907, bounds.height / 513) }
    private var origin: NSPoint { NSPoint(x:(bounds.width-907*scale)/2,y:(bounds.height-513*scale)/2) }

    private var singleMode = true

    func configure(_ model: BrowserModel, singleMode: Bool) {
        self.model = model
        self.singleMode = singleMode
        if data == nil { data = try? OriginalUIData() }
        setAccessibilityElement(model.readingHardwareRAM)
        if model.readingHardwareRAM {
            setAccessibilityRole(.staticText)
            setAccessibilityLabel("Reading custom Snow RAM. \(model.hardwareRAMProgressLabel)")
        } else {
            setAccessibilityLabel("Original Virus Control Snow interface. Read current sound, then adjust an active control. Live mode streams changes while dragging and verifies on release. Staged editing is optional.")
        }
        needsDisplay = true
    }

    private func raw(_ path:String) -> Int? {
        if path == "VirusControl/InitialSyncProgress", let progress = model?.hardwareRAMProgress {
            // The original layout reserves 127 for leaving the sync page.
            return progress * 126 / BrowserModel.snowRAMSoundCount
        }
        if let override = ui[path] { return override }
        if path == "Multi Parameters/Panel Part" { return model?.editTarget == 64 ? 0 : model?.editTarget ?? 0 }
        if let value = model?.displayValue(path) { return value }
        return data?.defaults[path]
    }

    private func visible(_ condition:String?) -> Bool {
        guard let condition, !condition.isEmpty else { return true }
        guard let c = data?.conditions[condition], let tests = c["tests"] as? [[String:String]], !tests.isEmpty else { return false }
        let results: [Bool?] = tests.map { t in
            guard let p = t["param"], let value = raw(p), let minimum = Int(t["minvalue"] ?? ""), let maximum = Int(t["maxvalue"] ?? "") else { return nil }
            switch t["type"] {
            case "equals", "equal": return value == minimum
            case "inside": return value >= minimum && value <= maximum
            case "outside": return value < minimum || value > maximum
            default: return nil
            }
        }
        // Unknown conditions are hidden rather than guessed, including inverted conditions.
        guard results.allSatisfy({ $0 != nil }) else { return false }
        var result = c["operand"] as? String == "and" ? results.allSatisfy({ $0 == true }) : results.contains(where: { $0 == true })
        if c["result"] as? String == "invert" { result.toggle() }
        return result
    }

    private func image(_ name:String) -> CGImage? {
        if let value = images[name] { return value }
        guard let url = data?.resourceURL.appendingPathComponent(name), let source = NSImage(contentsOf: url), let cg = source.cgImage(forProposedRect:nil,context:nil,hints:nil) else { return nil }
        images[name] = cg; return cg
    }

    private func sprite(_ name:String, width:CGFloat, height:CGFloat, index:Int) -> NSImage? {
        guard width > 0, height > 0, let source = image(name) else { return nil }
        let w = min(Int(width),source.width), h = min(Int(height),source.height)
        let count = max(1, source.height/h)
        let frame = min(max(0,index),count-1)
        let key = "\(name)|\(w)|\(h)|\(frame)"
        if let value = sprites[key] { return value }
        guard let cropped = source.cropping(to: CGRect(x:0,y:frame*h,width:w,height:h)) else { return nil }
        let result = NSImage(cgImage:cropped,size:NSSize(width:w,height:h)); sprites[key] = result
        return result
    }

    private func text(_ value:String, in rect:NSRect, attributes:[String:String], fontSize: CGFloat = 8) {
        guard !value.isEmpty, attributes["Align"] != "No Label", rect.width > 0, rect.height > 0 else { return }
        let fontName = attributes["ControlFont"] ?? ""
        let color: NSColor
        if fontName.contains("White") {
            color = .white
        } else if fontName.contains("Blau") {
            color = NSColor(srgbRed:0.94, green:0.94, blue:0.94, alpha:1)
        } else if fontName.contains("Rot") {
            color = NSColor(srgbRed:0, green:0.14, blue:0.32, alpha:1)
        } else {
            color = .black
        }
        let paragraph = NSMutableParagraphStyle()
        paragraph.lineBreakMode = .byTruncatingTail
        paragraph.alignment = .center
        let font = NSFont.monospacedSystemFont(ofSize:min(fontSize, rect.height * 0.86), weight:.medium)
        let lineHeight = font.ascender - font.descender + font.leading
        let line = NSRect(x:rect.minX, y:rect.midY - lineHeight / 2, width:rect.width, height:lineHeight)
        NSGraphicsContext.saveGraphicsState()
        NSBezierPath(rect:rect).addClip()
        (value as NSString).draw(in:line, withAttributes:[
            .font:font, .foregroundColor:color, .paragraphStyle:paragraph
        ])
        NSGraphicsContext.restoreGraphicsState()
    }

    private func drawRotaryKnob(in rect: NSRect, artwork: String, position: CGFloat?) {
        let hasRing = artwork.hasPrefix("KNB_Ind_")
        let radius = rect.width * (hasRing ? 0.36 : 0.40)
        let center = NSPoint(x:rect.midX, y:rect.midY)
        let dial = NSBezierPath(ovalIn:NSRect(x:center.x - radius, y:center.y - radius,
                                               width:radius * 2, height:radius * 2))
        let angle = position.map { 135 + 270 * $0 }
        if hasRing {
            let track = NSBezierPath(ovalIn:rect.insetBy(dx:1.5, dy:1.5))
            NSColor(calibratedWhite:0.19, alpha:1).setFill()
            track.fill()
            if let angle {
                let start: CGFloat = artwork.contains("Bip") ? 270 : 135
                let arc = NSBezierPath()
                arc.appendArc(withCenter:center, radius:rect.width * 0.43,
                              startAngle:min(start, angle), endAngle:max(start, angle))
                arc.lineWidth = 1.8
                arc.lineCapStyle = .round
                NSColor(srgbRed:0.42, green:0.72, blue:0.98, alpha:1).setStroke()
                arc.stroke()
            }
        }
        NSGradient(starting:NSColor(calibratedWhite:0.59, alpha:1),
                   ending:NSColor(calibratedWhite:0.28, alpha:1))?.draw(in:dial, angle:90)
        dial.lineWidth = 0.9
        NSColor(calibratedWhite:0.15, alpha:1).setStroke()
        dial.stroke()

        guard let angle else { return }
        let radians = angle * .pi / 180
        let direction = NSPoint(x:cos(radians), y:sin(radians))
        let mark = NSBezierPath()
        mark.move(to:NSPoint(x:center.x + direction.x * radius * 0.25,
                             y:center.y + direction.y * radius * 0.25))
        mark.line(to:NSPoint(x:center.x + direction.x * radius * 0.81,
                             y:center.y + direction.y * radius * 0.81))
        mark.lineWidth = max(1.1, radius * 0.12)
        mark.lineCapStyle = .round
        NSColor(calibratedWhite:0.94, alpha:1).setStroke()
        mark.stroke()
    }

    private func drawEnvelope(_ attackPath: String, in rect: NSRect) {
        let group = String(attackPath.dropLast("/Attack".count))
        let values = ["Attack", "Decay", "Sustain", "Sustain Time", "Release"].compactMap {
            model?.displayValue(group + "/" + $0)
        }
        guard values.count == 5 else { return }

        // The graph shows the relative shape. Its horizontal scale is not calibrated in seconds.
        let plot = rect.insetBy(dx: 9, dy: 9)
        let duration: (Int) -> CGFloat = { 3 + CGFloat($0) / 127 * plot.width * 0.23 }
        let height: (CGFloat) -> CGFloat = { plot.maxY - $0 * plot.height }
        let attackEnd = plot.minX + duration(values[0])
        let decayEnd = attackEnd + duration(values[1])
        let sustainEnd = decayEnd + plot.width * 0.22
        let sustain = CGFloat(values[2]) / 127
        let slope = values[3] - 64
        let sustainTail = slope < 0
            ? sustain * (1 + CGFloat(slope) / 64)
            : sustain + (1 - sustain) * CGFloat(slope) / 63

        let curve = NSBezierPath()
        curve.move(to: NSPoint(x: plot.minX, y: height(0)))
        curve.line(to: NSPoint(x: attackEnd, y: height(1)))
        curve.line(to: NSPoint(x: decayEnd, y: height(sustain)))
        curve.line(to: NSPoint(x: sustainEnd, y: height(sustainTail)))
        curve.line(to: NSPoint(x: sustainEnd + duration(values[4]), y: height(0)))
        NSColor(srgbRed: 182.0 / 255, green: 200.0 / 255, blue: 228.0 / 255, alpha: 1).setStroke()
        curve.lineWidth = 1.5
        curve.stroke()
    }

    private func drawFilterResponse(_ type: String, cutoffPath: String, in rect: NSRect) {
        let group = String(cutoffPath.prefix(while: { $0 != "/" }))
        guard let value = model?.displayValue(cutoffPath),
              let resonance = model?.displayValue(group + "/Resonance") else { return }
        var cutoff = value
        if cutoffPath == "Filter 2/Offset for FilterLink" {
            guard let firstCutoff = model?.displayValue("Filter 1/Cutoff") else { return }
            cutoff = min(127, max(0, firstCutoff + value - 64))
        }

        // Illustrative response in knob units. The synth's DSP is not measured here.
        let plot = rect.insetBy(dx: 3, dy: 4)
        let center = Double(cutoff) / 127
        let q = 0.707 + 3 * Double(resonance) / 127
        let curve = NSBezierPath()
        for sample in 0...80 {
            let x = Double(sample) / 80
            let ratio = pow(2, (x - center) * 8)
            let squared = ratio * ratio
            let denominator = hypot(1 - squared, ratio / q)
            let numerator: Double
            switch type {
            case "LP4Response": numerator = 1
            case "HP4Response": numerator = squared
            case "BP4Response": numerator = ratio / q
            default: numerator = abs(1 - squared)
            }
            let decibels = 40 * log10(max(numerator / denominator, 0.0001))
            let level = min(1, max(0, (decibels + 42) / 56))
            let point = NSPoint(x: plot.minX + x * plot.width, y: plot.maxY - level * plot.height)
            if sample == 0 { curve.move(to: point) } else { curve.line(to: point) }
        }
        NSColor(srgbRed: 0, green: 25.0 / 255, blue: 65.0 / 255, alpha: 1).setStroke()
        curve.lineWidth = 1.5
        curve.stroke()
    }

    private func collection(_ pane:Int) -> String {
        let library = model?.presetLibrary ?? []
        if let file = browserFiles[pane], library.contains(where: { $0.file == file }) { return file }
        if pane == 0, let ram = model?.hardwareRAM.first?.file { return ram }
        let files = Array(Set(library.map(\.file))).sorted()
        return files.first(where: { $0.contains("Snow Factory Backup/\(pane == 0 ? "Ram" : "Rom")/") }) ?? files.first ?? ""
    }

    private func catalogue(_ pane:Int) -> [FactoryPreset] {
        let file = collection(pane)
        return (model?.presetLibrary ?? []).filter { $0.file == file && (searchText.isEmpty || $0.name.localizedCaseInsensitiveContains(searchText)) }
    }

    private func drawCatalogue(_ pane:Int, rect:NSRect) {
        let records = catalogue(pane), offset = min(browserOffsets[pane] ?? 0,max(0,records.count-128))
        NSColor(calibratedWhite:0.085,alpha:1).setFill(); rect.insetBy(dx:1,dy:1).fill()
        let columnWidth = rect.width/8
        for column in 0..<8 {
            for row in 0..<16 {
                let index = offset + column*16 + row
                let cell = NSRect(x:rect.minX+CGFloat(column)*columnWidth+3,y:rect.minY+4+CGFloat(row)*10.5,width:columnWidth-4,height:10.5)
                NSColor(calibratedWhite:0.085,alpha:1).setFill(); cell.fill()
                guard index < records.count else { continue }
                let record = records[index]
                if selectedPreset[pane] == record.id { NSColor(calibratedRed:0.18,green:0.30,blue:0.42,alpha:1).setFill(); cell.fill() }
                let a = ["ControlFont":"FNT_LCD_5x7_White_75.png"]
                text(record.name,in:cell.insetBy(dx:1,dy:0),attributes:a)
            }
        }
        hits.append((rect,"__catalogue_\(pane)",nil,"Catalogue"))
    }

    override func draw(_ dirtyRect: NSRect) {
        NSColor(calibratedWhite:0.19,alpha:1).setFill(); bounds.fill()
        guard let data else {
            text("Original interface assets unavailable", in:bounds, attributes:["ControlFont":"White"])
            return
        }
        hits = []; tips = [:]; removeAllToolTips()
        NSGraphicsContext.saveGraphicsState()
        let transform = NSAffineTransform(); transform.translateX(by:origin.x,yBy:origin.y); transform.scale(by:scale); transform.concat()
        NSGraphicsContext.current?.imageInterpolation = .high
        for child in data.frame["children"] as? [[String:Any]] ?? [] { drawNode(child,offset:.zero,part:-1) }
        if model?.readingHardwareRAM == true {
            hits = []; tips = [:]; removeAllToolTips()
        }
        NSGraphicsContext.restoreGraphicsState()
    }

    private func drawNode(_ node:[String:Any], offset:NSPoint, part:Int, inactive: Bool = false, dimPart: Bool = false) {
        let a = node["attributes"] as? [String:String] ?? [:]
        guard visible(a["Condition"]) else { return }
        let s = node["size"] as? [String:String] ?? [:]
        let rect = NSRect(x:offset.x + CGFloat(Double(s["left"] ?? "0") ?? 0),y:offset.y + CGFloat(Double(s["top"] ?? "0") ?? 0),width:CGFloat(Double(s["width"] ?? "0") ?? 0),height:CGFloat(Double(s["height"] ?? "0") ?? 0))
        let type = node["type"] as? String ?? ""
        let path = a["Parameter"] ?? ""
        let isSoftKnob = path.hasPrefix("Softknobs/Softknob ")
        let ownPart = Int(a["Part"] ?? "-1") ?? -1
        // In the original layout -1 means the selected part, not the parent's part 0.
        let thisPart = a["Part"] == nil ? part : ownPart
        let activePart = model?.editTarget == 64 ? 0 : model?.editTarget ?? 0
        var name = a["NormalBack"] ?? ""
        let definition = data?.parameters[path] ?? [:]
        let local = ["VirusControl/SelectedPage","VirusControl/Selected Section","VirusControl/SelectedUtilityPage","Envelope/Select"].contains(path)
        let bankMenu = path.hasPrefix("Browser ") && path.hasSuffix("/Selected Bank")
        let parameterControl = type.contains("Knob") || type.contains("Slider") ||
            ["RadioButton","Button","Menu","HierarchicMenu"].contains(type)
        let conditionApplies = visible(definition["condition"] as? String)
        let editableInPart = model.map {
            $0.editTarget != nil && (thisPart < 0 || thisPart == activePart) &&
                $0.editable[path]?.active(in:$0.packet) == true
        } ?? false
        let unavailable = !path.isEmpty && parameterControl && !local && !bankMenu && !isSoftKnob &&
            (!conditionApplies || (a["Enabled"] != "false" && !editableInPart))
        let dimContext = unavailable && !inactive ? NSGraphicsContext.current?.cgContext : nil
        dimContext?.saveGState()
        dimContext?.setAlpha(0.4)
        dimContext?.beginTransparencyLayer(auxiliaryInfo:nil)
        defer {
            dimContext?.endTransparencyLayer()
            dimContext?.restoreGState()
        }
        let value = raw(path) ?? 0
        let valueList = definition["valuelist"] as? String ?? ""
        let artworkLabel = data?.valueLists[valueList]?[String(value)]
        let onValue = Int(a["OnValue"] ?? "")
        let selected = onValue == nil ? value != 0 : value == onValue
        // Each envelope polarity strip stores minus and plus as separate frames.
        let usesPolarityFrames = name == "BTN_Filter_ENV_Pol.png"
        if selected, !usesPolarityFrames, let pressed = a["PressedBack"] { name = pressed }
        if !name.isEmpty, let img = image(name) {
            let frameCount = rect.height > 0 ? max(1,img.height/Int(rect.height)) : 1
            var index = 0
            if type.contains("Knob") || type.contains("Slider") {
                let minimum = Int(definition["minValue"] as? String ?? "0") ?? 0
                let maximum = path == "VirusControl/InitialSyncProgress" ? 126 :
                    Int(definition["maxValue"] as? String ?? "127") ?? 127
                if maximum > minimum { index = Int((Double(value-minimum)/Double(maximum-minimum)*Double(frameCount-1)).rounded()) }
            } else if usesPolarityFrames {
                index = value == 1 ? 1 : 0
            } else if type == "RadioButton" || type == "Button" {
                index = selected && a["PressedBack"] == nil ? 1 : 0
            }
            if type == "Knob", frameCount > 1,
               name == "KNB_Standard.png" || name == "KNB_Klein.png" || name.hasPrefix("KNB_Ind_") {
                let position = CGFloat(min(max(0, index), frameCount - 1)) / CGFloat(frameCount - 1)
                let valueIsUnread = isSoftKnob && model?.displayValue(path) == nil
                drawRotaryKnob(in:rect, artwork:name, position:valueIsUnread ? nil : position)
                if isSoftKnob, let slot = Int(path.suffix(1)),
                   let controllerValue = model?.softKnobControllerValue(slot: slot) {
                    let readout = NSRect(x:rect.minX, y:rect.minY - 14, width:rect.width, height:12)
                    text(String(controllerValue), in:readout, attributes:[:])
                }
            } else if let graphic = sprite(name,width:type == "Menu" ? CGFloat(img.width) : rect.width,
                                           height:rect.height,index:index) {
                graphic.draw(in:rect,from:.zero,operation:.sourceOver,fraction:1,respectFlipped:true,hints:nil)
            }
        }
        if type == "ADSTREnvelope" {
            drawEnvelope(path, in: rect)
        } else if ["LP4Response", "HP4Response", "BP4Response", "BS4Response"].contains(type) {
            drawFilterResponse(type, cutoffPath: path, in: rect)
        } else if type == "PatchBrowser" {
            drawCatalogue(path.contains("Browser 1/") ? 1 : 0,rect:rect)
        } else if type == "SearchEdit" {
            text(searchText.isEmpty ? "Search" : searchText,in:rect,attributes:a)
            hits.append((rect,path,nil,"Search"))
        } else if type == "StaticText" {
            let label = a["Name"] ?? ""
            if label != "StaticText" { text(label,in:rect,attributes:a) }
        } else if type == "NameEdit" {
            text(thisPart < 0 || thisPart == activePart ? model?.patchName ?? "" : "-- unread --",in:rect,attributes:a)
        } else if ["Menu","HierarchicMenu","TextSlider"].contains(type) {
            // These fields belong to the Multi dump, which the Single read does not supply.
            if path.hasPrefix("Multi Part Parameter/pr Output Select Control"),
               model?.rawValue(path) == nil { return }
            var label = model?.rawValue(path) != nil ? model?.label(path,value:value) ?? String(value) :
                artworkLabel ?? (raw(path) == nil ? "" : String(value))
            if unavailable && !conditionApplies { label = "—" }
            if path.hasPrefix("Soft Knobs/Name "), let slot = path.last,
               model?.rawValue("Soft Knobs/Destination \(slot)") == 0 {
                label = "Global"
            }
            if bankMenu {
                let pane = path.contains("Browser 1/") ? 1 : 0
                label = URL(fileURLWithPath:collection(pane)).deletingPathExtension().lastPathComponent
                hits.append((rect,path,nil,"Collection"))
            } else if thisPart >= 0 && thisPart != activePart { label = "--" }
            var labelRect = rect
            // Keep text inside the LCD area and clear of the arrow painted into each menu sprite.
            switch name {
            case "DSP_Menu_2.png":
                let artworkScale = rect.width / 64
                labelRect.origin.x += 5 * artworkScale
                labelRect.size.width = min(rect.width, 45 * artworkScale) - 5 * artworkScale
            case "DSP_Menu.png", "DSP_Menu_3.png":
                let artworkScale = rect.width / 95
                labelRect.origin.x += 3 * artworkScale
                labelRect.size.width = min(rect.width, 81 * artworkScale) - 3 * artworkScale
            default:
                break
            }
            text(label,in:labelRect,attributes:a)
        }
        let soundControl = parameterControl && editableInPart && a["Enabled"] != "false" && !unavailable
        if !inactive && (local || soundControl) { hits.append((rect,path,onValue,type)) }
        if !inactive && !path.isEmpty && rect.width > 5 && rect.height > 5 &&
            (isSoftKnob || artworkLabel != "" || model?.rawValue(path) != nil) {
            let actualRect = NSRect(x:origin.x+rect.minX*scale,y:origin.y+rect.minY*scale,width:rect.width*scale,height:rect.height*scale)
            let tag = addToolTip(actualRect,owner:self,userData:nil)
            tips[tag] = (path, local, soundControl, unavailable)
        }
        for (index, child) in (node["children"] as? [[String:Any]] ?? []).enumerated() {
            // The four children of the Snow's channel panel are ordered by part.
            let dimChannel = singleMode && name == "BG_PR_4_Channels.png" && index > 0
            drawNode(child,offset:rect.origin,part:thisPart,inactive:inactive || dimChannel,dimPart:dimChannel)
        }
        if dimPart {
            NSColor(calibratedWhite:0.17, alpha:0.60).setFill()
            rect.fill()
        }
        if name == "BG_Page_Startup_syncing.png", let model, model.readingHardwareRAM {
            // Cover the original timing estimate with the actual transfer state.
            let message = NSRect(x:rect.minX + 480, y:rect.minY + 169, width:381, height:50)
            let panel = NSBezierPath(roundedRect:message, xRadius:5, yRadius:5)
            NSColor(calibratedWhite:0.21, alpha:1).setFill()
            panel.fill()
            let style = ["ControlFont":"White"]
            text("Reading custom Snow RAM", in:message.insetBy(dx:8, dy:15).offsetBy(dx:0,dy:-9),
                 attributes:style, fontSize:12)
            text(model.hardwareRAMProgressLabel, in:message.insetBy(dx:8, dy:15).offsetBy(dx:0,dy:9),
                 attributes:style, fontSize:11)
        }
    }

    @objc func view(_ view:NSView, stringForToolTip tag:NSView.ToolTipTag, point:NSPoint, userData:UnsafeMutableRawPointer?) -> String {
        guard let tip = tips[tag] else { return "" }
        if tip.path == "VirusControl/Help Menu" { return "Help menu unavailable in this preview" }
        if tip.unavailable { return "\(tip.path) · Unavailable with the current settings" }
        if tip.path.hasPrefix("Softknobs/Softknob "), model?.displayValue(tip.path) == nil {
            return "Soft knob position unavailable"
        }
        let editHint = model?.liveMode == true ? "Live: drag to hear changes; release to verify. Menus apply immediately." : "Adjust to draft a value; Apply change to send"
        let mode = tip.local ? "Page/view selection" : tip.soundControl ? (model?.canEdit(tip.path) == true ? editHint : "Read current sound; parameter must be active in the sound’s mode") : "Read-only display; editing not yet connected"
        let value = raw(tip.path) ?? 0
        return "\(tip.path): \(model?.label(tip.path, value:value) ?? String(value)) — \(mode)"
    }

    override func mouseDown(with event:NSEvent) {
        let p = convert(event.locationInWindow,from:nil)
        let point = NSPoint(x:(p.x-origin.x)/scale,y:(p.y-origin.y)/scale)
        guard let hit = hits.reversed().first(where: { $0.rect.contains(point) }) else { return }
        if hit.type == "Search" {
            searchFocused = true; searchSelectAll = false; window?.makeFirstResponder(self); needsDisplay = true; return
        }
        searchFocused = false
        if hit.type == "Collection" {
            let pane = hit.parameter.contains("Browser 1/") ? 1 : 0
            let menu = NSMenu()
            for file in Array(Set(model?.presetLibrary.map(\.file) ?? [])).sorted() {
                let item = NSMenuItem(title:file,action:#selector(chooseCollection(_:)),keyEquivalent:"")
                item.target = self; item.representedObject = ["pane":pane,"file":file]
                item.state = file == collection(pane) ? .on : .off; menu.addItem(item)
            }
            menu.popUp(positioning:nil,at:p,in:self); return
        }
        if hit.type == "Catalogue" {
            let pane = hit.parameter == "__catalogue_1" ? 1 : 0
            let column = min(7,max(0,Int((point.x-hit.rect.minX)/(hit.rect.width/8))))
            let row = min(15,max(0,Int((point.y-hit.rect.minY-4)/10.5)))
            let records = catalogue(pane), offset = min(browserOffsets[pane] ?? 0,max(0,records.count-128))
            let index = offset+column*16+row
            if index < records.count {
                selectedPreset[pane] = records[index].id
                model?.selectedFactoryPreset = records[index]
                model?.status = records[index].canLoad
                    ? "Selected \(records[index].name) for audition"
                    : "\(records[index].name) is available for browsing"
                needsDisplay = true
            }
            return
        }
        if let model, let parameter = model.editable[hit.parameter] {
            guard model.canEdit(hit.parameter) else { return }
            if hit.type == "RadioButton", let value = hit.value {
                model.stage(hit.parameter,value:value); needsDisplay = true
            } else if ["Menu","HierarchicMenu"].contains(hit.type) || hit.type == "Button" && parameter.maximum-parameter.minimum > 1 {
                let menu = NSMenu()
                for value in parameter.minimum...parameter.maximum {
                    let item = NSMenuItem(title:model.label(hit.parameter,value:value),action:#selector(chooseValue(_:)),keyEquivalent:"")
                    item.target = self; item.representedObject = ["path":hit.parameter,"value":value]
                    item.state = model.displayValue(hit.parameter) == value ? .on : .off; menu.addItem(item)
                }
                menu.popUp(positioning:nil,at:p,in:self)
            } else if hit.type == "Button" {
                let old = model.displayValue(hit.parameter) ?? parameter.minimum
                model.stage(hit.parameter,value:old == parameter.minimum ? parameter.maximum : parameter.minimum); needsDisplay = true
            } else {
                dragStart = (point,Double(model.displayValue(hit.parameter) ?? parameter.minimum),hit.parameter,parameter.minimum,parameter.maximum,hit.type.contains("Horizontal"),hit.type.contains("Inverse"))
                if model.liveMode { model.beginLive(hit.parameter) }
            }
        } else {
            ui[hit.parameter] = hit.value ?? ((raw(hit.parameter) ?? 0) == 0 ? 1 : 0)
            needsDisplay = true
        }
    }

    override func mouseDragged(with event:NSEvent) {
        guard let start = dragStart, let model, !model.busy || model.liveEditing else { return }
        let p = convert(event.locationInWindow,from:nil)
        let point = NSPoint(x:(p.x-origin.x)/scale,y:(p.y-origin.y)/scale)
        let delta = start.horizontal ? point.x-start.point.x : start.point.y-point.y
        let gain = Double(start.maximum-start.minimum)/212
        model.stage(start.path,value:Int((start.value+Double(delta)*gain*(start.inverse ? -1 : 1)).rounded()))
        needsDisplay = true
    }
    override func mouseUp(with event:NSEvent) { model?.finishLive(); dragStart = nil }

    @objc private func chooseValue(_ sender:NSMenuItem) {
        guard let value = sender.representedObject as? [String:Any], let path = value["path"] as? String, let raw = value["value"] as? Int else { return }
        model?.stage(path,value:raw); needsDisplay = true
    }

    @objc private func chooseCollection(_ sender:NSMenuItem) {
        guard let object = sender.representedObject as? [String:Any], let pane = object["pane"] as? Int, let file = object["file"] as? String else { return }
        browserFiles[pane] = file; browserOffsets[pane] = 0; needsDisplay = true
    }

    override func keyDown(with event:NSEvent) {
        guard searchFocused else { super.keyDown(with:event); return }
        if event.keyCode == 53 { searchFocused = false; return }
        if event.modifierFlags.contains(.command) && event.charactersIgnoringModifiers?.lowercased() == "a" { searchSelectAll = true; return }
        if event.keyCode == 51 {
            if searchSelectAll { searchText = ""; searchSelectAll = false }
            else if !searchText.isEmpty { searchText.removeLast() }
        }
        else if let characters = event.characters, !event.modifierFlags.contains(.command) {
            if searchSelectAll { searchText = ""; searchSelectAll = false }
            searchText += String(characters.filter { !$0.isNewline && $0.asciiValue.map({$0 >= 32}) == true }.prefix(max(0,32-searchText.count)))
        }
        browserOffsets = [:]; needsDisplay = true
    }

    override func selectAll(_ sender:Any?) { if searchFocused { searchSelectAll = true } else { super.selectAll(sender) } }

    override func scrollWheel(with event:NSEvent) {
        let p = convert(event.locationInWindow,from:nil), point = NSPoint(x:(p.x-origin.x)/scale,y:(p.y-origin.y)/scale)
        guard let hit = hits.reversed().first(where: { $0.type == "Catalogue" && $0.rect.contains(point) }) else { super.scrollWheel(with:event); return }
        let pane = hit.parameter == "__catalogue_1" ? 1 : 0
        let count = catalogue(pane).count
        let delta = event.scrollingDeltaY == 0 ? 0 : event.scrollingDeltaY > 0 ? -16 : 16
        browserOffsets[pane] = min(max(0,count-128),max(0,(browserOffsets[pane] ?? 0)+delta)); needsDisplay = true
    }
}

struct OriginalSurface: NSViewRepresentable {
    @ObservedObject var model: BrowserModel
    let singleMode: Bool
    func makeNSView(context:Context) -> OriginalCanvas { let view = OriginalCanvas(); view.configure(model,singleMode:singleMode); return view }
    func updateNSView(_ view:OriginalCanvas,context:Context) { view.configure(model,singleMode:singleMode) }
}

struct OriginalInterface: View {
    @ObservedObject var model: BrowserModel
    @State private var target = 64
    var body: some View {
        VStack(spacing:10) {
            HStack {
                Text("Virus Control · Snow").font(.headline)
                Spacer()
                Toggle("Live",isOn:$model.liveMode).toggleStyle(.checkbox).disabled(model.busy)
                Picker("Current buffer",selection:$target) {
                    Text("Single mode").tag(64)
                    ForEach(0..<4) { Text("Multi / Part \($0+1)").tag($0) }
                }.frame(width:220).disabled(model.busy)
                Button("Read current sound") {
                    if target == 64 { model.readCurrentViaUSB() }
                    else { model.readCurrent(target:target) }
                }.disabled(model.busy)
                    .help("Uses direct USB in Single mode and CoreMIDI Plugin I/O for Multi parts.")
                Button("Export .syx…") { model.export() }.disabled(model.busy || model.packet.isEmpty)
            }
            OriginalSurface(model:model,singleMode:target == 64).aspectRatio(907.0/513.0,contentMode:.fit)
                .border(Color.black.opacity(0.5),width:1)
            if let preset = model.selectedFactoryPreset {
                HStack {
                    Text("Selected preset · \(preset.name)").lineLimit(1)
                    Button("Load into current sound") { model.loadFactory(target: target) }
                        .disabled(!model.canLoadFactory(target: target))
                    Text(preset.canLoad ? "Replaces the Single-mode edit buffer" : "Audition is available for Snow RAM and Snow factory presets")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                }
            }
            HStack {
                if model.readingHardwareRAM {
                    Spacer()
                    Button("Cancel RAM Read") { model.cancelHardwareRAMRead() }
                    Spacer()
                } else {
                    if let path = model.pendingPath {
                        Text("\(path): \(model.label(path,value:model.pendingValue))").monospacedDigit().lineLimit(1)
                    } else { Text(model.editTarget == nil ? "Read a current sound, then adjust an active control." : model.liveMode ? "Live controls ready — drag an active control." : "Select an active control to draft a change.").foregroundStyle(.secondary) }
                    if !model.liveMode {
                        Button("Apply change") { model.applyDraft() }
                            .disabled(model.editTarget != target || model.pendingPath.map { !model.canEdit($0) } ?? true)
                        Button("Discard") { model.discardDraft() }.disabled(model.busy || model.pendingPath == nil)
                    }
                    Button("Undo last edit") { model.undo() }.disabled(model.busy || model.pendingPath != nil || model.undoChange == nil || model.editTarget != target)
                    if model.busy { ProgressView().controlSize(.small) }
                    Spacer()
                }
            }
            Text(model.readingHardwareRAM ? "Custom sounds will appear under Snow RAM in the Browser." : model.status)
                .font(.callout).multilineTextAlignment(.center).frame(maxWidth:.infinity).textSelection(.enabled)
        }.padding(16).onChange(of:target) { _ in model.editTarget = nil; model.discardDraft(); model.undoChange = nil }
            .onReceive(NotificationCenter.default.publisher(for:NSApplication.willResignActiveNotification)) { _ in model.finishLive() }
    }
}

struct MainInterface: View {
    @StateObject private var model = BrowserModel()
    @State private var original = true
    private let refreshTimer = Timer.publish(every:0.25, on:.main, in:.default).autoconnect()
    var body: some View {
        VStack(spacing:0) {
            HStack {
                Picker("Interface",selection:$original) { Text("Original Virus Control").tag(true); Text("Inspector / catalogue").tag(false) }
                    .pickerStyle(.segmented).frame(width:380)
                Toggle("Follow Snow", isOn:$model.followSnow)
                    .toggleStyle(.checkbox)
                    .help("Mirror front-panel changes in Single mode.")
            }.padding(.top,10)
            if original { OriginalInterface(model:model) } else { BrowserView(model:model) }
        }.frame(minWidth:1000,minHeight:730)
            .onReceive(refreshTimer) { _ in
                model.checkUSBConnection()
                model.refreshFromSnow()
            }
            .onChange(of:model.liveMode) { _ in model.discardDraft() }
    }
}
