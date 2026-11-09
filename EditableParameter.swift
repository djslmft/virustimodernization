import Foundation

struct EditCondition: Decodable {
    let offset: Int
    let minimum: Int
    let maximum: Int
    let kind: Int
    func matches(_ packet: [UInt8]) -> Bool? {
        guard offset < packet.count-1 else { return nil }
        let value = Int(packet[offset])
        switch kind {
        case 0: return value == minimum
        case 1: return value >= minimum && value <= maximum
        case 2: return value < minimum || value > maximum
        default: return nil
        }
    }
}

struct EditableParameter: Decodable, Identifiable {
    let id: String
    let group: String
    let name: String
    let offset: Int
    let page: Int
    let controller: Int
    let minimum: Int
    let maximum: Int
    let valueList: String
    let condition: String
    let guards: [EditCondition]
    let guardAnd: Bool
    let guardInvert: Bool
    func active(in packet: [UInt8]) -> Bool {
        guard PresetPacket.valid(packet), offset < packet.count-1, packet[7] == 0,
              [0,1,2,3,64].contains(Int(packet[8])) else { return false }
        let results = guards.map { $0.matches(packet) }
        guard results.allSatisfy({ $0 != nil }) else { return false }
        if results.isEmpty { return true }
        let result = guardAnd ? results.allSatisfy({ $0 == true }) : results.contains(where: { $0 == true })
        return guardInvert ? !result : result
    }
}

struct VerifiedEdit {
    let target: Int
    let parameter: String
    let before: Int
    let after: Int
}
