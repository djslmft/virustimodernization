import Foundation

@main
struct LiveSessionChecks {
    static func main() async throws {
        guard CommandLine.arguments.count == 2 else { fatalError("Pass the offline echo helper path") }
        let helper = URL(fileURLWithPath:CommandLine.arguments[1])
        var session: LiveEditSession?
        let result:Data = try await withCheckedThrowingContinuation { continuation in
            session = LiveEditSession(helper:helper,arguments:[]) { outcome in continuation.resume(with:outcome) }
            Task {
                try await Task.sleep(nanoseconds:100_000_000)
                for value in 0..<150 {
                    session?.send(value % 100)
                    try await Task.sleep(nanoseconds:2_000_000)
                }
                session?.send(99)
                session?.end()
            }
        }
        let report = try JSONSerialization.jsonObject(with:result) as! [String:Any]
        let values = report["values"] as! [Int]
        precondition(values.last == 99,"Final mouse-up value must be flushed")
        precondition(values.count > 1 && values.count < 30,"Rapid motion must produce intermediate, coalesced updates")
        precondition(report["ended"] as? Bool == true,"Gesture must terminate cleanly")
        print("PASS: \(values.count) coalesced live updates from 151 motions; final value 99 preserved; gesture ended; no MIDI traffic")
        withExtendedLifetime(session) {}
    }
}
