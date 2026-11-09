import Foundation
import Darwin

/// One bounded helper process per gesture. Only the latest value is sent each tick.
final class LiveEditSession: @unchecked Sendable {
    private let process = Process()
    private let input = Pipe()
    private let output = Pipe()
    private let errors = Pipe()
    private let queue = DispatchQueue(label:"VirusLiveGesture")
    private let lock = NSLock()
    private var latest: Int?
    private var timer: DispatchSourceTimer?
    private var ended = false
    private let completion: @Sendable (Result<Data,Error>) -> Void

    init(helper:URL, arguments:[String], completion:@escaping @Sendable (Result<Data,Error>) -> Void) {
        self.completion = completion
        process.executableURL = helper; process.arguments = arguments
        process.standardInput = input; process.standardOutput = output; process.standardError = errors
        // A refused/ended helper must produce a write error, not SIGPIPE in the GUI.
        _ = fcntl(input.fileHandleForWriting.fileDescriptor,F_SETNOSIGPIPE,1)
        queue.async { [self] in
            do {
                try process.run()
                let timer = DispatchSource.makeTimerSource(queue:queue)
                timer.schedule(deadline:.now(),repeating:1.0/30,leeway:.milliseconds(2))
                timer.setEventHandler { [weak self] in self?.pump() }
                self.timer = timer; timer.resume()
                DispatchQueue.global(qos:.userInitiated).async { [self] in
                    let data = output.fileHandleForReading.readDataToEndOfFile()
                    process.waitUntilExit()
                    queue.async { [self] in
                        timer.cancel(); self.timer = nil; ended = true
                        try? input.fileHandleForWriting.close()
                        if data.isEmpty {
                            let errorData = errors.fileHandleForReading.readDataToEndOfFile()
                            completion(.failure(NSError(domain:"LiveEdit",code:1,userInfo:[NSLocalizedDescriptionKey:String(decoding:errorData,as:UTF8.self)])))
                        } else { completion(.success(data)) }
                    }
                }
            } catch { ended = true; completion(.failure(error)) }
        }
    }

    func send(_ value:Int) { lock.lock(); latest = value; lock.unlock() }

    private func pump() {
        guard !ended else { return }
        lock.lock(); let value = latest; latest = nil; lock.unlock()
        guard let value else { return }
        do { try input.fileHandleForWriting.write(contentsOf:Data("\(value)\n".utf8)) }
        catch { endOnQueue() }
    }

    func end() { queue.async { [self] in endOnQueue() } }

    private func endOnQueue() {
        guard !ended else { return }
        pumpFinal()
        ended = true; timer?.cancel(); timer = nil
        try? input.fileHandleForWriting.write(contentsOf:Data("END\n".utf8))
        try? input.fileHandleForWriting.close()
    }

    private func pumpFinal() {
        lock.lock(); let value = latest; latest = nil; lock.unlock()
        if let value { try? input.fileHandleForWriting.write(contentsOf:Data("\(value)\n".utf8)) }
    }
}
