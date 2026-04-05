import Foundation

/// A single physical send/receive on the wire.
struct WireExchange {
    let commandBytes: Data
    let responseBytes: Data

    var commandHex: String { commandBytes.map { String(format: "%02X", $0) }.joined() }
    var responseHex: String { responseBytes.map { String(format: "%02X", $0) }.joined() }
    var swHex: String {
        guard responseBytes.count >= 2 else { return "????" }
        let sw1 = responseBytes[responseBytes.count - 2]
        let sw2 = responseBytes[responseBytes.count - 1]
        return String(format: "%02X%02X", sw1, sw2)
    }
}

/// Complete logical PIV operation: command + response + all wire-level exchanges.
struct PIVExchange {
    let command: PIVCommand
    let response: PIVResponse
    let wireExchanges: [WireExchange]

    // Convenience forwarding
    var sw: UInt16 { response.sw }
    var swHex: String { response.swHex }
    var data: Data { response.data }
    var success: Bool { response.success }
}
