import Foundation

/// Logical PIV response (assembled after any response chaining).
struct PIVResponse {
    let data: Data
    let sw1: UInt8
    let sw2: UInt8

    var sw: UInt16 { (UInt16(sw1) << 8) | UInt16(sw2) }
    var swHex: String { String(format: "%04X", sw) }
    var success: Bool { sw == 0x9000 }
    var description: String { SW.describe(swHex) }

    init(from resp: ResponseAPDU) {
        self.data = resp.data
        self.sw1 = resp.sw1
        self.sw2 = resp.sw2
    }

    init(data: Data = Data(), sw1: UInt8 = 0x90, sw2: UInt8 = 0x00) {
        self.data = data
        self.sw1 = sw1
        self.sw2 = sw2
    }
}
