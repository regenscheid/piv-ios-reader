import Foundation

/// Logical PIV command (before any chaining or SM wrapping).
struct PIVCommand {
    let cla: UInt8
    let ins: UInt8
    let p1: UInt8
    let p2: UInt8
    let data: Data
    let le: Int?

    init(from apdu: CommandAPDU) {
        self.cla = apdu.cla
        self.ins = apdu.ins
        self.p1 = apdu.p1
        self.p2 = apdu.p2
        self.data = apdu.data
        self.le = apdu.le
    }

    /// Full APDU as uppercase hex string.
    var apduHex: String {
        CommandAPDU(cla: cla, ins: ins, p1: p1, p2: p2, data: data, le: le).hex
    }

    /// Human-readable INS name.
    var insName: String {
        let names: [UInt8: String] = [
            0xA4: "SELECT", 0xCB: "GET DATA", 0x20: "VERIFY",
            0x87: "GENERAL AUTHENTICATE", 0xDB: "PUT DATA",
            0x47: "GENERATE KEY PAIR", 0x24: "CHANGE REFERENCE DATA",
            0x2C: "RESET RETRY COUNTER",
        ]
        return names[ins] ?? String(format: "INS=%02X", ins)
    }
}
