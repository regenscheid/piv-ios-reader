import Foundation
import CoreNFC

/// A command APDU (Application Protocol Data Unit) to send to a PIV card.
struct CommandAPDU {
    let cla: UInt8
    let ins: UInt8
    let p1: UInt8
    let p2: UInt8
    let data: Data
    let le: Int? // nil = absent, 0 = 256 (short) or 65536 (extended)

    init(cla: UInt8 = 0x00, ins: UInt8, p1: UInt8, p2: UInt8,
         data: Data = Data(), le: Int? = nil) {
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.data = data
        self.le = le
    }

    /// Encode as raw bytes (short-length encoding; max 255 data bytes).
    func toBytes() -> Data {
        var buf = Data([cla, ins, p1, p2])

        if !data.isEmpty {
            if data.count <= 255 {
                buf.append(UInt8(data.count))
            } else {
                // Extended length: 3-byte Lc
                buf.append(0x00)
                buf.append(UInt8(data.count >> 8))
                buf.append(UInt8(data.count & 0xFF))
            }
            buf.append(data)
        }

        if let le = le {
            if data.count > 255 || le > 256 {
                // Extended Le
                buf.append(UInt8(le >> 8))
                buf.append(UInt8(le & 0xFF))
            } else {
                buf.append(UInt8(le & 0xFF))
            }
        }

        return buf
    }

    /// Hex string of the raw APDU.
    var hex: String {
        toBytes().map { String(format: "%02X", $0) }.joined()
    }

    /// Convert to Core NFC APDU for transmission.
    /// Note: CoreNFC expects the *decoded* Le value (1–65536 or -1 for absent).
    /// ISO 7816 encodes Le=0 to mean 256 on the wire, but CoreNFC wants 256 directly.
    func toNFCAPDU() -> NFCISO7816APDU {
        let expectedLen: Int
        if let le = le {
            expectedLen = le == 0 ? 256 : le
        } else {
            expectedLen = -1
        }
        return NFCISO7816APDU(
            instructionClass: cla,
            instructionCode: ins,
            p1Parameter: p1,
            p2Parameter: p2,
            data: data,
            expectedResponseLength: expectedLen
        )
    }

    /// Parse a CommandAPDU from raw bytes.
    static func fromBytes(_ raw: Data) -> CommandAPDU? {
        guard raw.count >= 4 else { return nil }
        let cla = raw[0], ins = raw[1], p1 = raw[2], p2 = raw[3]

        if raw.count == 4 {
            return CommandAPDU(cla: cla, ins: ins, p1: p1, p2: p2)
        }

        var offset = 4
        var lc = 0
        var extended = false

        if raw[offset] == 0x00 && raw.count > offset + 2 {
            // Extended length
            extended = true
            lc = (Int(raw[offset + 1]) << 8) | Int(raw[offset + 2])
            offset += 3
        } else {
            lc = Int(raw[offset])
            offset += 1
        }

        let data: Data
        if lc > 0 && offset + lc <= raw.count {
            data = raw[offset..<(offset + lc)]
            offset += lc
        } else {
            data = Data()
        }

        var le: Int? = nil
        if offset < raw.count {
            if extended {
                if offset + 2 <= raw.count {
                    le = (Int(raw[offset]) << 8) | Int(raw[offset + 1])
                }
            } else {
                le = Int(raw[offset])
                if le == 0 { le = 256 }
            }
        }

        return CommandAPDU(cla: cla, ins: ins, p1: p1, p2: p2,
                           data: Data(data), le: le)
    }
}

extension CommandAPDU: CustomStringConvertible {
    var description: String {
        let insName = insNames[ins] ?? String(format: "%02X", ins)
        return "CommandAPDU(\(insName), data=\(data.count)B)"
    }
}

private let insNames: [UInt8: String] = [
    0xA4: "SELECT",
    0xCB: "GET DATA",
    0x20: "VERIFY",
    0x87: "GENERAL AUTHENTICATE",
    0xDB: "PUT DATA",
    0x47: "GENERATE KEY PAIR",
    0x24: "CHANGE REFERENCE DATA",
    0x2C: "RESET RETRY COUNTER",
]
