import Foundation

/// A response APDU from the card.
struct ResponseAPDU {
    let data: Data
    let sw1: UInt8
    let sw2: UInt8

    /// Combined status word as UInt16.
    var sw: UInt16 { (UInt16(sw1) << 8) | UInt16(sw2) }

    /// Status word as 4-character hex string (e.g. "9000").
    var swHex: String { String(format: "%04X", sw) }

    /// True if SW == 9000.
    var success: Bool { sw == 0x9000 }

    /// Human-readable SW description.
    var swDescription: String { SW.describe(swHex) }

    /// Full response bytes (data + SW1 + SW2).
    var responseBytes: Data {
        var buf = data
        buf.append(sw1)
        buf.append(sw2)
        return buf
    }

    /// Create from raw data + status word bytes.
    static func from(data: Data, sw1: UInt8, sw2: UInt8) -> ResponseAPDU {
        ResponseAPDU(data: data, sw1: sw1, sw2: sw2)
    }

    /// Parse from complete response bytes (data || SW1 || SW2).
    static func fromBytes(_ raw: Data) -> ResponseAPDU? {
        guard raw.count >= 2 else { return nil }
        let sw1 = raw[raw.count - 2]
        let sw2 = raw[raw.count - 1]
        let data = raw.count > 2 ? raw[0..<(raw.count - 2)] : Data()
        return ResponseAPDU(data: Data(data), sw1: sw1, sw2: sw2)
    }
}

extension ResponseAPDU: CustomStringConvertible {
    var description: String {
        "ResponseAPDU(sw=\(swHex), data=\(data.count)B)"
    }
}
