import Foundation

/// Full PIV AID (including version bytes).
let pivAIDFull = "A000000308000010000100"

/// Right-truncated PIV AID (without version bytes).
let pivAIDTruncated = "A00000030800001000"

/// Build a SELECT command APDU.
func buildSelect(aidHex: String) -> CommandAPDU {
    let aidBytes = Data(hexString: aidHex)
    return CommandAPDU(ins: 0xA4, p1: 0x04, p2: 0x00, data: aidBytes, le: 0)
}

/// Parse a successful SELECT response.
///
/// Returns a dictionary with application_label, aid, algorithm_identifiers, etc.
func parseSelectResponse(_ resp: ResponseAPDU) -> [String: Any] {
    var result: [String: Any] = ["sw": resp.swHex]
    guard !resp.data.isEmpty else { return result }

    let tlvs = parseTLV(resp.data)
    guard let apt = findTag(tlvs, 0x61) else { return result }
    let children = apt.children()

    // Application Label (tag 50)
    if let label = findTag(children, 0x50) {
        result["application_label"] = String(data: label.value, encoding: .ascii) ?? ""
    }
    // AID (tag 4F)
    if let aid = findTag(children, 0x4F) {
        result["aid"] = aid.value.map { String(format: "%02X", $0) }.joined()
    }
    // Coexistent Tag Allocation Authority (tag 79)
    if let auth = findTag(children, 0x79) {
        result["coexistent_tag_allocation_authority"] =
            auth.value.map { String(format: "%02X", $0) }.joined()
    }
    // Cryptographic Algorithm Identifiers (tag AC)
    if let ac = findTag(children, 0xAC) {
        var algos: [String] = []
        for child in ac.children() where child.tag == 0x80 {
            algos.append(child.value.map { String(format: "%02X", $0) }.joined())
        }
        result["algorithm_identifiers"] = algos
    }

    return result
}

// MARK: - Data hex helper

extension Data {
    /// Initialize from a hex string (e.g. "A000000308").
    init(hexString hex: String) {
        let chars = Array(hex)
        var bytes: [UInt8] = []
        for i in stride(from: 0, to: chars.count - 1, by: 2) {
            if let b = UInt8(String(chars[i]) + String(chars[i + 1]), radix: 16) {
                bytes.append(b)
            }
        }
        self.init(bytes)
    }

    /// Uppercase hex string representation.
    var hexString: String {
        map { String(format: "%02X", $0) }.joined()
    }
}
