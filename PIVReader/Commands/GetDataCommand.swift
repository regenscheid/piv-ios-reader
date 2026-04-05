import Foundation

/// Build a GET DATA command APDU for a named PIV data object.
///
/// - Parameter objectName: Key from DataObjects registry (e.g. "CHUID").
/// - Returns: CommandAPDU with INS=CB, P1=3F, P2=FF, data = 5C-wrapped tag.
func buildGetData(objectName: String) throws -> CommandAPDU {
    guard let spec = DataObjects.byKey(objectName) else {
        throw PIVError.badTLV("Unknown object: \(objectName)")
    }
    return buildGetData(spec: spec)
}

/// Build a GET DATA command APDU for a PIVObjectSpec.
func buildGetData(spec: PIVObjectSpec) -> CommandAPDU {
    // Data field: tag 5C wrapping the object's BER-TLV tag bytes
    let data = buildTLV(tag: 0x5C, value: spec.berTLVTag)
    return CommandAPDU(ins: 0xCB, p1: 0x3F, p2: 0xFF, data: data, le: 0)
}

/// Build a GET DATA command APDU from a raw tag hex string.
func buildGetData(tagHex: String) -> CommandAPDU {
    let tagBytes = Data(hexString: tagHex)
    let data = buildTLV(tag: 0x5C, value: tagBytes)
    return CommandAPDU(ins: 0xCB, p1: 0x3F, p2: 0xFF, data: data, le: 0)
}

/// Parse a GET DATA response (minimal: just report TLV validity).
func parseGetDataResponse(_ resp: ResponseAPDU) -> [String: Any] {
    var result: [String: Any] = ["sw": resp.swHex, "data_len": resp.data.count]
    if !resp.data.isEmpty {
        let tlvs = parseTLV(resp.data)
        result["tlv_valid"] = !tlvs.isEmpty
        result["tlv_tags"] = tlvs.map { $0.tagHex }
    }
    return result
}
