import Foundation

/// GENERAL AUTHENTICATE modes.
enum GAMode: String {
    case internalAuthenticate = "internal_authenticate"
    case externalAuthenticate = "external_authenticate"
    case mutualAuthenticate   = "mutual_authenticate"
    case sign                 = "sign"
    case keyEstablish         = "key_establish"
}

/// Build a GENERAL AUTHENTICATE command APDU.
///
/// Constructs the Dynamic Authentication Template (tag 7C) based on the mode.
///
/// - Parameters:
///   - mode: GA operation mode.
///   - algorithmRef: Algorithm identifier hex (e.g. "11" for ECC P-256).
///   - keyRef: Key slot hex (e.g. "9A").
///   - challenge: Challenge/data bytes for signing or authentication.
///   - witness: Witness bytes (for mutual auth).
///   - dataPayload: Pre-built payload for key establishment.
func buildGeneralAuthenticate(
    mode: GAMode,
    algorithmRef: String = "07",
    keyRef: String = "9A",
    challenge: Data? = nil,
    witness: Data? = nil,
    dataPayload: Data? = nil
) -> CommandAPDU {
    let p1 = UInt8(algorithmRef, radix: 16) ?? 0x07
    let p2 = UInt8(keyRef, radix: 16) ?? 0x9A

    // Build inner 7C content based on mode
    var inner = Data()

    switch mode {
    case .internalAuthenticate:
        // Request: 7C { 81 [challenge], 82 00 }
        inner.append(buildTLV(tag: 0x81, value: challenge ?? Data(count: 16)))
        inner.append(buildTLV(tag: 0x82, value: Data()))

    case .externalAuthenticate:
        // Request: 7C { 82 [witness], 80 [challenge] }
        if let w = witness { inner.append(buildTLV(tag: 0x82, value: w)) }
        if let c = challenge { inner.append(buildTLV(tag: 0x80, value: c)) }

    case .mutualAuthenticate:
        // Request: 7C { 80 [decrypted_witness], 81 [challenge] }
        if let w = witness { inner.append(buildTLV(tag: 0x80, value: w)) }
        if let c = challenge { inner.append(buildTLV(tag: 0x81, value: c)) }

    case .sign:
        // Request: 7C { 81 [data_to_sign], 82 00 }
        inner.append(buildTLV(tag: 0x81, value: challenge ?? Data()))
        inner.append(buildTLV(tag: 0x82, value: Data()))

    case .keyEstablish:
        // Request: pre-built payload (for SM ECDH)
        if let payload = dataPayload {
            inner.append(payload)
        } else {
            inner.append(buildTLV(tag: 0x81, value: challenge ?? Data()))
            inner.append(buildTLV(tag: 0x82, value: Data()))
        }
    }

    let data = buildTLV(tag: 0x7C, value: inner)
    return CommandAPDU(ins: 0x87, p1: p1, p2: p2, data: data, le: 0)
}

/// Parse a GENERAL AUTHENTICATE response.
func parseGeneralAuthenticateResponse(_ resp: ResponseAPDU) -> [String: Any] {
    var result: [String: Any] = ["sw": resp.swHex]
    guard resp.success, !resp.data.isEmpty else { return result }

    let tlvs = parseTLV(resp.data)
    guard let template = findTag(tlvs, 0x7C) else {
        result["tlv_valid"] = false
        return result
    }
    result["tlv_valid"] = true

    let children = template.children()
    if let witness = findTag(children, 0x80) {
        result["witness"] = witness.value.hexString
    }
    if let challenge = findTag(children, 0x81) {
        result["challenge"] = challenge.value.hexString
    }
    if let response = findTag(children, 0x82) {
        result["response"] = response.value.hexString
    }
    if let keyPoint = findTag(children, 0x86) {
        result["key_point"] = keyPoint.value.hexString
    }

    return result
}
