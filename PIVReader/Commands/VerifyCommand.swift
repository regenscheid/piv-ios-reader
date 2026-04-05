import Foundation

/// Build a VERIFY command APDU.
///
/// - Parameters:
///   - keyRef: Key reference hex (e.g. "80" for PIV PIN, "00" for Global PIN).
///   - pin: ASCII PIN string (padded to 8 bytes with 0xFF). Nil for status check.
///   - resetSecurityStatus: If true, sends P1=0xFF to reset security status.
func buildVerify(keyRef: String = "80", pin: String? = nil,
                 resetSecurityStatus: Bool = false) -> CommandAPDU {
    let p2 = UInt8(keyRef, radix: 16) ?? 0x80
    let p1: UInt8 = resetSecurityStatus ? 0xFF : 0x00

    var data = Data()
    if let pin = pin {
        // PIN: ASCII bytes padded to 8 with 0xFF
        var pinBytes = Array(pin.utf8)
        while pinBytes.count < 8 {
            pinBytes.append(0xFF)
        }
        data = Data(pinBytes.prefix(8))
    }

    if data.isEmpty && !resetSecurityStatus {
        // Status check: no data, no Le
        return CommandAPDU(ins: 0x20, p1: p1, p2: p2)
    }

    return CommandAPDU(ins: 0x20, p1: p1, p2: p2, data: data)
}

/// Parse a VERIFY response.
func parseVerifyResponse(_ resp: ResponseAPDU) -> [String: Any] {
    var result: [String: Any] = ["sw": resp.swHex]
    result["verified"] = resp.success

    if let retries = parseRetryCount(resp.swHex) {
        result["retries_remaining"] = retries
    }
    if resp.sw == SW.authMethodBlocked.rawValue {
        result["blocked"] = true
    }

    return result
}
