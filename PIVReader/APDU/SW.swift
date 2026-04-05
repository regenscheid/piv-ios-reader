import Foundation

/// Common PIV status words.
enum SW: UInt16 {
    case success               = 0x9000
    case warningNVUnchanged    = 0x6200
    case wrongLength           = 0x6700
    case smNotSupported        = 0x6882
    case securityNotSatisfied  = 0x6982
    case authMethodBlocked     = 0x6983
    case conditionsNotSatisfied = 0x6985
    case smDataMissing         = 0x6987
    case smDataIncorrect       = 0x6988
    case wrongData             = 0x6A80
    case functionNotSupported  = 0x6A81
    case fileNotFound          = 0x6A82
    case incorrectP1P2        = 0x6A86
    case refDataNotFound       = 0x6A88
    case insNotSupported       = 0x6D00
    case claNotSupported       = 0x6E00

    /// Human-readable description of a status word hex string.
    static func describe(_ swHex: String) -> String {
        if let raw = UInt16(swHex, radix: 16), let known = SW(rawValue: raw) {
            return known.label
        }
        if swHex.hasPrefix("61") {
            let remaining = UInt8(swHex.suffix(2), radix: 16) ?? 0
            return "\(remaining) bytes remaining"
        }
        if swHex.hasPrefix("63C") {
            if let retries = parseRetryCount(swHex) {
                return "Verification failed, \(retries) retries remaining"
            }
        }
        return "Unknown status word"
    }

    var label: String {
        switch self {
        case .success:               return "Success"
        case .warningNVUnchanged:    return "Warning: non-volatile memory unchanged"
        case .wrongLength:           return "Wrong length"
        case .smNotSupported:        return "Secure messaging not supported"
        case .securityNotSatisfied:  return "Security status not satisfied"
        case .authMethodBlocked:     return "Authentication method blocked"
        case .conditionsNotSatisfied: return "Conditions of use not satisfied"
        case .smDataMissing:         return "Expected SM data objects missing"
        case .smDataIncorrect:       return "SM data objects incorrect"
        case .wrongData:             return "Wrong data"
        case .functionNotSupported:  return "Function not supported"
        case .fileNotFound:          return "File/application not found"
        case .incorrectP1P2:        return "Incorrect P1/P2 parameters"
        case .refDataNotFound:       return "Reference data not found"
        case .insNotSupported:       return "INS not supported"
        case .claNotSupported:       return "CLA not supported"
        }
    }
}

/// Check if SW1=61 (more data available).
func isMoreData(_ sw1: UInt8) -> Bool {
    sw1 == 0x61
}

/// Extract retry count X from SW "63CX".
func parseRetryCount(_ swHex: String) -> Int? {
    guard swHex.count == 4, swHex.hasPrefix("63C") else { return nil }
    return Int(String(swHex.last!), radix: 16)
}

/// Check if a status word hex matches any in the allowed list.
/// Supports prefix matching (e.g. "61" matches "6100"-"61FF").
func swMatches(_ actual: String, allowed: [String]) -> Bool {
    for pattern in allowed {
        if pattern.count < 4 {
            if actual.hasPrefix(pattern) { return true }
        } else {
            if actual == pattern { return true }
        }
    }
    return false
}
