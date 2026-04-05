import Foundation

/// Domain errors for PIV operations.
enum PIVError: Error, LocalizedError {
    case notConnected
    case nfcSessionFailed(String)
    case badTLV(String)
    case commandFailed(sw: UInt16, description: String)
    case smMACFailed
    case smDecryptFailed
    case smCounterDesync
    case smEstablishmentFailed(String)
    case certificateParseFailed(String)
    case unsupportedAlgorithm(UInt8)
    case timeout

    var errorDescription: String? {
        switch self {
        case .notConnected: return "Not connected to card"
        case .nfcSessionFailed(let msg): return "NFC session failed: \(msg)"
        case .badTLV(let msg): return "TLV parse error: \(msg)"
        case .commandFailed(let sw, let desc): return "Command failed (SW=\(String(format: "%04X", sw))): \(desc)"
        case .smMACFailed: return "SM MAC verification failed"
        case .smDecryptFailed: return "SM decryption failed"
        case .smCounterDesync: return "SM counter desynchronized"
        case .smEstablishmentFailed(let msg): return "SM key establishment failed: \(msg)"
        case .certificateParseFailed(let msg): return "Certificate parse failed: \(msg)"
        case .unsupportedAlgorithm(let alg): return "Unsupported algorithm: 0x\(String(format: "%02X", alg))"
        case .timeout: return "Operation timed out"
        }
    }
}
