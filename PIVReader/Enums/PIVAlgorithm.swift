import Foundation

/// Algorithm identifiers for GENERAL AUTHENTICATE / GENERATE KEY PAIR.
enum PIVAlgorithm: UInt8 {
    case tdes    = 0x03
    case rsa3072 = 0x05
    case rsa2048 = 0x07
    case aes128  = 0x08
    case aes192  = 0x0A
    case aes256  = 0x0C
    case eccP256 = 0x11
    case eccP384 = 0x14
    case cs2     = 0x27  // SM Cipher Suite 2 (P-256 / AES-128)
    case cs7     = 0x2E  // SM Cipher Suite 7 (P-384 / AES-256)

    var label: String {
        switch self {
        case .tdes:    return "3DES"
        case .rsa3072: return "RSA-3072"
        case .rsa2048: return "RSA-2048"
        case .aes128:  return "AES-128"
        case .aes192:  return "AES-192"
        case .aes256:  return "AES-256"
        case .eccP256: return "ECC P-256"
        case .eccP384: return "ECC P-384"
        case .cs2:     return "CS2 (P-256/AES-128)"
        case .cs7:     return "CS7 (P-384/AES-256)"
        }
    }

    var hex: String { String(format: "%02X", rawValue) }

    /// True for asymmetric algorithms (ECC, RSA).
    var isAsymmetric: Bool {
        switch self {
        case .eccP256, .eccP384, .rsa2048, .rsa3072: return true
        default: return false
        }
    }

    /// Key size in bytes for symmetric algorithms.
    var keySize: Int? {
        switch self {
        case .aes128: return 16
        case .aes192: return 24
        case .aes256: return 32
        case .tdes:   return 24
        default:      return nil
        }
    }
}
