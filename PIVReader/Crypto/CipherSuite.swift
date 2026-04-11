import Foundation

/// PIV Secure Messaging cipher suites (SP 800-73-5).
enum CipherSuite: UInt8 {
    case cs2 = 0x27  // P-256 / AES-128 / SHA-256
    case cs7 = 0x2E  // P-384 / AES-256 / SHA-384

    /// Symmetric key length in bytes.
    var keyLength: Int {
        switch self {
        case .cs2: return 16  // AES-128
        case .cs7: return 32  // AES-256
        }
    }

    /// ECDH curve for this cipher suite.
    var curve: ECCurve {
        switch self {
        case .cs2: return .p256
        case .cs7: return .p384
        }
    }

    /// Hash algorithm used in KDF.
    var hashAlgorithm: HashAlgorithm {
        switch self {
        case .cs2: return .sha256
        case .cs7: return .sha384
        }
    }

    /// Hash output length in bytes.
    var hashLength: Int {
        switch self {
        case .cs2: return 32
        case .cs7: return 48
        }
    }

    /// AlgorithmID value for KDF OtherInfo (SP 800-56A §5.8.1).
    var kdfAlgorithmID: Data {
        switch self {
        case .cs2: return Data([0x09, 0x09, 0x09, 0x09])
        case .cs7: return Data([0x0D, 0x0D, 0x0D, 0x0D])
        }
    }

    /// Nonce length in the SM establishment protocol.
    var nonceLength: Int {
        switch self {
        case .cs2: return 16
        case .cs7: return 24
        }
    }

    /// Total KDF output needed: SK_CFRM + SK_MAC + SK_ENC + SK_RMAC.
    var kdfOutputLength: Int { keyLength * 4 }

    /// Resolve from string name ("cs2", "cs7") or hex ("27", "2E").
    static func fromName(_ name: String) -> CipherSuite? {
        switch name.lowercased() {
        case "cs2", "27": return .cs2
        case "cs7", "2e": return .cs7
        default: return nil
        }
    }
}

/// EC curve identifiers.
enum ECCurve {
    case p256
    case p384

    /// Uncompressed point size in bytes (1 + 2*coordLen).
    var pointSize: Int {
        switch self {
        case .p256: return 65   // 1 + 32 + 32
        case .p384: return 97   // 1 + 48 + 48
        }
    }

    /// Coordinate size in bytes.
    var coordSize: Int {
        switch self {
        case .p256: return 32
        case .p384: return 48
        }
    }
}

/// Hash algorithm identifiers.
enum HashAlgorithm {
    case sha256
    case sha384
}
