import Foundation

/// Key slot references for GENERAL AUTHENTICATE / GENERATE KEY PAIR.
enum PIVSlot: UInt8 {
    case smCardAuth         = 0x04
    case authentication     = 0x9A
    case cardManagement     = 0x9B
    case digitalSignature   = 0x9C
    case keyManagement      = 0x9D
    case cardAuthentication = 0x9E

    // Retired key management slots
    case retired1  = 0x82
    case retired2  = 0x83
    case retired3  = 0x84
    case retired4  = 0x85
    case retired5  = 0x86
    case retired6  = 0x87
    case retired7  = 0x88
    case retired8  = 0x89
    case retired9  = 0x8A
    case retired10 = 0x8B
    case retired11 = 0x8C
    case retired12 = 0x8D
    case retired13 = 0x8E
    case retired14 = 0x8F
    case retired15 = 0x90
    case retired16 = 0x91
    case retired17 = 0x92
    case retired18 = 0x93
    case retired19 = 0x94
    case retired20 = 0x95

    var label: String {
        switch self {
        case .smCardAuth:         return "SM Card Auth"
        case .authentication:     return "PIV Authentication"
        case .cardManagement:     return "Card Management"
        case .digitalSignature:   return "Digital Signature"
        case .keyManagement:      return "Key Management"
        case .cardAuthentication: return "Card Authentication"
        default:
            let num = Int(rawValue) - 0x82 + 1
            return "Retired Key Management \(num)"
        }
    }

    var hex: String { String(format: "%02X", rawValue) }
}
