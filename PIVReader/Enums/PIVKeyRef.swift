import Foundation

/// Key references for VERIFY, CHANGE REFERENCE DATA, RESET RETRY COUNTER.
enum PIVKeyRef: UInt8 {
    case globalPIN       = 0x00
    case pivPIN          = 0x80
    case puk             = 0x81
    case pairingCode     = 0x98
    case cardManagement  = 0x9B

    var label: String {
        switch self {
        case .globalPIN:      return "Global PIN"
        case .pivPIN:         return "PIV PIN"
        case .puk:            return "PUK"
        case .pairingCode:    return "Pairing Code"
        case .cardManagement: return "Card Management Key"
        }
    }

    var hex: String { String(format: "%02X", rawValue) }
}
