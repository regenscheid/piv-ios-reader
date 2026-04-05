import Foundation

/// Top-level return type from all PIVCard methods.
///
/// Provides direct access to status word and data, plus optional parsed
/// content and the full wire-level exchange for debugging.
struct CardResponse {
    let sw1: UInt8
    let sw2: UInt8
    let data: Data
    let command: PIVCommand
    var parsed: (any PIVDataObject)? = nil
    var exchange: PIVExchange? = nil

    var sw: UInt16 { (UInt16(sw1) << 8) | UInt16(sw2) }
    var swHex: String { String(format: "%04X", sw) }
    var success: Bool { sw == 0x9000 }
    var description: String { SW.describe(swHex) }

    var wireExchanges: [WireExchange] { exchange?.wireExchanges ?? [] }
}
