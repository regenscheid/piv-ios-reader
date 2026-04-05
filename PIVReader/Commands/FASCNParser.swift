import Foundation

// MARK: - FASC-N (Federal Agency Smart Credential Number)
//
// Decoded from 25 bytes (200 bits) of BCD-P encoding per SP 800-73-4 Appendix A.
// Each symbol is 5 bits: 4-bit BCD value + 1 odd-parity bit.

struct FASCN {
    let agencyCode: String          // 4 digits
    let systemCode: String          // 4 digits
    let credentialNumber: String    // 6 digits
    let credentialSeries: String    // 1 digit (CS)
    let individualCredentialIssue: String // 1 digit (ICI)
    let personIdentifier: String    // 10 digits (PI)
    let organizationalCategory: String   // 1 digit (OC)
    let organizationalIdentifier: String // 4 digits (OI)
    let personOrgAssociation: String     // 1 digit (POA)

    var agencyName: String? { AgencyCodes.lookup(agencyCode) }

    var formatted: String {
        "\(agencyCode)-\(systemCode)-\(credentialNumber)-\(credentialSeries)-\(individualCredentialIssue)-\(personIdentifier)-\(organizationalCategory)-\(organizationalIdentifier)-\(personOrgAssociation)"
    }
}

// MARK: - BCD-P Decoder

// 5-bit BCD-P codes: 4-bit BCD + 1 odd-parity bit (MSB first)
// From SP 800-73-4 Appendix A / pivsetup/profile.py _BCDP table
private let bcdpDecode: [UInt8: Character] = [
    0b00001: "0", 0b00010: "1", 0b00100: "2", 0b00111: "3",
    0b01000: "4", 0b01011: "5", 0b01101: "6", 0b01110: "7",
    0b10000: "8", 0b10011: "9",
]

private let SS: UInt8 = 0b11010  // Start Sentinel
private let FS: UInt8 = 0b01010  // Field Separator
private let ES: UInt8 = 0b11111  // End Sentinel

/// Read 5 bits from a byte array at a given bit offset.
private func read5Bits(from data: Data, bitOffset: Int) -> UInt8 {
    let byteIndex = bitOffset / 8
    let bitIndex = bitOffset % 8
    let remaining = 8 - bitIndex

    if remaining >= 5 {
        // All 5 bits are in one byte
        return (data[byteIndex] >> (remaining - 5)) & 0x1F
    } else {
        // Split across two bytes
        let highBits = data[byteIndex] & (0xFF >> bitIndex)
        let needed = 5 - remaining
        let lowBits = data[byteIndex + 1] >> (8 - needed)
        return (highBits << needed) | lowBits
    }
}

/// Decode a 25-byte FASC-N from BCD-P encoding.
///
/// Format: SS + Agency(4) + System(4) + FS + Credential(6) + FS + CS(1) + FS +
///         ICI(1) + FS + PI(10) + FS + OC(1) + FS + OI(4) + FS + POA(1) + ES + LRC
/// = 40 five-bit codes = 200 bits = 25 bytes
func decodeFASCN(_ data: Data) throws -> FASCN {
    guard data.count == 25 else {
        throw PIVError.badTLV("FASC-N must be 25 bytes, got \(data.count)")
    }

    // Read all 40 five-bit symbols
    var symbols = [UInt8]()
    for i in 0..<40 {
        symbols.append(read5Bits(from: data, bitOffset: i * 5))
    }

    // Validate start sentinel
    guard symbols[0] == SS else {
        throw PIVError.badTLV("FASC-N missing Start Sentinel")
    }

    // Helper to extract digit string from symbols at given range
    func digits(_ range: Range<Int>) throws -> String {
        var result = ""
        for i in range {
            guard let ch = bcdpDecode[symbols[i]] else {
                throw PIVError.badTLV("FASC-N invalid BCD at position \(i)")
            }
            result.append(ch)
        }
        return result
    }

    // Helper to validate field separator at position
    func expectFS(_ pos: Int) throws {
        guard symbols[pos] == FS else {
            throw PIVError.badTLV("FASC-N missing Field Separator at position \(pos)")
        }
    }

    // Parse fields per layout:
    // [0] SS
    // [1..4] Agency (4 digits)
    // [5..8] System (4 digits)
    // [9] FS
    // [10..15] Credential (6 digits)
    // [16] FS
    // [17] CS (1 digit)
    // [18] FS
    // [19] ICI (1 digit)
    // [20] FS
    // [21..30] PI (10 digits)
    // [31] FS
    // [32] OC (1 digit)
    // [33] FS
    // [34..37] OI (4 digits)
    // [38] FS  -- wait, let me recount
    //
    // Actually per SP 800-73-4:
    // SS Agency(4) System(4) FS Cred(6) FS CS FS ICI FS PI(10) OC OI(4) POA ES LRC
    // But pivsetup/profile.py shows:
    // SS + agency(4) + system(4) + FS + cred(6) + FS + cs + FS + ici + FS + pi(10) + FS + oc + FS + oi(4) + FS + poa
    // That's: 1+4+4+1+6+1+1+1+1+1+10+1+1+1+4+1+1 = 40, then ES+LRC would make 42.
    // But we only have 40 symbols (200 bits = 25 bytes).
    //
    // Re-reading the Python code:
    // seq = ['SS'] + agency(4) + system(4) + ['FS'] + cred(6) + ['FS', cs, 'FS', ici, 'FS']
    //        + pi(10) + ['FS', oc, 'FS'] + oi(4) + ['FS', poa]
    // Count: 1+4+4+1+6+1+1+1+1+1+10+1+1+1+4+1+1 = 40
    // Note: NO ES or LRC in the Python encoder! The 40 symbols = 200 bits = 25 bytes exactly.

    let agency = try digits(1..<5)
    let system = try digits(5..<9)
    try expectFS(9)
    let credential = try digits(10..<16)
    try expectFS(16)
    let cs = try digits(17..<18)
    try expectFS(18)
    let ici = try digits(19..<20)
    try expectFS(20)
    let pi = try digits(21..<31)
    try expectFS(31)
    let oc = try digits(32..<33)
    try expectFS(33)
    let oi = try digits(34..<38)
    try expectFS(38)
    let poa = try digits(39..<40)

    return FASCN(
        agencyCode: agency,
        systemCode: system,
        credentialNumber: credential,
        credentialSeries: cs,
        individualCredentialIssue: ici,
        personIdentifier: pi,
        organizationalCategory: oc,
        organizationalIdentifier: oi,
        personOrgAssociation: poa
    )
}

// MARK: - CHUID Container Parser

/// Parse a CHUID data object, extracting FASC-N, GUID, expiration, and signature.
///
/// Mirrors the Python `parse_chuid_container()` in `pivlib/commands/chuid.py`.
func parseCHUIDContainer(_ data: Data) -> PIVChuid? {
    let tlvs = parseTLV(data)

    // Unwrap outer 0x53 container if present
    let innerTLVs: [TLV]
    if let container = findTag(tlvs, 0x53) {
        innerTLVs = container.children()
    } else {
        innerTLVs = tlvs
    }

    // Tag 0x30 - FASC-N (25 bytes)
    let fascnTLV = findTag(innerTLVs, 0x30)
    var fascn: FASCN? = nil
    if let raw = fascnTLV?.value, raw.count == 25 {
        fascn = try? decodeFASCN(raw)
    }

    // Tag 0x34 - GUID (16 bytes)
    let guidTLV = findTag(innerTLVs, 0x34)
    let guid = guidTLV?.value

    // Tag 0x35 - Expiration Date (YYYYMMDD ASCII)
    let expiryTLV = findTag(innerTLVs, 0x35)
    var expirationDate: String? = nil
    if let raw = expiryTLV?.value, !raw.isEmpty {
        expirationDate = String(data: raw, encoding: .ascii)
    }

    // Tag 0x3E - Issuer Asymmetric Signature
    let sigTLV = findTag(innerTLVs, 0x3E)

    // Tag 0xFE - Error Detection Code
    let edcTLV = findTag(innerTLVs, 0xFE)

    return PIVChuid(
        rawData: data,
        tag: 0,
        name: "CHUID",
        fascn: fascn,
        guid: guid,
        expirationDate: expirationDate,
        issuerSignature: sigTLV?.value,
        errorDetectionCode: edcTLV?.value
    )
}
