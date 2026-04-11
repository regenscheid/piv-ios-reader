import Foundation

// MARK: - TLV

/// A single BER-TLV element (supports multi-byte tags up to 3 bytes).
struct TLV {
    let tag: UInt32
    let value: Data

    var tagHex: String {
        if tag <= 0xFF { return String(format: "%02X", tag) }
        if tag <= 0xFFFF { return String(format: "%04X", tag) }
        return String(format: "%06X", tag)
    }

    var length: Int { value.count }

    /// Parse the value as nested TLV children (for constructed tags).
    func children() -> [TLV] {
        return parseTLV(value)
    }

    /// Find first immediate child with the given tag.
    func find(_ searchTag: UInt32) -> TLV? {
        return findTag(children(), searchTag)
    }

    /// Pretty-print this TLV as an indented tree.
    func display(indent: Int = 0) -> String {
        let prefix = String(repeating: "  ", count: indent)
        let name = pivTagName(tag)
        let nameStr = name != nil ? "  (\(name!))" : ""
        let header = "\(prefix)[\(tagHex)]\(nameStr)  len=\(length)"

        if isConstructed(tag) && !value.isEmpty {
            let kids = children()
            if !kids.isEmpty {
                let childLines = kids.map { $0.display(indent: indent + 1) }.joined(separator: "\n")
                return "\(header)\n\(childLines)"
            }
        }

        let valueHex = value.map { String(format: "%02X", $0) }.joined()
        // Try ASCII for printable data
        if let ascii = String(data: value, encoding: .ascii),
           ascii.allSatisfy({ $0.asciiValue.map { $0 >= 32 && $0 < 127 } ?? false }) {
            return "\(header)  = '\(valueHex)'  (ASCII: '\(ascii)')"
        }
        return "\(header)  = \(valueHex)"
    }
}

extension TLV: CustomStringConvertible {
    var description: String {
        let kids = children()
        if isConstructed(tag), !kids.isEmpty {
            return "TLV(tag=0x\(tagHex), \(kids.count) children)"
        }
        return "TLV(tag=0x\(tagHex), len=\(length))"
    }
}

// MARK: - Parsing

/// Parse a byte buffer as a sequence of BER-TLV elements.
func parseTLV(_ data: Data) -> [TLV] {
    var results: [TLV] = []
    var offset = 0

    while offset < data.count {
        // Skip padding bytes (0x00, 0xFF)
        if data[offset] == 0x00 || data[offset] == 0xFF {
            offset += 1
            continue
        }

        // Parse tag
        let (tag, tagLen) = parseTag(data, offset: offset)
        offset += tagLen
        guard offset < data.count else { break }

        // Parse length
        let (length, lenLen) = parseLength(data, offset: offset)
        offset += lenLen
        guard offset + length <= data.count else { break }

        // Extract value
        let value = data[offset..<(offset + length)]
        results.append(TLV(tag: tag, value: Data(value)))
        offset += length
    }

    return results
}

/// Pretty-print raw data as a TLV tree.
func displayTLV(_ data: Data, indent: Int = 0) -> String {
    let tlvs = parseTLV(data)
    return tlvs.map { $0.display(indent: indent) }.joined(separator: "\n")
}

/// Find first TLV with given tag (non-recursive).
func findTag(_ tlvs: [TLV], _ tag: UInt32) -> TLV? {
    return tlvs.first { $0.tag == tag }
}

/// Find first TLV with given tag, searching recursively into constructed children.
func findTagRecursive(_ tlvs: [TLV], _ tag: UInt32) -> TLV? {
    for t in tlvs {
        if t.tag == tag { return t }
        if isConstructed(t.tag) {
            if let found = findTagRecursive(t.children(), tag) {
                return found
            }
        }
    }
    return nil
}

// MARK: - Building

/// Encode a single BER-TLV element.
func buildTLV(tag: UInt32, value: Data) -> Data {
    var result = Data()
    result.append(contentsOf: encodeTag(tag))
    result.append(contentsOf: encodeLength(value.count))
    result.append(value)
    return result
}

// MARK: - Internal Helpers

private func parseTag(_ data: Data, offset: Int) -> (UInt32, Int) {
    let b0 = data[offset]
    if (b0 & 0x1F) != 0x1F {
        // Single-byte tag
        return (UInt32(b0), 1)
    }
    // Multi-byte tag
    var tag = UInt32(b0)
    var i = 1
    repeat {
        guard offset + i < data.count else { break }
        tag = (tag << 8) | UInt32(data[offset + i])
        i += 1
    } while data[offset + i - 1] & 0x80 != 0
    return (tag, i)
}

private func parseLength(_ data: Data, offset: Int) -> (Int, Int) {
    let b0 = data[offset]
    if b0 < 0x80 {
        return (Int(b0), 1)
    }
    let numBytes = Int(b0 & 0x7F)
    guard numBytes > 0, offset + 1 + numBytes <= data.count else {
        return (0, 1)
    }
    var length = 0
    for i in 0..<numBytes {
        length = (length << 8) | Int(data[offset + 1 + i])
    }
    return (length, 1 + numBytes)
}

private func encodeTag(_ tag: UInt32) -> [UInt8] {
    if tag <= 0xFF { return [UInt8(tag)] }
    if tag <= 0xFFFF { return [UInt8(tag >> 8), UInt8(tag & 0xFF)] }
    return [UInt8(tag >> 16), UInt8((tag >> 8) & 0xFF), UInt8(tag & 0xFF)]
}

private func encodeLength(_ length: Int) -> [UInt8] {
    if length < 0x80 { return [UInt8(length)] }
    if length <= 0xFF { return [0x81, UInt8(length)] }
    if length <= 0xFFFF { return [0x82, UInt8(length >> 8), UInt8(length & 0xFF)] }
    return [0x83, UInt8(length >> 16), UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)]
}

func isConstructed(_ tag: UInt32) -> Bool {
    // Bit 6 of the first tag byte indicates constructed
    let firstByte: UInt8
    if tag <= 0xFF { firstByte = UInt8(tag) }
    else if tag <= 0xFFFF { firstByte = UInt8(tag >> 8) }
    else { firstByte = UInt8(tag >> 16) }
    return (firstByte & 0x20) != 0
}

// MARK: - PIV Tag Names

private func pivTagName(_ tag: UInt32) -> String? {
    let names: [UInt32: String] = [
        0x4F: "Application Identifier (AID)",
        0x50: "Application Label",
        0x53: "PIV Data Object",
        0x5C: "Tag List",
        0x61: "Application Property Template",
        0x70: "Certificate",
        0x71: "CertInfo",
        0x79: "Coexistent Tag Allocation Authority",
        0x7C: "Dynamic Authentication Template",
        0x7E: "Discovery Object",
        0x80: "Witness / Algorithm Identifier",
        0x81: "Challenge / Nonce",
        0x82: "Response / Cardholder Certificate",
        0x86: "Public Key Point",
        0x87: "SM Encrypted Data",
        0x8E: "SM MAC",
        0x97: "SM Expected Le",
        0x99: "SM Status",
        0xAC: "Cryptographic Algorithm Identifier Template",
        0xFE: "Error Detection Code",
        0x5FC102: "CHUID",
        0x5FC105: "X509 PIV Authentication",
        0x5FC101: "X509 Card Authentication",
        0x5FC10A: "X509 Digital Signature",
        0x5FC10B: "X509 Key Management",
        0x5FC107: "Card Capability Container",
        0x5FC123: "Pairing Code Reference Data",
        0x7F21: "Card Verifiable Certificate",
        0x7F49: "Public Key Template",
    ]
    return names[tag]
}
