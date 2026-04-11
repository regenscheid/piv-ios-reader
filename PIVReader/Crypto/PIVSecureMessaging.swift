import Foundation

// MARK: - SM TLV Tags (SP 800-73-5)

private let TAG_DATA: UInt32   = 0x87  // Encrypted data (0x01 prefix = padding indicator)
private let TAG_MAC: UInt32    = 0x8E  // Cryptographic MAC (8 bytes, truncated CMAC)
private let TAG_LE: UInt32     = 0x97  // Expected Le
private let TAG_STATUS: UInt32 = 0x99  // Response status words (SW1 SW2)

// MARK: - ISO 9797-1 Method 2 Padding

/// Pad to 16-byte boundary: append 0x80 then 0x00s.
func smPad(_ data: Data) -> Data {
    var padded = data
    padded.append(0x80)
    while padded.count % 16 != 0 {
        padded.append(0x00)
    }
    return padded
}

/// Remove ISO 9797-1 Method 2 padding.
func smUnpad(_ data: Data) -> Data? {
    guard let idx = data.lastIndex(of: 0x80) else { return nil }
    // All bytes after 0x80 must be 0x00
    for i in (idx + 1)..<data.count {
        if data[i] != 0x00 { return nil }
    }
    return data.prefix(idx)
}

// MARK: - ClientPIVSM

/// Host-side Secure Messaging state machine.
///
/// Wraps outgoing commands and unwraps incoming responses using AES-CBC
/// encryption and AES-CMAC authentication, with counter-derived IVs.
class ClientPIVSM {
    let skEnc: Data    // Encryption key
    let skMAC: Data    // Command MAC key
    let skRMAC: Data   // Response MAC key
    let cipherSuite: CipherSuite

    private(set) var cmdCounter: Int = 0
    private(set) var rspCounter: Int = 0
    private(set) var cmdMCV: Data   // 16-byte message chaining value (commands)
    private(set) var rspMCV: Data   // 16-byte message chaining value (responses)

    init(skEnc: Data, skMAC: Data, skRMAC: Data, cipherSuite: CipherSuite) {
        self.skEnc = skEnc
        self.skMAC = skMAC
        self.skRMAC = skRMAC
        self.cipherSuite = cipherSuite
        self.cmdMCV = Data(count: 16)
        self.rspMCV = Data(count: 16)
    }

    // MARK: - Wrap Command

    /// Wrap a plaintext APDU for SM transmission.
    ///
    /// Returns the complete SM-wrapped APDU as raw bytes.
    func wrapCommand(cla: UInt8, ins: UInt8, p1: UInt8, p2: UInt8,
                     data: Data = Data(), le: Int? = nil,
                     chaining: Bool = false) -> Data {
        cmdCounter += 1

        // SM CLA: set SM bit (0x0C), optionally chaining bit (0x10)
        var smCLA = (cla & 0xF0) | 0x0C
        if chaining { smCLA |= 0x10 }

        // Build SM data field
        var smData = Data()

        // Encrypted data (tag 87)
        if !data.isEmpty {
            let padded = smPad(data)
            let iv = cmdIV()
            let encrypted = PIVCrypto.aesCBCEncrypt(key: skEnc, iv: iv, plaintext: padded)
            // Tag 87 value = 0x01 (padding indicator) || ciphertext
            var tag87Value = Data([0x01])
            tag87Value.append(encrypted)
            smData.append(buildTLV(tag: TAG_DATA, value: tag87Value))
        }

        // Le (tag 97)
        if let le = le {
            if le == 0 || le == 256 {
                smData.append(buildTLV(tag: TAG_LE, value: Data([0x00])))
            } else if le > 256 {
                smData.append(buildTLV(tag: TAG_LE, value: Data([
                    UInt8(le >> 8), UInt8(le & 0xFF)
                ])))
            } else {
                smData.append(buildTLV(tag: TAG_LE, value: Data([UInt8(le)])))
            }
        }

        // Compute MAC: CMAC(skMAC, MCV || pad(header) || data_TLVs)
        let header = smPad(Data([smCLA, ins, p1, p2]))
        var macInput = cmdMCV
        macInput.append(header)
        macInput.append(smData)
        let fullMAC = PIVCrypto.aesCMAC(key: skMAC, data: macInput)

        // Update MCV with full 16-byte MAC
        cmdMCV = fullMAC

        // Append truncated MAC (8 bytes) as tag 8E
        smData.append(buildTLV(tag: TAG_MAC, value: fullMAC.prefix(8)))

        // Build final APDU: CLA INS P1 P2 Lc data 00
        var apdu = Data([smCLA, ins, p1, p2])
        if smData.count <= 255 {
            apdu.append(UInt8(smData.count))
        } else {
            apdu.append(0x00)
            apdu.append(UInt8(smData.count >> 8))
            apdu.append(UInt8(smData.count & 0xFF))
        }
        apdu.append(smData)
        apdu.append(0x00) // Le

        return apdu
    }

    // MARK: - Unwrap Response

    /// Unwrap an SM-protected response.
    ///
    /// - Parameter response: Raw response bytes including trailing SW1 SW2.
    /// - Returns: Tuple of (plaintext data, status word).
    func unwrapResponse(_ response: Data) throws -> (Data, UInt16) {
        rspCounter += 1

        guard response.count >= 2 else {
            throw PIVError.smDecryptFailed
        }

        // Outer SW (should be 9000 for SM)
        let outerSW1 = response[response.count - 2]
        let outerSW2 = response[response.count - 1]
        guard outerSW1 == 0x90, outerSW2 == 0x00 else {
            // Non-9000 outer SW = SM not applied, pass through
            let sw = (UInt16(outerSW1) << 8) | UInt16(outerSW2)
            return (Data(), sw)
        }

        let body = response.prefix(response.count - 2)
        let tlvs = parseTLV(body)

        // Extract components
        var encryptedData: Data? = nil
        var macData: Data? = nil
        var statusData: Data? = nil

        for tlv in tlvs {
            switch tlv.tag {
            case TAG_DATA:
                // Strip 0x01 padding indicator prefix
                if tlv.value.first == 0x01 {
                    encryptedData = tlv.value.dropFirst()
                } else {
                    encryptedData = tlv.value
                }
            case TAG_MAC:
                macData = tlv.value
            case TAG_STATUS:
                statusData = tlv.value
            default:
                break
            }
        }

        // Verify MAC
        guard let mac = macData, mac.count == 8 else {
            throw PIVError.smMACFailed
        }

        // Rebuild MAC input: MCV || everything except tag 8E
        var macInput = rspMCV
        for tlv in tlvs where tlv.tag != TAG_MAC {
            macInput.append(buildTLV(tag: tlv.tag, value: tlv.value))
        }
        let expectedMAC = PIVCrypto.aesCMAC(key: skRMAC, data: macInput)
        rspMCV = expectedMAC

        guard mac == expectedMAC.prefix(8) else {
            throw PIVError.smMACFailed
        }

        // Decrypt data if present
        var plaintext = Data()
        if let ct = encryptedData, !ct.isEmpty {
            let iv = rspIV()
            let decrypted = PIVCrypto.aesCBCDecrypt(key: skEnc, iv: iv, ciphertext: Data(ct))
            guard let unpadded = smUnpad(decrypted) else {
                throw PIVError.smDecryptFailed
            }
            plaintext = unpadded
        }

        // Extract inner SW from tag 99
        let sw: UInt16
        if let status = statusData, status.count >= 2 {
            sw = (UInt16(status[0]) << 8) | UInt16(status[1])
        } else {
            sw = 0x9000
        }

        return (plaintext, sw)
    }

    // MARK: - IV Derivation

    /// Command IV: AES-ECB(skEnc, counter block).
    private func cmdIV() -> Data {
        var block = Data(count: 16)
        // Counter in last 4 bytes, big-endian
        let c = UInt32(cmdCounter)
        block[12] = UInt8((c >> 24) & 0xFF)
        block[13] = UInt8((c >> 16) & 0xFF)
        block[14] = UInt8((c >> 8) & 0xFF)
        block[15] = UInt8(c & 0xFF)
        return PIVCrypto.aesECBEncrypt(key: skEnc, block: block)
    }

    /// Response IV: AES-ECB(skEnc, 0x80 || counter block).
    private func rspIV() -> Data {
        var block = Data(count: 16)
        block[0] = 0x80
        let c = UInt32(rspCounter)
        block[12] = UInt8((c >> 24) & 0xFF)
        block[13] = UInt8((c >> 16) & 0xFF)
        block[14] = UInt8((c >> 8) & 0xFF)
        block[15] = UInt8(c & 0xFF)
        return PIVCrypto.aesECBEncrypt(key: skEnc, block: block)
    }
}
