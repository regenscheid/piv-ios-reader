import Foundation

// MARK: - SM Key Establishment (SP 800-73-5 Section 4.1)

/// Perform ECDH One-Pass key establishment to create an SM session.
///
/// Protocol steps:
/// 1. Generate ephemeral ECC key pair
/// 2. Send GENERAL AUTHENTICATE with ephemeral public key + host identity
/// 3. Parse card response (nonce, auth cryptogram, CVC)
/// 4. Extract card's static public key from CVC
/// 5. Compute ECDH shared secret Z
/// 6. Derive session keys via Concat KDF
/// 7. Verify card's auth cryptogram
/// 8. Return ClientPIVSM with session keys
///
/// - Parameters:
///   - session: Active transport session (must have PIV selected).
///   - cipherSuite: CS2 (P-256/AES-128) or CS7 (P-384/AES-256).
///   - idSH: Host identity (8 bytes, default all zeros).
/// - Returns: Configured ClientPIVSM ready for SM wrapping.
func performSMKeyEstablishment(
    session: Session,
    cipherSuite: CipherSuite = .cs2,
    idSH: Data = Data(count: 8)
) async throws -> ClientPIVSM {

    let curve = cipherSuite.curve

    // Step 1: Generate ephemeral key pair
    let keyPair = try PIVCrypto.ecdhGenerateKeyPair(curve: curve)
    let ephPublicPoint = keyPair.publicPoint

    // Step 2: Build and send GENERAL AUTHENTICATE
    // CB_H = control byte (0x00 = no persistent binding), ID_sH = host identity, Q_eH = ephemeral public point
    let cbH: UInt8 = 0x00
    var tag81Value = Data([cbH])
    tag81Value.append(idSH)
    tag81Value.append(ephPublicPoint)

    let innerPayload = buildTLV(tag: 0x81, value: tag81Value)
        + buildTLV(tag: 0x82, value: Data())  // empty tag 82 = request response

    let apdu = buildGeneralAuthenticate(
        mode: .keyEstablish,
        algorithmRef: String(format: "%02X", cipherSuite.rawValue),
        keyRef: "04",  // SM_CARD_AUTH slot
        dataPayload: innerPayload
    )

    let resp = try await session.transmit(apdu)
    guard resp.success else {
        throw PIVError.smEstablishmentFailed("GA failed: \(resp.swHex)")
    }

    // Step 3: Parse response — 7C { 82 [CB_ICC || N_ICC || AuthCryptogram || C_ICC] }
    let tlvs = parseTLV(resp.data)
    guard let template = findTag(tlvs, 0x7C),
          let tag82 = findTag(template.children(), 0x82) else {
        throw PIVError.smEstablishmentFailed("Missing 7C/82 in response")
    }

    let responseData = tag82.value
    guard responseData.count > 1 else {
        throw PIVError.smEstablishmentFailed("Empty tag 82 response")
    }

    // Parse: CB_ICC (1 byte) || N_ICC (16 or 24 bytes) || AuthCryptogram (16 bytes) || C_ICC (rest)
    let cbICC = responseData[0]
    let nonceLen = cipherSuite.nonceLength
    let macLen = 16
    let headerLen = 1 + nonceLen + macLen

    guard responseData.count > headerLen else {
        throw PIVError.smEstablishmentFailed("Response too short")
    }

    let nICC = responseData[1..<(1 + nonceLen)]
    let authCryptogram = responseData[(1 + nonceLen)..<(1 + nonceLen + macLen)]
    let cICC = responseData[headerLen...]

    // Step 4: Extract card static public key from CVC
    let cICCData = Data(cICC)
    let qSICC = try extractPublicKeyFromCVC(cICCData, curve: curve)

    // Step 5: ECDH shared secret
    let z = try keyPair.computeSharedSecret(qSICC)

    // Step 6: ID_sICC = leftmost 8 bytes of SHA-256(C_ICC)
    let idSICC = PIVCrypto.sha256(cICCData).prefix(8)

    // Step 7: KDF — derive SK_CFRM, SK_MAC, SK_ENC, SK_RMAC
    let keyMaterial = concatKDF(
        z: z,
        cipherSuite: cipherSuite,
        idSH: idSH,
        cbH: cbH,
        ephPublicPoint: ephPublicPoint,
        idSICC: Data(idSICC),
        nICC: Data(nICC),
        cbICC: cbICC
    )

    let keyLen = cipherSuite.keyLength
    let skCFRM = keyMaterial[0..<keyLen]
    let skMAC  = keyMaterial[keyLen..<(keyLen * 2)]
    let skENC  = keyMaterial[(keyLen * 2)..<(keyLen * 3)]
    let skRMAC = keyMaterial[(keyLen * 3)..<(keyLen * 4)]

    // Step 8: Verify AuthCryptogram
    // AuthCryptogram = CMAC(SK_CFRM, "KC_1_V" || ID_sICC || ID_sH || Q_eH)
    // Q_eH in MacData = X||Y coordinates only (no 04 prefix), per SP 800-73-5 §4.1.7
    var authInput = Data("KC_1_V".utf8)
    authInput.append(Data(idSICC))
    authInput.append(idSH)
    authInput.append(ephPublicPoint.dropFirst())  // X||Y coordinates without 04 prefix

    let expectedAuth = PIVCrypto.aesCMAC(key: Data(skCFRM), data: authInput)
    guard Data(authCryptogram) == expectedAuth.prefix(macLen) else {
        throw PIVError.smEstablishmentFailed("AuthCryptogram verification failed")
    }

    // Step 8: Return SM session
    return ClientPIVSM(
        skEnc: Data(skENC),
        skMAC: Data(skMAC),
        skRMAC: Data(skRMAC),
        cipherSuite: cipherSuite
    )
}

// MARK: - Concat KDF (SP 800-56A §5.8.1)

/// Derive key material using the Concatenation KDF.
func concatKDF(
    z: Data,
    cipherSuite: CipherSuite,
    idSH: Data,
    cbH: UInt8,
    ephPublicPoint: Data,
    idSICC: Data,
    nICC: Data,
    cbICC: UInt8
) -> Data {
    // Build OtherInfo per SP 800-73-5 §4.1.6
    var otherInfo = Data()

    // AlgorithmID: length || value
    let algID = cipherSuite.kdfAlgorithmID
    otherInfo.append(UInt8(algID.count))
    otherInfo.append(algID)

    // PartyUInfo (host): 0x08 || ID_sH || 0x01 || CB_H || 0x10 || T16(Q_eH)
    otherInfo.append(UInt8(idSH.count))
    otherInfo.append(idSH)
    otherInfo.append(0x01)
    otherInfo.append(cbH)
    // T16 = first 16 bytes of ephemeral public key coordinates (skip 04 prefix)
    let t16 = ephPublicPoint.dropFirst().prefix(16)
    otherInfo.append(UInt8(t16.count))
    otherInfo.append(t16)

    // PartyVInfo (card): len || ID_sICC || len || N_ICC || 0x01 || CB_ICC
    otherInfo.append(UInt8(idSICC.count))
    otherInfo.append(idSICC)
    otherInfo.append(UInt8(nICC.count))
    otherInfo.append(nICC)
    otherInfo.append(0x01)
    otherInfo.append(cbICC)

    // Hash iterations: counter(4 bytes BE) || Z || OtherInfo
    let hashLen = cipherSuite.hashLength
    let needed = cipherSuite.kdfOutputLength
    let iterations = (needed + hashLen - 1) / hashLen

    var output = Data()
    for i in 1...iterations {
        var input = Data()
        // Counter as 4-byte big-endian
        input.append(UInt8((i >> 24) & 0xFF))
        input.append(UInt8((i >> 16) & 0xFF))
        input.append(UInt8((i >> 8) & 0xFF))
        input.append(UInt8(i & 0xFF))
        input.append(z)
        input.append(otherInfo)
        output.append(PIVCrypto.hash(input, algorithm: cipherSuite.hashAlgorithm))
    }

    return output.prefix(needed)
}

// MARK: - CVC Parsing

/// Extract the uncompressed EC public point from a Card Verifiable Certificate.
///
/// Supports two CVC formats:
/// - Flat: 7F21 → 7F49 → 86
/// - BSI/EAC with 7F4E wrapper: 7F21 → 7F4E → 7F49 → 86
func extractPublicKeyFromCVC(_ cvc: Data, curve: ECCurve) throws -> Data {
    let tlvs = parseTLV(cvc)

    // Try finding 86 (public key point) recursively
    if let pointTLV = findTagRecursive(tlvs, 0x86) {
        let point = pointTLV.value
        guard point.count == curve.pointSize, point.first == 0x04 else {
            throw PIVError.smEstablishmentFailed(
                "Invalid EC point in CVC: expected \(curve.pointSize) bytes, got \(point.count)")
        }
        return point
    }

    throw PIVError.smEstablishmentFailed("No public key (tag 86) found in CVC")
}
