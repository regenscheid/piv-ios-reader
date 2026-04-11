import Foundation
import CommonCrypto
import Security

// MARK: - Algorithm Detection

/// Detected asymmetric algorithm from a certificate's public key.
enum DetectedAlgorithm {
    case rsa2048
    case rsa3072
    case eccP256
    case eccP384

    var pivAlgorithm: PIVAlgorithm {
        switch self {
        case .rsa2048: return .rsa2048
        case .rsa3072: return .rsa3072
        case .eccP256: return .eccP256
        case .eccP384: return .eccP384
        }
    }

    var label: String { pivAlgorithm.label }

    /// RSA modulus size in bytes, or ECC coordinate size.
    var keySizeBytes: Int {
        switch self {
        case .rsa2048: return 256
        case .rsa3072: return 384
        case .eccP256: return 32
        case .eccP384: return 48
        }
    }

    /// Hash algorithm: SHA-256 for RSA-2048/P-256, SHA-384 for RSA-3072/P-384.
    var usesSHA384: Bool {
        switch self {
        case .rsa3072, .eccP384: return true
        case .rsa2048, .eccP256: return false
        }
    }

    var digestLength: Int { usesSHA384 ? 48 : 32 }

    var isRSA: Bool {
        switch self {
        case .rsa2048, .rsa3072: return true
        case .eccP256, .eccP384: return false
        }
    }
}

// MARK: - Challenge-Response Result

struct ChallengeResponseResult {
    let success: Bool
    let algorithm: String
    let error: String?
}

// MARK: - Challenge-Response

/// Implements PIV card authentication via GENERAL AUTHENTICATE (internal authenticate).
///
/// Protocol:
/// 1. Generate random challenge, hash it
/// 2. For RSA: build PKCS#1 v1.5 padded block. For ECC: use raw digest.
/// 3. Send GA to card slot 9E (no PIN required)
/// 4. Verify returned signature against certificate's public key
enum ChallengeResponse {

    /// Detect the algorithm from a certificate's public key using Security.framework.
    static func detectAlgorithm(certDER: Data) -> DetectedAlgorithm? {
        guard let secCert = SecCertificateCreateWithData(nil, certDER as CFData),
              let secKey = SecCertificateCopyKey(secCert) else {
            return nil
        }

        guard let attributes = SecKeyCopyAttributes(secKey) as? [CFString: Any],
              let keyType = attributes[kSecAttrKeyType] as? String,
              let keySizeBits = attributes[kSecAttrKeySizeInBits] as? Int else {
            return nil
        }

        if keyType == (kSecAttrKeyTypeRSA as String) {
            return keySizeBits <= 2048 ? .rsa2048 : .rsa3072
        }

        if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) {
            return keySizeBits <= 256 ? .eccP256 : .eccP384
        }

        return nil
    }

    // MARK: - PKCS#1 v1.5 Padding

    // ASN.1 DigestInfo prefixes (from pivlib/crypto/operations.py)
    private static let digestInfoSHA256: [UInt8] = [
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
    ]
    private static let digestInfoSHA384: [UInt8] = [
        0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
    ]

    /// Build PKCS#1 v1.5 padded block for RSA signing.
    ///
    /// The card performs raw RSA (modular exponentiation only), so the host
    /// must supply the fully padded block: `00 01 FF...FF 00 DigestInfo(digest)`
    static func pkcs1v15PadForSign(digest: Data, useSHA384: Bool, keySizeBytes: Int) -> Data {
        let prefix = Data(useSHA384 ? digestInfoSHA384 : digestInfoSHA256)
        let digestInfo = prefix + digest
        let padLen = keySizeBytes - digestInfo.count - 3 // 00 01 ... 00
        var padded = Data([0x00, 0x01])
        padded.append(Data(repeating: 0xFF, count: padLen))
        padded.append(0x00)
        padded.append(digestInfo)
        return padded
    }

    // MARK: - Hash

    /// Compute SHA-256 or SHA-384 digest.
    private static func computeDigest(_ data: Data, useSHA384: Bool) -> Data {
        if useSHA384 {
            return PIVCrypto.sha384(data)
        } else {
            return PIVCrypto.sha256(data)
        }
    }

    // MARK: - Signature Verification

    /// Verify a signature against a certificate's public key using Security.framework.
    ///
    /// - For RSA: verifies PKCS#1 v1.5 signature over digest
    /// - For ECC: verifies ECDSA DER-encoded (r, s) signature over digest
    static func verifySignature(
        certDER: Data,
        signature: Data,
        digest: Data,
        algorithm: DetectedAlgorithm
    ) -> Bool {
        guard let secCert = SecCertificateCreateWithData(nil, certDER as CFData),
              let secKey = SecCertificateCopyKey(secCert) else {
            return false
        }

        let secAlgorithm: SecKeyAlgorithm
        if algorithm.isRSA {
            secAlgorithm = algorithm.usesSHA384
                ? .rsaSignatureDigestPKCS1v15SHA384
                : .rsaSignatureDigestPKCS1v15SHA256
        } else {
            secAlgorithm = algorithm.usesSHA384
                ? .ecdsaSignatureDigestX962SHA384
                : .ecdsaSignatureDigestX962SHA256
        }

        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(
            secKey,
            secAlgorithm,
            digest as CFData,
            signature as CFData,
            &error
        )

        return result
    }

    // MARK: - Perform Challenge-Response

    /// Perform a full challenge-response against the card authentication slot (9E).
    ///
    /// 1. Detect algorithm from certificate
    /// 2. Generate random challenge, hash it
    /// 3. Build payload (PKCS#1 v1.5 for RSA, raw digest for ECC)
    /// 4. Send GENERAL AUTHENTICATE (internal authenticate)
    /// 5. Verify returned signature
    static func performChallengeResponse(
        card: PIVCard,
        certDER: Data
    ) async throws -> ChallengeResponseResult {
        // 1. Detect algorithm
        guard let algorithm = detectAlgorithm(certDER: certDER) else {
            return ChallengeResponseResult(
                success: false, algorithm: "Unknown",
                error: "Could not detect key algorithm from certificate"
            )
        }

        // 2. Generate random challenge and hash it
        var randomBytes = [UInt8](repeating: 0, count: 64)
        guard SecRandomCopyBytes(kSecRandomDefault, 64, &randomBytes) == errSecSuccess else {
            return ChallengeResponseResult(
                success: false, algorithm: algorithm.label,
                error: "Failed to generate random challenge"
            )
        }
        let challenge = Data(randomBytes)
        let digest = computeDigest(challenge, useSHA384: algorithm.usesSHA384)

        // 3. Build payload
        let payload: Data
        if algorithm.isRSA {
            payload = pkcs1v15PadForSign(
                digest: digest,
                useSHA384: algorithm.usesSHA384,
                keySizeBytes: algorithm.keySizeBytes
            )
        } else {
            payload = digest
        }

        // 4. Send GA internal authenticate to slot 9E
        let apdu = buildGeneralAuthenticate(
            mode: .internalAuthenticate,
            algorithmRef: algorithm.pivAlgorithm.hex,
            keyRef: PIVSlot.cardAuthentication.hex,
            challenge: payload
        )
        let resp = try await card.transmit(apdu)

        guard resp.success else {
            return ChallengeResponseResult(
                success: false, algorithm: algorithm.label,
                error: "GA failed: \(resp.swHex)"
            )
        }

        // 5. Extract signature from response (tag 82 inside 7C)
        guard let signature = extractGASignature(resp) else {
            return ChallengeResponseResult(
                success: false, algorithm: algorithm.label,
                error: "No signature in GA response"
            )
        }

        // 6. Verify signature
        let verified = verifySignature(
            certDER: certDER,
            signature: signature,
            digest: digest,
            algorithm: algorithm
        )

        if verified {
            return ChallengeResponseResult(
                success: true, algorithm: algorithm.label, error: nil
            )
        } else {
            return ChallengeResponseResult(
                success: false, algorithm: algorithm.label,
                error: "Signature verification failed"
            )
        }
    }
}
