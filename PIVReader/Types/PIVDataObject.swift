import Foundation
import CommonCrypto

/// Base protocol for parsed PIV card response objects.
protocol PIVDataObject {
    var rawData: Data { get }
    var tag: UInt32 { get }
    var name: String { get }
}

// MARK: - PIVCertificate

/// Parsed PIV certificate container (GET DATA on a cert slot).
struct PIVCertificate: PIVDataObject {
    let rawData: Data
    let tag: UInt32
    let name: String
    let certDER: Data
    let compressed: Bool
    let certInfoByte: UInt8?
    let errorDetectionCode: Data?

    /// Summarize the X.509 certificate using Security.framework.
    func summarize() -> CertificateSummary? {
        guard let secCert = SecCertificateCreateWithData(nil, certDER as CFData) else {
            return nil
        }
        let subject = SecCertificateCopySubjectSummary(secCert) as String? ?? "Unknown"
        // SecCertificate provides limited parsing; for full details
        // you would parse the DER ASN.1 directly or use swift-certificates.
        return CertificateSummary(
            subject: subject,
            derLength: certDER.count,
            compressed: compressed,
            fingerprint: sha256Hex(certDER)
        )
    }
}

/// Summary of a parsed X.509 certificate.
struct CertificateSummary {
    let subject: String
    let derLength: Int
    let compressed: Bool
    let fingerprint: String // SHA-256 hex
    var chainValidation: ValidationResult = .notEvaluated
    var signatureVerified: Bool = false  // true if signature verified against a known issuer
    var issuerName: String? = nil        // issuer that verified the signature
}

// MARK: - PIVPublicKey

/// Parsed public key from GENERATE ASYMMETRIC KEY PAIR.
struct PIVPublicKey: PIVDataObject {
    let rawData: Data
    let tag: UInt32
    let name: String
    let keyType: String     // "ECC" or "RSA"
    let algorithmHex: String
    let ecPoint: Data?      // 04 || X || Y (uncompressed)
    let rsaModulus: Data?
    let rsaExponent: Data?

    var keySizeBits: Int? {
        if let pt = ecPoint {
            let coordLen = (pt.count - 1) / 2
            return coordLen * 8
        }
        if let mod = rsaModulus {
            return mod.count * 8
        }
        return nil
    }
}

// MARK: - Helpers

private func sha256Hex(_ data: Data) -> String {
    var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    data.withUnsafeBytes { ptr in
        _ = CC_SHA256(ptr.baseAddress, CC_LONG(data.count), &hash)
    }
    return hash.map { String(format: "%02x", $0) }.joined()
}
