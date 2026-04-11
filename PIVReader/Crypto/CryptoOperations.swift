import Foundation
import CommonCrypto
import CryptoKit
import Security
import X509
import SwiftASN1

// MARK: - CryptoOperations
//
// This file provides the cryptographic primitives needed for PIV Secure
// Messaging.  AES-CBC and SHA use CommonCrypto.  ECDH uses CryptoKit.
// Certificate operations use swift-certificates and Security.framework.
//

struct PIVCrypto {

    // MARK: - AES-CBC (no padding — caller handles ISO 9797-1 padding)

    /// AES-CBC encrypt with no padding. Plaintext must be a multiple of 16 bytes.
    static func aesCBCEncrypt(key: Data, iv: Data, plaintext: Data) -> Data {
        precondition(plaintext.count % 16 == 0, "Plaintext must be block-aligned")
        var outBuffer = Data(count: plaintext.count + kCCBlockSizeAES128)
        var outLength = 0
        let outBufferCount = outBuffer.count

        let status = key.withUnsafeBytes { keyPtr in
            iv.withUnsafeBytes { ivPtr in
                plaintext.withUnsafeBytes { inPtr in
                    outBuffer.withUnsafeMutableBytes { outPtr in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(0),  // No padding
                            keyPtr.baseAddress, key.count,
                            ivPtr.baseAddress,
                            inPtr.baseAddress, plaintext.count,
                            outPtr.baseAddress, outBufferCount,
                            &outLength
                        )
                    }
                }
            }
        }
        precondition(status == kCCSuccess, "AES-CBC encrypt failed: \(status)")
        return outBuffer.prefix(outLength)
    }

    /// AES-CBC decrypt with no padding. Ciphertext must be a multiple of 16 bytes.
    static func aesCBCDecrypt(key: Data, iv: Data, ciphertext: Data) -> Data {
        precondition(ciphertext.count % 16 == 0, "Ciphertext must be block-aligned")
        var outBuffer = Data(count: ciphertext.count + kCCBlockSizeAES128)
        var outLength = 0
        let outBufferCount = outBuffer.count

        let status = key.withUnsafeBytes { keyPtr in
            iv.withUnsafeBytes { ivPtr in
                ciphertext.withUnsafeBytes { inPtr in
                    outBuffer.withUnsafeMutableBytes { outPtr in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(0),
                            keyPtr.baseAddress, key.count,
                            ivPtr.baseAddress,
                            inPtr.baseAddress, ciphertext.count,
                            outPtr.baseAddress, outBufferCount,
                            &outLength
                        )
                    }
                }
            }
        }
        precondition(status == kCCSuccess, "AES-CBC decrypt failed: \(status)")
        return outBuffer.prefix(outLength)
    }

    /// AES-ECB encrypt a single 16-byte block (used for IV derivation).
    static func aesECBEncrypt(key: Data, block: Data) -> Data {
        precondition(block.count == 16, "ECB block must be 16 bytes")
        var outBuffer = Data(count: 32)
        var outLength = 0
        let outBufferCount = outBuffer.count

        let status = key.withUnsafeBytes { keyPtr in
            block.withUnsafeBytes { inPtr in
                outBuffer.withUnsafeMutableBytes { outPtr in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode),
                        keyPtr.baseAddress, key.count,
                        nil,
                        inPtr.baseAddress, block.count,
                        outPtr.baseAddress, outBufferCount,
                        &outLength
                    )
                }
            }
        }
        precondition(status == kCCSuccess, "AES-ECB encrypt failed: \(status)")
        return outBuffer.prefix(16)
    }

    // MARK: - AES-CMAC (RFC 4493)
    //
    // Implements CMAC using AES-ECB subkey derivation per the RFC.

    /// AES-CMAC producing a full 16-byte MAC.
    static func aesCMAC(key: Data, data: Data) -> Data {
        // Generate subkeys K1, K2
        let zero = Data(count: 16)
        let l = aesECBEncrypt(key: key, block: zero)
        let k1 = shiftLeft(l)
        let k2 = shiftLeft(k1)

        let n = data.count
        let blockCount = max((n + 15) / 16, 1)
        let lastBlockComplete = (n > 0) && (n % 16 == 0)

        // Build last block with XOR of K1 or K2
        var lastBlock: Data
        if lastBlockComplete {
            let start = (blockCount - 1) * 16
            lastBlock = Data(data[start..<(start + 16)])
            lastBlock = xor(lastBlock, k1)
        } else {
            let start = (blockCount - 1) * 16
            var partial = Data(data[start...])
            // Pad: append 0x80 then zeros
            partial.append(0x80)
            while partial.count < 16 { partial.append(0x00) }
            lastBlock = xor(partial, k2)
        }

        // CBC-MAC
        var x = Data(count: 16) // IV = zeros
        for i in 0..<(blockCount - 1) {
            let block = Data(data[(i * 16)..<((i + 1) * 16)])
            x = aesECBEncrypt(key: key, block: xor(x, block))
        }
        x = aesECBEncrypt(key: key, block: xor(x, lastBlock))

        return x
    }

    // MARK: - SHA

    static func sha256(_ data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { ptr in
            _ = CC_SHA256(ptr.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }

    static func sha384(_ data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA384_DIGEST_LENGTH))
        data.withUnsafeBytes { ptr in
            _ = CC_SHA384(ptr.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }

    static func hash(_ data: Data, algorithm: HashAlgorithm) -> Data {
        switch algorithm {
        case .sha256: return sha256(data)
        case .sha384: return sha384(data)
        }
    }

    // MARK: - ECDH (CryptoKit)

    /// Type-erased wrapper for CryptoKit key agreement results, allowing
    /// `performSMKeyEstablishment` to work with both P-256 and P-384.
    struct ECDHKeyPair {
        /// Uncompressed public point (0x04 || x || y).
        let publicPoint: Data
        /// Computes the ECDH shared secret Z given a peer's uncompressed public point.
        let computeSharedSecret: (Data) throws -> Data
    }

    /// Generate an ephemeral EC key pair for ECDH key agreement.
    ///
    /// Returns an `ECDHKeyPair` containing the public point and a closure
    /// that computes the shared secret given a peer's uncompressed public point.
    static func ecdhGenerateKeyPair(curve: ECCurve) throws -> ECDHKeyPair {
        switch curve {
        case .p256:
            let privateKey = P256.KeyAgreement.PrivateKey()
            // CryptoKit rawRepresentation is x||y without 0x04 prefix
            let publicPoint = Data([0x04]) + privateKey.publicKey.rawRepresentation
            return ECDHKeyPair(publicPoint: publicPoint) { peerPublicPoint in
                // Strip 0x04 prefix for CryptoKit
                let peerRaw = peerPublicPoint.dropFirst()
                let peerKey = try P256.KeyAgreement.PublicKey(rawRepresentation: peerRaw)
                let shared = try privateKey.sharedSecretFromKeyAgreement(with: peerKey)
                return shared.withUnsafeBytes { Data($0) }
            }
        case .p384:
            let privateKey = P384.KeyAgreement.PrivateKey()
            let publicPoint = Data([0x04]) + privateKey.publicKey.rawRepresentation
            return ECDHKeyPair(publicPoint: publicPoint) { peerPublicPoint in
                let peerRaw = peerPublicPoint.dropFirst()
                let peerKey = try P384.KeyAgreement.PublicKey(rawRepresentation: peerRaw)
                let shared = try privateKey.sharedSecretFromKeyAgreement(with: peerKey)
                return shared.withUnsafeBytes { Data($0) }
            }
        }
    }

    // MARK: - Certificate Info Helpers

    /// Extract the issuer name from a DER certificate using swift-certificates.
    static func getCertIssuerName(_ certDER: Data) -> String? {
        do {
            let cert = try X509.Certificate(derEncoded: Array(certDER))
            return String(describing: cert.issuer)
        } catch {
            return nil
        }
    }

    // MARK: - Certificate Signature Verification

    /// Verify a certificate's signature against a set of potential issuer certificates.
    ///
    /// Returns the issuer subject name if signature is valid, nil otherwise.
    /// Uses SecTrust for mathematical signature verification.
    static func verifyCertificateSignature(
        certDER: Data,
        issuerCandidateDERs: [Data]
    ) -> String? {
        guard let leafCert = SecCertificateCreateWithData(nil, certDER as CFData) else {
            return nil
        }

        for issuerDER in issuerCandidateDERs {
            guard let issuerCert = SecCertificateCreateWithData(nil, issuerDER as CFData) else {
                continue
            }

            // Build a minimal chain: leaf + candidate issuer
            let policy = SecPolicyCreateBasicX509()
            var trust: SecTrust?
            let status = SecTrustCreateWithCertificates(
                [leafCert, issuerCert] as CFArray,
                policy,
                &trust
            )
            guard status == errSecSuccess, let trust else { continue }

            // Set the candidate issuer as the trust anchor
            SecTrustSetAnchorCertificates(trust, [issuerCert] as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, true)

            if SecTrustEvaluateWithError(trust, nil) {
                // Signature valid — extract issuer subject name
                do {
                    let cert = try X509.Certificate(derEncoded: Array(issuerDER))
                    return String(describing: cert.subject)
                } catch {
                    return "Unknown Issuer"
                }
            }
        }

        return nil
    }

    /// Check if a certificate is self-signed (issuer == subject and signature verifies with own key).
    static func isSelfSigned(certDER: Data) -> Bool {
        do {
            let cert = try X509.Certificate(derEncoded: Array(certDER))
            guard cert.issuer == cert.subject else { return false }

            // Verify signature with own key via SecTrust
            guard let secCert = SecCertificateCreateWithData(nil, certDER as CFData) else {
                return false
            }
            let policy = SecPolicyCreateBasicX509()
            var trust: SecTrust?
            let status = SecTrustCreateWithCertificates(
                [secCert] as CFArray, policy, &trust
            )
            guard status == errSecSuccess, let trust else { return false }
            SecTrustSetAnchorCertificates(trust, [secCert] as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, true)
            return SecTrustEvaluateWithError(trust, nil)
        } catch {
            return false
        }
    }

    // MARK: - PKCS#7 Parsing

    /// Parse a PKCS#7 (.p7b) bundle (PEM or DER) and extract all X.509 certificates.
    ///
    /// Parses the PKCS#7 ContentInfo/SignedData ASN.1 structure using SwiftASN1
    /// and extracts embedded certificates as DER-encoded Data.
    static func parsePKCS7Certificates(_ p7bData: Data) throws -> [Data] {
        // Detect PEM vs DER: PEM starts with "-----BEGIN"
        let derBytes: [UInt8]
        if p7bData.prefix(10).starts(with: Data("-----BEGIN".utf8)) {
            guard let pemString = String(data: p7bData, encoding: .utf8) else {
                throw PIVError.certificateParseFailed("Invalid PEM encoding")
            }
            let pemDoc = try PEMDocument(pemString: pemString)
            derBytes = Array(pemDoc.derBytes)
        } else {
            derBytes = Array(p7bData)
        }

        // Parse ContentInfo SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
        let parsed = try DER.parse(derBytes)
        let contentInfo = try DER.sequence(parsed, identifier: .sequence) { nodes in
            let contentType = try ASN1ObjectIdentifier(derEncoded: &nodes)
            // content is [0] EXPLICIT — context tag 0, constructed
            let contentNode = try DER.explicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { node in
                return node
            }
            return (contentType, contentNode)
        }

        // Verify this is signedData (1.2.840.113549.1.7.2)
        let signedDataOID: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 7, 2]
        guard contentInfo.0 == signedDataOID else {
            throw PIVError.certificateParseFailed("Not a PKCS#7 SignedData (OID: \(contentInfo.0))")
        }

        // Parse SignedData SEQUENCE { version, digestAlgorithms, encapContentInfo,
        //   certificates [0] IMPLICIT ..., crls [1] IMPLICIT ..., signerInfos }
        let signedDataNode = contentInfo.1
        guard case .constructed(let signedDataChildren) = signedDataNode.content else {
            throw PIVError.certificateParseFailed("SignedData is not a constructed SEQUENCE")
        }

        var certs = [Data]()
        let certTag = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)

        for node in signedDataChildren {
            if node.identifier == certTag, case .constructed(let certNodes) = node.content {
                // Each child is a DER-encoded Certificate
                for certNode in certNodes {
                    var serializer = DER.Serializer()
                    try serializer.serialize(certNode)
                    certs.append(Data(serializer.serializedBytes))
                }
                break
            }
        }

        return certs
    }

    // MARK: - CMAC Helpers

    /// Left-shift a 16-byte block by 1 bit, XOR with 0x87 if MSB was set (GF(2^128)).
    private static func shiftLeft(_ data: Data) -> Data {
        var result = Data(count: 16)
        var carry: UInt8 = 0
        for i in stride(from: 15, through: 0, by: -1) {
            result[i] = (data[i] << 1) | carry
            carry = (data[i] & 0x80) != 0 ? 1 : 0
        }
        if (data[0] & 0x80) != 0 {
            result[15] ^= 0x87
        }
        return result
    }

    /// XOR two equal-length Data values.
    private static func xor(_ a: Data, _ b: Data) -> Data {
        precondition(a.count == b.count)
        return Data(zip(a, b).map { $0 ^ $1 })
    }
}
