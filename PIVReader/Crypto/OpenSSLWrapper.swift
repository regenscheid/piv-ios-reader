import Foundation
import CommonCrypto
import OpenSSL

// MARK: - OpenSSLCrypto
//
// This file provides the cryptographic primitives needed for PIV Secure
// Messaging.  The real implementation would call OpenSSL (libcrypto) via
// C-interop for CMAC and ECDH.  The stubs below document the exact API
// surface required; AES-CBC and SHA are implemented using CommonCrypto
// (always available on iOS) as a working baseline.
//
// To complete the OpenSSL integration:
// 1. Add an OpenSSL XCFramework via SPM (e.g. OpenSSL-Swift)
// 2. Replace the CMAC and ECDH stubs with EVP calls
//

struct OpenSSLCrypto {

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
    // REQUIRES OpenSSL. This stub implements CMAC using AES-ECB per the RFC.
    // Replace with CMAC_CTX calls for production use.

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

    // MARK: - ECDH (OpenSSL 3.x EVP_PKEY API)

    /// Map ECCurve to the OpenSSL curve name string.
    private static func curveName(for curve: ECCurve) -> String {
        switch curve {
        case .p256: return "P-256"
        case .p384: return "P-384"
        }
    }

    /// Generate an ephemeral EC key pair. Returns (privateKeyBytes, uncompressedPublicPoint).
    static func ecdhGenerateKeyPair(curve: ECCurve) throws -> (privateKey: Data, publicPoint: Data) {
        let name = curveName(for: curve)

        // Build params with curve name, then keygen
        let bldGen = OSSL_PARAM_BLD_new()!
        defer { OSSL_PARAM_BLD_free(bldGen) }
        name.withCString { OSSL_PARAM_BLD_push_utf8_string(bldGen, "group", $0, 0) }
        guard let genParams = OSSL_PARAM_BLD_to_param(bldGen) else {
            throw PIVError.smEstablishmentFailed("OSSL_PARAM_BLD_to_param (keygen) failed")
        }
        defer { OSSL_PARAM_free(genParams) }

        guard let ctx = EVP_PKEY_CTX_new_from_name(nil, "EC", nil) else {
            throw PIVError.smEstablishmentFailed("EVP_PKEY_CTX_new_from_name failed")
        }
        defer { EVP_PKEY_CTX_free(ctx) }

        guard EVP_PKEY_keygen_init(ctx) == 1 else {
            throw PIVError.smEstablishmentFailed("EVP_PKEY_keygen_init failed")
        }
        guard EVP_PKEY_CTX_set_params(ctx, genParams) == 1 else {
            throw PIVError.smEstablishmentFailed("EVP_PKEY_CTX_set_params failed")
        }

        var pkey: OpaquePointer? // EVP_PKEY*
        guard EVP_PKEY_keygen(ctx, &pkey) == 1, let pkey else {
            throw PIVError.smEstablishmentFailed("EVP_PKEY_keygen failed")
        }
        defer { EVP_PKEY_free(pkey) }

        // Extract private key as BIGNUM
        var bn: OpaquePointer? // BIGNUM*
        guard EVP_PKEY_get_bn_param(pkey, "priv", &bn) == 1, let bn else {
            throw PIVError.smEstablishmentFailed("EVP_PKEY_get_bn_param(priv) failed")
        }
        defer { BN_free(bn) }

        var privBytes = [UInt8](repeating: 0, count: curve.coordSize)
        guard BN_bn2binpad(bn, &privBytes, Int32(curve.coordSize)) == Int32(curve.coordSize) else {
            throw PIVError.smEstablishmentFailed("BN_bn2binpad failed")
        }

        // Extract public point (uncompressed)
        var pubLen = 0
        guard EVP_PKEY_get_octet_string_param(pkey, "encoded-pub-key", nil, 0, &pubLen) == 1,
              pubLen == curve.pointSize else {
            throw PIVError.smEstablishmentFailed("EVP_PKEY_get_octet_string_param(encoded-pub-key) size check failed")
        }
        var pubBytes = [UInt8](repeating: 0, count: pubLen)
        guard EVP_PKEY_get_octet_string_param(pkey, "encoded-pub-key", &pubBytes, pubLen, &pubLen) == 1 else {
            throw PIVError.smEstablishmentFailed("EVP_PKEY_get_octet_string_param(encoded-pub-key) failed")
        }

        return (Data(privBytes), Data(pubBytes))
    }

    /// Build an EVP_PKEY from raw private key bytes + curve name using OSSL_PARAM.
    private static func evpPKeyFromPrivateKey(_ privateKey: Data, curve: ECCurve) throws -> OpaquePointer {
        let name = curveName(for: curve)

        guard let ctx = EVP_PKEY_CTX_new_from_name(nil, "EC", nil) else {
            throw PIVError.smEstablishmentFailed("EVP_PKEY_CTX_new_from_name failed")
        }
        defer { EVP_PKEY_CTX_free(ctx) }

        guard EVP_PKEY_fromdata_init(ctx) == 1 else {
            throw PIVError.smEstablishmentFailed("EVP_PKEY_fromdata_init failed")
        }

        // Build OSSL_PARAM array: group, priv key
        let bld = OSSL_PARAM_BLD_new()!
        defer { OSSL_PARAM_BLD_free(bld) }

        name.withCString { OSSL_PARAM_BLD_push_utf8_string(bld, "group", $0, 0) }

        let privBN = privateKey.withUnsafeBytes { BN_bin2bn($0.baseAddress, Int32(privateKey.count), nil) }
        guard let privBN else {
            throw PIVError.smEstablishmentFailed("BN_bin2bn failed")
        }
        defer { BN_free(privBN) }
        OSSL_PARAM_BLD_push_BN(bld, "priv", privBN)

        guard let params = OSSL_PARAM_BLD_to_param(bld) else {
            throw PIVError.smEstablishmentFailed("OSSL_PARAM_BLD_to_param failed")
        }
        defer { OSSL_PARAM_free(params) }

        var pkey: OpaquePointer? // EVP_PKEY*
        // EVP_PKEY_KEYPAIR = OSSL_KEYMGMT_SELECT_ALL_PARAMETERS(0x84) | PUBLIC_KEY(0x02) | PRIVATE_KEY(0x01) = 0x87
        guard EVP_PKEY_fromdata(ctx, &pkey, Int32(0x87), params) == 1, let pkey else {
            throw PIVError.smEstablishmentFailed("EVP_PKEY_fromdata failed")
        }

        return pkey
    }

    /// Build an EVP_PKEY from a peer's uncompressed public point.
    private static func evpPKeyFromPublicPoint(_ point: Data, curve: ECCurve) throws -> OpaquePointer {
        let name = curveName(for: curve)

        guard let ctx = EVP_PKEY_CTX_new_from_name(nil, "EC", nil) else {
            throw PIVError.smEstablishmentFailed("EVP_PKEY_CTX_new_from_name failed")
        }
        defer { EVP_PKEY_CTX_free(ctx) }

        guard EVP_PKEY_fromdata_init(ctx) == 1 else {
            throw PIVError.smEstablishmentFailed("EVP_PKEY_fromdata_init failed")
        }

        let bld = OSSL_PARAM_BLD_new()!
        defer { OSSL_PARAM_BLD_free(bld) }

        name.withCString { OSSL_PARAM_BLD_push_utf8_string(bld, "group", $0, 0) }
        point.withUnsafeBytes { OSSL_PARAM_BLD_push_octet_string(bld, "pub", $0.baseAddress, point.count) }

        guard let params = OSSL_PARAM_BLD_to_param(bld) else {
            throw PIVError.smEstablishmentFailed("OSSL_PARAM_BLD_to_param failed")
        }
        defer { OSSL_PARAM_free(params) }

        var pkey: OpaquePointer? // EVP_PKEY*
        // EVP_PKEY_PUBLIC_KEY = OSSL_KEYMGMT_SELECT_ALL_PARAMETERS(0x84) | PUBLIC_KEY(0x02) = 0x86
        guard EVP_PKEY_fromdata(ctx, &pkey, Int32(0x86), params) == 1, let pkey else {
            throw PIVError.smEstablishmentFailed("EVP_PKEY_fromdata (pub) failed")
        }

        return pkey
    }

    /// Compute ECDH shared secret Z from private key + peer public point.
    static func ecdhComputeSharedSecret(
        privateKey: Data, peerPublicPoint: Data, curve: ECCurve
    ) throws -> Data {
        let privKey = try evpPKeyFromPrivateKey(privateKey, curve: curve)
        defer { EVP_PKEY_free(privKey) }

        let peerKey = try evpPKeyFromPublicPoint(peerPublicPoint, curve: curve)
        defer { EVP_PKEY_free(peerKey) }

        // Derive shared secret
        guard let dctx = EVP_PKEY_CTX_new(privKey, nil) else {
            throw PIVError.smEstablishmentFailed("EVP_PKEY_CTX_new failed")
        }
        defer { EVP_PKEY_CTX_free(dctx) }

        guard EVP_PKEY_derive_init(dctx) == 1 else {
            throw PIVError.smEstablishmentFailed("EVP_PKEY_derive_init failed")
        }
        guard EVP_PKEY_derive_set_peer(dctx, peerKey) == 1 else {
            throw PIVError.smEstablishmentFailed("EVP_PKEY_derive_set_peer failed")
        }

        // Query output size
        var secretLen = 0
        guard EVP_PKEY_derive(dctx, nil, &secretLen) == 1 else {
            throw PIVError.smEstablishmentFailed("EVP_PKEY_derive (size query) failed")
        }

        var secret = [UInt8](repeating: 0, count: secretLen)
        guard EVP_PKEY_derive(dctx, &secret, &secretLen) == 1 else {
            throw PIVError.smEstablishmentFailed("EVP_PKEY_derive failed")
        }

        return Data(secret.prefix(secretLen))
    }

    // MARK: - Certificate Info Helpers

    /// Extract the issuer name from a DER certificate (for debugging).
    static func getCertIssuerName(_ certDER: Data) -> String? {
        let cert: OpaquePointer? = certDER.withUnsafeBytes { (rawPtr: UnsafeRawBufferPointer) -> OpaquePointer? in
            var ptr: UnsafePointer<UInt8>? = rawPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
            return d2i_X509(nil, &ptr, rawPtr.count)
        }
        guard let cert else { return nil }
        defer { X509_free(cert) }

        guard let issuerName = X509_get_issuer_name(cert) else { return nil }
        guard let oneline = X509_NAME_oneline(issuerName, nil, 0) else { return nil }
        defer { CRYPTO_free(oneline, #file, #line) }
        return String(cString: oneline)
    }

    // MARK: - Certificate Signature Verification

    /// Verify a certificate's signature against a set of potential issuer certificates.
    ///
    /// Returns the issuer subject name if signature is valid, nil otherwise.
    /// This checks ONLY that the signature is mathematically correct — not chain
    /// trust, expiration, or revocation.
    static func verifyCertificateSignature(
        certDER: Data,
        issuerCandidateDERs: [Data]
    ) -> String? {
        // Parse the leaf cert
        let cert: OpaquePointer? = certDER.withUnsafeBytes { (rawPtr: UnsafeRawBufferPointer) -> OpaquePointer? in
            var ptr: UnsafePointer<UInt8>? = rawPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
            return d2i_X509(nil, &ptr, rawPtr.count)
        }
        guard let cert else { return nil }
        defer { X509_free(cert) }

        // Try each candidate as the issuer
        for issuerDER in issuerCandidateDERs {
            let issuer: OpaquePointer? = issuerDER.withUnsafeBytes { (rawPtr: UnsafeRawBufferPointer) -> OpaquePointer? in
                var ptr: UnsafePointer<UInt8>? = rawPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                return d2i_X509(nil, &ptr, rawPtr.count)
            }
            guard let issuer else { continue }
            defer { X509_free(issuer) }

            // Extract issuer's public key and verify cert's signature
            guard let issuerKey = X509_get0_pubkey(issuer) else { continue }

            if X509_verify(cert, issuerKey) == 1 {
                // Signature valid — extract issuer subject name
                guard let namePtr = X509_get_subject_name(issuer) else { return "Unknown Issuer" }
                guard let oneline = X509_NAME_oneline(namePtr, nil, 0) else { return "Unknown Issuer" }
                defer { CRYPTO_free(oneline, #file, #line) }
                return String(cString: oneline)
            }
        }

        return nil
    }

    /// Check if a certificate is self-signed (issuer == subject and signature verifies with own key).
    static func isSelfSigned(certDER: Data) -> Bool {
        let cert: OpaquePointer? = certDER.withUnsafeBytes { (rawPtr: UnsafeRawBufferPointer) -> OpaquePointer? in
            var ptr: UnsafePointer<UInt8>? = rawPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
            return d2i_X509(nil, &ptr, rawPtr.count)
        }
        guard let cert else { return false }
        defer { X509_free(cert) }

        guard let pubkey = X509_get0_pubkey(cert) else { return false }
        return X509_verify(cert, pubkey) == 1
    }

    // MARK: - PKCS#7 Parsing

    /// Parse a PKCS#7 (.p7b) bundle (PEM or DER) and extract all X.509 certificates.
    ///
    /// Used to extract intermediate CA certs from the FPKI bundle.
    static func parsePKCS7Certificates(_ p7bData: Data) throws -> [Data] {
        var certs = [Data]()

        // Detect PEM vs DER: PEM starts with "-----BEGIN"
        let isPEM = p7bData.prefix(10).starts(with: Data("-----BEGIN".utf8))

        let p7: UnsafeMutablePointer<PKCS7>?
        if isPEM {
            // PEM: use BIO + PEM_read_bio_PKCS7
            guard let bio = p7bData.withUnsafeBytes({ BIO_new_mem_buf($0.baseAddress, Int32(p7bData.count)) }) else {
                throw PIVError.certificateParseFailed("BIO_new_mem_buf failed")
            }
            defer { BIO_free(bio) }
            p7 = PEM_read_bio_PKCS7(bio, nil, nil, nil)
        } else {
            // DER: use d2i_PKCS7
            p7 = p7bData.withUnsafeBytes { (rawPtr: UnsafeRawBufferPointer) -> UnsafeMutablePointer<PKCS7>? in
                var ptr: UnsafePointer<UInt8>? = rawPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                return d2i_PKCS7(nil, &ptr, rawPtr.count)
            }
        }

        guard let p7 else {
            throw PIVError.certificateParseFailed("PKCS7 parse failed (isPEM=\(isPEM))")
        }
        defer { PKCS7_free(p7) }

        // Get the certificate stack from the SignedData
        guard let certStack = p7.pointee.d.sign.pointee.cert else {
            return certs // No certs in bundle
        }

        // sk_X509_num / sk_X509_value are C macros; use OPENSSL_sk_* directly
        let count = OPENSSL_sk_num(certStack)
        for i in 0..<count {
            guard let rawX509 = OPENSSL_sk_value(certStack, i) else { continue }
            let x509 = OpaquePointer(rawX509)

            // Serialize X509 to DER
            var derPtr: UnsafeMutablePointer<UInt8>? = nil
            let derLen = i2d_X509(x509, &derPtr)
            guard derLen > 0, let derPtr else { continue }
            defer { CRYPTO_free(derPtr, #file, #line) }

            certs.append(Data(bytes: derPtr, count: Int(derLen)))
        }

        return certs
    }

    // MARK: - FASC-N Extraction from Certificate

    /// OID for FASC-N in subjectAltName: 2.16.840.1.101.3.6.6
    private static let fascnOID = "2.16.840.1.101.3.6.6"

    /// Extract the raw FASC-N bytes from a certificate's subjectAltName extension.
    ///
    /// The FASC-N is stored as an OtherName with OID 2.16.840.1.101.3.6.6,
    /// containing a DER OCTET STRING with the 25-byte FASC-N.
    static func extractFASCNFromCertificate(_ derData: Data) -> Data? {
        return derData.withUnsafeBytes { (rawPtr: UnsafeRawBufferPointer) -> Data? in
            var ptr: UnsafePointer<UInt8>? = rawPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
            guard let x509 = d2i_X509(nil, &ptr, rawPtr.count) else {
                return nil
            }
            defer { X509_free(x509) }

            // Get subjectAltName extension
            guard let sans = X509_get_ext_d2i(x509, NID_subject_alt_name, nil, nil) else {
                return nil
            }
            let generalNames = OpaquePointer(sans) // GENERAL_NAMES* (STACK_OF(GENERAL_NAME))
            defer { GENERAL_NAMES_free(generalNames) }

            // Build the target OID
            guard let targetOID = OBJ_txt2obj(fascnOID, 1) else {
                return nil
            }
            defer { ASN1_OBJECT_free(targetOID) }

            // sk_GENERAL_NAME_num / sk_GENERAL_NAME_value are C macros
            let count = OPENSSL_sk_num(generalNames)
            for i in 0..<count {
                guard let rawGN = OPENSSL_sk_value(generalNames, i) else { continue }
                let gn = UnsafeMutablePointer<GENERAL_NAME>(OpaquePointer(rawGN))

                // Check for OtherName type
                guard gn.pointee.type == GEN_OTHERNAME else { continue }

                let otherName = gn.pointee.d.otherName!

                // Compare OID
                guard OBJ_cmp(otherName.pointee.type_id, targetOID) == 0 else { continue }

                // Extract the value — it's an ASN1_TYPE wrapping an OCTET STRING
                guard let asn1Value = otherName.pointee.value else { continue }

                // The value is a context-tagged [0] EXPLICIT wrapping of OCTET STRING.
                // Get the DER encoding and parse the OCTET STRING from it.
                var derOut: UnsafeMutablePointer<UInt8>? = nil
                let derLen = i2d_ASN1_TYPE(asn1Value, &derOut)
                guard derLen > 0, let derOut else { continue }
                defer { CRYPTO_free(derOut, #file, #line) }

                let derBytes = Data(bytes: derOut, count: Int(derLen))

                // Parse the DER to find the OCTET STRING containing the 25-byte FASC-N.
                // The structure is: context [0] { OCTET STRING { fascn bytes } }
                // Walk through looking for tag 0x04 (OCTET STRING) with 25 bytes.
                if let fascn = extractOctetString(from: derBytes, expectedLength: 25) {
                    return fascn
                }
            }

            return nil
        }
    }

    /// Extract an OCTET STRING of expected length from DER data.
    private static func extractOctetString(from data: Data, expectedLength: Int) -> Data? {
        var i = 0
        while i < data.count {
            let tag = data[i]
            i += 1
            guard i < data.count else { break }

            // Parse length
            var length = 0
            if data[i] < 0x80 {
                length = Int(data[i])
                i += 1
            } else {
                let numBytes = Int(data[i] & 0x7F)
                i += 1
                for _ in 0..<numBytes {
                    guard i < data.count else { return nil }
                    length = (length << 8) | Int(data[i])
                    i += 1
                }
            }

            if tag == 0x04 && length == expectedLength && i + length <= data.count {
                return data[i..<(i + length)]
            }

            // If constructed, recurse into contents
            if tag & 0x20 != 0 {
                let inner = data[i..<min(i + length, data.count)]
                if let result = extractOctetString(from: Data(inner), expectedLength: expectedLength) {
                    return result
                }
            }

            i += length
        }
        return nil
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
