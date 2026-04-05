import Foundation
import Security
import CommonCrypto

/// Parse a PIV certificate container (tag 53 or raw content).
///
/// The container holds:
/// - Tag 70: X.509 certificate (DER or gzip-compressed DER)
/// - Tag 71: CertInfo byte (0x00 = uncompressed, 0x01 = gzip)
/// - Tag FE: Error Detection Code
func parseCertContainer(_ data: Data, tag: UInt32 = 0, name: String = "") -> PIVCertificate? {
    let tlvs = parseTLV(data)

    // If wrapped in tag 53, unwrap first
    let contentTLVs: [TLV]
    if let container = findTag(tlvs, 0x53) {
        contentTLVs = container.children()
    } else {
        contentTLVs = tlvs
    }

    // Tag 70: certificate
    guard let certTLV = findTag(contentTLVs, 0x70) else {
        return nil
    }

    // Tag 71: cert info byte
    let certInfoByte = findTag(contentTLVs, 0x71)?.value.first

    // Tag FE: error detection code
    let edc = findTag(contentTLVs, 0xFE)?.value

    // Decompress if CertInfo == 0x01 (gzip)
    var certDER = certTLV.value
    var compressed = false
    if certInfoByte == 0x01 {
        if let decompressed = gzipDecompress(certDER) {
            certDER = decompressed
            compressed = true
        }
    }

    return PIVCertificate(
        rawData: data,
        tag: tag,
        name: name,
        certDER: certDER,
        compressed: compressed,
        certInfoByte: certInfoByte,
        errorDetectionCode: edc
    )
}

/// Summarize a DER-encoded X.509 certificate using Security.framework.
func summarizeCertificate(_ der: Data) -> CertificateSummary? {
    guard let secCert = SecCertificateCreateWithData(nil, der as CFData) else {
        return nil
    }
    let subject = SecCertificateCopySubjectSummary(secCert) as String? ?? "Unknown"
    return CertificateSummary(
        subject: subject,
        derLength: der.count,
        compressed: false,
        fingerprint: der.sha256Hex
    )
}

// MARK: - gzip decompression (minimal, using zlib which is always available on iOS)

import Compression

private func gzipDecompress(_ data: Data) -> Data? {
    // Skip gzip header (10 bytes minimum) to get to deflate stream
    guard data.count > 10, data[0] == 0x1F, data[1] == 0x8B else {
        return nil
    }

    // Find start of deflate data (skip header + optional fields)
    var offset = 10
    let flags = data[3]
    if flags & 0x04 != 0 { // FEXTRA
        guard offset + 2 <= data.count else { return nil }
        let xlen = Int(data[offset]) | (Int(data[offset + 1]) << 8)
        offset += 2 + xlen
    }
    if flags & 0x08 != 0 { // FNAME
        while offset < data.count && data[offset] != 0 { offset += 1 }
        offset += 1
    }
    if flags & 0x10 != 0 { // FCOMMENT
        while offset < data.count && data[offset] != 0 { offset += 1 }
        offset += 1
    }
    if flags & 0x02 != 0 { offset += 2 } // FHCRC

    guard offset < data.count else { return nil }

    let compressed = data[offset...]
    let bufferSize = data.count * 4  // generous estimate
    var output = Data(count: bufferSize)

    let result = output.withUnsafeMutableBytes { outPtr -> Int in
        compressed.withUnsafeBytes { inPtr -> Int in
            let written = compression_decode_buffer(
                outPtr.bindMemory(to: UInt8.self).baseAddress!, bufferSize,
                inPtr.bindMemory(to: UInt8.self).baseAddress!, compressed.count,
                nil, COMPRESSION_ZLIB
            )
            return written
        }
    }

    guard result > 0 else { return nil }
    return output.prefix(result)
}

// MARK: - Data extension

private extension Data {
    var sha256Hex: String {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        withUnsafeBytes { ptr in
            _ = CC_SHA256(ptr.baseAddress, CC_LONG(count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
}
