import Foundation
import Security

/// Result of certificate chain validation against FPKI trust anchors.
enum ValidationResult {
    case valid
    case invalid(String)
    case notEvaluated
}

/// Validates a leaf certificate against the FPKI Common Policy CA G2 root
/// using the iOS SecTrust API.
struct CertChainValidator {

    /// Validate a leaf certificate's chain.
    ///
    /// - Parameters:
    ///   - leafDER: The end-entity certificate in DER format.
    ///   - intermediateDERs: All known intermediate CA certificates (DER).
    ///   - rootDER: The FPKI Common Policy CA G2 root certificate (DER).
    /// - Returns: `.valid` if the chain validates, `.invalid(reason)` otherwise.
    static func validate(
        leafDER: Data,
        intermediateDERs: [Data],
        rootDER: Data
    ) -> ValidationResult {
        // Create SecCertificate for the leaf
        guard let leafCert = SecCertificateCreateWithData(nil, leafDER as CFData) else {
            return .invalid("Failed to parse leaf certificate")
        }

        // Create SecCertificate for the root
        guard let rootCert = SecCertificateCreateWithData(nil, rootDER as CFData) else {
            return .invalid("Failed to parse root certificate")
        }

        // Build the certificate chain array: leaf + intermediates
        var certChain: [SecCertificate] = [leafCert]
        for intermDER in intermediateDERs {
            if let cert = SecCertificateCreateWithData(nil, intermDER as CFData) {
                certChain.append(cert)
            }
        }

        // Create trust evaluation policy
        let policy = SecPolicyCreateBasicX509()

        // Create SecTrust
        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(
            certChain as CFArray,
            policy,
            &trust
        )
        guard status == errSecSuccess, let trust else {
            return .invalid("SecTrustCreateWithCertificates failed: \(status)")
        }

        // Set the FPKI root as the only trust anchor
        let anchorStatus = SecTrustSetAnchorCertificates(trust, [rootCert] as CFArray)
        guard anchorStatus == errSecSuccess else {
            return .invalid("SecTrustSetAnchorCertificates failed: \(anchorStatus)")
        }

        // Only trust our anchor, not the system trust store
        SecTrustSetAnchorCertificatesOnly(trust, true)

        // Evaluate
        var error: CFError?
        let isValid = SecTrustEvaluateWithError(trust, &error)

        if isValid {
            return .valid
        } else {
            let reason: String
            if let error = error {
                reason = (error as Error).localizedDescription
            } else {
                reason = "Unknown validation failure"
            }
            return .invalid(reason)
        }
    }
}
