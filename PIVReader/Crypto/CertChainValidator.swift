import Foundation
import Security

/// Result of certificate chain validation against configured trust anchors.
enum ValidationResult {
    case valid
    case invalid(String)
    case notEvaluated
}

/// Validates a leaf certificate against configured trust anchors
/// using the iOS SecTrust API.
struct CertChainValidator {

    /// Validate a leaf certificate's chain against the TrustStore.
    static func validate(leafDER: Data, trustStore: TrustStore) -> ValidationResult {
        let anchors = trustStore.enabledTrustAnchors
        let intermediates = trustStore.enabledIntermediates

        guard !anchors.isEmpty else {
            return .invalid("No trust anchors configured")
        }

        return validate(
            leafDER: leafDER,
            intermediateDERs: intermediates,
            anchorDERs: anchors
        )
    }

    /// Validate a leaf certificate's chain.
    ///
    /// - Parameters:
    ///   - leafDER: The end-entity certificate in DER format.
    ///   - intermediateDERs: All known intermediate CA certificates (DER).
    ///   - anchorDERs: Trust anchor certificates (DER). All are set as anchors.
    /// - Returns: `.valid` if the chain validates, `.invalid(reason)` otherwise.
    static func validate(
        leafDER: Data,
        intermediateDERs: [Data],
        anchorDERs: [Data]
    ) -> ValidationResult {
        // Create SecCertificate for the leaf
        guard let leafCert = SecCertificateCreateWithData(nil, leafDER as CFData) else {
            return .invalid("Failed to parse leaf certificate")
        }

        // Build the certificate chain array: leaf + intermediates
        var certChain: [SecCertificate] = [leafCert]
        for intermDER in intermediateDERs {
            if let cert = SecCertificateCreateWithData(nil, intermDER as CFData) {
                certChain.append(cert)
            }
        }

        // Parse trust anchors
        var anchorCerts: [SecCertificate] = []
        for anchorDER in anchorDERs {
            if let cert = SecCertificateCreateWithData(nil, anchorDER as CFData) {
                anchorCerts.append(cert)
            }
        }
        guard !anchorCerts.isEmpty else {
            return .invalid("No valid trust anchor certificates")
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

        // Set configured anchors as the only trust anchors
        let anchorStatus = SecTrustSetAnchorCertificates(trust, anchorCerts as CFArray)
        guard anchorStatus == errSecSuccess else {
            return .invalid("SecTrustSetAnchorCertificates failed: \(anchorStatus)")
        }

        // Only trust our anchors, not the system trust store
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
