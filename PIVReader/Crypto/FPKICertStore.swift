import Foundation

/// Downloads and caches FPKI root and intermediate CA certificates
/// for PIV certificate chain validation.
///
/// The root cert is the Federal Common Policy CA G2.
/// Intermediate certs are downloaded as a weekly-updated PKCS#7 bundle.
actor FPKICertStore {
    static let shared = FPKICertStore()

    static let rootURL = URL(string: "http://repo.fpki.gov/fcpca/fcpcag2.crt")!
    static let intermediatesURL = URL(string:
        "https://www.idmanagement.gov/implement/tools/CACertificatesValidatingToFederalCommonPolicyG2.p7b")!

    private var rootCertDER: Data?
    private var intermediateCertDERs: [Data]?
    private var loadError: String?

    var isLoaded: Bool { rootCertDER != nil && intermediateCertDERs != nil }

    /// Download and parse the FPKI root and intermediate certificates.
    func loadCertificates() async {
        guard !isLoaded else { return }

        do {
            // Download root and intermediates in parallel
            async let rootData = URLSession.shared.data(from: Self.rootURL)
            async let p7bData = URLSession.shared.data(from: Self.intermediatesURL)

            let (rootBytes, _) = try await rootData
            let (p7bBytes, _) = try await p7bData

            // Root is raw DER
            rootCertDER = rootBytes
            print("FPKI: Root cert downloaded (\(rootBytes.count) bytes)")

            // Intermediates are in a PKCS#7 bundle — parse with OpenSSL
            intermediateCertDERs = try OpenSSLCrypto.parsePKCS7Certificates(p7bBytes)
            print("FPKI: Loaded \(intermediateCertDERs?.count ?? 0) intermediate certs from P7B (\(p7bBytes.count) bytes)")

            loadError = nil
        } catch {
            loadError = error.localizedDescription
            print("FPKI: Failed to load certificates: \(error.localizedDescription)")
        }
    }

    /// Returns the cached certificates, or nil if not loaded.
    func getCertificates() -> (root: Data, intermediates: [Data])? {
        guard let root = rootCertDER, let intermediates = intermediateCertDERs else {
            return nil
        }
        return (root, intermediates)
    }

    /// Human-readable status for UI.
    var statusDescription: String {
        if isLoaded {
            return "Loaded (\(intermediateCertDERs?.count ?? 0) intermediates)"
        } else if let err = loadError {
            return "Error: \(err)"
        } else {
            return "Not loaded"
        }
    }
}
