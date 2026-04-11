import Foundation
import CommonCrypto
import Security

/// A CA certificate entry in the trust store.
struct TrustCertificate: Identifiable, Codable {
    let id: String          // SHA-256 fingerprint (hex)
    let subject: String
    let issuer: String
    let derBase64: String   // DER-encoded cert as base64
    let source: Source
    var isEnabled: Bool
    var isTrustAnchor: Bool // true = root/anchor, false = intermediate

    enum Source: String, Codable {
        case fpkiRoot
        case fpkiIntermediate
        case userImported
    }

    var derData: Data? { Data(base64Encoded: derBase64) }
}

/// Manages trusted CA certificates for chain validation.
///
/// Loads FPKI certs on first use, persists user configuration (enable/disable)
/// and user-imported certificates to the app's documents directory.
class TrustStore: ObservableObject {
    static let shared = TrustStore()

    @Published private(set) var certificates: [TrustCertificate] = []
    @Published private(set) var isLoaded = false

    private let storeURL: URL = {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return docs.appendingPathComponent("trust_store.json")
    }()

    // MARK: - Load

    /// Load persisted trust store, then fetch FPKI certs if not already present.
    func loadIfNeeded() async {
        guard !isLoaded else { return }
        loadFromDisk()

        // Download FPKI certs and merge any new ones
        await mergeFPKICerts()
        isLoaded = true
    }

    // MARK: - Accessors

    /// All enabled trust anchor DERs (roots).
    var enabledTrustAnchors: [Data] {
        certificates
            .filter { $0.isEnabled && $0.isTrustAnchor }
            .compactMap { $0.derData }
    }

    /// All enabled intermediate DERs.
    var enabledIntermediates: [Data] {
        certificates
            .filter { $0.isEnabled && !$0.isTrustAnchor }
            .compactMap { $0.derData }
    }

    /// True if there are any enabled trust anchors.
    var hasTrustAnchors: Bool {
        certificates.contains { $0.isEnabled && $0.isTrustAnchor }
    }

    // MARK: - Mutate

    func setEnabled(_ id: String, enabled: Bool) {
        guard let idx = certificates.firstIndex(where: { $0.id == id }) else { return }
        certificates[idx].isEnabled = enabled
        saveToDisk()
    }

    func setTrustAnchor(_ id: String, isTrustAnchor: Bool) {
        guard let idx = certificates.firstIndex(where: { $0.id == id }) else { return }
        certificates[idx].isTrustAnchor = isTrustAnchor
        saveToDisk()
    }

    func removeCertificate(_ id: String) {
        certificates.removeAll { $0.id == id }
        saveToDisk()
    }

    /// Import a DER or PEM certificate file.
    func importCertificate(from data: Data, isTrustAnchor: Bool = true) -> String? {
        let derData: Data
        if let pemString = String(data: data, encoding: .utf8),
           pemString.contains("-----BEGIN CERTIFICATE-----") {
            // PEM: strip headers and decode base64
            let base64 = pemString
                .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
                .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
                .replacingOccurrences(of: "\n", with: "")
                .replacingOccurrences(of: "\r", with: "")
            guard let decoded = Data(base64Encoded: base64) else {
                return "Invalid PEM encoding"
            }
            derData = decoded
        } else {
            derData = data
        }

        guard SecCertificateCreateWithData(nil, derData as CFData) != nil else {
            return "Not a valid X.509 certificate"
        }

        let entry = makeTrustCert(derData: derData, source: .userImported, isTrustAnchor: isTrustAnchor)

        if certificates.contains(where: { $0.id == entry.id }) {
            return "Certificate already in trust store"
        }

        certificates.append(entry)
        saveToDisk()
        return nil
    }

    // MARK: - FPKI Integration

    private func mergeFPKICerts() async {
        await FPKICertStore.shared.loadCertificates()
        guard let fpki = await FPKICertStore.shared.getCertificates() else { return }

        let existingIDs = Set(certificates.map(\.id))

        // Root
        let rootEntry = makeTrustCert(derData: fpki.root, source: .fpkiRoot, isTrustAnchor: true)
        if !existingIDs.contains(rootEntry.id) {
            certificates.append(rootEntry)
        }

        // Intermediates
        for intDER in fpki.intermediates {
            let entry = makeTrustCert(derData: intDER, source: .fpkiIntermediate, isTrustAnchor: false)
            if !existingIDs.contains(entry.id) {
                certificates.append(entry)
            }
        }

        saveToDisk()
    }

    // MARK: - Persistence

    private func loadFromDisk() {
        guard FileManager.default.fileExists(atPath: storeURL.path) else { return }
        do {
            let data = try Data(contentsOf: storeURL)
            certificates = try JSONDecoder().decode([TrustCertificate].self, from: data)
        } catch {
            print("TrustStore: Failed to load: \(error)")
        }
    }

    private func saveToDisk() {
        do {
            let data = try JSONEncoder().encode(certificates)
            try data.write(to: storeURL, options: .atomic)
        } catch {
            print("TrustStore: Failed to save: \(error)")
        }
    }

    // MARK: - Helpers

    private func makeTrustCert(derData: Data, source: TrustCertificate.Source, isTrustAnchor: Bool) -> TrustCertificate {
        let fingerprint = sha256Hex(derData)
        let subject: String
        let issuer: String

        if let secCert = SecCertificateCreateWithData(nil, derData as CFData) {
            subject = SecCertificateCopySubjectSummary(secCert) as String? ?? "Unknown"
        } else {
            subject = "Unknown"
        }

        if let name = PIVCrypto.getCertIssuerName(derData) {
            issuer = name
        } else {
            issuer = "Unknown"
        }

        return TrustCertificate(
            id: fingerprint,
            subject: subject,
            issuer: issuer,
            derBase64: derData.base64EncodedString(),
            source: source,
            isEnabled: true,
            isTrustAnchor: isTrustAnchor
        )
    }

    private func sha256Hex(_ data: Data) -> String {
        var hash = [UInt8](repeating: 0, count: 32)
        data.withUnsafeBytes { _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash) }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
}
