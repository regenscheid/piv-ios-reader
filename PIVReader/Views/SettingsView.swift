import SwiftUI
import UniformTypeIdentifiers

struct SettingsView: View {
    @AppStorage("enableSM") private var enableSM: Bool = false
    @ObservedObject var trustStore: TrustStore = .shared

    var body: some View {
        Form {
            Section {
                Toggle("Enable Secure Messaging", isOn: $enableSM)
            } footer: {
                Text("When enabled, the app will attempt to establish an encrypted channel (SM) with the card after SELECT. If SM establishment fails, the app falls back to unprotected communication.")
            }

            Section {
                NavigationLink {
                    CardRegistrationView(registry: CardRegistry.shared)
                } label: {
                    HStack {
                        Text("Registered Cards")
                        Spacer()
                        Text("\(CardRegistry.shared.cards.count)")
                            .foregroundColor(.secondary)
                    }
                }
            } footer: {
                Text("Register PIV cards to store identity information for quick lookup during card reads.")
            }

            Section {
                NavigationLink {
                    TrustStoreView(trustStore: trustStore)
                } label: {
                    HStack {
                        Text("CA Certificates")
                        Spacer()
                        Text("\(trustStore.certificates.filter(\.isEnabled).count) enabled")
                            .foregroundColor(.secondary)
                    }
                }
            } footer: {
                Text("Configure which CA certificates are used as trust anchors and intermediates for certificate chain validation.")
            }
        }
        .navigationTitle("Settings")
    }
}

// MARK: - Trust Store View

struct TrustStoreView: View {
    @ObservedObject var trustStore: TrustStore
    @State private var showImporter = false
    @State private var importError: String?

    private var fpkiRoots: [TrustCertificate] {
        trustStore.certificates.filter { $0.source == .fpkiRoot }
    }
    private var fpkiIntermediates: [TrustCertificate] {
        trustStore.certificates.filter { $0.source == .fpkiIntermediate }
    }
    private var userImported: [TrustCertificate] {
        trustStore.certificates.filter { $0.source == .userImported }
    }

    var body: some View {
        List {
            if !fpkiRoots.isEmpty {
                Section("FPKI Root") {
                    ForEach(fpkiRoots) { cert in
                        CertRow(cert: cert, trustStore: trustStore)
                    }
                }
            }

            if !fpkiIntermediates.isEmpty {
                Section("FPKI Intermediates (\(fpkiIntermediates.count))") {
                    ForEach(fpkiIntermediates) { cert in
                        CertRow(cert: cert, trustStore: trustStore)
                    }
                }
            }

            if !userImported.isEmpty {
                Section("Imported") {
                    ForEach(userImported) { cert in
                        CertRow(cert: cert, trustStore: trustStore, canDelete: true)
                    }
                    .onDelete { offsets in
                        let ids = offsets.map { userImported[$0].id }
                        ids.forEach { trustStore.removeCertificate($0) }
                    }
                }
            }

            Section {
                Button {
                    showImporter = true
                } label: {
                    Label("Import Certificate", systemImage: "plus.circle")
                }
            } footer: {
                Text("Import a DER (.cer, .crt, .der) or PEM (.pem) encoded X.509 certificate. Imported certificates are added as trust anchors by default.")
            }

            if let error = importError {
                Section {
                    Text(error)
                        .foregroundColor(.red)
                        .font(.caption)
                }
            }
        }
        .navigationTitle("CA Certificates")
        .fileImporter(
            isPresented: $showImporter,
            allowedContentTypes: [
                .x509Certificate,
                UTType(filenameExtension: "pem") ?? .data,
                UTType(filenameExtension: "crt") ?? .data,
                UTType(filenameExtension: "cer") ?? .data,
                .data,
            ],
            allowsMultipleSelection: false
        ) { result in
            importError = nil
            switch result {
            case .success(let urls):
                guard let url = urls.first else { return }
                guard url.startAccessingSecurityScopedResource() else {
                    importError = "Cannot access file"
                    return
                }
                defer { url.stopAccessingSecurityScopedResource() }
                do {
                    let data = try Data(contentsOf: url)
                    if let err = trustStore.importCertificate(from: data) {
                        importError = err
                    }
                } catch {
                    importError = error.localizedDescription
                }
            case .failure(let error):
                importError = error.localizedDescription
            }
        }
    }
}

// MARK: - Certificate Row

private struct CertRow: View {
    let cert: TrustCertificate
    @ObservedObject var trustStore: TrustStore
    var canDelete: Bool = false

    var body: some View {
        NavigationLink {
            CACertDetailView(cert: cert, trustStore: trustStore, canDelete: canDelete)
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(cert.subject)
                        .font(.subheadline)
                        .lineLimit(1)
                    HStack(spacing: 4) {
                        if cert.isTrustAnchor {
                            Text("Root")
                                .font(.caption2)
                                .padding(.horizontal, 4)
                                .padding(.vertical, 1)
                                .background(Color.blue.opacity(0.15))
                                .cornerRadius(3)
                        }
                        if !cert.isEnabled {
                            Text("Disabled")
                                .font(.caption2)
                                .foregroundColor(.red)
                        }
                    }
                }
                Spacer()
                if cert.isEnabled {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundColor(.green)
                        .font(.caption)
                } else {
                    Image(systemName: "circle")
                        .foregroundColor(.secondary)
                        .font(.caption)
                }
            }
        }
    }
}

// MARK: - CA Cert Detail View

struct CACertDetailView: View {
    let cert: TrustCertificate
    @ObservedObject var trustStore: TrustStore
    var canDelete: Bool = false
    @Environment(\.dismiss) private var dismiss

    private var enabledBinding: Binding<Bool> {
        Binding(
            get: { cert.isEnabled },
            set: { trustStore.setEnabled(cert.id, enabled: $0) }
        )
    }

    private var trustAnchorBinding: Binding<Bool> {
        Binding(
            get: { cert.isTrustAnchor },
            set: { trustStore.setTrustAnchor(cert.id, isTrustAnchor: $0) }
        )
    }

    var body: some View {
        Form {
            Section("Certificate") {
                LabeledContent("Subject", value: cert.subject)
                LabeledContent("Issuer", value: cert.issuer)
                LabeledContent("Source", value: sourceLabel)
            }

            Section("Fingerprint (SHA-256)") {
                Text(cert.id)
                    .font(.system(.caption2, design: .monospaced))
                    .textSelection(.enabled)
            }

            Section {
                Toggle("Enabled", isOn: enabledBinding)
                Toggle("Trust Anchor (Root)", isOn: trustAnchorBinding)
            } header: {
                Text("Trust Settings")
            } footer: {
                Text("Trust anchors are used as root certificates for chain validation. Non-anchor certificates are used as intermediates to help build the chain.")
            }

            if canDelete {
                Section {
                    Button(role: .destructive) {
                        trustStore.removeCertificate(cert.id)
                        dismiss()
                    } label: {
                        Label("Remove Certificate", systemImage: "trash")
                    }
                }
            }
        }
        .navigationTitle("CA Certificate")
    }

    private var sourceLabel: String {
        switch cert.source {
        case .fpkiRoot: return "FPKI Root"
        case .fpkiIntermediate: return "FPKI Intermediate"
        case .userImported: return "Imported"
        }
    }
}
