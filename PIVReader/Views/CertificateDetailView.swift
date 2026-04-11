import SwiftUI

struct CertificateDetailView: View {
    let name: String
    let summary: CertificateSummary

    var body: some View {
        List {
            Section("Certificate") {
                LabeledContent("Slot", value: name)
                LabeledContent("Subject", value: summary.subject)
                LabeledContent("DER Size", value: "\(summary.derLength) bytes")
                LabeledContent("Compressed", value: summary.compressed ? "Yes" : "No")
            }

            Section("Fingerprint") {
                Text(summary.fingerprint)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
            }

            Section("Signature") {
                if summary.signatureVerified {
                    Label("Signature valid", systemImage: "checkmark.seal.fill")
                        .foregroundColor(.green)
                    if let issuer = summary.issuerName {
                        Text("Signed by: \(issuer)")
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .textSelection(.enabled)
                    }
                } else {
                    Label("Signature not verified",
                          systemImage: "xmark.seal")
                        .foregroundColor(.orange)
                    Text("Could not find issuer certificate")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }

            Section("Chain Validation") {
                switch summary.chainValidation {
                case .valid:
                    Label("Valid — chains to trusted root",
                          systemImage: "checkmark.shield.fill")
                        .foregroundColor(.green)
                case .invalid(let reason):
                    Label("Invalid", systemImage: "xmark.shield.fill")
                        .foregroundColor(.red)
                    Text(reason)
                        .font(.caption)
                        .foregroundColor(.secondary)
                case .notEvaluated:
                    Label("Not evaluated", systemImage: "questionmark.circle")
                        .foregroundColor(.secondary)
                }
            }
        }
        .navigationTitle("Certificate")
    }
}
