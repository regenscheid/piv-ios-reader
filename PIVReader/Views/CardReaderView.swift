import SwiftUI

// MARK: - View Model

@MainActor
class CardReaderViewModel: ObservableObject {
    @Published var status: String = "Tap 'Read Card' to begin"
    @Published var appLabel: String? = nil
    @Published var aidHex: String? = nil
    @Published var smCipherSuites: [String] = []
    @Published var certificates: [(name: String, summary: CertificateSummary)] = []
    @Published var chuid: PIVChuid? = nil
    @Published var challengeResult: ChallengeResponseResult? = nil
    @Published var tlvDump: String? = nil
    @Published var isReading = false
    @Published var error: String? = nil
    @Published var showPINEntry = false
    @Published var pinAction: ((String) -> Void)? = nil

    func startReading(useUSB: Bool = false) {
        guard !isReading else { return }
        isReading = true
        error = nil
        certificates = []
        chuid = nil
        challengeResult = nil
        appLabel = nil
        aidHex = nil
        smCipherSuites = []
        tlvDump = nil

        Task {
            await readCard(useUSB: useUSB)
            isReading = false
        }
    }

    private func readCard(useUSB: Bool) async {
        let transport: CardTransport
        let usbTransport: USBTransport?

        if useUSB {
            let usb = USBTransport()
            usbTransport = usb
            transport = usb
        } else {
            usbTransport = nil
            transport = NFCTransport()
        }

        // Start downloading FPKI certs in parallel
        let fpkiTask = Task { await FPKICertStore.shared.loadCertificates() }

        do {
            if let usb = usbTransport {
                status = "Connecting to USB reader..."
                try await usb.connect()
                // USB connects instantly — wait for FPKI certs before proceeding
                await fpkiTask.value
            } else {
                status = "Waiting for card..."
                try await (transport as! NFCTransport).startSession(alertMessage: "Hold your PIV card near iPhone")
            }

            let card = PIVCard(transport: transport)

            // SELECT PIV
            status = "Selecting PIV application..."
            let selectResp = try await card.select()
            guard selectResp.success else {
                throw PIVError.commandFailed(
                    sw: selectResp.sw,
                    description: "SELECT failed"
                )
            }

            // Show Application Property Template
            if let info = card.selectInfo {
                appLabel = info["application_label"] as? String
                aidHex = info["aid"] as? String
                smCipherSuites = (info["algorithm_identifiers"] as? [String]) ?? []
            }

            // Show raw TLV
            if !selectResp.data.isEmpty {
                tlvDump = displayTLV(selectResp.data)
            }

            // Read Card Auth cert (always accessible contactless, no PIN)
            status = "Reading Card Authentication certificate..."
            let cardAuthResp = try await card.getCertificate(DataObjects.X509_CARD_AUTH)
            if cardAuthResp.success, let cert = cardAuthResp.parsed as? PIVCertificate,
               var summary = cert.summarize() {
                summary.chainValidation = await validateCert(cert.certDER)
                let sig = await verifySignature(cert.certDER)
                summary.signatureVerified = sig.verified
                summary.issuerName = sig.issuer
                certificates.append((name: "Card Authentication (9E)", summary: summary))

                // Challenge-response to prove card has private key
                status = "Authenticating card..."
                challengeResult = try? await ChallengeResponse.performChallengeResponse(
                    card: card, certDER: cert.certDER
                )
            }

            // Read CHUID (always accessible)
            status = "Reading CHUID..."
            let chuidResp = try await card.getCHUID()
            if chuidResp.success, let parsed = chuidResp.parsed as? PIVChuid {
                chuid = parsed
            }

            // Try reading PIV Auth cert (may need VCI on contactless)
            status = "Reading PIV Authentication certificate..."
            let pivAuthResp = try await card.getCertificate(DataObjects.X509_PIV_AUTH)
            if pivAuthResp.success, let cert = pivAuthResp.parsed as? PIVCertificate,
               var summary = cert.summarize() {
                summary.chainValidation = await validateCert(cert.certDER)
                let sig = await verifySignature(cert.certDER)
                summary.signatureVerified = sig.verified
                summary.issuerName = sig.issuer
                certificates.append((name: "PIV Authentication (9A)", summary: summary))
            } else if pivAuthResp.sw == SW.securityNotSatisfied.rawValue {
                status = "PIV Auth cert requires PIN or VCI"
            }

            // Done
            let certCount = certificates.count
            if let nfc = transport as? NFCTransport {
                nfc.endSession(message: "Done — \(certCount) cert(s) read")
            } else {
                usbTransport?.disconnect()
            }
            status = "Complete: \(certCount) certificate(s) read"

        } catch {
            if let nfc = transport as? NFCTransport {
                nfc.endSession(error: error.localizedDescription)
            } else {
                usbTransport?.disconnect()
            }
            self.error = error.localizedDescription
            status = "Error"
        }
    }

    private func validateCert(_ certDER: Data) async -> ValidationResult {
        guard let certs = await FPKICertStore.shared.getCertificates() else {
            return .notEvaluated
        }
        return CertChainValidator.validate(
            leafDER: certDER,
            intermediateDERs: certs.intermediates,
            rootDER: certs.root
        )
    }

    /// Verify the certificate's signature against known intermediate/root certs.
    private func verifySignature(_ certDER: Data) async -> (verified: Bool, issuer: String?) {
        // Log the cert's issuer field for debugging
        if let certIssuer = OpenSSLCrypto.getCertIssuerName(certDER) {
            print("Cert issuer: \(certIssuer)")
        }

        // Build candidate issuers: intermediates + root
        var candidates = [Data]()
        if let certs = await FPKICertStore.shared.getCertificates() {
            candidates.append(contentsOf: certs.intermediates)
            candidates.append(certs.root)
            print("Signature verification: \(candidates.count) candidate issuers loaded")
        } else {
            print("Signature verification: NO candidate issuers (FPKI certs not loaded)")
        }

        // Also check if self-signed
        if OpenSSLCrypto.isSelfSigned(certDER: certDER) {
            return (true, "Self-signed")
        }

        if let issuer = OpenSSLCrypto.verifyCertificateSignature(
            certDER: certDER,
            issuerCandidateDERs: candidates
        ) {
            return (true, issuer)
        }

        return (false, nil)
    }
}

// MARK: - View

struct CardReaderView: View {
    @StateObject private var viewModel = CardReaderViewModel()

    var body: some View {
        List {
            // Status
            Section("Status") {
                Text(viewModel.status)
                    .foregroundColor(viewModel.error != nil ? .red : .primary)
                if let error = viewModel.error {
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                }
            }

            // Application Info
            if viewModel.appLabel != nil || viewModel.aidHex != nil {
                Section("Application") {
                    if let label = viewModel.appLabel {
                        LabeledContent("Label", value: label)
                    }
                    if let aid = viewModel.aidHex {
                        LabeledContent("AID", value: aid)
                    }
                    if !viewModel.smCipherSuites.isEmpty {
                        LabeledContent("SM Suites",
                                       value: viewModel.smCipherSuites.joined(separator: ", "))
                    }
                }
            }

            // Card Authentication (challenge-response)
            if let result = viewModel.challengeResult {
                Section("Card Authentication") {
                    if result.success {
                        Label("Card verified (\(result.algorithm))",
                              systemImage: "checkmark.seal.fill")
                            .foregroundColor(.green)
                    } else {
                        Label("Verification failed",
                              systemImage: "xmark.seal.fill")
                            .foregroundColor(.red)
                        if let err = result.error {
                            Text(err)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                }
            }

            // CHUID / FASC-N
            if let chuid = viewModel.chuid {
                Section("CHUID") {
                    if let fascn = chuid.fascn {
                        LabeledContent("Agency Code", value: fascn.agencyCode)
                        if let name = fascn.agencyName {
                            LabeledContent("Agency", value: name)
                        }
                        LabeledContent("System Code", value: fascn.systemCode)
                        LabeledContent("Credential #", value: fascn.credentialNumber)
                        LabeledContent("Person ID", value: fascn.personIdentifier)
                        LabeledContent("CS/ICI", value: "\(fascn.credentialSeries)/\(fascn.individualCredentialIssue)")
                        LabeledContent("OC/OI/POA", value: "\(fascn.organizationalCategory)/\(fascn.organizationalIdentifier)/\(fascn.personOrgAssociation)")
                    }
                    if let uuid = chuid.guidUUID {
                        LabeledContent("GUID", value: uuid)
                    }
                    if let exp = chuid.expirationDate {
                        LabeledContent("Expires", value: exp)
                    }
                }
            }

            // Certificates
            if !viewModel.certificates.isEmpty {
                Section("Certificates") {
                    ForEach(viewModel.certificates, id: \.name) { item in
                        NavigationLink {
                            CertificateDetailView(
                                name: item.name,
                                summary: item.summary
                            )
                        } label: {
                            VStack(alignment: .leading) {
                                Text(item.name)
                                    .font(.headline)
                                Text(item.summary.subject)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                }
            }

            // Raw TLV
            if let tlv = viewModel.tlvDump {
                Section("SELECT Response TLV") {
                    Text(tlv)
                        .font(.system(.caption, design: .monospaced))
                }
            }
        }
        .safeAreaInset(edge: .top) {
            HStack(spacing: 10) {
                Image("pivlogo")
                    .renderingMode(.original)
                    .resizable()
                    .scaledToFit()
                    .frame(height: 40)
                Text("PIV Reader")
                    .font(.title2.bold())
                Spacer()
                Menu {
                    Button {
                        viewModel.startReading(useUSB: false)
                    } label: {
                        Label("NFC (Contactless)", systemImage: "wave.3.right")
                    }
                    Button {
                        viewModel.startReading(useUSB: true)
                    } label: {
                        Label("USB Reader", systemImage: "cable.connector")
                    }
                } label: {
                    Label("Read Card", systemImage: "wave.3.right")
                        .font(.body.bold())
                }
                .disabled(viewModel.isReading)
            }
            .padding(.horizontal)
            .padding(.vertical, 8)
            .background(.bar)
        }
    }
}
