import SwiftUI

// MARK: - View Model

@MainActor
class CardReaderViewModel: ObservableObject {
    @AppStorage("enableSM") var enableSM: Bool = false

    @Published var status: String = "Tap 'Read Card' to begin"
    @Published var appLabel: String? = nil
    @Published var aidHex: String? = nil
    @Published var smCipherSuites: [String] = []
    @Published var smStatus: String? = nil
    @Published var certificates: [(name: String, summary: CertificateSummary)] = []
    @Published var chuid: PIVChuid? = nil
    @Published var challengeResult: ChallengeResponseResult? = nil
    @Published var tlvDump: String? = nil
    @Published var isReading = false
    @Published var error: String? = nil

    /// True if VCI entry should be offered (card supports SM and some objects need VCI).
    @Published var vciAvailable = false
    /// Controls the pairing code entry sheet.
    @Published var showVCIEntry = false

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
        smStatus = nil
        tlvDump = nil
        vciAvailable = false

        Task {
            await readCard(useUSB: useUSB)
            isReading = false
        }
    }

    // MARK: - Standard Card Read

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

        // Load trust store (downloads FPKI certs if needed)
        let trustTask = Task { await TrustStore.shared.loadIfNeeded() }

        do {
            if let usb = usbTransport {
                status = "Connecting to USB reader..."
                try await usb.connect()
                await trustTask.value
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

            if !selectResp.data.isEmpty {
                tlvDump = displayTLV(selectResp.data)
            }

            // Attempt SM if enabled in settings and card supports it
            if enableSM && card.supportsSM {
                status = "Establishing Secure Messaging..."
                do {
                    let suite = try await card.establishSM()
                    let suiteName = suite == .cs7 ? "CS7 (P-384/AES-256)" : "CS2 (P-256/AES-128)"
                    smStatus = "Active: \(suiteName)"
                    print("SM established: \(suiteName)")
                } catch {
                    // Graceful fallback — continue without SM
                    smStatus = "Failed"
                    print("SM establishment failed (falling back): \(error)")
                }
            }

            let smWasActive = card.smActive

            // Read Card Auth cert (always accessible contactless, no PIN)
            status = "Reading Card Authentication certificate..."
            let cardAuthResp = try await card.getCertificate(DataObjects.X509_CARD_AUTH)
            if cardAuthResp.success, let cert = cardAuthResp.parsed as? PIVCertificate,
               var summary = cert.summarize() {
                summary.chainValidation = validateCert(cert.certDER)
                let sig = verifySignature(cert.certDER)
                summary.signatureVerified = sig.verified
                summary.issuerName = sig.issuer
                summary.smProtected = smWasActive
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

            // Try reading PIV Auth cert (needs VCI on contactless)
            status = "Reading PIV Authentication certificate..."
            let pivAuthResp = try await card.getCertificate(DataObjects.X509_PIV_AUTH)
            if pivAuthResp.success, let cert = pivAuthResp.parsed as? PIVCertificate,
               var summary = cert.summarize() {
                summary.chainValidation = validateCert(cert.certDER)
                let sig = verifySignature(cert.certDER)
                summary.signatureVerified = sig.verified
                summary.issuerName = sig.issuer
                summary.smProtected = smWasActive
                certificates.append((name: "PIV Authentication (9A)", summary: summary))
            } else if pivAuthResp.sw == SW.securityNotSatisfied.rawValue {
                // Card has the object but it requires VCI
                if card.supportsSM {
                    vciAvailable = true
                }
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

    // MARK: - VCI Read (SM + Pairing Code)

    func readCardWithVCI(pairingCode: String) {
        guard !isReading else { return }
        isReading = true
        error = nil

        Task {
            await performVCIRead(pairingCode: pairingCode)
            isReading = false
        }
    }

    private func performVCIRead(pairingCode: String) async {
        let transport = NFCTransport()

        do {
            status = "Waiting for card (VCI)..."
            try await transport.startSession(alertMessage: "Hold your PIV card near iPhone")

            let card = PIVCard(transport: transport)

            // SELECT PIV
            status = "Selecting PIV application..."
            let selectResp = try await card.select()
            guard selectResp.success else {
                throw PIVError.commandFailed(sw: selectResp.sw, description: "SELECT failed")
            }

            // Establish SM (required for VCI)
            status = "Establishing Secure Messaging..."
            let suite = try await card.establishSM()
            let suiteName = suite == .cs7 ? "CS7 (P-384/AES-256)" : "CS2 (P-256/AES-128)"
            smStatus = "Active: \(suiteName)"

            // VERIFY pairing code under SM
            status = "Verifying pairing code..."
            let verifyResp = try await card.verifyPairingCode(pairingCode)
            if !verifyResp.success {
                if verifyResp.sw1 == 0x63 {
                    let retries = verifyResp.sw2 & 0x0F
                    throw PIVError.commandFailed(
                        sw: verifyResp.sw,
                        description: "Pairing code rejected — \(retries) retries remaining"
                    )
                } else if verifyResp.sw == SW.authMethodBlocked.rawValue {
                    throw PIVError.commandFailed(
                        sw: verifyResp.sw,
                        description: "Pairing code blocked (0 retries remaining)"
                    )
                } else {
                    throw PIVError.commandFailed(
                        sw: verifyResp.sw,
                        description: "VERIFY pairing code failed"
                    )
                }
            }

            // VCI is now active — re-read all data objects
            certificates = []
            chuid = nil
            challengeResult = nil
            vciAvailable = false

            // Read Card Auth cert (9E)
            status = "Reading Card Authentication certificate (VCI)..."
            let cardAuthResp = try await card.getCertificate(DataObjects.X509_CARD_AUTH)
            if cardAuthResp.success, let cert = cardAuthResp.parsed as? PIVCertificate,
               var summary = cert.summarize() {
                summary.chainValidation = validateCert(cert.certDER)
                let sig = verifySignature(cert.certDER)
                summary.signatureVerified = sig.verified
                summary.issuerName = sig.issuer
                summary.smProtected = true
                certificates.append((name: "Card Authentication (9E)", summary: summary))

                status = "Authenticating card..."
                challengeResult = try? await ChallengeResponse.performChallengeResponse(
                    card: card, certDER: cert.certDER
                )
            }

            // Read CHUID
            status = "Reading CHUID (VCI)..."
            let chuidResp = try await card.getCHUID()
            if chuidResp.success, let parsed = chuidResp.parsed as? PIVChuid {
                chuid = parsed
            }

            // Read PIV Auth cert (9A) — should now succeed under VCI
            status = "Reading PIV Authentication certificate (VCI)..."
            let pivAuthResp = try await card.getCertificate(DataObjects.X509_PIV_AUTH)
            if pivAuthResp.success, let cert = pivAuthResp.parsed as? PIVCertificate,
               var summary = cert.summarize() {
                summary.chainValidation = validateCert(cert.certDER)
                let sig = verifySignature(cert.certDER)
                summary.signatureVerified = sig.verified
                summary.issuerName = sig.issuer
                summary.smProtected = true
                certificates.append((name: "PIV Authentication (9A)", summary: summary))
            }

            // Read Digital Signature cert (9C)
            status = "Reading Digital Signature certificate (VCI)..."
            let digSigResp = try await card.getCertificate(DataObjects.X509_DIGITAL_SIG)
            if digSigResp.success, let cert = digSigResp.parsed as? PIVCertificate,
               var summary = cert.summarize() {
                summary.chainValidation = validateCert(cert.certDER)
                let sig = verifySignature(cert.certDER)
                summary.signatureVerified = sig.verified
                summary.issuerName = sig.issuer
                summary.smProtected = true
                certificates.append((name: "Digital Signature (9C)", summary: summary))
            }

            // Read Key Management cert (9D)
            status = "Reading Key Management certificate (VCI)..."
            let keyMgmtResp = try await card.getCertificate(DataObjects.X509_KEY_MGMT)
            if keyMgmtResp.success, let cert = keyMgmtResp.parsed as? PIVCertificate,
               var summary = cert.summarize() {
                summary.chainValidation = validateCert(cert.certDER)
                let sig = verifySignature(cert.certDER)
                summary.signatureVerified = sig.verified
                summary.issuerName = sig.issuer
                summary.smProtected = true
                certificates.append((name: "Key Management (9D)", summary: summary))
            }

            // Done
            let certCount = certificates.count
            transport.endSession(message: "VCI done — \(certCount) cert(s) read")
            status = "VCI complete: \(certCount) certificate(s) read"

        } catch {
            transport.endSession(error: error.localizedDescription)
            self.error = error.localizedDescription
            status = "VCI error"
        }
    }

    // MARK: - Helpers

    private func validateCert(_ certDER: Data) -> ValidationResult {
        let store = TrustStore.shared
        guard store.hasTrustAnchors else { return .notEvaluated }
        return CertChainValidator.validate(leafDER: certDER, trustStore: store)
    }

    private func verifySignature(_ certDER: Data) -> (verified: Bool, issuer: String?) {
        if let certIssuer = PIVCrypto.getCertIssuerName(certDER) {
            print("Cert issuer: \(certIssuer)")
        }

        let store = TrustStore.shared
        var candidates = store.enabledIntermediates
        candidates.append(contentsOf: store.enabledTrustAnchors)

        if PIVCrypto.isSelfSigned(certDER: certDER) {
            return (true, "Self-signed")
        }

        if let issuer = PIVCrypto.verifyCertificateSignature(
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
    @State private var showSettings = false

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
                    if let sm = viewModel.smStatus {
                        LabeledContent("Secure Messaging", value: sm)
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
                            HStack {
                                VStack(alignment: .leading) {
                                    Text(item.name)
                                        .font(.headline)
                                    Text(item.summary.subject)
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                                Spacer()
                                if item.summary.smProtected {
                                    Image(systemName: "lock.fill")
                                        .font(.caption)
                                        .foregroundColor(.green)
                                }
                            }
                        }
                    }
                }
            }

            // VCI Entry
            if viewModel.vciAvailable {
                Section {
                    Button {
                        viewModel.showVCIEntry = true
                    } label: {
                        Label("Enter VCI Pairing Code", systemImage: "key.fill")
                    }
                    .disabled(viewModel.isReading)
                } footer: {
                    Text("Some data objects require VCI (Virtual Contact Interface). Enter the 8-digit pairing code to establish VCI and read protected objects over NFC.")
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
        .sheet(isPresented: $viewModel.showVCIEntry) {
            PINEntryView(
                title: "VCI Pairing Code",
                prompt: "Enter 8-digit pairing code"
            ) { code in
                viewModel.readCardWithVCI(pairingCode: code)
            }
        }
        .sheet(isPresented: $showSettings) {
            NavigationStack {
                SettingsView()
                    .toolbar {
                        ToolbarItem(placement: .confirmationAction) {
                            Button("Done") { showSettings = false }
                        }
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
                Button {
                    showSettings = true
                } label: {
                    Image(systemName: "gearshape")
                        .font(.title3)
                }
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
