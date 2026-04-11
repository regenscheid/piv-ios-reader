import SwiftUI
import CommonCrypto

// MARK: - Registered Cards List

struct CardRegistrationView: View {
    @ObservedObject var registry: CardRegistry
    @State private var showRegister = false
    @State private var registrationTransport: RegistrationTransport?

    enum RegistrationTransport {
        case nfc
        case usb
    }

    var body: some View {
        List {
            if !registry.cards.isEmpty {
                ForEach(registry.cards) { card in
                    NavigationLink {
                        RegisteredCardDetailView(card: card, registry: registry)
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(card.subjectName)
                                .font(.headline)
                            if let org = card.organization {
                                Text(org)
                                    .font(.subheadline)
                                    .foregroundColor(.secondary)
                            }
                            Text(card.id.prefix(8) + "...")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                                .monospaced()
                        }
                    }
                }
                .onDelete { offsets in
                    let ids = offsets.map { registry.cards[$0].id }
                    ids.forEach { registry.delete($0) }
                }
            } else {
                Text("No registered cards")
                    .foregroundColor(.secondary)
            }

            Section {
                Menu {
                    Button {
                        registrationTransport = .nfc
                    } label: {
                        Label("NFC (requires VCI)", systemImage: "wave.3.right")
                    }
                    Button {
                        registrationTransport = .usb
                    } label: {
                        Label("USB Reader", systemImage: "cable.connector")
                    }
                } label: {
                    Label("Register Card", systemImage: "plus.circle")
                }
            }
        }
        .navigationTitle("Registered Cards")
        .sheet(item: $registrationTransport) { transport in
            NavigationStack {
                CardRegistrationFlowView(
                    registry: registry,
                    useUSB: transport == .usb
                )
            }
        }
    }
}

extension CardRegistrationView.RegistrationTransport: Identifiable {
    var id: String {
        switch self {
        case .nfc: return "nfc"
        case .usb: return "usb"
        }
    }
}

// MARK: - Registration Flow

struct CardRegistrationFlowView: View {
    @ObservedObject var registry: CardRegistry
    let useUSB: Bool

    @Environment(\.dismiss) private var dismiss

    @State private var status = "Ready"
    @State private var isReading = false
    @State private var error: String?

    // Collected card data
    @State private var cardUUID: String?
    @State private var subjectName: String?
    @State private var organization: String?
    @State private var organizationalUnits: [String] = []
    @State private var cardAuthFingerprint: String?
    @State private var pivAuthCertDER: Data?
    @State private var supportsVCI = false
    @State private var requiresPairingCode = false

    // User inputs
    @State private var showPairingCodeEntry = false
    @State private var showUSBPINEntry = false
    @State private var pairingCode: String = ""
    @State private var savePairingCode = true
    @State private var pinToSave: String = ""
    @State private var savePIN = false
    @State private var showPINEntry = false

    private var canRegister: Bool {
        cardUUID != nil && subjectName != nil
    }

    var body: some View {
        Form {
            Section("Status") {
                Text(status)
                    .foregroundColor(error != nil ? .red : .primary)
                if let error {
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                }
            }

            if canRegister {
                Section("Card Identity") {
                    LabeledContent("Name", value: subjectName ?? "Unknown")
                    if let org = organization {
                        LabeledContent("Organization", value: org)
                    }
                    if !organizationalUnits.isEmpty {
                        LabeledContent("Unit(s)", value: organizationalUnits.joined(separator: ", "))
                    }
                    if let uuid = cardUUID {
                        LabeledContent("UUID") {
                            Text(uuid)
                                .font(.system(.caption2, design: .monospaced))
                                .textSelection(.enabled)
                        }
                    }
                }

                if supportsVCI {
                    Section {
                        Toggle("Save Pairing Code", isOn: $savePairingCode)
                        if savePairingCode && !pairingCode.isEmpty {
                            LabeledContent("Code", value: pairingCode)
                        }
                    } header: {
                        Text("VCI Pairing Code")
                    } footer: {
                        Text("The pairing code is stored locally for automatic VCI establishment. It is not a secret.")
                    }
                }

                Section {
                    Toggle("Save PIN (biometric protected)", isOn: $savePIN)
                    if savePIN {
                        if pinToSave.isEmpty {
                            Button("Enter PIN") {
                                showPINEntry = true
                            }
                        } else {
                            LabeledContent("PIN", value: String(repeating: "*", count: pinToSave.count))
                        }
                    }
                } header: {
                    Text("PIV PIN")
                } footer: {
                    Text("The PIN is encrypted and requires Face ID or Touch ID to access.")
                }

                Section {
                    Button("Register Card") {
                        registerCard()
                    }
                    .disabled(!canRegister)
                    .font(.headline)
                }
            } else if !isReading {
                Section {
                    Button {
                        startRegistration()
                    } label: {
                        Label(
                            useUSB ? "Connect and Read" : "Read Card via NFC",
                            systemImage: useUSB ? "cable.connector" : "wave.3.right"
                        )
                    }
                }
            }
        }
        .navigationTitle("Register Card")
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
        }
        .sheet(isPresented: $showPairingCodeEntry) {
            PINEntryView(
                title: "VCI Pairing Code",
                prompt: "Enter 8-digit pairing code"
            ) { code in
                pairingCode = code
                performNFCRegistration(pairingCode: code)
            }
        }
        .sheet(isPresented: $showPINEntry) {
            PINEntryView(
                title: "PIV PIN",
                prompt: "Enter PIV application PIN"
            ) { pin in
                pinToSave = pin
            }
        }
        .sheet(isPresented: $showUSBPINEntry) {
            PINEntryView(
                title: "PIV PIN",
                prompt: "Enter PIN to read card data and pairing code"
            ) { pin in
                performUSBRegistration(pin: pin)
            }
        }
    }

    private func startRegistration() {
        if useUSB {
            showUSBPINEntry = true
        } else {
            showPairingCodeEntry = true
        }
    }

    // MARK: - USB Registration

    private func performUSBRegistration(pin: String) {
        isReading = true
        error = nil
        pinToSave = pin
        Task {
            await doUSBRegistration(pin: pin)
            isReading = false
        }
    }

    private func doUSBRegistration(pin: String) async {
        let usb = USBTransport()
        do {
            status = "Connecting to USB reader..."
            try await usb.connect()
            let card = PIVCard(transport: usb)

            status = "Selecting PIV application..."
            let selectResp = try await card.select()
            guard selectResp.success else {
                throw PIVError.commandFailed(sw: selectResp.sw, description: "SELECT failed")
            }

            // VERIFY PIN (needed to read pairing code container)
            status = "Verifying PIN..."
            let pinResp = try await card.verify(pin: pin)
            guard pinResp.success else {
                if pinResp.sw1 == 0x63 {
                    let retries = pinResp.sw2 & 0x0F
                    throw PIVError.commandFailed(sw: pinResp.sw, description: "Wrong PIN — \(retries) retries remaining")
                }
                throw PIVError.commandFailed(sw: pinResp.sw, description: "PIN verification failed")
            }

            try await readCardData(card: card, vciPairingCode: nil)

            // Read Pairing Code Reference Data Container (requires PIN)
            if supportsVCI {
                status = "Reading pairing code..."
                let pcResp = try await card.getData(DataObjects.PAIRING_CODE_REF)
                if pcResp.success, !pcResp.data.isEmpty {
                    // Parse: outer tag 53, inner contains the pairing code bytes
                    let tlvs = parseTLV(pcResp.data)
                    if let container = findTag(tlvs, 0x53) {
                        // The pairing code is typically tag 99 inside the container
                        let innerTLVs = container.children()
                        if let codeTLV = findTag(innerTLVs, 0x99) {
                            if let code = String(data: codeTLV.value, encoding: .utf8) {
                                pairingCode = code
                                savePairingCode = true
                                print("[REG] Read pairing code from card: \(code.count) chars")
                            }
                        } else if let code = String(data: container.value, encoding: .ascii) {
                            // Fallback: try the whole container value as ASCII
                            pairingCode = code.trimmingCharacters(in: .controlCharacters)
                            savePairingCode = true
                            print("[REG] Read pairing code (raw) from card: \(pairingCode.count) chars")
                        }
                    }
                }
            }

            usb.disconnect()
        } catch {
            usb.disconnect()
            self.error = error.localizedDescription
            status = "Error"
        }
    }

    // MARK: - NFC/VCI Registration

    private func performNFCRegistration(pairingCode: String) {
        isReading = true
        error = nil
        Task {
            await doNFCRegistration(pairingCode: pairingCode)
            isReading = false
        }
    }

    private func doNFCRegistration(pairingCode: String) async {
        let transport = NFCTransport()
        do {
            status = "Waiting for card..."
            try await transport.startSession(alertMessage: "Hold your PIV card near iPhone")
            let card = PIVCard(transport: transport)

            // SELECT
            status = "Selecting PIV application..."
            let selectResp = try await card.select()
            guard selectResp.success else {
                throw PIVError.commandFailed(sw: selectResp.sw, description: "SELECT failed")
            }

            // Establish SM
            status = "Establishing Secure Messaging..."
            try await card.establishSM()

            // VERIFY pairing code
            status = "Verifying pairing code..."
            let verifyResp = try await card.verifyPairingCode(pairingCode)
            guard verifyResp.success else {
                if verifyResp.sw1 == 0x63 {
                    let retries = verifyResp.sw2 & 0x0F
                    throw PIVError.commandFailed(sw: verifyResp.sw,
                        description: "Pairing code rejected — \(retries) retries remaining")
                }
                throw PIVError.commandFailed(sw: verifyResp.sw, description: "VERIFY pairing code failed")
            }
            self.pairingCode = pairingCode

            try await readCardData(card: card, vciPairingCode: pairingCode)
            transport.endSession(message: "Card data read successfully")
        } catch {
            transport.endSession(error: error.localizedDescription)
            self.error = error.localizedDescription
            status = "Error"
        }
    }

    // MARK: - Read Card Data (Common)

    private func readCardData(card: PIVCard, vciPairingCode: String?) async throws {
        // Discovery Object
        status = "Reading Discovery Object..."
        if let discovery = try? await card.getDiscovery() {
            supportsVCI = discovery.supportsVCI
            requiresPairingCode = discovery.requiresPairingCode
        }

        // PIV Auth cert (9A) — for subject name + UUID
        status = "Reading PIV Authentication certificate..."
        let pivAuthResp = try await card.getCertificate(DataObjects.X509_PIV_AUTH)
        print("[REG] PIV Auth (9A) SW: \(pivAuthResp.swHex), data: \(pivAuthResp.data.count) bytes")
        if pivAuthResp.success, let cert = pivAuthResp.parsed as? PIVCertificate {
            pivAuthCertDER = cert.certDER
            let dn = PIVCrypto.parseCertSubjectDN(cert.certDER)
            subjectName = dn.cn ?? "Unknown"
            organization = dn.o
            organizationalUnits = dn.ous

            if let uuid = PIVCrypto.extractUUIDFromCertSAN(cert.certDER) {
                cardUUID = uuid
            }
        }

        // Card Auth cert (9E) — for fingerprint + UUID fallback
        status = "Reading Card Authentication certificate..."
        let cardAuthResp = try await card.getCertificate(DataObjects.X509_CARD_AUTH)
        print("[REG] Card Auth (9E) SW: \(cardAuthResp.swHex), data: \(cardAuthResp.data.count) bytes")
        if cardAuthResp.success, let cert = cardAuthResp.parsed as? PIVCertificate {
            cardAuthFingerprint = sha256Hex(cert.certDER)

            if cardUUID == nil, let uuid = PIVCrypto.extractUUIDFromCertSAN(cert.certDER) {
                cardUUID = uuid
            }
        }

        if cardUUID == nil {
            throw PIVError.badTLV("Could not extract UUID from certificate SAN")
        }

        // Check for duplicate
        if let existingCard = registry.lookup(uuid: cardUUID!) {
            status = "Card already registered as \(existingCard.subjectName)"
        } else {
            status = "Card read — ready to register"
        }
    }

    // MARK: - Register

    private func registerCard() {
        guard let uuid = cardUUID, let name = subjectName else { return }

        let card = RegisteredCard(
            id: uuid,
            registeredAt: Date(),
            subjectName: name,
            organization: organization,
            organizationalUnits: organizationalUnits,
            cardAuthFingerprint: cardAuthFingerprint,
            pivAuthCertBase64: pivAuthCertDER?.base64EncodedString(),
            supportsVCI: supportsVCI,
            requiresPairingCode: requiresPairingCode,
            pairingCode: savePairingCode ? pairingCode : nil,
            hasPIN: false
        )
        registry.register(card)

        if savePIN && !pinToSave.isEmpty {
            _ = registry.savePIN(pinToSave, forCardID: uuid)
        }

        dismiss()
    }

    private func sha256Hex(_ data: Data) -> String {
        var hash = [UInt8](repeating: 0, count: 32)
        data.withUnsafeBytes { _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash) }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Registered Card Detail

struct RegisteredCardDetailView: View {
    let card: RegisteredCard
    @ObservedObject var registry: CardRegistry
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Form {
            Section("Identity") {
                LabeledContent("Name", value: card.subjectName)
                if let org = card.organization {
                    LabeledContent("Organization", value: org)
                }
                if !card.organizationalUnits.isEmpty {
                    ForEach(card.organizationalUnits, id: \.self) { ou in
                        LabeledContent("Unit", value: ou)
                    }
                }
            }

            Section("Card") {
                LabeledContent("UUID") {
                    Text(card.id)
                        .font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled)
                }
                LabeledContent("Registered", value: card.registeredAt.formatted(date: .abbreviated, time: .shortened))
                LabeledContent("VCI Support", value: card.supportsVCI ? "Yes" : "No")
                if card.supportsVCI {
                    LabeledContent("Pairing Code Required", value: card.requiresPairingCode ? "Yes" : "No")
                }
            }

            Section("Saved Credentials") {
                HStack {
                    Text("Pairing Code")
                    Spacer()
                    if card.pairingCode != nil {
                        Text("Saved")
                            .foregroundColor(.green)
                    } else {
                        Text("Not saved")
                            .foregroundColor(.secondary)
                    }
                }
                HStack {
                    Text("PIV PIN")
                    Spacer()
                    if card.hasPIN {
                        Text("Saved (biometric)")
                            .foregroundColor(.green)
                    } else {
                        Text("Not saved")
                            .foregroundColor(.secondary)
                    }
                }
            }

            if let fp = card.cardAuthFingerprint {
                Section("Card Auth Fingerprint") {
                    Text(fp)
                        .font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled)
                }
            }

            Section {
                Button(role: .destructive) {
                    registry.delete(card.id)
                    dismiss()
                } label: {
                    Label("Delete Registration", systemImage: "trash")
                }
            }
        }
        .navigationTitle("Registered Card")
    }
}
