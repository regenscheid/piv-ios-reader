import Foundation

/// High-level async API for PIV card operations over NFC.
///
/// Mirrors the Python pivlib `PIVCard` class. All methods are async
/// since NFC communication is inherently asynchronous on iOS.
///
/// Usage:
/// ```swift
/// let transport = NFCTransport()
/// try await transport.startSession()
/// let card = PIVCard(session: Session(transport: transport))
/// try await card.select()
/// let cert = try await card.getCertificate(DataObjects.X509_CARD_AUTH)
/// ```
class PIVCard {
    let session: Session
    private(set) var selectInfo: [String: Any]? = nil

    init(session: Session) {
        self.session = session
    }

    /// Convenience: create from a transport directly.
    convenience init(transport: CardTransport, maxAPDULength: Int = 255) {
        self.init(session: Session(transport: transport, maxAPDULength: maxAPDULength))
    }

    // MARK: - SELECT

    /// SELECT the PIV application.
    @discardableResult
    func select(aid: String = pivAIDFull) async throws -> CardResponse {
        let apdu = buildSelect(aidHex: aid)
        let resp = try await session.transmit(apdu)
        if resp.success {
            session.setSelected(aid)
            let parsed = parseSelectResponse(
                ResponseAPDU(data: resp.data, sw1: resp.sw1, sw2: resp.sw2)
            )
            selectInfo = parsed
        }
        return resp
    }

    // MARK: - VERIFY

    /// VERIFY PIN.
    @discardableResult
    func verify(pin: String?, keyRef: PIVKeyRef = .pivPIN) async throws -> CardResponse {
        let apdu = buildVerify(keyRef: keyRef.hex, pin: pin)
        let resp = try await session.transmit(apdu)
        if resp.success {
            session.setPINVerified(keyRef.hex)
        }
        return resp
    }

    /// Check PIN retry status (no PIN submitted).
    func verifyStatus(keyRef: PIVKeyRef = .pivPIN) async throws -> CardResponse {
        let apdu = buildVerify(keyRef: keyRef.hex, pin: nil)
        return try await session.transmit(apdu)
    }

    /// VERIFY pairing code (for VCI).
    @discardableResult
    func verifyPairingCode(_ code: String) async throws -> CardResponse {
        let apdu = buildVerify(keyRef: PIVKeyRef.pairingCode.hex, pin: code)
        let resp = try await session.transmit(apdu)
        if resp.success {
            session.setPINVerified(PIVKeyRef.pairingCode.hex)
        }
        return resp
    }

    // MARK: - GET DATA

    /// GET DATA for a PIV data object.
    func getData(_ spec: PIVObjectSpec) async throws -> CardResponse {
        let apdu = buildGetData(spec: spec)
        return try await session.transmit(apdu)
    }

    /// GET DATA by object name string.
    func getData(_ name: String) async throws -> CardResponse {
        let apdu = try buildGetData(objectName: name)
        return try await session.transmit(apdu)
    }

    /// GET DATA for CHUID, with automatic FASC-N parsing.
    func getCHUID() async throws -> CardResponse {
        let apdu = buildGetData(spec: DataObjects.CHUID)
        var resp = try await session.transmit(apdu)
        if resp.success, !resp.data.isEmpty {
            if let chuid = parseCHUIDContainer(resp.data) {
                resp = CardResponse(
                    sw1: resp.sw1, sw2: resp.sw2,
                    data: resp.data, command: resp.command,
                    parsed: chuid, exchange: resp.exchange
                )
            }
        }
        return resp
    }

    /// GET DATA for a certificate, with automatic parsing.
    func getCertificate(_ spec: PIVObjectSpec) async throws -> CardResponse {
        let apdu = buildGetData(spec: spec)
        var resp = try await session.transmit(apdu)
        if resp.success, !resp.data.isEmpty {
            if let cert = parseCertContainer(resp.data, tag: 0, name: spec.key) {
                resp = CardResponse(
                    sw1: resp.sw1, sw2: resp.sw2,
                    data: resp.data, command: resp.command,
                    parsed: cert, exchange: resp.exchange
                )
            }
        }
        return resp
    }

    // MARK: - Discovery Object

    /// Read and parse the Discovery Object to determine VCI support.
    ///
    /// Returns VCI capability flags, or nil if the Discovery Object is absent or unparseable.
    func getDiscovery() async throws -> (supportsVCI: Bool, requiresPairingCode: Bool)? {
        let resp = try await getData(DataObjects.DISCOVERY)
        guard resp.success, !resp.data.isEmpty else { return nil }

        let tlvs = parseTLV(resp.data)
        // Discovery Object is tag 7E containing tag 5F2F (PIN Usage Policy)
        guard let outer = findTag(tlvs, 0x7E) else { return nil }
        guard let pup = findTagRecursive(outer.children(), 0x5F2F) else { return nil }
        guard !pup.value.isEmpty else { return nil }

        let byte1 = pup.value[0]
        let supportsVCI = (byte1 & 0x08) != 0
        let requiresPairingCode = (byte1 & 0x04) == 0  // bit clear = required
        return (supportsVCI, requiresPairingCode)
    }

    // MARK: - GENERAL AUTHENTICATE

    /// GENERAL AUTHENTICATE.
    func generalAuthenticate(
        mode: GAMode,
        slot: PIVSlot = .authentication,
        algorithm: PIVAlgorithm = .eccP256,
        challenge: Data? = nil,
        witness: Data? = nil,
        dataPayload: Data? = nil
    ) async throws -> CardResponse {
        let apdu = buildGeneralAuthenticate(
            mode: mode,
            algorithmRef: algorithm.hex,
            keyRef: slot.hex,
            challenge: challenge,
            witness: witness,
            dataPayload: dataPayload
        )
        return try await session.transmit(apdu)
    }

    // MARK: - Secure Messaging

    /// Detect the preferred SM cipher suite from the cached SELECT response.
    ///
    /// Prefers CS7 (P-384/AES-256) if advertised, falls back to CS2 (P-256/AES-128).
    /// Returns nil if the card does not advertise any SM cipher suite.
    func detectSMCipherSuite() -> CipherSuite? {
        guard let algos = selectInfo?["algorithm_identifiers"] as? [String] else {
            return nil
        }
        // Prefer CS7 (0x2E), fall back to CS2 (0x27)
        if algos.contains("2E") { return .cs7 }
        if algos.contains("27") { return .cs2 }
        return nil
    }

    /// True if the card advertises SM support in its SELECT response.
    var supportsSM: Bool { detectSMCipherSuite() != nil }

    /// Establish SM via ECDH key agreement.
    ///
    /// After this call, all subsequent commands are automatically SM-wrapped.
    /// If no cipher suite is specified, auto-detects from the SELECT response.
    @discardableResult
    func establishSM(cipherSuite: CipherSuite? = nil,
                     idSH: Data = Data(count: 8)) async throws -> CipherSuite {
        guard let suite = cipherSuite ?? detectSMCipherSuite() else {
            throw PIVError.smEstablishmentFailed(
                "Card does not advertise an SM cipher suite in SELECT response"
            )
        }
        let sm = try await performSMKeyEstablishment(
            session: session,
            cipherSuite: suite,
            idSH: idSH
        )
        session.activateSM(sm)
        return suite
    }

    /// Tear down SM session.
    func terminateSM() {
        session.deactivateSM()
    }

    /// True if SM is active.
    var smActive: Bool { session.smActive }

    /// True if VCI is established (SM + pairing code).
    var vciActive: Bool { session.vciActive }

    // MARK: - Raw Transmit

    /// Send a raw CommandAPDU (escape hatch).
    func transmit(_ apdu: CommandAPDU) async throws -> CardResponse {
        return try await session.transmit(apdu)
    }
}
