import Foundation

// MARK: - Session State

/// Mutable session state tracked across commands.
struct SessionState {
    var selectedAID: String? = nil
    var smActive: Bool = false
    var sm: ClientPIVSM? = nil
    var securityStatus: [String: Bool] = [:]  // keyRef hex → verified
    var pairingCodeRequired: Bool? = nil       // nil = unknown
}

// MARK: - Session

/// Stateful wrapper around a CardTransport.
///
/// Handles SM wrapping/unwrapping transparently and tracks security status.
class Session {
    let transport: CardTransport
    private(set) var state = SessionState()
    private(set) var transcript: [CardResponse] = []
    let maxAPDULength: Int

    init(transport: CardTransport, maxAPDULength: Int = 255) {
        self.transport = transport
        self.maxAPDULength = maxAPDULength
    }

    /// True if SM is currently active.
    var smActive: Bool { state.smActive }

    /// True if VCI is established (SM active + pairing code verified).
    var vciActive: Bool {
        state.smActive && (state.securityStatus["98"] == true)
    }

    // MARK: - Transmit

    /// Transmit a command APDU, handling SM wrapping and command chaining.
    func transmit(_ apdu: CommandAPDU) async throws -> CardResponse {
        if let sm = state.sm, state.smActive {
            return try await transmitSM(apdu, sm: sm)
        }
        return try await transmitPlain(apdu)
    }

    /// Transmit without SM (plain APDU, with command chaining if needed).
    private func transmitPlain(_ apdu: CommandAPDU) async throws -> CardResponse {
        let command = PIVCommand(from: apdu)

        if apdu.data.count > maxAPDULength {
            // Command chaining
            return try await transmitChained(apdu, command: command)
        }

        let resp = try await transport.transmit(apdu)
        let response = PIVResponse(from: resp)
        let cardResp = CardResponse(
            sw1: resp.sw1, sw2: resp.sw2,
            data: resp.data, command: command
        )
        transcript.append(cardResp)
        return cardResp
    }

    /// Command chaining: split data into maxAPDULength-byte chunks.
    private func transmitChained(_ apdu: CommandAPDU, command: PIVCommand) async throws -> CardResponse {
        let chunks = stride(from: 0, to: apdu.data.count, by: maxAPDULength).map {
            apdu.data[$0..<min($0 + maxAPDULength, apdu.data.count)]
        }

        var lastResp: ResponseAPDU?
        for (i, chunk) in chunks.enumerated() {
            let isLast = (i == chunks.count - 1)
            let chainCLA: UInt8 = isLast ? apdu.cla : (apdu.cla | 0x10)
            let chainLE: Int? = isLast ? apdu.le : nil

            let chainAPDU = CommandAPDU(
                cla: chainCLA, ins: apdu.ins, p1: apdu.p1, p2: apdu.p2,
                data: Data(chunk), le: chainLE
            )
            lastResp = try await transport.transmit(chainAPDU)

            // Check intermediate responses
            if !isLast && !lastResp!.success {
                break
            }
        }

        let resp = lastResp ?? ResponseAPDU(data: Data(), sw1: 0x6F, sw2: 0x00)
        let cardResp = CardResponse(
            sw1: resp.sw1, sw2: resp.sw2,
            data: resp.data, command: command
        )
        transcript.append(cardResp)
        return cardResp
    }

    /// Transmit with SM wrapping and unwrapping.
    ///
    /// The SM payload is wrapped once (single encryption + MAC), then split
    /// across transport chunks if it exceeds maxAPDULength. This matches
    /// SP 800-73-5 Fig. 4: the MAC covers the entire payload, and chaining
    /// only splits the encrypted data at the transport level.
    private func transmitSM(_ apdu: CommandAPDU, sm: ClientPIVSM) async throws -> CardResponse {
        let command = PIVCommand(from: apdu)

        // Wrap the command (single encryption + MAC over entire payload)
        let wrappedBytes = sm.wrapCommand(
            cla: apdu.cla, ins: apdu.ins, p1: apdu.p1, p2: apdu.p2,
            data: apdu.data, le: apdu.le
        )

        let wrappedAPDU = CommandAPDU.fromBytes(wrappedBytes)!
        let smPayload = wrappedAPDU.data
        var resp: ResponseAPDU

        if smPayload.count > maxAPDULength {
            // SM command chaining: split the SM payload across transport chunks.
            // First chunk(s): CLA with chaining bit (0x10), no Le
            // Last chunk:     CLA without chaining bit, Le=0x00
            let chunks = stride(from: 0, to: smPayload.count, by: maxAPDULength).map {
                smPayload[$0..<min($0 + maxAPDULength, smPayload.count)]
            }

            resp = ResponseAPDU(data: Data(), sw1: 0x6F, sw2: 0x00)
            for (i, chunk) in chunks.enumerated() {
                let isLast = (i == chunks.count - 1)
                let chunkCLA: UInt8 = isLast
                    ? (wrappedAPDU.cla & ~0x10)
                    : (wrappedAPDU.cla | 0x10)
                let chunkAPDU = CommandAPDU(
                    cla: chunkCLA,
                    ins: wrappedAPDU.ins,
                    p1: wrappedAPDU.p1,
                    p2: wrappedAPDU.p2,
                    data: Data(chunk),
                    le: isLast ? 0 : nil
                )
                resp = try await transport.transmit(chunkAPDU)
                if !isLast && !resp.success {
                    break
                }
            }
        } else {
            resp = try await transport.transmit(wrappedAPDU)
        }

        // Unwrap the response
        let (plaintext, innerSW) = try sm.unwrapResponse(resp.responseBytes)

        let cardResp = CardResponse(
            sw1: UInt8(innerSW >> 8),
            sw2: UInt8(innerSW & 0xFF),
            data: plaintext,
            command: command
        )
        transcript.append(cardResp)
        return cardResp
    }

    // MARK: - SM Lifecycle

    func activateSM(_ sm: ClientPIVSM) {
        state.sm = sm
        state.smActive = true
    }

    func deactivateSM() {
        state.sm = nil
        state.smActive = false
    }

    // MARK: - Security Status

    func setSelected(_ aid: String) {
        state.selectedAID = aid
    }

    func setPINVerified(_ keyRef: String) {
        state.securityStatus[keyRef] = true
    }

    func clearPINVerified(_ keyRef: String) {
        state.securityStatus[keyRef] = false
    }

    func isPINVerified(_ keyRef: String) -> Bool {
        state.securityStatus[keyRef] ?? false
    }

    /// Reset all session state (simulates card reset).
    func reset() {
        state = SessionState()
    }
}
