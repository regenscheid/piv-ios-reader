import Foundation
import CoreNFC

/// Protocol for card communication (abstraction over NFC / stub).
protocol CardTransport {
    func transmit(_ apdu: CommandAPDU) async throws -> ResponseAPDU
    var isConnected: Bool { get }
}

// MARK: - NFCTransport

/// Core NFC transport: communicates with an ISO 7816 contactless card.
///
/// Usage:
/// ```swift
/// let transport = NFCTransport()
/// try await transport.startSession()
/// let resp = try await transport.transmit(buildSelect(aidHex: pivAIDFull))
/// transport.endSession()
/// ```
class NFCTransport: NSObject, CardTransport {
    private var nfcSession: NFCTagReaderSession?
    private var tag: NFCISO7816Tag?
    private var continuation: CheckedContinuation<NFCISO7816Tag, Error>?

    var isConnected: Bool { tag != nil }

    /// Start an NFC reader session and wait for a tag.
    ///
    /// Returns when a tag is detected and connected. The NFC sheet remains
    /// visible for the duration; call `endSession()` when done.
    func startSession(alertMessage: String = "Hold your PIV card near iPhone") async throws {
        tag = try await withCheckedThrowingContinuation { cont in
            self.continuation = cont
            guard let session = NFCTagReaderSession(
                pollingOption: [.iso14443, .iso15693],
                delegate: self
            ) else {
                cont.resume(throwing: PIVError.nfcSessionFailed("NFC not available on this device"))
                self.continuation = nil
                return
            }
            session.alertMessage = alertMessage
            self.nfcSession = session
            session.begin()
        }
    }

    /// End the NFC session and dismiss the system NFC sheet.
    func endSession(message: String? = nil) {
        if let msg = message {
            nfcSession?.alertMessage = msg
        }
        nfcSession?.invalidate()
        nfcSession = nil
        tag = nil
    }

    /// End the session with an error message.
    func endSession(error: String) {
        nfcSession?.invalidate(errorMessage: error)
        nfcSession = nil
        tag = nil
    }

    /// Transmit a command APDU and return the response.
    ///
    /// Handles 61XX (GET RESPONSE) chaining manually, since CoreNFC does not
    /// always do it automatically for ISO 7816 APDUs.
    func transmit(_ apdu: CommandAPDU) async throws -> ResponseAPDU {
        guard let tag = tag else { throw PIVError.notConnected }

        let nfcAPDU = apdu.toNFCAPDU()
        var (responseData, sw1, sw2) = try await tag.sendCommand(apdu: nfcAPDU)
        var allData = Data(responseData)

        // Handle 61XX: more data available, send GET RESPONSE to retrieve it
        while sw1 == 0x61 {
            let remaining = Int(sw2) == 0 ? 256 : Int(sw2)
            let getResponse = CommandAPDU(ins: 0xC0, p1: 0x00, p2: 0x00, le: remaining)
            let grAPDU = getResponse.toNFCAPDU()
            (responseData, sw1, sw2) = try await tag.sendCommand(apdu: grAPDU)
            allData.append(contentsOf: responseData)
        }

        return ResponseAPDU(data: allData, sw1: sw1, sw2: sw2)
    }
}

// MARK: - NFCTagReaderSessionDelegate

extension NFCTransport: NFCTagReaderSessionDelegate {

    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        print("NFC session active — polling for tags...")
    }

    func tagReaderSession(_ session: NFCTagReaderSession,
                          didDetect tags: [NFCTag]) {
        // Log all detected tag types for debugging
        for (i, tag) in tags.enumerated() {
            switch tag {
            case .iso7816(let t):
                print("Tag[\(i)]: ISO 7816 — AID: \(t.initialSelectedAID), identifier: \(t.identifier.map { String(format: "%02X", $0) }.joined())")
            case .iso15693(let t):
                print("Tag[\(i)]: ISO 15693 — identifier: \(t.identifier.map { String(format: "%02X", $0) }.joined())")
            case .miFare(let t):
                print("Tag[\(i)]: MiFare — type: \(t.mifareFamily.rawValue), identifier: \(t.identifier.map { String(format: "%02X", $0) }.joined())")
            case .feliCa(let t):
                print("Tag[\(i)]: FeliCa — identifier: \(t.currentIDm.map { String(format: "%02X", $0) }.joined())")
            @unknown default:
                print("Tag[\(i)]: Unknown type")
            }
        }

        // Try to find an ISO 7816 tag; fall back to MiFare (which also supports ISO 7816 APDUs)
        var targetTag: NFCTag?
        var isoTag: NFCISO7816Tag?

        for tag in tags {
            switch tag {
            case .iso7816(let t):
                targetTag = tag
                isoTag = t
            case .miFare(let t):
                // MiFare DESFire and Plus cards support ISO 7816 commands
                if targetTag == nil, let iso = t as? NFCISO7816Tag {
                    targetTag = tag
                    isoTag = iso
                }
            default:
                break
            }
            if targetTag != nil { break }
        }

        guard let targetTag, let isoTag else {
            let tagTypes = tags.map { tag -> String in
                switch tag {
                case .iso7816: return "iso7816"
                case .miFare(let t): return "miFare(\(t.mifareFamily.rawValue))"
                case .iso15693: return "iso15693"
                case .feliCa: return "feliCa"
                @unknown default: return "unknown"
                }
            }.joined(separator: ", ")
            print("No ISO 7816 tag found. Detected: [\(tagTypes)] — restarting polling...")
            session.alertMessage = "Card not recognized. Hold card steady near top of iPhone."
            session.restartPolling()
            return
        }

        session.connect(to: targetTag) { [weak self] error in
            if let error = error {
                print("Connection failed: \(error.localizedDescription) — restarting polling...")
                session.alertMessage = "Connection lost. Hold card steady near top of iPhone."
                session.restartPolling()
            } else {
                self?.continuation?.resume(returning: isoTag)
                self?.continuation = nil
            }
        }
    }

    func tagReaderSession(_ session: NFCTagReaderSession,
                          didInvalidateWithError error: Error) {
        print("NFC session invalidated: \(error.localizedDescription)")
        // If continuation is still pending, fail it
        continuation?.resume(throwing: PIVError.nfcSessionFailed(error.localizedDescription))
        continuation = nil
        tag = nil
    }
}
