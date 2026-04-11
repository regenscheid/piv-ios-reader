import Foundation
import Security
import UserNotifications
import UIKit
import os

private let appGroupID = "group.com.pivforge.PIVReader"
private let log = Logger(subsystem: "com.pivforge.PIVReader", category: "TokenRequest")

/// Handles cryptographic operation requests from the CryptoTokenKit token extension.
@MainActor
class TokenRequestHandler: NSObject, ObservableObject {
    static let shared = TokenRequestHandler()

    @Published var hasPendingRequest = false
    @Published var requestStatus: String?
    @Published var requestError: String?
    @Published var showPINEntry = false

    private var pendingUserInfo: [AnyHashable: Any]?
    private var pendingCardUUID: String?

    override init() {
        super.init()
        // Delegate is set in AppDelegate.didFinishLaunching for cold-launch support
        requestNotificationPermission()
        log.debug("[CTK] TokenRequestHandler initialized")
    }

    private func requestNotificationPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { granted, _ in
            log.debug("[CTK] Notifications \(granted ? "granted" : "denied")")
        }
    }

    // MARK: - Handle Request

    func handleNotification(_ userInfo: [AnyHashable: Any]) {
        log.debug("[CTK] handleNotification called")
        pendingUserInfo = userInfo
        hasPendingRequest = true
        requestError = nil

        guard let keyObjectID = userInfo["keyObjectID"] as? String else {
            requestError = "Invalid sign request — no keyObjectID"
            log.debug("[CTK] ERROR: no keyObjectID in notification")
            return
        }

        let cardUUID = String(keyObjectID.dropLast(3))  // Remove "-9A"
        pendingCardUUID = cardUUID
        log.debug("[CTK] Sign request for card UUID: \(cardUUID)")

        // Try biometric PIN retrieval on a background thread (keychain call blocks)
        if let registered = CardRegistry.shared.lookup(uuid: cardUUID), registered.hasPIN {
            requestStatus = "Authenticating to retrieve PIN..."
            log.debug("[CTK] Card has saved PIN, attempting biometric read")
            Task.detached {
                let pin = CardRegistry.shared.readPIN(forCardID: cardUUID)
                await MainActor.run {
                    if let pin {
                        log.debug("[CTK] Biometric PIN read succeeded")
                        Task { await self.performSignRequest(pin: pin) }
                    } else {
                        log.debug("[CTK] Biometric PIN read failed, showing manual entry")
                        self.requestStatus = "Enter PIN"
                        self.showPINEntry = true
                    }
                }
            }
        } else {
            log.debug("[CTK] No saved PIN, showing manual entry")
            requestStatus = "Enter PIN"
            showPINEntry = true
        }
    }

    /// Perform the signing operation using a PIV card.
    func performSignRequest(pin: String) async {
        guard let userInfo = pendingUserInfo,
              let operationType = userInfo["operationType"] as? String,
              let dataToSign = userInfo["data"] as? Data,
              let keyObjectID = userInfo["keyObjectID"] as? String else {
            requestError = "Invalid sign request"
            log.debug("[CTK] ERROR: missing fields in pendingUserInfo")
            return
        }

        showPINEntry = false
        let cardUUID = String(keyObjectID.dropLast(3))
        let registry = CardRegistry.shared

        do {
            // Detect algorithm from registered certificate
            guard let registered = registry.lookup(uuid: cardUUID),
                  let certBase64 = registered.pivAuthCertBase64,
                  let certDER = Data(base64Encoded: certBase64),
                  let algorithm = ChallengeResponse.detectAlgorithm(certDER: certDER) else {
                throw PIVError.badTLV("Cannot detect algorithm for card \(cardUUID)")
            }
            log.debug("[CTK] Detected algorithm: \(algorithm.label)")

            // Determine signing scheme from the algorithm name passed by the extension
            let algorithmRaw = userInfo["algorithm"] as? String ?? ""
            let isPSS = algorithmRaw.contains("PSS")
            let isMessage = algorithmRaw.contains("Message") || algorithmRaw.contains("message") || dataToSign.count > 48
            let useSHA384 = algorithmRaw.contains("SHA384") || algorithmRaw.contains("384")

            log.debug("[CTK] algorithmRaw=\(algorithmRaw) isPSS=\(isPSS) isMessage=\(isMessage) useSHA384=\(useSHA384)")

            let payload: Data
            if algorithm.isRSA {
                // Hash the message if needed
                let digest: Data
                if isMessage {
                    digest = useSHA384 ? PIVCrypto.sha384(dataToSign) : PIVCrypto.sha256(dataToSign)
                    log.debug("[CTK] RSA: hashed \(dataToSign.count)-byte message to \(digest.count)-byte digest")
                } else {
                    digest = dataToSign
                }

                if isPSS {
                    // RSA-PSS padding (RFC 8017 §9.1.1)
                    payload = rsaPSSPad(digest: digest, useSHA384: useSHA384, keySizeBytes: algorithm.keySizeBytes)
                    log.debug("[CTK] RSA-PSS padded: \(payload.count) bytes")
                } else {
                    // PKCS#1 v1.5 padding
                    payload = ChallengeResponse.pkcs1v15PadForSign(
                        digest: digest,
                        useSHA384: useSHA384,
                        keySizeBytes: algorithm.keySizeBytes
                    )
                    log.debug("[CTK] RSA PKCS#1 v1.5 padded: \(payload.count) bytes")
                }
            } else {
                // ECC: hash if message, otherwise pass digest directly
                if isMessage {
                    payload = useSHA384 ? PIVCrypto.sha384(dataToSign) : PIVCrypto.sha256(dataToSign)
                    log.debug("[CTK] ECC: hashed to \(payload.count)-byte digest")
                } else {
                    payload = dataToSign
                    log.debug("[CTK] ECC raw digest: \(payload.count) bytes")
                }
            }

            // Auto-detect transport: try USB first, fall back to NFC
            let transport: CardTransport
            let nfcTransport: NFCTransport?
            let isUSB: Bool

            let usb = USBTransport()
            do {
                requestStatus = "Connecting to USB reader..."
                try await usb.connect()
                transport = usb
                nfcTransport = nil
                isUSB = true
                log.debug("[CTK] Using USB transport")
            } catch {
                log.debug("[CTK] USB not available (\(error)), falling back to NFC")
                let nfc = NFCTransport()
                try await nfc.startSession(alertMessage: "Hold your PIV card near iPhone to sign")
                transport = nfc
                nfcTransport = nfc
                isUSB = false
            }

            let card = PIVCard(transport: transport)
            requestStatus = "Selecting PIV..."
            log.debug("[CTK] Sending SELECT")

            let selectResp = try await card.select()
            guard selectResp.success else {
                throw PIVError.commandFailed(sw: selectResp.sw, description: "SELECT failed")
            }
            log.debug("[CTK] SELECT OK")

            // If NFC, need SM + VCI for PIV Auth key access
            if !isUSB {
                requestStatus = "Establishing Secure Messaging..."
                log.debug("[CTK] Establishing SM")
                try await card.establishSM()

                if let pairingCode = registered.pairingCode {
                    requestStatus = "Verifying pairing code..."
                    log.debug("[CTK] Verifying pairing code")
                    let verifyResp = try await card.verifyPairingCode(pairingCode)
                    guard verifyResp.success else {
                        throw PIVError.commandFailed(sw: verifyResp.sw, description: "Pairing code failed")
                    }
                }
            }

            // VERIFY PIN
            requestStatus = "Verifying PIN..."
            log.debug("[CTK] Verifying PIN")
            let pinResp = try await card.verify(pin: pin)
            guard pinResp.success else {
                if pinResp.sw1 == 0x63 {
                    let retries = pinResp.sw2 & 0x0F
                    throw PIVError.commandFailed(sw: pinResp.sw, description: "Wrong PIN — \(retries) retries")
                }
                throw PIVError.commandFailed(sw: pinResp.sw, description: "PIN verification failed")
            }
            log.debug("[CTK] PIN OK")

            // GENERAL AUTHENTICATE (sign with PIV Auth key, slot 9A)
            requestStatus = "Signing..."
            log.debug("[CTK] Sending GENERAL AUTHENTICATE")
            let gaResp = try await card.generalAuthenticate(
                mode: .internalAuthenticate,
                slot: .authentication,
                algorithm: algorithm.pivAlgorithm,
                challenge: payload
            )

            guard gaResp.success else {
                throw PIVError.commandFailed(sw: gaResp.sw, description: "Sign failed: \(gaResp.swHex)")
            }

            guard let signature = extractGASignature(gaResp) else {
                throw PIVError.badTLV("No signature in GA response")
            }
            log.debug("[CTK] Got signature: \(signature.count) bytes")

            // Write result to shared UserDefaults for the extension to pick up
            let resultKey = operationType == "signData" ? "signedData" : "decryptedData"
            if let defaults = UserDefaults(suiteName: appGroupID) {
                defaults.setValue(signature, forKey: resultKey)
                defaults.synchronize()
                log.debug("[CTK] Wrote \(resultKey) to shared UserDefaults")
            } else {
                log.debug("[CTK] ERROR: Could not open shared UserDefaults!")
            }

            if let nfc = nfcTransport {
                nfc.endSession(message: "Signed successfully")
            } else if isUSB {
                (transport as? USBTransport)?.disconnect()
            }

            requestStatus = "Signed successfully"
            log.debug("[CTK] Sign flow complete")
            hasPendingRequest = false
            pendingUserInfo = nil

            // Brief delay to let UserDefaults sync, then switch back to Safari
            try? await Task.sleep(nanoseconds: 300_000_000)
            await UIApplication.shared.open(URL(string: "https://")!)

        } catch {
            log.debug("[CTK] ERROR: \(error)")
            requestError = error.localizedDescription
            requestStatus = "Sign failed"
            cancelRequest()
        }
    }

    func cancelRequest() {
        if let defaults = UserDefaults(suiteName: appGroupID) {
            defaults.setValue(true, forKey: "canceledByUser")
            defaults.synchronize()
        }
        hasPendingRequest = false
        pendingUserInfo = nil
        showPINEntry = false
    }
}

// MARK: - RSA-PSS Padding (RFC 8017 §9.1.1)

/// Apply EMSA-PSS encoding for RSA-PSS signatures.
/// The PIV card does raw modular exponentiation, so we must construct
/// the full PSS-padded block on the host side.
private func rsaPSSPad(digest: Data, useSHA384: Bool, keySizeBytes: Int) -> Data {
    let hashLen = useSHA384 ? 48 : 32
    let sLen = hashLen  // salt length = hash length (standard)
    let emLen = keySizeBytes

    // Generate random salt
    var salt = Data(count: sLen)
    _ = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, sLen, $0.baseAddress!) }

    // M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    var mPrime = Data(count: 8)
    mPrime.append(digest)
    mPrime.append(salt)

    // H = Hash(M')
    let h = useSHA384 ? PIVCrypto.sha384(mPrime) : PIVCrypto.sha256(mPrime)

    // DB = PS || 0x01 || salt
    // PS length = emLen - sLen - hashLen - 2
    let psLen = emLen - sLen - hashLen - 2
    var db = Data(count: psLen)
    db.append(0x01)
    db.append(salt)

    // dbMask = MGF1(H, emLen - hashLen - 1)
    let dbMaskLen = emLen - hashLen - 1
    let dbMask = mgf1(seed: h, length: dbMaskLen, useSHA384: useSHA384)

    // maskedDB = DB xor dbMask
    var maskedDB = Data(count: db.count)
    for i in 0..<db.count {
        maskedDB[i] = db[i] ^ dbMask[i]
    }

    // Set the leftmost bits to zero (for key size alignment)
    let topBits = (8 * emLen) - (keySizeBytes * 8 - 1)
    if topBits > 0 {
        // Clear the top bit(s) — for standard key sizes this clears bit 7 of byte 0
        maskedDB[0] &= UInt8(0xFF >> topBits)
    }

    // EM = maskedDB || H || 0xBC
    var em = maskedDB
    em.append(h)
    em.append(0xBC)

    return em
}

/// MGF1 mask generation function (RFC 8017 §B.2.1)
private func mgf1(seed: Data, length: Int, useSHA384: Bool) -> Data {
    var output = Data()
    var counter: UInt32 = 0

    while output.count < length {
        var input = seed
        // Append counter as 4-byte big-endian
        input.append(UInt8((counter >> 24) & 0xFF))
        input.append(UInt8((counter >> 16) & 0xFF))
        input.append(UInt8((counter >> 8) & 0xFF))
        input.append(UInt8(counter & 0xFF))
        output.append(useSHA384 ? PIVCrypto.sha384(input) : PIVCrypto.sha256(input))
        counter += 1
    }

    return output.prefix(length)
}

// MARK: - Notification Delegate

extension TokenRequestHandler: UNUserNotificationCenterDelegate {
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let userInfo = response.notification.request.content.userInfo
        log.debug("[CTK] Notification tapped, forwarding to handler")
        Task { @MainActor in
            handleNotification(userInfo)
        }
        completionHandler()
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }
}
