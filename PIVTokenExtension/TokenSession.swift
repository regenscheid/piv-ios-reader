//
//  TokenSession.swift
//  PIVTokenExtension
//

import CryptoTokenKit
import UserNotifications
import OSLog

private let appGroupID = "group.com.pivforge.PIVReader"
private let pollInterval: TimeInterval = 0.25
private let sessionTimeout: TimeInterval = 95

private let logger = Logger(subsystem: "com.pivreader.TokenExtension", category: "CTK")

class TokenSession: TKTokenSession, TKTokenSessionDelegate {

    // Debounce duplicate calls from CryptoTokenKit
    private var signSessionEndTime = Date(timeIntervalSinceNow: -10)
    private var decryptSessionEndTime = Date(timeIntervalSinceNow: -10)

    enum OperationType: String {
        case signData = "signData"
        case decryptData = "decryptData"
    }

    // MARK: - Auth

    func tokenSession(
        _ session: TKTokenSession,
        beginAuthFor operation: TKTokenOperation,
        constraint: Any
    ) throws -> TKTokenAuthOperation {
        logger.debug("beginAuthFor operation: \(String(describing: operation))")
        return TKTokenPasswordAuthOperation()
    }

    // MARK: - Capabilities

    func tokenSession(
        _ session: TKTokenSession,
        supports operation: TKTokenOperation,
        keyObjectID: Any,
        algorithm: TKTokenKeyAlgorithm
    ) -> Bool {
        switch operation {
        case .signData, .decryptData:
            return true
        default:
            return false
        }
    }

    // MARK: - Sign

    func tokenSession(
        _ session: TKTokenSession,
        sign dataToSign: Data,
        keyObjectID: Any,
        algorithm: TKTokenKeyAlgorithm
    ) throws -> Data {
        // Debounce duplicate requests
        if signSessionEndTime.timeIntervalSinceNow > 0 {
            cancelAllNotifications()
            throw NSError(domain: TKErrorDomain, code: TKError.Code.canceledByUser.rawValue)
        }
        if signSessionEndTime.timeIntervalSinceNow < 0 {
            reset()
            signSessionEndTime = Date(timeIntervalSinceNow: sessionTimeout + 5)
        }

        guard let key = try? session.token.configuration.key(for: keyObjectID),
              let objectId = keyObjectID as? String else {
            logger.error("No key or objectId for sign request")
            throw NSError(domain: TKErrorDomain, code: TKError.Code.canceledByUser.rawValue)
        }

        let keyType = detectKeyType(key: key)

        // Detect the actual algorithm the TLS stack is requesting
        let algorithmChecks: [(String, SecKeyAlgorithm)] = [
            ("rsaSignatureMessagePSSSHA256", .rsaSignatureMessagePSSSHA256),
            ("rsaSignatureMessagePSSSHA384", .rsaSignatureMessagePSSSHA384),
            ("rsaSignatureMessagePSSSHA512", .rsaSignatureMessagePSSSHA512),
            ("rsaSignatureDigestPSSSHA256", .rsaSignatureDigestPSSSHA256),
            ("rsaSignatureDigestPSSSHA384", .rsaSignatureDigestPSSSHA384),
            ("rsaSignatureDigestPSSSHA512", .rsaSignatureDigestPSSSHA512),
            ("rsaSignatureMessagePKCS1v15SHA256", .rsaSignatureMessagePKCS1v15SHA256),
            ("rsaSignatureMessagePKCS1v15SHA384", .rsaSignatureMessagePKCS1v15SHA384),
            ("rsaSignatureMessagePKCS1v15SHA512", .rsaSignatureMessagePKCS1v15SHA512),
            ("rsaSignatureDigestPKCS1v15SHA256", .rsaSignatureDigestPKCS1v15SHA256),
            ("rsaSignatureDigestPKCS1v15SHA384", .rsaSignatureDigestPKCS1v15SHA384),
            ("rsaSignatureDigestPKCS1v15SHA512", .rsaSignatureDigestPKCS1v15SHA512),
            ("rsaSignatureDigestPKCS1v15Raw", .rsaSignatureDigestPKCS1v15Raw),
            ("rsaSignatureRaw", .rsaSignatureRaw),
            ("ecdsaSignatureMessageX962SHA256", .ecdsaSignatureMessageX962SHA256),
            ("ecdsaSignatureMessageX962SHA384", .ecdsaSignatureMessageX962SHA384),
            ("ecdsaSignatureDigestX962SHA256", .ecdsaSignatureDigestX962SHA256),
            ("ecdsaSignatureDigestX962SHA384", .ecdsaSignatureDigestX962SHA384),
        ]

        var matchedAlgorithm = "unknown"
        for (name, alg) in algorithmChecks {
            if algorithm.isAlgorithm(alg) {
                matchedAlgorithm = name
                break
            }
        }

        logger.info("SIGN: objectId=\(objectId) keyType=\(keyType) matchedAlgorithm=\(matchedAlgorithm) dataSize=\(dataToSign.count)")

        sendNotification(
            type: .signData,
            data: dataToSign,
            keyObjectID: objectId,
            keyType: keyType,
            algorithm: matchedAlgorithm
        )

        let result = try pollForResult(resultKey: "signedData")
        logger.info("SIGN: returning \(result.count) bytes to CryptoTokenKit")
        return result
    }

    // MARK: - Decrypt

    func tokenSession(
        _ session: TKTokenSession,
        decrypt ciphertext: Data,
        keyObjectID: Any,
        algorithm: TKTokenKeyAlgorithm
    ) throws -> Data {
        if decryptSessionEndTime.timeIntervalSinceNow > 0 {
            cancelAllNotifications()
            throw NSError(domain: TKErrorDomain, code: TKError.Code.canceledByUser.rawValue)
        }
        if decryptSessionEndTime.timeIntervalSinceNow < 0 {
            reset()
            decryptSessionEndTime = Date(timeIntervalSinceNow: sessionTimeout + 5)
        }

        guard let key = try? session.token.configuration.key(for: keyObjectID),
              let objectId = keyObjectID as? String else {
            throw NSError(domain: TKErrorDomain, code: TKError.Code.canceledByUser.rawValue)
        }

        let keyType = detectKeyType(key: key)
        let algorithmName = resolveAlgorithm(algorithm, key: key, operation: .decryptData)

        sendNotification(
            type: .decryptData,
            data: ciphertext,
            keyObjectID: objectId,
            keyType: keyType,
            algorithm: algorithmName
        )

        return try pollForResult(resultKey: "decryptedData")
    }

    // MARK: - Polling

    private func pollForResult(resultKey: String) throws -> Data {
        let loopEnd = Date(timeIntervalSinceNow: sessionTimeout)

        while Date() < loopEnd {
            Thread.sleep(forTimeInterval: pollInterval)

            guard let defaults = UserDefaults(suiteName: appGroupID) else { continue }

            if let resultData = defaults.value(forKey: resultKey) as? Data {
                logger.debug("Got \(resultKey) from UserDefaults")
                signSessionEndTime = Date(timeIntervalSinceNow: 3)
                decryptSessionEndTime = Date(timeIntervalSinceNow: 3)
                reset()
                return resultData
            }

            if defaults.value(forKey: "canceledByUser") != nil {
                logger.debug("User canceled")
                signSessionEndTime = Date(timeIntervalSinceNow: 3)
                decryptSessionEndTime = Date(timeIntervalSinceNow: 3)
                reset()
                throw NSError(domain: TKErrorDomain, code: TKError.Code.canceledByUser.rawValue)
            }
        }

        logger.debug("Polling timeout")
        reset()
        throw NSError(domain: TKErrorDomain, code: TKError.Code.canceledByUser.rawValue)
    }

    // MARK: - Helpers

    private func detectKeyType(key: TKTokenKeychainKey) -> UInt8 {
        if key.keyType == kSecAttrKeyTypeRSA as String {
            return key.keySizeInBits <= 2048 ? 0x07 : 0x05  // RSA 2048 or RSA 3072
        } else if key.keyType == kSecAttrKeyTypeECSECPrimeRandom as String {
            return key.keySizeInBits <= 256 ? 0x11 : 0x14  // P-256 or P-384
        }
        return 0x00
    }

    /// Map TKTokenKeyAlgorithm to a SecKeyAlgorithm name string for the main app.
    private func resolveAlgorithm(_ algorithm: TKTokenKeyAlgorithm, key: TKTokenKeychainKey, operation: OperationType) -> String {
        let isEC = key.keyType == kSecAttrKeyTypeECSECPrimeRandom as String
        let is384 = key.keySizeInBits > 256

        if operation == .signData {
            if isEC {
                return is384
                    ? SecKeyAlgorithm.ecdsaSignatureDigestX962SHA384.rawValue as String
                    : SecKeyAlgorithm.ecdsaSignatureDigestX962SHA256.rawValue as String
            } else {
                return is384
                    ? SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA384.rawValue as String
                    : SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA256.rawValue as String
            }
        } else {
            return SecKeyAlgorithm.rsaEncryptionPKCS1.rawValue as String
        }
    }

    private func sendNotification(
        type: OperationType,
        data: Data,
        keyObjectID: String,
        keyType: UInt8,
        algorithm: String
    ) {
        cancelAllNotifications()

        let content = UNMutableNotificationContent()
        content.title = "PIV Card Required"
        content.body = type == .signData
            ? "Tap here to sign with your PIV card."
            : "Tap here to decrypt with your PIV card."
        content.categoryIdentifier = type.rawValue
        content.userInfo = [
            "operationType": type.rawValue,
            "data": data,
            "keyObjectID": keyObjectID,
            "algorithm": algorithm,
            "keyType": keyType,
        ]
        content.sound = .default

        let action = UNNotificationAction(
            identifier: type.rawValue,
            title: "Open PIV Reader",
            options: .foreground
        )
        let category = UNNotificationCategory(
            identifier: type.rawValue,
            actions: [action],
            intentIdentifiers: []
        )

        let center = UNUserNotificationCenter.current()
        center.setNotificationCategories([category])
        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: UNTimeIntervalNotificationTrigger(timeInterval: 0.1, repeats: false)
        )
        center.add(request)
    }

    private func reset() {
        cancelAllNotifications()
        if let defaults = UserDefaults(suiteName: appGroupID) {
            defaults.removeObject(forKey: "canceledByUser")
            defaults.removeObject(forKey: "signedData")
            defaults.removeObject(forKey: "decryptedData")
        }
    }

    private func cancelAllNotifications() {
        let center = UNUserNotificationCenter.current()
        center.removeAllDeliveredNotifications()
        center.removeAllPendingNotificationRequests()
    }
}
