import Foundation
import Security
import LocalAuthentication

/// A registered PIV card in the database.
struct RegisteredCard: Identifiable, Codable {
    let id: String                  // UUID from cert SAN (OID 1.3.6.1.1.16.4)
    let registeredAt: Date
    let subjectName: String         // CN from PIV Auth cert
    let organization: String?       // O from PIV Auth cert
    let organizationalUnits: [String] // OU(s) from PIV Auth cert
    let cardAuthFingerprint: String? // SHA-256 of card auth cert DER
    let supportsVCI: Bool
    let requiresPairingCode: Bool
    var pairingCode: String?        // plain storage (not a secret)
    var hasPIN: Bool                // true if PIN stored in keychain
}

/// Manages registered PIV cards with JSON persistence and keychain PIN storage.
class CardRegistry: ObservableObject {
    static let shared = CardRegistry()

    @Published private(set) var cards: [RegisteredCard] = []

    private static let keychainService = "com.pivreader.card-secrets"

    private let storeURL: URL = {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return docs.appendingPathComponent("card_registry.json")
    }()

    init() {
        loadFromDisk()
    }

    // MARK: - Lookup

    func lookup(uuid: String) -> RegisteredCard? {
        cards.first { $0.id.lowercased() == uuid.lowercased() }
    }

    func lookupByCardAuthFingerprint(_ fingerprint: String) -> RegisteredCard? {
        cards.first { $0.cardAuthFingerprint?.lowercased() == fingerprint.lowercased() }
    }

    // MARK: - Registration

    func register(_ card: RegisteredCard) {
        if let idx = cards.firstIndex(where: { $0.id == card.id }) {
            cards[idx] = card
        } else {
            cards.append(card)
        }
        saveToDisk()
    }

    func delete(_ id: String) {
        cards.removeAll { $0.id == id }
        deletePIN(forCardID: id)
        saveToDisk()
    }

    func updatePairingCode(_ id: String, code: String?) {
        guard let idx = cards.firstIndex(where: { $0.id == id }) else { return }
        cards[idx].pairingCode = code
        saveToDisk()
    }

    // MARK: - PIN (Keychain with Biometric)

    func savePIN(_ pin: String, forCardID cardID: String) -> Bool {
        deletePIN(forCardID: cardID)

        guard let pinData = pin.data(using: .utf8) else { return false }

        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet,
            &error
        ) else { return false }

        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.keychainService,
            kSecAttrAccount: "\(cardID)-pin",
            kSecValueData: pinData,
            kSecAttrAccessControl: access,
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecSuccess {
            if let idx = cards.firstIndex(where: { $0.id == cardID }) {
                cards[idx].hasPIN = true
                saveToDisk()
            }
            return true
        }
        print("Keychain save failed: \(status)")
        return false
    }

    /// Read PIN from keychain. Triggers biometric prompt.
    func readPIN(forCardID cardID: String) -> String? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.keychainService,
            kSecAttrAccount: "\(cardID)-pin",
            kSecReturnData: true,
            kSecUseOperationPrompt: "Authenticate to access PIV PIN",
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data {
            return String(data: data, encoding: .utf8)
        }
        return nil
    }

    func deletePIN(forCardID cardID: String) {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.keychainService,
            kSecAttrAccount: "\(cardID)-pin",
        ]
        SecItemDelete(query as CFDictionary)

        if let idx = cards.firstIndex(where: { $0.id == cardID }) {
            cards[idx].hasPIN = false
            saveToDisk()
        }
    }

    // MARK: - Persistence

    private func loadFromDisk() {
        guard FileManager.default.fileExists(atPath: storeURL.path) else { return }
        do {
            let data = try Data(contentsOf: storeURL)
            cards = try JSONDecoder().decode([RegisteredCard].self, from: data)
        } catch {
            print("CardRegistry: Failed to load: \(error)")
        }
    }

    private func saveToDisk() {
        do {
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(cards)
            try data.write(to: storeURL, options: [.atomic, .completeFileProtection])
        } catch {
            print("CardRegistry: Failed to save: \(error)")
        }
    }
}
