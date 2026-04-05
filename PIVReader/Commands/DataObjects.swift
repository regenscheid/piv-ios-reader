import Foundation

// MARK: - PIVObjectSpec

/// Registry descriptor for a PIV data object (tag, access rules, requirement).
struct PIVObjectSpec {
    let key: String           // e.g. "CHUID", "X509_PIV_AUTH"
    let name: String          // Human-readable name
    let berTLVTag: Data       // Raw BER-TLV tag bytes (e.g. 5FC102)
    let isCertificate: Bool

    var berTLVTagHex: String {
        berTLVTag.map { String(format: "%02X", $0) }.joined()
    }
}

// MARK: - DataObjects Registry

/// Namespace providing static access to all standard PIV data objects.
enum DataObjects {
    static let CARD_CAPABILITY_CONTAINER = PIVObjectSpec(
        key: "CARD_CAPABILITY_CONTAINER", name: "Card Capability Container",
        berTLVTag: Data([0x5F, 0xC1, 0x07]), isCertificate: false)

    static let CHUID = PIVObjectSpec(
        key: "CHUID", name: "Card Holder Unique Identifier",
        berTLVTag: Data([0x5F, 0xC1, 0x02]), isCertificate: false)

    static let X509_PIV_AUTH = PIVObjectSpec(
        key: "X509_PIV_AUTH", name: "X.509 Certificate for PIV Authentication",
        berTLVTag: Data([0x5F, 0xC1, 0x05]), isCertificate: true)

    static let X509_CARD_AUTH = PIVObjectSpec(
        key: "X509_CARD_AUTH", name: "X.509 Certificate for Card Authentication",
        berTLVTag: Data([0x5F, 0xC1, 0x01]), isCertificate: true)

    static let X509_DIGITAL_SIG = PIVObjectSpec(
        key: "X509_DIGITAL_SIG", name: "X.509 Certificate for Digital Signature",
        berTLVTag: Data([0x5F, 0xC1, 0x0A]), isCertificate: true)

    static let X509_KEY_MGMT = PIVObjectSpec(
        key: "X509_KEY_MGMT", name: "X.509 Certificate for Key Management",
        berTLVTag: Data([0x5F, 0xC1, 0x0B]), isCertificate: true)

    static let CARDHOLDER_FINGERPRINTS = PIVObjectSpec(
        key: "CARDHOLDER_FINGERPRINTS", name: "Cardholder Fingerprints",
        berTLVTag: Data([0x5F, 0xC1, 0x03]), isCertificate: false)

    static let SECURITY_OBJECT = PIVObjectSpec(
        key: "SECURITY_OBJECT", name: "Security Object",
        berTLVTag: Data([0x5F, 0xC1, 0x06]), isCertificate: false)

    static let FACIAL_IMAGE = PIVObjectSpec(
        key: "FACIAL_IMAGE", name: "Cardholder Facial Image",
        berTLVTag: Data([0x5F, 0xC1, 0x08]), isCertificate: false)

    static let PRINTED_INFORMATION = PIVObjectSpec(
        key: "PRINTED_INFORMATION", name: "Printed Information",
        berTLVTag: Data([0x5F, 0xC1, 0x09]), isCertificate: false)

    static let DISCOVERY = PIVObjectSpec(
        key: "DISCOVERY", name: "Discovery Object",
        berTLVTag: Data([0x7E]), isCertificate: false)

    static let KEY_HISTORY = PIVObjectSpec(
        key: "KEY_HISTORY", name: "Key History Object",
        berTLVTag: Data([0x5F, 0xC1, 0x0C]), isCertificate: false)

    static let CARDHOLDER_IRIS = PIVObjectSpec(
        key: "CARDHOLDER_IRIS", name: "Cardholder Iris Images",
        berTLVTag: Data([0x5F, 0xC1, 0x21]), isCertificate: false)

    static let BIOMETRIC_INFO = PIVObjectSpec(
        key: "BIOMETRIC_INFO", name: "Biometric Information Templates Group",
        berTLVTag: Data([0x7F, 0x61]), isCertificate: false)

    static let SM_CERT_SIGNER = PIVObjectSpec(
        key: "SM_CERT_SIGNER", name: "Secure Messaging Certificate Signer",
        berTLVTag: Data([0x5F, 0xC1, 0x22]), isCertificate: true)

    static let PAIRING_CODE_REF = PIVObjectSpec(
        key: "PAIRING_CODE_REF", name: "Pairing Code Reference Data",
        berTLVTag: Data([0x5F, 0xC1, 0x23]), isCertificate: false)

    /// All registered objects.
    static let all: [PIVObjectSpec] = [
        CARD_CAPABILITY_CONTAINER, CHUID,
        X509_PIV_AUTH, X509_CARD_AUTH, X509_DIGITAL_SIG, X509_KEY_MGMT,
        CARDHOLDER_FINGERPRINTS, SECURITY_OBJECT, FACIAL_IMAGE,
        PRINTED_INFORMATION, DISCOVERY, KEY_HISTORY,
        CARDHOLDER_IRIS, BIOMETRIC_INFO, SM_CERT_SIGNER, PAIRING_CODE_REF,
    ]

    /// Look up a data object by key name (e.g. "CHUID", "X509_PIV_AUTH").
    static func byKey(_ key: String) -> PIVObjectSpec? {
        all.first { $0.key == key }
    }

    /// Look up a data object by its BER-TLV tag hex (e.g. "5FC102").
    static func byTagHex(_ hex: String) -> PIVObjectSpec? {
        let upper = hex.uppercased()
        return all.first { $0.berTLVTagHex == upper }
    }
}
