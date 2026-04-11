# PIV Reader for iOS

<p align="center">
  <img src="pivlogo.svg" alt="PIV Reader" width="200">
</p>

An iOS app for reading, validating, and authenticating with PIV (Personal Identity Verification) smart cards over NFC and USB.

## Features

**Card Reading**
- Read PIV certificates (Card Auth, PIV Auth, Digital Signature, Key Management) over NFC or USB smart card readers
- CHUID and FASC-N parsing with agency code lookup
- Challenge-response card authentication to verify the card holds its private key

**Certificate Validation**
- Certificate chain validation against configurable CA trust anchors
- Pre-loaded FPKI (Federal PKI) root and intermediate certificates
- Import custom CA certificates (DER or PEM) for non-federal PKI environments
- Per-certificate enable/disable and root/intermediate classification

**Secure Messaging (SM)**
- PIV Secure Messaging per SP 800-73-5 with cipher suites CS2 (P-256/AES-128) and CS7 (P-384/AES-256)
- ECDH key establishment with AES-CBC encryption and AES-CMAC authentication
- Configurable via Settings — graceful fallback if the card doesn't support SM

**Virtual Contact Interface (VCI)**
- Full VCI support for reading protected data objects over NFC
- SM establishment + pairing code verification
- Pairing code auto-read from card during USB registration

**Card Registration**
- Register cards to a local database for identity lookup
- Extracts cardholder name, organization, and UUID from certificate Subject and SAN
- Saved pairing codes for automatic VCI establishment
- Biometric-protected (Face ID / Touch ID) PIV PIN storage in the iOS Keychain

**Safari Client Certificate Authentication**
- CryptoTokenKit token extension exposes registered PIV certificates to Safari and other apps
- Enables mutual TLS (mTLS) client certificate authentication using PIV cards
- Supports RSA (PKCS#1 v1.5 and PSS) and ECDSA signature schemes
- Works over NFC (with SM/VCI) and USB smart card readers

## Requirements

- iOS 16.0 or later
- iPhone with NFC capability (for contactless card reading)
- USB smart card reader (for contact interface, requires USB-C adapter)

## Architecture

PIV Reader is built entirely in Swift with no third-party dependencies beyond Apple's [swift-certificates](https://github.com/apple/swift-certificates) package for X.509 and ASN.1 parsing.

| Component | Purpose |
|-----------|---------|
| **PIVReader** (main app) | Card reading UI, certificate validation, card registration, sign request handling |
| **PIVTokenExtension** | CryptoTokenKit extension that exposes registered certificates to Safari for mTLS |
| **PIVLib** (SPM library) | Core PIV protocol implementation — APDU encoding, TLV parsing, Secure Messaging, ECDH, certificate operations |

### Cryptography

All cryptographic operations use built-in iOS frameworks:

- **CryptoKit** — ECDH key agreement (P-256, P-384)
- **CommonCrypto** — AES-CBC, AES-ECB, SHA-256, SHA-384, AES-CMAC (RFC 4493)
- **Security.framework** — SecTrust chain validation, SecKey signature verification, Keychain with biometric access control
- **swift-certificates / SwiftASN1** — X.509 certificate parsing, Distinguished Name extraction, SAN/OtherName parsing, PKCS#7/CMS bundle parsing

No OpenSSL or other C crypto libraries are used.

### PIV Protocol Support

- SP 800-73-5 compliant SELECT, GET DATA, VERIFY, GENERAL AUTHENTICATE
- Secure Messaging key establishment (One-Pass ECDH, SP 800-73-5 Section 4.1)
- SM command/response wrapping with counter-derived IVs
- Command chaining for large SM payloads
- Discovery Object parsing for VCI capability detection

## Privacy

PIV Reader processes all card data locally on your device. No card data is stored permanently or transmitted to any server. Network access is limited to downloading publicly available Federal PKI CA certificates for chain validation.

See the full [Privacy Policy](docs/privacy.md).

## License

See [LICENSE](LICENSE) for details.
