# Privacy Policy — PIV Reader

**Last updated:** April 11, 2026

## Overview

PIV Reader is a smart card utility app that reads and verifies PIV (Personal Identity Verification) credentials via NFC or USB smart card readers. Your privacy is important to us.

## Data Collection

**PIV Reader does not collect or transmit any personal data to external servers.**

- No analytics, tracking, or telemetry is used.
- No user accounts or sign-ins are required.
- No card data is sent to any server.

## Local Data Storage

PIV Reader stores certain data locally on your device to enable card registration and certificate authentication features:

- **Card registration database** — When you register a card, the app saves the cardholder's name, organization, card UUID, and certificates in a local file protected by iOS Data Protection (encrypted at rest).
- **VCI pairing codes** — Saved alongside card registrations in the local database. Pairing codes are not considered secret and are stored without additional encryption.
- **PIV PIN** — If you choose to save a PIN, it is stored in the iOS Keychain with biometric access control (Face ID or Touch ID). The PIN cannot be accessed without biometric authentication and never leaves the Secure Enclave's protection.
- **CA certificates** — Trusted root and intermediate CA certificates are stored locally for certificate chain validation.
- **Registered certificates** — PIV authentication certificates from registered cards are stored locally and made available to the system via CryptoTokenKit for client certificate authentication in Safari and other apps.

All locally stored data remains on your device and is not backed up to iCloud or transmitted externally.

## Network Access

The app makes the following network requests:

- **Federal PKI root certificate** is downloaded from `repo.fpki.gov` (a U.S. government server) to validate certificate chains.
- **Federal PKI intermediate CA bundle** is downloaded from `idmanagement.gov` (a U.S. government server) for certificate chain validation.

These downloads contain only publicly available government CA certificates. No user or card data is sent in these requests.

## CryptoTokenKit Extension

PIV Reader includes a system extension that makes registered PIV certificates available to Safari and other apps for client certificate authentication (mutual TLS). When a website requests a client certificate:

- The system presents the registered certificate to the requesting app.
- If the user selects the certificate, the app is opened to perform the cryptographic signing operation on the physical PIV card.
- The private key never leaves the PIV card — only the resulting signature is returned to the requesting app.

## Third-Party Services

PIV Reader does not use any third-party services, SDKs, or analytics platforms. The only external dependency is Apple's open-source [swift-certificates](https://github.com/apple/swift-certificates) library for X.509 certificate parsing.

## Data Deletion

You can delete all locally stored data at any time:

- **Card registrations** — Swipe to delete individual cards in Settings → Registered Cards, which also removes saved PINs from the Keychain.
- **CA certificates** — Manage in Settings → CA Certificates.
- **All data** — Deleting the app removes all local data, Keychain entries, and CryptoTokenKit certificate registrations.

## Contact

If you have questions about this privacy policy:

- **GitHub Issues:** [github.com/regenscheid/piv-ios-reader/issues](https://github.com/regenscheid/piv-ios-reader/issues)
- **Email:** [andy@pivforge.com](mailto:andy@pivforge.com)
