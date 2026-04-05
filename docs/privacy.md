# Privacy Policy — PIV Reader

**Last updated:** April 5, 2026

## Overview

PIV Reader is a smart card utility app that reads and verifies PIV (Personal Identity Verification) credentials via NFC or USB smart card readers. Your privacy is important to us.

## Data Collection

**PIV Reader does not collect, store, or transmit any personal data.**

- All card data (certificates, CHUID, FASC-N) is processed entirely on your device.
- No card data is saved to disk or sent to any server.
- No analytics, tracking, or telemetry is used.
- No user accounts or sign-ins are required.

## Network Access

The app makes the following network requests:

- **Federal PKI root certificate** is downloaded from `repo.fpki.gov` (a U.S. government server) to validate certificate chains.
- **Federal PKI intermediate CA bundle** is downloaded from `idmanagement.gov` (a U.S. government server) for certificate chain validation.

These downloads contain only publicly available government CA certificates. No user or card data is sent in these requests.

## Third-Party Services

PIV Reader does not use any third-party services, SDKs, or analytics platforms.

## Contact

If you have questions about this privacy policy, please open an issue at [github.com/regenscheid/piv-ios-reader](https://github.com/regenscheid/piv-ios-reader).
