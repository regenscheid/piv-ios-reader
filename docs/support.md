---
layout: default
title: Support — PIV Reader
---

# Support — PIV Reader

## Getting Help

If you encounter a bug, have a feature request, or need help using PIV Reader, we're here to help.

### GitHub Issues

The best way to report bugs or request features is through GitHub Issues:

[Open an Issue](https://github.com/regenscheid/piv-ios-reader/issues)

When reporting a bug, please include:
- Your iOS version and iPhone model
- What you were trying to do
- What happened instead
- Any error messages displayed in the app

### Email

For questions, feedback, or support inquiries:

[andy@pivforge.com](mailto:andy@pivforge.com)

## Frequently Asked Questions

**What cards does PIV Reader support?**
PIV Reader supports PIV cards compliant with NIST SP 800-73. This includes U.S. federal employee and contractor PIV cards, as well as PIV-compatible credentials.

**Does it work with NFC?**
Yes, but with important limitations. Over NFC (contactless), only certain data objects are freely accessible — typically the Card Authentication certificate (9E) and CHUID. Most other data objects, including the PIV Authentication certificate (9A), Digital Signature certificate (9C), and Key Management certificate (9D), require VCI (Virtual Contact Interface) to access over NFC. VCI requires the card to support Secure Messaging and typically a pairing code. Many PIV cards do not support VCI, which means those protected data objects can only be read over a contact (USB) interface.

**Does it work with USB smart card readers?**
Yes. PIV Reader supports USB CCID smart card readers connected via USB-C (or Lightning adapter). USB provides contact-interface access to all data objects without requiring Secure Messaging or VCI. If your card doesn't support VCI, USB is the only way to read protected certificates.

**Can I use my PIV card to log into websites?**
Yes. After registering a card, PIV Reader makes the PIV Authentication certificate available to Safari for mutual TLS client certificate authentication. When a website requests a client certificate, you can authenticate using your PIV card over NFC or USB. Note that NFC signing requires VCI (SM + pairing code) since the PIV Authentication key is in a protected slot.

**Tips for USB reader authentication with Safari:** For the best experience with USB readers, plug in the reader before navigating to the website, but do not insert the card yet. When Safari prompts for a certificate and PIV Reader launches, insert the card at that point. This prevents iOS's built-in smart card support from intercepting the card before PIV Reader can handle the signing request.

**Is my PIN stored securely?**
If you choose to save your PIN, it is stored in the iOS Keychain protected by Face ID or Touch ID. The PIN cannot be accessed without biometric authentication.

**Does the app send any data to a server?**
No. All card data is processed locally on your device. The only network requests are to download publicly available Federal PKI CA certificates for chain validation. See our [Privacy Policy](privacy.md) for details.
