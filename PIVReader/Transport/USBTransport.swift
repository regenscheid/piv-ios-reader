import Foundation
import CryptoTokenKit

/// CryptoTokenKit-based transport for USB smart card readers on iOS 16+.
///
/// Uses TKSmartCardSlotManager to discover USB readers and TKSmartCard
/// to transmit APDUs. This works because iOS gained USB smart card support
/// alongside FIDO security key support in iOS 16.
class USBTransport: CardTransport {
    private var card: TKSmartCard?
    private var slotName: String?

    var isConnected: Bool { card != nil }

    /// Discover available USB smart card slots.
    static func availableSlots() -> [String] {
        TKSmartCardSlotManager.default?.slotNames ?? []
    }

    /// Connect to the first available USB smart card reader (or a specific one).
    func connect(readerName: String? = nil) async throws {
        guard let mgr = TKSmartCardSlotManager.default else {
            throw PIVError.notConnected
        }

        let slots = mgr.slotNames
        print("USB smart card slots: \(slots)")

        guard !slots.isEmpty else {
            throw PIVError.nfcSessionFailed("No USB smart card readers found")
        }

        // Find a slot with a card present, or match by name
        var targetName: String?

        // First pass: find a slot that already has a card
        for name in slots {
            if let slot = await mgr.getSlot(withName: name),
               slot.state == .validCard {
                print("Found card in slot: \(name)")
                targetName = name
                break
            }
        }

        // Second pass: match by name if specified, or pick first
        if targetName == nil {
            if let readerName {
                targetName = slots.first(where: { $0.localizedCaseInsensitiveContains(readerName) })
            }
            // Default to first slot
            if targetName == nil { targetName = slots[0] }
        }

        guard let targetName else {
            throw PIVError.nfcSessionFailed("No suitable reader found. Available: \(slots)")
        }

        guard let slot = await mgr.getSlot(withName: targetName) else {
            throw PIVError.nfcSessionFailed("Failed to get slot '\(targetName)'")
        }

        // If no card present, wait for one (up to 30 seconds)
        if slot.makeSmartCard() == nil {
            print("Waiting for card on '\(targetName)'...")
            let gotCard = await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
                var observation: NSKeyValueObservation?
                observation = slot.observe(\.state, options: [.new]) { slot, _ in
                    if slot.state == .validCard {
                        observation?.invalidate()
                        cont.resume(returning: true)
                    }
                }

                // Timeout after 30 seconds
                DispatchQueue.global().asyncAfter(deadline: .now() + 30) {
                    observation?.invalidate()
                    cont.resume(returning: false)
                }
            }

            if !gotCard {
                throw PIVError.nfcSessionFailed("Timed out waiting for card on '\(targetName)'")
            }
        }

        guard let smartCard = slot.makeSmartCard() else {
            throw PIVError.nfcSessionFailed("No card in reader '\(targetName)'")
        }

        try await smartCard.beginSession()
        self.card = smartCard
        self.slotName = targetName
        print("Connected to USB reader: \(targetName)")
    }

    func disconnect() {
        card?.endSession()
        card = nil
        slotName = nil
    }

    /// Transmit a command APDU via USB and return the response.
    /// Handles 61XX GET RESPONSE chaining.
    func transmit(_ apdu: CommandAPDU) async throws -> ResponseAPDU {
        guard let card else { throw PIVError.notConnected }

        let rawAPDU = apdu.toBytes()
        var responseData = try await card.transmit(rawAPDU)

        // Response is raw bytes: data || SW1 || SW2
        guard responseData.count >= 2 else {
            throw PIVError.nfcSessionFailed("USB response too short")
        }

        var sw1 = responseData[responseData.count - 2]
        var sw2 = responseData[responseData.count - 1]
        var allData = responseData.count > 2 ? Data(responseData[0..<(responseData.count - 2)]) : Data()

        // Handle 61XX: more data available
        while sw1 == 0x61 {
            let remaining = Int(sw2) == 0 ? 256 : Int(sw2)
            let getResponse = CommandAPDU(ins: 0xC0, p1: 0x00, p2: 0x00, le: remaining)
            responseData = try await card.transmit(getResponse.toBytes())

            guard responseData.count >= 2 else { break }
            sw1 = responseData[responseData.count - 2]
            sw2 = responseData[responseData.count - 1]
            if responseData.count > 2 {
                allData.append(responseData[0..<(responseData.count - 2)])
            }
        }

        return ResponseAPDU(data: allData, sw1: sw1, sw2: sw2)
    }
}
