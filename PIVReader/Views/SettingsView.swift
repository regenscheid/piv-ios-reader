import SwiftUI

struct SettingsView: View {
    @AppStorage("enableSM") private var enableSM: Bool = false

    var body: some View {
        Form {
            Section {
                Toggle("Enable Secure Messaging", isOn: $enableSM)
            } footer: {
                Text("When enabled, the app will attempt to establish an encrypted channel (SM) with the card after SELECT. SM protects commands and responses from eavesdropping over NFC. If SM establishment fails (e.g., the card's SM key is not provisioned), the app falls back to unprotected communication.")
            }
        }
        .navigationTitle("Settings")
    }
}
