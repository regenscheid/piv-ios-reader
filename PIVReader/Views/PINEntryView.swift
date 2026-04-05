import SwiftUI

/// A simple PIN / pairing code entry sheet.
struct PINEntryView: View {
    let title: String
    let prompt: String
    let onSubmit: (String) -> Void

    @State private var pin: String = ""
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section(prompt) {
                    SecureField("Enter PIN", text: $pin)
                        .keyboardType(.numberPad)
                        .textContentType(.oneTimeCode)
                }
            }
            .navigationTitle(title)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Submit") {
                        onSubmit(pin)
                        dismiss()
                    }
                    .disabled(pin.isEmpty)
                }
            }
        }
    }
}
