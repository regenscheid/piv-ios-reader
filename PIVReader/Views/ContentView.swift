import SwiftUI

#Preview {
    ContentView()
}

struct ContentView: View {
    @EnvironmentObject var tokenHandler: TokenRequestHandler

    var body: some View {
        NavigationStack {
            CardReaderView()
                .navigationBarTitleDisplayMode(.inline)
                .toolbar(.hidden, for: .navigationBar)
        }
        .sheet(isPresented: $tokenHandler.showPINEntry) {
            PINEntryView(
                title: "PIV PIN",
                prompt: "Enter PIN to sign with your PIV card"
            ) { pin in
                Task {
                    await tokenHandler.performSignRequest(pin: pin)
                }
            }
        }
        .overlay {
            if tokenHandler.hasPendingRequest && !tokenHandler.showPINEntry {
                SignRequestOverlay(handler: tokenHandler)
            }
        }
    }
}

// MARK: - Sign Request Overlay

struct SignRequestOverlay: View {
    @ObservedObject var handler: TokenRequestHandler

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "key.fill")
                .font(.largeTitle)
                .foregroundColor(.blue)

            Text("Sign Request")
                .font(.headline)

            if let status = handler.requestStatus {
                Text(status)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }

            if let error = handler.requestError {
                Text(error)
                    .font(.caption)
                    .foregroundColor(.red)
                    .multilineTextAlignment(.center)
            }

            ProgressView()
                .padding(.top, 4)

            Button("Cancel") {
                handler.cancelRequest()
            }
            .foregroundColor(.red)
        }
        .padding(32)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.black.opacity(0.3))
    }
}
