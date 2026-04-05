import SwiftUI

#Preview {
    ContentView()
}

struct ContentView: View {
    var body: some View {
        NavigationStack {
            CardReaderView()
                .navigationBarTitleDisplayMode(.inline)
                .toolbar(.hidden, for: .navigationBar)
        }
    }
}
