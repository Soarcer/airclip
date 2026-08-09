import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var core: CoreController
    @State private var confirmForget = false

    var body: some View {
        NavigationStack {
            List {
                Section("This iPhone") {
                    LabeledContent("Device ID") {
                        Text(core.deviceId.prefix(16))
                            .font(.footnote.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }

                if core.isPaired {
                    Section("Paired PC") {
                        LabeledContent("Name", value: core.peerName ?? "PC")
                        Button("Forget this PC", role: .destructive) {
                            confirmForget = true
                        }
                    }
                }

                Section {
                    Button("Search for my PC again") {
                        core.refreshDiscovery()
                    }
                } footer: {
                    Text("AirClip finds your PC on the local network. If you've changed Wi\u{2011}Fi, search again.")
                }

                Section {
                    // The privacy claim is the product (SPEC goal 4), so it is stated in
                    // the app rather than only in the App Store listing.
                    Label("Nothing leaves your network", systemImage: "lock.shield")
                    Text("Clips travel directly to your PC over Wi\u{2011}Fi, encrypted end to end. There is no account and no server.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } header: {
                    Text("Privacy")
                }
            }
            .navigationTitle("Settings")
            .confirmationDialog(
                "Forget this PC?",
                isPresented: $confirmForget,
                titleVisibility: .visible
            ) {
                Button("Forget", role: .destructive) { core.forgetPeer() }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("You'll need to scan the pairing code again to reconnect.")
            }
        }
    }
}
