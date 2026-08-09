import SwiftUI
import UIKit

/// Status, the in-app Beam button (SPEC R4), and the PC's staged clips.
///
/// The Action Button path does not come through here — it runs in the intent extension
/// without launching the app (SPEC R3). This screen exists for the first beam, for
/// troubleshooting, and for pulling clips from the PC.
struct HomeView: View {
    @EnvironmentObject private var core: CoreController
    @State private var showPairing = false

    var body: some View {
        NavigationStack {
            List {
                statusSection
                if core.isPaired {
                    beamSection
                    stagedSection
                }
            }
            .navigationTitle("AirClip")
            .refreshable { core.refreshStagedClips() }
            .sheet(isPresented: $showPairing) {
                PairView().environmentObject(core)
            }
        }
    }

    private var statusSection: some View {
        Section {
            if core.localNetworkDenied {
                // A denied Local Network permission leaves the app dead, so recovery has
                // to be one tap away (IOS-PLATFORM-NOTES §3).
                VStack(alignment: .leading, spacing: 8) {
                    Label("Local Network access is off", systemImage: "wifi.slash")
                        .foregroundStyle(.orange)
                    Text("AirClip can only reach your PC over your Wi-Fi network.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Button("Open Settings") {
                        if let url = URL(string: UIApplication.openSettingsURLString) {
                            UIApplication.shared.open(url)
                        }
                    }
                }
            } else if core.isPaired {
                Label {
                    VStack(alignment: .leading) {
                        Text(core.peerName ?? "Your PC")
                        Text("Paired").font(.caption).foregroundStyle(.secondary)
                    }
                } icon: {
                    Image(systemName: "desktopcomputer").foregroundStyle(.green)
                }
            } else {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Not paired yet")
                        .font(.headline)
                    Text("Open AirClip on your PC, choose \u{201C}Pair new iPhone\u{201D}, and scan the code.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Button {
                        showPairing = true
                    } label: {
                        Label("Scan pairing code", systemImage: "qrcode.viewfinder")
                    }
                    .buttonStyle(.borderedProminent)
                }
            }
        }
    }

    private var beamSection: some View {
        Section("Send") {
            Button {
                // Reading the pasteboard triggers the iOS paste chip; detectedPatterns
                // lets us skip that entirely when there is nothing to send.
                beamPasteboard()
            } label: {
                HStack {
                    Label("Beam clipboard to PC", systemImage: "paperplane.fill")
                    Spacer()
                    if core.isBeaming { ProgressView() }
                }
            }
            .disabled(core.isBeaming)

            if let summary = core.lastBeamSummary {
                Label(summary, systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                    .font(.footnote)
            }
            if let error = core.lastError {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .font(.footnote)
            }
        }
    }

    private var stagedSection: some View {
        Section("From your PC") {
            if core.stagedClips.isEmpty {
                Text("Copy something on your PC, then pull to refresh.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(core.stagedClips, id: \.stageId) { item in
                    Button {
                        copyToPasteboard(item)
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.preview)
                                .lineLimit(2)
                                .foregroundStyle(.primary)
                            Text(byteLabel(item.size))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
    }

    private func beamPasteboard() {
        let pasteboard = UIPasteboard.general
        // Cheap pre-check that does not trip the paste banner.
        guard pasteboard.hasStrings || pasteboard.hasURLs else {
            return
        }
        let text = pasteboard.string ?? pasteboard.url?.absoluteString ?? ""
        core.beam(text: text)
    }

    private func copyToPasteboard(_ item: FfiStageItem) {
        Task {
            // Writing the pasteboard is unrestricted from a foreground app; the keyboard
            // extension deliberately does not do this (ADR-7).
            if let body = await core.fetchStagedBody(stageId: item.stageId) {
                UIPasteboard.general.string = body
            }
        }
    }

    private func byteLabel(_ size: UInt32) -> String {
        size < 1024 ? "\(size) bytes" : "\(size / 1024) KB"
    }
}
