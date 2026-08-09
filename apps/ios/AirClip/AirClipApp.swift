import SwiftUI

@main
struct AirClipApp: App {
    @StateObject private var launcher = Launcher()

    var body: some Scene {
        WindowGroup {
            switch launcher.state {
            case let .ready(core):
                RootView().environmentObject(core)
            case let .failed(message):
                StartupFailureView(message: message)
            }
        }
    }
}

/// Owns the one-shot construction of the core.
///
/// `CoreController.init` can fail (Keychain unavailable, runtime creation), and a
/// throwing initialiser behind `@StateObject` has no clean failure path — so the outcome
/// is modelled explicitly and the UI branches on it.
@MainActor
final class Launcher: ObservableObject {
    enum State {
        case ready(CoreController)
        case failed(String)
    }

    let state: State

    init() {
        do {
            state = .ready(try CoreController())
        } catch {
            state = .failed(error.localizedDescription)
        }
    }
}

struct RootView: View {
    @EnvironmentObject private var core: CoreController

    var body: some View {
        TabView {
            HomeView()
                .tabItem { Label("Home", systemImage: "paperplane") }
            SettingsView()
                .tabItem { Label("Settings", systemImage: "gearshape") }
        }
        // Addresses go stale when the phone changes network, so re-browse on foreground
        // rather than trusting whatever was found at launch.
        .onAppear { core.refreshDiscovery() }
    }
}

struct StartupFailureView: View {
    let message: String

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle")
                .font(.largeTitle)
                .foregroundStyle(.orange)
            Text("AirClip couldn't start")
                .font(.headline)
            Text(message)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding()
    }
}
