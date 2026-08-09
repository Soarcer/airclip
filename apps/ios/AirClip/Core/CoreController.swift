import Foundation
import SwiftUI

/// Everything the UI knows about the core. One instance, injected as an environment
/// object; screens stay dumb (CLAUDE.md working style).
@MainActor
final class CoreController: ObservableObject {
    enum PairingPhase: Equatable {
        case idle
        case scanning
        case connecting
        /// Both sides computed these four emoji; the user must compare them.
        case confirming(emoji: [String])
        case paired(name: String)
        case failed(reason: String)
    }

    @Published private(set) var isPaired = false
    @Published private(set) var peerName: String?
    @Published private(set) var pairingPhase: PairingPhase = .idle
    @Published private(set) var lastError: String?
    @Published private(set) var isBeaming = false
    @Published private(set) var lastBeamSummary: String?
    @Published private(set) var stagedClips: [FfiStageItem] = []
    @Published private(set) var localNetworkDenied = false

    private let handle: CoreHandle
    private let keychain: KeychainStore
    private var discovery: LocalNetworkDiscovery?

    /// Set once and reused; the PC shows this in its pairing window and toasts.
    private var deviceDisplayName: String {
        UIDevice.current.name
    }

    init() throws {
        let keychain = KeychainStore()
        self.keychain = keychain

        // The listener is created before the handle so no event can be missed between
        // construction and assignment.
        let relay = EventRelay()
        handle = try CoreHandle(keystore: keychain, listener: relay)
        relay.controller = self

        refreshPeers()
        startDiscovery()
    }

    var deviceId: String { handle.deviceId() }

    // MARK: - Discovery

    func startDiscovery() {
        if discovery == nil {
            discovery = LocalNetworkDiscovery { [weak self] host, port in
                self?.handle.addPeerHint(host: host, port: port)
            }
        }
        discovery?.start()
    }

    func stopDiscovery() {
        discovery?.stop()
    }

    /// Called when a screen appears. Hints are cleared first so a stale address from a
    /// previous network cannot keep us dialling somewhere unreachable.
    func refreshDiscovery() {
        handle.clearPeerHints()
        discovery?.stop()
        discovery?.start()
        localNetworkDenied = discovery?.permissionDenied ?? false
    }

    // MARK: - Pairing

    func beginPairing(qrURL: String) {
        pairingPhase = .connecting
        // Off the main actor: this blocks on the network until the PC answers.
        Task.detached { [handle, deviceDisplayName] in
            do {
                try handle.startPairing(qrUrl: qrURL, displayName: deviceDisplayName)
            } catch {
                await MainActor.run { [weak self] in
                    self?.pairingPhase = .failed(reason: Self.describe(error))
                }
            }
        }
    }

    /// The user says the emoji match. Only now is anything persisted (PROTOCOL §7.2).
    func confirmPairing() {
        Task.detached { [handle] in
            do {
                try handle.confirmSas()
            } catch {
                await MainActor.run { [weak self] in
                    self?.pairingPhase = .failed(reason: Self.describe(error))
                }
            }
        }
    }

    /// The user says they differ — abort without sending the confirming MAC.
    func cancelPairing() {
        handle.cancelPairing()
        pairingPhase = .idle
    }

    func forgetPeer() {
        for peer in handle.peers() {
            handle.forgetPeer(deviceId: peer.deviceId)
        }
        refreshPeers()
        pairingPhase = .idle
    }

    // MARK: - Beaming

    /// Beam text from the in-app button (SPEC R4). The Action Button path uses the same
    /// core call from the intent extension, not this method.
    func beam(text: String) {
        guard !text.isEmpty else { return }
        isBeaming = true
        lastError = nil

        Task.detached { [handle] in
            let result = handle.beamTextAwait(text: text, timeoutMs: 2000)
            await MainActor.run { [weak self] in
                self?.isBeaming = false
                self?.apply(result)
            }
        }
    }

    private func apply(_ result: BeamResult) {
        switch result {
        case .sent:
            lastBeamSummary = "Sent to \(peerName ?? "your PC")"
            lastError = nil
        case .notPaired:
            lastError = "Pair with your PC first."
        case .unreachable:
            lastError = "Your PC isn't reachable on this Wi-Fi."
        case .timedOut:
            lastError = "Your PC didn't respond. Is AirClip running on it?"
        case let .tooLarge(maxBytes):
            lastError = "That clip is too large (max \(maxBytes / 1024) KB)."
        case let .failed(reason):
            lastError = reason
        }
    }

    // MARK: - Staged clips (PC → iPhone)

    func refreshStagedClips() {
        Task.detached { [handle] in
            let items = (try? handle.fetchStageListAwait(timeoutMs: 2000)) ?? []
            await MainActor.run { [weak self] in
                self?.stagedClips = items
            }
        }
    }

    func fetchStagedBody(stageId: String) async -> String? {
        let handle = self.handle
        return await Task.detached {
            try? handle.fetchStageItemAwait(stageId: stageId, timeoutMs: 2000)
        }.value
    }

    // MARK: - Events from the core

    fileprivate func handle(event: CoreEvent) {
        switch event {
        case let .pairingSas(emoji):
            pairingPhase = .confirming(emoji: emoji)
        case let .paired(_, displayName):
            refreshPeers()
            pairingPhase = .paired(name: displayName)
        case let .pairingFailed(reason):
            pairingPhase = .failed(reason: reason)
        case .peerUnreachable:
            lastError = "Your PC isn't reachable on this Wi-Fi."
        }
    }

    private func refreshPeers() {
        let peers = handle.peers()
        isPaired = !peers.isEmpty
        peerName = peers.first?.displayName
    }

    private static func describe(_ error: Error) -> String {
        (error as? FfiError)?.localizedDescription ?? error.localizedDescription
    }
}

/// Bridges the core's callback interface onto the main actor.
///
/// Separate from `CoreController` because the core may deliver events from its own
/// thread, and `CoreEventListener` cannot itself be `@MainActor`.
private final class EventRelay: CoreEventListener, @unchecked Sendable {
    weak var controller: CoreController?

    func onEvent(event: CoreEvent) {
        Task { @MainActor [weak self] in
            self?.controller?.handle(event: event)
        }
    }
}
