import Foundation
import Network

/// Browses `_airclip._tcp` and feeds resolved addresses to the core as *hints*.
///
/// ADR-4: iOS uses `NWBrowser` natively rather than the Rust mDNS implementation, so the
/// Local Network permission dialog is triggered by a first-party API and the OS handles
/// interface changes for us.
///
/// PROTOCOL §4 is explicit that this is a hint only — a spoofed record can make us dial an
/// attacker, but cannot survive the handshake. Nothing here is treated as identity.
///
/// Browsing is started on demand and stopped as soon as an address is found: continuous
/// browsing is a battery and App Review liability (IOS-PLATFORM-NOTES §5).
@MainActor
final class LocalNetworkDiscovery {
    private var browser: NWBrowser?
    private var connections: [NWConnection] = []
    private let onHint: (String, UInt16) -> Void

    /// Set when the browser reports a permission-denied state, so the UI can offer the
    /// Settings deep link instead of spinning forever (IOS-PLATFORM-NOTES §3).
    private(set) var permissionDenied = false

    init(onHint: @escaping (String, UInt16) -> Void) {
        self.onHint = onHint
    }

    func start() {
        guard browser == nil else { return }
        permissionDenied = false

        let params = NWParameters()
        params.includePeerToPeer = false
        let descriptor = NWBrowser.Descriptor.bonjour(type: "_airclip._tcp", domain: nil)
        let browser = NWBrowser(for: descriptor, using: params)

        browser.stateUpdateHandler = { [weak self] state in
            guard case .failed = state else { return }
            Task { @MainActor in
                // A denied Local Network permission surfaces here as a failure rather
                // than as an explicit permission callback.
                self?.permissionDenied = true
                self?.stop()
            }
        }

        browser.browseResultsChangedHandler = { [weak self] results, _ in
            Task { @MainActor in
                for result in results {
                    self?.resolve(result)
                }
            }
        }

        self.browser = browser
        browser.start(queue: .main)
    }

    func stop() {
        browser?.cancel()
        browser = nil
        connections.forEach { $0.cancel() }
        connections.removeAll()
    }

    /// NWBrowser yields service *names*, not addresses. A short-lived NWConnection is the
    /// supported way to force resolution and read the endpoint back.
    private func resolve(_ result: NWBrowser.Result) {
        guard case .service = result.endpoint else { return }

        let connection = NWConnection(to: result.endpoint, using: .tcp)
        connections.append(connection)

        connection.stateUpdateHandler = { [weak self, weak connection] state in
            guard let connection else { return }
            switch state {
            case .ready:
                if let path = connection.currentPath,
                   case let .hostPort(host, port) = path.remoteEndpoint
                {
                    Task { @MainActor in
                        self?.emit(host: host, port: port)
                        connection.cancel()
                    }
                }
            case .failed, .cancelled:
                Task { @MainActor in
                    self?.connections.removeAll { $0 === connection }
                }
            default:
                break
            }
        }
        connection.start(queue: .main)
    }

    private func emit(host: NWEndpoint.Host, port: NWEndpoint.Port) {
        let literal: String
        switch host {
        case let .ipv4(address):
            literal = "\(address)"
        case let .ipv6(address):
            // Strip the zone/scope suffix ("fe80::1%en0"); the core parses bare literals.
            literal = "\(address)".components(separatedBy: "%").first ?? "\(address)"
        case let .name(name, _):
            // The core deliberately refuses hostnames — resolving one here could send
            // traffic off the LAN, which ADR-2 forbids.
            _ = name
            return
        @unknown default:
            return
        }
        onHint(literal, port.rawValue)
    }
}
