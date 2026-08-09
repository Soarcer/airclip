import Foundation
import Security

/// Keychain-backed implementation of the core's `KeystoreDelegate` (PROTOCOL §3).
///
/// Accessibility is `AfterFirstUnlockThisDeviceOnly`:
///   - *AfterFirstUnlock* because the App Intent runs from the Action Button while the
///     phone is locked; `WhenUnlocked` would make the hero flow fail exactly when it is
///     most useful.
///   - *ThisDeviceOnly* because identity keys must never ride an iCloud Keychain backup
///     to another device (CLAUDE.md: non-synchronizable).
///
/// Items live in the shared access group so the extensions can beam without launching
/// the container app.
final class KeychainStore: KeystoreDelegate {
    private let accessGroup: String
    private let service = "com.narrion.airclip"

    private enum Key {
        static let identitySeed = "identity-seed"
        static let pairings = "pairings"
    }

    init(accessGroup: String = "group.com.narrion.airclip") {
        self.accessGroup = accessGroup
    }

    // MARK: - KeystoreDelegate

    func loadIdentitySeed() -> Data? {
        read(Key.identitySeed)
    }

    func storeIdentitySeed(seed: Data) {
        write(Key.identitySeed, seed)
    }

    func loadPairings() -> String? {
        read(Key.pairings).flatMap { String(data: $0, encoding: .utf8) }
    }

    func storePairings(json: String) {
        write(Key.pairings, Data(json.utf8))
    }

    // MARK: - Keychain plumbing

    private func baseQuery(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
        ]
    }

    private func read(_ account: String) -> Data? {
        var query = baseQuery(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else { return nil }
        return item as? Data
    }

    private func write(_ account: String, _ value: Data) {
        // Update-then-add: SecItemAdd fails with errSecDuplicateItem on an existing
        // account, and a delete-then-add would leave a window where the identity is gone.
        let attributes: [String: Any] = [kSecValueData as String: value]
        let status = SecItemUpdate(baseQuery(account) as CFDictionary, attributes as CFDictionary)
        if status == errSecSuccess { return }

        var insert = baseQuery(account)
        insert[kSecValueData as String] = value
        insert[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(insert as CFDictionary, nil)
        if addStatus != errSecSuccess {
            // Never log the value. A failure here means the next launch regenerates the
            // identity and the user has to re-pair — worth surfacing, not worth crashing.
            NSLog("AirClip: keychain write failed for %@ (OSStatus %d)", account, addStatus)
        }
    }

    /// Used by Settings → "Forget this PC" and by the reset path.
    func delete(_ account: String) {
        SecItemDelete(baseQuery(account) as CFDictionary)
    }

    func deleteAll() {
        delete(Key.identitySeed)
        delete(Key.pairings)
    }
}
