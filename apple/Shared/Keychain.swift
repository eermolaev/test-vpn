import Foundation
import Security

/// Stores profile secrets in the Keychain group shared with the extension
/// (SEC-LOG-001: secrets never go to files or UserDefaults).
enum Keychain {
    private static let service = "vpn.profiles"

    enum KeychainError: LocalizedError {
        case status(OSStatus)
        var errorDescription: String? {
            if case .status(let s) = self {
                return (SecCopyErrorMessageString(s, nil) as String?) ?? "Keychain error \(s)"
            }
            return nil
        }
    }

    private static func baseQuery(_ account: String) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
        ]
        if !AppConfig.appIdentifierPrefix.isEmpty {
            q[kSecAttrAccessGroup as String] = AppConfig.keychainGroup
        }
        return q
    }

    static func set(_ value: String, for account: String) throws {
        let data = Data(value.utf8)
        let query = baseQuery(account)
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var add = query
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
            let s = SecItemAdd(add as CFDictionary, nil)
            guard s == errSecSuccess else { throw KeychainError.status(s) }
        } else if status != errSecSuccess {
            throw KeychainError.status(status)
        }
    }

    static func get(_ account: String) -> String? {
        var query = baseQuery(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func delete(_ account: String) {
        SecItemDelete(baseQuery(account) as CFDictionary)
    }
}
