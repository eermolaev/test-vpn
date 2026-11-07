import Foundation

/// Identifiers shared by the app and the packet tunnel extension. Values come
/// from Info.plist, which takes them from Config/Base.xcconfig.
enum AppConfig {
    private static func value(_ key: String) -> String {
        Bundle.main.object(forInfoDictionaryKey: key) as? String ?? ""
    }

    static var appGroupID: String { value("AppGroupID") }
    static var tunnelBundleID: String { value("TunnelBundleID") }
    /// "TEAMID." — needed for the shared Keychain access group.
    static var appIdentifierPrefix: String { value("AppIdentifierPrefix") }
    static var keychainGroup: String { appIdentifierPrefix + appGroupID }

    static var containerURL: URL {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupID)
            ?? FileManager.default.temporaryDirectory
    }

    static var sharedDefaults: UserDefaults {
        UserDefaults(suiteName: appGroupID) ?? .standard
    }
}
