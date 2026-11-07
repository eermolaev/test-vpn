import Foundation

/// Profile metadata in the App Group; secrets in the Keychain.
enum ProfileStore {
    private static let key = "profiles"

    static func load() -> [ProfileMeta] {
        guard let data = AppConfig.sharedDefaults.data(forKey: key) else { return [] }
        return (try? JSONDecoder().decode([ProfileMeta].self, from: data)) ?? []
    }

    static func save(_ profiles: [ProfileMeta]) {
        if let data = try? JSONEncoder().encode(profiles) {
            AppConfig.sharedDefaults.set(data, forKey: key)
        }
    }

    static func profileJSON(_ id: UUID) -> String? { Keychain.get(id.uuidString) }

    static func setProfileJSON(_ json: String, for id: UUID) throws {
        try Keychain.set(json, for: id.uuidString)
    }

    static func delete(_ id: UUID) {
        Keychain.delete(id.uuidString)
        save(load().filter { $0.id != id })
    }
}

enum SettingsStore {
    private static let key = "settings"

    static func load() -> GlobalSettings {
        guard let data = AppConfig.sharedDefaults.data(forKey: key) else { return GlobalSettings() }
        return (try? JSONDecoder().decode(GlobalSettings.self, from: data)) ?? GlobalSettings()
    }

    static func save(_ s: GlobalSettings) {
        if let data = try? JSONEncoder().encode(s) {
            AppConfig.sharedDefaults.set(data, forKey: key)
        }
    }
}
