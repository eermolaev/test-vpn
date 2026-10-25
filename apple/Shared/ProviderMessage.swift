import Foundation

/// Messages from the app to the packet tunnel extension.
enum ProviderMessage: Codable {
    case status
    case updateSettings(String) // tunnel.Settings JSON
    case reconnect

    var data: Data { (try? JSONEncoder().encode(self)) ?? Data() }

    static func decode(_ data: Data) -> ProviderMessage? {
        try? JSONDecoder().decode(ProviderMessage.self, from: data)
    }
}

/// Reply to a provider message.
struct ProviderReply: Codable {
    var status: String?
    var error: String?

    var data: Data { (try? JSONEncoder().encode(self)) ?? Data() }
}
