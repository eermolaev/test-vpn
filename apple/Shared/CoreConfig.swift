import Foundation

/// Builds the JSON documents understood by the Go core (tunnel.Settings and
/// tunnel.Config).
enum CoreConfig {
    struct Settings: Encodable {
        var exclusions: [String]
        var dnsServers: [String]
        var directDNSServers: [String]
        var exclusionDNSMode: String
        var blockQUIC: Bool
    }

    static func settings(global: GlobalSettings, profile: ProfileMeta?, networkDNS: [String]) -> Settings {
        let dns = profile?.dnsOverride ?? global.dns
        return Settings(
            exclusions: profile?.exclusionsOverride ?? global.exclusions,
            dnsServers: dns.servers,
            directDNSServers: global.exclusionDNSMode == .network ? networkDNS : [],
            exclusionDNSMode: global.exclusionDNSMode.rawValue,
            blockQUIC: global.blockQUIC
        )
    }

    static func settingsJSON(global: GlobalSettings, profile: ProfileMeta?, networkDNS: [String]) -> String {
        encode(settings(global: global, profile: profile, networkDNS: networkDNS))
    }

    /// The tunnel config embeds the profile JSON (with secrets) verbatim.
    static func tunnelJSON(profileJSON: String, profile: ProfileMeta, global: GlobalSettings,
                           networkID: String, interfaceIndex: Int32, interfaceName: String,
                           networkDNS: [String], mtu: Int) -> String {
        let s = settings(global: global, profile: profile, networkDNS: networkDNS)
        var obj: [String: Any] = [
            "profile": (try? JSONSerialization.jsonObject(with: Data(profileJSON.utf8))) ?? [:],
            "networkID": networkID,
            "interfaceIndex": interfaceIndex,
            "interfaceName": interfaceName,
            "mtu": mtu,
            "exclusions": s.exclusions,
            "dnsServers": s.dnsServers,
            "directDNSServers": s.directDNSServers,
            "exclusionDNSMode": s.exclusionDNSMode,
            "blockQUIC": s.blockQUIC,
        ]
        if let manual = profile.manualTransport { obj["manualTransport"] = manual }
        let data = (try? JSONSerialization.data(withJSONObject: obj)) ?? Data()
        return String(data: data, encoding: .utf8) ?? "{}"
    }

    private static func encode<T: Encodable>(_ v: T) -> String {
        let data = (try? JSONEncoder().encode(v)) ?? Data()
        return String(data: data, encoding: .utf8) ?? "{}"
    }
}
