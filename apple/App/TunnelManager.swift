import Foundation
import NetworkExtension

/// Owns the NETunnelProviderManager (one VPN configuration for the app).
@MainActor
final class TunnelManager {
    private(set) var manager: NETunnelProviderManager?

    func load() async throws {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        manager = managers.first
    }

    var status: NEVPNStatus { manager?.connection.status ?? .invalid }

    /// Writes the configuration for profile and settings (PLAT-003, PLAT-004).
    func configure(profile: ProfileMeta, settings: GlobalSettings) async throws {
        let m = manager ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = AppConfig.tunnelBundleID
        proto.serverAddress = profile.name
        proto.providerConfiguration = ["profileID": profile.id.uuidString]
        // Strict tunnel: all traffic goes to the extension, which applies the
        // kill switch and domain exclusions itself (SEC-KILL-001, spec 6.2).
        proto.includeAllNetworks = true
        proto.excludeLocalNetworks = settings.allowLocalNetwork
        #if os(iOS)
        proto.excludeAPNs = true             // push notifications keep working
        proto.excludeCellularServices = true // calls, SMS, VoLTE
        #endif
        m.protocolConfiguration = proto
        m.localizedDescription = "VPN"
        m.isEnabled = true
        if settings.connectOnDemand {
            let rule = NEOnDemandRuleConnect()
            rule.interfaceTypeMatch = .any
            m.onDemandRules = [rule]
            m.isOnDemandEnabled = true
        } else {
            m.onDemandRules = nil
            m.isOnDemandEnabled = false
        }
        try await m.saveToPreferences()
        try await m.loadFromPreferences()
        manager = m
    }

    func connect() throws {
        try manager?.connection.startVPNTunnel()
    }

    func disconnect() {
        manager?.connection.stopVPNTunnel()
    }

    /// Sends a message to the running extension.
    func send(_ message: ProviderMessage) async -> ProviderReply? {
        guard let session = manager?.connection as? NETunnelProviderSession,
              session.status != .disconnected, session.status != .invalid else { return nil }
        return await withCheckedContinuation { cont in
            do {
                try session.sendProviderMessage(message.data) { data in
                    let reply = data.flatMap { try? JSONDecoder().decode(ProviderReply.self, from: $0) }
                    cont.resume(returning: reply)
                }
            } catch {
                cont.resume(returning: nil)
            }
        }
    }
}
