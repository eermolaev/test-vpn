import Foundation
import NetworkExtension
import Observation
import Vpncore

/// App state shared by all views.
@MainActor
@Observable
final class AppModel {
    var profiles: [ProfileMeta] = []
    var selectedID: UUID?
    var settings = GlobalSettings()
    var vpnStatus: NEVPNStatus = .invalid
    var coreStatus: CoreStatus?
    var lastError: String?
    var egress: EgressResult?
    var egressRunning = false
    var geoIPUpdated: String?

    private let tunnel = TunnelManager()
    private var pollTask: Task<Void, Never>?
    private var observer: NSObjectProtocol?

    var selected: ProfileMeta? { profiles.first { $0.id == selectedID } }

    func load() async {
        profiles = ProfileStore.load()
        settings = SettingsStore.load()
        do {
            try await tunnel.load()
            if let idString = (tunnel.manager?.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerConfiguration?["profileID"] as? String {
                selectedID = UUID(uuidString: idString)
            }
        } catch {
            lastError = error.localizedDescription
        }
        if selectedID == nil { selectedID = profiles.first?.id }
        vpnStatus = tunnel.status
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.statusChanged() }
        }
        statusChanged()
    }

    private func statusChanged() {
        vpnStatus = tunnel.status
        pollTask?.cancel()
        guard vpnStatus == .connected || vpnStatus == .connecting || vpnStatus == .reasserting else {
            coreStatus = nil
            return
        }
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refreshCoreStatus()
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    func refreshCoreStatus() async {
        guard let reply = await tunnel.send(.status), let json = reply.status else { return }
        coreStatus = try? JSONDecoder().decode(CoreStatus.self, from: Data(json.utf8))
    }

    // MARK: Profiles

    /// Imports a link, config, key or decoded QR code. If `into` is set, the
    /// transports are added to that profile (SEC-NET-001).
    func importProfile(_ input: String, into target: UUID? = nil) throws {
        var err: NSError?
        let json = VpncoreParseProfile(input, &err)
        if let err { throw err }
        if let target, let existing = ProfileStore.profileJSON(target) {
            let merged = VpncoreMergeProfiles(existing, json, &err)
            if let err { throw err }
            try save(json: merged, id: target, name: nil)
        } else {
            try save(json: json, id: UUID(), name: nil)
        }
    }

    private func save(json: String, id: UUID, name: String?) throws {
        var err: NSError?
        let summary = VpncoreSummarizeProfile(json, &err)
        if let err { throw err }
        try ProfileStore.setProfileJSON(json, for: id)
        let decoded = try? JSONDecoder().decode(ProfileSummary.self, from: Data(summary.utf8))
        if let i = profiles.firstIndex(where: { $0.id == id }) {
            profiles[i].summaryJSON = summary
        } else {
            profiles.append(ProfileMeta(id: id, name: name ?? decoded?.name ?? "Server", summaryJSON: summary))
            selectedID = id
        }
        ProfileStore.save(profiles)
    }

    func update(_ meta: ProfileMeta) {
        guard let i = profiles.firstIndex(where: { $0.id == meta.id }) else { return }
        profiles[i] = meta
        ProfileStore.save(profiles)
        Task { await applySettings() }
    }

    func delete(_ id: UUID) {
        ProfileStore.delete(id)
        profiles.removeAll { $0.id == id }
        if selectedID == id { selectedID = profiles.first?.id }
    }

    // MARK: Connection

    func connect() async {
        guard let profile = selected else { return }
        lastError = nil
        do {
            try await tunnel.configure(profile: profile, settings: settings)
            try tunnel.connect()
        } catch {
            lastError = error.localizedDescription
        }
    }

    func disconnect() { tunnel.disconnect() }

    func reconnect() async { _ = await tunnel.send(.reconnect) }

    // MARK: Settings

    func saveSettings(_ s: GlobalSettings) async {
        settings = s
        SettingsStore.save(s)
        await applySettings()
    }

    /// Pushes settings to a running tunnel without reconnecting (SPLIT-001,
    /// GEO-010). Saved settings are also used on the next connection.
    private func applySettings() async {
        let json = CoreConfig.settingsJSON(global: settings, profile: selected, networkDNS: [])
        if let reply = await tunnel.send(.updateSettings(json)), let error = reply.error {
            lastError = error
        }
        if let profile = selected, tunnel.manager != nil {
            try? await tunnel.configure(profile: profile, settings: settings)
        }
    }

    // MARK: Diagnostics

    static var geoIPPath: URL { AppConfig.containerURL.appendingPathComponent("dbip-country-lite.mmdb") }

    func runEgressCheck() async {
        egressRunning = true
        defer { egressRunning = false }
        let cfg: [String: Any] = [
            "expectedCountry": selected?.expectedCountry ?? "",
            "geoipPath": FileManager.default.fileExists(atPath: Self.geoIPPath.path) ? Self.geoIPPath.path : "",
            "timeZone": TimeZone.current.identifier,
            "exclusions": coreStatus?.exclusions ?? (selected?.exclusionsOverride ?? settings.exclusions).count,
        ]
        let json = String(data: (try? JSONSerialization.data(withJSONObject: cfg)) ?? Data(), encoding: .utf8) ?? "{}"
        let result = await Task.detached { () -> String? in
            var err: NSError?
            let out = VpncoreRunEgressCheck(json, &err)
            return err == nil ? out : nil
        }.value
        if let result {
            egress = try? JSONDecoder().decode(EgressResult.self, from: Data(result.utf8))
        }
    }

    func updateGeoIP() async {
        let dir = AppConfig.containerURL.path
        let result = await Task.detached { () -> (String?, String?) in
            var err: NSError?
            let path = VpncoreUpdateGeoIP(dir, &err)
            return (err == nil ? path : nil, err?.localizedDescription)
        }.value
        if let error = result.1 {
            lastError = error
        } else {
            geoIPUpdated = Date().formatted(date: .abbreviated, time: .shortened)
        }
    }
}
