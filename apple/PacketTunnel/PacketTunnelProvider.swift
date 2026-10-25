import NetworkExtension
import Vpncore

/// Packet tunnel provider shared by iOS and macOS. All routing decisions are
/// made by the Go core: this class only configures the tunnel interface and
/// moves packets (spec 6.2).
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var tunnel: VpncoreTunnel?
    private let callbacks = CoreCallbacks()
    private let monitor = NetworkMonitor()
    private var profile: ProfileMeta?

    /// Tunnel interface addresses. IPv6 is routed into the tunnel only to be
    /// dropped by the core (GEO-003).
    private static let ipv4Address = "10.255.0.2"
    private static let ipv6Address = "fd00:255::2"
    private static let mtu = 1400

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        #if os(iOS)
        // PLAT-002: stay well below the extension memory limit.
        VpncoreSetMemoryLimit(30 << 20)
        #endif
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let idString = proto.providerConfiguration?["profileID"] as? String,
              let id = UUID(uuidString: idString),
              let meta = ProfileStore.load().first(where: { $0.id == id }),
              let profileJSON = ProfileStore.profileJSON(id) else {
            completionHandler(TunnelError.noProfile)
            return
        }
        profile = meta
        let global = SettingsStore.load()
        let dnsServers = (meta.dnsOverride ?? global.dns).servers

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.255.0.1")
        let ipv4 = NEIPv4Settings(addresses: [Self.ipv4Address], subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4
        let ipv6 = NEIPv6Settings(addresses: [Self.ipv6Address], networkPrefixLengths: [128])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6
        let dns = NEDNSSettings(servers: dnsServers)
        dns.matchDomains = [""] // all queries go to the tunnel resolver
        settings.dnsSettings = dns
        settings.mtu = NSNumber(value: Self.mtu)

        monitor.start { [weak self] snapshot in
            self?.tunnel?.networkChanged(snapshot.networkID, interfaceIndex: snapshot.interfaceIndex, interfaceName: snapshot.interfaceName)
        }
        let net = monitor.current

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            if let error {
                completionHandler(error)
                return
            }
            let config = CoreConfig.tunnelJSON(
                profileJSON: profileJSON, profile: meta, global: global,
                networkID: net.networkID, interfaceIndex: net.interfaceIndex, interfaceName: net.interfaceName,
                networkDNS: NetworkMonitor.systemDNSServers(), mtu: Self.mtu)
            self.callbacks.flow = self.packetFlow
            var err: NSError?
            let t = VpncoreStartWithCallbacks(config, self.callbacks, self.callbacks, self.callbacks, self.callbacks, &err)
            if let err {
                completionHandler(err)
                return
            }
            self.tunnel = t
            self.readPackets()
            // The kill switch is active from here; the core connects in the
            // background and reports progress through status updates.
            completionHandler(nil)
        }
    }

    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self, let tunnel = self.tunnel else { return }
            for p in packets {
                tunnel.inputPacket(p)
            }
            self.readPackets()
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        monitor.stop()
        tunnel?.stop()
        tunnel = nil
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let message = ProviderMessage.decode(messageData) else {
            completionHandler?(ProviderReply(error: "bad message").data)
            return
        }
        switch message {
        case .status:
            completionHandler?(ProviderReply(status: tunnel?.status()).data)
        case .updateSettings(let json):
            do {
                try tunnel?.updateSettings(json)
                completionHandler?(ProviderReply(status: tunnel?.status()).data)
            } catch {
                completionHandler?(ProviderReply(error: error.localizedDescription).data)
            }
        case .reconnect:
            tunnel?.reconnect()
            completionHandler?(ProviderReply(status: tunnel?.status()).data)
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func wake() {
        tunnel?.reconnect()
    }
}

enum TunnelError: LocalizedError {
    case noProfile
    var errorDescription: String? { "The VPN profile was not found. Open the app and select a profile." }
}
