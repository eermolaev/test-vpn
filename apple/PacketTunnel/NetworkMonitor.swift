import Foundation
import Network
#if os(macOS)
import SystemConfiguration
#endif

/// Tracks the physical network: interface for direct (excluded) flows and a
/// coarse network identity for the per-network transport memory (SEC-NET-005).
final class NetworkMonitor {
    struct Snapshot {
        var networkID = ""
        var interfaceName = ""
        var interfaceIndex: Int32 = 0
    }

    private let monitor = NWPathMonitor(prohibitedInterfaceTypes: [.other])
    private let queue = DispatchQueue(label: "vpn.network-monitor")
    private let lock = NSLock()
    private var snapshot = Snapshot()

    var current: Snapshot {
        lock.lock()
        defer { lock.unlock() }
        return snapshot
    }

    func start(onChange: @escaping (Snapshot) -> Void) {
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            let s = Self.snapshot(path)
            self.lock.lock()
            let changed = s.networkID != self.snapshot.networkID || s.interfaceName != self.snapshot.interfaceName
            self.snapshot = s
            self.lock.unlock()
            if changed {
                onChange(s)
            }
        }
        monitor.start(queue: queue)
    }

    func stop() { monitor.cancel() }

    private static func snapshot(_ path: NWPath) -> Snapshot {
        guard path.status == .satisfied,
              let iface = path.availableInterfaces.first(where: { $0.type != .other && $0.type != .loopback }) else {
            return Snapshot()
        }
        let type: String
        switch iface.type {
        case .wifi: type = "wifi"
        case .cellular: type = "cellular"
        case .wiredEthernet: type = "ethernet"
        default: type = "other"
        }
        return Snapshot(networkID: "\(type):\(iface.name)", interfaceName: iface.name, interfaceIndex: Int32(iface.index))
    }

    /// DNS servers of the physical network for excluded domains (SPLIT-003).
    /// On iOS they are not available to the extension; the core then queries
    /// the selected public resolver directly.
    static func systemDNSServers() -> [String] {
        #if os(macOS)
        guard let store = SCDynamicStoreCreate(nil, "vpn" as CFString, nil, nil),
              let global = SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString) as? [String: Any],
              let service = global["PrimaryService"] as? String,
              let dns = SCDynamicStoreCopyValue(store, "State:/Network/Service/\(service)/DNS" as CFString) as? [String: Any],
              let servers = dns["ServerAddresses"] as? [String] else { return [] }
        return servers.filter(DNSSettings.isIPv4)
        #else
        return []
        #endif
    }
}
