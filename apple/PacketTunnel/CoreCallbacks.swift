import Foundation
import NetworkExtension
import os
import Vpncore

/// Implements the callback interfaces of the Go core.
final class CoreCallbacks: NSObject, VpncorePacketWriterProtocol, VpncoreStatusListenerProtocol, VpncoreLoggerProtocol, VpncoreStoreProtocol {
    weak var flow: NEPacketTunnelFlow?
    private let logger = Logger(subsystem: "vpn.tunnel", category: "core")

    func writePacket(_ packet: Data?) {
        guard let packet, let first = packet.first else { return }
        let family = (first >> 4) == 6 ? AF_INET6 : AF_INET
        flow?.writePackets([packet], withProtocols: [NSNumber(value: family)])
    }

    func onStatus(_ statusJSON: String?) {
        guard let statusJSON else { return }
        // The app polls status via provider messages; keep the latest copy in
        // the App Group so it is available right after the app launches.
        AppConfig.sharedDefaults.set(statusJSON, forKey: "lastStatus")
    }

    func log(_ line: String?) {
        // Lines are already redacted by the core (SEC-LOG-001).
        logger.info("\(line ?? "", privacy: .public)")
    }

    func load(_ key: String?) -> String {
        AppConfig.sharedDefaults.string(forKey: "core." + (key ?? "")) ?? ""
    }

    func save(_ key: String?, value: String?) {
        AppConfig.sharedDefaults.set(value, forKey: "core." + (key ?? ""))
    }
}
