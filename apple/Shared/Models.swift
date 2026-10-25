import Foundation

/// DNS resolver presets (GEO-010).
enum DNSPreset: String, Codable, CaseIterable, Identifiable {
    case google, cloudflare, quad9, custom
    var id: String { rawValue }

    var title: String {
        switch self {
        case .google: "Google (8.8.8.8)"
        case .cloudflare: "Cloudflare (1.1.1.1)"
        case .quad9: "Quad9 (9.9.9.9)"
        case .custom: "Custom"
        }
    }

    var servers: [String] {
        switch self {
        case .google: ["8.8.8.8", "8.8.4.4"]
        case .cloudflare: ["1.1.1.1", "1.0.0.1"]
        case .quad9: ["9.9.9.9", "149.112.112.112"]
        case .custom: []
        }
    }
}

/// How excluded domains are resolved (SPLIT-003).
enum ExclusionDNSMode: String, Codable, CaseIterable, Identifiable {
    case network, `public`
    var id: String { rawValue }
    var title: String {
        switch self {
        case .network: "Network DNS"
        case .public: "Selected public DNS, directly"
        }
    }
}

struct DNSSettings: Codable, Equatable {
    var preset: DNSPreset = .google
    var custom: [String] = []

    var servers: [String] { preset == .custom ? custom : preset.servers }

    /// Validates custom servers: 1 to 4 IPv4 addresses (IPv6 is blocked, GEO-003).
    static func validate(_ servers: [String]) -> String? {
        if servers.isEmpty { return "Enter at least one address." }
        if servers.count > 4 { return "At most 4 addresses." }
        for s in servers where !isIPv4(s) {
            return "\(s) is not an IPv4 address."
        }
        return nil
    }

    static func isIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { p in
            guard let n = Int(p), String(n) == p else { return false }
            return (0...255).contains(n)
        }
    }
}

/// Global settings; a profile may override exclusions and DNS.
struct GlobalSettings: Codable, Equatable {
    var exclusions: [String] = []
    var dns = DNSSettings()
    var exclusionDNSMode: ExclusionDNSMode = .network
    var blockQUIC = true
    var allowLocalNetwork = false
    var connectOnDemand = false
}

/// Non-secret profile metadata. The full profile (with keys) is in the Keychain.
struct ProfileMeta: Codable, Identifiable, Equatable {
    var id: UUID
    var name: String
    var summaryJSON: String
    var expectedCountry: String = ""
    var manualTransport: String?
    var exclusionsOverride: [String]?
    var dnsOverride: DNSSettings?

    var summary: ProfileSummary? {
        try? JSONDecoder().decode(ProfileSummary.self, from: Data(summaryJSON.utf8))
    }
}

struct ProfileSummary: Decodable {
    struct Transport: Decodable, Identifiable {
        var id: String
        var kind: String
        var policy: String
        var label: String?
        var detail: String
    }
    var name: String
    var transports: [Transport]
}

/// Mirrors tunnel.Status in the Go core.
struct CoreStatus: Decodable, Equatable {
    struct Stats: Decodable, Equatable {
        var tcpTunnel = 0, tcpDirect = 0, tcpReject = 0
        var udpTunnel = 0, udpDirect = 0, udpReject = 0
        var dnsQueries = 0, dnsDirect = 0, dnsTunnel = 0, dnsFailed = 0
    }
    var state: String
    var transportKind: String?
    var attempt: Int?
    var round: Int?
    var errorClass: String?
    var errorMessage: String?
    var exclusions: Int
    var dnsServers: [String]?
    var stats: Stats
}

/// Mirrors egress.Result in the Go core.
struct EgressResult: Decodable {
    struct Source: Decodable, Identifiable {
        var service: String
        var ip: String?
        var error: String?
        var id: String { service }
    }
    struct IPv4: Decodable { var ip: String?; var confirmed: Bool; var sources: [Source] }
    struct Country: Decodable { var iso: String?; var name: String?; var source: String?; var buildDate: String?; var error: String? }
    struct IPv6: Decodable { var blocked: Bool; var ip: String? }
    struct STUN: Decodable { var ip: String?; var error: String? }
    struct Bypass: Decodable { var checked: Bool; var blocked: Bool; var ip: String? }
    struct Finding: Decodable, Identifiable {
        var code: String
        var severity: String
        var message: String
        var id: String { code }
    }
    var checkedAt: String
    var expectedCountry: String?
    var ipv4: IPv4
    var country: Country
    var countryMatch: Bool?
    var ipv6: IPv6
    var stun: STUN
    var bypass: Bypass
    var exclusions: Int
    var findings: [Finding]?
}
