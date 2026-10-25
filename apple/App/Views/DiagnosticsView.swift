import SwiftUI

/// Exit verification and tunnel statistics (GEO-005…GEO-009).
struct DiagnosticsView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Form {
            Section {
                Button(model.egressRunning ? "Checking…" : "Check exit and leaks") {
                    Task { await model.runEgressCheck() }
                }
                .disabled(model.egressRunning || model.coreStatus?.state != "connected")
            } footer: {
                Text("This check is diagnostic: websites may use another GeoIP database and see a different country.")
            }
            if let r = model.egress {
                Section("Exit") {
                    row("Expected country", r.expectedCountry?.isEmpty == false ? r.expectedCountry! : "—")
                    row("Exit country", [r.country.iso, r.country.name].compactMap { $0 }.joined(separator: " ").ifEmpty("unknown"))
                    row("Exit IPv4", (r.ipv4.ip ?? "unknown") + (r.ipv4.confirmed ? "" : " (not confirmed)"))
                    row("IPv6", r.ipv6.blocked ? "blocked" : "LEAK: \(r.ipv6.ip ?? "")")
                    row("WebRTC (STUN)", r.stun.ip ?? (r.stun.error.map { "failed: \($0)" } ?? "—"))
                    if r.bypass.checked {
                        row("Direct bypass", r.bypass.blocked ? "blocked" : "LEAK: \(r.bypass.ip ?? "")")
                    }
                    if let src = r.country.source {
                        row("GeoIP data", src + (r.country.buildDate.map { ", built \($0.prefix(10))" } ?? ""))
                    }
                }
                if let findings = r.findings, !findings.isEmpty {
                    Section("Findings") {
                        ForEach(findings) { f in
                            Label(f.message, systemImage: icon(f.severity)).foregroundStyle(color(f.severity))
                        }
                    }
                }
                Section("IP services") {
                    ForEach(r.ipv4.sources) { s in row(s.service, s.ip ?? (s.error ?? "")) }
                }
            }
            if let s = model.coreStatus {
                Section("Tunnel") {
                    row("State", s.state)
                    row("Transport", s.transportKind ?? "—")
                    row("DNS", (s.dnsServers ?? []).joined(separator: ", "))
                    row("TCP flows", "tunnel \(s.stats.tcpTunnel) · direct \(s.stats.tcpDirect) · rejected \(s.stats.tcpReject)")
                    row("UDP flows", "tunnel \(s.stats.udpTunnel) · direct \(s.stats.udpDirect) · rejected \(s.stats.udpReject)")
                    row("DNS queries", "tunnel \(s.stats.dnsTunnel) · direct \(s.stats.dnsDirect) · failed \(s.stats.dnsFailed)")
                    Button("Reconnect") { Task { await model.reconnect() } }
                }
            }
            Section {
                Button("Update GeoIP database") { Task { await model.updateGeoIP() } }
                if let updated = model.geoIPUpdated { row("Updated", updated) }
            } footer: {
                Text("IP Geolocation by DB-IP (db-ip.com), CC BY 4.0.")
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Diagnostics")
    }

    private func row(_ title: String, _ value: String) -> some View {
        LabeledContent(title) { Text(value).textSelection(.enabled) }
    }

    private func icon(_ severity: String) -> String {
        switch severity {
        case "critical": "xmark.octagon.fill"
        case "warning": "exclamationmark.triangle.fill"
        default: "info.circle"
        }
    }

    private func color(_ severity: String) -> Color {
        switch severity {
        case "critical": .red
        case "warning": .orange
        default: .secondary
        }
    }
}

private extension String {
    func ifEmpty(_ fallback: String) -> String { isEmpty ? fallback : self }
}
