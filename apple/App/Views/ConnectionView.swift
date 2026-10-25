import NetworkExtension
import SwiftUI

struct ConnectionView: View {
    @Environment(AppModel.self) private var model
    @State private var showImport = false
    @State private var importTarget: UUID?

    var body: some View {
        @Bindable var model = model
        Form {
            Section {
                HStack {
                    Image(systemName: statusIcon).foregroundStyle(statusColor).font(.title2)
                    VStack(alignment: .leading) {
                        Text(statusTitle).font(.headline)
                        if let detail = statusDetail {
                            Text(detail).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    Spacer()
                    Button(isActive ? "Disconnect" : "Connect") {
                        Task { isActive ? model.disconnect() : await model.connect() }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.selected == nil)
                }
                if let message = model.coreStatus?.errorMessage, !message.isEmpty {
                    Label(message, systemImage: "exclamationmark.triangle").font(.caption)
                }
            }
            Section("Profiles") {
                if model.profiles.isEmpty {
                    Text("Import a vless:// link, an AmneziaWG config, an Amnezia vpn:// key, an xray JSON config or a QR code.")
                        .foregroundStyle(.secondary)
                }
                Picker("Profile", selection: $model.selectedID) {
                    ForEach(model.profiles) { p in Text(p.name).tag(Optional(p.id)) }
                }
                .disabled(isActive)
                if let profile = model.selected {
                    NavigationLink("Profile details") { ProfileDetailView(profileID: profile.id) }
                    Button("Add transports to this profile…") {
                        importTarget = profile.id
                        showImport = true
                    }
                }
                Button("Import profile…") {
                    importTarget = nil
                    showImport = true
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("VPN")
        .sheet(isPresented: $showImport) {
            NavigationStack { ImportView(target: importTarget) }
        }
    }

    private var isActive: Bool {
        [.connected, .connecting, .reasserting].contains(model.vpnStatus)
    }

    private var statusTitle: String {
        switch model.coreStatus?.state {
        case "connected": return "Connected"
        case "connecting": return "Connecting…"
        case "reconnecting": return "Reconnecting — traffic blocked"
        case "failed": return "Not connected — traffic blocked"
        default:
            switch model.vpnStatus {
            case .connected: return "Tunnel up"
            case .connecting, .reasserting: return "Starting…"
            case .disconnecting: return "Disconnecting…"
            default: return "Disconnected"
            }
        }
    }

    private var statusDetail: String? {
        guard let s = model.coreStatus else { return nil }
        var parts: [String] = []
        if let kind = s.transportKind { parts.append(kind) }
        if s.state == "connecting", let a = s.attempt, let r = s.round { parts.append("attempt \(a), round \(r)") }
        if s.exclusions > 0 { parts.append("\(s.exclusions) exclusions") }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    private var statusIcon: String {
        switch model.coreStatus?.state {
        case "connected": "lock.fill"
        case "failed", "reconnecting": "lock.trianglebadge.exclamationmark"
        default: model.vpnStatus == .disconnected || model.vpnStatus == .invalid ? "lock.open" : "lock"
        }
    }

    private var statusColor: Color {
        switch model.coreStatus?.state {
        case "connected": .green
        case "failed", "reconnecting": .orange
        default: .secondary
        }
    }
}

struct ProfileDetailView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let profileID: UUID
    @State private var meta: ProfileMeta?

    var body: some View {
        Form {
            if let binding = Binding($meta) {
                Section("Profile") {
                    TextField("Name", text: binding.name)
                    TextField("Expected country (ISO code, e.g. DE)", text: binding.expectedCountry)
                }
                Section {
                    Picker("Transport", selection: binding.manualTransport) {
                        Text("Automatic").tag(String?.none)
                        ForEach(meta?.summary?.transports ?? []) { t in
                            Text("\(t.label ?? t.kind) (\(t.detail))").tag(Optional(t.id))
                        }
                    }
                } header: {
                    Text("Transport")
                } footer: {
                    Text("Automatic tries primary transports first and never falls back to plain WireGuard or unprotected VLESS. Choosing a transport pins it.")
                }
                Section("Transports") {
                    ForEach(meta?.summary?.transports ?? []) { t in
                        VStack(alignment: .leading) {
                            Text(t.label?.isEmpty == false ? t.label! : t.kind).font(.headline)
                            Text("\(t.kind) · \(t.detail) · \(t.policy)").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                Section {
                    Button("Save") {
                        if let meta { model.update(meta) }
                        dismiss()
                    }
                    Button("Delete profile", role: .destructive) {
                        model.delete(profileID)
                        dismiss()
                    }
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle(meta?.name ?? "Profile")
        .onAppear { meta = model.profiles.first { $0.id == profileID } }
    }
}
