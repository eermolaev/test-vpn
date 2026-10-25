import SwiftUI

/// DNS and connection settings (GEO-010, SPLIT-003, PLAT-003/004).
struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var draft = GlobalSettings()
    @State private var customText = ""
    @State private var dnsError: String?

    var body: some View {
        Form {
            Section {
                Picker("Resolver", selection: $draft.dns.preset) {
                    ForEach(DNSPreset.allCases) { Text($0.title).tag($0) }
                }
                if draft.dns.preset == .custom {
                    TextField("IPv4 addresses, comma separated", text: $customText)
                        .autocorrectionDisabled()
                        .onChange(of: customText) { validateCustom() }
                    if let dnsError {
                        Text(dnsError).font(.caption).foregroundStyle(.red)
                    }
                }
            } header: {
                Text("DNS")
            } footer: {
                Text("Queries go through the VPN to this resolver, so it sees the exit IP. Default: Google Public DNS.")
            }
            Section {
                Picker("Excluded domains resolve via", selection: $draft.exclusionDNSMode) {
                    ForEach(ExclusionDNSMode.allCases) { Text($0.title).tag($0) }
                }
            } footer: {
                Text("Your provider sees DNS queries and connections for excluded domains. On iOS the network DNS is not available to the VPN; the selected resolver is queried directly instead.")
            }
            Section("Connection") {
                Toggle("Block QUIC inside VLESS tunnels", isOn: $draft.blockQUIC)
                Toggle("Allow local network access", isOn: $draft.allowLocalNetwork)
                Toggle("Connect on demand", isOn: $draft.connectOnDemand)
            }
            Section {
                Button("Save") {
                    if draft.dns.preset == .custom { draft.dns.custom = parseCustom() }
                    Task { await model.saveSettings(draft) }
                }
                .disabled(draft.dns.preset == .custom && dnsError != nil)
                Button("Reset to defaults") {
                    draft = GlobalSettings(exclusions: model.settings.exclusions)
                    customText = ""
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Settings")
        .onAppear {
            draft = model.settings
            customText = draft.dns.custom.joined(separator: ", ")
            validateCustom()
        }
    }

    private func parseCustom() -> [String] {
        customText.split(whereSeparator: { $0 == "," || $0 == " " || $0 == "\n" }).map(String.init)
    }

    private func validateCustom() {
        dnsError = DNSSettings.validate(parseCustom())
    }
}
