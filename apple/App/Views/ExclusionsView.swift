import SwiftUI
import UniformTypeIdentifiers
import Vpncore

/// Domain exclusion list editor (SPLIT-001, SPLIT-005, SPLIT-006).
struct ExclusionsView: View {
    @Environment(AppModel.self) private var model
    @State private var text = ""
    @State private var validation = Validation()
    @State private var useProfileList = false
    @State private var exporting = false
    @State private var importing = false

    struct Validation: Decodable {
        struct LineError: Decodable, Identifiable {
            var line: Int
            var text: String
            var error: String
            var id: Int { line }
        }
        var rules = 0
        var normalized = ""
        var errors: [LineError] = []
    }

    var body: some View {
        Form {
            Section {
                Text("Traffic to these domains bypasses the VPN. These sites see your real IP address and country.")
                    .font(.callout).foregroundStyle(.secondary)
                if model.selected != nil {
                    Toggle("Separate list for this profile", isOn: $useProfileList)
                        .onChange(of: useProfileList) { load() }
                }
            }
            Section {
                TextEditor(text: $text)
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 200)
                    .autocorrectionDisabled()
                    #if os(iOS)
                    .textInputAutocapitalization(.never)
                    #endif
                    .onChange(of: text) { validate() }
            } header: {
                Text("One domain per line")
            } footer: {
                Text("example.com covers all subdomains; full:example.com matches only that name; lines starting with # are comments. Up to 1000 entries.")
            }
            if !validation.errors.isEmpty {
                Section("Problems") {
                    ForEach(validation.errors) { e in
                        Label("Line \(e.line): \(e.text) — \(e.error)", systemImage: "exclamationmark.triangle")
                            .font(.caption)
                    }
                }
            }
            Section {
                Button("Save (\(validation.rules) rules)") { save() }
                    .disabled(!validation.errors.isEmpty)
                Button("Export…") { exporting = true }
                Button("Import…") { importing = true }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Exclusions")
        .onAppear {
            useProfileList = model.selected?.exclusionsOverride != nil
            load()
        }
        .fileExporter(isPresented: $exporting, document: TextDocument(text: validation.normalized), contentType: .plainText, defaultFilename: "exclusions.txt") { _ in }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.plainText]) { result in
            guard case .success(let url) = result else { return }
            let access = url.startAccessingSecurityScopedResource()
            defer { if access { url.stopAccessingSecurityScopedResource() } }
            if let s = try? String(contentsOf: url, encoding: .utf8) { text = s }
        }
    }

    private func load() {
        let list = useProfileList ? (model.selected?.exclusionsOverride ?? model.settings.exclusions) : model.settings.exclusions
        text = list.joined(separator: "\n")
        validate()
    }

    private func validate() {
        let json = VpncoreValidateExclusions(text)
        validation = (try? JSONDecoder().decode(Validation.self, from: Data(json.utf8))) ?? Validation()
    }

    private func save() {
        let rules = validation.normalized.split(separator: "\n").map(String.init)
        if useProfileList, var meta = model.selected {
            meta.exclusionsOverride = rules
            model.update(meta)
        } else {
            if var meta = model.selected, meta.exclusionsOverride != nil, !useProfileList {
                meta.exclusionsOverride = nil
                model.update(meta)
            }
            var s = model.settings
            s.exclusions = rules
            Task { await model.saveSettings(s) }
        }
    }
}

struct TextDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.plainText] }
    var text: String
    init(text: String) { self.text = text }
    init(configuration: ReadConfiguration) throws {
        text = String(data: configuration.file.regularFileContents ?? Data(), encoding: .utf8) ?? ""
    }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: Data(text.utf8))
    }
}
