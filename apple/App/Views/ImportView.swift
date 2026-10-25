import SwiftUI
import UniformTypeIdentifiers
#if os(iOS)
import VisionKit
#endif

struct ImportView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let target: UUID?

    /// One fileImporter per view: SwiftUI ignores all but one.
    enum FileMode { case config, qrImage }
    @State private var text = ""
    @State private var error: String?
    @State private var fileMode: FileMode?
    @State private var lastMode: FileMode = .config
    @State private var scanQR = false

    var body: some View {
        Form {
            Section {
                TextEditor(text: $text)
                    .font(.system(.footnote, design: .monospaced))
                    .frame(minHeight: 140)
                Button("Paste") {
                    #if os(iOS)
                    text = UIPasteboard.general.string ?? ""
                    #else
                    text = NSPasteboard.general.string(forType: .string) ?? ""
                    #endif
                }
            } header: {
                Text("Link, config or key")
            } footer: {
                Text("Supported: vless:// links (one per line), AmneziaWG .conf, Amnezia vpn:// keys, xray JSON.")
            }
            Section("Other sources") {
                Button("Open file…") { lastMode = .config; fileMode = .config }
                Button("QR code from image…") { lastMode = .qrImage; fileMode = .qrImage }
                #if os(iOS)
                if DataScannerViewController.isSupported {
                    Button("Scan QR code") { scanQR = true }
                }
                #endif
            }
            if let error {
                Section { Label(error, systemImage: "xmark.octagon").foregroundStyle(.red) }
            }
        }
        .formStyle(.grouped)
        .navigationTitle(target == nil ? "Import profile" : "Add transports")
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            ToolbarItem(placement: .confirmationAction) {
                Button("Import") { importText(text) }.disabled(text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .fileImporter(isPresented: Binding(get: { fileMode != nil }, set: { if !$0 { fileMode = nil } }),
                      allowedContentTypes: lastMode == .qrImage ? [.image] : [.plainText, .json, .data]) { result in
            // The presentation binding may be reset before this runs.
            let mode = lastMode
            guard case .success(let url) = result else { return }
            if mode == .qrImage {
                let access = url.startAccessingSecurityScopedResource()
                defer { if access { url.stopAccessingSecurityScopedResource() } }
                if let code = QRDecoder.decode(url: url) { importText(code) } else { error = "No QR code found in the image." }
            } else {
                text = read(url) ?? text
            }
        }
        #if os(iOS)
        .sheet(isPresented: $scanQR) {
            QRScannerView { code in
                scanQR = false
                importText(code)
            }
            .ignoresSafeArea()
        }
        #endif
    }

    private func read(_ url: URL) -> String? {
        let access = url.startAccessingSecurityScopedResource()
        defer { if access { url.stopAccessingSecurityScopedResource() } }
        return try? String(contentsOf: url, encoding: .utf8)
    }

    private func importText(_ input: String) {
        do {
            try model.importProfile(input, into: target)
            dismiss()
        } catch {
            self.error = error.localizedDescription
        }
    }
}

#if os(iOS)
/// Camera QR scanner (VisionKit).
struct QRScannerView: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let vc = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])],
                                           qualityLevel: .balanced, isHighlightingEnabled: true)
        vc.delegate = context.coordinator
        try? vc.startScanning()
        return vc
    }

    func updateUIViewController(_ vc: DataScannerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(onCode: onCode) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let onCode: (String) -> Void
        private var done = false
        init(onCode: @escaping (String) -> Void) { self.onCode = onCode }

        func dataScanner(_ scanner: DataScannerViewController, didAdd added: [RecognizedItem], allItems: [RecognizedItem]) {
            guard !done else { return }
            for item in added {
                if case .barcode(let code) = item, let value = code.payloadStringValue {
                    done = true
                    scanner.stopScanning()
                    onCode(value)
                    return
                }
            }
        }
    }
}
#endif
