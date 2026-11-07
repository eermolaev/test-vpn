import SwiftUI

struct ContentView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        TabView {
            Tab("Connection", systemImage: "lock.shield") { NavigationStack { ConnectionView() } }
            Tab("Exclusions", systemImage: "arrow.triangle.branch") { NavigationStack { ExclusionsView() } }
            Tab("Settings", systemImage: "gearshape") { NavigationStack { SettingsView() } }
            Tab("Diagnostics", systemImage: "stethoscope") { NavigationStack { DiagnosticsView() } }
        }
        .alert("Error", isPresented: Binding(get: { model.lastError != nil }, set: { if !$0 { model.lastError = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.lastError ?? "")
        }
    }
}
