import SwiftUI

@main
struct VPNApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(model)
                .task { await model.load() }
        }
        #if os(macOS)
        .defaultSize(width: 720, height: 560)
        #endif
    }
}
