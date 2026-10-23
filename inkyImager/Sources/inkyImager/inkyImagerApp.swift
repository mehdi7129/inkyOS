import SwiftUI

@main
struct InkyImagerApp: App {
    @NSApplicationDelegateAdaptor(ImagerAppDelegate.self) private var delegate
    @StateObject private var model = ImagerModel()
    var body: some Scene {
        WindowGroup {
            ImagerView(model: model)
                .task { model.refreshDevices() }
                .onAppear { delegate.model = model; delegate.installWindowGuards() }
        }
        .defaultSize(width: 720, height: 690)
        .windowResizability(.contentMinSize)
        .commands { CommandGroup(replacing: .newItem) {} }
    }
}

@MainActor
final class ImagerAppDelegate: NSObject, NSApplicationDelegate {
    weak var model: ImagerModel?
    private var guards: [ObjectIdentifier: ClosingGuard] = [:]
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if model?.isBusy == true || model?.ejectPending == true {
            NSSound.beep(); return .terminateCancel
        }
        return .terminateNow
    }
    func installWindowGuards() {
        DispatchQueue.main.async {
            for window in NSApp.windows where self.guards[ObjectIdentifier(window)] == nil {
                let guardDelegate = ClosingGuard(model: self.model, original: window.delegate)
                self.guards[ObjectIdentifier(window)] = guardDelegate
                window.delegate = guardDelegate
            }
        }
    }
}

@MainActor
private final class ClosingGuard: NSObject, NSWindowDelegate {
    weak var model: ImagerModel?
    weak var original: NSWindowDelegate?
    init(model: ImagerModel?, original: NSWindowDelegate?) { self.model = model; self.original = original }
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if model?.isBusy == true || model?.ejectPending == true { NSSound.beep(); return false }
        return original?.windowShouldClose?(sender) ?? true
    }
    override func responds(to selector: Selector!) -> Bool {
        super.responds(to: selector) || (original?.responds(to: selector) ?? false)
    }
    override func forwardingTarget(for selector: Selector!) -> Any? {
        (original?.responds(to: selector) ?? false) ? original : super.forwardingTarget(for: selector)
    }
}
