import AppKit
import Foundation
import ImagerCore
import Darwin

@MainActor
final class ImagerModel: ObservableObject {
    @Published var devices: [SDCard] = []
    @Published var selectedDeviceID: String?
    @Published var ssid = ""
    @Published var password = ""
    @Published var country = "FR"
    @Published var phase: FlashPhase = .idle
    @Published var progress = 0.0
    @Published var errorMessage: String?
    @Published var statusMessage = ""
    @Published var isBusy = false
    @Published var imageVersion = ""
    @Published var ejectPending = false

    private var manifest: OSManifest?
    private var resources: URL?
    private var workspace: URL?
    private var pendingRequest: URL?

    init() {
        if let root = Bundle.main.resourceURL,
           let data = try? Data(contentsOf: root.appendingPathComponent("InkyOS.json")),
           let metadata = try? JSONDecoder().decode(OSManifest.self, from: data),
           metadata.schemaVersion == 1, metadata.configurationFile == "inky-imager.json",
           metadata.imageFile == "InkyOS.img.xz", metadata.imageBytes > 0 {
            manifest = metadata; resources = root; imageVersion = metadata.version
        } else {
            statusMessage = "L’image InkyOS n’est pas encore disponible dans cette installation."
        }
    }

    var canFlash: Bool {
        if ejectPending { return !isBusy }
        return !isBusy && manifest != nil && selectedDeviceID != nil && wifiValid
    }

    private var wifiValid: Bool {
        let ssidBytes = Array(ssid.utf8), key = Array(password.utf8)
        let hexadecimal = key.count == 64 && key.allSatisfy { (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }
        return (1...32).contains(ssidBytes.count) && !ssidBytes.contains(0) && country == "FR" &&
            (hexadecimal || ((8...63).contains(key.count) && key.allSatisfy { (32...126).contains($0) }))
    }

    func refreshDevices() {
        guard !isBusy, !ejectPending else { return }
        Task {
            do {
                let found = try await Task.detached { try DiskService.listCards() }.value
                devices = found
                if !found.contains(where: { $0.id == selectedDeviceID }) { selectedDeviceID = nil }
                if found.count == 1 && selectedDeviceID == nil { selectedDeviceID = found[0].id }
            } catch { saveFailure(error); errorMessage = error.localizedDescription }
        }
    }

    func startFlash() {
        guard canFlash else { return }
        if ejectPending { ejectCard(); return }
        guard cleanup() else { return }
        guard let metadata = manifest, let resource = resources,
              let card = devices.first(where: { $0.id == selectedDeviceID }) else { return }
        let wifi = WiFiConfiguration(ssid: ssid, password: password, country: country)
        isBusy = true; phase = .preparing; progress = 0; errorMessage = nil
        statusMessage = "Vérification de l’image InkyOS…"
        Task {
            do {
                let directory = try makeWorkspace()
                workspace = directory
                let image = directory.appendingPathComponent("InkyOS.img")
                try await Task.detached {
                    let compressed = resource.appendingPathComponent(metadata.imageFile)
                    guard try ImageTools.sha256(url: compressed) == metadata.compressedSHA256 else {
                        throw PreparationError.message("L’image intégrée est endommagée. Réinstallez inkyImager.")
                    }
                    try XZDecoder.decode(source: compressed, destination: image, expectedBytes: metadata.imageBytes) { done, total in
                        Task { @MainActor in self.progress = 0.18 * Double(done) / Double(max(total, 1)) }
                    }
                    guard try ImageTools.sha256(url: image) == metadata.imageSHA256 else {
                        throw PreparationError.message("La vérification de l’image InkyOS a échoué.")
                    }
                }.value
                phase = .configuring; progress = 0.20; statusMessage = "Préparation de votre Wi-Fi…"
                try await Task.detached { try ImagePreparation.personalize(image: image, wifi: wifi, filename: metadata.configurationFile) }.value
                let hash = try await Task.detached { try ImageTools.sha256(url: image) }.value
                let request = FlashRequest(imagePath: image.path, imageSHA256: hash, imageBytes: metadata.imageBytes,
                    target: card, progressPath: directory.appendingPathComponent("progress.json").path, ownerUID: getuid())
                let requestURL = directory.appendingPathComponent("request.json")
                try writePrivate(JSONEncoder().encode(request), to: requestURL)
                pendingRequest = requestURL
                try await runHelper(requestURL: requestURL, ejectOnly: false)
                finishOperation()
            } catch {
                saveFailure(error)
                phase = .failed; errorMessage = friendly(error); isBusy = false
                cleanup()
            }
        }
    }

    private func ejectCard() {
        guard let request = pendingRequest else { return }
        isBusy = true; errorMessage = nil; phase = .ejecting
        Task {
            do { try await runHelper(requestURL: request, ejectOnly: true); finishOperation() }
            catch { saveFailure(error); isBusy = false; phase = .failed; errorMessage = friendly(error) }
        }
    }

    private func finishOperation() {
        isBusy = false; password = ""
        if ejectPending {
            phase = .finished
            statusMessage = "La carte est vérifiée. Cliquez sur Éjecter pour terminer."
        } else {
            phase = .finished; progress = 1
            statusMessage = "Retirez la carte, insérez-la dans le Pi éteint, puis allumez votre cadre."
            cleanup()
        }
    }

    private func runHelper(requestURL: URL, ejectOnly: Bool) async throws {
        guard let helper = Bundle.main.executableURL?.deletingLastPathComponent().appendingPathComponent("inkyImagerHelper"),
              FileManager.default.isExecutableFile(atPath: helper.path) else {
            throw PreparationError.message("L’installation d’inkyImager est incomplète.")
        }
        let progressURL = requestURL.deletingLastPathComponent().appendingPathComponent("progress.json")
        // The helper needs the verified receipt for an eject-only retry.
        let previousProgress = ejectOnly ? (try? Data(contentsOf: progressURL)) : nil
        statusMessage = "Autorisez l’écriture de la carte dans la fenêtre macOS."
        // Keep the logged-in user's audit session and GUI responsibility. Only
        // Apple's authopen obtains privileged access to the selected raw device.
        let arguments = ["--request", requestURL.path] + (ejectOnly ? ["--eject"] : [])
        let task = Task.detached { try SystemCommand.run(helper.path, arguments, timeout: 7200) }
        let watcher = Task { @MainActor in
            while !Task.isCancelled {
                if let data = try? Data(contentsOf: progressURL), data != previousProgress,
                   let event = try? JSONDecoder().decode(FlashProgress.self, from: data) {
                    self.phase = event.phase; self.statusMessage = event.message
                    self.ejectPending = event.ejectOnlyFailure
                    switch event.phase {
                    case .writing: self.progress = 0.25 + 0.40 * event.fraction
                    case .verifying: self.progress = 0.65 + 0.32 * event.fraction
                    case .ejecting: self.progress = 0.98
                    case .finished: self.progress = 1
                    default: break
                    }
                }
                try? await Task.sleep(nanoseconds: 150_000_000)
            }
        }
        defer { watcher.cancel() }
        var commandError: Error?
        do { _ = try await task.value } catch { commandError = error }
        // Read the final receipt even when the command failed. It is more precise
        // than AppleScript's wrapper error and must survive the watcher cancellation.
        if let data = try? Data(contentsOf: progressURL),
           let event = try? JSONDecoder().decode(FlashProgress.self, from: data) {
            ejectPending = event.ejectOnlyFailure
            statusMessage = event.message
            if event.readbackVerified && (commandError == nil || event.ejectOnlyFailure) { return }
            if event.phase == .failed { throw PreparationError.message(event.message) }
        }
        if let commandError { throw commandError }
        throw PreparationError.message("La fin de l’installation n’a pas pu être confirmée.")
    }

    private func makeWorkspace() throws -> URL {
        let parent = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Caches/fr.mehdiguiard.inkyimager")
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let directory = parent.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        if let metadata = manifest {
            let available = try directory.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey]).volumeAvailableCapacityForImportantUsage ?? 0
            guard available >= metadata.imageBytes + 1_073_741_824 else {
                try? FileManager.default.removeItem(at: directory)
                throw PreparationError.message("Il faut au moins 4 Go libres pour préparer la carte.")
            }
        }
        return directory
    }

    @discardableResult private func cleanup() -> Bool {
        guard let directory = workspace else { return true }
        do {
            try ImagePreparation.detachPrivateImage(directory.appendingPathComponent("InkyOS.img"))
            try FileManager.default.removeItem(at: directory)
            workspace = nil; pendingRequest = nil
            return true
        } catch {
            errorMessage = "macOS utilise encore la préparation. Réessayez pour la fermer avant de poursuivre."
            return false
        }
    }

    private func writePrivate(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: .withoutOverwriting)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    private func saveFailure(_ error: Error) {
        // Keep a small, private diagnostic after deleting the Wi-Fi-bearing image.
        // No SSID, password, command arguments or request contents are recorded.
        let root = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Caches/fr.mehdiguiard.inkyimager/Diagnostics")
        do {
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
            var report: [String: Any] = ["schemaVersion": 1, "date": ISO8601DateFormatter().string(from: Date()),
                "phase": phase.rawValue, "error": error.localizedDescription]
            if let workspace,
               let data = try? Data(contentsOf: workspace.appendingPathComponent("progress.json")), data.count <= 65536,
               let event = try? JSONDecoder().decode(FlashProgress.self, from: data),
               let object = try? JSONSerialization.jsonObject(with: JSONEncoder().encode(event)) {
                report["helperProgress"] = object
            }
            let file = root.appendingPathComponent(UUID().uuidString + ".json")
            try writePrivate(JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys]), to: file)
        } catch { /* A failed diagnostic must not hide the original operation error. */ }
    }
    private func friendly(_ error: Error) -> String {
        let message = error.localizedDescription
        return message.contains("(-128)") ? "Installation annulée." : message
    }
}
