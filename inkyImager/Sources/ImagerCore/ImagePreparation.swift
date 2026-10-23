import Foundation
import Darwin

public struct OSManifest: Codable, Sendable {
    public let schemaVersion: Int
    public let version: String
    public let imageFile: String
    public let compressedSHA256: String
    public let imageSHA256: String
    public let imageBytes: Int64
    public let configurationFile: String
}

public struct WiFiConfiguration: Codable, Sendable {
    public let ssid: String
    public let password: String
    public let country: String
    public init(ssid: String, password: String, country: String) { self.ssid = ssid; self.password = password; self.country = country }
}

private struct BootConfiguration: Encodable {
    let schema_version = 1
    let wifi: WiFiConfiguration
}

public enum PreparationError: LocalizedError {
    case message(String)
    public var errorDescription: String? { if case .message(let value) = self { return value }; return nil }
}

public enum ImagePreparation {
    public static func execute(_ executable: String, _ arguments: [String]) throws -> Data {
        try SystemCommand.run(executable, arguments, timeout: executable == "/usr/bin/osascript" ? 7200 : 30)
    }

    public static func detachPrivateImage(_ image: URL) throws {
        let output = try execute("/usr/bin/hdiutil", ["info", "-plist"])
        guard let plist = try PropertyListSerialization.propertyList(from: output, format: nil) as? [String: Any],
              let images = plist["images"] as? [[String: Any]] else {
            throw PreparationError.message("macOS n’a pas confirmé la fermeture de la préparation.")
        }
        for item in images where item["image-path"] as? String == image.path {
            guard let entities = item["system-entities"] as? [[String: Any]],
                  let device = entities.compactMap({ $0["dev-entry"] as? String }).first(where: {
                      $0.range(of: #"^/dev/disk[0-9]+$"#, options: .regularExpression) != nil
                  }) else { throw PreparationError.message("La préparation est encore utilisée par macOS.") }
            _ = try execute("/usr/bin/hdiutil", ["detach", device])
        }
    }

    public static func personalize(image: URL, wifi: WiFiConfiguration, filename: String) throws {
        guard filename == "inky-imager.json" else { throw PreparationError.message("Format d’image non reconnu.") }
        let output = try execute("/usr/bin/hdiutil", ["attach", "-nomount", "-readwrite", "-noautofsck", "-plist",
            "-imagekey", "diskimage-class=CRawDiskImage", image.path])
        guard let plist = try PropertyListSerialization.propertyList(from: output, format: nil) as? [String: Any],
              let entities = plist["system-entities"] as? [[String: Any]],
              let whole = entities.compactMap({ $0["dev-entry"] as? String }).first(where: {
                  $0.range(of: #"^/dev/disk[0-9]+$"#, options: .regularExpression) != nil
              }),
              let fat = entities.first(where: { ($0["content-hint"] as? String) == "DOS_FAT_32" ||
                  ($0["content-hint"] as? String) == "Windows_FAT_32" }),
              let partition = fat["dev-entry"] as? String,
              partition == whole + "s1" else {
            // If attach succeeded, drain only the device entries belonging to this image.
            if let plist = try? PropertyListSerialization.propertyList(from: output, format: nil) as? [String: Any],
               let entities = plist["system-entities"] as? [[String: Any]],
               let device = entities.compactMap({ $0["dev-entry"] as? String }).first {
                _ = try? execute("/usr/bin/hdiutil", ["detach", device])
            }
            throw PreparationError.message("La partition de démarrage InkyOS n’a pas été trouvée.")
        }
        var detached = false
        defer { if !detached { _ = try? execute("/usr/bin/hdiutil", ["detach", whole]) } }
        let privateMount = image.deletingLastPathComponent().appendingPathComponent("boot")
        try FileManager.default.createDirectory(at: privateMount, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        _ = try execute("/usr/sbin/diskutil", ["mount", "-mountPoint", privateMount.path, partition])
        let infoData = try execute("/usr/sbin/diskutil", ["info", "-plist", partition])
        guard let info = try PropertyListSerialization.propertyList(from: infoData, format: nil) as? [String: Any],
              info["DeviceNode"] as? String == partition,
              let mountpoint = info["MountPoint"] as? String, mountpoint == privateMount.path else {
            throw PreparationError.message("Impossible de préparer le Wi-Fi dans l’image.")
        }
        let destination = URL(fileURLWithPath: mountpoint).appendingPathComponent(filename)
        guard !FileManager.default.fileExists(atPath: destination.path) else {
            throw PreparationError.message("L’image contient déjà une configuration Wi-Fi.")
        }
        let data = try JSONEncoder().encode(BootConfiguration(wifi: wifi))
        guard data.count <= 4096 else { throw PreparationError.message("La configuration Wi-Fi est trop longue.") }
        try data.write(to: destination, options: .withoutOverwriting)
        let fd = open(destination.path, O_RDONLY | O_NOFOLLOW)
        guard fd >= 0 else { throw PreparationError.message("Impossible de relire la configuration Wi-Fi.") }
        let synchronized = fsync(fd) == 0
        close(fd) // No descriptor may keep the FAT volume busy during unmount.
        guard synchronized, try Data(contentsOf: destination) == data else {
            throw PreparationError.message("La vérification des paramètres Wi-Fi a échoué.")
        }
        _ = try execute("/usr/sbin/diskutil", ["unmount", partition])
        _ = try execute("/usr/bin/hdiutil", ["detach", whole])
        detached = true
        try FileManager.default.removeItem(at: privateMount)
    }
}

private extension String {
    var nonempty: String? { isEmpty ? nil : self }
}
