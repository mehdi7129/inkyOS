import Foundation
import IOKit
import Darwin

public enum SystemCommand {
    /// Fixed executables and argument arrays; no shell and no inherited environment.
    public static func run(_ executable: String, _ arguments: [String], timeout: TimeInterval = 30) throws -> Data {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"]
        func scratchFD() throws -> Int32 {
            var template = Array("/private/tmp/inkyimager-command.XXXXXX".utf8CString)
            let fd = mkstemp(&template)
            guard fd >= 0 else { throw ImagerError("Impossible de préparer une commande système.") }
            _ = template.withUnsafeBufferPointer { Darwin.unlink($0.baseAddress!) }
            _ = fchmod(fd, 0o600)
            return fd
        }
        let stdout = try scratchFD()
        defer { close(stdout) }
        let stderr = try scratchFD()
        defer { close(stderr) }
        process.standardOutput = FileHandle(fileDescriptor: stdout, closeOnDealloc: false)
        process.standardError = FileHandle(fileDescriptor: stderr, closeOnDealloc: false)
        try process.run()
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.02) }
        if process.isRunning {
            process.terminate()
            Thread.sleep(forTimeInterval: 0.1)
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            process.waitUntilExit()
            throw ImagerError("macOS n’a pas terminé l’opération. La carte doit rester branchée.")
        }
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw ImagerError("macOS n’a pas pu terminer \(URL(fileURLWithPath: executable).lastPathComponent).")
        }
        guard lseek(stdout, 0, SEEK_SET) == 0 else { throw ImagerError("Réponse système illisible.") }
        var result = Data(), buffer = [UInt8](repeating: 0, count: 65536)
        while true {
            let count = Darwin.read(stdout, &buffer, buffer.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw ImagerError("Réponse système illisible.") }
            if count == 0 { break }
            guard result.count + count <= 4 * 1024 * 1024 else { throw ImagerError("Réponse système trop volumineuse.") }
            result.append(contentsOf: buffer.prefix(count))
        }
        return result
    }
}

public enum DiskService {
    public static func listCards() throws -> [SDCard] {
        let raw = try SystemCommand.run("/usr/sbin/diskutil", ["list", "-plist", "physical"])
        let list = try PropertyListSerialization.propertyList(from: raw, format: nil) as? [String: Any]
        let rows = list?["AllDisksAndPartitions"] as? [[String: Any]] ?? []
        return rows.compactMap { row in
            guard let name = row["DeviceIdentifier"] as? String else { return nil }
            return try? identify(name)
        }.sorted { $0.id.localizedStandardCompare($1.id) == .orderedAscending }
    }

    public static func identify(_ name: String) throws -> SDCard {
        guard name.range(of: #"^disk[0-9]+$"#, options: .regularExpression) != nil else {
            throw ImagerError("Choisissez une carte entière, pas une partition.")
        }
        let raw = try SystemCommand.run("/usr/sbin/diskutil", ["info", "-plist", name])
        guard let info = try PropertyListSerialization.propertyList(from: raw, format: nil) as? [String: Any] else {
            throw ImagerError("La carte n’est plus disponible.")
        }
        guard let matching = IOBSDNameMatching(kIOMainPortDefault, 0, name) else {
            throw ImagerError("La carte n’est plus disponible.")
        }
        let entry = IOServiceGetMatchingService(kIOMainPortDefault, matching)
        guard entry != 0 else { throw ImagerError("La carte a été retirée.") }
        defer { IOObjectRelease(entry) }
        var identifier: UInt64 = 0
        var properties: Unmanaged<CFMutableDictionary>?
        guard IORegistryEntryGetRegistryEntryID(entry, &identifier) == KERN_SUCCESS,
              IORegistryEntryCreateCFProperties(entry, &properties, kCFAllocatorDefault, 0) == KERN_SUCCESS,
              let media = properties?.takeRetainedValue() as? [String: Any] else {
            throw ImagerError("L’identité de la carte est indisponible.")
        }
        let rootData = try SystemCommand.run("/usr/sbin/diskutil", ["info", "-plist", "/"])
        guard let root = try PropertyListSerialization.propertyList(from: rootData, format: nil) as? [String: Any] else {
            throw ImagerError("Impossible d’identifier le disque système du Mac.")
        }
        return try validated(info: info, media: media, registryID: identifier, name: name,
                             protectedDisks: protectedDisks(rootInfo: root))
    }

    // Public for fixture verification without opening or modifying any device.
    public static func protectedDisks(rootInfo: [String: Any]) throws -> Set<String> {
        let stores = rootInfo["APFSPhysicalStores"] as? [[String: Any]] ?? []
        var result = Set<String>()
        for store in stores {
            guard let value = store["APFSPhysicalStore"] as? String,
                  let match = value.range(of: #"^disk[0-9]+"#, options: .regularExpression) else {
                throw ImagerError("Le disque système du Mac n’a pas pu être protégé.")
            }
            result.insert(String(value[match]))
        }
        guard !result.isEmpty else { throw ImagerError("Le disque système du Mac n’a pas pu être protégé.") }
        return result
    }

    public static func isPresent(registryID: UInt64) -> Bool {
        guard let matching = IORegistryEntryIDMatching(registryID) else { return true }
        let entry = IOServiceGetMatchingService(kIOMainPortDefault, matching)
        guard entry != 0 else { return false }
        IOObjectRelease(entry)
        return true
    }

    public static func validated(info: [String: Any], media: [String: Any], registryID: UInt64,
                                 name: String, protectedDisks: Set<String> = []) throws -> SDCard {
        let bus = info["BusProtocol"] as? String
        guard name.range(of: #"^disk[0-9]+$"#, options: .regularExpression) != nil,
              !protectedDisks.contains(name), info["DeviceIdentifier"] as? String == name,
              info["DeviceNode"] as? String == "/dev/" + name,
              info["WholeDisk"] as? Bool == true,
              info["VirtualOrPhysical"] as? String == "Physical",
              bus == "Secure Digital" || bus == "USB",
              info["Removable"] as? Bool == true,
              info["Ejectable"] as? Bool == true,
              info["Writable"] as? Bool == true,
              info["OSInternalMedia"] as? Bool != true,
              media["Whole"] as? Bool == true,
              media["Removable"] as? Bool == true,
              media["Ejectable"] as? Bool == true,
              let size = media["Size"] as? NSNumber,
              CFGetTypeID(size) != CFBooleanGetTypeID(),
              let diskSize = info["IOKitSize"] as? NSNumber,
              CFGetTypeID(diskSize) != CFBooleanGetTypeID(),
              case let capacity = size.int64Value,
              capacity > 0, (info["IOKitSize"] as? NSNumber)?.int64Value == capacity,
              registryID > 0 else {
            throw ImagerError("Seules les cartes SD et les supports USB amovibles sont proposés.")
        }
        return SDCard(id: name, name: info["MediaName"] as? String ?? "Carte SD", capacity: capacity, registryID: registryID)
    }

    public static func requireSame(_ target: SDCard) throws {
        guard try identify(target.id) == target else {
            throw ImagerError("La carte sélectionnée a changé. Sélectionnez-la à nouveau.")
        }
    }
}
