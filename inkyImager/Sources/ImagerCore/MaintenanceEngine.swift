import Foundation
import CryptoKit
import Darwin

public struct MaintenanceGeometry: Codable, Equatable, Sendable {
    public let capacity: Int64
    public let bootOffset: Int64
    public let bootBytes: Int64
    public let rootOffset: Int64
    public let rootBytes: Int64

    public var suffixOffset: Int64 { rootOffset + rootBytes }
    public var suffixBytes: Int64 { capacity - suffixOffset }

    /// MBR only, with exactly the FAT + Linux layout produced by this OS.
    /// Geometry is obtained from the current medium, never from a prior flash.
    public static func parse(mbr: Data, capacity: Int64) throws -> MaintenanceGeometry {
        guard capacity > 0, capacity % 512 == 0, mbr.count == 512,
              mbr[510] == 0x55, mbr[511] == 0xaa else { throw ImagerError("Table de partitions MBR invalide.") }
        func entry(_ index: Int) throws -> (UInt8, Int64, Int64) {
            let at = 446 + 16 * index
            guard mbr[at] == 0 || mbr[at] == 0x80 else { throw ImagerError("Entrée MBR invalide.") }
            let start = Int64(le32(mbr, at + 8)) * 512
            let bytes = Int64(le32(mbr, at + 12)) * 512
            guard start >= 512, bytes > 0, start <= capacity, bytes <= capacity - start else {
                throw ImagerError("Une partition dépasse la carte sélectionnée.")
            }
            return (mbr[at + 4], start, bytes)
        }
        let boot = try entry(0), root = try entry(1)
        guard boot.0 == 0x0b || boot.0 == 0x0c, root.0 == 0x83,
              boot.1 + boot.2 <= root.1, root.2 >= 4096,
              mbr[478..<510].allSatisfy({ $0 == 0 }) else {
            throw ImagerError("Cette carte n’a pas les deux partitions InkyOS attendues.")
        }
        return MaintenanceGeometry(capacity: capacity, bootOffset: boot.1, bootBytes: boot.2,
                                   rootOffset: root.1, rootBytes: root.2)
    }
}

public struct MaintenanceHashes: Codable, Equatable, Sendable {
    public let wholeSHA256: String
    public let mbrSHA256: String
    public let prefixSHA256: String
    public let rootSHA256: String
    public let suffixSHA256: String
}

public struct MaintenanceAcquisition: Codable, Sendable {
    public let schemaVersion: Int
    public let kind: String
    public let operationID: String
    public let status: String
    public let target: SDCard
    public let backupFile: String
    public let geometry: MaintenanceGeometry
    public let hashes: MaintenanceHashes
    public let localReadbackVerified: Bool
    public let rawOpenedReadOnly: Bool
    public let sdWritesIssued: Bool
    public let limits: [String]
}

public struct MaintenanceResult: Codable, Sendable {
    public var status: String
    public var readbackVerified: Bool
    public var ejected: Bool
}

private struct AcquireRequest: Decodable {
    let schemaVersion: Int, ownerUID: UInt32
    let target: SDCard
    let backupFile: String
}

private struct RootRequest: Decodable {
    let schemaVersion: Int, ownerUID: UInt32
    let target: SDCard
    let backupFile: String
    let candidateFile: String
    let candidateSHA256: String
    let acquisitionReceiptSHA256: String
    let candidateApprovalFile: String
    let candidateApprovalSHA256: String
}

private struct CandidateApproval: Decodable {
    let schemaVersion: Int, kind: String, status: String
    let acquisitionReceiptSHA256: String, sourceBackupSHA256: String
    let candidateSHA256: String, candidateBytes: Int64
    let baselineBackend: String, targetBackend: String
    let preservationVerified: Bool, installedDeltaVerified: Bool, filesystemVerified: Bool
}

private struct MaintenanceWriteReceipt: Codable {
    var schemaVersion = 1
    var kind = "inkyos-maintenance-root-write"
    let operationID: String
    let target: SDCard
    let geometry: MaintenanceGeometry
    let acquisitionReceiptSHA256: String
    let candidateSHA256: String
    var status = "preparing"
    var writeStarted = false
    var readbackVerified = false
    var preservedExteriorVerified = false
    var ejected = false
    var message = "Vérification de la mise à jour…"
}

private let baselineBackend = "b75bf1e7d0ab0a50d14f01527994fc17a3f62e42"
private let updatedBackend = "716104b130d34d1973001e78f15e25989d4c2e76"

private func le32(_ data: Data, _ at: Int) -> UInt32 {
    UInt32(data[at]) | UInt32(data[at + 1]) << 8 | UInt32(data[at + 2]) << 16 | UInt32(data[at + 3]) << 24
}

private func hex(_ digest: SHA256.Digest) -> String { digest.map { String(format: "%02x", $0) }.joined() }
private func validSHA(_ value: String) -> Bool { value.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil }

private final class MaintenanceControl: @unchecked Sendable {
    static let lock = NSLock()
    static var cancelled = false
    static var sources: [DispatchSourceSignal] = []
    let deadline = ProcessInfo.processInfo.systemUptime + 7200
    func check() throws {
        Self.lock.lock(); let cancelled = Self.cancelled; Self.lock.unlock()
        guard !cancelled else { throw ImagerError("Maintenance interrompue. Laissez la carte branchée.") }
        guard ProcessInfo.processInfo.systemUptime < deadline else {
            throw ImagerError("La maintenance a dépassé son délai. Laissez la carte branchée.")
        }
    }
}

private func exactRead(_ fd: Int32, at offset: Int64, bytes: Int) throws -> Data {
    guard offset >= 0, bytes >= 0 else { throw ImagerError("Plage de lecture invalide.") }
    var result = Data(count: bytes), done = 0
    try result.withUnsafeMutableBytes { buffer in
        while done < bytes {
            let count = pread(fd, buffer.baseAddress!.advanced(by: done), bytes - done, off_t(offset + Int64(done)))
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw ImagerError("La lecture de maintenance s’est interrompue.") }
            done += count
        }
    }
    return result
}

private struct Ext4Identity: Equatable {
    let uuid: Data, blocks: UInt64, blockBytes: UInt64
    static func read(_ fd: Int32, rootOffset: Int64, rootBytes: Int64) throws -> Ext4Identity {
        let block = try exactRead(fd, at: rootOffset + 1024, bytes: 1024)
        guard block[56] == 0x53, block[57] == 0xef, le32(block, 24) <= 6 else {
            throw ImagerError("Le filesystem ext4 attendu n’a pas été trouvé.")
        }
        let blockBytes = UInt64(1024) << le32(block, 24)
        let has64Bit = le32(block, 96) & 0x80 != 0
        let blocks = UInt64(le32(block, 4)) | (has64Bit ? UInt64(le32(block, 336)) << 32 : 0)
        let (filesystemBytes, overflow) = blocks.multipliedReportingOverflow(by: blockBytes)
        let uuid = Data(block[104..<120])
        guard blocks > 0, !overflow, rootBytes > 0, filesystemBytes <= UInt64(rootBytes),
              uuid.contains(where: { $0 != 0 }) else {
            throw ImagerError("L’identité ou la taille ext4 ne correspond pas à la partition.")
        }
        return Ext4Identity(uuid: uuid, blocks: blocks, blockBytes: blockBytes)
    }
}

/// Byte-range operations shared by production and regular-file fixtures.
/// The CLI never exposes regular files as physical write targets.
enum MaintenanceRanges {
    static func observe(_ fd: Int32, geometry: MaintenanceGeometry,
                        check: () throws -> Void = {},
                        progress: (Int64, Int64) throws -> Void = { _, _ in }) throws -> MaintenanceHashes {
        guard lseek(fd, 0, SEEK_SET) == 0 else { throw ImagerError("Impossible de relire la carte.") }
        var whole = SHA256(), prefix = SHA256(), root = SHA256(), suffix = SHA256()
        let mbr = try exactRead(fd, at: 0, bytes: 512)
        var copied: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 4 * 1024 * 1024)
        while copied < geometry.capacity {
            try check()
            let wanted = Int(min(Int64(buffer.count), geometry.capacity - copied))
            let count = Darwin.read(fd, &buffer, wanted)
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw ImagerError("La lecture du support est incomplète.") }
            buffer.withUnsafeBytes { bytes in
                let block = UnsafeRawBufferPointer(rebasing: bytes[..<count])
                whole.update(bufferPointer: block)
                var start = 0
                while start < count {
                    let position = copied + Int64(start)
                    let end: Int64 = position < geometry.rootOffset ? geometry.rootOffset :
                        (position < geometry.suffixOffset ? geometry.suffixOffset : geometry.capacity)
                    let length = min(count - start, Int(end - position))
                    let slice = UnsafeRawBufferPointer(rebasing: block[start..<(start + length)])
                    if position < geometry.rootOffset { prefix.update(bufferPointer: slice) }
                    else if position < geometry.suffixOffset { root.update(bufferPointer: slice) }
                    else { suffix.update(bufferPointer: slice) }
                    start += length
                }
            }
            copied += Int64(count)
            try progress(copied, geometry.capacity)
        }
        return MaintenanceHashes(wholeSHA256: hex(whole.finalize()), mbrSHA256: hex(SHA256.hash(data: mbr)),
            prefixSHA256: hex(prefix.finalize()), rootSHA256: hex(root.finalize()), suffixSHA256: hex(suffix.finalize()))
    }

    static func copy(_ input: Int32, to output: Int32, count: Int64,
                     check: () throws -> Void = {},
                     progress: (Int64, Int64) throws -> Void = { _, _ in }) throws -> String {
        var hash = SHA256(), done: Int64 = 0
        var buffer = [UInt8](repeating: 0, count: 4 * 1024 * 1024)
        while done < count {
            try check()
            let wanted = Int(min(Int64(buffer.count), count - done))
            let amount = Darwin.read(input, &buffer, wanted)
            if amount < 0 && errno == EINTR { continue }
            guard amount > 0 else { throw ImagerError("La copie de maintenance est incomplète.") }
            try buffer.withUnsafeBytes { bytes in
                let block = UnsafeRawBufferPointer(rebasing: bytes[..<amount])
                hash.update(bufferPointer: block); try writeAll(output, block)
            }
            done += Int64(amount); try progress(done, count)
        }
        return hex(hash.finalize())
    }

    static func replaceRoot(device: Int32, backup: Int32, candidate: Int32,
                            geometry: MaintenanceGeometry, expected: MaintenanceHashes, candidateSHA256: String,
                            check: () throws -> Void = {}, validateMedia: () throws -> Void = {},
                            willWrite: () throws -> Void, flush: () throws -> Void,
                            progress: (String, Int64, Int64) throws -> Void = { _, _, _ in }) throws -> MaintenanceHashes {
        let backupStamp = try fileInfo(backup), candidateStamp = try fileInfo(candidate)
        guard backupStamp.st_size == geometry.capacity, candidateStamp.st_size == geometry.rootBytes,
              validSHA(candidateSHA256), try observe(backup, geometry: geometry, check: check) == expected else {
            throw ImagerError("La sauvegarde ou le candidat ne correspond plus au reçu vérifié.")
        }
        try seekStart(candidate)
        guard try digestStream(candidate, count: geometry.rootBytes) == candidateSHA256 else {
            throw ImagerError("Le candidat de maintenance a changé.")
        }
        let originalIdentity = try Ext4Identity.read(backup, rootOffset: geometry.rootOffset, rootBytes: geometry.rootBytes)
        guard try Ext4Identity.read(candidate, rootOffset: 0, rootBytes: geometry.rootBytes) == originalIdentity else {
            throw ImagerError("Le candidat modifierait l’identité de la partition ext4.")
        }
        try requireUnchanged(backup, backupStamp); try requireUnchanged(candidate, candidateStamp)
        try validateMedia()
        let current = try observe(device, geometry: geometry, check: check) { try progress("checking-card", $0, $1) }
        guard current == expected else { throw ImagerError("La carte a changé depuis sa sauvegarde. Aucune écriture effectuée.") }
        try validateMedia(); try check()
        try requireUnchanged(backup, backupStamp); try requireUnchanged(candidate, candidateStamp)
        try seekStart(candidate)
        guard lseek(device, off_t(geometry.rootOffset), SEEK_SET) == geometry.rootOffset else {
            throw ImagerError("Impossible de positionner la partition root.")
        }
        try willWrite() // The durable receipt precedes the first device write.
        let written = try copy(candidate, to: device, count: geometry.rootBytes, check: check) { try progress("writing-root", $0, $1) }
        guard written == candidateSHA256 else { throw ImagerError("Le candidat a changé pendant l’écriture.") }
        try requireUnchanged(candidate, candidateStamp); try requireUnchanged(backup, backupStamp)
        try flush(); try validateMedia()
        let observed = try observe(device, geometry: geometry, check: check) { try progress("verifying-root", $0, $1) }
        guard observed.rootSHA256 == candidateSHA256,
              observed.mbrSHA256 == expected.mbrSHA256,
              observed.prefixSHA256 == expected.prefixSHA256,
              observed.suffixSHA256 == expected.suffixSHA256 else {
            throw ImagerError("La relecture ou la préservation des autres partitions n’a pas été confirmée.")
        }
        try requireUnchanged(candidate, candidateStamp); try requireUnchanged(backup, backupStamp)
        try validateMedia()
        return observed
    }
}

private final class MaintenanceWorkspace {
    let directory: Int32, url: URL
    private var operationLock: Int32 = -1
    private var deviceLock: Int32 = -1
    private var lastProgress = ""
    init(_ requestURL: URL) throws {
        guard getuid() >= 500, geteuid() == getuid() else {
            throw ImagerError("Lancez la maintenance dans votre session utilisateur, sans sudo.")
        }
        url = requestURL.deletingLastPathComponent()
        let openedDirectory = try Self.directory(url, privateLeaf: true)
        do {
            let acquiredLock = try Self.lock(".maintenance.lock", in: openedDirectory)
            directory = openedDirectory
            operationLock = acquiredLock
        } catch { close(openedDirectory); throw error }
    }
    deinit {
        if deviceLock >= 0 { flock(deviceLock, LOCK_UN); close(deviceLock) }
        if operationLock >= 0 { flock(operationLock, LOCK_UN); close(operationLock) }
        close(directory)
    }
    private static func directory(_ url: URL, privateLeaf: Bool) throws -> Int32 {
        guard url.path.hasPrefix("/"), url.standardizedFileURL.path == url.path, !url.path.contains("\0") else {
            throw ImagerError("Chemin de maintenance invalide.")
        }
        var fd = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw ImagerError("Dossier de maintenance inaccessible.") }
        do {
            for part in url.pathComponents.dropFirst() {
                let next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard next >= 0 else { throw ImagerError("Un dossier de maintenance est lié ou a changé.") }
                close(fd); fd = next
                let info = try fileInfo(fd)
                guard (info.st_uid == 0 || info.st_uid == getuid()), info.st_mode & 0o022 == 0 else {
                    throw ImagerError("Un dossier de maintenance n’est pas protégé.")
                }
            }
            let info = try fileInfo(fd)
            guard !privateLeaf || (info.st_uid == getuid() && info.st_mode & 0o777 == 0o700) else {
                throw ImagerError("Utilisez un dossier privé avec les permissions 0700.")
            }
            return fd
        } catch { close(fd); throw error }
    }
    private func leaf(_ name: String) throws {
        guard !name.isEmpty, name != ".", name != "..", name.range(of: #"^[A-Za-z0-9_.-]+$"#, options: .regularExpression) != nil else {
            throw ImagerError("Nom de fichier de maintenance invalide.")
        }
    }
    func input(_ name: String, maximum: Int64? = nil) throws -> (Int32, stat) {
        try leaf(name)
        let fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw ImagerError("Un fichier de maintenance est indisponible.") }
        do {
            let info = try fileInfo(fd)
            guard info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid(), info.st_nlink == 1,
                  [0o400, 0o600].contains(Int(info.st_mode & 0o777)), info.st_size > 0,
                  maximum == nil || info.st_size <= maximum! else {
                throw ImagerError("Les permissions d’un fichier de maintenance sont incorrectes.")
            }
            return (fd, info)
        } catch { close(fd); throw error }
    }
    func data(_ name: String, maximum: Int64 = 128 * 1024) throws -> Data {
        let (fd, info) = try input(name, maximum: maximum); defer { close(fd) }
        let data = try exactRead(fd, at: 0, bytes: Int(info.st_size))
        try requireUnchanged(fd, info); return data
    }
    func create(_ name: String) throws -> Int32 {
        try leaf(name)
        let fd = openat(directory, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw ImagerError("Le fichier de sauvegarde existe déjà ou ne peut pas être créé.") }
        guard fchmod(fd, 0o600) == 0 else { close(fd); throw ImagerError("Impossible de protéger la sauvegarde.") }
        return fd
    }
    func exists(_ name: String) throws -> Bool {
        try leaf(name)
        var info = stat()
        if fstatat(directory, name, &info, AT_SYMLINK_NOFOLLOW) == 0 { return true }
        guard errno == ENOENT else { throw ImagerError("Impossible de vérifier le reçu précédent.") }
        return false
    }
    private static func lock(_ name: String, in parent: Int32) throws -> Int32 {
        let fd = openat(parent, name, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw ImagerError("Verrou de maintenance indisponible.") }
        do {
            let info = try fileInfo(fd)
            guard info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid(), info.st_nlink == 1,
                  info.st_mode & 0o777 == 0o600, flock(fd, LOCK_EX | LOCK_NB) == 0 else {
                throw ImagerError("Une maintenance utilise déjà cette carte ou ce dossier.")
            }
            return fd
        } catch { close(fd); throw error }
    }
    func lockDevice(_ target: SDCard) throws {
        guard target.id.range(of: #"^disk[0-9]+$"#, options: .regularExpression) != nil else { throw ImagerError("Carte invalide.") }
        let root = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Caches/fr.mehdiguiard.inkyimager/MaintenanceLocks")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let parent = try Self.directory(root, privateLeaf: true); defer { close(parent) }
        deviceLock = try Self.lock(target.id + ".lock", in: parent)
    }
    func save<T: Encodable>(_ object: T, name: String) throws {
        try leaf(name)
        let data = try JSONEncoder().encode(object)
        guard data.count <= 128 * 1024 else { throw ImagerError("Reçu de maintenance trop volumineux.") }
        let temporary = ".receipt-" + UUID().uuidString
        let fd = try create(temporary)
        defer { close(fd); unlinkat(directory, temporary, 0) }
        try data.withUnsafeBytes { try writeAll(fd, $0) }
        guard fsync(fd) == 0 else { throw ImagerError("Synchronisation du reçu impossible.") }
        var existing = stat()
        if fstatat(directory, name, &existing, AT_SYMLINK_NOFOLLOW) == 0 {
            guard existing.st_mode & S_IFMT == S_IFREG, existing.st_uid == getuid(), existing.st_nlink == 1,
                  [0o400, 0o600].contains(Int(existing.st_mode & 0o777)) else {
                throw ImagerError("Le reçu existant a changé.")
            }
        } else if errno != ENOENT { throw ImagerError("Le reçu existant est inaccessible.") }
        guard renameat(directory, temporary, directory, name) == 0, fsync(directory) == 0 else {
            throw ImagerError("Publication du reçu impossible.")
        }
    }
    func progress(_ phase: String, done: Int64 = 0, total: Int64 = 0, message: String = "") throws {
        let bucket = total > 0 ? Int(min(100, max(0, Double(done) / Double(total) * 100))) : 0
        let signature = phase + ":" + String(bucket) + ":" + message
        if signature == lastProgress { return }; lastProgress = signature
        struct Event: Encodable { let phase: String, bytesDone: Int64, bytesTotal: Int64, message: String }
        try save(Event(phase: phase, bytesDone: done, bytesTotal: total, message: message), name: "maintenance-progress.json")
    }
    func requireSpace(_ bytes: Int64) throws {
        guard bytes > 0, bytes <= Int64.max - 1_073_741_824 else { throw ImagerError("Capacité de sauvegarde invalide.") }
        try requireAvailable(UInt64(bytes + 1_073_741_824))
    }
    func requireReserve() throws { try requireAvailable(1_073_741_824) }
    private func requireAvailable(_ bytes: UInt64) throws {
        var info = statfs()
        guard fstatfs(directory, &info) == 0 else { throw ImagerError("Espace de sauvegarde indisponible.") }
        let (free, overflow) = UInt64(info.f_bavail).multipliedReportingOverflow(by: UInt64(info.f_bsize))
        guard !overflow, free >= bytes else {
            throw ImagerError("Espace libre insuffisant sur le volume privé de maintenance ; réservez au moins 1 Go après les fichiers préparés.")
        }
    }
}

public enum MaintenanceEngine {
    public static func installCancellationHandlers() {
        guard MaintenanceControl.sources.isEmpty else { return }
        for number in [SIGINT, SIGTERM] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .global())
            source.setEventHandler {
                MaintenanceControl.lock.lock(); MaintenanceControl.cancelled = true; MaintenanceControl.lock.unlock()
            }
            source.resume(); MaintenanceControl.sources.append(source)
        }
    }

    public static func run(command: String, requestURL: URL) throws -> MaintenanceResult {
        let workspace = try MaintenanceWorkspace(requestURL), control = MaintenanceControl()
        do {
            switch command {
            case "acquire": return try acquire(requestURL, workspace: workspace, control: control)
            case "write-root": return try writeRoot(requestURL, workspace: workspace, control: control)
            case "eject": return try ejectOnly(requestURL, workspace: workspace)
            default: throw ImagerError("Commande de maintenance inconnue.")
            }
        } catch {
            try? workspace.progress("failed", message: error.localizedDescription)
            throw error
        }
    }

    private static func acquire(_ url: URL, workspace: MaintenanceWorkspace, control: MaintenanceControl) throws -> MaintenanceResult {
        let request = try JSONDecoder().decode(AcquireRequest.self, from: workspace.data(url.lastPathComponent))
        guard request.schemaVersion == 1, request.ownerUID == getuid(), request.backupFile == "sd-backup.img" else {
            throw ImagerError("Requête d’acquisition invalide.")
        }
        try workspace.lockDevice(request.target); try DiskService.requireSame(request.target)
        try workspace.requireSpace(request.target.capacity)
        // Refuse stale partial/completed outputs before unmounting anything.
        for name in [request.backupFile, ".sd-backup.partial", "acquisition.json"] {
            var value = stat()
            guard fstatat(workspace.directory, name, &value, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT else {
                throw ImagerError("Ce dossier contient déjà une acquisition. Conservez-la pour revue.")
            }
        }
        try workspace.progress("authorizing-readonly", message: "Autorisez la sauvegarde en lecture seule de la SD.")
        try control.check()
        _ = try SystemCommand.run("/usr/sbin/diskutil", ["unmountDisk", "/dev/" + request.target.id])
        let card = try AuthorizedDisk.open(target: request.target, readOnly: true); defer { close(card) }
        try control.check(); try workspace.requireSpace(request.target.capacity)
        let geometry = try MaintenanceGeometry.parse(mbr: exactRead(card, at: 0, bytes: 512), capacity: request.target.capacity)
        _ = try Ext4Identity.read(card, rootOffset: geometry.rootOffset, rootBytes: geometry.rootBytes)
        let output = try workspace.create(".sd-backup.partial"); defer { close(output) }
        guard lseek(card, 0, SEEK_SET) == 0 else { throw ImagerError("Impossible de lire la carte depuis son début.") }
        let streamHash = try MaintenanceRanges.copy(card, to: output, count: geometry.capacity, check: control.check) {
            try workspace.progress("acquiring-readonly", done: $0, total: $1)
        }
        guard fsync(output) == 0 else { throw ImagerError("Synchronisation de la sauvegarde impossible.") }
        try DiskService.requireSame(request.target)
        let copied = try fileInfo(output)
        guard copied.st_size == geometry.capacity else { throw ImagerError("La sauvegarde a une taille incorrecte.") }
        let hashes = try MaintenanceRanges.observe(output, geometry: geometry, check: control.check) {
            try workspace.progress("local-readback", done: $0, total: $1)
        }
        try requireUnchanged(output, copied)
        guard hashes.wholeSHA256 == streamHash,
              try MaintenanceGeometry.parse(mbr: exactRead(output, at: 0, bytes: 512), capacity: geometry.capacity) == geometry,
              try hex(SHA256.hash(data: exactRead(card, at: 0, bytes: 512))) == hashes.mbrSHA256 else {
            throw ImagerError("La relecture locale ou la table de partitions a changé pendant l’acquisition.")
        }
        try DiskService.requireSame(request.target)
        guard fchmod(output, 0o400) == 0, fsync(output) == 0 else { throw ImagerError("Impossible de protéger la sauvegarde vérifiée.") }
        guard renameatx_np(workspace.directory, ".sd-backup.partial", workspace.directory, request.backupFile, UInt32(RENAME_EXCL)) == 0,
              fsync(workspace.directory) == 0 else { throw ImagerError("Impossible de publier la sauvegarde vérifiée.") }
        let receipt = MaintenanceAcquisition(schemaVersion: 1, kind: "inkyos-maintenance-acquisition", operationID: UUID().uuidString,
            status: "complete", target: request.target, backupFile: request.backupFile, geometry: geometry, hashes: hashes,
            localReadbackVerified: true, rawOpenedReadOnly: true, sdWritesIssued: false,
            limits: ["No application-issued raw SD writes; unmounting may flush prior writes pending in macOS.",
                     "Local readback verifies the received stream, not a second independent SD acquisition.",
                     "A backup does not establish runtime or hardware qualification."])
        try workspace.save(receipt, name: "acquisition.json")
        try workspace.progress("acquisition-complete", message: "Sauvegarde et relecture locale vérifiées. Aucune écriture brute SD émise.")
        return MaintenanceResult(status: "acquisition-complete", readbackVerified: true, ejected: false)
    }

    private static func rootRequest(_ url: URL, workspace: MaintenanceWorkspace) throws -> RootRequest {
        let request = try JSONDecoder().decode(RootRequest.self, from: workspace.data(url.lastPathComponent))
        guard request.schemaVersion == 1, request.ownerUID == getuid(), request.backupFile == "sd-backup.img",
              request.candidateFile == "root-candidate.img", request.candidateApprovalFile == "candidate-approval.json",
              [request.candidateSHA256, request.acquisitionReceiptSHA256, request.candidateApprovalSHA256].allSatisfy(validSHA) else {
            throw ImagerError("Requête de mise à jour root invalide.")
        }
        return request
    }

    private static func writeRoot(_ url: URL, workspace: MaintenanceWorkspace, control: MaintenanceControl) throws -> MaintenanceResult {
        let request = try rootRequest(url, workspace: workspace)
        try workspace.lockDevice(request.target)
        if try workspace.exists("write-receipt.json") {
            let previous = try JSONDecoder().decode(MaintenanceWriteReceipt.self, from: workspace.data("write-receipt.json"))
            guard !previous.writeStarted else {
                throw ImagerError(previous.readbackVerified ? "Cette mise à jour est déjà écrite. Utilisez seulement la commande eject." :
                    "Une écriture a déjà commencé. Conservez la carte pour revue ; ne relancez pas.")
            }
        }
        let receiptData = try workspace.data("acquisition.json")
        guard hex(SHA256.hash(data: receiptData)) == request.acquisitionReceiptSHA256 else { throw ImagerError("Le reçu d’acquisition a changé.") }
        let acquisition = try JSONDecoder().decode(MaintenanceAcquisition.self, from: receiptData)
        guard acquisition.schemaVersion == 1, acquisition.kind == "inkyos-maintenance-acquisition", acquisition.status == "complete",
              acquisition.target == request.target, acquisition.backupFile == request.backupFile,
              acquisition.rawOpenedReadOnly, !acquisition.sdWritesIssued, acquisition.localReadbackVerified,
              acquisition.geometry.capacity == request.target.capacity else { throw ImagerError("Une acquisition complète et vérifiée de cette même carte est requise.") }
        let approvalData = try workspace.data(request.candidateApprovalFile)
        guard hex(SHA256.hash(data: approvalData)) == request.candidateApprovalSHA256 else { throw ImagerError("Le reçu du candidat a changé.") }
        let approval = try JSONDecoder().decode(CandidateApproval.self, from: approvalData)
        guard approval.schemaVersion == 1, approval.kind == "inkyos-maintenance-candidate", approval.status == "complete",
              approval.acquisitionReceiptSHA256 == request.acquisitionReceiptSHA256,
              approval.sourceBackupSHA256 == acquisition.hashes.wholeSHA256,
              approval.candidateSHA256 == request.candidateSHA256, approval.candidateBytes == acquisition.geometry.rootBytes,
              approval.baselineBackend == baselineBackend, approval.targetBackend == updatedBackend,
              approval.preservationVerified, approval.installedDeltaVerified, approval.filesystemVerified else {
            throw ImagerError("Le candidat n’a pas les preuves de préservation et de validation requises.")
        }
        let (backup, backupStamp) = try workspace.input(request.backupFile); defer { close(backup) }
        let (candidate, candidateStamp) = try workspace.input(request.candidateFile); defer { close(candidate) }
        let geometry = try MaintenanceGeometry.parse(mbr: exactRead(backup, at: 0, bytes: 512), capacity: backupStamp.st_size)
        guard geometry == acquisition.geometry, candidateStamp.st_size == geometry.rootBytes else {
            throw ImagerError("La géométrie du candidat ou de la sauvegarde a changé.")
        }
        var receipt = MaintenanceWriteReceipt(operationID: UUID().uuidString, target: request.target, geometry: geometry,
            acquisitionReceiptSHA256: request.acquisitionReceiptSHA256, candidateSHA256: request.candidateSHA256)
        try workspace.save(receipt, name: "write-receipt.json")
        do {
            try workspace.progress("authorizing-root", message: "Autorisez uniquement la mise à jour root de la carte sauvegardée.")
            try control.check(); try workspace.requireReserve(); try DiskService.requireSame(request.target)
            _ = try SystemCommand.run("/usr/sbin/diskutil", ["unmountDisk", "/dev/" + request.target.id])
            let card = try AuthorizedDisk.open(target: request.target); defer { close(card) }
            try requireUnchanged(backup, backupStamp); try requireUnchanged(candidate, candidateStamp)
            _ = try MaintenanceRanges.replaceRoot(device: card, backup: backup, candidate: candidate, geometry: geometry,
                expected: acquisition.hashes, candidateSHA256: request.candidateSHA256, check: control.check,
                validateMedia: { try DiskService.requireSame(request.target) }, willWrite: {
                    try workspace.requireReserve()
                    receipt.writeStarted = true; receipt.status = "writing-root"
                    receipt.message = "Écriture bornée à la partition root…"
                    try workspace.save(receipt, name: "write-receipt.json")
                }, flush: {
                    if fsync(card) != 0 && errno != EINVAL && errno != ENOTSUP { throw ImagerError("Synchronisation de la carte impossible.") }
                    _ = try SystemCommand.run("/bin/sync", [])
                    guard ioctl(card, 0x20006416) == 0 else { throw ImagerError("Le contrôleur SD n’a pas confirmé la synchronisation.") }
                }, progress: { phase, done, total in try workspace.progress(phase, done: done, total: total) })
            receipt.readbackVerified = true; receipt.preservedExteriorVerified = true; receipt.status = "verified"
            receipt.message = "Partition root relue ; MBR, FAT et autres octets préservés."
            try workspace.save(receipt, name: "write-receipt.json")
        } catch {
            receipt.status = "failed"; receipt.message = error.localizedDescription
            try? workspace.save(receipt, name: "write-receipt.json"); throw error
        }
        return try eject(request: request, receipt: &receipt, workspace: workspace)
    }

    private static func ejectOnly(_ url: URL, workspace: MaintenanceWorkspace) throws -> MaintenanceResult {
        let request = try rootRequest(url, workspace: workspace); try workspace.lockDevice(request.target)
        var receipt = try JSONDecoder().decode(MaintenanceWriteReceipt.self, from: workspace.data("write-receipt.json"))
        guard receipt.schemaVersion == 1, receipt.kind == "inkyos-maintenance-root-write", receipt.target == request.target,
              receipt.candidateSHA256 == request.candidateSHA256, receipt.acquisitionReceiptSHA256 == request.acquisitionReceiptSHA256,
              receipt.writeStarted, receipt.readbackVerified, receipt.preservedExteriorVerified,
              ["verified", "eject_pending", "complete"].contains(receipt.status) else {
            throw ImagerError("Aucune mise à jour vérifiée ne peut être éjectée avec cette requête.")
        }
        return try eject(request: request, receipt: &receipt, workspace: workspace)
    }

    private static func eject(request: RootRequest, receipt: inout MaintenanceWriteReceipt,
                              workspace: MaintenanceWorkspace) throws -> MaintenanceResult {
        do {
            if DiskService.isPresent(registryID: request.target.registryID) {
                try DiskService.requireSame(request.target)
                _ = try SystemCommand.run("/usr/sbin/diskutil", ["eject", "/dev/" + request.target.id])
                let deadline = ProcessInfo.processInfo.systemUptime + 3
                while DiskService.isPresent(registryID: request.target.registryID), ProcessInfo.processInfo.systemUptime < deadline {
                    Thread.sleep(forTimeInterval: 0.05)
                }
                guard !DiskService.isPresent(registryID: request.target.registryID) else { throw ImagerError("macOS utilise encore la carte.") }
            }
            receipt.status = "complete"; receipt.ejected = true; receipt.message = "Mise à jour vérifiée, carte éjectée."
        } catch {
            receipt.status = "eject_pending"; receipt.ejected = false
            receipt.message = "Mise à jour vérifiée ; éjection retenue par macOS. Utilisez seulement eject, jamais write-root."
        }
        try workspace.save(receipt, name: "write-receipt.json")
        try workspace.progress(receipt.status, message: receipt.message)
        return MaintenanceResult(status: receipt.status, readbackVerified: receipt.readbackVerified, ejected: receipt.ejected)
    }
}
