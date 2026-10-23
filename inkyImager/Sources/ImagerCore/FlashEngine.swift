import Foundation
import Darwin
import CryptoKit

private func checkedDirectory(_ path: String, owner: uid_t, privateLeaf: Bool) throws -> (Int32, stat) {
    let url = URL(fileURLWithPath: path)
    guard path.hasPrefix("/"), !path.contains("\0"), url.standardizedFileURL.path == path else {
        throw ImagerError("Chemin de travail invalide.")
    }
    var fd = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    guard fd >= 0 else { throw ImagerError("Dossier de travail inaccessible.") }
    do {
        for part in url.pathComponents.dropFirst() {
            let next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
            guard next >= 0 else { throw ImagerError("Un dossier de travail a changé ou est lié.") }
            close(fd); fd = next
            let value = try fileInfo(fd)
            guard value.st_mode & S_IFMT == S_IFDIR,
                  value.st_uid == 0 || value.st_uid == owner,
                  value.st_mode & 0o022 == 0 else {
                throw ImagerError("Le dossier de travail n’est pas protégé.")
            }
        }
        let value = try fileInfo(fd)
        if privateLeaf {
            guard value.st_uid == owner, value.st_mode & 0o777 == 0o700 else {
                throw ImagerError("Le dossier privé doit appartenir à l’utilisateur.")
            }
        }
        return (fd, value)
    } catch { close(fd); throw error }
}

private func privateFile(_ name: String, directory: Int32, owner: uid_t, maximum: Int64? = nil) throws -> (Int32, stat) {
    guard !name.isEmpty, name != ".", name != "..", !name.contains("/") else {
        throw ImagerError("Nom de fichier invalide.")
    }
    let fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
    guard fd >= 0 else { throw ImagerError("Le fichier privé est indisponible.") }
    do {
        let value = try fileInfo(fd)
        guard value.st_mode & S_IFMT == S_IFREG, value.st_uid == owner,
              value.st_mode & 0o777 == 0o600, value.st_nlink == 1, value.st_size > 0,
              maximum == nil || value.st_size <= maximum! else {
            throw ImagerError("Les permissions du fichier privé sont incorrectes.")
        }
        return (fd, value)
    } catch { close(fd); throw error }
}

private final class ProgressWriter: @unchecked Sendable {
    let directory: Int32
    let owner: uid_t, group: gid_t
    private let lock = NSLock()
    private var lastPercent: Int = -1
    init(directory: Int32, owner: uid_t, group: gid_t) {
        self.directory = directory; self.owner = owner; self.group = group
    }
    func publish(_ value: FlashProgress, force: Bool = false) throws {
        lock.lock(); defer { lock.unlock() }
        let percent = Int(value.fraction * 100)
        if !force && lastPercent == percent { return }
        lastPercent = percent
        let encoded = try JSONEncoder().encode(value)
        let temporary = ".progress-" + UUID().uuidString
        let fd = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw ImagerError("Impossible d’enregistrer la progression.") }
        defer { close(fd); unlinkat(directory, temporary, 0) }
        guard fchmod(fd, 0o600) == 0, fchown(fd, owner, group) == 0 else {
            throw ImagerError("Impossible de protéger la progression.")
        }
        try encoded.withUnsafeBytes { try writeAll(fd, $0) }
        guard fsync(fd) == 0 else { throw ImagerError("Impossible de synchroniser la progression.") }
        var existing = stat()
        if fstatat(directory, "progress.json", &existing, AT_SYMLINK_NOFOLLOW) == 0 {
            guard existing.st_mode & S_IFMT == S_IFREG, existing.st_uid == owner,
                  existing.st_nlink == 1, existing.st_mode & 0o777 == 0o600 else {
                throw ImagerError("Le fichier de progression a changé.")
            }
        } else if errno != ENOENT { throw ImagerError("La progression est inaccessible.") }
        guard renameat(directory, temporary, directory, "progress.json") == 0, fsync(directory) == 0 else {
            throw ImagerError("Impossible de publier la progression.")
        }
    }
}

public enum FlashEngine {
    /// User-session writer. Only Apple's authopen opens the selected raw device;
    /// this process retains the app's user identity and removable-volume consent.
    /// No filesystem injection or Wi-Fi credentials are accepted here.
    public static func run(requestURL: URL, ejectOnly: Bool = false) throws {
        guard getuid() >= 500, geteuid() == getuid() else {
            throw ImagerError("L’installation doit être lancée depuis votre session inkyImager.")
        }
        var requestStat = stat()
        guard lstat(requestURL.path, &requestStat) == 0, requestStat.st_uid == getuid(),
              requestStat.st_mode & S_IFMT == S_IFREG else {
            throw ImagerError("La requête privée n’est pas valide.")
        }
        let (directory, directoryStat) = try checkedDirectory(requestURL.deletingLastPathComponent().path,
                                                             owner: requestStat.st_uid, privateLeaf: true)
        defer { close(directory) }
        let (requestFD, before) = try privateFile(requestURL.lastPathComponent, directory: directory,
                                                 owner: requestStat.st_uid, maximum: 64 * 1024)
        let request: FlashRequest
        do {
            let data = try FileHandle(fileDescriptor: dup(requestFD), closeOnDealloc: true).readToEnd() ?? Data()
            try requireUnchanged(requestFD, before)
            request = try JSONDecoder().decode(FlashRequest.self, from: data)
            close(requestFD)
        } catch { close(requestFD); throw error }
        guard request.ownerUID == requestStat.st_uid,
              URL(fileURLWithPath: request.progressPath) == requestURL.deletingLastPathComponent().appendingPathComponent("progress.json"),
              request.target.capacity > 0, request.target.registryID > 0 else {
            throw ImagerError("La requête ne correspond plus à cette installation.")
        }
        let writer = ProgressWriter(directory: directory, owner: request.ownerUID, group: directoryStat.st_gid)
        if ejectOnly {
            let (fd, _) = try privateFile("progress.json", directory: directory, owner: request.ownerUID, maximum: 65536)
            let previous: FlashProgress
            do {
                let data = try FileHandle(fileDescriptor: dup(fd), closeOnDealloc: true).readToEnd() ?? Data()
                previous = try JSONDecoder().decode(FlashProgress.self, from: data); close(fd)
            } catch { close(fd); throw error }
            guard previous.readbackVerified, previous.ejectOnlyFailure else {
                throw ImagerError("Aucune éjection en attente pour cette carte.")
            }
            try eject(request.target, writer: writer)
            return
        }
        do { try flash(request, requestURL: requestURL, directory: directory, writer: writer) }
        catch {
            try? writer.publish(FlashProgress(phase: .failed, fraction: 0, message: error.localizedDescription), force: true)
            throw error
        }
    }

    private static func flash(_ request: FlashRequest, requestURL: URL, directory: Int32,
                              writer: ProgressWriter) throws {
        guard request.imageSHA256.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil,
              request.imageBytes > 0, request.imageBytes <= request.target.capacity,
              URL(fileURLWithPath: request.imagePath).deletingLastPathComponent() == requestURL.deletingLastPathComponent() else {
            throw ImagerError("L’image ou la carte sélectionnée n’est pas valide.")
        }
        try DiskService.requireSame(request.target)
        let (image, before) = try privateFile(URL(fileURLWithPath: request.imagePath).lastPathComponent,
                                             directory: directory, owner: request.ownerUID)
        defer { close(image) }
        guard before.st_size == request.imageBytes else { throw ImagerError("La taille de l’image a changé.") }
        try writer.publish(FlashProgress(phase: .preparing, fraction: 0, message: "Vérification de l’image…"), force: true)
        guard try digestStream(image, count: request.imageBytes) == request.imageSHA256 else {
            throw ImagerError("L’image préparée est endommagée.")
        }
        try requireUnchanged(image, before); try seekStart(image)
        try DiskService.requireSame(request.target)
        _ = try SystemCommand.run("/usr/sbin/diskutil", ["unmountDisk", "/dev/" + request.target.id])
        let card = try AuthorizedDisk.open(target: request.target)
        do {
            try requireUnchanged(image, before)
            try writer.publish(FlashProgress(phase: .writing, fraction: 0, message: "Écriture d’InkyOS…"), force: true)
            let copied = try digestStream(image, count: request.imageBytes, progress: { done, total in
                try? writer.publish(FlashProgress(phase: .writing, fraction: Double(done) / Double(total),
                    message: "Écriture d’InkyOS…", bytesDone: done, bytesTotal: total))
            }, destination: card)
            guard copied == request.imageSHA256 else { throw ImagerError("L’image a changé pendant l’écriture.") }
            try requireUnchanged(image, before)
            if fsync(card) != 0 && errno != EINVAL && errno != ENOTSUP { throw ImagerError("Synchronisation de la carte impossible.") }
            _ = try SystemCommand.run("/bin/sync", [])
            guard ioctl(card, 0x20006416) == 0 else { throw ImagerError("La carte n’a pas confirmé la synchronisation.") }
            try DiskService.requireSame(request.target)
            try seekStart(card)
            try writer.publish(FlashProgress(phase: .verifying, fraction: 0, message: "Relecture de la carte…"), force: true)
            let observed = try digestStream(card, count: request.imageBytes, progress: { done, total in
                try? writer.publish(FlashProgress(phase: .verifying, fraction: Double(done) / Double(total),
                    message: "Relecture de la carte…", bytesDone: done, bytesTotal: total))
            })
            guard observed == request.imageSHA256 else {
                throw ImagerError("La relecture ne correspond pas à l’image. Laissez la carte branchée.")
            }
            try requireUnchanged(image, before)
            close(card)
        } catch { close(card); throw error }
        try eject(request.target, writer: writer)
    }

    private static func eject(_ target: SDCard, writer: ProgressWriter) throws {
        try writer.publish(FlashProgress(phase: .ejecting, fraction: 1, message: "Carte vérifiée. Éjection…",
                                         readbackVerified: true), force: true)
        do {
            if DiskService.isPresent(registryID: target.registryID) {
                try DiskService.requireSame(target)
                _ = try SystemCommand.run("/usr/sbin/diskutil", ["eject", "/dev/" + target.id])
                let deadline = Date().addingTimeInterval(2)
                while DiskService.isPresent(registryID: target.registryID) && Date() < deadline {
                    Thread.sleep(forTimeInterval: 0.05)
                }
                guard !DiskService.isPresent(registryID: target.registryID) else {
                    throw ImagerError("macOS retient encore la carte.")
                }
            }
            try writer.publish(FlashProgress(phase: .finished, fraction: 1,
                message: "Carte prête. Insérez-la dans le Pi éteint, puis allumez-le.", readbackVerified: true), force: true)
        } catch {
            // Never repeat write/verify when Spotlight retains an already verified card.
            try writer.publish(FlashProgress(phase: .finished, fraction: 1,
                message: "Carte vérifiée. macOS retient encore son éjection.",
                ejectOnlyFailure: true, readbackVerified: true), force: true)
        }
    }
}
