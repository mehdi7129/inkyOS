import Foundation
import CryptoKit
import Darwin
import CXZ

struct FileStamp: Equatable {
    let device: dev_t, inode: ino_t, size: off_t
    let mode: mode_t, owner: uid_t, group: gid_t, links: nlink_t
    let modifiedSeconds: Int, modifiedNanos: Int, changedSeconds: Int, changedNanos: Int
    init(_ value: stat) {
        device = value.st_dev; inode = value.st_ino; size = value.st_size
        mode = value.st_mode; owner = value.st_uid; group = value.st_gid; links = value.st_nlink
        modifiedSeconds = value.st_mtimespec.tv_sec; modifiedNanos = value.st_mtimespec.tv_nsec
        changedSeconds = value.st_ctimespec.tv_sec; changedNanos = value.st_ctimespec.tv_nsec
    }
}

func fileInfo(_ fd: Int32) throws -> stat {
    var value = stat()
    guard fstat(fd, &value) == 0 else { throw ImagerError("Le fichier n’est plus lisible.") }
    return value
}

func regularInput(_ path: String) throws -> (Int32, stat) {
    let fd = Darwin.open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
    guard fd >= 0 else { throw ImagerError("Impossible d’ouvrir l’image InkyOS.") }
    do {
        let value = try fileInfo(fd)
        guard value.st_mode & S_IFMT == S_IFREG, value.st_nlink == 1, value.st_size > 0 else {
            throw ImagerError("L’image doit être un fichier ordinaire non lié.")
        }
        return (fd, value)
    } catch { close(fd); throw error }
}

func requireUnchanged(_ fd: Int32, _ before: stat) throws {
    guard FileStamp(try fileInfo(fd)) == FileStamp(before) else {
        throw ImagerError("L’image a changé pendant l’opération.")
    }
}

func seekStart(_ fd: Int32) throws {
    guard lseek(fd, 0, SEEK_SET) == 0 else { throw ImagerError("Impossible de relire l’image.") }
}

func writeAll(_ fd: Int32, _ data: UnsafeRawBufferPointer) throws {
    var offset = 0
    while offset < data.count {
        let count = Darwin.write(fd, data.baseAddress!.advanced(by: offset), data.count - offset)
        if count < 0 && errno == EINTR { continue }
        guard count > 0 else { throw ImagerError("L’écriture n’a pas pu être terminée. Laissez la carte branchée.") }
        offset += count
    }
}

func digestStream(_ fd: Int32, count: Int64, progress: (@Sendable (Int64, Int64) -> Void)? = nil,
                  destination: Int32? = nil) throws -> String {
    guard count > 0 else { throw ImagerError("L’image est vide.") }
    var hash = SHA256(), copied: Int64 = 0
    var buffer = [UInt8](repeating: 0, count: 4 * 1024 * 1024)
    while copied < count {
        let wanted = Int(min(Int64(buffer.count), count - copied))
        let readCount = Darwin.read(fd, &buffer, wanted)
        if readCount < 0 && errno == EINTR { continue }
        guard readCount > 0 else { throw ImagerError("La lecture s’est interrompue avant la fin de l’image.") }
        try buffer.withUnsafeBytes { bytes in
            let block = UnsafeRawBufferPointer(rebasing: bytes[..<readCount])
            hash.update(bufferPointer: block)
            if let destination { try writeAll(destination, block) }
        }
        copied += Int64(readCount)
        progress?(copied, count)
    }
    return hash.finalize().map { String(format: "%02x", $0) }.joined()
}

public enum ImageTools {
    public static func sha256(url: URL, progress: (@Sendable (Int64, Int64) -> Void)? = nil) throws -> String {
        let (fd, before) = try regularInput(url.path)
        defer { close(fd) }
        let result = try digestStream(fd, count: before.st_size, progress: progress)
        try requireUnchanged(fd, before)
        return result
    }
}

private final class XZProgressContext: Sendable {
    let callback: @Sendable (Int64, Int64) -> Void
    let total: Int64
    init(total: Int64, callback: @escaping @Sendable (Int64, Int64) -> Void) {
        self.total = total; self.callback = callback
    }
}

public enum XZDecoder {
    public static func decode(source: URL, destination: URL, expectedBytes: Int64,
                              progress: @escaping @Sendable (Int64, Int64) -> Void = { _, _ in }) throws {
        guard expectedBytes > 0 else { throw ImagerError("Taille d’image invalide.") }
        let (input, before) = try regularInput(source.path)
        defer { close(input) }
        let output = Darwin.open(destination.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard output >= 0 else { throw ImagerError("Impossible de créer l’image temporaire.") }
        defer { close(output) }
        guard fchmod(output, 0o600) == 0 else { throw ImagerError("Impossible de protéger l’image temporaire.") }
        let context = XZProgressContext(total: expectedBytes, callback: progress)
        let pointer = Unmanaged.passUnretained(context).toOpaque()
        var error = [CChar](repeating: 0, count: 512)
        let code = inky_xz_decode(input, output, UInt64(expectedBytes), { bytes, raw in
            guard let raw else { return }
            let box = Unmanaged<XZProgressContext>.fromOpaque(raw).takeUnretainedValue()
            box.callback(Int64(bytes), box.total)
        }, pointer, &error, error.count)
        guard code == 0 else { throw ImagerError(String(cString: error)) }
        guard fsync(output) == 0 else { throw ImagerError("Impossible de synchroniser l’image temporaire.") }
        try requireUnchanged(input, before)
    }
}
