import Foundation
import Darwin
import CAuthOpen

public enum AuthorizedDisk {
    /// Grants access to this device only. authopen presents macOS authorization
    /// and passes an open descriptor back without elevating the writer process.
    public static func open(target: SDCard, readOnly: Bool = false) throws -> Int32 {
        try DiskService.requireSame(target)
        let path = "/dev/r" + target.id
        var before = stat()
        guard lstat(path, &before) == 0, before.st_mode & S_IFMT == S_IFCHR else {
            throw ImagerError("Le support sélectionné n’est plus disponible.")
        }
        // authopen accepts the plain access mode. The /dev path is checked
        // with lstat before and after the grant; no create/truncate is used.
        let flags = readOnly ? O_RDONLY : O_RDWR
        var diagnostic = [CChar](repeating: 0, count: 2048)
        let descriptor = inky_authopen(path, flags, &diagnostic, diagnostic.count)
        guard descriptor >= 0 else {
            let detail = String(cString: diagnostic)
            throw ImagerError("macOS n’a pas autorisé l’accès à la carte SD sélectionnée." +
                (detail.isEmpty ? "" : "\n" + detail))
        }
        do {
            // The card may have been removed/replaced while the user answered
            // the authorization prompt. Never use the granted FD before both
            // the media identity and its character-device identity match.
            try DiskService.requireSame(target)
            let opened = try fileInfo(descriptor)
            var named = stat()
            guard lstat(path, &named) == 0,
                  opened.st_mode & S_IFMT == S_IFCHR,
                  named.st_mode & S_IFMT == S_IFCHR,
                  opened.st_rdev == named.st_rdev, opened.st_rdev == before.st_rdev else {
                throw ImagerError("Le support ouvert n’est pas la carte sélectionnée.")
            }
            return descriptor
        } catch {
            close(descriptor)
            throw error
        }
    }
}
