import Foundation
import ImagerCore
import Darwin

let arguments = Array(CommandLine.arguments.dropFirst())
do {
    guard getuid() >= 500, geteuid() == getuid() else {
        throw ImagerError("Lancez la maintenance dans votre session utilisateur, sans sudo.")
    }
    if arguments == ["list"] {
        let data = try JSONEncoder().encode(DiskService.listCards())
        print(String(decoding: data, as: UTF8.self))
        exit(0)
    }
    guard arguments.count == 3, ["acquire", "write-root", "eject"].contains(arguments[0]),
          arguments[1] == "--request", arguments[2].hasPrefix("/") else {
        fputs("Utilisation : inkyMaintenance list | {acquire|write-root|eject} --request /dossier-prive/requete.json\n", stderr)
        exit(2)
    }
    MaintenanceEngine.installCancellationHandlers()
    let result = try MaintenanceEngine.run(command: arguments[0], requestURL: URL(fileURLWithPath: arguments[2]))
    print(String(decoding: try JSONEncoder().encode(result), as: UTF8.self))
    exit(result.status == "eject_pending" ? 3 : 0)
} catch {
    fputs(error.localizedDescription + "\n", stderr)
    exit(1)
}
