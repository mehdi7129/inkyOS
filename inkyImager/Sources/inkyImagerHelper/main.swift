import Foundation
import ImagerCore
import Darwin

let args = Array(CommandLine.arguments.dropFirst())
if args.count == 2, args[0] == "--check-access" {
    do {
        guard getuid() >= 500, geteuid() == getuid() else {
            throw ImagerError("Le diagnostic doit être lancé dans la session utilisateur.")
        }
        let target = try DiskService.identify(args[1])
        let fd = try AuthorizedDisk.open(target: target, readOnly: true)
        close(fd) // Opening only: no card bytes are read or written.
        let report: [String: Any] = ["read_only": true, "sd_writes": false,
            "access_opened": true, "device": target.id, "capacity": target.capacity]
        let data = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
        print(String(decoding: data, as: UTF8.self))
        exit(0)
    } catch {
        fputs((error.localizedDescription + "\n"), stderr)
        exit(1)
    }
}
guard (args.count == 2 || args.count == 3), args.first == "--request",
      args.count == 2 || args.last == "--eject" else {
    fputs("Utilisation : inkyImagerHelper --request fichier.json [--eject]\n", stderr)
    exit(2)
}
do {
    try FlashEngine.run(requestURL: URL(fileURLWithPath: args[1]), ejectOnly: args.count == 3)
} catch {
    fputs((error.localizedDescription + "\n"), stderr)
    exit(1)
}
