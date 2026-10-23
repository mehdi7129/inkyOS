import Foundation
import ImagerCore
import Darwin

let args = Array(CommandLine.arguments.dropFirst())
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
