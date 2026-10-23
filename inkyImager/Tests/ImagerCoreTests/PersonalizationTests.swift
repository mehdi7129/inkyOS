import XCTest
import Foundation
import ImagerCore

final class PersonalizationTests: XCTestCase {
    func testPrivateFATImageRoundTrip() throws {
        guard let source = ProcessInfo.processInfo.environment["INKY_IMAGER_FAT_FIXTURE"] else {
            throw XCTSkip("Run explicitly with a regular image fixture; never a physical device.")
        }
        XCTAssertFalse(source.hasPrefix("/dev/"))
        let original = URL(fileURLWithPath: source)
        let parent = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Caches/inkyImager-integration-tests")
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let directory = parent.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let image = directory.appendingPathComponent("fixture.img")
        let before = try ImageTools.sha256(url: original)
        _ = try ImagePreparation.execute("/bin/cp", ["-c", original.path, image.path])
        let wifi = WiFiConfiguration(ssid: "Cadre épreuve ;\\\"", password: "Only-fixture-1234!$", country: "FR")
        try ImagePreparation.personalize(image: image, wifi: wifi, filename: "inky-imager.json")
        XCTAssertNotEqual(try ImageTools.sha256(url: image), before)
        XCTAssertEqual(try ImageTools.sha256(url: original), before)
        // A fresh read-only mount proves the JSON survived unmount/detach.
        let output = try ImagePreparation.execute("/usr/bin/hdiutil", ["attach", "-nomount", "-readonly", "-plist", "-imagekey", "diskimage-class=CRawDiskImage", image.path])
        let plist = try XCTUnwrap(try PropertyListSerialization.propertyList(from: output, format: nil) as? [String: Any])
        let entities = try XCTUnwrap(plist["system-entities"] as? [[String: Any]])
        let whole = try XCTUnwrap(entities.compactMap { $0["dev-entry"] as? String }.first { $0.range(of: #"^/dev/disk[0-9]+$"#, options: .regularExpression) != nil })
        defer { _ = try? ImagePreparation.execute("/usr/bin/hdiutil", ["detach", whole]) }
        let mount = directory.appendingPathComponent("check")
        try FileManager.default.createDirectory(at: mount, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        _ = try ImagePreparation.execute("/usr/sbin/diskutil", ["mount", "readOnly", "-mountPoint", mount.path, whole + "s1"])
        let value = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: mount.appendingPathComponent("inky-imager.json"))) as? [String: Any])
        let saved = try XCTUnwrap(value["wifi"] as? [String: String])
        XCTAssertEqual(saved["ssid"], wifi.ssid)
        XCTAssertEqual(saved["password"], wifi.password)
        XCTAssertEqual(saved["country"], "FR")
        _ = try ImagePreparation.execute("/usr/sbin/diskutil", ["unmount", whole + "s1"])
    }
}
