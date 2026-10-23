import XCTest
import Foundation
import Darwin
@testable import ImagerCore

final class ImagerCoreTests: XCTestCase {
    private func workspace() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("inkyimager-tests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        return url
    }
    private func disk(bus: String = "Secure Digital", removable: Bool = true, internalOS: Bool = false) -> [String: Any] {
        ["DeviceIdentifier": "disk13", "DeviceNode": "/dev/disk13", "WholeDisk": true,
         "VirtualOrPhysical": "Physical", "BusProtocol": bus, "Removable": removable,
         "Ejectable": true, "Writable": true, "OSInternalMedia": internalOS,
         "Internal": true, "IOKitSize": Int64(15_938_355_200), "MediaName": "SD reader"]
    }
    private var media: [String: Any] {
        ["Whole": true, "Removable": true, "Ejectable": true, "Size": Int64(15_938_355_200)]
    }

    func testInternalSDReaderIsAccepted() throws {
        let card = try DiskService.validated(info: disk(), media: media, registryID: 42, name: "disk13")
        XCTAssertEqual(card.capacity, 15_938_355_200)
    }
    func testUSBReaderIsAcceptedButFixedDriveIsRefused() throws {
        XCTAssertNoThrow(try DiskService.validated(info: disk(bus: "USB"), media: media, registryID: 42, name: "disk13"))
        XCTAssertThrowsError(try DiskService.validated(info: disk(bus: "USB", removable: false), media: media, registryID: 42, name: "disk13"))
    }
    func testSystemPhysicalStoreIsRefusedEvenWhenUSBRemovable() throws {
        let protected = try DiskService.protectedDisks(rootInfo: ["APFSPhysicalStores": [["APFSPhysicalStore": "disk13s2"]]])
        XCTAssertEqual(protected, ["disk13"])
        XCTAssertThrowsError(try DiskService.validated(info: disk(bus: "USB"), media: media, registryID: 42,
                                                       name: "disk13", protectedDisks: protected))
        XCTAssertThrowsError(try DiskService.protectedDisks(rootInfo: [:]))
    }
    func testSSDVirtualPartitionAndChangedCapacityAreRefused() throws {
        XCTAssertThrowsError(try DiskService.validated(info: disk(bus: "Apple Fabric"), media: media, registryID: 42, name: "disk13"))
        XCTAssertThrowsError(try DiskService.validated(info: disk(internalOS: true), media: media, registryID: 42, name: "disk13"))
        var virtual = disk(); virtual["VirtualOrPhysical"] = "Virtual"
        XCTAssertThrowsError(try DiskService.validated(info: virtual, media: media, registryID: 42, name: "disk13"))
        XCTAssertThrowsError(try DiskService.validated(info: disk(), media: media, registryID: 42, name: "disk13s1"))
        var mismatch = media; mismatch["Size"] = Int64(16_000_000_000)
        XCTAssertThrowsError(try DiskService.validated(info: disk(), media: mismatch, registryID: 42, name: "disk13"))
    }
    func testImageHashAndNoFollow() throws {
        let dir = try workspace(), source = dir.appendingPathComponent("source.img")
        try Data("abc".utf8).write(to: source)
        XCTAssertEqual(try ImageTools.sha256(url: source), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        let link = dir.appendingPathComponent("link.img")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: source)
        XCTAssertThrowsError(try ImageTools.sha256(url: link))
    }
    func testRealCopyThenIndependentReadbackDetectsCorruption() throws {
        let dir = try workspace(), source = dir.appendingPathComponent("source.img"), target = dir.appendingPathComponent("target.img")
        let bytes = Data((0..<(9 * 1024 * 1024)).map { UInt8(truncatingIfNeeded: $0 * 13) })
        try bytes.write(to: source)
        let (input, _) = try regularInput(source.path); defer { close(input) }
        let output = Darwin.open(target.path, O_RDWR | O_CREAT | O_EXCL, 0o600); defer { close(output) }
        XCTAssertGreaterThanOrEqual(output, 0)
        let written = try digestStream(input, count: Int64(bytes.count), destination: output)
        try seekStart(output)
        XCTAssertEqual(try digestStream(output, count: Int64(bytes.count)), written)
        var changed: UInt8 = 99
        XCTAssertEqual(pwrite(output, &changed, 1, 100), 1)
        try seekStart(output)
        XCTAssertNotEqual(try digestStream(output, count: Int64(bytes.count)), written)
    }
    func testXZDecoderAndBoundedFailure() throws {
        let dir = try workspace(), source = dir.appendingPathComponent("source.xz")
        let archive = Data(base64Encoded: "/Td6WFoAAATm1rRGAgAhARYAAAB0L+WjAQAKaW5reUltYWdlcgoAAJzzAJZN6vowAAEjC8Ib/QkftvN9AQAAAAAEWVo=")!
        try archive.write(to: source)
        let output = dir.appendingPathComponent("image.img")
        try XZDecoder.decode(source: source, destination: output, expectedBytes: 11)
        XCTAssertEqual(try Data(contentsOf: output), Data("inkyImager\n".utf8))
        XCTAssertThrowsError(try XZDecoder.decode(source: source, destination: dir.appendingPathComponent("too-small.img"), expectedBytes: 10))
        try (archive + Data([1])).write(to: dir.appendingPathComponent("trailing.xz"))
        XCTAssertThrowsError(try XZDecoder.decode(source: dir.appendingPathComponent("trailing.xz"), destination: dir.appendingPathComponent("trailing.img"), expectedBytes: 11))
        try archive.dropLast(4).write(to: dir.appendingPathComponent("truncated.xz"))
        XCTAssertThrowsError(try XZDecoder.decode(source: dir.appendingPathComponent("truncated.xz"), destination: dir.appendingPathComponent("truncated.img"), expectedBytes: 11))
    }
    func testEjectOnlyResultRoundTripDoesNotMeanWriteFailure() throws {
        let value = FlashProgress(phase: .finished, fraction: 1, message: "Carte vérifiée", ejectOnlyFailure: true, readbackVerified: true)
        let decoded = try JSONDecoder().decode(FlashProgress.self, from: JSONEncoder().encode(value))
        XCTAssertEqual(decoded.phase, .finished)
        XCTAssertTrue(decoded.readbackVerified)
        XCTAssertTrue(decoded.ejectOnlyFailure)
    }
}
