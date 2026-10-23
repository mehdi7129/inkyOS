import XCTest
import Foundation
import CryptoKit
import Darwin
@testable import ImagerCore

final class MaintenanceTests: XCTestCase {
    private let capacity: Int64 = 65_536
    private func u32(_ value: UInt32, into data: inout Data, at: Int) {
        for byte in 0..<4 { data[at + byte] = UInt8(truncatingIfNeeded: value >> (byte * 8)) }
    }
    private func mbr() -> Data {
        var data = Data(repeating: 0, count: 512)
        data[510] = 0x55; data[511] = 0xaa
        data[450] = 0x0c; u32(1, into: &data, at: 454); u32(8, into: &data, at: 458)
        data[466] = 0x83; u32(16, into: &data, at: 470); u32(64, into: &data, at: 474)
        return data
    }
    private func image() throws -> (Data, MaintenanceGeometry) {
        let table = mbr(), geometry = try MaintenanceGeometry.parse(mbr: table, capacity: capacity)
        var data = Data((0..<Int(capacity)).map { UInt8(truncatingIfNeeded: $0 * 31 + 7) })
        data.replaceSubrange(0..<512, with: table)
        let at = Int(geometry.rootOffset) + 1024
        data.replaceSubrange(at..<(at + 1024), with: Data(repeating: 0, count: 1024))
        data[at + 56] = 0x53; data[at + 57] = 0xef
        u32(UInt32(geometry.rootBytes / 1024), into: &data, at: at + 4)
        u32(0, into: &data, at: at + 24)
        for byte in 0..<16 { data[at + 104 + byte] = UInt8(byte + 1) }
        return (data, geometry)
    }
    private func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    private func fixture() throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("inky-maintenance-fixture-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        return directory
    }
    private func file(_ data: Data, name: String, in directory: URL) throws -> Int32 {
        let path = directory.appendingPathComponent(name).path
        let fd = Darwin.open(path, O_RDWR | O_CREAT | O_EXCL, 0o600)
        guard fd >= 0 else { throw ImagerError("Fixture unavailable") }
        do { try data.withUnsafeBytes { try writeAll(fd, $0) }; try seekStart(fd) }
        catch { close(fd); throw error }
        addTeardownBlock { close(fd) }
        return fd
    }
    private func prepared() throws -> (URL, Data, Data, MaintenanceGeometry, MaintenanceHashes, Int32, Int32, Int32) {
        let directory = try fixture(), (original, geometry) = try image()
        var replacement = Data(original[Int(geometry.rootOffset)..<Int(geometry.suffixOffset)])
        replacement[9_000] ^= 0xff
        let device = try file(original, name: "device.fixture", in: directory)
        let backup = try file(original, name: "backup.fixture", in: directory)
        let candidate = try file(replacement, name: "candidate.fixture", in: directory)
        let observed = try MaintenanceRanges.observe(backup, geometry: geometry)
        return (directory, original, replacement, geometry, observed, device, backup, candidate)
    }

    func testMBRGeometryIsDerivedFromCurrentTableIncludingSuffix() throws {
        let geometry = try MaintenanceGeometry.parse(mbr: mbr(), capacity: capacity)
        XCTAssertEqual(geometry.bootOffset, 512)
        XCTAssertEqual(geometry.bootBytes, 4096)
        XCTAssertEqual(geometry.rootOffset, 8192)
        XCTAssertEqual(geometry.rootBytes, 32768)
        XCTAssertEqual(geometry.suffixBytes, 24576)
    }

    func testMalformedAndUnexpectedPartitionLayoutsAreRejected() {
        var cases: [Data] = []
        var invalid = mbr(); invalid[510] = 0; cases.append(invalid)
        invalid = mbr(); invalid[450] = 0xee; cases.append(invalid)
        invalid = mbr(); invalid[466] = 7; cases.append(invalid)
        invalid = mbr(); invalid[478] = 1; cases.append(invalid)
        invalid = mbr(); u32(0, into: &invalid, at: 474); cases.append(invalid)
        invalid = mbr(); u32(2, into: &invalid, at: 470); cases.append(invalid)
        invalid = mbr(); u32(UInt32.max, into: &invalid, at: 470); cases.append(invalid)
        invalid = mbr(); u32(UInt32.max, into: &invalid, at: 474); cases.append(invalid)
        invalid = mbr(); invalid[446] = 7; cases.append(invalid)
        for data in cases { XCTAssertThrowsError(try MaintenanceGeometry.parse(mbr: data, capacity: capacity)) }
        for bytes in [Int64(-512), 0, capacity - 1, Int64.max] {
            XCTAssertThrowsError(try MaintenanceGeometry.parse(mbr: mbr(), capacity: bytes))
        }
    }

    func testHashObservationSeparatesMBRFATRootAndSuffix() throws {
        let directory = try fixture(), (original, geometry) = try image()
        let fd = try file(original, name: "source.fixture", in: directory)
        let result = try MaintenanceRanges.observe(fd, geometry: geometry)
        XCTAssertEqual(result.wholeSHA256, hash(original))
        XCTAssertEqual(result.mbrSHA256, hash(Data(original.prefix(512))))
        XCTAssertEqual(result.prefixSHA256, hash(Data(original.prefix(Int(geometry.rootOffset)))))
        XCTAssertEqual(result.rootSHA256, hash(Data(original[Int(geometry.rootOffset)..<Int(geometry.suffixOffset)])))
        XCTAssertEqual(result.suffixSHA256, hash(Data(original.suffix(Int(geometry.suffixBytes)))))
    }

    func testPartitionEndingAtCapacityHasExplicitEmptySuffixHash() throws {
        let directory = try fixture(), (original, initial) = try image()
        let geometry = try MaintenanceGeometry.parse(mbr: mbr(), capacity: initial.suffixOffset)
        let fd = try file(Data(original.prefix(Int(geometry.capacity))), name: "no-suffix.fixture", in: directory)
        let result = try MaintenanceRanges.observe(fd, geometry: geometry)
        XCTAssertEqual(geometry.suffixBytes, 0)
        XCTAssertEqual(result.suffixSHA256, hash(Data()))
    }

    func testSuccessfulRootReplacementPreservesEveryExteriorByte() throws {
        let (directory, original, replacement, geometry, expected, device, backup, candidate) = try prepared()
        var writeStarted = false
        let result = try MaintenanceRanges.replaceRoot(device: device, backup: backup, candidate: candidate,
            geometry: geometry, expected: expected, candidateSHA256: hash(replacement), willWrite: { writeStarted = true },
            flush: { XCTAssertEqual(fsync(device), 0) })
        XCTAssertTrue(writeStarted)
        var wanted = original
        wanted.replaceSubrange(Int(geometry.rootOffset)..<Int(geometry.suffixOffset), with: replacement)
        XCTAssertEqual(try Data(contentsOf: directory.appendingPathComponent("device.fixture")), wanted)
        XCTAssertEqual(result.rootSHA256, hash(replacement))
        XCTAssertEqual(result.prefixSHA256, expected.prefixSHA256)
        XCTAssertEqual(result.suffixSHA256, expected.suffixSHA256)
        XCTAssertEqual(result.mbrSHA256, expected.mbrSHA256)
    }

    func testChangedCardIsRejectedBeforeFirstWrite() throws {
        let (directory, original, replacement, geometry, expected, device, backup, candidate) = try prepared()
        var value: UInt8 = 42
        XCTAssertEqual(pwrite(device, &value, 1, 700), 1)
        let before = try Data(contentsOf: directory.appendingPathComponent("device.fixture"))
        XCTAssertNotEqual(before, original)
        var started = false
        XCTAssertThrowsError(try MaintenanceRanges.replaceRoot(device: device, backup: backup, candidate: candidate,
            geometry: geometry, expected: expected, candidateSHA256: hash(replacement), willWrite: { started = true }, flush: {}))
        XCTAssertFalse(started)
        XCTAssertEqual(try Data(contentsOf: directory.appendingPathComponent("device.fixture")), before)
    }

    func testChangedBackupAndCandidateHashAreRejectedBeforeWriting() throws {
        let (directory, original, replacement, geometry, expected, device, backup, candidate) = try prepared()
        var started = false, value: UInt8 = 42
        XCTAssertThrowsError(try MaintenanceRanges.replaceRoot(device: device, backup: backup, candidate: candidate,
            geometry: geometry, expected: expected, candidateSHA256: String(repeating: "0", count: 64),
            willWrite: { started = true }, flush: {}))
        XCTAssertEqual(pwrite(backup, &value, 1, 900), 1)
        XCTAssertThrowsError(try MaintenanceRanges.replaceRoot(device: device, backup: backup, candidate: candidate,
            geometry: geometry, expected: expected, candidateSHA256: hash(replacement), willWrite: { started = true }, flush: {}))
        XCTAssertFalse(started)
        XCTAssertEqual(try Data(contentsOf: directory.appendingPathComponent("device.fixture")), original)
    }

    func testChangedExt4IdentityIsRejectedEvenWithMatchingCandidateHash() throws {
        let (directory, original, replacement, geometry, expected, device, backup, _) = try prepared()
        var wrongIdentity = replacement
        wrongIdentity[1024 + 104] ^= 0xff
        let candidate = try file(wrongIdentity, name: "wrong-uuid.fixture", in: directory)
        var started = false
        XCTAssertThrowsError(try MaintenanceRanges.replaceRoot(device: device, backup: backup, candidate: candidate,
            geometry: geometry, expected: expected, candidateSHA256: hash(wrongIdentity), willWrite: { started = true }, flush: {}))
        XCTAssertFalse(started)
        XCTAssertEqual(try Data(contentsOf: directory.appendingPathComponent("device.fixture")), original)
    }

    func testMediaReidentificationAndCancellationCanStopBeforeWriting() throws {
        let (directory, original, replacement, geometry, expected, device, backup, candidate) = try prepared()
        var started = false
        XCTAssertThrowsError(try MaintenanceRanges.replaceRoot(device: device, backup: backup, candidate: candidate,
            geometry: geometry, expected: expected, candidateSHA256: hash(replacement),
            validateMedia: { throw ImagerError("changed identity fixture") }, willWrite: { started = true }, flush: {}))
        XCTAssertThrowsError(try MaintenanceRanges.replaceRoot(device: device, backup: backup, candidate: candidate,
            geometry: geometry, expected: expected, candidateSHA256: hash(replacement),
            check: { throw ImagerError("cancel fixture") }, willWrite: { started = true }, flush: {}))
        XCTAssertFalse(started)
        XCTAssertEqual(try Data(contentsOf: directory.appendingPathComponent("device.fixture")), original)
    }

    func testFailedDurableWriteReceiptStopsBeforeAnyMutation() throws {
        let (directory, original, replacement, geometry, expected, device, backup, candidate) = try prepared()
        XCTAssertThrowsError(try MaintenanceRanges.replaceRoot(device: device, backup: backup, candidate: candidate,
            geometry: geometry, expected: expected, candidateSHA256: hash(replacement),
            willWrite: { throw ImagerError("receipt publication fixture") }, flush: {}))
        XCTAssertEqual(try Data(contentsOf: directory.appendingPathComponent("device.fixture")), original)
    }

    private func privateWorkspace() throws -> URL {
        let directory = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Caches/inky-maintenance-tests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        return directory
    }
    private func privateJSON(_ value: Any, name: String, in directory: URL) throws {
        let path = directory.appendingPathComponent(name)
        try JSONSerialization.data(withJSONObject: value).write(to: path)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
    }
    private func request(in directory: URL) throws -> [String: Any] {
        let target: [String: Any] = ["id": "disk999999", "name": "inert fixture", "capacity": capacity, "registryID": 42]
        let request: [String: Any] = ["schemaVersion": 1, "ownerUID": getuid(), "target": target,
            "backupFile": "sd-backup.img", "candidateFile": "root-candidate.img", "candidateSHA256": String(repeating: "a", count: 64),
            "acquisitionReceiptSHA256": String(repeating: "b", count: 64),
            "candidateApprovalFile": "candidate-approval.json", "candidateApprovalSHA256": String(repeating: "c", count: 64)]
        try privateJSON(request, name: "write-request.json", in: directory)
        return request
    }
    func testAlreadyStartedWriteIsNotRetriedAndUnverifiedReceiptCannotEject() throws {
        let directory = try privateWorkspace(), request = try request(in: directory)
        let geometry = try MaintenanceGeometry.parse(mbr: mbr(), capacity: capacity)
        let receipt: [String: Any] = ["schemaVersion": 1, "kind": "inkyos-maintenance-root-write", "operationID": UUID().uuidString,
            "target": request["target"]!, "geometry": try JSONSerialization.jsonObject(with: JSONEncoder().encode(geometry)),
            "acquisitionReceiptSHA256": request["acquisitionReceiptSHA256"]!, "candidateSHA256": request["candidateSHA256"]!,
            "status": "failed", "writeStarted": true, "readbackVerified": false, "preservedExteriorVerified": false,
            "ejected": false, "message": "fixture failed after write started"]
        try privateJSON(receipt, name: "write-receipt.json", in: directory)
        let old = try Data(contentsOf: directory.appendingPathComponent("write-receipt.json"))
        let url = directory.appendingPathComponent("write-request.json")
        XCTAssertThrowsError(try MaintenanceEngine.run(command: "write-root", requestURL: url)) { error in
            XCTAssertTrue(error.localizedDescription.contains("écriture a déjà commencé"))
        }
        XCTAssertThrowsError(try MaintenanceEngine.run(command: "eject", requestURL: url)) { error in
            XCTAssertTrue(error.localizedDescription.contains("Aucune mise à jour vérifiée"))
        }
        XCTAssertEqual(try Data(contentsOf: directory.appendingPathComponent("write-receipt.json")), old)
    }

    func testMalformedPreviousReceiptIsPreservedAndNeverTreatedAsNewOperation() throws {
        let directory = try privateWorkspace(); _ = try request(in: directory)
        let path = directory.appendingPathComponent("write-receipt.json")
        let old = Data("{broken previous receipt".utf8)
        try old.write(to: path); try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        XCTAssertThrowsError(try MaintenanceEngine.run(command: "write-root", requestURL: directory.appendingPathComponent("write-request.json")))
        XCTAssertEqual(try Data(contentsOf: path), old)
    }

    func testSymlinkRequestAndNonPrivateWorkspaceAreRejectedBeforeMediaAccess() throws {
        let directory = try privateWorkspace()
        try privateJSON(["schemaVersion": 1], name: "actual.json", in: directory)
        let request = directory.appendingPathComponent("acquire-request.json")
        try FileManager.default.createSymbolicLink(at: request, withDestinationURL: directory.appendingPathComponent("actual.json"))
        XCTAssertThrowsError(try MaintenanceEngine.run(command: "acquire", requestURL: request)) { error in
            XCTAssertTrue(error.localizedDescription.contains("fichier de maintenance est indisponible"))
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: directory.path)
        XCTAssertThrowsError(try MaintenanceEngine.run(command: "acquire", requestURL: request)) { error in
            XCTAssertTrue(error.localizedDescription.contains("0700"))
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: directory.appendingPathComponent("acquisition.json").path))
    }

    func testSymlinkWorkspaceParentIsRejectedBeforeRequestOrMediaAccess() throws {
        let directory = try privateWorkspace()
        let link = directory.deletingLastPathComponent().appendingPathComponent("inky-maintenance-link-" + UUID().uuidString)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: directory)
        addTeardownBlock { try? FileManager.default.removeItem(at: link) }
        XCTAssertThrowsError(try MaintenanceEngine.run(command: "acquire", requestURL: link.appendingPathComponent("request.json"))) { error in
            XCTAssertTrue(error.localizedDescription.contains("lié ou a changé"))
        }
    }
}
