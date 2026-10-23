import Foundation

public struct SDCard: Identifiable, Codable, Equatable, Sendable {
    public let id: String
    public let name: String
    public let capacity: Int64
    public let registryID: UInt64
    public init(id: String, name: String, capacity: Int64, registryID: UInt64) {
        self.id = id; self.name = name; self.capacity = capacity; self.registryID = registryID
    }
}

public enum FlashPhase: String, Codable, Sendable {
    case idle, preparing, writing, verifying, configuring, ejecting, finished, failed
}

public struct FlashProgress: Codable, Sendable {
    public let phase: FlashPhase
    public let fraction: Double
    public let message: String
    public let bytesDone: Int64?
    public let bytesTotal: Int64?
    public let ejectOnlyFailure: Bool
    public let readbackVerified: Bool
    public init(phase: FlashPhase, fraction: Double, message: String,
                bytesDone: Int64? = nil, bytesTotal: Int64? = nil,
                ejectOnlyFailure: Bool = false, readbackVerified: Bool = false) {
        self.phase = phase; self.fraction = fraction; self.message = message
        self.bytesDone = bytesDone; self.bytesTotal = bytesTotal
        self.ejectOnlyFailure = ejectOnlyFailure; self.readbackVerified = readbackVerified
    }
}

public struct FlashRequest: Codable, Sendable {
    public let imagePath: String
    public let imageSHA256: String
    public let imageBytes: Int64
    public let target: SDCard
    public let progressPath: String
    public let ownerUID: UInt32
    public init(imagePath: String, imageSHA256: String, imageBytes: Int64, target: SDCard,
                progressPath: String, ownerUID: UInt32) {
        self.imagePath = imagePath; self.imageSHA256 = imageSHA256
        self.imageBytes = imageBytes; self.target = target
        self.progressPath = progressPath; self.ownerUID = ownerUID
    }
}

public struct ImagerError: LocalizedError, Sendable {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}
