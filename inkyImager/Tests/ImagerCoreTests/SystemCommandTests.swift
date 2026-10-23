import XCTest
import Foundation
@testable import ImagerCore

final class SystemCommandTests: XCTestCase {
    func testAppleScriptFailurePreservesDiagnosticAndExitStatus() throws {
        XCTAssertThrowsError(try SystemCommand.run("/usr/bin/osascript", [
            "-e", "error \"Fixture preparation refusee\" number 4190"
        ])) { error in
            guard let failure = error as? SystemCommandFailure else { return XCTFail("Expected a typed command failure") }
            XCTAssertEqual(failure.executable, "osascript")
            XCTAssertEqual(failure.exitStatus, 1)
            XCTAssertFalse(failure.timedOut)
            XCTAssertTrue(failure.standardError.contains("Fixture preparation refusee"))
            XCTAssertTrue(failure.standardError.contains("4190"))
            XCTAssertTrue(failure.localizedDescription.contains("code 1"))
        }
    }

    func testAppleScriptCancellationRemainsRecognizable() throws {
        XCTAssertThrowsError(try SystemCommand.run("/usr/bin/osascript", ["-e", "error number -128"])) { error in
            guard let failure = error as? SystemCommandFailure else { return XCTFail("Expected a typed command failure") }
            XCTAssertEqual(failure.exitStatus, 1)
            XCTAssertTrue(failure.localizedDescription.contains("(-128)"))
        }
    }

    func testFalseReturnsExitStatusWithoutInventingDiagnostic() throws {
        XCTAssertThrowsError(try SystemCommand.run("/usr/bin/false", [])) { error in
            guard let failure = error as? SystemCommandFailure else { return XCTFail("Expected a typed command failure") }
            XCTAssertEqual(failure.executable, "false")
            XCTAssertEqual(failure.exitStatus, 1)
            XCTAssertEqual(failure.standardError, "")
        }
    }

    func testPrintfSuccessReturnsExactOutput() throws {
        let output = try SystemCommand.run("/usr/bin/printf", ["inkyImager\n"])
        XCTAssertEqual(output, Data("inkyImager\n".utf8))
    }

    func testLargeAppleScriptDiagnosticIsBounded() throws {
        let script = "set diagnostic to \"\"\nrepeat 20000 times\nset diagnostic to diagnostic & \"x\"\nend repeat\nerror diagnostic number 4191"
        XCTAssertThrowsError(try SystemCommand.run("/usr/bin/osascript", ["-e", script])) { error in
            guard let failure = error as? SystemCommandFailure else { return XCTFail("Expected a typed command failure") }
            XCTAssertLessThanOrEqual(failure.standardError.utf8.count, 8192 + 32)
            XCTAssertTrue(failure.standardError.contains("[diagnostic tronqué]"))
            XCTAssertLessThan(failure.localizedDescription.utf8.count, 2300)
        }
    }

    func testTimeoutTerminatesChildAndReportsTypedFailure() throws {
        let start = Date()
        XCTAssertThrowsError(try SystemCommand.run("/bin/sleep", ["2"], timeout: 0.05)) { error in
            guard let failure = error as? SystemCommandFailure else { return XCTFail("Expected a typed command failure") }
            XCTAssertEqual(failure.executable, "sleep")
            XCTAssertTrue(failure.timedOut)
            XCTAssertNotEqual(failure.exitStatus, 0)
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 2)
    }
}
