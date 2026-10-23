import XCTest
import Darwin
import CAuthOpen

final class AuthorizedDiskTests: XCTestCase {
    // These inputs must be rejected before any process or authorization dialog
    // starts. They never open a physical device.
    func testOnlyWholeRawDevicePathsAreEligible() {
        for path in ["", "/etc/passwd", "/dev/disk13", "/dev/rdisk13s1", "/dev/rdisk", "/dev/rdisk13/../rdisk0"] {
            var error = [CChar](repeating: 0, count: 2048)
            XCTAssertEqual(inky_authopen(path, O_RDONLY, &error, error.count), -1, path)
            XCTAssertEqual(errno, EINVAL, path)
        }
    }

    func testNoCreationTruncationAppendOrWriteOnlyAccess() {
        for flags in [O_WRONLY, O_RDWR | O_CREAT, O_RDWR | O_TRUNC, O_RDWR | O_APPEND, O_RDWR | O_EXLOCK] {
            var error = [CChar](repeating: 0, count: 2048)
            XCTAssertEqual(inky_authopen("/dev/rdisk999999", flags, &error, error.count), -1)
            XCTAssertEqual(errno, EINVAL)
        }
    }
}
