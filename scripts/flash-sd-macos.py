#!/usr/bin/env python3
"""Write one pinned image to one identified removable Secure Digital medium.

macOS only; no enumeration of filesystem contents. --write is required to
mutate the card. The selected IORegistry object must survive every preflight.
"""
import argparse
import errno
import fcntl
import hashlib
import json
import os
import platform
import plistlib
import re
import stat
import subprocess
import sys


class Refused(ValueError):
    pass


# macOS SDK sys/disk.h: _IO('d', 22), sys/ioccom.h IOC_VOID=0x20000000.
DKIOCSYNCHRONIZECACHE = 0x20006416


def raw_device_flags():
    exclusive = getattr(os, 'O_EXLOCK', None)
    if exclusive is None:
        raise Refused('macOS exclusive device locking is required')
    return os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | exclusive


def flush_card(fd):
    try:
        os.fsync(fd)
    except OSError as error:
        if error.errno not in (errno.EINVAL, errno.ENOTSUP):
            raise
    run(['/bin/sync'])
    # The raw device driver must acknowledge synchronization. Ejection alone
    # does not report synchronization failures. Unsupported ioctl is a failure.
    fcntl.ioctl(fd, DKIOCSYNCHRONIZECACHE)


def run(argv):
    return subprocess.check_output(argv, timeout=30, stderr=subprocess.DEVNULL)


def media_record(device, command=run):
    if not re.fullmatch(r"disk[0-9]+", device):
        raise Refused("A whole disk identifier is required")
    data = plistlib.loads(command(["/usr/sbin/diskutil", "info", "-plist", device]))
    roots = plistlib.loads(command(["/usr/sbin/ioreg", "-a", "-r", "-c", "IOMedia"]))
    matches = []

    def visit(value):
        if isinstance(value, list):
            for child in value:
                visit(child)
        elif isinstance(value, dict):
            if value.get("BSD Name") == device:
                matches.append(value)
            visit(value.get("IORegistryEntryChildren", []))

    visit(roots)
    if len(matches) != 1:
        raise Refused("Expected one live IORegistry medium")
    entry = matches[0]
    if (data.get("DeviceIdentifier") != device
            or data.get("DeviceNode") != "/dev/" + device
            or data.get("WholeDisk") is not True
            or data.get("VirtualOrPhysical") != "Physical"
            or data.get("BusProtocol") != "Secure Digital"
            or data.get("Removable") is not True
            or data.get("Ejectable") is not True
            or data.get("Writable") is not True
            or data.get("OSInternalMedia") is True
            or entry.get("Whole") is not True
            or entry.get("Removable") is not True
            or entry.get("Ejectable") is not True):
        raise Refused("Only a writable removable Secure Digital card is accepted")
    size, registry_id = entry.get("Size"), entry.get("IORegistryEntryID")
    if (type(size) is not int or size <= 0 or size != data.get("IOKitSize")
            or type(registry_id) is not int or registry_id <= 0):
        raise Refused("Inconsistent medium size or live identity")
    return {"device": device, "capacity_bytes": size, "registry_id": registry_id}


def require_same(observed, expected):
    if observed != expected:
        raise Refused("Selected medium changed; nothing further may be written")


def open_image(path, expected_sha256):
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise Refused("A pinned SHA-256 is required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
            raise Refused("Image must be a nonempty regular file")
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 4 * 1024**2)
            if not block:
                break
            digest.update(block)
        if digest.hexdigest() != expected_sha256:
            raise Refused("Image hash differs from the pin")
        require_unchanged(fd, before)
        os.lseek(fd, 0, os.SEEK_SET)
        return fd, before
    except BaseException:
        os.close(fd)
        raise


def require_unchanged(fd, before):
    after = os.fstat(fd)
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
        raise Refused("Image changed during the operation")


def write_image(image_fd, device_fd, size):
    count, digest = 0, hashlib.sha256()
    while count < size:
        block = os.read(image_fd, min(4 * 1024**2, size - count))
        if not block:
            raise Refused("Image ended early")
        digest.update(block)
        remaining = memoryview(block)
        while remaining:
            written = os.write(device_fd, remaining)
            if written <= 0:
                raise Refused("Card write did not advance")
            remaining = remaining[written:]
        count += len(block)
    return digest.hexdigest()


def readback(device_fd, size):
    os.lseek(device_fd, 0, os.SEEK_SET)
    count, digest = 0, hashlib.sha256()
    while count < size:
        block = os.read(device_fd, min(4 * 1024**2, size - count))
        if not block:
            raise Refused("Card readback ended early")
        digest.update(block)
        count += len(block)
    return digest.hexdigest()


def flash(image, image_sha256, expected, *, write=False):
    if platform.system() != "Darwin":
        raise Refused("This operation is restricted to macOS")
    require_same(media_record(expected["device"]), expected)
    image_fd, before = open_image(image, image_sha256)
    try:
        if before.st_size > expected["capacity_bytes"]:
            raise Refused("Image exceeds card capacity")
        require_same(media_record(expected["device"]), expected)
        result = {"schema_version": 1, "scope": "sd-write-readback", "device": expected["device"],
                  "capacity_bytes": expected["capacity_bytes"], "image_bytes": before.st_size,
                  "image_sha256": image_sha256, "hardware_boot_qualified": False,
                  "card_written": False, "readback_verified": False, "ejected": False,
                  "controller_cache_flush_acknowledged": False,
                  "limits": ["Only the image-length prefix is written and verified.",
                             "Remaining card bytes are not erased or inspected.",
                             "A driver flush acknowledgement does not qualify SD power-loss behavior.",
                             "This does not establish a Raspberry Pi boot or application qualification."]}
        if not write:
            return result
        if os.geteuid() != 0:
            raise Refused("Card writes require macOS administrator authentication")
        command = ["/usr/sbin/diskutil", "unmountDisk", "/dev/" + expected["device"]]
        run(command)
        require_same(media_record(expected["device"]), expected)
        raw_path = "/dev/r" + expected["device"]
        fd = os.open(raw_path, raw_device_flags())
        try:
            info = os.fstat(fd)
            if not stat.S_ISCHR(info.st_mode) or info.st_rdev != os.stat(raw_path).st_rdev:
                raise Refused("Expected the selected raw card device")
            require_same(media_record(expected["device"]), expected)
            require_unchanged(image_fd, before)
            print("Writing the pinned image to the selected SD card...", flush=True)
            copied_sha256 = write_image(image_fd, fd, before.st_size)
            flush_card(fd)
            result['controller_cache_flush_acknowledged'] = True
            require_unchanged(image_fd, before)
            if copied_sha256 != image_sha256:
                raise Refused("Image bytes changed while being written")
            require_same(media_record(expected["device"]), expected)
            print("Verifying the complete image-length readback...", flush=True)
            observed = readback(fd, before.st_size)
            if observed != image_sha256:
                raise Refused("Card readback differs from the image pin")
            result.update(card_written=True, readback_verified=True)
        finally:
            os.close(fd)
        require_same(media_record(expected["device"]), expected)
        run(["/usr/sbin/diskutil", "eject", "/dev/" + expected["device"]])
        result["ejected"] = True
        return result
    finally:
        os.close(image_fd)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image", required=True)
    p.add_argument("--sha256", required=True)
    p.add_argument("--device", required=True)
    p.add_argument("--capacity-bytes", type=int, required=True)
    p.add_argument("--registry-id", type=int, required=True)
    p.add_argument("--write", action="store_true")
    args = p.parse_args()
    expected = {"device": args.device, "capacity_bytes": args.capacity_bytes,
                "registry_id": args.registry_id}
    try:
        result = flash(args.image, args.sha256, expected, write=args.write)
        print(json.dumps(result, indent=2, sort_keys=True))
    except (Refused, OSError, subprocess.SubprocessError, ValueError) as error:
        print("flash-sd-macos: " + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
