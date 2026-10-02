#!/usr/bin/env python3
"""Acquire one identified SD into a new private directory, without raw writes.

Dry-run by default. --acquire requires administrator authentication. The
destination must be a new direct child of an existing private directory (0700).
Failed acquisitions are preserved and must never be treated as complete.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import time


_spec = importlib.util.spec_from_file_location(
    "inkyos_flash_media", Path(__file__).with_name("flash-sd-macos.py"))
_media = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_media)
media_record = _media.media_record
run = _media.run
Refused = _media.Refused
BLOCK_SIZE = 4 * 1024**2


class StderrProgress:
    """Emit only a fixed phase, percentage and byte counters; never card data."""
    def __init__(self):
        self.phase, self.count, self.updated_at = None, 0, 0

    def __call__(self, phase, count, total):
        if (phase not in ("copy", "local_readback")
                or type(count) is not int or type(total) is not int
                or total <= 0 or not 0 <= count <= total):
            raise Refused("invalid_progress_update")
        now = time.monotonic()
        if (phase != self.phase or count - self.count >= 256 * 1024**2
                or now - self.updated_at >= 2
                or (count == total and count != self.count)):
            print(f"{phase}: {100 * count / total:.1f}% ({count}/{total} bytes)",
                  file=sys.stderr, flush=True)
            self.phase, self.count, self.updated_at = phase, count, now


def require_same(observed, expected):
    if observed != expected:
        raise Refused("medium_changed")


def raw_device_flags():
    exclusive = getattr(os, "O_EXLOCK", None)
    if exclusive is None:
        raise Refused("exclusive_lock_unavailable")
    return os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | exclusive


def owner_identity(uid, gid, acquire):
    if (uid is None) != (gid is None):
        raise Refused("owner_pair_required")
    if uid is None:
        return None
    if uid <= 0 or gid < 0:
        raise Refused("invalid_owner")
    if acquire:
        if (os.environ.get("SUDO_UID") != str(uid)
                or os.environ.get("SUDO_GID") != str(gid)):
            raise Refused("owner_must_match_sudo_operator")
    elif uid != os.getuid() or gid != os.getgid():
        raise Refused("owner_must_match_operator")
    return uid, gid


def directory_flags():
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK


def open_destination_parent(output_dir, owner):
    """Walk every ancestor through directory FDs, rejecting symlinks/writable paths."""
    path = Path(output_dir)
    if (not path.is_absolute() or ".." in path.parts or path.name in ("", ".", "..")
            or path.parent.name != "private"):
        raise Refused("new_directory_must_be_direct_child_of_private")
    parent_info = os.lstat(path.parent)
    operator_uid = owner[0] if owner else parent_info.st_uid
    if not owner and os.geteuid() != 0 and operator_uid != os.getuid():
        raise Refused("private_directory_owner_mismatch")
    descriptors = []
    try:
        fd = os.open("/", directory_flags())
        descriptors.append((fd, None, None, os.fstat(fd)))
        for component in path.parent.parts[1:]:
            child = os.open(component, directory_flags(), dir_fd=fd)
            descriptors.append((child, fd, component, os.fstat(child)))
            fd = child
        for current, _, _, _ in descriptors:
            info = os.fstat(current)
            if info.st_uid not in (0, operator_uid) or stat.S_IMODE(info.st_mode) & 0o022:
                raise Refused("unprotected_destination_ancestor")
        parent = os.fstat(fd)
        if parent.st_uid != operator_uid or stat.S_IMODE(parent.st_mode) != 0o700:
            raise Refused("private_directory_must_be_owned_0700")
        try:
            os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Refused("destination_already_exists")
        return descriptors, path.name
    except BaseException:
        for current, _, _, _ in reversed(descriptors):
            os.close(current)
        raise


def require_ancestry(descriptors):
    for fd, parent, name, original in descriptors:
        before = os.fstat(fd)
        if (before.st_uid != original.st_uid
                or stat.S_IMODE(before.st_mode) != stat.S_IMODE(original.st_mode)):
            raise Refused("destination_ancestry_changed")
        if parent is None:
            continue
        after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISDIR(after.st_mode)
                or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                or stat.S_IMODE(after.st_mode) & 0o022):
            raise Refused("destination_ancestry_changed")


def require_local_entry(fd, directory_fd):
    opened = os.fstat(fd)
    live = os.stat("returned.img", dir_fd=directory_fd, follow_symlinks=False)
    if (not stat.S_ISREG(live.st_mode) or live.st_nlink != 1
            or stat.S_IMODE(live.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (live.st_dev, live.st_ino)):
        raise Refused("local_image_entry_changed")


def require_raw_device(fd, raw_path):
    opened = os.fstat(fd)
    live = os.stat(raw_path, follow_symlinks=False)
    if (not stat.S_ISCHR(opened.st_mode) or not stat.S_ISCHR(live.st_mode)
            or (opened.st_dev, opened.st_ino, opened.st_rdev)
            != (live.st_dev, live.st_ino, live.st_rdev)):
        raise Refused("raw_device_identity_changed")


def write_all(fd, block):
    remaining = memoryview(block)
    while remaining:
        written = os.write(fd, remaining)
        if written <= 0:
            raise Refused("destination_write_did_not_advance")
        remaining = remaining[written:]


def copy_card(raw_fd, output_fd, size, progress=None):
    count, digest = 0, hashlib.sha256()
    if progress is not None:
        progress("copy", count, size)
    while count < size:
        block = os.read(raw_fd, min(BLOCK_SIZE, size - count))
        if not block:
            raise Refused("card_ended_early")
        # Holes preserve every byte but avoid allocating known zero-filled
        # blocks. The SD is still read in full; hashes include all zero bytes.
        if block.count(0) == len(block):
            os.lseek(output_fd, len(block), os.SEEK_CUR)
        else:
            write_all(output_fd, block)
        digest.update(block)
        count += len(block)
        if progress is not None:
            progress("copy", count, size)
    os.ftruncate(output_fd, size)
    return digest.hexdigest()


def local_readback(fd, size, progress=None):
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size != size:
        raise Refused("local_image_size_mismatch")
    os.lseek(fd, 0, os.SEEK_SET)
    count, digest = 0, hashlib.sha256()
    if progress is not None:
        progress("local_readback", count, size)
    while count < size:
        block = os.read(fd, min(BLOCK_SIZE, size - count))
        if not block:
            raise Refused("local_image_ended_early")
        digest.update(block)
        count += len(block)
        if progress is not None:
            progress("local_readback", count, size)
    after = os.fstat(fd)
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
        raise Refused("local_image_changed")
    return digest.hexdigest()


def receipt(directory_fd, result, owner):
    fd = os.open("acquisition.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(fd, 0o600)
        if owner:
            os.fchown(fd, *owner)
        write_all(fd, (json.dumps(result, sort_keys=True, indent=2) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def acquire_sd(output_dir, expected, *, acquire=False, owner_uid=None, owner_gid=None,
               progress=None):
    result = {"schema_version": 1, "scope": "private-full-sd-acquisition",
              "status": "dry_run", "device": expected["device"],
              "capacity_bytes": expected["capacity_bytes"], "registry_id": expected["registry_id"],
              "private_artifact": True, "raw_opened_readonly": False,
              "copy_complete": False, "local_readback_verified": False,
              "sha256": None, "allocated_bytes": None, "sparse": True,
              "ejected": False, "hardware_qualified": False,
              "receipt_saved": False, "error": None,
              "limits": ["The full copy can contain private keys and unallocated card bytes.",
                         "A stream hash and local readback do not independently reread the SD.",
                         "Unmounting may flush writes previously pending in macOS.",
                         "No runtime, poweroff, enrollment or hardware qualification is established.",
                         "The shared media guard currently requires a writable SD medium."]}
    descriptors, raw_fd, image_fd, directory_fd = [], None, None, None
    owner = None
    try:
        if platform.system() != "Darwin":
            raise Refused("macos_required")
        if acquire and os.geteuid() != 0:
            raise Refused("administrator_authentication_required")
        owner = owner_identity(owner_uid, owner_gid, acquire)
        require_same(media_record(expected["device"]), expected)
        descriptors, name = open_destination_parent(output_dir, owner)
        parent_fd = descriptors[-1][0]
        if os.fstatvfs(parent_fd).f_bavail * os.fstatvfs(parent_fd).f_frsize < expected["capacity_bytes"]:
            raise Refused("insufficient_destination_space")
        raw_device_flags()
        require_ancestry(descriptors)
        require_same(media_record(expected["device"]), expected)
        if not acquire:
            return result
        result["status"] = "acquiring"
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        directory_fd = os.open(name, directory_flags(), dir_fd=parent_fd)
        descriptors.append((directory_fd, parent_fd, name, os.fstat(directory_fd)))
        os.fchmod(directory_fd, 0o700)
        if owner:
            os.fchown(directory_fd, *owner)
        descriptors[-1] = (directory_fd, parent_fd, name, os.fstat(directory_fd))
        image_fd = os.open("returned.img", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                           0o600, dir_fd=directory_fd)
        os.fchmod(image_fd, 0o600)
        if owner:
            os.fchown(image_fd, *owner)
        require_same(media_record(expected["device"]), expected)
        run(["/usr/sbin/diskutil", "unmountDisk", "/dev/" + expected["device"]])
        require_same(media_record(expected["device"]), expected)
        raw_path = "/dev/r" + expected["device"]
        raw_fd = os.open(raw_path, raw_device_flags())
        require_raw_device(raw_fd, raw_path)
        require_same(media_record(expected["device"]), expected)
        require_ancestry(descriptors)
        require_local_entry(image_fd, directory_fd)
        result["raw_opened_readonly"] = True
        progress_options = {"progress": progress} if progress is not None else {}
        stream_hash = copy_card(raw_fd, image_fd, expected["capacity_bytes"], **progress_options)
        os.fsync(image_fd)
        require_raw_device(raw_fd, raw_path)
        require_same(media_record(expected["device"]), expected)
        if local_readback(image_fd, expected["capacity_bytes"], **progress_options) != stream_hash:
            raise Refused("local_readback_hash_mismatch")
        require_raw_device(raw_fd, raw_path)
        require_same(media_record(expected["device"]), expected)
        require_ancestry(descriptors)
        require_local_entry(image_fd, directory_fd)
        result.update(status="complete", copy_complete=True, local_readback_verified=True,
                      sha256=stream_hash, allocated_bytes=os.fstat(image_fd).st_blocks * 512)
    except KeyboardInterrupt:
        result.update(status="failed", copy_complete=False, local_readback_verified=False,
                      sha256=None, error="interrupted")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result.update(status="failed", copy_complete=False, local_readback_verified=False, sha256=None,
                      error=str(error) if isinstance(error, Refused) else type(error).__name__)
    finally:
        if raw_fd is not None:
            os.close(raw_fd)
        if image_fd is not None:
            os.close(image_fd)
        if directory_fd is not None:
            try:
                result["receipt_saved"] = True
                receipt(directory_fd, result, owner)
                os.fsync(directory_fd)
            except (OSError, ValueError):
                result.update(status="failed", copy_complete=False, local_readback_verified=False,
                              sha256=None, receipt_saved=False, error="receipt_save_failed")
        for fd, _, _, _ in reversed(descriptors):
            os.close(fd)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--device", required=True)
    parser.add_argument("--capacity-bytes", type=int, required=True)
    parser.add_argument("--registry-id", type=int, required=True)
    parser.add_argument("--owner-uid", type=int)
    parser.add_argument("--owner-gid", type=int)
    parser.add_argument("--acquire", action="store_true")
    parser.add_argument("--progress", action="store_true",
                        help="Show copy/readback phase and byte progress on stderr only")
    args = parser.parse_args()
    result = acquire_sd(args.output_dir,
                        {"device": args.device, "capacity_bytes": args.capacity_bytes,
                         "registry_id": args.registry_id}, acquire=args.acquire,
                        owner_uid=args.owner_uid, owner_gid=args.owner_gid,
                        progress=StderrProgress() if args.progress else None)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 2 if result["status"] == "failed" else 0


if __name__ == "__main__":
    sys.exit(main())
