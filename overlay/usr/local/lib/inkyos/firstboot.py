#!/usr/bin/env python3
"""Persist the InkyOS system hostname before network services start.

Runtime CLI: Linux root only, no alternate-root option. Tests call
initialize_system with a fixture root and injected entropy/hostname functions.
This code does not manage machine-id, SSH, time or application identities.
"""

import argparse
import fcntl
import itertools
import json
import os
from pathlib import PurePosixPath
import re
import socket
import stat
import sys


class FirstBootError(RuntimeError):
    pass


HOSTNAME = re.compile(r"inky-[0-9a-f]{32}\Z")
_temporary_counter = itertools.count()


def _secure_metadata(info, owner_uid, *, directory=False, private=False):
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(info.st_mode) or info.st_uid != owner_uid:
        raise FirstBootError("Unsafe file type or owner; no identity regenerated.")
    if info.st_mode & 0o022:
        raise FirstBootError("Group/world-writable system path refused.")
    if not directory and info.st_nlink != 1:
        raise FirstBootError("Hard-linked system file refused.")
    if private and stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600):
        raise FirstBootError("Private state permissions must be 0700/0600.")


class SystemFiles:
    def __init__(self, root, owner_uid):
        self.owner_uid = owner_uid
        self.root = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            _secure_metadata(os.fstat(self.root), owner_uid, directory=True)
        except BaseException:
            os.close(self.root)
            raise

    def close(self):
        os.close(self.root)

    def directory(self, path):
        parts = PurePosixPath(path).parts
        if ".." in parts or PurePosixPath(path).is_absolute():
            raise FirstBootError("Only internal relative paths are accepted.")
        fd = os.dup(self.root)
        try:
            for part in parts:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=fd)
                os.close(fd)
                fd = child
                _secure_metadata(os.fstat(fd), self.owner_uid, directory=True)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def read(self, directory, name, *, private=False, limit=1024 * 1024):
        try:
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return None
        _secure_metadata(info, self.owner_uid, private=private)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            _secure_metadata(os.fstat(fd), self.owner_uid, private=private)
            with os.fdopen(fd, "rb", closefd=False) as stream:
                content = stream.read(limit + 1)
            if len(content) > limit:
                raise FirstBootError("System file exceeds inspection limit.")
            try:
                return content.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise FirstBootError("System file is not valid UTF-8.") from exc
        finally:
            os.close(fd)

    def write_atomic(self, directory, name, content, mode, checkpoint):
        """Same-directory exclusive temp, file fsync, replace, directory fsync."""
        temporary = None
        fd = None
        try:
            for _ in range(100):
                temporary = f".{name}.inkyos-{os.getpid()}-{next(_temporary_counter)}"
                try:
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 mode, dir_fd=directory)
                    break
                except FileExistsError:
                    temporary = None
            if fd is None:
                raise FirstBootError("Cannot create an exclusive temporary file.")
            os.fchmod(fd, mode)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(content.encode("utf-8"))
                stream.flush()
            os.fsync(fd)
            checkpoint(f"{name}:temp_fsynced")
            os.close(fd)
            fd = None
            # Targets were preflighted and can only be changed by the owner of
            # the non-writable parent directory. Never dereference the target.
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            temporary = None
            checkpoint(f"{name}:replaced")
            os.fsync(directory)
            checkpoint(f"{name}:directory_fsynced")
        finally:
            if fd is not None:
                os.close(fd)
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass


def kernel_random_bytes(size):
    """Linux getrandom(flags=0) blocks until the kernel CRNG is initialized."""
    result = bytearray()
    while len(result) < size:
        result.extend(os.getrandom(size - len(result), 0))
    return bytes(result)


def _load_state(content):
    try:
        # Reject duplicate keys instead of silently accepting the last value.
        def unique_pairs(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = value
            return result
        state = json.loads(content, object_pairs_hook=unique_pairs)
        if (not isinstance(state, dict) or set(state) != {"version", "hostname"}
                or type(state["version"]) is not int or state["version"] != 1
                or not isinstance(state["hostname"], str)
                or not HOSTNAME.fullmatch(state["hostname"])):
            raise ValueError("invalid schema")
        return state
    except (ValueError, TypeError) as exc:
        raise FirstBootError("Existing system.json is invalid; identity regeneration refused.") from exc


def _hosts_with_hostname(content, hostname):
    lines = []
    if content is None:
        content = "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n"
    for line in content.splitlines():
        fields = line.split("#", 1)[0].split()
        if fields and fields[0] == "127.0.1.1":
            continue
        lines.append(line)
    while lines and not lines[-1]:
        lines.pop()
    lines.append(f"127.0.1.1\t{hostname}\t# InkyOS system hostname")
    return "\n".join(lines) + "\n"


def initialize_system(root, *, entropy, set_runtime_hostname, owner_uid=0, checkpoint=None):
    """Fixture-capable core. Runtime entry point supplies only root=/.

    A checkpoint callback is for deterministic crash simulation in tests. A
    failure before state commit may discard an unused identity; once state is
    present it is authoritative and is never regenerated, even if invalid.
    """
    checkpoint = checkpoint or (lambda _stage: None)
    files = SystemFiles(root, owner_uid)
    etc = parent = state_dir = lock = None
    try:
        etc = files.directory("etc")
        parent = files.directory("var/lib")
        # Preflight system targets before committing a new identity.
        old_hostname = files.read(etc, "hostname", limit=4096)
        old_hosts = files.read(etc, "hosts")
        try:
            os.mkdir("inkyos", 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        state_dir = files.directory("var/lib/inkyos")
        _secure_metadata(os.fstat(state_dir), owner_uid, directory=True, private=True)
        os.fsync(parent)
        lock = os.open(".firstboot.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                       0o600, dir_fd=state_dir)
        _secure_metadata(os.fstat(lock), owner_uid, private=True)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise FirstBootError("Another system first-boot process owns the state lock.") from exc
        content = files.read(state_dir, "system.json", private=True, limit=4096)
        created = content is None
        if created:
            random = entropy(16)
            if not isinstance(random, bytes) or len(random) != 16:
                raise FirstBootError("Entropy provider did not return 16 bytes.")
            state = {"version": 1, "hostname": "inky-" + random.hex()}
            serialized = json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n"
            files.write_atomic(state_dir, "system.json", serialized, 0o600, checkpoint)
        else:
            state = _load_state(content)
        hostname = state["hostname"]
        new_hostname = hostname + "\n"
        new_hosts = _hosts_with_hostname(old_hosts, hostname)
        if old_hostname != new_hostname:
            files.write_atomic(etc, "hostname", new_hostname, 0o644, checkpoint)
        if old_hosts != new_hosts:
            files.write_atomic(etc, "hosts", new_hosts, 0o644, checkpoint)
        set_runtime_hostname(hostname)
        checkpoint("runtime_hostname:applied")
        return {"hostname": hostname, "created": created}
    except OSError as exc:
        # Do not echo file content, entropy or arbitrary filesystem paths.
        raise FirstBootError(f"System first boot failed ({type(exc).__name__}); no replacement identity issued.") from exc
    finally:
        for fd in (lock, state_dir, parent, etc):
            if fd is not None:
                os.close(fd)
        files.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        parser.error("Runtime command requires Linux root; tests must use the injected fixture API.")
    try:
        result = initialize_system("/", entropy=kernel_random_bytes,
                                   set_runtime_hostname=lambda value: socket.sethostname(value.encode("ascii")))
    except FirstBootError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print("InkyOS system hostname initialized." if result["created"] else "InkyOS system hostname reconciled.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
