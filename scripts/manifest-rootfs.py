#!/usr/bin/env python3
"""Schema 2 metadata manifest of unbooted, generic image filesystems only.

Never use on personal/runtime filesystems. File bytes and xattr values are
represented only by SHA-256 and byte count. Linux ACLs are covered by their
system.posix_acl_* xattrs, not by a translation from another platform's ACLs.

xattrs.status='inspected' means the API successfully listed attributes; an
empty entries mapping is not a claim that the filesystem can store xattrs.
ENOTSUP/EOPNOTSUPP (including when returned by FAT) is explicitly 'unsupported'
with reason='filesystem'. Non-Linux/missing APIs use reason='platform'. Other
errors, including EACCES/EPERM, abort rather than silently claiming absence.

Every tree includes its root as '.'. Hardlink groups contain sorted relative
member paths; incomplete groups fail. No inode number is serialized. Timestamps,
allocation, filesystem UUIDs and journaling are excluded: equality of this
manifest still does not establish byte-for-byte disk reproducibility.

Inputs must be private, read-only build mounts. Linux uses directory fds and
O_NOFOLLOW; /proc/self/fd accesses only descriptors owned by this process.
Python 3.9+ is supported. Non-Linux fixture tests deliberately omit Linux xattrs.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


SCHEMA_VERSION = 2
SCOPE = "content-and-metadata-without-timestamps"


class ManifestError(RuntimeError):
    pass


def _signature(info):
    # Internal race detection only; these volatile fields are never exported.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _check_stable(before, after):
    if _signature(before) != _signature(after):
        raise ManifestError("An input changed while being inventoried")


def _open_root(path):
    """Open every directory component without following filesystem symlinks."""
    path = Path(path).absolute()
    if ".." in path.parts:
        raise ManifestError("Parent traversal in an input root is refused")
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _xattrs(target, *, nofollow=False):
    if (not sys.platform.startswith("linux") or not hasattr(os, "listxattr")
            or not hasattr(os, "getxattr")):
        return {"status": "unsupported", "reason": "platform"}
    kwargs = {"follow_symlinks": False} if nofollow else {}
    try:
        names = os.listxattr(target, **kwargs)
        entries = {}
        for name in sorted(names):
            value = os.getxattr(target, name, **kwargs)
            entries[name] = {"size_bytes": len(value),
                             "sha256": hashlib.sha256(value).hexdigest()}
        return {"status": "inspected", "entries": entries}
    except OSError as exc:
        if exc.errno in {errno.ENOTSUP, errno.EOPNOTSUPP}:
            return {"status": "unsupported", "reason": "filesystem"}
        raise ManifestError(f"Extended attribute inspection failed ({type(exc).__name__})") from exc


def _path_xattrs(parent_fd, name):
    # Linux llistxattr/lgetxattr need a path for symlinks and special files.
    # The parent is anchored to our fd and the final component is not followed.
    return _xattrs(f"/proc/self/fd/{parent_fd}/{name}", nofollow=True)


def _regular_file(parent_fd, name, before):
    fd = path_fd = None
    try:
        if sys.platform.startswith("linux") and hasattr(os, "O_PATH"):
            # Pin the selected inode first, without opening a device or FIFO
            # if the directory entry is concurrently replaced.
            path_fd = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=parent_fd)
            _check_stable(before, os.fstat(path_fd))
            if not stat.S_ISREG(os.fstat(path_fd).st_mode):
                raise ManifestError("Expected a regular file")
            fd = os.open(f"/proc/self/fd/{path_fd}", os.O_RDONLY | os.O_NONBLOCK)
        else:
            # Fixture fallback. O_NONBLOCK prevents accidental FIFO blocking.
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        current = os.fstat(fd)
        _check_stable(before, current)
        if not stat.S_ISREG(current.st_mode):
            raise ManifestError("Expected a regular file")
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(fd, "rb", closefd=False) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                size += len(chunk)
                digest.update(chunk)
        attributes = _xattrs(fd)
        _check_stable(before, os.fstat(fd))
        if size != before.st_size:
            raise ManifestError("File size changed during inspection")
        return {"size_bytes": size, "sha256": digest.hexdigest(), "xattrs": attributes}
    finally:
        if fd is not None:
            os.close(fd)
        if path_fd is not None:
            os.close(path_fd)


def inventory(root):
    """Return deterministic schema-2 records, with no absolute input paths."""
    records = {}
    links = {}

    def record_metadata(info):
        return {"mode": format(stat.S_IMODE(info.st_mode), "04o"),
                "uid": info.st_uid, "gid": info.st_gid}

    def visit(directory, relative, before):
        _check_stable(before, os.fstat(directory))
        record = record_metadata(before)
        record.update(type="directory", xattrs=_xattrs(directory))
        records[relative] = record
        with os.scandir(directory) as iterator:
            names = sorted(entry.name for entry in iterator)
        for name in names:
            path = name if relative == "." else relative + "/" + name
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            record = record_metadata(info)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=directory)
                try:
                    visit(child, path, info)
                finally:
                    os.close(child)
                continue
            if stat.S_ISREG(info.st_mode):
                record.update(type="file", **_regular_file(directory, name, info))
            elif stat.S_ISLNK(info.st_mode):
                record.update(type="symlink", target=os.readlink(name, dir_fd=directory),
                              xattrs=_path_xattrs(directory, name))
            elif stat.S_ISFIFO(info.st_mode):
                record.update(type="fifo", xattrs=_path_xattrs(directory, name))
            elif stat.S_ISSOCK(info.st_mode):
                record.update(type="socket", xattrs=_path_xattrs(directory, name))
            elif stat.S_ISCHR(info.st_mode) or stat.S_ISBLK(info.st_mode):
                record.update(type="char" if stat.S_ISCHR(info.st_mode) else "block",
                              device={"major": os.major(info.st_rdev), "minor": os.minor(info.st_rdev)},
                              xattrs=_path_xattrs(directory, name))
            else:
                raise ManifestError("Unrecognized filesystem entry type")
            _check_stable(info, os.stat(name, dir_fd=directory, follow_symlinks=False))
            records[path] = record
            links.setdefault((info.st_dev, info.st_ino), []).append((path, info.st_nlink))
        _check_stable(before, os.fstat(directory))

    root_fd = _open_root(root)
    try:
        visit(root_fd, ".", os.fstat(root_fd))
    finally:
        os.close(root_fd)
    for members in links.values():
        paths = sorted(path for path, _count in members)
        if any(count != len(paths) for _path, count in members):
            raise ManifestError("Hardlink group is incomplete or changed across the inspected root boundary")
        if len(paths) > 1:
            for path in paths:
                records[path]["hardlinks"] = paths
    return records


def build_manifest(rootfs, bootfs):
    return {"schema_version": SCHEMA_VERSION, "scope": SCOPE,
            "rootfs": inventory(rootfs), "bootfs": inventory(bootfs)}


def _check_output(output, roots):
    if os.path.lexists(output):
        raise ManifestError("Output must not already exist")
    resolved_output = Path(output).resolve()
    for root in roots:
        resolved_root = Path(root).resolve()
        if os.path.commonpath((resolved_output, resolved_root)) == str(resolved_root):
            raise ManifestError("Output must be outside every inspected filesystem")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--bootfs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        _check_output(args.output, (args.rootfs, args.bootfs))
        result = build_manifest(args.rootfs, args.bootfs)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(result, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
    except (ManifestError, OSError) as exc:
        print(f"Manifest refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
