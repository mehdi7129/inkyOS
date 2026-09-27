#!/usr/bin/env python3
"""Bounded, inert inspection of pinned application archives; never extract/install.

The adjacent verify-application module is trusted repository tooling. No source,
wheel, build backend or other code from the inspected bundle is imported.
See docs/ARCHIVE-CONTRACT.md for the deliberately narrow archive contract.
"""

import argparse
from collections import namedtuple
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tarfile
import zlib


_spec = importlib.util.spec_from_file_location(
    "_inkyos_archive_input_verifier", Path(__file__).with_name("verify-application.py"))
verifier = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verifier)

Limits = namedtuple("Limits", "members member_bytes total_bytes pax_bytes pax_total_bytes "
                    "tar_overhead_bytes zip_directory_bytes path_bytes depth",
                    defaults=(20000, 256 * 1024**2, 2 * 1024**3, 64 * 1024,
                              8 * 1024**2, 64 * 1024**2, 16 * 1024**2, 1024, 32))
DEFAULT_LIMITS = Limits()
CHUNK = 64 * 1024
APPLICATION_ROOT_FILES = frozenset({"install.sh", "README.md", "LICENSE", "CHANGELOG.md",
                                    "VERSION"})
APPLICATION_REQUIRED_FILES = frozenset({"server/pyproject.toml", "client/dist/index.html",
                                        "VERSION", "server/SOURCE_COMMIT"})
PAX_KEYS = frozenset({"path", "size", "mtime", "atime", "ctime", "uid", "gid",
                      "uname", "gname", "comment"})


class ArchiveError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ArchiveError(message)


def safe_name(name, directory, limits):
    require(isinstance(name, str) and name, "Empty archive path")
    require(not name.startswith("/") and "\\" not in name and ":" not in name,
            "Absolute, drive or backslash archive path")
    require(all(ord(c) >= 32 and ord(c) != 127 for c in name), "Control character in archive path")
    try:
        encoded = name.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise ArchiveError("Invalid UTF-8 archive path") from exc
    require(len(encoded) <= limits.path_bytes, "Archive path exceeds limit")
    if directory and name.endswith("/"):
        name = name[:-1]
    parts = name.split("/")
    require(len(parts) <= limits.depth and all(part not in {"", ".", ".."} for part in parts),
            "Noncanonical or traversing archive path")
    require(all(len(part.encode("utf-8")) <= 255 for part in parts), "Archive path component too long")
    return name


class Paths:
    def __init__(self):
        self.explicit = {}
        self.nodes = {}

    def add(self, path, kind):
        require(path not in self.explicit, "Duplicate archive path")
        parts = path.split("/")
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            require(self.nodes.get(parent, "directory") == "directory", "File/directory path collision")
            self.nodes[parent] = "directory"
        require(path not in self.nodes or self.nodes[path] == kind, "File/directory path collision")
        self.nodes[path] = kind
        self.explicit[path] = kind


def application_path(path, kind):
    if path in APPLICATION_ROOT_FILES:
        require(kind == "file", "Application root metadata must be a regular file")
        return
    if path in {"server", "shared", "scripts", "client", "client/dist"}:
        require(kind == "directory", "Application source roots must be directories")
        return
    require(path.startswith(("server/", "shared/", "scripts/", "client/dist/")),
            "Entry outside the flat application layout")


def wheelhouse_path(path, kind):
    if path == "licenses":
        require(kind == "directory", "Licenses root must be a directory")
    elif path.startswith("licenses/"):
        return
    else:
        require(kind == "file" and "/" not in path and
                (path == "provenance.json" or path.endswith(".whl")),
                "Entry outside the flat wheelhouse layout")


class GzipReader:
    """One gzip member, bounded output, complete trailer/CRC, no trailing bytes."""
    def __init__(self, stream, limit):
        self.stream = stream
        self.decoder = zlib.decompressobj(zlib.MAX_WBITS | 16)
        self.pending = b""
        self.finished = False
        self.total = 0
        self.limit = limit

    def read(self, amount):
        require(amount > 0, "Invalid gzip read size")
        chunks = []
        remaining = amount
        while remaining and not self.finished:
            if not self.pending:
                self.pending = self.stream.read(CHUNK)
                require(bool(self.pending), "Truncated gzip stream")
            try:
                output = self.decoder.decompress(self.pending, min(remaining, self.limit - self.total + 1))
            except zlib.error as exc:
                raise ArchiveError("Invalid gzip stream or CRC") from exc
            self.pending = self.decoder.unconsumed_tail
            self.total += len(output)
            require(self.total <= self.limit, "Expanded tar stream exceeds limit")
            chunks.append(output)
            remaining -= len(output)
            if self.decoder.eof:
                require(not self.decoder.unused_data and not self.pending and not self.stream.read(1),
                        "Concatenated gzip members or trailing compressed bytes")
                self.finished = True
        return b"".join(chunks)

    def exact(self, size):
        if size == 0:
            return b""
        data = self.read(size)
        require(len(data) == size, "Truncated tar stream")
        return data


def pax_fields(data):
    fields = {}
    offset = 0
    while offset < len(data):
        space = data.find(b" ", offset)
        require(space > offset and space - offset <= 10, "Malformed PAX record length")
        raw_length = data[offset:space]
        require(re.fullmatch(b"[1-9][0-9]*", raw_length), "Malformed PAX record length")
        length = int(raw_length)
        end = offset + length
        require(end <= len(data) and end > space + 2 and data[end - 1:end] == b"\n", "Malformed PAX record")
        key, separator, value = data[space + 1:end - 1].partition(b"=")
        require(separator, "Malformed PAX key")
        try:
            key, value = key.decode("ascii"), value.decode("utf-8")
        except UnicodeError as exc:
            raise ArchiveError("Invalid PAX encoding") from exc
        require(key in PAX_KEYS and key not in fields and "\x00" not in value,
                "Unsupported, duplicate or invalid PAX attribute")
        fields[key] = value
        offset = end
    return fields


def consume_tar_data(reader, size, capture=False):
    captured = []
    remaining = size
    while remaining:
        block = reader.exact(min(CHUNK, remaining))
        if capture:
            captured.append(block)
        remaining -= len(block)
    padding = (-size) % 512
    require(not any(reader.exact(padding)), "Nonzero tar member padding")
    return b"".join(captured)


def scan_tar(stream, source_commit, limits=DEFAULT_LIMITS):
    reader = GzipReader(stream, limits.total_bytes + limits.tar_overhead_bytes)
    paths = Paths()
    total = members = headers = pax_total = 0
    pending = None
    global_seen = False
    source_matches = False
    while True:
        header = reader.exact(512)
        if header == bytes(512):
            require(reader.exact(512) == bytes(512), "Tar must end with two zero blocks")
            require(pending is None, "Dangling PAX header")
            while True:
                tail = reader.read(CHUNK)
                require(not any(tail), "Nonzero bytes after tar terminator")
                if not tail:
                    break
            require(reader.total % 512 == 0, "Unaligned tar padding")
            break
        headers += 1
        require(headers <= 2 * limits.members + 1, "Too many tar headers")
        try:
            info = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
        except (tarfile.HeaderError, UnicodeError, ValueError) as exc:
            raise ArchiveError("Malformed tar header") from exc
        require(info.size >= 0 and not info.mode & 0o6000, "Negative size or privileged tar mode")
        if info.type in {tarfile.XHDTYPE, tarfile.XGLTYPE}:
            require(pending is None and info.size <= limits.pax_bytes, "Oversized or stacked PAX header")
            pax_total += info.size
            require(pax_total <= limits.pax_total_bytes, "PAX metadata exceeds limit")
            # This bounded header name is metadata, never a filesystem entry.
            # Standard writers use '././@PaxHeader'; only the effective payload
            # path below is subject to the filesystem layout/path policy.
            fields = pax_fields(consume_tar_data(reader, info.size, capture=True))
            if info.type == tarfile.XGLTYPE:
                require(not global_seen and members == 0 and set(fields) <= {"comment"},
                        "Unsupported global PAX header")
                global_seen = True
            else:
                pending = fields
            continue
        require(info.type in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE},
                "Tar links, sparse files and special/extension entries are forbidden")
        require(not info.linkname, "Unexpected tar link target")
        kind = "directory" if info.type == tarfile.DIRTYPE else "file"
        fields = pending or {}
        pending = None
        name = fields.get("path", info.name)
        size = info.size
        if "size" in fields:
            require(re.fullmatch(r"[0-9]{1,12}", fields["size"]), "Invalid PAX file size")
            size = int(fields["size"])
        path = safe_name(name, kind == "directory", limits)
        application_path(path, kind)
        paths.add(path, kind)
        members += 1
        require(members <= limits.members and size <= limits.member_bytes, "Tar member limit exceeded")
        require(kind != "directory" or size == 0, "Directory with data")
        total += size
        require(total <= limits.total_bytes, "Expanded tar file bytes exceed limit")
        if path == "server/SOURCE_COMMIT":
            require(size in {40, 41}, "SOURCE_COMMIT must contain the complete source commit")
            value = consume_tar_data(reader, size, capture=True)
            require(value in {source_commit.encode("ascii"), source_commit.encode("ascii") + b"\n"},
                    "SOURCE_COMMIT differs from the manifest declaration")
            source_matches = True
        else:
            consume_tar_data(reader, size)
    files = {path for path, kind in paths.explicit.items() if kind == "file"}
    require(APPLICATION_REQUIRED_FILES <= files and source_matches, "Required application files missing")
    require(any(path.startswith("shared/") for path in files) and
            any(path.startswith("scripts/") for path in files), "Shared/scripts payload missing")
    return {"format": "tar.gz", "layout": "flat-application-v1", "members": members,
            "files": len(files), "expanded_file_bytes": total, "tar_stream_bytes": reader.total,
            "required_paths_present": True, "source_commit_declaration_matches": True,
            "gzip_members": 1, "gzip_crc_verified": True}


def read_at(stream, offset, size):
    require(offset >= 0 and size >= 0, "Invalid ZIP byte range")
    stream.seek(offset)
    data = stream.read(size)
    require(len(data) == size, "Truncated ZIP structure")
    return data


def zip_extras(data):
    offset = 0
    seen = set()
    while offset < len(data):
        require(len(data) - offset >= 4, "Malformed ZIP extra field")
        tag, length = struct.unpack_from("<HH", data, offset)
        offset += 4
        require(tag in {0x5455, 0x7875} and tag not in seen, "Unsupported or duplicate ZIP extra field")
        require(offset + length <= len(data), "Truncated ZIP extra field")
        seen.add(tag)
        offset += length


def zip_payload(stream, offset, compressed, expected, method, crc):
    stream.seek(offset)
    total = actual_crc = 0
    if method == 0:
        require(compressed == expected, "Stored ZIP size mismatch")
        remaining = compressed
        while remaining:
            data = stream.read(min(CHUNK, remaining))
            require(data, "Truncated stored ZIP payload")
            remaining -= len(data)
            total += len(data)
            actual_crc = zlib.crc32(data, actual_crc)
    else:
        decoder = zlib.decompressobj(-zlib.MAX_WBITS)
        pending = b""
        remaining = compressed
        while remaining or pending:
            if not pending:
                pending = stream.read(min(CHUNK, remaining))
                require(pending, "Truncated compressed ZIP payload")
                remaining -= len(pending)
            try:
                data = decoder.decompress(pending, min(CHUNK, expected - total + 1))
            except zlib.error as exc:
                raise ArchiveError("Invalid ZIP deflate stream") from exc
            pending = decoder.unconsumed_tail
            total += len(data)
            require(total <= expected, "ZIP expands beyond its declared size")
            actual_crc = zlib.crc32(data, actual_crc)
            if decoder.eof:
                require(not decoder.unused_data and not pending and remaining == 0,
                        "Bytes after ZIP deflate stream")
        require(decoder.eof, "Truncated ZIP deflate stream")
    require(total == expected and actual_crc & 0xffffffff == crc, "ZIP expanded size or CRC mismatch")


def scan_zip(stream, limits=DEFAULT_LIMITS):
    stream.seek(0, os.SEEK_END)
    length = stream.tell()
    require(length >= 22, "Truncated ZIP")
    tail_offset = max(0, length - 65557)
    tail = read_at(stream, tail_offset, length - tail_offset)
    found = tail.rfind(b"PK\x05\x06")
    require(found >= 0 and found + 22 <= len(tail), "ZIP end record missing")
    end = tail_offset + found
    _, disk, central_disk, disk_count, count, directory_size, directory_offset, comment_size = struct.unpack_from("<4s4H2IH", tail, found)
    require(disk == central_disk == 0 and disk_count == count and count != 0xffff,
            "Multipart/ZIP64 archives are unsupported")
    require(directory_size != 0xffffffff and directory_offset != 0xffffffff and
            end + 22 + comment_size == length, "ZIP64 or trailing ZIP bytes")
    require(count <= limits.members and directory_size <= limits.zip_directory_bytes,
            "ZIP central directory exceeds limit")
    require(directory_offset + directory_size == end, "Unexpected data around ZIP central directory")
    directory = read_at(stream, directory_offset, directory_size)
    records = []
    paths = Paths()
    cursor = total = 0
    while cursor < len(directory):
        require(len(directory) - cursor >= 46 and len(records) < limits.members, "Malformed/oversized ZIP directory")
        header = struct.unpack_from("<4s6H3I5H2I", directory, cursor)
        (signature, made_by, needed, flags, method, _time, _date, crc, compressed, size,
         name_size, extra_size, member_comment, member_disk, _internal, external, local) = header
        require(signature == b"PK\x01\x02" and member_disk == 0 and needed <= 20,
                "Unsupported ZIP directory record")
        require(flags & ~0x080e == 0 and method in {0, 8}, "Encrypted or unsupported ZIP member")
        stop = cursor + 46 + name_size + extra_size + member_comment
        require(stop <= len(directory), "Truncated ZIP directory member")
        raw_name = directory[cursor + 46:cursor + 46 + name_size]
        try:
            name = raw_name.decode("utf-8" if flags & 0x800 else "cp437")
        except UnicodeError as exc:
            raise ArchiveError("Invalid ZIP name encoding") from exc
        zip_extras(directory[cursor + 46 + name_size:cursor + 46 + name_size + extra_size])
        mode = external >> 16
        require(not mode & 0o6000, "Privileged ZIP mode")
        file_type = stat.S_IFMT(mode)
        is_directory = name.endswith("/")
        require(file_type in ({0, stat.S_IFDIR} if is_directory else {0, stat.S_IFREG}),
                "ZIP links, specials or inconsistent file types")
        require(not external & 0x10 or is_directory, "Inconsistent ZIP DOS directory flag")
        kind = "directory" if is_directory else "file"
        path = safe_name(name, is_directory, limits)
        wheelhouse_path(path, kind)
        paths.add(path, kind)
        require(size <= limits.member_bytes and (kind != "directory" or size == 0), "ZIP member size limit")
        total += size
        require(total <= limits.total_bytes, "Expanded ZIP bytes exceed limit")
        records.append({"name": raw_name, "local": local, "flags": flags, "method": method,
                        "crc": crc, "compressed": compressed, "size": size})
        cursor = stop
    require(len(records) == count, "ZIP directory entry count mismatch")
    ordered = sorted(records, key=lambda record: record["local"])
    require(ordered and ordered[0]["local"] == 0, "ZIP must not have a wrapper/prefix")
    for index, record in enumerate(ordered):
        offset = record["local"]
        boundary = ordered[index + 1]["local"] if index + 1 < len(ordered) else directory_offset
        require(0 <= offset < boundary <= directory_offset, "Overlapping ZIP members")
        local_header = struct.unpack("<4s5H3I2H", read_at(stream, offset, 30))
        sig, needed, flags, method, _time, _date, crc, compressed, size, name_size, extra_size = local_header
        require(sig == b"PK\x03\x04" and needed <= 20 and
                flags == record["flags"] and method == record["method"], "ZIP local/central header mismatch")
        payload = offset + 30 + name_size + extra_size
        require(payload <= boundary, "ZIP local header overlaps another member")
        require(read_at(stream, offset + 30, name_size) == record["name"], "ZIP filename disagreement")
        zip_extras(read_at(stream, offset + 30 + name_size, extra_size))
        end_payload = payload + record["compressed"]
        require(end_payload <= boundary, "ZIP compressed payload overlaps another member")
        if flags & 8:
            descriptor_size = boundary - end_payload
            require(descriptor_size in {12, 16}, "Invalid ZIP data descriptor length")
            descriptor = read_at(stream, end_payload, descriptor_size)
            if len(descriptor) == 16:
                require(descriptor[:4] == b"PK\x07\x08", "Invalid ZIP data descriptor signature")
                descriptor = descriptor[4:]
            require(struct.unpack("<III", descriptor) == (record["crc"], record["compressed"], record["size"]),
                    "ZIP data descriptor mismatch")
            require(crc in {0, record["crc"]} and compressed in {0, record["compressed"]}
                    and size in {0, record["size"]}, "Invalid deferred ZIP sizes")
        else:
            require(end_payload == boundary and (crc, compressed, size) ==
                    (record["crc"], record["compressed"], record["size"]), "ZIP local sizes or byte ranges disagree")
        zip_payload(stream, payload, record["compressed"], record["size"], method, record["crc"])
    files = {path for path, kind in paths.explicit.items() if kind == "file"}
    wheels = [path for path in files if "/" not in path and path.endswith(".whl")]
    require(wheels and {"provenance.json", "licenses/index.json"} <= files and
            any(path.startswith("licenses/") and path != "licenses/index.json" for path in files),
            "Wheelhouse wheel/provenance/license files missing")
    return {"format": "zip", "layout": "flat-wheelhouse-v1", "members": count,
            "files": len(files), "wheel_files": len(wheels), "expanded_file_bytes": total,
            "zip_crc_verified": True, "wheel_contents_inspected": False,
            "provenance_content_interpreted": False}


def file_signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)


def hash_open_file(stream, asset):
    stream.seek(0)
    digest = hashlib.sha256()
    total = 0
    while True:
        block = stream.read(CHUNK)
        if not block:
            break
        total += len(block)
        require(total <= asset["size_bytes"], "Asset changed or exceeded size during rehash")
        digest.update(block)
    require(total == asset["size_bytes"] and digest.hexdigest() == asset["sha256"], "Archive rehash mismatch")
    stream.seek(0)


def inspect_application(manifest, expected_hash, assets_directory, limits=DEFAULT_LIMITS):
    checked = verifier.verify(manifest, expected_hash, assets_directory)
    directory = os.open(assets_directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    reports = {}
    try:
        for asset in checked["assets"]:
            if asset["role"] == "python_lock":
                continue
            fd = os.open(asset["filename"], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
            with os.fdopen(fd, "rb") as stream:
                before = os.fstat(stream.fileno())
                require(stat.S_ISREG(before.st_mode) and before.st_size == asset["size_bytes"], "Regular archive of pinned size required")
                hash_open_file(stream, asset)
                require(file_signature(before) == file_signature(os.fstat(stream.fileno())), "Archive changed during initial rehash")
                report = (scan_tar(stream, checked["source_commit"], limits)
                          if asset["role"] == "application" else scan_zip(stream, limits))
                require(file_signature(before) == file_signature(os.fstat(stream.fileno())), "Archive changed during parsing")
                hash_open_file(stream, asset)
                require(file_signature(before) == file_signature(os.fstat(stream.fileno())) ==
                        file_signature(os.stat(asset["filename"], dir_fd=directory, follow_symlinks=False)),
                        "Archive changed or was replaced during inspection")
                reports[asset["role"]] = {**report, "sha256": asset["sha256"], "compressed_size_bytes": asset["size_bytes"]}
    finally:
        os.close(directory)
    return {"schema_version": 1, "scope": "pinned-application-archive-structure", "passed": True,
            "manifest_sha256": expected_hash, "source_commit": checked["source_commit"],
            "application_version": checked["application_version"], "archives": reports,
            "limits": limits._asdict(), "integration_enabled": False, "qualification_granted": False,
            "target_code_executed": False, "files_extracted": 0,
            "limitations": ["Archive structure and pinned bytes only; SOURCE_COMMIT remains a producer declaration.",
                            "Wheel archives are opaque: no tag, metadata, dependency closure or RECORD checks.",
                            "Provenance, licenses and VERSION contents are not interpreted or qualified.",
                            "Python lock syntax, offline installation and runtime behavior are not tested.",
                            "No semantic source/UI check, exhaustive secret scan or external qualification evidence check."]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--assets-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        require(not os.path.lexists(args.output), "Output already exists")
        require(not args.output.resolve().is_relative_to(args.assets_dir.resolve()), "Output must be outside asset bundle")
        report = inspect_application(args.manifest, args.sha256, args.assets_dir)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except (OSError, ValueError, TypeError, KeyError, struct.error) as exc:
        print(f"Archive inspection refused ({type(exc).__name__}); no payload installed.", file=sys.stderr)
        return 1
    print("Pinned archive structures inspected; integration remains disabled.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
