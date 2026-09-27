#!/usr/bin/env python3
"""Compare two prototype build manifests, without opening images or target files.

Exit 0 means identical recipe inputs and recorded filesystem content. Image
SHA-256 equality is reported separately; timestamps and filesystem allocation
are outside the filesystem manifest's scope. No path is excluded.
"""

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


MAX_MANIFEST_BYTES = 64 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MODE = re.compile(r"[0-7]{4}\Z")


class ComparisonError(ValueError):
    pass


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ComparisonError("Duplicate JSON key in a manifest")
        value[key] = item
    return value


def _invalid_constant(_value):
    raise ComparisonError("Non-finite number in a manifest")


def read_manifest(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_MANIFEST_BYTES:
            raise ComparisonError("Manifest must be a regular file of at most 64 MiB")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            raw = source.read(MAX_MANIFEST_BYTES + 1)
        if len(raw) > MAX_MANIFEST_BYTES:
            raise ComparisonError("Manifest exceeds 64 MiB")
        return json.loads(raw, object_pairs_hook=_unique_object,
                          parse_constant=_invalid_constant)
    finally:
        os.close(descriptor)


def _hash(value):
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def _integer(value):
    return type(value) is int and value >= 0


def _relative_path(value):
    if not isinstance(value, str) or not value or "\x00" in value:
        return False
    path = PurePosixPath(value)
    return (not path.is_absolute() and ".." not in path.parts
            and value != "." and str(path) == value)


def validate_build(value):
    if (not isinstance(value, dict) or type(value.get("schema_version")) is not int
            or value["schema_version"] != 1 or value.get("kind") != "system-prototype"
            or "application" not in value or value["application"] is not None):
        raise ComparisonError("Expected a schema 1 system-prototype with application=null")
    recipe = value.get("recipe")
    if (not isinstance(recipe, dict) or type(recipe.get("schema_version")) is not int
            or recipe["schema_version"] != 1
            or not isinstance(recipe.get("source_commit"), str)
            or re.fullmatch(r"[0-9a-f]{40}", recipe["source_commit"]) is None
            or type(recipe.get("worktree_dirty")) is not bool
            or not isinstance(recipe.get("files"), dict)):
        raise ComparisonError("Recipe must include schema, source_commit, worktree_dirty and files")
    if any(not _relative_path(path) or not _hash(digest)
           for path, digest in recipe["files"].items()):
        raise ComparisonError("Invalid recipe path or SHA-256")
    image = value.get("image")
    if not isinstance(image, dict) or not _hash(image.get("sha256")):
        raise ComparisonError("Image SHA-256 is missing or invalid")
    return value


def validate_filesystem(value):
    if (not isinstance(value, dict) or type(value.get("schema_version")) is not int
            or value["schema_version"] != 1
            or value.get("scope") != "content-without-timestamps"
            or set(value) != {"schema_version", "scope", "rootfs", "bootfs"}):
        raise ComparisonError("Expected the complete schema 1 content-without-timestamps manifest")
    for section in ("rootfs", "bootfs"):
        entries = value[section]
        if not isinstance(entries, dict):
            raise ComparisonError("Filesystem entries must be objects")
        for path, record in entries.items():
            if (not _relative_path(path) or not isinstance(record, dict)
                    or not isinstance(record.get("mode"), str)
                    or MODE.fullmatch(record["mode"]) is None
                    or not _integer(record.get("uid")) or not _integer(record.get("gid"))):
                raise ComparisonError("Invalid filesystem path, mode or owner record")
            kind = record.get("type")
            if kind == "file":
                valid = _integer(record.get("size_bytes")) and _hash(record.get("sha256"))
            elif kind == "symlink":
                valid = isinstance(record.get("target"), str) and bool(record["target"])
            elif kind == "directory":
                valid = True
            elif kind == "special":
                valid = _integer(record.get("device"))
            else:
                valid = False
            if not valid:
                raise ComparisonError("Incomplete or unknown filesystem record type")
    return value


def _canonical(value):
    # Compare every recorded field, preserving JSON distinctions such as true/1.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def changes(left, right):
    """Return names only: never include hashes, symlink targets or file content."""
    left_names, right_names = set(left), set(right)
    return {
        "added": sorted(right_names - left_names),
        "removed": sorted(left_names - right_names),
        "modified": sorted(name for name in left_names & right_names
                           if _canonical(left[name]) != _canonical(right[name])),
    }


def _unchanged(difference):
    return not any(difference.values())


def compare_builds(left_directory, right_directory):
    builds = []
    filesystems = []
    for directory in (Path(left_directory), Path(right_directory)):
        builds.append(validate_build(read_manifest(directory / "manifest.json")))
        filesystems.append(validate_filesystem(read_manifest(directory / "filesystem-manifest.json")))
    recipes = [build["recipe"] for build in builds]
    metadata = [{key: value for key, value in recipe.items() if key != "files"}
                for recipe in recipes]
    recipe_changes = {
        "metadata": changes(*metadata),
        "files": changes(*(recipe["files"] for recipe in recipes)),
    }
    filesystem_changes = {
        section: changes(*(filesystem[section] for filesystem in filesystems))
        for section in ("rootfs", "bootfs")
    }
    inputs_equal = all(_unchanged(diff) for diff in recipe_changes.values())
    content_equal = all(_unchanged(diff) for diff in filesystem_changes.values())
    return {
        "schema_version": 1,
        "scope": "recorded-build-inputs-and-content-without-timestamps",
        "direction": "left-to-right",
        "inputs_equal": inputs_equal,
        "content_equal": content_equal,
        "image_byte_identical": builds[0]["image"]["sha256"] == builds[1]["image"]["sha256"],
        "success": inputs_equal and content_equal,
        "path_exclusions": [],
        "recipe_differences": recipe_changes,
        "filesystem_differences": filesystem_changes,
        "limits": [
            "Comparison uses recorded manifests and image SHA-256; image files are not reread.",
            "Timestamps and filesystem allocation/layout are not represented by the content manifest.",
            "A differing image hash is reported separately and does not fail matching inputs/content.",
        ],
    }


def write_report(path, result):
    # Exclusive creation also refuses existing symlinks, devices and reports.
    with Path(path).open("x", encoding="utf-8") as output:
        json.dump(result, output, indent=2, sort_keys=True)
        output.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("left", type=Path, help="First prototype build directory")
    parser.add_argument("right", type=Path, help="Second prototype build directory")
    parser.add_argument("--output", type=Path, required=True, metavar="NEW.json")
    args = parser.parse_args(argv)
    try:
        if os.path.lexists(args.output):
            raise ComparisonError("Output already exists; refusing to overwrite it")
        result = compare_builds(args.left, args.right)
        write_report(args.output, result)
    except (ComparisonError, OSError, ValueError) as error:
        print(f"compare-builds: {error}", file=sys.stderr)
        return 2
    for label, key in (("Recipe inputs", "inputs_equal"),
                       ("Filesystem content (no timestamps)", "content_equal"),
                       ("Image bytes (recorded SHA-256)", "image_byte_identical")):
        print(f"{label}: {'identical' if result[key] else 'different'}")
    for section, difference in result["filesystem_differences"].items():
        print(f"{section}: " + ", ".join(f"{len(paths)} {kind}" for kind, paths in difference.items()))
    print(f"Report: {args.output}")
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
