#!/usr/bin/env python3
"""Compare verified export reports; optionally rehash both image files too.

By default, all declared reports are rehashed and image type/size are checked.
--verify-images additionally rereads the large images. Equality of recorded
image hashes is kept distinct from verified byte equality.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys


SPEC = importlib.util.spec_from_file_location("_inkyos_verify_artifacts", Path(__file__).with_name("verify-artifacts.py"))
artifacts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifacts)
ComparisonError = artifacts.ArtifactError
validate_build = artifacts.validate_build
validate_filesystem = artifacts.validate_filesystem


def read_manifest(path):
    export = artifacts.ExportDirectory(Path(path).parent)
    try:
        return artifacts.parse_json(export.read(Path(path).name))
    finally:
        export.close()


def changes(left, right):
    """Return names only, never content, hashes, xattr values or symlink targets."""
    left_names, right_names = set(left), set(right)
    return {"added": sorted(right_names - left_names), "removed": sorted(left_names - right_names),
            "modified": sorted(name for name in left_names & right_names
                               if artifacts.canonical(left[name]) != artifacts.canonical(right[name]))}


def unchanged(difference):
    return not any(difference.values())


def compare_builds(left_directory, right_directory, *, verify_images=False):
    exports = [artifacts.load_export(directory, verify_images=verify_images)
               for directory in (left_directory, right_directory)]
    builds = [export["manifest"] for export in exports]
    filesystems = [export["filesystem"] for export in exports]
    if filesystems[0]["schema_version"] != filesystems[1]["schema_version"]:
        raise ComparisonError("Mixed filesystem schemas cannot establish equal scope; compare v1/v1 or v2/v2")
    version = filesystems[0]["schema_version"]
    recipes = [build["recipe"] for build in builds]
    metadata = [{key: value for key, value in recipe.items() if key != "files"} for recipe in recipes]
    recipe_changes = {"metadata": changes(*metadata), "files": changes(*(recipe["files"] for recipe in recipes))}
    filesystem_changes = {section: changes(*(filesystem[section] for filesystem in filesystems))
                          for section in ("rootfs", "bootfs")}
    inputs_equal = all(unchanged(diff) for diff in recipe_changes.values())
    content_equal = all(unchanged(diff) for diff in filesystem_changes.values())
    hashes_equal = builds[0]["image"]["sha256"] == builds[1]["image"]["sha256"]
    extended_complete = version == 2 and all(record["xattrs"]["status"] == "inspected"
        for filesystem in filesystems for section in ("rootfs", "bootfs") for record in filesystem[section].values())
    return {
        "schema_version": 1, "scope": "verified-export-reports-and-recorded-filesystem-content",
        "direction": "left-to-right", "inputs_equal": inputs_equal, "content_equal": content_equal,
        "declared_report_hashes_verified": True, "image_hashes_verified": verify_images,
        "recorded_image_hashes_equal": hashes_equal,
        "image_byte_identical": hashes_equal if verify_images else None,
        "filesystem_schema_version": version, "extended_metadata_fully_inspected": extended_complete,
        "success": inputs_equal and content_equal, "path_exclusions": [],
        "recipe_differences": recipe_changes, "filesystem_differences": filesystem_changes,
        "authenticity_verified": False, "hardware_qualified": False,
        "limits": [
            "Every declared report hash, gate consistency and recipe-inputs.json is rechecked against the local unsigned manifest.",
            "Image hashes were rechecked." if verify_images else "Image bytes were not hashed; only image type and size were checked.",
            "Filesystem records are compared, not regenerated from the images; no image is mounted or executed.",
            "Timestamps and filesystem allocation/layout are outside the content manifest.",
            "Schema 1 omits xattrs, ACLs and hardlink groups." if version == 1 else "Schema 2 compares recorded xattrs and hardlink groups; unsupported xattrs remain unknown.",
            "Different verified image hashes do not fail matching recorded recipe/filesystem content.",
            "Integrity and record equality prove neither authenticity nor successful boot or hardware qualification.",
        ],
    }


def write_report(path, result, input_directories=()):
    artifacts.write_report(path, result, input_directories)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("left", type=Path, help="First prototype export directory")
    parser.add_argument("right", type=Path, help="Second prototype export directory")
    parser.add_argument("--output", type=Path, required=True, metavar="NEW.json")
    parser.add_argument("--verify-images", action="store_true", help="Also rehash both image files (several GiB each)")
    args = parser.parse_args(argv)
    try:
        if os.path.lexists(args.output):
            raise ComparisonError("Output already exists; refusing to overwrite it")
        result = compare_builds(args.left, args.right, verify_images=args.verify_images)
        write_report(args.output, result, (args.left, args.right))
    except (ComparisonError, OSError, ValueError, TypeError, KeyError) as error:
        print(f"compare-builds: {error}", file=sys.stderr)
        return 2
    for label, key in (("Recipe inputs", "inputs_equal"), ("Recorded filesystem content", "content_equal"),
                       ("Recorded image SHA-256", "recorded_image_hashes_equal")):
        print(f"{label}: {'identical' if result[key] else 'different'}")
    print(f"Image bytes rehashed: {'yes' if args.verify_images else 'no'}")
    for section, difference in result["filesystem_differences"].items():
        print(f"{section}: " + ", ".join(f"{len(paths)} {kind}" for kind, paths in difference.items()))
    print(f"Report: {args.output}")
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
