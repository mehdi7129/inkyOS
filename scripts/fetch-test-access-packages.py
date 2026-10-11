#!/usr/bin/env python3
"""Fetch the reviewed TEST-only I2C package delta; never resolve or install packages."""

import argparse
import http.client
import importlib.util
import json
from pathlib import Path
import re
import sys
import urllib.error


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("_inkyos_fetch_packages", ROOT / "scripts/fetch-packages.py")
shared = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(shared)
base = shared.base
FIELDS = {"version", "status", "scope", "verified_at", "base_image_sha256", "reviewed_source_commit",
          "architecture", "debian_release", "packages", "provenance", "notes"}
PACKAGE_FIELDS = {"name", "version", "architecture", "source_package", "filename", "url", "sha256",
                  "size_bytes", "depends", "recommends", "suggests", "required_dependencies_in_base",
                  "required_dependencies_in_delta"}
DEPENDENCY_FIELDS = {"name", "version", "architecture", "constraints"}


def require(value, message):
    if value is not True:
        raise base.FetchError(message)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate package lock field")
            result[key] = value
        return result

    def invalid(_):
        raise base.FetchError("Non-finite package lock number")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def dependencies(rows):
    require(type(rows) is list and len(rows) <= 16, "Invalid reviewed dependency list")
    names = set()
    for row in rows:
        require(type(row) is dict and set(row) == DEPENDENCY_FIELDS, "Unknown dependency field")
        require(type(row["name"]) is str and re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", row["name"]) is not None
                and row["name"] not in names, "Invalid or duplicate dependency name")
        names.add(row["name"])
        require(type(row["version"]) is str and re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]*", row["version"]) is not None
                and row["architecture"] in {"arm64", "all"}, "Invalid reviewed dependency version/architecture")
        require(type(row["constraints"]) is list and len(row["constraints"]) <= 8
                and all(type(x) is str and 0 < len(x) <= 128 for x in row["constraints"]),
                "Invalid dependency constraints")


def load_lock(path):
    with base.open_regular(path) as source:
        raw = source.read(1024 * 1024 + 1)
    require(len(raw) <= 1024 * 1024, "Package lock exceeds 1 MiB")
    lock = strict_json(raw)
    require(type(lock) is dict and set(lock) == FIELDS, "Unknown TEST package lock field")
    # Reuse the existing URL, exact version, architecture, hash, size and duplicate
    # checks. Compare both reads so a changed lock cannot mix reviewed metadata.
    require(shared.load_lock(path) == lock, "Package lock changed during validation")
    require(lock["scope"] == "test-access-only" and lock["status"] == "experimental-not-hardware-qualified",
            "Unexpected package delta scope")
    require(type(lock["verified_at"]) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}", lock["verified_at"]) is not None
            and type(lock["reviewed_source_commit"]) is str
            and re.fullmatch(r"[0-9a-f]{40}", lock["reviewed_source_commit"]) is not None,
            "Reviewed date/source commit required")
    require([p["name"] for p in lock["packages"]] == ["libi2c0", "i2c-tools"],
            "TEST delta must contain only libi2c0 then i2c-tools")
    for package in lock["packages"]:
        require(set(package) == PACKAGE_FIELDS, "Unknown TEST package field")
        require(package["source_package"] == "i2c-tools" and package["architecture"] == "arm64"
                and package["url"] == "https://deb.debian.org/debian/pool/main/i/i2c-tools/" + package["filename"],
                "Unexpected TEST package source")
        require(all(type(package[key]) is str and len(package[key]) <= 4096
                    for key in ("depends", "recommends", "suggests")), "Invalid dependency metadata")
        dependencies(package["required_dependencies_in_base"])
        dependencies(package["required_dependencies_in_delta"])
    library, tools = lock["packages"]
    require(not library["required_dependencies_in_delta"]
            and tools["required_dependencies_in_delta"] == [{"name": library["name"],
                "version": library["version"], "architecture": library["architecture"], "constraints": [">= 4.0"]}],
            "Delta dependency must bind the locked libi2c0")
    provenance = lock["provenance"]
    require(type(provenance) is dict and set(provenance) == {"reference_lock", "reference_lock_sha256",
            "inrelease", "packages_index", "authenticated_release_sha256",
            "signature_verification_record_sha256", "authentication"}, "Unknown provenance field")
    require(provenance["reference_lock"] == "config/system-packages.lock.json"
            and provenance["authentication"] == "previously-verified-debian-inrelease-reused",
            "Unexpected provenance method")
    for key in ("reference_lock_sha256", "authenticated_release_sha256", "signature_verification_record_sha256"):
        base.check_hash(provenance[key], "provenance." + key)
    for key, suffix in (("inrelease", "InRelease"), ("packages_index", "main/binary-arm64/Packages.xz")):
        value = provenance[key]
        require(type(value) is dict and set(value) == ({"url", "sha256", "size_bytes", "release_date"}
                if key == "inrelease" else {"url", "sha256", "size_bytes"}), "Unknown repository metadata field")
        require(value["url"] == "https://deb.debian.org/debian/dists/trixie/" + suffix,
                "Unexpected repository metadata URL")
        base.check_hash(value["sha256"], key + ".sha256")
        base.check_size(value["size_bytes"], 32 * 1024**2, key + ".size_bytes")
    require(type(provenance["inrelease"]["release_date"]) is str
            and 0 < len(provenance["inrelease"]["release_date"]) <= 128, "Invalid repository release date")
    require(type(lock["notes"]) is list and len(lock["notes"]) <= 16
            and all(type(x) is str and 0 < len(x) <= 4096 for x in lock["notes"]), "Invalid package notes")
    return lock


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=ROOT / "config/test-access-packages.lock.json")
    parser.add_argument("--base-lock", type=Path, default=ROOT / "config/base-image.lock.json")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "cache/packages")
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args(argv)
    try:
        lock = load_lock(args.lock)
        shared.verify_base(lock, args.base_lock)
        packages = shared.fetch_packages(lock, args.cache_dir, timeout=args.timeout)
        print(json.dumps({"status": lock["status"], "scope": lock["scope"],
                          "base_image_sha256": lock["base_image_sha256"], "packages": packages}, sort_keys=True))
        return 0
    except (base.FetchError, OSError, ValueError, TypeError, urllib.error.URLError, http.client.HTTPException, EOFError) as error:
        print(f"fetch-test-access-packages: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("fetch-test-access-packages: interrupted; incomplete download discarded", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
