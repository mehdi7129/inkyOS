#!/usr/bin/env python3
"""Fetch the reviewed, hash-locked .deb delta without resolving or installing APT packages."""

import argparse
import http.client
import importlib.util
import json
import math
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("_inkyos_fetch_base", ROOT / "scripts/fetch-base.py")
base = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)
MAX_PACKAGE_BYTES = 128 * 1024**2
MAX_DELTA_BYTES = 256 * 1024**2
MAX_PACKAGES = 32


def load_lock(path):
    with base.open_regular(path) as source:
        raw = source.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise base.FetchError("Package lock exceeds 1 MiB")
    lock = json.loads(raw)
    if not isinstance(lock, dict) or type(lock.get("version")) is not int or lock["version"] != 1:
        raise base.FetchError("Unsupported package lock version")
    base.check_hash(lock.get("base_image_sha256"), "base_image_sha256")
    if lock.get("architecture") != "arm64" or lock.get("debian_release") != "trixie":
        raise base.FetchError("Package delta must target the reviewed ARM64 Trixie base")
    packages = lock.get("packages")
    if not isinstance(packages, list) or not 1 <= len(packages) <= MAX_PACKAGES:
        raise base.FetchError(f"Package lock must contain 1 to {MAX_PACKAGES} entries")
    names, filenames = set(), set()
    total = 0
    for package in packages:
        if not isinstance(package, dict):
            raise base.FetchError("Package entry must be an object")
        name, version, arch = (package.get(field) for field in ("name", "version", "architecture"))
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", name):
            raise base.FetchError("Invalid Debian package name")
        if not isinstance(version, str) or not re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]*", version):
            raise base.FetchError("Exact Debian package version is required")
        if arch not in {"arm64", "all"}:
            raise base.FetchError("Unexpected package architecture")
        filename, url = package.get("filename"), package.get("url")
        if not isinstance(filename, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_~\-]*\.deb", filename):
            raise base.FetchError("Package filename must be a plain .deb basename")
        # Debian pool filenames omit the epoch from the package version.
        if filename != f"{name}_{version.split(':', 1)[-1]}_{arch}.deb":
            raise base.FetchError("Filename differs from package name/version/architecture")
        if not isinstance(url, str):
            raise base.FetchError("Package HTTPS URL is required")
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or urllib.parse.unquote(Path(parsed.path).name) != filename
                or "/pool/" not in parsed.path or "latest" in parsed.path.lower()):
            raise base.FetchError("Use an exact HTTPS Debian pool URL without credentials or aliases")
        if name in names or filename in filenames:
            raise base.FetchError("Duplicate package name or filename")
        names.add(name)
        filenames.add(filename)
        base.check_hash(package.get("sha256"), f"{name}.sha256")
        base.check_size(package.get("size_bytes"), MAX_PACKAGE_BYTES, f"{name}.size_bytes")
        total += package["size_bytes"]
    if total > MAX_DELTA_BYTES:
        raise base.FetchError("Package delta exceeds the size limit")
    return lock


def verify_base(lock, base_lock_path):
    image = base.load_lock(base_lock_path)["image"]
    if image["extracted_sha256"] != lock["base_image_sha256"]:
        raise base.FetchError("Package delta was reviewed for a different base image")
    if image.get("arch") != lock["architecture"] or image.get("debian_release") != lock["debian_release"]:
        raise base.FetchError("Package delta architecture/release differs from base lock")


def fetch_packages(lock, cache_dir, timeout=30, opener=None):
    if not math.isfinite(timeout) or not 0 < timeout <= 300:
        raise base.FetchError("Timeout must be greater than 0 and at most 300 seconds")
    results = []
    for package in lock["packages"]:
        path = base.fetch_image(package, cache_dir, timeout=timeout, opener=opener)
        results.append({"name": package["name"], "version": package["version"], "architecture": package["architecture"],
                        "path": str(path), "sha256": package["sha256"], "size_bytes": package["size_bytes"]})
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=ROOT / "config/system-packages.lock.json")
    parser.add_argument("--base-lock", type=Path, default=ROOT / "config/base-image.lock.json")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "cache/packages")
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args(argv)
    try:
        lock = load_lock(args.lock)
        verify_base(lock, args.base_lock)
        packages = fetch_packages(lock, args.cache_dir, timeout=args.timeout)
        print(json.dumps({"status": lock.get("status"), "base_image_sha256": lock["base_image_sha256"], "packages": packages}, sort_keys=True))
        return 0
    except (base.FetchError, OSError, ValueError, urllib.error.URLError, http.client.HTTPException, EOFError) as error:
        print(f"fetch-packages: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("fetch-packages: interrupted; incomplete download discarded", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
