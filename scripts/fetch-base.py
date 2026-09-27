#!/usr/bin/env python3
"""Fetch a locked base image; optionally extract it to a regular file, never a device."""

import argparse
import hashlib
import http.client
import json
import lzma
import math
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
CHUNK_SIZE = 1024 * 1024
MAX_ARCHIVE_BYTES = 2 * 1024**3
MAX_IMAGE_BYTES = 8 * 1024**3
MAX_SECONDS = 1800
USER_AGENT = "Mozilla/5.0 (compatible; InkyOS-base-fetch/1.0)"


class FetchError(Exception):
    """An input, integrity or safety check failed."""


def progress(message):
    print(message, file=sys.stderr, flush=True)


def check_hash(value, label):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise FetchError(f"{label}: a lowercase SHA-256 is required")


def check_size(value, limit, label):
    if type(value) is not int or not 0 < value <= limit:
        raise FetchError(f"{label}: expected integer between 1 and {limit}")


def load_lock(path):
    with open_regular(path) as source:
        raw = source.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise FetchError("Lock exceeds 1 MiB")
    lock = json.loads(raw)
    if not isinstance(lock, dict) or type(lock.get("version")) is not int or lock["version"] != 1:
        raise FetchError("Unsupported lock version")
    image = lock.get("image")
    if not isinstance(image, dict):
        raise FetchError("Lock image object is required")
    filename = image.get("filename", "")
    if not isinstance(filename, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.img\.xz", filename):
        raise FetchError("Image filename must be a plain .img.xz basename")
    url = image.get("url")
    if not isinstance(url, str):
        raise FetchError("Image HTTPS URL is required")
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or Path(parsed.path).name != filename
            or "latest" in url.lower() or not re.search(r"\d{4}-\d{2}-\d{2}", parsed.path)):
        raise FetchError("Use a dated HTTPS archive URL without credentials, query or latest alias")
    check_hash(image.get("sha256"), "image.sha256")
    check_hash(image.get("extracted_sha256"), "image.extracted_sha256")
    check_size(image.get("size_bytes"), MAX_ARCHIVE_BYTES, "image.size_bytes")
    check_size(image.get("extracted_size_bytes"), MAX_IMAGE_BYTES, "image.extracted_size_bytes")
    return lock


def assert_destination(path):
    """Reject devices, symlinks and existing non-regular paths before writing."""
    path = Path(path).absolute()
    if path.resolve().is_relative_to(Path("/dev")):
        raise FetchError(f"Device paths are forbidden: {path}")
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return path
    if not stat.S_ISREG(mode):
        raise FetchError(f"Destination must be a regular file, not a link/device: {path}")
    return path


def open_regular(path):
    # O_NONBLOCK also prevents a substituted FIFO from hanging before fstat.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise FetchError(f"Not a regular file: {path}")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def digest_file(path, expected_size):
    with open_regular(path) as source:
        if os.fstat(source.fileno()).st_size != expected_size:
            raise FetchError(f"Unexpected file size: {path}")
        digest = hashlib.sha256()
        total = 0
        while chunk := source.read(CHUNK_SIZE):
            total += len(chunk)
            if total > expected_size:
                raise FetchError(f"File exceeds locked size: {path}")
            digest.update(chunk)
    if total != expected_size:
        raise FetchError(f"File changed size during verification: {path}")
    return digest.hexdigest()


def verify_existing(path, expected_hash, expected_size):
    path = assert_destination(path)
    if not path.exists():
        return False
    progress(f"Verifying existing file: {path}")
    if digest_file(path, expected_size) != expected_hash:
        raise FetchError(f"SHA-256 mismatch; existing file left unchanged: {path}")
    return True


def write_verified(destination, expected_hash, expected_size, producer):
    """Publish only a complete verified file; never overwrite a concurrent file."""
    destination = assert_destination(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".part", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as output:
            total, actual_hash = producer(output)
            if total != expected_size:
                raise FetchError(f"Size mismatch: got {total}, expected {expected_size}")
            if actual_hash != expected_hash:
                raise FetchError(f"SHA-256 mismatch for {destination.name}")
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError:
            if not verify_existing(destination, expected_hash, expected_size):
                raise FetchError(f"Destination changed concurrently: {destination}")
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def copy_bounded(source, output, expected_size, deadline):
    digest = hashlib.sha256()
    total = 0
    while True:
        if time.monotonic() > deadline:
            raise FetchError("Operation exceeded total time limit")
        chunk = source.read(min(CHUNK_SIZE, expected_size - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > expected_size:
            raise FetchError("Stream exceeds locked size")
        output.write(chunk)
        digest.update(chunk)
    return total, digest.hexdigest()


def fetch_image(image, cache_dir, timeout=30, opener=None):
    destination = Path(cache_dir) / image["filename"]
    if verify_existing(destination, image["sha256"], image["size_bytes"]):
        return destination.absolute()
    if not math.isfinite(timeout) or not 0 < timeout <= 300:
        raise FetchError("Timeout must be greater than 0 and at most 300 seconds")
    opener = opener or urllib.request.urlopen
    request = urllib.request.Request(image["url"], headers={"User-Agent": USER_AGENT})
    progress(f"Downloading locked archive: {image['filename']}")

    def produce(output):
        deadline = time.monotonic() + MAX_SECONDS
        with opener(request, timeout=timeout) as response:
            if urllib.parse.urlsplit(response.geturl()).scheme != "https":
                raise FetchError("Refusing a redirect outside HTTPS")
            length = response.headers.get("Content-Length")
            if length is not None and int(length) != image["size_bytes"]:
                raise FetchError("HTTP Content-Length does not match the lock")
            return copy_bounded(response, output, image["size_bytes"], deadline)

    return write_verified(destination, image["sha256"], image["size_bytes"], produce)


def extract_image(archive, destination, image):
    destination = assert_destination(destination)
    if destination.suffix != ".img":
        raise FetchError("Extraction destination must end with .img")
    # Re-verify even when this function is used independently from fetch_image.
    if not verify_existing(archive, image["sha256"], image["size_bytes"]):
        raise FetchError("Verified archive is missing")
    if verify_existing(destination, image["extracted_sha256"], image["extracted_size_bytes"]):
        return destination
    progress(f"Extracting and verifying image: {destination}")

    def produce(output):
        with open_regular(archive) as compressed:
            with lzma.LZMAFile(compressed, "rb") as source:
                return copy_bounded(source, output, image["extracted_size_bytes"], time.monotonic() + MAX_SECONDS)

    return write_verified(destination, image["extracted_sha256"], image["extracted_size_bytes"], produce)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=ROOT / "config/base-image.lock.json")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / "cache")
    parser.add_argument("--extract", type=Path, metavar="OUTPUT.img", help="Opt in to extraction to a regular file")
    parser.add_argument("--timeout", type=float, default=30, help="Network socket timeout in seconds (default: 30)")
    args = parser.parse_args(argv)
    try:
        lock = load_lock(args.lock)
        image = lock["image"]
        archive = fetch_image(image, args.cache_dir, args.timeout)
        result = {"archive_path": str(archive), "sha256": image["sha256"], "size_bytes": image["size_bytes"], "status": lock.get("status")}
        if args.extract:
            extracted = extract_image(archive, args.extract, image)
            result.update(image_path=str(extracted), image_sha256=image["extracted_sha256"], image_size_bytes=image["extracted_size_bytes"])
        print(json.dumps(result, sort_keys=True))
        return 0
    except (FetchError, OSError, ValueError, urllib.error.URLError, http.client.HTTPException, lzma.LZMAError, EOFError) as error:
        print(f"fetch-base: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("fetch-base: interrupted; incomplete output discarded", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
