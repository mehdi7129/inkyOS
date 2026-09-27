"""Small offline fixtures exercise integrity, interrupted writes and cache reuse."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error


SPEC = importlib.util.spec_from_file_location("fetch_base", Path(__file__).resolve().parents[1] / "scripts/fetch-base.py")
fetch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fetch)


class Response(io.BytesIO):
    def __init__(self, content, content_length=None):
        super().__init__(content)
        self.headers = {} if content_length is None else {"Content-Length": str(content_length)}

    def geturl(self):
        return "https://downloads.raspberrypi.com/fixtures/2026-09-15-test.img.xz"


class FetchBaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.raw = b"small, fictional image fixture\n" * 100
        self.compressed = lzma.compress(self.raw)
        self.image = {
            "filename": "2026-09-15-test.img.xz",
            "url": "https://downloads.raspberrypi.com/fixtures/2026-09-15-test.img.xz",
            "sha256": hashlib.sha256(self.compressed).hexdigest(),
            "size_bytes": len(self.compressed),
            "extracted_sha256": hashlib.sha256(self.raw).hexdigest(),
            "extracted_size_bytes": len(self.raw),
        }
        self.lock = self.root / "lock.json"
        self.write_lock()
        self.stderr = redirect_stderr(io.StringIO())
        self.stderr.__enter__()
        self.addCleanup(self.stderr.__exit__, None, None, None)

    def write_lock(self):
        self.lock.write_text(json.dumps({"version": 1, "status": "experimental-not-hardware-qualified", "image": self.image}))

    def opener(self, _request, timeout):
        self.assertGreater(timeout, 0)
        return Response(self.compressed, len(self.compressed))

    def fetch_fixture(self):
        return fetch.fetch_image(self.image, self.root / "cache", opener=self.opener)

    def assert_no_parts(self):
        self.assertEqual(list(self.root.rglob("*.part")), [])

    def test_lock_rejects_fifo_and_symlink(self):
        fifo = self.root / "lock-fifo"
        os.mkfifo(fifo)
        with self.assertRaises(fetch.FetchError):
            fetch.load_lock(fifo)
        link = self.root / "lock-link"
        link.symlink_to(self.lock)
        with self.assertRaises(OSError):
            fetch.load_lock(link)

    def test_download_and_cache_rehash_without_network(self):
        archive = self.fetch_fixture()
        self.assertEqual(archive.read_bytes(), self.compressed)
        with patch.object(fetch.urllib.request, "urlopen", side_effect=AssertionError("cache used network")):
            self.assertEqual(fetch.fetch_image(self.image, self.root / "cache"), archive)
        self.assert_no_parts()

    def test_corrupt_cache_is_refused_and_preserved(self):
        archive = self.fetch_fixture()
        tampered = bytes([self.compressed[0] ^ 1]) + self.compressed[1:]
        archive.write_bytes(tampered)
        with patch.object(fetch.urllib.request, "urlopen", side_effect=AssertionError("corrupt cache fetched again")):
            with self.assertRaisesRegex(fetch.FetchError, "SHA-256"):
                fetch.fetch_image(self.image, archive.parent)
        self.assertEqual(archive.read_bytes(), tampered)

    def test_corrupt_download_is_never_published(self):
        def opener(_request, timeout):
            return Response(b"x" * len(self.compressed))
        with self.assertRaisesRegex(fetch.FetchError, "SHA-256"):
            fetch.fetch_image(self.image, self.root / "cache", opener=opener)
        self.assertFalse((self.root / "cache" / self.image["filename"]).exists())
        self.assert_no_parts()

    def test_interrupted_transfer_cleans_temporary_file(self):
        class Interrupted(Response):
            def read(self, size):
                if self.tell():
                    raise urllib.error.URLError("connection interrupted")
                return super().read(10)
        with self.assertRaises(urllib.error.URLError):
            fetch.fetch_image(self.image, self.root / "cache", opener=lambda *a, **kw: Interrupted(self.compressed))
        self.assert_no_parts()
        self.assertFalse((self.root / "cache" / self.image["filename"]).exists())

    def test_size_bound_applies_without_content_length(self):
        with self.assertRaisesRegex(fetch.FetchError, "exceeds locked size"):
            fetch.fetch_image(self.image, self.root / "cache", opener=lambda *a, **kw: Response(self.compressed + b"x"))
        self.assert_no_parts()

    def test_truncated_download_is_rejected(self):
        with self.assertRaisesRegex(fetch.FetchError, "Size mismatch"):
            fetch.fetch_image(self.image, self.root / "cache", opener=lambda *a, **kw: Response(self.compressed[:-1]))
        self.assert_no_parts()

    def test_extract_verified_image_and_refuse_modified_existing_output(self):
        archive = self.fetch_fixture()
        destination = self.root / "build/base.img"
        self.assertEqual(fetch.extract_image(archive, destination, self.image), destination)
        self.assertEqual(destination.read_bytes(), self.raw)
        self.assertEqual(fetch.extract_image(archive, destination, self.image), destination)
        destination.write_bytes(b"x" * len(self.raw))
        with self.assertRaisesRegex(fetch.FetchError, "SHA-256"):
            fetch.extract_image(archive, destination, self.image)
        self.assertEqual(destination.read_bytes(), b"x" * len(self.raw))

    def test_extract_size_is_bounded_and_partial_output_removed(self):
        archive = self.fetch_fixture()
        self.image["extracted_size_bytes"] = len(self.raw) - 1
        destination = self.root / "base.img"
        with self.assertRaisesRegex(fetch.FetchError, "exceeds locked size"):
            fetch.extract_image(archive, destination, self.image)
        self.assertFalse(destination.exists())
        self.assert_no_parts()

    def test_invalid_xz_is_not_published(self):
        archive = self.root / "invalid.img.xz"
        content = b"this is not xz"
        archive.write_bytes(content)
        self.image.update(size_bytes=len(content), sha256=hashlib.sha256(content).hexdigest())
        with self.assertRaises(lzma.LZMAError):
            fetch.extract_image(archive, self.root / "base.img", self.image)
        self.assert_no_parts()

    def test_symlink_and_device_targets_are_rejected(self):
        archive = self.fetch_fixture()
        real = self.root / "real.img"
        real.write_bytes(b"keep")
        link = self.root / "link.img"
        link.symlink_to(real)
        with self.assertRaises(fetch.FetchError):
            fetch.extract_image(archive, link, self.image)
        with self.assertRaises(fetch.FetchError):
            fetch.assert_destination(Path("/dev/null"))
        self.assertEqual(real.read_bytes(), b"keep")

    def test_lock_requires_hash_and_dated_url(self):
        self.assertEqual(fetch.load_lock(self.lock)["image"], self.image)
        for key, value in [("sha256", ""), ("size_bytes", True), ("url", "https://example.org/latest.img.xz"), ("filename", "../../image.img.xz")]:
            with self.subTest(key=key):
                original = self.image[key]
                self.image[key] = value
                self.write_lock()
                with self.assertRaises(fetch.FetchError):
                    fetch.load_lock(self.lock)
                self.image[key] = original

    def test_cli_json_and_opt_in_extraction(self):
        self.fetch_fixture()
        output = io.StringIO()
        with redirect_stdout(output), patch.object(fetch.urllib.request, "urlopen", side_effect=AssertionError("unexpected network")):
            result = fetch.main(["--lock", str(self.lock), "--cache-dir", str(self.root / "cache")])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["sha256"], self.image["sha256"])
        self.assertNotIn("image_path", json.loads(output.getvalue()))
        self.assertFalse((self.root / "build").exists())


if __name__ == "__main__":
    unittest.main()
