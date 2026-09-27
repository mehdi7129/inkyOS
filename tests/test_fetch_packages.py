"""Offline tests for package lock constraints and verified delta downloads."""

from contextlib import redirect_stderr, redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error


SPEC = importlib.util.spec_from_file_location("fetch_packages", Path(__file__).resolve().parents[1] / "scripts/fetch-packages.py")
fetch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fetch)


class Response(io.BytesIO):
    def __init__(self, content):
        super().__init__(content)
        self.headers = {}

    def geturl(self):
        return "https://deb.debian.org/debian/pool/main/f/fixture/fixture_1.0-1_arm64.deb"


class PackageFetchTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.content = b"small fictional package, never installed\n"
        self.package = {
            "name": "fixture", "version": "1.0-1", "architecture": "arm64",
            "filename": "fixture_1.0-1_arm64.deb",
            "url": "https://deb.debian.org/debian/pool/main/f/fixture/fixture_1.0-1_arm64.deb",
            "size_bytes": len(self.content), "sha256": hashlib.sha256(self.content).hexdigest(),
        }
        self.lock = {
            "version": 1, "architecture": "arm64", "debian_release": "trixie",
            "status": "experimental-not-hardware-qualified", "base_image_sha256": "a" * 64,
            "packages": [self.package],
        }
        self.path = self.root / "packages.json"
        self.base_path = self.root / "base.json"
        self.base_path.write_text(json.dumps({"version": 1, "image": {
            "filename": "2026-09-15-fixture.img.xz", "url": "https://example.test/images/2026-09-15-fixture.img.xz",
            "sha256": "b" * 64, "size_bytes": 1, "extracted_sha256": "a" * 64,
            "extracted_size_bytes": 1, "arch": "arm64", "debian_release": "trixie",
        }}))
        self.stderr = redirect_stderr(io.StringIO())
        self.stderr.__enter__()
        self.addCleanup(self.stderr.__exit__, None, None, None)

    def load(self, value=None):
        self.path.write_text(json.dumps(self.lock if value is None else value))
        return fetch.load_lock(self.path)

    def download(self):
        return fetch.fetch_packages(self.load(), self.root / "cache", opener=lambda *a, **kw: Response(self.content))

    def test_cache_is_verified_without_network(self):
        result = self.download()
        self.assertEqual(Path(result[0]["path"]).read_bytes(), self.content)
        with patch.object(fetch.base.urllib.request, "urlopen", side_effect=AssertionError("unexpected network")):
            self.assertEqual(fetch.fetch_packages(self.load(), self.root / "cache"), result)

    def test_corrupt_cache_is_left_untouched(self):
        path = Path(self.download()[0]["path"])
        path.write_bytes(b"x" * len(self.content))
        with self.assertRaisesRegex(fetch.base.FetchError, "SHA-256"):
            fetch.fetch_packages(self.load(), path.parent)
        self.assertEqual(path.read_bytes(), b"x" * len(self.content))

    def test_corrupt_or_oversized_download_is_not_published(self):
        for data in [b"x" * len(self.content), self.content + b"x"]:
            with self.subTest(data=data):
                with self.assertRaises(fetch.base.FetchError):
                    fetch.fetch_packages(self.load(), self.root / "cache", opener=lambda *a, **kw: Response(data))
                self.assertEqual(list((self.root / "cache").iterdir()), [])

    def test_interrupted_transfer_cleans_partial_file(self):
        class Interrupted(Response):
            def read(self, size):
                if self.tell():
                    raise urllib.error.URLError("interrupted")
                return super().read(4)
        with self.assertRaises(urllib.error.URLError):
            fetch.fetch_packages(self.load(), self.root / "cache", opener=lambda *a, **kw: Interrupted(self.content))
        self.assertEqual(list((self.root / "cache").iterdir()), [])

    def test_rejects_wrong_arch_hash_version_and_path(self):
        for field, value in [("architecture", "amd64"), ("sha256", ""), ("version", "latest"),
                             ("filename", "../fixture.deb"), ("size_bytes", True),
                             ("url", "https://user:secret@deb.debian.org/debian/pool/f.deb")]:
            with self.subTest(field=field):
                invalid = copy.deepcopy(self.lock)
                invalid["packages"][0][field] = value
                with self.assertRaises(fetch.base.FetchError):
                    self.load(invalid)

    def test_duplicates_and_version_filename_mismatch_fail(self):
        invalid = copy.deepcopy(self.lock)
        invalid["packages"].append(copy.deepcopy(self.package))
        with self.assertRaisesRegex(fetch.base.FetchError, "Duplicate"):
            self.load(invalid)
        invalid = copy.deepcopy(self.lock)
        invalid["packages"][0]["version"] = "2.0-1"
        with self.assertRaisesRegex(fetch.base.FetchError, "Filename differs"):
            self.load(invalid)

    def test_wrong_base_hash_fails_before_download(self):
        invalid = copy.deepcopy(self.lock)
        invalid["base_image_sha256"] = "c" * 64
        self.load(invalid)
        with patch.object(fetch.base.urllib.request, "urlopen", side_effect=AssertionError("unexpected network")):
            self.assertEqual(fetch.main(["--lock", str(self.path), "--base-lock", str(self.base_path)]), 1)

    def test_symlink_cache_destination_is_refused(self):
        cache = self.root / "cache"
        cache.mkdir()
        victim = self.root / "keep"
        victim.write_bytes(b"keep")
        (cache / self.package["filename"]).symlink_to(victim)
        with self.assertRaises(fetch.base.FetchError):
            fetch.fetch_packages(self.load(), cache)
        self.assertEqual(victim.read_bytes(), b"keep")

    def test_cli_emits_json_for_the_exact_reviewed_delta(self):
        self.download()
        output = io.StringIO()
        with redirect_stdout(output), patch.object(fetch.base.urllib.request, "urlopen", side_effect=AssertionError("unexpected network")):
            rc = fetch.main(["--lock", str(self.path), "--base-lock", str(self.base_path), "--cache-dir", str(self.root / "cache")])
        self.assertEqual(rc, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["base_image_sha256"], self.lock["base_image_sha256"])
        self.assertEqual(report["packages"][0]["sha256"], self.package["sha256"])


if __name__ == "__main__":
    unittest.main()
