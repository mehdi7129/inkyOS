"""Offline validation of the TEST-only package lock and shared verified fetcher."""

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


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("fetch_test_access_packages", ROOT / "scripts/fetch-test-access-packages.py")
fetch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fetch)


class TestAccessPackageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.path = self.directory / "lock.json"
        self.lock = json.loads((ROOT / "config/test-access-packages.lock.json").read_bytes())

    def load(self, lock=None):
        self.path.write_text(json.dumps(self.lock if lock is None else lock))
        return fetch.load_lock(self.path)

    def test_reviewed_lock_targets_only_missing_i2c_packages(self):
        lock = self.load()
        fetch.shared.verify_base(lock, ROOT / "config/base-image.lock.json")
        self.assertEqual([p["name"] for p in lock["packages"]], ["libi2c0", "i2c-tools"])
        self.assertEqual([p["version"] for p in lock["packages"]], ["4.4-2", "4.4-2"])
        self.assertEqual(sum(p["size_bytes"] for p in lock["packages"]), 88576)

    def test_unknown_fields_rejected_at_each_schema_level(self):
        for path in ((), ("packages", 0), ("packages", 0, "required_dependencies_in_base", 0),
                     ("provenance",), ("provenance", "inrelease"), ("provenance", "packages_index")):
            with self.subTest(path=path):
                lock = copy.deepcopy(self.lock)
                target = lock
                for key in path:
                    target = target[key]
                target["unreviewed"] = True
                with self.assertRaises(fetch.base.FetchError):
                    self.load(lock)

    def test_duplicate_and_nonfinite_json_rejected(self):
        for raw in ('{"version":1,"version":1}', '{"value":NaN}', '{"value":Infinity}'):
            with self.subTest(raw=raw):
                self.path.write_text(raw)
                with self.assertRaises(fetch.base.FetchError):
                    fetch.load_lock(self.path)

    def test_additional_packages_or_reversed_dependency_order_rejected(self):
        for packages in (list(reversed(self.lock["packages"])), self.lock["packages"][:1],
                         self.lock["packages"] + [copy.deepcopy(self.lock["packages"][0])]):
            lock = copy.deepcopy(self.lock)
            lock["packages"] = packages
            with self.assertRaises(fetch.base.FetchError):
                self.load(lock)

    def test_other_pool_source_and_architecture_rejected(self):
        for key, value in (("url", self.lock["packages"][0]["url"].replace("deb.debian.org", "example.test")),
                           ("source_package", "unreviewed"), ("architecture", "amd64")):
            lock = copy.deepcopy(self.lock)
            lock["packages"][0][key] = value
            with self.assertRaises(fetch.base.FetchError):
                self.load(lock)

    def test_hash_size_and_exact_version_use_shared_checks(self):
        for key, value in (("sha256", "bad"), ("size_bytes", True), ("version", "latest")):
            lock = copy.deepcopy(self.lock)
            lock["packages"][0][key] = value
            with self.assertRaises(fetch.base.FetchError):
                self.load(lock)

    def test_changed_delta_dependency_rejected(self):
        lock = copy.deepcopy(self.lock)
        lock["packages"][1]["required_dependencies_in_delta"][0]["version"] = "4.0-1"
        with self.assertRaisesRegex(fetch.base.FetchError, "bind the locked"):
            self.load(lock)

    def test_duplicate_base_dependency_rejected(self):
        lock = copy.deepcopy(self.lock)
        rows = lock["packages"][0]["required_dependencies_in_base"]
        rows.append(copy.deepcopy(rows[0]))
        with self.assertRaises(fetch.base.FetchError):
            self.load(lock)

    def test_lock_changed_between_common_and_closed_validation_rejected(self):
        self.path.write_text(json.dumps(self.lock))
        changed = copy.deepcopy(self.lock)
        changed["notes"] = ["changed concurrently"]
        with patch.object(fetch.shared, "load_lock", return_value=changed):
            with self.assertRaisesRegex(fetch.base.FetchError, "changed during validation"):
                fetch.load_lock(self.path)

    def test_cli_verifies_both_cached_files_without_network(self):
        cache = self.directory / "cache"
        cache.mkdir()
        for package in self.lock["packages"]:
            raw = ("synthetic fixture " + package["name"]).encode()
            package.update(sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw))
            (cache / package["filename"]).write_bytes(raw)
        self.load()
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(io.StringIO()), patch.object(
                fetch.base.urllib.request, "urlopen", side_effect=AssertionError("unexpected network")):
            code = fetch.main(["--lock", str(self.path), "--cache-dir", str(cache)])
        self.assertEqual(code, 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["scope"], "test-access-only")
        self.assertEqual(len(result["packages"]), 2)

    def test_corrupt_cache_preserved_without_network(self):
        cache = self.directory / "cache"
        cache.mkdir()
        first = self.lock["packages"][0]
        target = cache / first["filename"]
        target.write_bytes(b"not the authenticated package")
        self.load()
        with redirect_stderr(io.StringIO()), patch.object(fetch.base.urllib.request, "urlopen",
                side_effect=AssertionError("unexpected network")):
            self.assertEqual(fetch.main(["--lock", str(self.path), "--cache-dir", str(cache)]), 1)
        self.assertEqual(target.read_bytes(), b"not the authenticated package")

    def test_wrong_base_refused_before_fetch(self):
        self.lock["base_image_sha256"] = "0" * 64
        self.load()
        with redirect_stderr(io.StringIO()), patch.object(fetch.shared, "fetch_packages",
                side_effect=AssertionError("unexpected fetch")):
            self.assertEqual(fetch.main(["--lock", str(self.path)]), 1)


if __name__ == "__main__":
    unittest.main()
