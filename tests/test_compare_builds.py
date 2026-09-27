"""Compare synthetic export reports and optional tiny image fixtures; no rootfs."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/compare-builds.py"
spec = importlib.util.spec_from_file_location("compare_builds", SCRIPT)
compare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare)
fixture_spec = importlib.util.spec_from_file_location("artifact_fixtures", Path(__file__).with_name("test_verify_artifacts.py"))
fixtures = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixtures)


def file_record(digest="1" * 64):
    return {"type": "file", "mode": "0644", "uid": 0, "gid": 0,
            "size_bytes": 10, "sha256": digest}


class CompareBuildsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.left = self.root / "prototype.left"
        self.right = self.root / "prototype.right"
        self.output = self.root / "comparison.json"
        self.build = fixtures.default_build()
        self.filesystem = {
            "schema_version": 1, "scope": "content-without-timestamps",
            "rootfs": {
                "etc": {"type": "directory", "mode": "0755", "uid": 0, "gid": 0},
                "etc/hostname": file_record(),
                "bin": {"type": "symlink", "mode": "0777", "uid": 0, "gid": 0,
                        "target": "usr/bin"},
            },
            "bootfs": {"cmdline.txt": file_record()},
        }
        self.save(self.left)
        self.save(self.right)

    def save(self, directory, build=None, filesystem=None):
        fixtures.save_export(directory, build=build if build is not None else self.build,
                             filesystem=filesystem if filesystem is not None else self.filesystem)

    def run_cli(self):
        return subprocess.run([sys.executable, str(SCRIPT), str(self.left), str(self.right),
                               "--output", str(self.output)], capture_output=True, text=True)

    def test_identical_builds_succeed_without_opening_images(self):
        completed = self.run_cli()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(self.output.read_text())
        self.assertTrue(result["inputs_equal"])
        self.assertTrue(result["content_equal"])
        self.assertTrue(result["recorded_image_hashes_equal"])
        self.assertIsNone(result["image_byte_identical"])
        self.assertFalse(result["image_hashes_verified"])
        self.assertTrue(result["success"])
        self.assertEqual(result["path_exclusions"], [])

    def test_only_image_hash_difference_does_not_fail_content_comparison(self):
        other = copy.deepcopy(self.build)
        other["image"]["sha256"] = "d" * 64
        self.save(self.right, build=other)
        completed = self.run_cli()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(self.output.read_text())
        self.assertTrue(result["success"])
        self.assertFalse(result["recorded_image_hashes_equal"])
        self.assertIsNone(result["image_byte_identical"])
        self.assertIn("Recorded image SHA-256: different", completed.stdout)

    def test_source_commit_and_dirty_flag_are_recipe_inputs(self):
        for field, changed in (("source_commit", "d" * 40), ("worktree_dirty", True)):
            with self.subTest(field=field):
                other = copy.deepcopy(self.build)
                other["recipe"][field] = changed
                self.save(self.right, build=other)
                result = compare.compare_builds(self.left, self.right)
                self.assertFalse(result["inputs_equal"])
                self.assertTrue(result["content_equal"])
                self.assertFalse(result["success"])
                self.assertEqual(result["recipe_differences"]["metadata"]["modified"], [field])

    def test_recipe_file_hash_changes_fail_even_with_equal_content_and_image(self):
        other = copy.deepcopy(self.build)
        other["recipe"]["files"]["scripts/build.py"] = "d" * 64
        self.save(self.right, build=other)
        completed = self.run_cli()
        self.assertEqual(completed.returncode, 1, completed.stderr)
        result = json.loads(self.output.read_text())
        self.assertFalse(result["inputs_equal"])
        self.assertTrue(result["content_equal"])
        self.assertTrue(result["recorded_image_hashes_equal"])
        self.assertEqual(result["recipe_differences"]["files"]["modified"], ["scripts/build.py"])

    def test_file_hash_mode_owner_group_and_symlink_target_are_compared(self):
        for path, field, changed in (("etc/hostname", "sha256", "d" * 64),
                                     ("etc/hostname", "mode", "0600"),
                                     ("etc/hostname", "uid", 1000),
                                     ("etc/hostname", "gid", 1000),
                                     ("bin", "target", "different-target")):
            with self.subTest(path=path, field=field):
                other = copy.deepcopy(self.filesystem)
                other["rootfs"][path][field] = changed
                self.save(self.right, filesystem=other)
                result = compare.compare_builds(self.left, self.right)
                self.assertTrue(result["inputs_equal"])
                self.assertFalse(result["content_equal"])
                self.assertFalse(result["success"])
                self.assertEqual(result["filesystem_differences"]["rootfs"]["modified"], [path])
                self.assertNotIn("different-target", json.dumps(result))
                self.assertNotIn("d" * 64, json.dumps(result))

    def test_all_paths_in_both_filesystems_are_reported_without_values(self):
        other = copy.deepcopy(self.filesystem)
        del other["rootfs"]["etc/hostname"]
        other["rootfs"]["var/lib/inkyos/system.json"] = file_record("e" * 64)
        other["bootfs"]["cmdline.txt"]["sha256"] = "f" * 64
        self.save(self.right, filesystem=other)
        completed = self.run_cli()
        self.assertEqual(completed.returncode, 1, completed.stderr)
        result = json.loads(self.output.read_text())
        self.assertEqual(result["filesystem_differences"]["rootfs"], {
            "added": ["var/lib/inkyos/system.json"], "removed": ["etc/hostname"], "modified": []})
        self.assertEqual(result["filesystem_differences"]["bootfs"]["modified"], ["cmdline.txt"])
        self.assertNotIn("e" * 64, self.output.read_text())

    def test_extra_record_and_recipe_fields_are_not_silently_ignored(self):
        other_build = copy.deepcopy(self.build)
        other_build["recipe"]["additional_input"] = "unprinted input"
        other_fs = copy.deepcopy(self.filesystem)
        other_fs["rootfs"]["etc"]["additional_attribute"] = "unprinted attribute"
        self.save(self.right, build=other_build, filesystem=other_fs)
        result = compare.compare_builds(self.left, self.right)
        self.assertFalse(result["inputs_equal"])
        self.assertFalse(result["content_equal"])
        self.assertEqual(result["recipe_differences"]["metadata"]["added"], ["additional_input"])
        self.assertEqual(result["filesystem_differences"]["rootfs"]["modified"], ["etc"])
        self.assertNotIn("unprinted", json.dumps(result))

    def test_existing_output_and_symlink_are_never_overwritten(self):
        sentinel = self.root / "sentinel"
        sentinel.write_text("UNCHANGED")
        for symlink in (False, True):
            with self.subTest(symlink=symlink):
                if symlink:
                    self.output.symlink_to(sentinel)
                else:
                    self.output.write_text("UNCHANGED")
                completed = self.run_cli()
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(self.output.read_text(), "UNCHANGED")
                self.assertEqual(sentinel.read_text(), "UNCHANGED")
                self.output.unlink()

    def test_incomplete_or_wrong_scope_inputs_fail_without_output(self):
        for change in ("application", "scope", "owner", "path"):
            with self.subTest(change=change):
                build, filesystem = copy.deepcopy(self.build), copy.deepcopy(self.filesystem)
                if change == "application":
                    del build["application"]
                elif change == "scope":
                    filesystem["scope"] = "other"
                elif change == "owner":
                    del filesystem["rootfs"]["etc"]["uid"]
                else:
                    filesystem["rootfs"]["../outside"] = file_record()
                self.save(self.right, build=build, filesystem=filesystem)
                completed = self.run_cli()
                self.assertEqual(completed.returncode, 2)
                self.assertFalse(self.output.exists())

    def test_duplicate_keys_and_non_regular_manifest_are_rejected(self):
        path = self.right / "manifest.json"
        path.write_text('{"schema_version":1,"schema_version":1}')
        self.assertEqual(self.run_cli().returncode, 2)
        self.assertFalse(self.output.exists())
        path.unlink()
        path.symlink_to(self.left / "manifest.json")
        self.assertEqual(self.run_cli().returncode, 2)
        path.unlink()
        os.mkfifo(path)
        self.assertEqual(self.run_cli().returncode, 2)
        self.assertFalse(self.output.exists())

    def test_report_changed_without_matching_hash_is_rejected(self):
        (self.right / "filesystem-manifest.json").write_text(json.dumps(self.filesystem) + "\n")
        with self.assertRaisesRegex(compare.ComparisonError, "SHA-256 mismatch"):
            compare.compare_builds(self.left, self.right)

    def test_optional_image_rehash_detects_corruption_and_never_claims_unread_bytes_equal(self):
        report = compare.compare_builds(self.left, self.right, verify_images=True)
        self.assertTrue(report["image_hashes_verified"])
        self.assertTrue(report["image_byte_identical"])
        image = self.right / "prototype.img"
        image.write_bytes(b"x" * image.stat().st_size)
        fast = compare.compare_builds(self.left, self.right)
        self.assertTrue(fast["recorded_image_hashes_equal"])
        self.assertIsNone(fast["image_byte_identical"])
        with self.assertRaisesRegex(compare.ComparisonError, "Image SHA-256"):
            compare.compare_builds(self.left, self.right, verify_images=True)

    def test_v1_and_v2_cannot_be_silently_projected_onto_common_fields(self):
        self.save(self.right, filesystem=fixtures.default_filesystem(2))
        with self.assertRaisesRegex(compare.ComparisonError, "Mixed filesystem schemas"):
            compare.compare_builds(self.left, self.right)

    def test_v2_metadata_is_compared_and_unsupported_xattrs_remain_unknown(self):
        filesystem = fixtures.default_filesystem(2)
        self.save(self.left, filesystem=filesystem)
        self.save(self.right, filesystem=filesystem)
        equal = compare.compare_builds(self.left, self.right)
        self.assertTrue(equal["content_equal"])
        self.assertTrue(equal["extended_metadata_fully_inspected"])
        changed = copy.deepcopy(filesystem)
        changed["rootfs"]["etc/hostname"]["xattrs"]["entries"]["user.test"] = {"size_bytes": 3, "sha256": "a" * 64}
        self.save(self.right, filesystem=changed)
        report = compare.compare_builds(self.left, self.right)
        self.assertFalse(report["content_equal"])
        self.assertEqual(report["filesystem_differences"]["rootfs"]["modified"], ["etc/hostname"])
        changed["rootfs"]["etc/hostname"]["xattrs"] = {"status": "unsupported", "reason": "platform"}
        self.save(self.left, filesystem=changed)
        self.save(self.right, filesystem=changed)
        report = compare.compare_builds(self.left, self.right)
        self.assertTrue(report["content_equal"])
        self.assertFalse(report["extended_metadata_fully_inspected"])


if __name__ == "__main__":
    unittest.main()
