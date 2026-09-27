"""Synthetic exports exercise integrity and consistency without real disk images."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/verify-artifacts.py"
SPEC = importlib.util.spec_from_file_location("verify_artifacts", SCRIPT)
artifacts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifacts)
IMAGE = b"fictional image fixture; never mounted\n"


def default_build():
    return {"schema_version": 1, "kind": "system-prototype", "hardware_qualified": False, "application": None,
            "image": {"filename": "prototype.img", "size_bytes": len(IMAGE), "sha256": hashlib.sha256(IMAGE).hexdigest()},
            "recipe": {"schema_version": 1, "source_commit": "b" * 40, "worktree_dirty": False,
                       "files": {"scripts/build.py": "c" * 64}}}


def file_record(digest="1" * 64):
    return {"type": "file", "mode": "0644", "uid": 0, "gid": 0, "size_bytes": 10, "sha256": digest}


def default_filesystem(version=1):
    fs = {"schema_version": 1, "scope": "content-without-timestamps",
          "rootfs": {"etc": {"type": "directory", "mode": "0755", "uid": 0, "gid": 0},
                     "etc/hostname": file_record(),
                     "bin": {"type": "symlink", "mode": "0777", "uid": 0, "gid": 0, "target": "usr/bin"}},
          "bootfs": {"cmdline.txt": file_record()}}
    if version == 2:
        fs.update(schema_version=2, scope="content-and-metadata-without-timestamps")
        for section in ("rootfs", "bootfs"):
            fs[section]["."] = {"type": "directory", "mode": "0755", "uid": 0, "gid": 0}
            for record in fs[section].values():
                record["xattrs"] = {"status": "inspected", "entries": {}}
    return fs


def save_export(directory, *, build=None, filesystem=None, image=IMAGE):
    directory.mkdir(exist_ok=True)
    manifest = copy.deepcopy(default_build() if build is None else build)
    filesystem = copy.deepcopy(default_filesystem() if filesystem is None else filesystem)
    static = {"schema_version": 1, "scope": "offline-system-prototype-contract", "passed": True,
              "failed_checks": [], "checks": [{"id": identifier, "passed": True} for identifier in sorted(artifacts.REQUIRED_STATIC_CHECKS)]}
    smoke = {"passed": True, "checks": {name: True for name in artifacts.REQUIRED_SMOKE_CHECKS}}
    reports = {name: b"fixture evidence\n" for name in artifacts.REQUIRED_REPORTS}
    for name, value in {"qualification-static.json": static, "firstboot-smoke.json": smoke,
                        "filesystem-manifest.json": filesystem, "builder.json": {"fixture": True},
                        "image-inspection.json": {"image": {key: manifest["image"][key] for key in ("sha256", "size_bytes")}}}.items():
        reports[name] = json.dumps(value).encode()
    manifest["reports"] = {}
    for name, raw in reports.items():
        (directory / name).write_bytes(raw)
        manifest["reports"][name] = hashlib.sha256(raw).hexdigest()
    (directory / manifest["image"]["filename"]).write_bytes(image)
    (directory / "recipe-inputs.json").write_text(json.dumps(manifest["recipe"]))
    (directory / "manifest.json").write_text(json.dumps(manifest))
    return manifest


def rehash_report(directory, name, value):
    raw = json.dumps(value).encode() if isinstance(value, (dict, list)) else value
    (directory / name).write_bytes(raw)
    path = directory / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest["reports"][name] = hashlib.sha256(raw).hexdigest()
    path.write_text(json.dumps(manifest))


class VerifyArtifactsTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.export = self.root / "export"
        self.output = self.root / "verification.json"
        save_export(self.export)

    def cli(self, output=True):
        args = [sys.executable, str(SCRIPT), str(self.export)]
        if output:
            args += ["--output", str(self.output)]
        return subprocess.run(args, capture_output=True, text=True, timeout=5)

    def test_full_integrity_is_explicitly_not_authenticity_or_hardware_qualification(self):
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertTrue(report["passed"])
        self.assertTrue(report["image_sha256_verified"])
        self.assertFalse(report["authenticity_verified"])
        self.assertFalse(report["hardware_qualified"])
        self.assertEqual(set(report["declared_reports_verified"]), artifacts.REQUIRED_REPORTS)

    def test_same_size_image_corruption_is_rejected(self):
        path = self.export / "prototype.img"
        path.write_bytes(b"x" * len(IMAGE))
        result = self.cli()
        self.assertEqual(result.returncode, 2)
        self.assertIn("Image SHA-256", result.stderr)
        self.assertFalse(self.output.exists())

    def test_report_corruption_and_every_additional_declared_report_are_checked(self):
        rehash_report(self.export, "additional.txt", b"extra evidence")
        self.assertTrue(artifacts.load_export(self.export)["report"]["passed"])
        (self.export / "additional.txt").write_text("altered")
        with self.assertRaisesRegex(artifacts.ArtifactError, "SHA-256 mismatch"):
            artifacts.load_export(self.export)

    def test_required_report_cannot_be_omitted(self):
        path = self.export / "manifest.json"
        manifest = json.loads(path.read_text())
        del manifest["reports"]["fsck-fat.txt"]
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(artifacts.ArtifactError, "required build reports"):
            artifacts.load_export(self.export)

    def test_forged_pass_with_failed_or_omitted_checks_is_rejected_after_rehash(self):
        for filename, change in (("qualification-static.json", "false"), ("qualification-static.json", "empty"),
                                 ("firstboot-smoke.json", "false"), ("firstboot-smoke.json", "empty")):
            with self.subTest(filename=filename, change=change):
                save_export(self.export)
                value = json.loads((self.export / filename).read_text())
                if change == "empty":
                    value["checks"] = {} if filename.startswith("firstboot") else []
                elif filename.startswith("firstboot"):
                    value["checks"]["parent_hostname_unchanged"] = False
                else:
                    value["checks"][0]["passed"] = False
                rehash_report(self.export, filename, value)
                with self.assertRaises(artifacts.ArtifactError):
                    artifacts.load_export(self.export)

    def test_recipe_inputs_and_image_inspection_must_agree(self):
        path = self.export / "recipe-inputs.json"
        value = json.loads(path.read_text())
        value["worktree_dirty"] = True
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(artifacts.ArtifactError, "recipe-inputs"):
            artifacts.load_export(self.export)
        save_export(self.export)
        rehash_report(self.export, "image-inspection.json", {"image": {"sha256": "e" * 64, "size_bytes": len(IMAGE)}})
        with self.assertRaisesRegex(artifacts.ArtifactError, "Image-inspection"):
            artifacts.load_export(self.export)

    def test_traversal_and_absolute_names_are_rejected(self):
        for name in ("../outside", "/etc/passwd", "sub/report.json", "."):
            with self.subTest(name=name):
                manifest = save_export(self.export)
                manifest["reports"][name] = "a" * 64
                (self.export / "manifest.json").write_text(json.dumps(manifest))
                with self.assertRaises(artifacts.ArtifactError):
                    artifacts.load_export(self.export)

    def test_links_and_fifos_are_rejected_for_images_and_reports_without_hanging(self):
        for name in ("prototype.img", "filesystem-manifest.json", "manifest.json", "recipe-inputs.json"):
            for kind in ("link", "fifo"):
                with self.subTest(name=name, kind=kind):
                    save_export(self.export)
                    path = self.export / name
                    target = self.root / "outside"
                    target.write_bytes(path.read_bytes())
                    path.unlink()
                    if kind == "link":
                        path.symlink_to(target)
                    else:
                        os.mkfifo(path)
                    self.assertEqual(self.cli().returncode, 2)
                    self.assertFalse(self.output.exists())
                    path.unlink()

    def test_v2_xattrs_and_hardlinks_are_validated(self):
        fs = default_filesystem(2)
        record = fs["rootfs"]["etc/hostname"]
        record["hardlinks"] = ["etc/alias", "etc/hostname"]
        record["xattrs"]["entries"]["system.posix_acl_access"] = {"sha256": "e" * 64, "size_bytes": 24}
        fs["rootfs"]["etc/alias"] = copy.deepcopy(record)
        save_export(self.export, filesystem=fs)
        self.assertEqual(artifacts.load_export(self.export)["report"]["filesystem_manifest_schema"], 2)
        del fs["rootfs"]["etc/alias"]
        rehash_report(self.export, "filesystem-manifest.json", fs)
        with self.assertRaisesRegex(artifacts.ArtifactError, "hardlink"):
            artifacts.load_export(self.export)

    def test_duplicate_json_keys_and_nonfinite_values_fail(self):
        for raw in (b'{"schema_version":1,"schema_version":1}', b'{"image":NaN}'):
            (self.export / "manifest.json").write_bytes(raw)
            self.assertEqual(self.cli().returncode, 2)
            self.assertFalse(self.output.exists())

    def test_output_is_new_and_outside_input_directory(self):
        self.output.write_text("UNCHANGED")
        self.assertEqual(self.cli().returncode, 2)
        self.assertEqual(self.output.read_text(), "UNCHANGED")
        self.output = self.export / "new.json"
        self.assertEqual(self.cli().returncode, 2)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
