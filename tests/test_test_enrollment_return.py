"""Synthetic readonly trees/export only; no mount, device, keygen or private read."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

controller = load(ROOT / "scripts/verify-test-enrollment-return.py", "return_fixture_controller")
seed = load(ROOT / "tests/test_verify_test_enrollment.py", "return_synthetic_export_seed")
runtime = controller.runtime


def put(root, relative, raw, mode=0o644):
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    for parent in (target.parent, *target.parent.parents):
        if parent == root:
            break
        parent.chmod(0o755)
    target.write_bytes(raw)
    target.chmod(mode)
    return target


class FixtureAdapter(controller.NativeAdapter):
    def __init__(self, root, boot, export):
        super().__init__(root, boot, export)
        self.mount_result = {key: True for key in controller.CHECKS[:2]}
    def environment(self):
        return True
    def open(self):
        for path, fat, private in zip(self.paths, (False, True, False), (False, False, True)):
            self.trees.append(controller.ReadTree(path, owner=os.geteuid(), group=os.getegid(),
                               fat=fat, private=private, _fixture=True))
        self.root, self.boot, self.export = self.trees
    def mounts(self):
        return self.mount_result


class ReturnTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root, self.boot, self.export = (self.base / name for name in ("root", "boot", "expected"))
        for path in (self.root, self.boot, self.export):
            path.mkdir(mode=0o700)
            path.chmod(0o700)
        self.manifest, self.blobs = seed.fixture(self.export)
        for path in self.export.iterdir():
            path.chmod(0o600)
        self.profile_raw = self.blobs["private-profile.json"]
        self.profile = json.loads(self.profile_raw)
        self.profile_hash = controller.digest(self.profile_raw)
        self.host = seed.profile_fixture.profile()["operator_public_key"]
        # The synthetic host wire is intentionally different from operator wire.
        wire = runtime.public_key(self.host)
        import base64
        self.host = "ssh-ed25519 " + base64.b64encode(wire[:-32] + b"h" * 32).decode()
        self.state = {"schema_version": 1, "kind": "test-lan-enrollment-state", "state": "enrolled",
                      "profile_sha256": self.profile_hash, "application_activation_authorized": False}
        self.report = {"schema_version": 1, "kind": "test-lan-enrollment-report", "state": "enrolled",
            "challenge": self.profile["challenge"], "application_source_commit": runtime.SOURCE,
            "application_manifest_sha256": runtime.MANIFEST_HASH, "parent_image_sha256": runtime.PARENT_IMAGE_SHA256,
            "profile_sha256": self.profile_hash, "host_public_key": self.host,
            "host_public_key_sha256": controller.digest(runtime.public_key(self.host)),
            "runtime_source_sha256": controller.digest(self.blobs["scripts/test-enrollment-firstboot.py"]),
            "observations": {kind: {"status": "blocked", "live_evidence": False, "data": None} for kind in ("panel", "radio")},
            "live_evidence": True, **{key: False for key in runtime.FALSE_FIELDS}}
        put(self.root, controller.PROFILE, self.profile_raw, 0o600)
        put(self.root, controller.STATE, runtime.canonical(self.state), 0o600)
        put(self.root, controller.PUBLIC_KEY, (self.host + " inkyos-test-host\n").encode(), 0o644)
        put(self.root, controller.PRIVATE_KEY, b"SYNTHETIC_PLACEHOLDER_NEVER_OPENED", 0o600)
        put(self.root, controller.RUNTIME, self.blobs["scripts/test-enrollment-firstboot.py"], 0o555)
        for relative in (str(Path(controller.PROFILE).parent), str(Path(controller.STATE).parent), "usr/local/lib/inkyos"):
            (self.root / relative).chmod(0o700)
        self.write_report()

    def write_report(self):
        put(self.boot, controller.REPORT, runtime.canonical(self.report), 0o644)

    def adapter(self):
        return FixtureAdapter(self.root, self.boot, self.export)

    def check(self, code=0):
        result, actual = controller.compare(self.adapter())
        self.assertEqual(actual, code, result)
        return result

    def test_consistent_return_fixture_passes_comparison_only_with_closed_private_output(self):
        result = self.check()
        self.assertTrue(result["passed"])
        self.assertTrue(all(result["checks"].values()))
        self.assertEqual(result["observation_source"], "fixture")
        for key in ("native_readonly_evidence", "image_sha256_verified", "authenticity_verified",
                    "runtime_execution_attested", "shutdown_observed", "hardware_qualified", "release_qualified",
                    "application_activation_authorized", "ssh_access_enabled", "network_profile_present"):
            self.assertIs(result[key], False)
        output = json.dumps(result)
        for token in (self.profile["challenge"], self.profile["operator_public_key"], self.host,
                      self.profile_hash, self.report["runtime_source_sha256"], str(self.base), "SYNTHETIC_PLACEHOLDER"):
            self.assertNotIn(token, output)

    def test_private_key_and_image_are_stat_only_and_no_process_can_run(self):
        original = controller.os.open
        def safe(path, *args, **kwargs):
            self.assertNotEqual(os.fspath(path), "ssh_host_ed25519_key")
            self.assertNotEqual(os.fspath(path), "inkyos-test-enrollment.img")
            return original(path, *args, **kwargs)
        with mock.patch.object(controller.os, "open", side_effect=safe), \
                mock.patch("subprocess.Popen", side_effect=AssertionError("No commands")):
            self.check()

    def test_report_alone_never_passes_pending_or_review_required_ext4_state(self):
        for state in ("pending", "review-required"):
            self.state["state"] = state
            (self.root / controller.STATE).write_bytes(runtime.canonical(self.state))
            result = self.check(1)
            self.assertFalse(result["checks"]["state_enrolled"])

    def test_missing_state_or_public_report_is_incomplete_and_keeps_all_files(self):
        for root, relative in ((self.root, controller.STATE), (self.boot, controller.REPORT)):
            path = root / relative
            raw = path.read_bytes(); path.unlink()
            result = self.check(1)
            self.assertEqual(result["error"], "return_incomplete")
            path.write_bytes(raw); path.chmod(0o600 if relative == controller.STATE else 0o644)

    def test_profile_expected_bytes_nonce_pins_and_binding_divergence_fail(self):
        for key, value in (("challenge", "b" * 64), ("profile_sha256", "b" * 64),
                           ("application_source_commit", "a" * 40), ("application_manifest_sha256", "a" * 64),
                           ("parent_image_sha256", "a" * 64)):
            saved = self.report[key]
            self.report[key] = value; self.write_report()
            result = self.check(1)
            self.assertFalse(result["checks"]["report_profile_binding"])
            self.report[key] = saved; self.write_report()
        profile = dict(self.profile, challenge="b" * 64)
        (self.root / controller.PROFILE).write_bytes(runtime.canonical(profile))
        result = self.check(1)
        self.assertFalse(result["checks"]["profile_matches_expected_bytes"])

    def test_noncanonical_profile_and_wrong_state_hash_cannot_pass(self):
        (self.root / controller.PROFILE).write_bytes(json.dumps(self.profile).encode())
        self.assertFalse(self.check(1)["checks"]["profile_canonical"])
        (self.root / controller.PROFILE).write_bytes(self.profile_raw)
        self.state["profile_sha256"] = "c" * 64
        (self.root / controller.STATE).write_bytes(runtime.canonical(self.state))
        self.assertFalse(self.check(1)["checks"]["state_profile_binding"])

    def test_host_public_and_wire_hash_mismatches_fail(self):
        self.report["host_public_key"] = self.profile["operator_public_key"]
        self.write_report()
        self.assertFalse(self.check(1)["checks"]["host_public_binding"])
        self.report["host_public_key"] = self.host
        self.report["host_public_key_sha256"] = "a" * 64
        self.write_report()
        self.assertFalse(self.check(1)["checks"]["host_public_binding"])

    def test_runtime_expected_and_report_hash_binding_is_required_without_importing_target(self):
        path = self.root / controller.RUNTIME
        path.chmod(0o600)
        path.write_bytes(b"raise AssertionError('MUST_NOT_EXECUTE')\n")
        path.chmod(0o555)
        self.assertFalse(self.check(1)["checks"]["runtime_binding"])
        path.chmod(0o600)
        path.write_bytes(self.blobs["scripts/test-enrollment-firstboot.py"])
        path.chmod(0o555)
        self.report["runtime_source_sha256"] = "a" * 64; self.write_report()
        self.assertFalse(self.check(1)["checks"]["runtime_binding"])

    def test_forged_live_claim_or_qualification_or_extra_private_field_cannot_pass(self):
        self.report["live_evidence"] = False; self.write_report()
        self.assertFalse(self.check(1)["checks"]["public_report_live_claim"])
        self.report["live_evidence"] = True
        for key in runtime.FALSE_FIELDS:
            self.report[key] = True; self.write_report(); self.check(2)
            self.report[key] = False
        self.report["PRIVATE_LOG"] = "SSID MAC PASSWORD SERIAL"; self.write_report()
        self.check(2)

    def test_duplicate_float_boolint_and_invalid_json_are_fixed_errors_without_value_echo(self):
        target = self.boot / controller.REPORT
        for raw in (b'{"schema_version":1,"schema_version":1}', b'{"x":1e309}', b'{"x":NaN}',
                    runtime.canonical(dict(self.report, schema_version=True)), b'PRIVATE_PATH PASSWORD\xff'):
            target.write_bytes(raw)
            result = self.check(2)
            self.assertEqual(result["error"], "invalid_input")
            self.assertNotIn("PRIVATE_PATH", json.dumps(result))

    def test_partial_temp_or_extra_private_files_block_without_reading_them(self):
        for root, relative in ((self.root, str(Path(controller.STATE).parent / ".state.json.tmp")),
                               (self.root, str(Path(controller.PROFILE).parent / "credentials.json")),
                               (self.boot, "." + controller.REPORT + ".tmp")):
            target = put(root, relative, b"PRIVATE_MUST_NOT_READ", 0o600)
            (self.root / Path(controller.PROFILE).parent).chmod(0o700)
            (self.root / Path(controller.STATE).parent).chmod(0o700)
            self.assertFalse(self.check(1)["checks"]["no_partial_artifacts"])
            target.unlink()

    def test_unsafe_mount_blocks_before_expected_or_private_reads(self):
        adapter = self.adapter()
        adapter.mount_result[controller.CHECKS[0]] = False
        adapter.expected = mock.Mock(side_effect=AssertionError("No files"))
        adapter.returned = mock.Mock(side_effect=AssertionError("No private files"))
        result, code = controller.compare(adapter)
        self.assertEqual(code, 1)
        self.assertEqual(result["error"], "readonly_mount_required")
        adapter.expected.assert_not_called(); adapter.returned.assert_not_called()

    def test_links_special_files_wrong_modes_and_oversize_input_refused(self):
        path = self.root / controller.STATE
        original = path.read_bytes()
        for kind in ("symlink", "hardlink", "fifo", "mode", "size"):
            path.unlink()
            if kind == "symlink": path.symlink_to("profile.json")
            elif kind == "hardlink": os.link(self.root / controller.PROFILE, path)
            elif kind == "fifo": os.mkfifo(path, 0o600)
            else:
                path.write_bytes(original if kind == "mode" else b"x" * 4097)
                path.chmod(0o644 if kind == "mode" else 0o600)
            self.check(2)
            path.unlink(); path.write_bytes(original); path.chmod(0o600)

    def test_symlink_ancestor_and_private_key_symlink_refused_without_open(self):
        private = self.root / controller.PRIVATE_KEY
        private.unlink(); private.symlink_to("profile.json")
        self.check(2)
        private.unlink(); private.write_bytes(b"PLACEHOLDER"); private.chmod(0o600)
        folder = self.root / Path(controller.STATE).parent
        relocated = folder.with_name("moved")
        folder.rename(relocated); folder.symlink_to(relocated.name)
        self.check(2)

    def test_modified_read_or_later_replacement_fails_stability(self):
        adapter = self.adapter()
        original = adapter.returned
        def changed():
            result = original()
            (self.root / controller.STATE).write_bytes(runtime.canonical(self.state) + b"\n")
            return result
        adapter.returned = changed
        result, code = controller.compare(adapter)
        self.assertEqual(code, 2)
        self.assertFalse(result["checks"]["reads_stable"])

    def test_parent_directory_privacy_change_after_read_is_detected(self):
        adapter = self.adapter()
        original = adapter.returned
        def changed():
            result = original()
            (self.root / Path(controller.STATE).parent).chmod(0o755)
            return result
        adapter.returned = changed
        result, code = controller.compare(adapter)
        self.assertEqual(code, 2)
        self.assertFalse(result["checks"]["reads_stable"])

    def test_expected_export_tamper_tar_privacy_image_metadata_and_bounds_refused(self):
        report = self.export / "build.log"
        report.write_bytes(report.read_bytes() + b"tampered")
        self.check(2)

    def test_expected_image_size_or_link_is_rejected_using_metadata_only(self):
        path = self.export / "inkyos-test-enrollment.img"
        path.write_bytes(b"CHANGED_SYNTHETIC_SIZE")
        self.check(2)
        path.unlink()
        path.symlink_to("build.log")
        self.check(2)

    def test_expected_archive_and_total_budget_checked_before_proof_read(self):
        original = controller.ReadTree.info
        for name, size in (("recipe.tar", controller.MAX_ARCHIVE + 1),
                           ("build.log", controller.MAX_TOTAL + 1)):
            def oversized(tree, relative, **kwargs):
                value = original(tree, relative, **kwargs)
                if tree.path == str(self.export) and relative == name:
                    class Large:
                        st_size = size
                    return Large()
                return value
            with mock.patch.object(controller.ReadTree, "info", new=oversized):
                self.check(2)
        large_names = set(sorted(set(self.manifest["reports"]) - {"recipe.tar"})[:3])
        def cumulative(tree, relative, **kwargs):
            value = original(tree, relative, **kwargs)
            if tree.path == str(self.export) and relative in large_names:
                class Large:
                    st_size = controller.MAX_TOTAL // 3 + 1
                return Large()
            return value
        with mock.patch.object(controller.ReadTree, "info", new=cumulative):
            self.check(2)


class MountAndCliTests(unittest.TestCase):
    def test_mount_selects_fd_record_and_rejects_rw_wrong_fs_dev_or_subdirectory(self):
        info = b"7 1 8:2 / /mnt/root rw - ext4 /dev/loop0 rw\n8 7 8:2 / /mnt/root ro - ext4 /dev/loop0 rw\n"
        kwargs = {"device": os.makedev(8, 2), "path": "/mnt/root", "filesystem": "ext4"}
        self.assertTrue(controller.readonly_mount(info, b"mnt_id:\t8\n", **kwargs))
        for changed, fd in ((info, b"mnt_id:\t7\n"), (info.replace(b"- ext4", b"- vfat"), b"mnt_id:\t8\n"),
                            (info.replace(b"8:2", b"8:3"), b"mnt_id:\t8\n"),
                            (info.replace(b"8 7 8:2 / ", b"8 7 8:2 /subdir "), b"mnt_id:\t8\n"),
                            (info + info.splitlines()[1] + b"\n", b"mnt_id:\t8\n"),
                            (info, b"mnt_id:\t8\nmnt_id:\t8\n"), (info, b"mnt_id: invalid\n")):
            self.assertFalse(controller.readonly_mount(changed, fd, **kwargs))
        escaped = b"8 1 8:2 / /mnt/card\\040test ro - vfat /dev/loop0 rw\n"
        self.assertTrue(controller.readonly_mount(escaped, b"mnt_id: 8\n", device=os.makedev(8, 2),
                                                 path="/mnt/card test", filesystem="vfat"))

    def test_public_observations_are_closed_and_never_qualify(self):
        empty = {kind: {"status": "blocked", "live_evidence": False, "data": None} for kind in ("panel", "radio")}
        self.assertTrue(controller.public_observations(empty))
        invalid = copy.deepcopy(empty); invalid["radio"]["PRIVATE_LOG"] = "SECRET"
        self.assertFalse(controller.public_observations(invalid))
        invalid = copy.deepcopy(empty); invalid["panel"]["live_evidence"] = 0
        self.assertFalse(controller.public_observations(invalid))

    def test_observed_panel_and_unqualified_radio_are_public_closed_data(self):
        panel = {"display_variant": 25, "panel_reference": "E640", "width": 600, "height": 400,
                 "color_code": 6, "color": "spectra6", "driver_class": "inky.inky_e640.Inky"}
        radio = {"firmware": {"country_abbrev": "FR", "ccode": "FR", "revision": 5},
                 "kernel": {"global_country": "FR", "phy_country_label": "99", "phy_custom": True,
                            "phy_self_managed": False},
                 "channels_2_4ghz": [{"frequency_mhz": 2412, "channel": 1, "disabled": False,
                                      "max_tx_power_mbm": 2000, "flags": ["no IR"]}]}
        observed = {"panel": {"status": "observed", "live_evidence": True, "data": panel},
                    "radio": {"status": "observed-unqualified", "live_evidence": True, "data": radio}}
        self.assertTrue(controller.public_observations(observed))
        for kind, field, value in (("panel", "width", True), ("panel", "timestamp", "PRIVATE"),
                                    ("radio", "SSID", "PRIVATE")):
            invalid = copy.deepcopy(observed)
            invalid[kind]["data"][field] = value
            self.assertFalse(controller.public_observations(invalid))

    def test_cli_errors_have_json_only_without_paths_or_unrecognized_arguments(self):
        for argv in ([], ["--PRIVATE_PATH"], ["--rootfs", "/PRIVATE\x00PATH", "--bootfs", "/BOOT", "--expected-export", "/EXPORT"]):
            output, error = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                code = controller.main(argv)
            self.assertEqual(code, 2)
            self.assertEqual(error.getvalue(), "")
            value = json.loads(output.getvalue())
            self.assertFalse(value["passed"])
            self.assertNotIn("PRIVATE", output.getvalue())
            self.assertNotIn("/EXPORT", output.getvalue())

    def test_native_environment_block_does_not_open_any_paths(self):
        adapter = controller.NativeAdapter("/PRIVATE", "/BOOT", "/EXPORT")
        with mock.patch.object(controller.sys, "platform", "darwin"), \
                mock.patch.object(controller.os, "open", side_effect=AssertionError("No paths")):
            result, code = controller.compare(adapter)
        self.assertEqual(code, 2)
        self.assertFalse(result["native_readonly_evidence"])


if __name__ == "__main__":
    unittest.main()
