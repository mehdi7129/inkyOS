"""Synthetic public keys/adapters/rootfs only; no keygen, poweroff or devices."""
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/test-enrollment-firstboot.py"
spec = importlib.util.spec_from_file_location("inkyos_enrollment_tests", SCRIPT)
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


def pub(value=b"o"):
    wire = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + value * 32
    return "ssh-ed25519 " + base64.b64encode(wire).decode("ascii")


def profile():
    return {"schema_version": 1, "kind": "test-lan-enrollment", "purpose": "test-enroll-and-stop",
        "state": "enrollment-pending", "application_source_commit": runtime.SOURCE,
        "application_manifest_sha256": runtime.MANIFEST_HASH, "parent_image_sha256": runtime.PARENT_IMAGE_SHA256,
        "operator_public_key": pub(), "challenge": "a" * 64, "country_requested": "FR",
        **{key: False for key in runtime.FALSE_FIELDS}}


class FixtureAdapter:
    def __init__(self):
        self.raw = runtime.canonical(profile())
        self.facts = {key: True for key in runtime.GUARDS}
        self.runtime_hash = "1" * 64
        self.states, self.reports, self.calls = [], [], []
        self.failure = None
        self.target = True
    def check(self, operation):
        self.calls.append(operation)
        if self.failure == operation:
            raise OSError("PRIVATE_PASSWORD PRIVATE_KEY /PRIVATE_PATH")
    def environment(self):
        self.check("environment")
        return self.target
    def profile(self):
        self.check("profile")
        return self.raw
    def guards(self):
        self.check("guards")
        return self.facts
    def fresh(self):
        self.check("fresh")
    def write_state(self, state, digest):
        self.check("state:" + state)
        self.states.append((state, digest))
    def key(self):
        self.check("key")
        return pub(b"h")
    def observations(self):
        self.check("observations")
        return {"panel": {"PRIVATE_KEY": "PRIVATE_SECRET"}, "radio": {"PRIVATE_ID": True}}
    def report(self, value):
        self.check("report")
        self.reports.append(value)
    def sync(self):
        raise AssertionError("Fixtures must never request native sync")
    def poweroff(self):
        raise AssertionError("Fixtures must never request poweroff")
    def close(self):
        self.calls.append("close")


class NativeGuardTests(unittest.TestCase):
    def gate(self, markers):
        source = ("class PreparedGuard:\n    def collect(self):\n        return "
                  + repr({key: True for key in runtime.GUARDS}) + "\n").encode()
        reader = mock.Mock()
        reader.read.side_effect = [runtime.canonical(value) for value in markers]
        adapter = SimpleNamespace(files=reader, source=mock.Mock(return_value=source))
        return adapter, runtime.NativeAdapter.guards(adapter)

    def test_final_marker_rechecked_and_shared_guard_pin_proof_preserved(self):
        marker = {"source_commit": runtime.SOURCE, "manifest_sha256": runtime.MANIFEST_HASH}
        adapter, facts = self.gate([marker, marker])
        self.assertTrue(all(value is True for value in facts.values()))
        self.assertEqual(adapter.files.read.call_args_list,
                         [mock.call(runtime.MARKER_PATH, limit=4096, mode=0o644)] * 2)
        adapter.source.assert_called_once_with(runtime.RADIO_PATH)

    def test_historical_or_crossed_marker_blocks_transplanted_final_profile_before_writes(self):
        historical = {"source_commit": "6a697d134290ced0214fc74b903f4b3c336d70fa",
                      "manifest_sha256": "2424fb9c32234ad7d359799f6b137e98298734023f0039afd1a57fbf265c250f"}
        for marker in (historical, dict(historical, source_commit=runtime.SOURCE),
                       dict(historical, manifest_sha256=runtime.MANIFEST_HASH)):
            native, facts = self.gate([marker])
            native.source.assert_not_called()
            adapter = FixtureAdapter()
            adapter.facts = facts
            output = runtime.enroll(adapter, live=True)
            self.assertFalse(output["passed"])
            self.assertEqual(adapter.states, [])
            self.assertNotIn("key", adapter.calls)
            self.assertNotIn("fresh", adapter.calls)

    def test_marker_changed_while_guard_runs_blocks(self):
        final = {"source_commit": runtime.SOURCE, "manifest_sha256": runtime.MANIFEST_HASH}
        _, facts = self.gate([final, dict(final, source_commit="a" * 40)])
        self.assertTrue(all(value is False for value in facts.values()))


class ProfileTests(unittest.TestCase):
    def test_exact_closed_profile_and_synthetic_wire_key_are_valid_without_io(self):
        with mock.patch.object(runtime.os, "open", side_effect=AssertionError("Pure validator")):
            self.assertTrue(runtime.validate_profile(profile()))
        self.assertEqual(len(runtime.PROFILE_FIELDS), 15)
        self.assertEqual(len(runtime.public_key(pub())), 51)

    def test_profile_types_pins_flags_nonce_country_and_extra_fields_fail(self):
        changes = [{"schema_version": True}, {"kind": "factory"}, {"purpose": "activate"},
            {"state": "enrolled"}, {"challenge": "0" * 64}, {"challenge": "A" * 64},
            {"challenge": "a" * 63}, {"country_requested": "US"}, {"PRIVATE_ID": "PRIVATE_DATA"},
            {"application_source_commit": "6a697d134290ced0214fc74b903f4b3c336d70fa"},
            {"application_manifest_sha256": "f" * 64}, {"parent_image_sha256": "f" * 64}]
        changes += [{field: value} for field in runtime.FALSE_FIELDS for value in (True, 0, "false")]
        for change in changes:
            value = dict(profile(), **change)
            self.assertFalse(runtime.validate_profile(value))
        for value in (None, [], True, {"schema_version": 1}):
            self.assertFalse(runtime.validate_profile(value))

    def test_public_key_rejects_comments_whitespace_noncanonical_and_wrong_wire(self):
        wire = runtime.public_key(pub())
        for value in (pub() + " comment", pub() + "\n", " " + pub(), pub().replace(" ", "  "),
                      "ssh-rsa " + pub().split()[1], pub() + "=", True, "ssh-ed25519 " + "!" * 68,
                      "ssh-ed25519 " + base64.b64encode(bytes(51)).decode(),
                      "ssh-ed25519 " + base64.b64encode(wire[:-1]).decode()):
            self.assertIsNone(runtime.public_key(value))

    def test_json_duplicate_float_nan_infinity_and_private_errors_are_rejected(self):
        for raw in (b'{"schema_version":1,"schema_version":1}', b'{"x":NaN}', b'{"x":1e309}',
                    b'{"x":1.0}', b"PRIVATE_MALFORMED", b"\xff"):
            with self.assertRaisesRegex(runtime.EnrollmentError, "^invalid_input$"):
                runtime.strict_json(raw)


class FlowTests(unittest.TestCase):
    def test_default_is_inert_with_no_adapter_calls_files_or_processes(self):
        adapter = FixtureAdapter()
        with mock.patch.object(runtime.os, "open", side_effect=AssertionError("No files")), \
                mock.patch.object(runtime.subprocess, "Popen", side_effect=AssertionError("No processes")):
            output = runtime.enroll(adapter)
        self.assertEqual(adapter.calls, [])
        self.assertFalse(output["passed"])

    def test_success_fixture_binds_exact_profile_bytes_and_public_host_only(self):
        adapter = FixtureAdapter()
        output = runtime.enroll(adapter, live=True)
        self.assertTrue(output["passed"])
        self.assertEqual([state for state, _ in adapter.states], ["pending", "enrolled"])
        report = adapter.reports[0]
        self.assertEqual(report["profile_sha256"], hashlib.sha256(adapter.raw).hexdigest())
        self.assertEqual(report["host_public_key"], pub(b"h"))
        self.assertEqual(report["host_public_key_sha256"], hashlib.sha256(runtime.public_key(pub(b"h"))).hexdigest())
        self.assertNotIn("operator_public_key", report)
        self.assertFalse(report["live_evidence"])
        self.assertTrue(all(report[field] is False for field in runtime.FALSE_FIELDS))
        self.assertTrue(all(item["live_evidence"] is False for item in report["observations"].values()))
        self.assertNotIn("PRIVATE", json.dumps(report))
        self.assertNotIn(profile()["challenge"], json.dumps(output))
        self.assertNotIn(pub(b"h"), json.dumps(output))
        self.assertFalse(output["poweroff_requested"])
        self.assertEqual(adapter.calls[-1], "close")

    def test_noncanonical_profile_and_unverified_model_block_before_guards_or_writes(self):
        for change in ("noncanonical", "target", "profile"):
            adapter = FixtureAdapter()
            if change == "noncanonical":
                adapter.raw = json.dumps(profile()).encode()
            elif change == "target":
                adapter.target = False
            else:
                adapter.raw = runtime.canonical(dict(profile(), ssh_access_enabled=True))
            output = runtime.enroll(adapter, live=True)
            self.assertFalse(output["passed"])
            self.assertNotIn("guards", adapter.calls)
            self.assertNotIn("fresh", adapter.calls)
            self.assertEqual(adapter.states, [])

    def test_guard_missing_or_nonboolean_blocks_before_fresh_key_and_report(self):
        for key in runtime.GUARDS:
            for value in (False, 1, "true"):
                adapter = FixtureAdapter()
                adapter.facts[key] = value
                output = runtime.enroll(adapter, live=True)
                self.assertEqual(output["error"], "prepared_guards_blocked")
                self.assertNotIn("fresh", adapter.calls)
                self.assertEqual(adapter.states, [])

    def test_existing_state_key_or_report_is_preserved_without_state_transition(self):
        class Existing(FixtureAdapter):
            def fresh(self):
                self.calls.append("fresh")
                raise runtime.EnrollmentError("existing_artifact")
        adapter = Existing()
        output = runtime.enroll(adapter, live=True)
        self.assertEqual(output["error"], "existing_artifact")
        self.assertEqual(adapter.states, [])
        self.assertEqual(adapter.reports, [])
        self.assertNotIn("key", adapter.calls)

    def test_partial_failures_mark_only_owned_state_review_required_and_hide_errors(self):
        for failure in ("key", "observations", "report", "state:enrolled"):
            adapter = FixtureAdapter()
            adapter.failure = failure
            output = runtime.enroll(adapter, live=True)
            self.assertFalse(output["passed"])
            self.assertEqual(output["state"], "review-required")
            self.assertEqual(adapter.states[0][0], "pending")
            self.assertEqual(adapter.states[-1][0], "review-required")
            self.assertNotIn("PRIVATE", json.dumps(output))
        adapter = FixtureAdapter()
        adapter.failure = "state:pending"
        output = runtime.enroll(adapter, live=True)
        self.assertEqual(adapter.states, [])
        self.assertNotIn("key", adapter.calls)
        self.assertEqual(output["state"], "blocked")

    def test_cli_default_and_disallowed_options_are_closed_and_private_safe(self):
        for args, code in (([], 1), (["--profile", "PRIVATE_PATH"], 2), (["--key", "PRIVATE_KEY"], 2)):
            result = subprocess.run([sys.executable, "-I", str(SCRIPT), *args], capture_output=True, text=True, timeout=3)
            self.assertEqual(result.returncode, code)
            self.assertEqual(result.stderr, "")
            self.assertNotIn("PRIVATE", result.stdout)
            self.assertFalse(json.loads(result.stdout)["passed"])


class FilesTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.root.chmod(0o755)
        parent = self.root / "etc/inkyos-test-enrollment"
        (self.root / "etc").mkdir(mode=0o755)
        (self.root / "etc").chmod(0o755)
        parent.mkdir(mode=0o700)
        self.item = parent / "profile.json"
        self.item.write_bytes(runtime.canonical(profile()))
        self.item.chmod(0o600)
        self.files = runtime.Files(self.root, owner=os.getuid())
        self.addCleanup(self.files.close)
        self.directory = self.files.directory("/etc/inkyos-test-enrollment", private=True)
        self.addCleanup(os.close, self.directory)

    def test_bounded_private_reader_validates_exact_modes_and_types(self):
        self.assertEqual(self.files.read(runtime.PROFILE_PATH, private=True, mode=0o600), self.item.read_bytes())
        for mode in (0o644, 0o666):
            self.item.chmod(mode)
            with self.assertRaises(runtime.EnrollmentError):
                self.files.read(runtime.PROFILE_PATH, private=True, mode=0o600)
        self.item.chmod(0o600)
        self.item.parent.chmod(0o755)
        with self.assertRaises(runtime.EnrollmentError):
            self.files.read(runtime.PROFILE_PATH, private=True, mode=0o600)

    def test_reader_refuses_symlinks_hardlinks_fifo_large_and_mutating_input(self):
        outside = self.root / "outside"
        outside.write_bytes(b"SYNTHETIC")
        outside.chmod(0o600)
        for kind in ("symlink", "hardlink", "fifo"):
            self.item.unlink()
            if kind == "symlink":
                self.item.symlink_to(outside)
            elif kind == "hardlink":
                os.link(outside, self.item)
            else:
                os.mkfifo(self.item, 0o600)
            with self.assertRaises((runtime.EnrollmentError, OSError)):
                self.files.read(runtime.PROFILE_PATH, private=True, mode=0o600)
        self.item.unlink()
        self.item.write_bytes(b"x" * 4097)
        self.item.chmod(0o600)
        with self.assertRaises(runtime.EnrollmentError):
            self.files.read(runtime.PROFILE_PATH, private=True, mode=0o600)
        self.item.write_bytes(b"synthetic")
        original = os.read
        def mutate(fd, count):
            raw = original(fd, count)
            with self.item.open("ab") as stream:
                stream.write(b"x")
            return raw
        with mock.patch.object(runtime.os, "read", side_effect=mutate):
            with self.assertRaises(runtime.EnrollmentError):
                self.files.read(runtime.PROFILE_PATH, private=True, mode=0o600)

    def rename(self, directory, old, new):
        # Fixture-only equivalent on macOS; production uses Linux NOREPLACE.
        try:
            os.stat(new, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            os.rename(old, new, src_dir_fd=directory, dst_dir_fd=directory)
        else:
            raise runtime.EnrollmentError("existing_artifact")

    def test_atomic_new_state_and_owned_transition_fsync_then_preserve_foreign_change(self):
        stamp = runtime.write_atomic(self.directory, "state.json", b"pending", owner=os.getuid(), rename=self.rename)
        self.assertEqual((self.item.parent / "state.json").read_bytes(), b"pending")
        self.assertEqual(stat.S_IMODE((self.item.parent / "state.json").stat().st_mode), 0o600)
        stamp = runtime.write_atomic(self.directory, "state.json", b"enrolled", owner=os.getuid(), replace_stamp=stamp)
        (self.item.parent / "state.json").write_bytes(b"FOREIGN_STATE")
        with self.assertRaises(runtime.EnrollmentError):
            runtime.write_atomic(self.directory, "state.json", b"review-required", owner=os.getuid(), replace_stamp=stamp)
        self.assertEqual((self.item.parent / "state.json").read_bytes(), b"FOREIGN_STATE")

    def test_atomic_refuses_existing_report_symlink_and_temp_and_preserves_partial_temp(self):
        for name in ("report.json", ".other.json.tmp"):
            (self.item.parent / name).symlink_to(self.item)
        before = self.item.read_bytes()
        for name in ("report.json", "other.json"):
            with self.assertRaises((runtime.EnrollmentError, OSError)):
                runtime.write_atomic(self.directory, name, b"new", owner=os.getuid(), rename=self.rename)
        self.assertEqual(self.item.read_bytes(), before)
        def refuse(*_args):
            raise runtime.EnrollmentError("atomic_write_refused")
        with self.assertRaises(runtime.EnrollmentError):
            runtime.write_atomic(self.directory, "partial.json", b"partial", owner=os.getuid(), rename=refuse)
        self.assertEqual((self.item.parent / ".partial.json.tmp").read_bytes(), b"partial")
        self.assertFalse((self.item.parent / "partial.json").exists())

    def test_pending_ownership_is_recorded_even_if_directory_fsync_fails_after_publish(self):
        published = []
        original = os.fsync
        def failed_directory(fd):
            if fd == self.directory:
                raise OSError("synthetic fsync failure")
            original(fd)
        with mock.patch.object(runtime.os, "fsync", side_effect=failed_directory):
            with self.assertRaises(OSError):
                runtime.write_atomic(self.directory, "state.json", b"pending", owner=os.getuid(),
                                     rename=self.rename, published=published.append)
        self.assertEqual(len(published), 1)
        self.assertEqual((self.item.parent / "state.json").read_bytes(), b"pending")

    def test_native_key_method_uses_only_fake_keygen_and_never_opens_private_contents(self):
        adapter = runtime.NativeAdapter.__new__(runtime.NativeAdapter)
        adapter.private = self.directory
        private = self.item.parent / "ssh_host_ed25519_key"
        public = self.item.parent / "ssh_host_ed25519_key.pub"
        def fake_keygen(argv, timeout, limit):
            self.assertEqual(argv, runtime.KEYGEN)
            self.assertEqual((timeout, limit), (8, 4096))
            private.write_bytes(b"SYNTHETIC_PRIVATE_MUST_NOT_BE_OPENED")
            private.chmod(0o600)
            public.write_bytes((pub(b"h") + " inkyos-test-host\n").encode())
            public.chmod(0o600)
            return (0, b"")
        adapter.run = fake_keygen
        def read_public(path, **kwargs):
            self.assertEqual(path, runtime.HOST_KEY_PATH + ".pub")
            self.assertEqual(kwargs, {"limit": 256, "mode": 0o644, "private": True})
            self.assertEqual(stat.S_IMODE(public.stat().st_mode), 0o644)
            return public.read_bytes()
        adapter.files = SimpleNamespace(read=read_public)
        original_open, original_stat, original_fstat = os.open, os.stat, os.fstat
        def opened(path, *args, **kwargs):
            if path == "ssh_host_ed25519_key" or str(path) == str(private):
                raise AssertionError("Private key contents must never be opened")
            return original_open(path, *args, **kwargs)
        def metadata(path, *args, **kwargs):
            info = original_stat(path, *args, **kwargs)
            return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_nlink=info.st_nlink, st_size=info.st_size) if path == "ssh_host_ed25519_key" else info
        def fmetadata(fd):
            info = original_fstat(fd)
            return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_nlink=info.st_nlink)
        with mock.patch.object(runtime.os, "open", side_effect=opened), \
                mock.patch.object(runtime.os, "stat", side_effect=metadata), \
                mock.patch.object(runtime.os, "fstat", side_effect=fmetadata):
            self.assertEqual(adapter.key(), pub(b"h"))
        self.assertEqual(private.read_bytes(), b"SYNTHETIC_PRIVATE_MUST_NOT_BE_OPENED")

    def test_native_key_method_refuses_any_preexisting_key_or_public_link_before_keygen(self):
        adapter = runtime.NativeAdapter.__new__(runtime.NativeAdapter)
        adapter.private = self.directory
        adapter.run = mock.Mock(side_effect=AssertionError("No key regeneration"))
        for name in ("ssh_host_ed25519_key", "ssh_host_ed25519_key.pub"):
            path = self.item.parent / name
            path.symlink_to(self.item)
            with self.assertRaisesRegex(runtime.EnrollmentError, "^existing_artifact$"):
                adapter.key()
            self.assertTrue(path.is_symlink())
            path.unlink()
        adapter.run.assert_not_called()


class MountAndObservationsTests(unittest.TestCase):
    def test_real_fat_fd_mount_record_selected_among_sandbox_binds(self):
        rows = b"17 1 8:1 / /boot/firmware rw - vfat /dev/sda1 rw\n18 1 8:1 / /boot/firmware ro - vfat /dev/sda1 ro\n"
        self.assertTrue(runtime.mount_is_fat(rows, b"mnt_id:\t17\n", os.makedev(8, 1)))
        for mountinfo, fdinfo, device in ((rows, b"mnt_id:\t18\n", os.makedev(8, 1)),
            (rows.replace(b"vfat", b"ext4"), b"mnt_id:\t17\n", os.makedev(8, 1)),
            (rows + rows.splitlines(keepends=True)[0], b"mnt_id:\t17\n", os.makedev(8, 1)),
            (rows, b"mnt_id:\t17\nmnt_id:\t17\n", os.makedev(8, 1)),
            (rows, b"mnt_id:\t17\nmnt_id:\tmalformed\n", os.makedev(8, 1)),
            (rows, b"mnt_id:\t17\n", os.makedev(8, 2)), (b"malformed", b"mnt_id:\t17\n", 0)):
            self.assertFalse(runtime.mount_is_fat(mountinfo, fdinfo, device))

    def test_panel_reduction_exports_reviewed_public_tuple_only(self):
        panel = {"display_variant": 25, "panel_reference": "E640", "width": 600, "height": 400,
                 "color_code": 6, "color": "spectra6", "driver_class": "inky.inky_e640.Inky"}
        value = {"schema_version": 1, "kind": "test-panel-observation", "observation_source": "live-system",
                 "live_evidence": True, "passed": True, "status": "PASS", "panel": panel,
                 "activation_authorized": False, "hardware_qualified": False, "release_qualified": False,
                 "PRIVATE_LOG": "PRIVATE_KEY"}
        reduced = runtime.reduced_observation(value, "panel")
        self.assertEqual(reduced["status"], "observed")
        self.assertNotIn("PRIVATE", json.dumps(reduced))
        for change in ({"width": 800}, {"color_code": 5}, {"width": True}, {"PRIVATE_ID": 1}):
            self.assertEqual(runtime.reduced_observation(dict(value, panel=dict(panel, **change)), "panel")["status"], "blocked")
        for change in ({"live_evidence": False}, {"observation_source": "fixture"}, {"hardware_qualified": True}):
            self.assertEqual(runtime.reduced_observation(dict(value, **change), "panel")["status"], "blocked")

    def test_radio_reduction_never_promotes_blocked_tuple_to_qualification(self):
        value = {"schema_version": 1, "kind": "test-radio-observation", "observation_source": "live-system",
            "live_evidence": True, "passed": False, "status": "BLOCKED", "observations_complete": True,
            "firmware_tuple_qualified": False, "activation_authorized": False, "hardware_qualified": False,
            "release_qualified": False, "firmware": {"country_abbrev": "FR", "ccode": "Q2", "revision": 14},
            "kernel": {"global_country": "FR", "phy_country_label": "99", "phy_custom": True, "phy_self_managed": False},
            "channels_2_4ghz": [{"frequency_mhz": 2412, "channel": 1, "disabled": False, "max_tx_power_mbm": 2000, "flags": []}]}
        self.assertEqual(runtime.reduced_observation(value, "radio")["status"], "observed-unqualified")
        for change in ({"passed": True}, {"firmware_tuple_qualified": True}, {"observations_complete": False},
                       {"firmware": {"country_abbrev": "PRIVATE", "ccode": "FR", "revision": 14}}):
            self.assertEqual(runtime.reduced_observation(dict(value, **change), "radio")["status"], "blocked")
        changed = copy.deepcopy(value)
        changed["channels_2_4ghz"][0]["max_tx_power_mbm"] = True
        self.assertEqual(runtime.reduced_observation(changed, "radio")["status"], "blocked")

    def test_commands_only_synthetic_processes_bounded_and_errors_discarded(self):
        run = lambda source, **kw: runtime.command((sys.executable, "-I", "-c", source), timeout=kw.pop("timeout", 1), **kw)
        self.assertEqual(run("print('synthetic')"), (0, b"synthetic\n"))
        self.assertIsNone(run("print('x'*1000)", limit=32))
        started = time.monotonic()
        self.assertIsNone(run("import time; time.sleep(4)", timeout=0.05))
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(run("import sys; sys.stderr.write('PRIVATE'); sys.exit(1)"), (1, b""))

    def test_unit_has_bounded_boot_dependency_and_no_hidden_home_or_radio_or_unconditional_stop(self):
        unit = (ROOT / "overlay-test-enrollment/inkyos-test-enrollment.service").read_text()
        for fragment in ("Requires=inkyos-firstboot.service", "TimeoutStartSec=110s", "PrivateNetwork=false", "ProtectHome=false"):
            self.assertIn(fragment, unit)
        for fragment in ("ExecStartPost", "enable ", "unmask", "PrivateDevices", "NetworkManager.service"):
            self.assertNotIn(fragment, unit)


if __name__ == "__main__":
    unittest.main()
