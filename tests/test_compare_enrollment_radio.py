"""Synthetic wrapper fixtures, without private files, git, services or devices.

Current diagnostic interfaces exercise guard preservation. Historical byte-for-
byte wiring is a separate bench; unit fixtures do not claim hardware evidence.
"""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


compare = module("radio_compare_tests", "compare-enrollment-radio.py")
radio = module("radio_compare_parser_tests", "observe-test-radio.py")
detail = module("radio_compare_detail_tests", "detail-enrollment-observers.py")


def sample(token=b"2412.0"):
    country = struct.pack("<4si4s", b"XY\0\0", 0, b"XY\0\0") + bytes(8)
    firmware = struct.pack("<HHH", 6, 1, 20) + bytes(2) + struct.pack("<HH", 24, 2) + country
    return {"wiphy_index": 3, "firmware": firmware,
            "regulatory": b"global\ncountry 00: DFS-UNSET\nphy#3\ncountry 99: DFS-UNSET\n",
            "channels": b"Wiphy phy3\n * " + token + b" MHz [1] (20.0 dBm)\n"
                        b"\tHT Capability overrides:\n\t * short GI for 40 MHz\n"}


def historical_parser_fixture(raw, index):
    # Interface fixture for the historical integer-only rejection. This is
    # deliberately not shipped as a replacement historical implementation.
    if b".0 MHz" in raw:
        raise radio.ObservationError("kernel_observation_invalid")
    return radio.parse_channels(raw, index)


def old_radio(values=None):
    reader = Mock(return_value=sample() if values is None else values)
    namespace = dict(vars(radio), parse_channels=historical_parser_fixture,
                     ProductionAdapter=lambda: SimpleNamespace(sample=reader))
    return namespace, reader


def configured():
    v2 = vars(module("radio_compare_detail_fixture", "detail-enrollment-observers.py"))
    compare.configure(v2, radio.parse_channels, "a" * 64)
    v1 = v2["compile_v1"]((ROOT / "scripts/diagnose-enrollment-observers.py").read_bytes())
    return v2, v1


class FixtureAdapter:
    def __init__(self, v1):
        self.calls, self.saved = [], []
        self.radio, self.sample_reader = old_radio()
        self.facts = {key: True for key in v1["GUARD_CHECKS"]}
        self.radio["PreparedGuard"] = lambda: SimpleNamespace(collect=lambda: self.facts)

    def environment(self): return True
    def fresh(self): self.calls.append("fresh")
    def pin_sources(self): self.calls.append("pins")
    def enrollment(self): return True
    def identity(self): return True
    def inactive_guards(self): return True
    def start_firstboot(self): self.calls.append("start"); return True
    def firstboot_success(self): return True
    def unchanged(self): self.calls.append("unchanged"); return True
    def wait_devices(self): return {"i2c1_present": True, "wlan0_present": True}
    def report(self, result): self.saved.append(copy.deepcopy(result))
    def close(self): self.calls.append("close")


class RadioComparisonTests(unittest.TestCase):
    def test_exact_public_pins_and_corrected_source_compile_without_live_io(self):
        self.assertEqual(compare.V2_SHA256, "33421c00f8368ef92e09141b10f28ec33c3392afbba9e53bf6bf776c3e858512")
        raw = (ROOT / "scripts/observe-test-radio.py").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), compare.PARSER_SHA256)
        with patch("subprocess.Popen", side_effect=AssertionError("live I/O")):
            parsed = compare.compile_pinned(raw, compare.PARSER_PATH, compare.PARSER_SHA256)
            self.assertEqual(parsed["parse_channels"](sample()["channels"], 3)[0]["frequency_mhz"], 2412)

    def test_corrupt_source_rejected_before_exec(self):
        for raw in (b"raise Exception('SECRET')", None, bytearray(b"SECRET")):
            with self.subTest(raw=type(raw)), patch("builtins.exec") as execute:
                with self.assertRaisesRegex(compare.ComparisonError, "source_pin_invalid"):
                    compare.compile_pinned(raw, compare.V2_PATH, compare.V2_SHA256)
                execute.assert_not_called()

    def test_one_sample_dot_zero_and_ht_prose_preserve_baseline_failure(self):
        namespace, reader = old_radio()
        baseline = detail.radio_detail(namespace, lambda: sample())
        observed = []
        def corrected(raw, index):
            observed.append((raw, index))
            return radio.parse_channels(raw, index)
        result = compare.compare_radio(detail.radio_detail, corrected, namespace)
        reader.assert_called_once_with()
        self.assertIs(observed[0][0], reader.return_value["channels"])
        self.assertEqual(observed[0][1], reader.return_value["wiphy_index"])
        self.assertTrue(result.pop("same_sample"))
        correction = result.pop("corrected_channels")
        self.assertEqual(result, baseline)
        self.assertEqual(result["channels"]["error"], "kernel_observation_invalid")
        self.assertIsNone(correction["error"])
        self.assertEqual(correction["data"][0]["frequency_mhz"], 2412)
        self.assertFalse(result["firmware_tuple_qualified"])

    def test_integer_baseline_and_corrected_channels_agree(self):
        namespace, reader = old_radio(sample(b"2412"))
        result = compare.compare_radio(detail.radio_detail, radio.parse_channels, namespace)
        self.assertEqual(result["channels"]["data"], result["corrected_channels"]["data"])
        reader.assert_called_once_with()

    def test_fraction_duplicates_and_unknown_flags_remain_closed(self):
        cases = [sample(token) for token in (b"2412.1", b"2412.00", b"+2412", b"2412e0")]
        duplicate = sample()
        duplicate["channels"] += b" * 2412 MHz [1] (20.0 dBm)\n"
        cases.append(duplicate)
        secret = sample()
        secret["channels"] = b"Wiphy PRIVATE_NAME\n * 2412 MHz [1] (20.0 dBm) (SECRET_FLAG)\n"
        cases.append(secret)
        for values in cases:
            namespace, reader = old_radio(values)
            result = compare.compare_radio(detail.radio_detail, radio.parse_channels, namespace)
            self.assertTrue(result["same_sample"])
            self.assertEqual(result["corrected_channels"], {"error": "kernel_observation_invalid", "data": None})
            self.assertNotIn("SECRET", json.dumps(result))
            self.assertNotIn("PRIVATE", json.dumps(result))
            reader.assert_called_once_with()

    def test_sample_failure_or_bad_mapping_never_retries_or_parses_correction(self):
        for bad in ({**sample(), "wiphy_index": True}, {**sample(), "extra": "SECRET"},
                    {**sample(), "channels": b""}, {**sample(), "channels": b"x" * 16385}):
            namespace, reader = old_radio(bad)
            corrected = Mock(side_effect=AssertionError("must not parse"))
            result = compare.compare_radio(detail.radio_detail, corrected, namespace)
            self.assertFalse(result["same_sample"])
            self.assertIsNotNone(result["sample_error"])
            corrected.assert_not_called()
            reader.assert_called_once_with()
        namespace, reader = old_radio()
        reader.side_effect = OSError("PRIVATE_PATH SECRET")
        result = compare.compare_radio(detail.radio_detail, Mock(), namespace)
        self.assertEqual(result["sample_error"], "observation_unavailable")
        self.assertFalse(result["same_sample"])
        self.assertNotIn("SECRET", json.dumps(result))
        reader.assert_called_once_with()

    def test_correction_exception_is_enum_only_and_baseline_kept(self):
        namespace, _ = old_radio(sample(b"2412"))
        corrected = Mock(side_effect=RuntimeError("SECRET PRIVATE_PATH"))
        result = compare.compare_radio(detail.radio_detail, corrected, namespace)
        self.assertIsNotNone(result["channels"]["data"])
        self.assertEqual(result["corrected_channels"], {"error": "observation_unavailable", "data": None})
        self.assertNotIn("SECRET", json.dumps(result))

    def test_radio_only_preserves_native_type_and_all_other_guard_methods(self):
        v2, v1 = configured()
        native = v1["NativeAdapter"].__new__(v1["NativeAdapter"])
        native.report = Mock()
        methods = {name: getattr(native, name).__func__ for name in (
            "environment", "fresh", "enrollment", "identity", "inactive_guards",
            "start_firstboot", "firstboot_success", "wait_devices", "close")}
        self.assertIs(v2["attach_details"](v1, native), native)
        self.assertIs(type(native), v1["NativeAdapter"])
        for name, method in methods.items():
            self.assertIs(getattr(native, name).__func__, method)
        # A radio-only probe needs no panel module, source, bus or driver.
        fixture = FixtureAdapter(v1)
        v2["attach_details"](v1, fixture)
        with patch("builtins.exec", side_effect=AssertionError("no panel imports")):
            result = fixture.probes()
        self.assertEqual(result["panel"], {"error": "not_requested", "data": None})
        fixture.sample_reader.assert_called_once_with()

    def test_every_observer_guard_blocks_sampling_including_truthy_nonboolean(self):
        for bad in (False, 1, "true", None):
            v2, v1 = configured()
            for key in v1["GUARD_CHECKS"]:
                fixture = FixtureAdapter(v1)
                fixture.facts[key] = bad
                v2["attach_details"](v1, fixture)
                result = fixture.probes()
                self.assertEqual(result["radio"]["sample_error"], "guards_blocked")
                fixture.sample_reader.assert_not_called()

    def test_pins_checked_before_start_and_failure_never_exports_error_text(self):
        v2, v1 = configured()
        fixture = v2["attach_details"](v1, FixtureAdapter(v1))
        with patch.object(compare, "read_pinned", side_effect=OSError("SECRET")):
            result = v1["diagnose"](fixture)
        self.assertEqual(result["error"], "source_pin_invalid")
        self.assertNotIn("start", fixture.calls)
        fixture.sample_reader.assert_not_called()
        self.assertNotIn("SECRET", json.dumps(result))

    def test_fat_change_after_start_or_after_sample_blocks_completion(self):
        for failure_call in (5, 9):
            v2, v1 = configured()
            fixture = v2["attach_details"](v1, FixtureAdapter(v1))
            count = 0
            def read(*_):
                nonlocal count
                count += 1
                if count == failure_call:
                    raise OSError("PRIVATE")
                return b"pinned"
            with patch.object(compare, "read_pinned", side_effect=read):
                result = v1["diagnose"](fixture)
            self.assertEqual(result["error"], "state_changed")
            self.assertFalse(result["completed"])
            self.assertEqual(fixture.sample_reader.call_count, 0 if failure_call == 5 else 1)

    def test_existing_state_guard_failure_is_not_overridden(self):
        v2, v1 = configured()
        fixture = FixtureAdapter(v1)
        fixture.unchanged = lambda: False
        v2["attach_details"](v1, fixture)
        with patch.object(compare, "read_pinned") as read:
            self.assertFalse(fixture.unchanged())
        read.assert_not_called()

    def test_completed_fixture_is_not_live_or_qualified_and_report_matches_names(self):
        v2, v1 = configured()
        fixture = v2["attach_details"](v1, FixtureAdapter(v1))
        with patch.object(compare, "read_pinned", return_value=b"pinned") as read:
            result = v1["diagnose"](fixture)
        self.assertTrue(result["completed"])
        self.assertEqual(read.call_count, 12)
        self.assertEqual(read.call_args_list[-1].args, (compare.SELF_PATH, "a" * 64))
        for key in ("live_evidence", "activation_authorized", "hardware_qualified", "release_qualified"):
            self.assertFalse(result[key])
        self.assertEqual(fixture.saved[0]["kind"], compare.KIND)
        self.assertEqual(fixture.saved[0]["v2_source_sha256"], compare.V2_SHA256)
        self.assertEqual(fixture.saved[0]["corrected_parser_sha256"], compare.PARSER_SHA256)
        self.assertEqual(fixture.saved[0]["comparison_source_sha256"], "a" * 64)
        self.assertEqual((v1["REPORT"], v1["CLAIM"]), (compare.REPORT, compare.CLAIM))

    def test_four_replay_names_refused_and_old_artifacts_preserved(self):
        v2, v1 = configured()
        names = (compare.REPORT, "." + compare.REPORT + ".tmp", compare.CLAIM, "." + compare.CLAIM + ".tmp")
        for name in names:
            with tempfile.TemporaryDirectory() as tmp:
                old = Path(tmp) / "inkyos-observer-detail.json"
                old.write_bytes(b"preserve")
                (Path(tmp) / name).write_bytes(b"claim")
                native = v1["NativeAdapter"].__new__(v1["NativeAdapter"])
                native.files = SimpleNamespace(directory=lambda *a, **k: os.open(tmp, os.O_RDONLY), close=lambda: None)
                native.runtime, native.boot = {}, None
                try:
                    with self.assertRaisesRegex(v1["DiagnosticError"], "existing_diagnostic"):
                        native.fresh()
                    self.assertEqual(old.read_bytes(), b"preserve")
                    self.assertEqual((Path(tmp) / name).read_bytes(), b"claim")
                finally:
                    native.close()

    def test_cli_rejects_arguments_wrong_target_and_loader_errors_without_echo(self):
        cases = [(["--root", "PRIVATE"], "invalid_arguments", "linux"),
                 ([], "target_unverified", "darwin"),
                 ([], "comparison_unavailable", "linux")]
        for args, expected, system in cases:
            output = io.StringIO()
            with patch.object(compare.sys, "platform", system), patch.object(compare.os, "geteuid", return_value=0), \
                    patch.object(compare.platform, "machine", return_value="aarch64"), \
                    patch.object(compare, "read_pinned", side_effect=OSError("PRIVATE SECRET")) as read, \
                    patch("sys.stdout", output):
                self.assertEqual(compare.main(args), 1)
            self.assertEqual(json.loads(output.getvalue())["error"], expected)
            self.assertNotIn("PRIVATE", output.getvalue())
            self.assertNotIn("SECRET", output.getvalue())
            if expected != "comparison_unavailable":
                read.assert_not_called()

    def test_wrapper_snapshot_digest_is_required_and_rechecked_before_start(self):
        for bad in (None, True, "", "G" * 64, "a" * 63):
            with self.assertRaises(compare.ComparisonError):
                compare.configure({}, radio.parse_channels, bad)
        v2, v1 = configured()
        fixture = v2["attach_details"](v1, FixtureAdapter(v1))
        def read(path, digest):
            if path == compare.SELF_PATH:
                raise compare.ComparisonError("source_pin_invalid")
            return b"pinned"
        with patch.object(compare, "read_pinned", side_effect=read):
            result = v1["diagnose"](fixture)
        self.assertEqual(result["error"], "source_pin_invalid")
        self.assertNotIn("start", fixture.calls)

    def test_main_snapshots_wrapper_and_only_passes_corrected_parser(self):
        source = b"synthetic snapshot"
        parsed = {"parse_channels": radio.parse_channels,
                  "ProductionAdapter": Mock(side_effect=AssertionError("unused"))}
        entry = Mock(return_value=0)
        with patch.object(compare.sys, "platform", "linux"), patch.object(compare.os, "geteuid", return_value=0), \
                patch.object(compare.platform, "machine", return_value="aarch64"), \
                patch.object(compare, "read_pinned", return_value=source) as read, \
                patch.object(compare, "compile_pinned", side_effect=[{"v2": True}, parsed]), \
                patch.object(compare, "configure", return_value={"main": entry}) as configure:
            self.assertEqual(compare.main([]), 0)
        self.assertEqual(read.call_args_list[0].args, (compare.SELF_PATH, None))
        configure.assert_called_once_with({"v2": True}, radio.parse_channels, hashlib.sha256(source).hexdigest())
        entry.assert_called_once_with([])
        parsed["ProductionAdapter"].assert_not_called()


class PinnedLoaderTests(unittest.TestCase):
    def setUp(self):
        self.raw = b"value = 1\n"
        self.digest = hashlib.sha256(self.raw).hexdigest()
        self.parent = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
        self.fat = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o777)
        self.file = SimpleNamespace(st_dev=1, st_ino=4, st_mode=stat.S_IFREG | 0o755,
            st_uid=0, st_gid=0, st_nlink=1, st_size=len(self.raw), st_mtime_ns=1, st_ctime_ns=1)

    def read(self, *, files=None, current=None, reads=None, opens=None):
        statuses = {1: self.parent, 2: self.parent, 3: self.fat, 4: self.file}
        if files:
            statuses.update(files)
        with patch.object(compare.os, "open", side_effect=opens or [1, 2, 3, 4]) as opened, \
                patch.object(compare.os, "fstat", side_effect=lambda fd: statuses[fd]), \
                patch.object(compare.os, "stat", return_value=current or self.file), \
                patch.object(compare.os, "read", side_effect=reads or [self.raw, b""]) as reader, \
                patch.object(compare.os, "close") as closed:
            result = compare.read_pinned(compare.V2_PATH, self.digest)
        return result, opened, reader, closed

    def test_no_follow_readonly_parent_fds_and_all_descriptors_closed(self):
        raw, opened, _, closed = self.read()
        self.assertEqual(raw, self.raw)
        for call in opened.call_args_list:
            self.assertEqual(call.args[1] & os.O_ACCMODE, os.O_RDONLY)
            self.assertTrue(call.args[1] & os.O_NOFOLLOW)
        self.assertEqual([call.kwargs.get("dir_fd") for call in opened.call_args_list], [None, 1, 2, 3])
        self.assertEqual([call.args[0] for call in closed.call_args_list], [1, 2, 4, 3])

    def test_owner_type_links_size_and_path_replacement_refused(self):
        for changes in ({"st_uid": 501}, {"st_mode": stat.S_IFLNK | 0o777}, {"st_nlink": 2},
                        {"st_size": 0}, {"st_size": compare.MAX_SOURCE + 1}):
            bad = SimpleNamespace(**{**vars(self.file), **changes})
            with self.subTest(changes=changes), self.assertRaises(compare.ComparisonError):
                self.read(files={4: bad})
        replaced = SimpleNamespace(**{**vars(self.file), "st_ino": 99})
        with self.assertRaises(compare.ComparisonError):
            self.read(current=replaced)
        for fd, bad in ((1, SimpleNamespace(st_uid=501, st_mode=0o755)),
                        (2, SimpleNamespace(st_uid=0, st_mode=0o777)),
                        (3, SimpleNamespace(st_uid=501, st_mode=0o777))):
            with self.assertRaises(compare.ComparisonError):
                self.read(files={fd: bad})

    def test_short_changed_or_oversized_source_rejected(self):
        for raw in (self.raw[:-1], b"x" * len(self.raw), b"x" * (compare.MAX_SOURCE + 1)):
            with self.assertRaises(compare.ComparisonError):
                self.read(reads=[raw, b""])

    def test_failed_open_closes_parent_and_traversal_is_refused(self):
        with patch.object(compare.os, "open", side_effect=[1, OSError("symlink")]), \
                patch.object(compare.os, "fstat", return_value=self.parent), \
                patch.object(compare.os, "close") as close:
            with self.assertRaises(OSError):
                compare.read_pinned(compare.V2_PATH, self.digest)
            close.assert_called_once_with(1)
        with patch.object(compare.os, "open") as opened:
            for path in ("/etc/SECRET", "/boot/firmware/../SECRET", "/boot/firmware/dir/file"):
                with self.assertRaises(compare.ComparisonError):
                    compare.read_pinned(path, self.digest)
            opened.assert_not_called()


if __name__ == "__main__":
    unittest.main()
