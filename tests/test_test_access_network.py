"""Country transaction fixtures; never change any host clock, network or radio."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("test_country_access", ROOT / "scripts/test-access-network.py")
country = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(country)


def observation():
    firmware = {"country_abbrev": "FR", "ccode": "FR", "revision": 0}
    kernel = {"global_country": "FR", "phy_country_label": "99", "phy_custom": False, "phy_self_managed": False}
    channels = [{"channel": number, "frequency_mhz": 2484 if number == 14 else 2407 + 5 * number,
                 "disabled": number == 14, "max_tx_power_mbm": None if number == 14 else 2000,
                 "flags": []} for number in range(1, 15)]
    return firmware, kernel, channels


class FixtureAdapter:
    def __init__(self):
        self.calls, self.values, self.failures = [], {}, {}
        self.seconds = 10.0

    def clock(self): return self.seconds
    def call(self, name, default=None):
        self.calls.append(name)
        if name in self.failures:
            raise self.failures[name]
        value = self.values.get(name, default)
        return value.pop(0) if type(value) is list else value
    def target(self): return self.call("target", True)
    def pin_sources(self): return self.call("pins")
    def lock(self): return self.call("lock")
    def prepared(self): return self.call("guards", True)
    def wifi_closed(self): return self.call("wifi", True)
    def mapping(self): return self.call("mapping", 3)
    def unchanged(self): return self.call("unchanged", True)
    def apply_country(self): return self.call("apply", True)
    def observe(self): return self.call("observe", (3, *observation()))
    def close(self): return self.call("close")
    def run(self, requested="FR"):
        return country.setup_country(self, country=requested, monotonic=self.clock)


class PolicyTests(unittest.TestCase):
    def test_fr_readback_with_custom_phy_is_test_only(self):
        for label in ("FR", "99"):
            fw, kernel, channels = observation()
            kernel["phy_country_label"] = label
            self.assertTrue(all(country.evaluate(fw, kernel, channels).values()))

    def test_firmware_codes_revision_types_and_extra_fields_fail(self):
        fw, kernel, channels = observation()
        for bad in ({**fw, "country_abbrev": "XY"}, {**fw, "ccode": "X2"},
                    {**fw, "country_abbrev": True}, {**fw, "revision": True},
                    {**fw, "revision": 0.0}, {**fw, "revision": -2}, {**fw, "revision": 65536},
                    {**fw, "SECRET": "private"}):
            self.assertFalse(all(country.evaluate(bad, kernel, channels).values()))
        for revision in (-1, 65535):
            self.assertTrue(all(country.evaluate({**fw, "revision": revision}, kernel, channels).values()))

    def test_global_and_phy_are_separate_strict_conditions(self):
        fw, kernel, channels = observation()
        for bad in ({**kernel, "global_country": "00"}, {**kernel, "phy_country_label": "98"},
                    {**kernel, "phy_country_label": "PRIVATE"}, {**kernel, "phy_custom": 1},
                    {**kernel, "phy_self_managed": True}, {**kernel, "extra": "SECRET"}):
            self.assertFalse(all(country.evaluate(fw, bad, channels).values()))

    def test_all_fourteen_channels_required_in_order_with_valid_frequency(self):
        fw, kernel, channels = observation()
        cases = [channels[:-1], channels + [channels[-1]], tuple(channels), channels[::-1]]
        for change in ({"channel": True}, {"channel": 1.0}, {"frequency_mhz": 2412.0},
                       {"frequency_mhz": 2417}, {"disabled": 0}, {"extra": "SECRET"}):
            value = copy.deepcopy(channels)
            value[0].update(change)
            cases.append(value)
        for value in cases:
            self.assertFalse(country.evaluate(fw, kernel, value)["channels_test_fr"])

    def test_channel_fourteen_must_be_disabled_and_power_bounded_integer(self):
        fw, kernel, channels = observation()
        for power in (True, 2000.0, "2000", -1, 2001, None):
            value = copy.deepcopy(channels)
            value[0]["max_tx_power_mbm"] = power
            self.assertFalse(country.evaluate(fw, kernel, value)["channels_test_fr"])
        for change in ({"disabled": False, "max_tx_power_mbm": 1000},
                       {"max_tx_power_mbm": 0}, {"flags": ["no IR"]}):
            value = copy.deepcopy(channels)
            value[-1].update(change)
            self.assertFalse(country.evaluate(fw, kernel, value)["channels_test_fr"])

    def test_flags_are_closed_and_at_least_one_channel_can_initiate(self):
        fw, kernel, channels = observation()
        for flags in (["SECRET"], ["no IR", "no IR"], [True], "no IR", {"no IR"}):
            value = copy.deepcopy(channels)
            value[0]["flags"] = flags
            self.assertFalse(country.evaluate(fw, kernel, value)["channels_test_fr"])
        for row in channels[:-1]:
            row["flags"] = ["no IR"]
        self.assertFalse(country.evaluate(fw, kernel, channels)["channels_test_fr"])
        channels[0]["flags"] = ["no ibss"]
        self.assertTrue(country.evaluate(fw, kernel, channels)["channels_test_fr"])


class TransactionTests(unittest.TestCase):
    def test_single_setter_order_no_global_qualification_or_connection_grant(self):
        adapter = FixtureAdapter()
        result = adapter.run()
        self.assertTrue(result["test_country_ready"])
        self.assertTrue(result["wifi_closed_verified"])
        self.assertEqual(adapter.calls, ["target", "pins", "lock", "guards", "wifi", "mapping", "unchanged",
            "apply", "wifi", "observe", "guards", "wifi", "mapping", "unchanged", "close"])
        for key in ("live_evidence", "firmware_tuple_qualified", "connection_authorized",
                    "activation_authorized", "hardware_qualified", "release_qualified"):
            self.assertFalse(result[key])

    def test_invalid_arguments_never_touch_system_or_echo_input(self):
        for requested in (None, True, "FR;reboot", "US", "PRIVATE"):
            adapter = FixtureAdapter()
            result = adapter.run(requested)
            self.assertEqual(adapter.calls, ["close"])
            self.assertEqual(result["error"], "invalid_arguments")
            self.assertNotIn("PRIVATE", json.dumps(result))

    def test_each_precondition_failure_prevents_country_mutation(self):
        for method, value in (("target", False), ("target", 1), ("guards", False),
                              ("wifi", False), ("mapping", True), ("mapping", 256), ("unchanged", False)):
            adapter = FixtureAdapter()
            adapter.values[method] = value
            result = adapter.run()
            self.assertFalse(result["test_country_ready"])
            self.assertFalse(result["country_set_attempted"])
            self.assertNotIn("apply", adapter.calls)
            self.assertEqual(adapter.calls[-1], "close")
        for method in ("pins", "lock"):
            adapter = FixtureAdapter()
            adapter.failures[method] = country.AccessError("source_pin_invalid" if method == "pins" else "lock_busy")
            self.assertFalse(adapter.run()["country_set_attempted"])
            self.assertNotIn("apply", adapter.calls)

    def test_country_ack_is_not_readback_and_is_never_retried(self):
        adapter = FixtureAdapter()
        adapter.values["apply"] = False
        result = adapter.run()
        self.assertTrue(result["country_set_attempted"])
        self.assertFalse(result["country_request_acknowledged"])
        self.assertEqual(result["error"], "country_request_failed")
        self.assertEqual(adapter.calls.count("apply"), 1)
        self.assertNotIn("observe", adapter.calls)
        adapter = FixtureAdapter()
        index, fw, kernel, channels = (3, *observation())
        fw["ccode"] = "XY"
        adapter.values["observe"] = (index, fw, kernel, channels)
        result = adapter.run()
        self.assertEqual(result["error"], "country_unconfirmed")
        self.assertTrue(result["country_request_acknowledged"])
        self.assertFalse(result["test_country_ready"])

    def test_state_or_mapping_change_after_setter_blocks_readiness(self):
        scenarios = [("wifi", [True, False]), ("wifi", [True, True, False]),
                     ("guards", [True, False]), ("mapping", [3, 4]),
                     ("mapping", [3, True]), ("unchanged", [True, False])]
        for key, value in scenarios:
            adapter = FixtureAdapter()
            adapter.values[key] = value
            result = adapter.run()
            self.assertTrue(result["country_set_attempted"])
            self.assertFalse(result["test_country_ready"])
            self.assertFalse(result["wifi_closed_verified"])
            self.assertIsNotNone(result["error"])
            self.assertEqual(adapter.calls[-1], "close")
        adapter = FixtureAdapter()
        adapter.values["observe"] = (4, *observation())
        self.assertEqual(adapter.run()["error"], "wlan0_mapping_unverified")

    def test_interruption_and_private_errors_release_lock_without_ready(self):
        for operation in ("pins", "lock", "apply", "observe", "guards"):
            for failure in (KeyboardInterrupt(), SystemExit("SECRET"), OSError("PRIVATE SECRET")):
                adapter = FixtureAdapter()
                adapter.failures[operation] = failure
                result = adapter.run()
                self.assertFalse(result["test_country_ready"])
                self.assertEqual(adapter.calls[-1], "close")
                self.assertNotIn("SECRET", json.dumps(result))
                self.assertNotIn("PRIVATE", json.dumps(result))

    def test_bad_structured_observation_never_exports_extra_or_raw_fields(self):
        adapter = FixtureAdapter()
        fw, kernel, channels = observation()
        fw["identity"] = "PRIVATE_MAC"
        kernel["ssid"] = "SECRET"
        channels[0]["raw"] = "SECRET"
        adapter.values["observe"] = (3, fw, kernel, channels)
        result = adapter.run()
        self.assertEqual(result["error"], "country_unconfirmed")
        self.assertIsNone(result["firmware"])
        self.assertIsNone(result["kernel"])
        self.assertIsNone(result["channels_2_4ghz"])
        self.assertNotIn("SECRET", json.dumps(result))

    def test_timeout_after_possible_mutation_cannot_claim_success(self):
        adapter = FixtureAdapter()
        def stalled():
            adapter.calls.append("apply")
            adapter.seconds += country.BUDGET
            return True
        adapter.apply_country = stalled
        result = adapter.run()
        self.assertEqual(result["error"], "runtime_timeout")
        self.assertTrue(result["country_set_attempted"])
        self.assertFalse(result["country_request_acknowledged"])
        self.assertFalse(result["test_country_ready"])
        self.assertEqual(adapter.calls[-1], "close")

    def test_close_failure_revokes_ready_and_is_closed(self):
        adapter = FixtureAdapter()
        adapter.failures["close"] = OSError("PRIVATE")
        result = adapter.run()
        self.assertFalse(result["test_country_ready"])
        self.assertEqual(result["error"], "observation_unavailable")
        self.assertNotIn("PRIVATE", json.dumps(result))


class NativeAdapterTests(unittest.TestCase):
    def test_source_pins_compile_without_any_child_process(self):
        with patch("subprocess.Popen", side_effect=AssertionError("no child")):
            for path, digest in country.PINS.items():
                raw = (ROOT / "scripts" / Path(path).name).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
                self.assertIn("__name__", country.compile_source(raw, path))
                with patch("builtins.exec") as execute:
                    with self.assertRaisesRegex(country.AccessError, "source_pin_invalid"):
                        country.compile_source(raw + b"\n", path)
                    execute.assert_not_called()

    def test_linux_root_aarch64_little_endian_exact_pi_required(self):
        with patch.object(country.sys, "platform", "linux"), patch.object(country.os, "geteuid", return_value=0), \
                patch.object(country.platform, "machine", return_value="aarch64"), \
                patch.object(country.sys, "byteorder", "little"), \
                patch.object(country, "read_source", return_value=country.PI_MODEL) as read:
            self.assertTrue(country.NativeAdapter().target())
            read.assert_called_once_with(country.MODEL, limit=128, mode=None)
            read.return_value = b"Raspberry Pi 4 Model B\0"
            self.assertFalse(country.NativeAdapter().target())
            read.reset_mock()
            with patch.object(country.os, "geteuid", return_value=501):
                self.assertFalse(country.NativeAdapter().target())
            read.assert_not_called()

    def test_only_country_set_command_and_strict_empty_success(self):
        adapter = country.NativeAdapter()
        adapter.command = Mock(return_value=b"")
        self.assertTrue(adapter.apply_country())
        adapter.command.assert_called_once_with(("/usr/sbin/iw", "reg", "set", "FR"))
        adapter.command.return_value = b"unexpected SECRET"
        self.assertFalse(adapter.apply_country())

    def test_nm_active_wireless_disabled_no_active_connections_no_link_required(self):
        adapter = country.NativeAdapter()
        helper = country.compile_source((ROOT / "scripts/test-lan-preflight.py").read_bytes(), country.HELPER)
        adapter.helper = helper
        good = {country.NM_SERVICE: b"ActiveState=active\nSubState=running\nLoadState=loaded\n",
                country.WIFI_STATE: b"v b false\n", country.ACTIVE_CONNECTIONS: b"v ao 0\n",
                country.LINK_STATE: b"Not connected.\n"}
        adapter.command = lambda argv: good[argv]
        self.assertTrue(adapter.wifi_closed())
        for key, bad in ((country.NM_SERVICE, b"ActiveState=inactive\nSubState=dead\nLoadState=loaded\n"),
                         (country.WIFI_STATE, b"v b true\n"), (country.ACTIVE_CONNECTIONS, b"v ao 1 PRIVATE\n"),
                         (country.LINK_STATE, b"Connected to PRIVATE\n")):
            adapter.command = lambda argv, key=key, bad=bad: bad if argv == key else good[argv]
            self.assertFalse(adapter.wifi_closed())

    def test_command_timeout_is_bounded_and_expired_budget_runs_nothing(self):
        adapter = country.NativeAdapter()
        runner = Mock(return_value=b"")
        adapter.radio = {"bounded_command": runner}
        adapter.deadline, adapter.monotonic = 11.0, lambda: 10.0
        self.assertEqual(adapter.command(country.SET_FR, timeout=50, limit=100000), b"")
        runner.assert_called_once_with(country.SET_FR, data=None, timeout=1.0, limit=country.MAX_OUTPUT)
        runner.reset_mock()
        adapter.monotonic = lambda: 11.0
        with self.assertRaisesRegex(country.AccessError, "runtime_timeout"):
            adapter.command(country.SET_FR)
        runner.assert_not_called()
        adapter.monotonic = lambda: 10.0
        runner.return_value = None
        with self.assertRaisesRegex(country.AccessError, "observation_unavailable"):
            adapter.command(country.SET_FR)

    def test_lock_is_exclusive_root_owned_nofollow_and_released(self):
        info = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o600, st_uid=0,
            st_gid=0, st_nlink=1, st_size=0, st_mtime_ns=1, st_ctime_ns=1)
        with patch.object(country, "directory", return_value=10), \
                patch.object(country.os, "open", return_value=11) as opened, \
                patch.object(country.os, "fstat", return_value=info), \
                patch.object(country.os, "stat", return_value=info), \
                patch.object(country.fcntl, "flock") as flock, patch.object(country.os, "close") as close:
            adapter = country.NativeAdapter()
            adapter.lock()
            self.assertTrue(opened.call_args.args[1] & os.O_NOFOLLOW)
            self.assertEqual(opened.call_args.kwargs, {"dir_fd": 10})
            flock.assert_called_once_with(11, country.fcntl.LOCK_EX | country.fcntl.LOCK_NB)
            adapter.close()
            self.assertEqual([item.args[0] for item in close.call_args_list], [11, 10])

    def test_busy_or_replaced_lock_refused(self):
        info = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o600, st_uid=0,
            st_gid=0, st_nlink=1, st_size=0, st_mtime_ns=1, st_ctime_ns=1)
        with patch.object(country, "directory", return_value=10), patch.object(country.os, "open", return_value=11), \
                patch.object(country.os, "fstat", return_value=info), patch.object(country.os, "close"), \
                patch.object(country.fcntl, "flock", side_effect=BlockingIOError):
            adapter = country.NativeAdapter()
            with self.assertRaisesRegex(country.AccessError, "lock_busy"):
                adapter.lock()
            adapter.close()
        replaced = SimpleNamespace(**{**vars(info), "st_ino": 8})
        with patch.object(country, "directory", return_value=10), patch.object(country.os, "open", return_value=11), \
                patch.object(country.os, "fstat", return_value=info), patch.object(country.os, "stat", return_value=replaced), \
                patch.object(country.os, "close"), patch.object(country.fcntl, "flock"):
            adapter = country.NativeAdapter()
            with self.assertRaisesRegex(country.AccessError, "lock_invalid"):
                adapter.lock()
            adapter.close()

    def test_cli_has_no_fixture_root_country_alias_or_mutation_without_explicit_flag(self):
        for args in ([], ["--fixture"], ["--root", "PRIVATE"], ["--apply-country", "US"], ["--apply-country", "FR", "SECRET"]):
            output = io.StringIO()
            with patch.object(country, "NativeAdapter") as native, patch("sys.stdout", output):
                self.assertEqual(country.main(args), 1)
            native.assert_not_called()
            self.assertFalse(json.loads(output.getvalue())["test_country_ready"])
            self.assertNotIn("PRIVATE", output.getvalue())
            self.assertNotIn("SECRET", output.getvalue())


class SourceReaderTests(unittest.TestCase):
    def setUp(self):
        self.raw = b"reviewed source\n"
        self.info = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o555, st_uid=0,
            st_gid=0, st_nlink=1, st_size=len(self.raw), st_mtime_ns=1, st_ctime_ns=1)

    def read(self, info=None, current=None, chunks=None):
        with patch.object(country, "directory", return_value=10), patch.object(country.os, "open", return_value=11) as opened, \
                patch.object(country.os, "fstat", return_value=info or self.info), \
                patch.object(country.os, "stat", return_value=current or self.info), \
                patch.object(country.os, "read", side_effect=chunks or [self.raw, b""]), \
                patch.object(country.os, "close") as close:
            raw = country.read_source(country.RADIO)
        return raw, opened, close

    def test_bounded_stable_read_closes_fds_and_does_not_follow_links(self):
        raw, opened, close = self.read()
        self.assertEqual(raw, self.raw)
        self.assertEqual(opened.call_args.args[1] & os.O_ACCMODE, os.O_RDONLY)
        self.assertTrue(opened.call_args.args[1] & os.O_NOFOLLOW)
        self.assertEqual([item.args[0] for item in close.call_args_list], [11, 10])

    def test_wrong_owner_mode_links_type_size_short_read_and_replacement_refused(self):
        for change in ({"st_uid": 501}, {"st_mode": stat.S_IFREG | 0o777}, {"st_nlink": 2},
                       {"st_mode": stat.S_IFLNK | 0o555}, {"st_size": 0}, {"st_size": 65537}):
            info = SimpleNamespace(**{**vars(self.info), **change})
            with self.assertRaises(country.AccessError):
                self.read(info=info)
        with self.assertRaises(country.AccessError):
            self.read(chunks=[self.raw[:-1], b""])
        with self.assertRaises(country.AccessError):
            self.read(current=SimpleNamespace(**{**vars(self.info), "st_ino": 3}))

    def test_unsafe_parent_or_open_failure_closes_directory(self):
        parent = SimpleNamespace(st_uid=501, st_mode=stat.S_IFDIR | 0o755)
        with patch.object(country.os, "open", return_value=10), patch.object(country.os, "fstat", return_value=parent), \
                patch.object(country.os, "close") as close:
            with self.assertRaises(country.AccessError):
                country.directory("/run")
            close.assert_called_once_with(10)
        with patch.object(country, "directory", return_value=10), patch.object(country.os, "open", side_effect=OSError), \
                patch.object(country.os, "close") as close:
            with self.assertRaises(OSError):
                country.read_source(country.RADIO)
            close.assert_called_once_with(10)


if __name__ == "__main__":
    unittest.main()
