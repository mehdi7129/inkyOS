"""Bluetooth preparation fixtures; never access hardware, DBus or a radio."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("test_access_bluetooth", ROOT / "scripts/test-access-bluetooth.py")
bt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bt)


class Clock:
    def __init__(self): self.now = 0.0
    def monotonic(self): return self.now
    def sleep(self, duration): self.now += duration


class Fixture:
    def __init__(self, clock):
        self.clock, self.calls, self.observations = clock, [], 0
        self.row = {"identity": ("private-controller", 1), "soft": True, "hard": False}
        self.unblock_time, self.delay = None, 0.5
        self.replies, self.change_at = {}, None

    def target(self): return True
    def observe(self):
        self.observations += 1
        row = copy.deepcopy(self.row)
        if self.change_at == self.observations:
            row["identity"] = ("private-other", 2)
        if self.unblock_time is not None and self.clock.now >= self.unblock_time + self.delay:
            row["soft"] = False
        return row

    def call(self, argv, timeout):
        self.calls.append((argv, timeout))
        if argv in self.replies:
            value = self.replies[argv]
            if isinstance(value, Exception): raise value
            return value
        if argv == bt.UNBLOCK: self.unblock_time = self.clock.now
        return (0, b"v b true\n") if argv == bt.POWERED else (0, b"")


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.fixture = Fixture(self.clock)

    def run_fixture(self):
        with patch.object(bt.time, "monotonic", self.clock.monotonic), patch.object(bt.time, "sleep", self.clock.sleep):
            return bt.prepare(self.fixture)

    def test_transition_waits_then_single_unblock_and_power_with_readback(self):
        result = self.run_fixture()
        self.assertTrue(result["passed"])
        self.assertEqual(result["checks"], dict.fromkeys(bt.CHECKS, True))
        self.assertEqual([x[0] for x in self.fixture.calls], [bt.POWERED, bt.UNBLOCK, bt.POWER_ON, bt.POWERED])
        self.assertEqual(self.clock.now, 0.5)
        self.assertFalse(result["live_evidence"])
        self.assertNotIn("private-controller", json.dumps(result))

    def test_initially_unblocked_needs_no_sleep(self):
        self.fixture.row["soft"] = False
        self.assertTrue(self.run_fixture()["passed"])
        self.assertEqual(self.clock.now, 0)

    def test_missing_controller_and_hard_block_never_mutate(self):
        for error in ("controller_unavailable", "hard_blocked"):
            self.fixture.observe = lambda: (_ for _ in ()).throw(bt.BluetoothError(error))
            result = self.run_fixture()
            self.assertEqual(result["error"], error)
            self.assertEqual(self.fixture.calls, [])
        self.fixture = Fixture(self.clock)
        self.fixture.row["hard"] = True
        self.assertEqual(self.run_fixture()["error"], "hard_blocked")
        self.assertFalse(self.fixture.calls)

    def test_timeout_waiting_for_unblock_never_powers(self):
        self.fixture.delay = 100
        result = self.run_fixture()
        self.assertEqual(result["error"], "unblock_unconfirmed")
        self.assertEqual(self.clock.now, bt.READY_TIMEOUT)
        self.assertFalse(result["power_attempted"])

    def test_each_identity_change_refuses_next_mutation_or_final_pass(self):
        # Initial row binds identity. Every subsequent observation is checked.
        for change in range(2, 8):
            self.clock = Clock()
            self.fixture = Fixture(self.clock)
            self.fixture.change_at = change
            result = self.run_fixture()
            self.assertEqual(result["error"], "controller_changed", change)
            self.assertFalse(result["passed"])
            calls = [row[0] for row in self.fixture.calls]
            self.assertLessEqual(calls.count(bt.UNBLOCK), 1)
            self.assertLessEqual(calls.count(bt.POWER_ON), 1)

    def test_foreign_errors_never_escape_into_diagnostic(self):
        self.fixture.replies[bt.UNBLOCK] = OSError("PRIVATE_MAC PRIVATE_NETWORK")
        result = self.run_fixture()
        self.assertEqual(result["error"], "observation_unavailable")
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_command_failures_and_malformed_dbus_fail_closed(self):
        for argv, reply, error in [(bt.POWERED, (0, b"b true\n"), "bluez_unavailable"),
                (bt.POWERED, (1, b""), "bluez_unavailable"), (bt.UNBLOCK, (1, b""), "unblock_failed"),
                (bt.POWER_ON, (0, b"unexpected"), "power_failed")]:
            self.fixture = Fixture(self.clock)
            self.fixture.replies[argv] = reply
            self.assertEqual(self.run_fixture()["error"], error)

    def test_power_ack_without_true_readback_is_not_success(self):
        self.fixture.replies[bt.POWERED] = (0, b"v b false\n")
        result = self.run_fixture()
        self.assertEqual(result["error"], "power_unconfirmed")
        self.assertTrue(result["checks"]["power_acknowledged"])
        self.assertFalse(result["passed"])

    def test_deadline_checks_before_and_after_operations(self):
        def slow_target():
            self.clock.now += bt.BUDGET
            return True
        self.fixture.target = slow_target
        self.assertEqual(self.run_fixture()["error"], "runtime_timeout")
        self.assertFalse(self.fixture.calls)

    def test_wait_reserves_power_and_readback_budget(self):
        original = self.fixture.call
        def slow_call(argv, timeout):
            self.clock.now += 4 if argv == bt.POWERED else 3
            return original(argv, timeout)
        self.fixture.call = slow_call
        self.fixture.delay = 100
        result = self.run_fixture()
        self.assertEqual(result["error"], "unblock_unconfirmed")
        self.assertEqual(self.clock.now, bt.BUDGET - 5)
        self.assertFalse(result["power_attempted"])

    def test_oversleep_cannot_enable_power(self):
        with patch.object(bt.time, "monotonic", self.clock.monotonic), \
                patch.object(bt.time, "sleep", lambda _duration: self.clock.sleep(100)):
            result = bt.prepare(self.fixture)
        self.assertEqual(result["error"], "unblock_unconfirmed")
        self.assertFalse(result["power_attempted"])

    def test_malformed_observation_rejected(self):
        for bad in (None, {}, {"identity": None, "hard": False, "soft": False},
                    {"identity": 1, "hard": 0, "soft": False}):
            self.fixture.observe = lambda: bad
            self.assertEqual(self.run_fixture()["error"], "controller_unavailable")
            self.assertFalse(self.fixture.calls)

    def test_native_subclass_does_not_claim_live(self):
        class Injected(Fixture, bt.NativeAdapter): pass
        self.fixture = Injected(self.clock)
        self.assertFalse(self.run_fixture()["live_evidence"])

    def test_direct_cli_is_inert(self):
        with patch.object(bt, "prepare") as prepare, contextlib.redirect_stdout(io.StringIO()) as stream:
            self.assertEqual(bt.main(), 1)
        prepare.assert_not_called()
        self.assertEqual(json.loads(stream.getvalue())["error"], "invalid_arguments")

    def test_fixed_commands_do_not_include_scan_or_application_operations(self):
        self.assertEqual(bt.UNBLOCK, ("/usr/sbin/rfkill", "unblock", "bluetooth"))
        self.assertEqual(bt.POWER_ON[-6:], ("Set", "ssv", "org.bluez.Adapter1", "Powered", "b", "true"))
        for argv in (bt.POWER_ON, bt.POWERED):
            self.assertIn("--auto-start=no", argv)
            self.assertIn("/org/bluez/hci0", argv)
        with patch.object(bt.subprocess, "Popen") as popen:
            with self.assertRaises(bt.BluetoothError):
                bt.command(("/usr/sbin/rfkill", "unblock", "all"), timeout=3)
            with self.assertRaises(bt.BluetoothError):
                bt.command(bt.UNBLOCK, timeout=0)
        popen.assert_not_called()

    def test_caller_budget_is_respected_and_invalid_budgets_are_inert(self):
        for budget in (0, -1, True, float("nan"), float("inf"), bt.BUDGET + 1):
            self.assertEqual(bt.prepare(self.fixture, timeout=budget)["error"], "invalid_arguments")
        with patch.object(bt.time, "monotonic", self.clock.monotonic):
            result = bt.prepare(self.fixture, timeout=5)
        self.assertEqual(result["error"], "runtime_timeout")
        self.assertFalse(result["unblock_attempted"])
        self.assertFalse(result["power_attempted"])

    def test_command_result_types_are_exact(self):
        for reply in ((False, b"v b true\n"), [0, b"v b true\n"], (0, "v b true\n")):
            self.fixture = Fixture(self.clock)
            self.fixture.replies[bt.POWERED] = reply
            self.assertEqual(self.run_fixture()["error"], "observation_unavailable")


class SysfsObservationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for kind, names in (("bluetooth", ["hci0"]), ("rfkill", ["rfkill0", "rfkill1"])):
            (self.root / kind).mkdir()
            for name in names: (self.root / kind / name).touch()
        self.hci = "/sys/devices/platform/controller/bluetooth/hci0"
        self.entries = {"hci0": (self.hci, (1, 2), (3, 4)),
                        "rfkill0": ("/sys/devices/platform/wlan/rfkill0", (5, 6), (7, 8)),
                        "rfkill1": (self.hci + "/rfkill1", (9, 10), (11, 12))}
        self.values = {self.entries["rfkill0"][0] + "/type": b"wlan\n",
                       self.entries["rfkill1"][0] + "/type": b"bluetooth\n",
                       self.entries["rfkill1"][0] + "/name": b"hci0\n",
                       self.entries["rfkill1"][0] + "/hard": b"0\n",
                       self.entries["rfkill1"][0] + "/soft": b"1\n"}

    def observe(self):
        with patch.object(bt, "directory", side_effect=lambda path: os.open(self.root / Path(path).name, os.O_RDONLY)), \
                patch.object(bt, "class_entry", side_effect=lambda path: self.entries[path.name]), \
                patch.object(bt, "attribute", side_effect=lambda path: self.values[path]):
            return bt.observe_controller()

    def test_exact_hci0_parent_binding_and_state(self):
        row = self.observe()
        self.assertTrue(row["soft"])
        self.assertFalse(row["hard"])
        self.assertEqual(row["identity"], (self.entries["hci0"], self.entries["rfkill1"]))

    def test_second_controller_missing_controller_or_second_bluetooth_rejected(self):
        extra = self.root / "bluetooth/hci1"
        extra.touch()
        with self.assertRaises(bt.BluetoothError): self.observe()
        extra.unlink()
        (self.root / "bluetooth/hci0").unlink()
        with self.assertRaises(bt.BluetoothError): self.observe()
        (self.root / "bluetooth/hci0").touch()
        self.values[self.entries["rfkill0"][0] + "/type"] = b"bluetooth\n"
        with self.assertRaises(bt.BluetoothError): self.observe()

    def test_wrong_parent_or_controller_name_cannot_be_unblocked(self):
        old = self.entries["rfkill1"]
        self.entries["rfkill1"] = ("/sys/devices/other/rfkill1", old[1], old[2])
        self.values["/sys/devices/other/rfkill1/type"] = b"bluetooth\n"
        with self.assertRaises(bt.BluetoothError): self.observe()
        self.entries["rfkill1"] = old
        self.values[old[0] + "/name"] = b"hci1\n"
        with self.assertRaises(bt.BluetoothError): self.observe()

    def test_noncanonical_sysfs_state_is_rejected(self):
        for value in (b"0", b"true\n", b"0\nprivate", b""):
            self.values[self.entries["rfkill1"][0] + "/hard"] = value
            with self.assertRaises(bt.BluetoothError): self.observe()


class NativeBoundaryTests(unittest.TestCase):
    def fake_command(self, source, timeout=2.0):
        native_popen = subprocess.Popen
        def substitute(argv, **kwargs):
            self.assertEqual(argv, bt.UNBLOCK)
            self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
            self.assertEqual(kwargs["env"]["LC_ALL"], "C")
            return native_popen((sys.executable, "-I", "-B", "-c", source), **kwargs)
        with patch.object(bt.subprocess, "Popen", side_effect=substitute):
            return bt.command(bt.UNBLOCK, timeout=timeout)

    def test_command_reads_exact_output_and_exit_without_stderr(self):
        self.assertEqual(self.fake_command("import sys;sys.stdout.write('ok');sys.stderr.write('PRIVATE');sys.exit(3)"),
                         (3, b"ok"))

    def test_excessive_output_and_stall_are_bounded(self):
        with self.assertRaisesRegex(bt.BluetoothError, "observation_unavailable"):
            self.fake_command("import sys;sys.stdout.write('x'*4097)")
        started = time.monotonic()
        with self.assertRaisesRegex(bt.BluetoothError, "runtime_timeout"):
            self.fake_command("import time;time.sleep(30)", timeout=0.4)
        self.assertLess(time.monotonic() - started, 2.0)

    def test_native_missing_sysfs_has_closed_error(self):
        with patch.object(bt, "observe_controller", side_effect=FileNotFoundError("PRIVATE")):
            with self.assertRaisesRegex(bt.BluetoothError, "controller_unavailable"):
                bt.NativeAdapter().observe()


if __name__ == "__main__":
    unittest.main()
