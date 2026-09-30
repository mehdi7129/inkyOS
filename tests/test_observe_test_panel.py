"""Synthetic EEPROM/ioctl/rootfs fixtures only; never open a hardware bus."""

import ctypes
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
SCRIPT = ROOT / "scripts/observe-test-panel.py"
def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
observer = load(SCRIPT, "inkyos_test_panel_observer")
preflight = load(ROOT / "scripts/test-lan-preflight.py", "inkyos_observer_test_preflight")


def encoded(variant=25, width=600, height=400, color=6, pcb=123, timestamp=b"PRIVATE_TIMESTAMP"):
    return struct.pack("<HHBBB22p", width, height, color, pcb, variant, timestamp)


class FixtureGuard:
    def __init__(self, facts=None):
        self.facts = {key: True for key in observer.CHECKS} if facts is None else facts
        self.calls = 0
    def collect(self):
        self.calls += 1
        return self.facts


class FixtureAdapter:
    def __init__(self, raw=None):
        self.raw = encoded() if raw is None else raw
        self.calls = 0
    def sample(self):
        self.calls += 1
        return self.raw


class ObserverTests(unittest.TestCase):
    def test_default_never_reads_files_checks_services_forks_or_opens_bus(self):
        guard, adapter = FixtureGuard(), FixtureAdapter()
        with mock.patch.object(observer.os, "open", side_effect=AssertionError("No opens")), \
                mock.patch.object(observer.os, "fork", side_effect=AssertionError("No worker")):
            output = observer.observe(adapter, guard)
        self.assertEqual((guard.calls, adapter.calls), (0, 0))
        self.assertFalse(output["passed"])
        self.assertEqual(output["observation_source"], "inactive")
        self.assertIsNone(output["panel"])

    def test_all_reviewed_catalogue_tuples_are_exact_and_private_fields_discarded(self):
        rows = ((20, 800, 480, 5, "AC073TC1A", "7colour", "inky.inky_ac073tc1a.Inky"),
                (21, 1600, 1200, 6, "EL133UF1", "spectra6", "inky.inky_el133uf1.Inky"),
                (22, 800, 480, 6, "E673", "spectra6", "inky.inky_e673.Inky"),
                (25, 600, 400, 6, "E640", "spectra6", "inky.inky_e640.Inky"))
        self.assertEqual(len(observer.CATALOGUE), 4)
        for variant, width, height, color, reference, color_name, driver in rows:
            with self.subTest(variant=variant):
                value = observer.parse_eeprom(encoded(variant, width, height, color))
                self.assertEqual(value, {"display_variant": variant, "panel_reference": reference,
                    "width": width, "height": height, "color_code": color, "color": color_name,
                    "driver_class": driver})
                self.assertNotIn("PRIVATE_", json.dumps(value))
                self.assertEqual(observer.parse_eeprom(encoded(variant, width, height, color, pcb=0,
                    timestamp=b"\xff" * 21)), value)
                for changes in ({"variant": 26}, {"width": width + 1}, {"height": height + 1},
                                {"color": 6 if color == 5 else 5}):
                    args = dict(variant=variant, width=width, height=height, color=color)
                    args.update(changes)
                    with self.assertRaises(observer.ObservationError):
                        observer.parse_eeprom(encoded(**args))

    def test_parser_rejects_malformed_size_type_and_unknown_or_crossed_mapping(self):
        for raw in (b"", encoded()[:-1], encoded() + b"x", bytearray(encoded()),
                    list(encoded()), "PRIVATE_RAW_DATA", encoded(variant=20),
                    encoded(variant=21, width=800, height=480)):
            with self.subTest(kind=type(raw).__name__), self.assertRaises(observer.ObservationError):
                observer.parse_eeprom(raw)

    def test_fixture_pass_never_claims_live_evidence_activation_or_qualification(self):
        output = observer.observe(FixtureAdapter(), FixtureGuard(), live=True)
        self.assertTrue(output["passed"])
        self.assertEqual(output["observation_source"], "fixture")
        for key in ("live_evidence", "activation_authorized", "hardware_qualified", "release_qualified"):
            self.assertFalse(output[key])
        self.assertEqual(output["scope"], "eeprom_declaration_only")
        self.assertNotIn("PRIVATE", json.dumps(output))

    def test_missing_nonboolean_guards_never_call_bus_adapter(self):
        for key in observer.CHECKS:
            for invalid in (False, 1, "yes", {"PRIVATE_SECRET": True}):
                facts = {name: True for name in observer.CHECKS}
                facts[key] = invalid
                adapter = FixtureAdapter()
                output = observer.observe(adapter, FixtureGuard(facts), live=True)
                self.assertEqual(adapter.calls, 0)
                self.assertFalse(output["passed"])
                self.assertFalse(output["checks"][key]["passed"])
                self.assertNotIn("PRIVATE", json.dumps(output))

    def test_subclasses_cannot_claim_production_evidence(self):
        class FakeProduction(observer.ProductionAdapter):
            def sample(self):
                return encoded()
        class FakePrepared(observer.PreparedGuard):
            def collect(self):
                return {key: True for key in observer.CHECKS}
        output = observer.observe(FakeProduction(), FakePrepared(), live=True)
        self.assertTrue(output["passed"])
        self.assertFalse(output["live_evidence"])
        self.assertEqual(output["observation_source"], "fixture")

    def test_exception_and_invalid_raw_data_have_fixed_private_safe_errors(self):
        class Broken:
            def sample(self):
                raise OSError("PRIVATE_PASSWORD PRIVATE_RAW_BYTES")
        for adapter, expected in ((Broken(), "observation_unavailable"),
                                  (FixtureAdapter(b"PRIVATE_DATA"), "eeprom_invalid")):
            output = observer.observe(adapter, FixtureGuard(), live=True)
            self.assertEqual(output["error"], expected)
            self.assertNotIn("PRIVATE", json.dumps(output))
            self.assertIsNone(output["panel"])

    def test_cli_inactive_and_unknown_arguments_emit_only_closed_json(self):
        for args, code in (([], 1), (["--bus", "/dev/PRIVATE_BUS"], 2),
                           (["--address", "PRIVATE_ADDRESS"], 2), (["--PRIVATE_SECRET"], 2)):
            output = subprocess.run([sys.executable, "-I", str(SCRIPT), *args],
                                    capture_output=True, text=True, timeout=3)
            self.assertEqual(output.returncode, code)
            self.assertEqual(output.stderr, "")
            self.assertEqual(len(output.stdout.splitlines()), 1)
            value = json.loads(output.stdout)
            self.assertFalse(value["passed"])
            self.assertFalse(value["activation_authorized"])
            self.assertNotIn("PRIVATE", output.stdout)

    def test_app_owned_or_unsafe_helper_is_rejected_before_read_or_execution(self):
        for change in ({"st_uid": 1000}, {"st_mode": stat.S_IFREG | 0o777},
                       {"st_nlink": 2}, {"st_size": 65537}, {"st_mode": stat.S_IFLNK | 0o755}):
            values = {"st_mode": stat.S_IFREG | 0o555, "st_uid": 0, "st_nlink": 1, "st_size": 16}
            values.update(change)
            def metadata(fd):
                if fd == 15:
                    return SimpleNamespace(**values)
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
            with mock.patch.object(observer.os, "open", side_effect=[10, 11, 12, 13, 14, 15]) as opened, \
                    mock.patch.object(observer.os, "fstat", side_effect=metadata), \
                    mock.patch.object(observer.os, "close"), \
                    mock.patch.object(observer.os, "read", side_effect=AssertionError("No unsafe helper read")) as read:
                with self.assertRaises(observer.ObservationError):
                    observer.load_helpers()
            read.assert_not_called()
            self.assertEqual([call.args[0] for call in opened.call_args_list],
                             ["/", "usr", "local", "lib", "inkyos", "test-lan-preflight.py"])


class IoctlTests(unittest.TestCase):
    def metadata(self, _fd):
        return SimpleNamespace(st_mode=stat.S_IFCHR | 0o660, st_uid=0, st_rdev=os.makedev(89, 1))

    def test_exact_fixed_device_address_pointer_write_and_29_byte_read_close(self):
        calls = []
        raw = encoded()
        def ioctl(fd, operation, arg):
            self.assertEqual(fd, 123)
            if operation == observer.I2C_SLAVE:
                calls.append((operation, arg))
                return 0
            self.assertEqual(operation, observer.I2C_SMBUS)
            data = arg.data.contents
            calls.append((operation, arg.read_write, arg.command, arg.size,
                          data.block[0], data.block[1]))
            if arg.read_write == 1:
                for index, value in enumerate(raw, 1):
                    data.block[index] = value
            return 0
        opener, closer = mock.Mock(return_value=123), mock.Mock()
        reader = observer.LinuxI2C(opener=opener, metadata=self.metadata, ioctl=ioctl, closer=closer)
        self.assertEqual(reader.sample(), raw)
        opener.assert_called_once_with("/dev/i2c-1", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        self.assertEqual(calls, [(0x0703, 0x50), (0x0720, 0, 0, 8, 1, 0), (0x0720, 1, 0, 8, 29, 0)])
        closer.assert_called_once_with(123)
        self.assertTrue(observer.abi_supported())
        self.assertEqual(ctypes.sizeof(observer.SMBusData), 34)

    def test_ioctl_failure_at_every_stage_closes_device_without_retry(self):
        for failure in range(3):
            calls = []
            def ioctl(*args):
                calls.append(args[1])
                if len(calls) - 1 == failure:
                    raise OSError("PRIVATE_RAW_ERROR")
                return 0
            closer = mock.Mock()
            reader = observer.LinuxI2C(opener=lambda *_: 123, metadata=self.metadata, ioctl=ioctl, closer=closer)
            with self.assertRaises(OSError):
                reader.sample()
            self.assertEqual(len(calls), failure + 1)
            closer.assert_called_once_with(123)

    def test_bad_device_metadata_or_unverified_abi_never_calls_ioctl(self):
        for change in ({"st_mode": stat.S_IFREG | 0o660}, {"st_mode": stat.S_IFCHR | 0o666},
                       {"st_uid": 1000}, {"st_rdev": os.makedev(89, 0)}, {"st_rdev": os.makedev(1, 3)}):
            values = vars(self.metadata(123))
            values.update(change)
            ioctl, closer = mock.Mock(), mock.Mock()
            reader = observer.LinuxI2C(opener=lambda *_: 123, metadata=lambda _: SimpleNamespace(**values),
                                      ioctl=ioctl, closer=closer)
            with self.assertRaises(observer.ObservationError):
                reader.sample()
            ioctl.assert_not_called()
            closer.assert_called_once_with(123)
        opener = mock.Mock()
        with mock.patch.object(observer, "abi_supported", return_value=False):
            with self.assertRaises(observer.ObservationError):
                observer.LinuxI2C(opener=opener).sample()
        opener.assert_not_called()

    def test_short_read_is_invalid_and_device_closes(self):
        def ioctl(_fd, operation, arg):
            if operation == observer.I2C_SMBUS and arg.read_write == 1:
                arg.data.contents.block[0] = 28
        closer = mock.Mock()
        reader = observer.LinuxI2C(opener=lambda *_: 123, metadata=self.metadata, ioctl=ioctl, closer=closer)
        with self.assertRaises(observer.ObservationError):
            reader.sample()
        closer.assert_called_once_with(123)

    def test_ctypes_request_is_accepted_by_stdlib_ioctl_on_nonhardware_pipe(self):
        # Unsupported ioctl on an anonymous pipe proves Python accepts the ABI
        # buffer object; this intentionally does not open /dev or prove I2C.
        read_fd, write_fd = os.pipe()
        try:
            data = observer.SMBusData()
            request = observer.SMBusRequest(1, 0, 8, ctypes.pointer(data))
            with self.assertRaises(OSError):
                observer.fcntl.ioctl(read_fd, observer.I2C_SMBUS, request)
        finally:
            os.close(read_fd)
            os.close(write_fd)


class GuardTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.root.chmod(0o755)
        self.manifest = (ROOT / "tests/fixtures/application-manifest-758a2bf7.json").read_bytes()
        self.source = "758a2bf7ed099aad41ef35316e53228e797b0b2b"
        self.digest = hashlib.sha256(self.manifest).hexdigest()
        self.marker = {"schema_version": 1, "kind": "test-lan-prepared", "state": "prepared-inactive",
            "application_runtime": "masked", "activation_authorized": False, "ready_for_activation": False,
            "factory_authority": False, "source_commit": self.source, "manifest_sha256": self.digest}
        self.put(preflight.MARKER, json.dumps(self.marker).encode())
        self.put(preflight.MANIFEST, self.manifest)
        self.put(preflight.SOURCE_FILE, (self.source + "\n").encode())
        self.store = preflight.ReadStore(self.root, owner_uid=os.getuid(), app_uid=os.getuid())
        self.addCleanup(self.store.close)
        self.calls = []
        self.guard = observer.PreparedGuard(helpers=vars(preflight), store=self.store,
            command=self.command, monotonic=lambda: 0)

    def put(self, relative, raw):
        path = self.root / relative
        parent = self.root
        for part in path.parent.relative_to(self.root).parts:
            parent /= part
            parent.mkdir(mode=0o755, exist_ok=True)
            parent.chmod(0o755)
        path.write_bytes(raw)
        path.chmod(0o644)
        return path

    def command(self, argv, *, timeout, limit):
        keys = [key for key in ("firstboot", "app", "helper") if argv == preflight.COMMANDS[key]]
        self.assertEqual(len(keys), 1, "No radio, clock, network, driver or other commands allowed")
        self.assertLessEqual(timeout, 2)
        self.assertGreater(timeout, 0)
        self.assertEqual(limit, 16384)
        self.calls.append(keys[0])
        return ("ActiveState=active\nSubState=exited\nLoadState=loaded\nResult=success\nExecMainStatus=0\n"
                if keys[0] == "firstboot" else
                "ActiveState=inactive\nSubState=dead\nLoadState=masked\nUnitFileState=masked\n")

    def test_exact_prepared_pin_and_three_stopped_service_guards_pass(self):
        output = observer.observe(FixtureAdapter(), self.guard, live=True)
        self.assertTrue(output["passed"])
        self.assertEqual(self.calls, ["firstboot", "app", "helper"])
        self.assertFalse(output["live_evidence"])
        self.assertFalse(self.guard.native_live)

    def test_historical_exact_pin_is_accepted_without_widening_source_allowlist(self):
        source = "6a697d134290ced0214fc74b903f4b3c336d70fa"
        manifest = (ROOT / "tests/fixtures/application-manifest-6a697d1.json").read_bytes()
        marker = dict(self.marker, source_commit=source, manifest_sha256=hashlib.sha256(manifest).hexdigest())
        self.put(preflight.MARKER, json.dumps(marker).encode())
        self.put(preflight.MANIFEST, manifest)
        self.put(preflight.SOURCE_FILE, source.encode())
        self.assertTrue(observer.observe(FixtureAdapter(), self.guard, live=True)["passed"])
        self.assertEqual(self.calls, ["firstboot", "app", "helper"])

    def test_bad_profiles_and_crossed_unknown_or_modified_pins_stop_commands_and_bus(self):
        for change in ({"schema_version": True}, {"activation_authorized": True},
                       {"state": "active"}, {"source_commit": "f" * 40},
                       {"manifest_sha256": "2424fb9c32234ad7d359799f6b137e98298734023f0039afd1a57fbf265c250f"}):
            self.put(preflight.MARKER, json.dumps(dict(self.marker, **change)).encode())
            self.calls.clear()
            adapter = FixtureAdapter()
            self.assertFalse(observer.observe(adapter, self.guard, live=True)["passed"])
            self.assertEqual((self.calls, adapter.calls), ([], 0))
        self.put(preflight.MARKER, json.dumps(self.marker).encode())
        for path, raw in ((preflight.MANIFEST, self.manifest + b"\n"),
                          (preflight.SOURCE_FILE, b"PRIVATE_SOURCE")):
            before = (self.root / path).read_bytes()
            self.put(path, raw)
            adapter = FixtureAdapter()
            self.assertFalse(observer.observe(adapter, self.guard, live=True)["passed"])
            self.assertEqual((self.calls, adapter.calls), ([], 0))
            self.put(path, before)

    def test_symlink_marker_and_failed_active_or_unmasked_services_block_bus(self):
        marker = self.root / preflight.MARKER
        original = marker.read_bytes()
        marker.unlink()
        marker.symlink_to(self.root / preflight.MANIFEST)
        adapter = FixtureAdapter()
        self.assertFalse(observer.observe(adapter, self.guard, live=True)["passed"])
        self.assertEqual((self.calls, adapter.calls), ([], 0))
        marker.unlink()
        self.put(preflight.MARKER, original)
        for key in ("firstboot", "app", "helper"):
            for invalid in (None, "PRIVATE_ERROR", "ActiveState=active\nSubState=running\nLoadState=loaded\nUnitFileState=enabled\n"):
                self.guard.command = lambda argv, **kwargs: invalid if argv == preflight.COMMANDS[key] else self.command(argv, **kwargs)
                adapter = FixtureAdapter()
                output = observer.observe(adapter, self.guard, live=True)
                self.assertFalse(output["passed"])
                self.assertEqual(adapter.calls, 0)
                self.assertNotIn("PRIVATE", json.dumps(output))

    def test_expired_guard_budget_does_not_run_commands_or_bus(self):
        self.guard.monotonic = mock.Mock(side_effect=[0, 7])
        adapter = FixtureAdapter()
        self.assertFalse(observer.observe(adapter, self.guard, live=True)["passed"])
        self.assertEqual((self.calls, adapter.calls), ([], 0))


class ProcessTests(unittest.TestCase):
    def test_child_synthetic_success_failure_and_timeout_are_bounded(self):
        self.assertEqual(observer.bounded_sample(encoded, timeout=0.5), encoded())
        def broken():
            raise OSError("PRIVATE_CHILD_ERROR")
        with self.assertRaisesRegex(observer.ObservationError, "^eeprom_unavailable$"):
            observer.bounded_sample(broken, timeout=0.5)
        started = time.monotonic()
        with self.assertRaisesRegex(observer.ObservationError, "^eeprom_timeout$"):
            observer.bounded_sample(lambda: time.sleep(5), timeout=0.05)
        self.assertLess(time.monotonic() - started, 1)


if __name__ == "__main__":
    unittest.main()
