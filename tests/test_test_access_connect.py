"""TEST connection sequencing, private synthetic profiles and inert commands."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).parents[1]
def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
access = load("access_connect_tests", "test-access-connect.py")
imp = load("access_connect_import_tests", "test-access-import.py")
legacy = load("access_connect_legacy_tests", "test-enrollment-firstboot.py")
country = load("access_connect_country_tests", "test-access-network.py")


class Fixture:
    def __init__(self, failure=None, value=False):
        self.events, self.failure, self.value = [], failure, value

    def step(self, name):
        self.events.append(name)
        if self.failure == len(self.events):
            if isinstance(self.value, BaseException):
                raise self.value
            return self.value
        return True

    def target(self): return self.step("target")
    def bind(self): return self.step("bind")
    def authenticate_cache(self): return self.step("authenticate_cache")
    def unchanged(self): return self.step("unchanged")
    def profiles_closed(self): return self.step("profiles_closed")
    def wifi_closed(self): return self.step("wifi_closed")
    def publish_profile(self): return self.step("publish_profile")
    def load_profile(self): return self.step("load_profile")
    def profile_restricted(self): return self.step("profile_restricted")
    def country_ready(self): return self.step("country_ready")
    def immediately_ready(self): return self.step("immediately_ready")
    def radio_on(self): return self.step("radio_on")
    def activate(self): return self.step("activate")
    def connected(self): return self.step("connected")
    def radio_off(self): return self.step("radio_off")
    def radio_off_verified(self): return self.step("radio_off_verified")
    def close(self): return self.step("close")


EXPECTED_ORDER = ["target", "bind", "authenticate_cache", "unchanged", "profiles_closed", "wifi_closed",
                  "publish_profile", "load_profile", "profile_restricted", "country_ready", "unchanged",
                  "profiles_closed", "profile_restricted", "immediately_ready", "radio_on", "activate",
                  "unchanged", "profiles_closed", "profile_restricted", "connected"]


def country_result():
    return {"schema_version": 1, "kind": "test-access-country-setup",
            "test_country_ready": False, "live_evidence": False, "country_set_attempted": True,
            "country_request_acknowledged": True, "wifi_closed_verified": True,
            "error": "country_unconfirmed", "checks": dict.fromkeys(access.COUNTRY_CHECKS, False)}


class ConnectTests(unittest.TestCase):
    def test_success_keeps_order_one_activation_and_never_claims_fixture_live(self):
        fixture = Fixture()
        result = access.connect(fixture)
        self.assertTrue(result["passed"])
        self.assertTrue(result["connected"])
        self.assertEqual(fixture.events, EXPECTED_ORDER + ["close"])
        self.assertEqual(result["checks"], dict.fromkeys(access.CHECKS, True))
        self.assertFalse(any(result["cleanup"].values()))
        self.assertIsNone(result["country_diagnostic"])
        for key in ("live_evidence", "ssh_started", "application_activation_authorized", "hardware_qualified", "release_qualified"):
            self.assertIs(result[key], False)

    def test_each_error_stops_then_rolls_radio_back_only_after_enable_attempt(self):
        for index in range(1, len(EXPECTED_ORDER) + 1):
            for value in (False, None, 1, "true", OSError("PRIVATE_SSID PRIVATE_PSK")):
                with self.subTest(index=index, value=type(value).__name__):
                    fixture = Fixture(index, value)
                    result = access.connect(fixture)
                    self.assertFalse(result["passed"])
                    self.assertFalse(result["connected"])
                    expected = EXPECTED_ORDER[:index]
                    if index >= 15:
                        expected += ["radio_off", "radio_off_verified"]
                        self.assertTrue(all(result["cleanup"].values()))
                    else:
                        self.assertFalse(any(result["cleanup"].values()))
                    self.assertEqual(fixture.events, expected + ["close"])
                    self.assertNotIn("PRIVATE", json.dumps(result))

    def test_cleanup_verifies_off_even_if_off_command_fails_or_raises(self):
        for value in (False, RuntimeError("private")):
            fixture = Fixture(16, False)
            def fail_off():
                fixture.events.append("radio_off")
                if isinstance(value, BaseException):
                    raise value
                return value
            fixture.radio_off = fail_off
            result = access.connect(fixture)
            self.assertFalse(result["passed"])
            self.assertTrue(result["cleanup"]["required"])
            self.assertFalse(result["cleanup"]["radio_off_acknowledged"])
            self.assertTrue(result["cleanup"]["radio_off_verified"])
            self.assertEqual(fixture.events[-3:], ["radio_off", "radio_off_verified", "close"])

    def test_close_failure_after_connection_also_requests_radio_off(self):
        fixture = Fixture(len(EXPECTED_ORDER) + 1, OSError("private"))
        result = access.connect(fixture)
        self.assertFalse(result["passed"])
        self.assertFalse(result["connected"])
        self.assertTrue(all(result["cleanup"].values()))
        self.assertEqual(fixture.events[-3:], ["close", "radio_off", "radio_off_verified"])

    def test_budget_reserves_cleanup_and_refuses_before_first_operation(self):
        fixture = Fixture()
        with patch.object(access.time, "monotonic", side_effect=[0, 84]):
            result = access.connect(fixture)
        self.assertEqual(result["error"], "runtime_timeout")
        self.assertEqual(fixture.events, ["close"])
        self.assertEqual(fixture.deadline, 90)
        self.assertEqual(fixture.work_deadline, 84)

    def test_injected_native_subclass_never_claims_live(self):
        class Injected(Fixture, access.NativeAdapter):
            pass
        self.assertFalse(access.connect(Injected())["live_evidence"])

    def test_native_commands_fixed_no_secret_arguments_and_exact_positive_outputs(self):
        native = access.NativeAdapter()
        native.country_module = vars(country)
        cases = [("load_profile", access.LOAD, (0, b"loaded private text never exported\n")),
                 ("profile_restricted", access.PROPERTIES, (0, access.PROPERTY_BYTES)),
                 ("radio_on", access.RADIO_ON, (0, b"")), ("activate", access.UP, (0, b"activated\n")),
                 ("radio_off", access.RADIO_OFF, (0, b"")),
                 ("radio_off_verified", country.WIFI_STATE, (0, b"v b false\n"))]
        for method, command, response in cases:
            with self.subTest(method=method), patch.object(native, "command", return_value=response) as called:
                self.assertTrue(getattr(native, method)())
                self.assertEqual(called.call_args.args, (command,))
        self.assertEqual(access.UP, (access.NMCLI, "--wait", "35", "connection", "up", "uuid", access.UUID, "ifname", "wlan0"))
        self.assertEqual(access.LOAD, (access.NMCLI, "connection", "load", access.PROFILE))
        for value in (None, (1, b""), (0, access.PROPERTY_BYTES.replace(b"\nno\n", b"\nyes\n")),
                      (0, access.PROPERTY_BYTES.replace(b"\nbg\n", b"\na\n")),
                      (0, access.PROPERTY_BYTES + b"extra\n")):
            with patch.object(native, "command", return_value=value):
                self.assertFalse(native.profile_restricted())

    def test_native_loader_rejects_any_unbound_source_before_execution(self):
        raw = {access.SELF: b"# synthetic self\n", access.IMPORTER: b"raise RuntimeError('must not run')\n",
               access.COUNTRY: b"raise RuntimeError('must not run')\n"}
        expected = {path[1:]: {"sha256": access.digest(data), "mode": "0555"} for path, data in raw.items()}
        for changed in raw:
            for mode in ("0555", "0644"):
                manifest = {"files": copy.deepcopy(expected)}
                manifest["files"][changed[1:]] = {"sha256": "0" * 64, "mode": mode}
                values = {**raw, access.MANIFEST: json.dumps(manifest).encode()}
                class Files:
                    def read(self, path, **_kwargs): return values[path]
                    def close(self): pass
                native = access.NativeAdapter()
                native.lib = {"Files": Files, "strict_json": legacy.strict_json}
                with patch.dict(access.__dict__, {"exec": lambda *_args: self.fail("unbound source executed")}):
                    with self.assertRaisesRegex(access.ConnectError, "sources_invalid"):
                        native.bind()

    def test_native_connection_requires_exactly_one_uuid_wlan_and_managed_connected(self):
        native = access.NativeAdapter()
        active = (0, (access.UUID + ":wlan0\n").encode())
        device = (0, ("100 (connected)\nyes\n" + access.UUID + "\n").encode())
        with patch.object(native, "command", side_effect=[active, device]) as called:
            self.assertTrue(native.connected())
            self.assertEqual([row.args[0] for row in called.call_args_list], [access.ACTIVE, access.DEVICE])
        for bad in ((0, active[1] * 2), (0, active[1].replace(b"wlan0", b"eth0")), (0, b""), None):
            with patch.object(native, "command", return_value=bad):
                self.assertFalse(native.connected())
        for bad in ((0, device[1].replace(b"yes", b"no")), (0, device[1].replace(b"100", b"30")), None):
            with patch.object(native, "command", side_effect=[active, bad]):
                self.assertFalse(native.connected())

    def test_country_setup_requires_current_live_success_and_relocks(self):
        native = access.NativeAdapter()
        native.work_deadline = time.monotonic() + 40
        events = []
        class CountryFixture:
            def mapping(self): events.append("mapping"); return 0
            def lock(self): events.append("lock")
        native.country = CountryFixture()
        value = {"test_country_ready": True, "live_evidence": True, "error": None, "wifi_closed_verified": True}
        def setup(adapter, *, country):
            self.assertIs(adapter, native.country)
            self.assertEqual(country, "FR")
            events.append("setup_country")
            return dict(value)
        native.country_module = {"BUDGET": 25, "setup_country": setup}
        self.assertTrue(native.country_ready())
        self.assertTrue(native.country_setup_attempted)
        self.assertEqual(native.country_result, value)
        self.assertEqual(events, ["mapping", "setup_country", "lock"])
        for key, wrong in (("live_evidence", False), ("test_country_ready", False),
                           ("wifi_closed_verified", 1), ("error", "country_unconfirmed")):
            before = dict(value)
            value[key] = wrong
            events.clear()
            with self.assertRaisesRegex(access.ConnectError, "country_unconfirmed"):
                native.country_ready()
            self.assertEqual(native.country_result, value)
            self.assertNotIn("lock", events)
            value.clear(); value.update(before)

    def test_immediate_guard_rechecks_prepared_wifi_mapping_and_pins(self):
        native = access.NativeAdapter()
        native.work_deadline, native.wiphy = time.monotonic() + 10, 0
        facts = {"prepared": True, "wifi_closed": True, "mapping": 0, "unchanged": True}
        native.country = SimpleNamespace(**{name: (lambda name=name: facts[name]) for name in facts})
        with tempfile.TemporaryDirectory(prefix="inkyos-phy-fixture-") as folder:
            root = Path(folder)
            (root / "phy0").mkdir()
            native.auth = SimpleNamespace(files=SimpleNamespace(directory=lambda _path: os.open(folder, os.O_RDONLY | os.O_DIRECTORY)))
            self.assertTrue(native.immediately_ready())
            for key, value in (("prepared", False), ("wifi_closed", False), ("mapping", 1), ("mapping", False), ("unchanged", False)):
                old = facts[key]; facts[key] = value
                self.assertFalse(native.immediately_ready())
                facts[key] = old
            (root / "phy1").mkdir()
            self.assertFalse(native.immediately_ready())
            (root / "phy0").rmdir()
            self.assertFalse(native.immediately_ready())
            (root / "phy1").rmdir()
            self.assertFalse(native.immediately_ready())

    def test_command_reserves_time_for_cleanup_with_inert_legacy_command(self):
        native = access.NativeAdapter()
        native.work_deadline, native.deadline = 84, 90
        calls = []
        native.lib = {"command": lambda argv, **kwargs: calls.append((argv, kwargs)) or (0, b"")}
        with patch.object(access.time, "monotonic", return_value=85):
            self.assertIsNone(native.command(access.RADIO_ON))
            self.assertTrue(native.radio_off())
        self.assertEqual(calls, [(access.RADIO_OFF, {"timeout": 3, "limit": 4096})])

    def test_cli_has_no_root_override_or_fixture_mode(self):
        for args in (["--root", "/fixture"], ["--live"], ["--test"], ["--help"]):
            result = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/test-access-connect.py"), *args],
                                    capture_output=True, timeout=4, check=False)
            self.assertEqual(result.returncode, 1)
            report = json.loads(result.stdout)
            self.assertEqual(report["error"], "invalid_arguments")
            self.assertFalse(any(report["checks"].values()))
            self.assertFalse(report["radio_enable_attempted"])
            self.assertEqual(result.stderr, b"")


class CountryDiagnosticTests(unittest.TestCase):
    def test_closed_projection_omits_all_observations_and_unknown_fields(self):
        value = country_result()
        value.update(firmware={"country_abbrev": "PRIVATE_FIRMWARE"}, kernel="PRIVATE_KERNEL",
                     stdout="PRIVATE_STDOUT", stderr="PRIVATE_STDERR", identifier="PRIVATE_IDENTIFIER",
                     ssid="PRIVATE_SSID", psk="PRIVATE_PSK", PRIVATE_KEY="PRIVATE_VALUE")
        result = access.project_country_diagnostic(True, value)
        self.assertEqual(result, {"status": "available", "error": "country_unconfirmed",
                                 **{name: value[name] for name in access.COUNTRY_BOOLEANS},
                                 "checks": dict.fromkeys(access.COUNTRY_CHECKS, False)})
        self.assertNotIn("PRIVATE", json.dumps(result))
        value["checks"]["firmware_country_fr"] = True
        self.assertFalse(result["checks"]["firmware_country_fr"])

    def test_missing_malformed_fields_and_unknown_errors_are_unavailable(self):
        changes = [("schema_version", True), ("schema_version", 2), ("kind", "PRIVATE_KIND"),
                   ("error", "PRIVATE_ERROR"), ("error", []), ("checks", None),
                   ("checks", {**country_result()["checks"], "PRIVATE_CHECK": True})]
        changes += [(name, bad) for name in access.COUNTRY_BOOLEANS for bad in (1, 0, "PRIVATE", None, [])]
        changes += [("checks", {**country_result()["checks"], name: bad})
                    for name in access.COUNTRY_CHECKS for bad in (1, "PRIVATE", None)]
        for key, bad in changes:
            with self.subTest(key=key, bad=bad):
                value = country_result()
                value[key] = bad
                self.assertEqual(access.project_country_diagnostic(True, value), {"status": "unavailable"})
        for key in country_result():
            value = country_result()
            del value[key]
            self.assertEqual(access.project_country_diagnostic(True, value), {"status": "unavailable"})
        for value in (None, True, [], "PRIVATE", 1):
            self.assertEqual(access.project_country_diagnostic(True, value), {"status": "unavailable"})
        self.assertIsNone(access.project_country_diagnostic(False, country_result()))
        for attempted in (None, 1, "PRIVATE", []):
            self.assertEqual(access.project_country_diagnostic(attempted, country_result()), {"status": "unavailable"})

    def test_known_error_enum_is_independent_from_country_module(self):
        self.assertEqual(access.COUNTRY_ERRORS, country.ERRORS | {"interrupted"})
        self.assertEqual(access.COUNTRY_CHECKS, country.POLICY_CHECKS)
        for error in (None, *access.COUNTRY_ERRORS):
            value = country_result()
            value["error"] = error
            self.assertEqual(access.project_country_diagnostic(True, value)["error"], error)
        with patch.object(country, "ERRORS", {"PRIVATE_UNREVIEWED_ERROR"}):
            value["error"] = "PRIVATE_UNREVIEWED_ERROR"
            self.assertEqual(access.project_country_diagnostic(True, value), {"status": "unavailable"})

    def test_native_failed_country_result_is_retained_before_require(self):
        fixture = Fixture()
        fixture.country = SimpleNamespace(mapping=lambda: 0, lock=lambda: self.fail("failure must not relock"))
        value = country_result()
        fixture.country_module = {"BUDGET": 25, "setup_country": lambda *_args, **_kwargs: value}
        def country_ready():
            fixture.events.append("country_ready")
            return access.NativeAdapter.country_ready(fixture)
        fixture.country_ready = country_ready
        result = access.connect(fixture)
        self.assertIs(fixture.country_result, value)
        self.assertEqual(result["error"], "country_unconfirmed")
        self.assertEqual(result["country_diagnostic"], access.project_country_diagnostic(True, value))
        self.assertFalse(any(result["cleanup"].values()))
        self.assertFalse(result["radio_enable_attempted"])
        self.assertEqual(fixture.events, EXPECTED_ORDER[:10] + ["close"])

    def test_raised_country_call_is_unavailable_without_exposing_exception(self):
        fixture = Fixture()
        fixture.country = SimpleNamespace(mapping=lambda: 0)
        def setup(*_args, **_kwargs):
            raise OSError("PRIVATE_COUNTRY_EXCEPTION")
        fixture.country_module = {"BUDGET": 25, "setup_country": setup}
        def country_ready():
            fixture.events.append("country_ready")
            return access.NativeAdapter.country_ready(fixture)
        fixture.country_ready = country_ready
        result = access.connect(fixture)
        self.assertEqual(result["error"], "connect_failed")
        self.assertEqual(result["country_diagnostic"], {"status": "unavailable"})
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertEqual(fixture.events, EXPECTED_ORDER[:10] + ["close"])

    def test_projection_does_not_change_radio_cleanup_or_reuse_stale_result(self):
        for value in (country_result(), {"PRIVATE": "PRIVATE"}, None):
            fixture = Fixture(16, False)
            def country_ready():
                fixture.country_setup_attempted, fixture.country_result = True, value
                return fixture.step("country_ready")
            fixture.country_ready = country_ready
            result = access.connect(fixture)
            self.assertEqual(result["error"], "connection_failed")
            self.assertEqual(result["country_diagnostic"], access.project_country_diagnostic(True, value))
            self.assertTrue(all(result["cleanup"].values()))
            self.assertEqual(fixture.events, EXPECTED_ORDER[:16] + ["radio_off", "radio_off_verified", "close"])
            self.assertNotIn("PRIVATE", json.dumps(result))
            fixture.events.clear()
            fixture.failure = 1
            result = access.connect(fixture)
            self.assertIsNone(result["country_diagnostic"])
            self.assertEqual(fixture.events, ["target", "close"])


class ProfileFilesTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix=".inkyos-connect-fixture-", dir=Path.home().resolve())
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        for path in access.PROFILE_DIRS:
            current = self.root
            for part in path.strip("/").split("/"):
                current /= part
                current.mkdir(mode=0o755, exist_ok=True)
                current.chmod(0o755)
        self.files = legacy.Files(str(self.root), owner=os.getuid())
        self.addCleanup(self.files.close)
        self.native = access.NativeAdapter()
        self.native.auth = SimpleNamespace(files=self.files)
        self.native.network = imp.network_profile({"security": "wpa2-personal", "band": "2.4GHz",
                                                  "ssid_hex": b"Fixture".hex(), "psk": "fixture-password"})
        def rename(directory, source, target):
            if sys.platform.startswith("linux"):
                legacy.rename_noreplace(directory, source, target)
            else:
                os.link(source, target, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
                os.unlink(source, dir_fd=directory)
        def write(directory, name, raw):
            return legacy.write_atomic(directory, name, raw, owner=os.getuid(), rename=rename)
        self.native.lib = {**vars(legacy), "write_atomic": write}
        self.native.command = lambda _argv, **_kwargs: (0, b"")
        self.profile = self.root / access.PROFILE.lstrip("/")

    def test_publish_private_exact_profile_and_reuse_without_replacement(self):
        self.assertTrue(self.native.profiles_closed())
        self.assertTrue(self.native.publish_profile())
        before = self.profile.stat()
        self.assertEqual(self.profile.read_bytes(), self.native.network)
        self.assertEqual(before.st_mode & 0o777, 0o600)
        self.assertTrue(self.native.publish_profile())
        self.assertEqual(before.st_ino, self.profile.stat().st_ino)
        self.assertTrue(self.native.profiles_closed())

    def test_unknown_profile_in_each_location_refused_without_opening_its_contents(self):
        for location in access.PROFILE_DIRS:
            path = self.root / location.lstrip("/") / "foreign.nmconnection"
            path.write_bytes(b"foreign private content"); path.chmod(0o600)
            with patch.object(self.files, "read", side_effect=AssertionError("do not inspect foreign secrets")):
                self.assertFalse(self.native.profiles_closed())
            path.unlink()

    def test_existing_changed_symlink_or_unsafe_profile_is_never_replaced(self):
        self.profile.write_bytes(b"preserve foreign bytes"); self.profile.chmod(0o600)
        self.assertFalse(self.native.publish_profile())
        self.assertEqual(self.profile.read_bytes(), b"preserve foreign bytes")
        self.assertFalse(self.native.profiles_closed())
        self.profile.chmod(0o666)
        with self.assertRaises(legacy.EnrollmentError):
            self.native.publish_profile()
        self.profile.unlink()
        outside = self.root / "outside"
        outside.write_bytes(b"untouched")
        self.profile.symlink_to(outside)
        with self.assertRaises(OSError):
            self.native.publish_profile()
        self.assertEqual(outside.read_bytes(), b"untouched")

    def test_unknown_in_memory_profile_or_duplicate_uuid_is_refused(self):
        for raw in (b"other\n", (access.UUID + "\n").encode() * 2):
            self.native.command = lambda _argv, raw=raw: (0, raw)
            self.assertFalse(self.native.profiles_closed())


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.expected = {"profile_sha256": "1" * 64, "challenge": "2" * 64,
                         "host_public_key_sha256": "3" * 64, "application_source_commit": "4" * 40,
                         "application_manifest_sha256": "5" * 64, "access_runtime_manifest_sha256": "6" * 64}
        self.value = {"wifi": {"security": "wpa2-personal", "band": "2.4GHz", "ssid_hex": b"Fixture".hex(), "psk": "fixture-password"}}
        self.raw, self.sig = imp.canonical(self.value), b"fixture-signature"
        self.network = imp.network_profile(self.value["wifi"])
        self.state = imp.state_record(self.expected, self.raw, self.sig, self.network, "imported")
        self.events = []
        self.native = access.NativeAdapter()
        self.native.expected, self.native.importer = self.expected, vars(imp)
        self.native.auth = SimpleNamespace(
            acquire=lambda: self.events.append("lock"), state=lambda: dict(self.state),
            capsule=lambda *, cached: self.events.append("cached" if cached is True else "WRONG_FAT") or (self.raw, self.sig),
            authenticate=lambda raw, sig: self.events.append("authenticate") or copy.deepcopy(self.value),
            read_cache=lambda name: self.network, unchanged=lambda: True)

    def test_cache_must_be_committed_reauthenticated_and_matches_network_hash(self):
        self.assertTrue(self.native.authenticate_cache())
        self.assertEqual(self.events, ["lock", "cached", "authenticate"])
        self.assertTrue(self.native.unchanged())
        self.network += b"\nchanged"
        self.assertFalse(self.native.unchanged())
        with self.assertRaisesRegex(access.ConnectError, "cache_invalid"):
            self.native.authenticate_cache()

    def test_partial_or_changed_cache_refused_before_profile_publication(self):
        for key, bad in (("state", "importing"), ("state", "review-required"),
                         ("profile_sha256", "a" * 64), ("network_sha256", "b" * 64)):
            old = self.state[key]; self.state[key] = bad
            with self.assertRaisesRegex(access.ConnectError, "cache_invalid"):
                self.native.authenticate_cache()
            self.state[key] = old


if __name__ == "__main__":
    unittest.main()
