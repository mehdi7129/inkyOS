"""Synthetic runtime fixtures only; no device, service, key or poweroff commands."""
import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


diag = module("observer_diagnostic_tests", ROOT / "scripts/diagnose-enrollment-observers.py")
runtime = module("observer_diagnostic_runtime_tests", ROOT / "scripts/test-enrollment-firstboot.py")
panel = module("observer_diagnostic_panel_tests", ROOT / "scripts/observe-test-panel.py")
radio = module("observer_diagnostic_radio_tests", ROOT / "scripts/observe-test-radio.py")


def profile():
    wire = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + b"p" * 32
    return {"schema_version": 1, "kind": "test-lan-enrollment", "purpose": "test-enroll-and-stop",
            "state": "enrollment-pending", "application_source_commit": runtime.SOURCE,
            "application_manifest_sha256": runtime.MANIFEST_HASH,
            "parent_image_sha256": runtime.PARENT_IMAGE_SHA256,
            "operator_public_key": "ssh-ed25519 " + base64.b64encode(wire).decode(),
            "challenge": "a" * 64, "country_requested": "FR",
            **{key: False for key in runtime.FALSE_FIELDS}}


def state(profile_raw):
    return {"schema_version": 1, "kind": "test-lan-enrollment-state", "state": "enrolled",
            "profile_sha256": hashlib.sha256(profile_raw).hexdigest(),
            "application_activation_authorized": False}


def observed(kind, error=None):
    value = panel.observe() if kind == "panel" else radio.observe()
    value.update(live_selected=True, observation_source="live-system", error=error)
    for key in diag.GUARD_CHECKS:
        value["checks"][key] = {"passed": True, "status": "PASS"}
    return value


class FixtureAdapter:
    def __init__(self):
        self.calls, self.reports, self.fail = [], [], None
        self.values = {}

    def invoke(self, name, value=True):
        self.calls.append(name)
        if name == self.fail:
            raise OSError("PRIVATE_KEY PRIVATE_IDENTITY /private/path")
        return self.values.get(name, value)

    def environment(self): return self.invoke("environment")
    def fresh(self): return self.invoke("fresh")
    def pin_sources(self): return self.invoke("pins")
    def enrollment(self): return self.invoke("enrollment")
    def identity(self): return self.invoke("identity")
    def inactive_guards(self): return self.invoke("inactive")
    def start_firstboot(self): return self.invoke("start")
    def firstboot_success(self): return self.invoke("firstboot")
    def unchanged(self): return self.invoke("unchanged")
    def wait_devices(self): return self.invoke("wait", {"i2c1_present": False, "wlan0_present": False})
    def probes(self):
        return self.invoke("probes", {kind: diag.projected_probe(vars(runtime), kind,
            (1, runtime.canonical(observed(kind, "observation_unavailable")))) for kind in ("panel", "radio")})
    def report(self, result):
        self.invoke("report")
        self.reports.append(copy.deepcopy(result))
    def close(self): self.calls.append("close")


class DiagnosticTests(unittest.TestCase):
    def test_checked_in_sources_match_all_immutable_pins(self):
        paths = {diag.RUNTIME: ROOT / "scripts/test-enrollment-firstboot.py",
                 diag.FIRSTBOOT: ROOT / "overlay/usr/local/lib/inkyos/firstboot.py",
                 diag.UNIT: ROOT / "overlay/etc/systemd/system/inkyos-firstboot.service",
                 diag.HELPER: ROOT / "scripts/test-lan-preflight.py",
                 diag.PANEL: ROOT / "scripts/observe-test-panel.py",
                 diag.RADIO: ROOT / "scripts/observe-test-radio.py"}
        for target, source in paths.items():
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), diag.PINS[target])

    def test_enrolled_profile_hash_final_pins_and_canonical_bytes_required(self):
        raw = runtime.canonical(profile())
        enrolled = runtime.canonical(state(raw))
        self.assertTrue(diag.valid_enrollment(vars(runtime), raw, enrolled))
        for key, value in (("state", "pending"), ("profile_sha256", "0" * 64),
                           ("application_activation_authorized", True), ("schema_version", True)):
            changed = state(raw)
            changed[key] = value
            self.assertFalse(diag.valid_enrollment(vars(runtime), raw, runtime.canonical(changed)))
        for key, value in (("application_source_commit", "f" * 40), ("country_requested", "US")):
            changed = profile()
            changed[key] = value
            changed_raw = runtime.canonical(changed)
            self.assertFalse(diag.valid_enrollment(vars(runtime), changed_raw, runtime.canonical(state(changed_raw))))
        noncanonical = json.dumps(profile()).encode()
        self.assertFalse(diag.valid_enrollment(vars(runtime), noncanonical, runtime.canonical(state(noncanonical))))

    def test_existing_identity_exact_schema_and_no_replacement(self):
        good = {"version": 1, "hostname": "inky-" + "a" * 32}
        self.assertTrue(diag.valid_identity(vars(runtime), runtime.canonical(good)))
        for value in ({}, {**good, "version": True}, {**good, "hostname": "PRIVATE_NAME"},
                      {**good, "private_key": "SECRET"}):
            self.assertFalse(diag.valid_identity(vars(runtime), runtime.canonical(value)))
        self.assertFalse(diag.valid_identity(vars(runtime), b'{"version":1,"version":1,"hostname":"inky-a"}'))

    def test_wifi_state_accepts_observed_boolean_expansion_only(self):
        for value in (b"[main]\nWirelessEnabled=false\n",
                      b"[main]\nNetworkingEnabled=true\nWirelessEnabled=false\nWWANEnabled=true\n"):
            self.assertTrue(diag.valid_wifi_state(value))
        for value in (b"[main]\nWirelessEnabled=true\n", b"[main]\nWirelessEnabled=false\nSSID=SECRET\n",
                      b"[main]\nWirelessEnabled=false\nWirelessEnabled=false\n", b"[main]\n", b"\xff"):
            self.assertFalse(diag.valid_wifi_state(value))

    def test_blocked_checks_errors_and_exit_one_are_retained(self):
        for kind, error in (("panel", "eeprom_unavailable"), ("radio", "observation_unavailable")):
            value = observed(kind, error)
            result = diag.projected_probe(vars(runtime), kind, (1, runtime.canonical(value)))
            self.assertEqual(result["outcome"], "reported")
            self.assertEqual(result["exit_code"], 1)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["error"], error)
            self.assertEqual(result["checks"], value["checks"])
            self.assertTrue(result["live_selected"])
            self.assertFalse(result["observations_complete"])

    def test_successful_panel_data_survives_reviewed_validator(self):
        value = observed("panel")
        value.update(passed=True, status="PASS", live_evidence=True,
                     panel=panel.parse_eeprom(struct.pack("<HHBBB22p", 600, 400, 6, 0, 25, b"ignored")))
        result = diag.projected_probe(vars(runtime), "panel", (0, runtime.canonical(value)))
        self.assertEqual(result["outcome"], "reported")
        self.assertEqual(result["observation"]["data"]["panel_reference"], "E640")
        self.assertNotIn("ignored", json.dumps(result))

    def test_malformed_unexpected_and_secret_probe_output_is_closed(self):
        value = observed("panel")
        variants = [b"PRIVATE_KEY raw stderr", b'{"schema_version":1,"schema_version":1}',
                    runtime.canonical({**value, "private_key": "SECRET"}),
                    runtime.canonical({**value, "error": "SECRET"}),
                    runtime.canonical({**value, "checks": {"SECRET": True}})]
        for raw in variants:
            result = diag.projected_probe(vars(runtime), "panel", (1, raw))
            self.assertEqual(result["outcome"], "invalid_output")
            self.assertNotIn("SECRET", json.dumps(result))
            self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertEqual(diag.projected_probe(vars(runtime), "panel", (99, b"SECRET"))["outcome"], "invalid_result")

    def test_timeout_or_unavailable_is_not_reported_as_valid_probe(self):
        result = diag.projected_probe(vars(runtime), "radio", None)
        self.assertEqual(result["outcome"], "timeout_or_unavailable")
        self.assertIsNone(result["exit_code"])
        self.assertIsNone(result["checks"])

    def test_replay_refused_before_any_service_and_no_report_replacement(self):
        adapter = FixtureAdapter()
        def replay():
            adapter.calls.append("fresh")
            raise diag.DiagnosticError("existing_diagnostic")
        adapter.fresh = replay
        result = diag.diagnose(adapter)
        self.assertEqual(result["error"], "existing_diagnostic")
        self.assertNotIn("start", adapter.calls)
        self.assertNotIn("report", adapter.calls)

    def test_all_four_replay_names_refused_by_native_fresh(self):
        names = (diag.REPORT, "." + diag.REPORT + ".tmp", diag.CLAIM, "." + diag.CLAIM + ".tmp")
        for name in names:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / name).write_bytes(b"preserve")
                native = diag.NativeAdapter.__new__(diag.NativeAdapter)
                native.files = SimpleNamespace(directory=lambda *args, **kwargs: os.open(tmp, os.O_RDONLY), close=lambda: None)
                native.runtime = {}
                native.boot = None
                try:
                    with self.assertRaisesRegex(diag.DiagnosticError, "existing_diagnostic"):
                        native.fresh()
                    self.assertEqual((Path(tmp) / name).read_bytes(), b"preserve")
                finally:
                    native.close()

    def test_bad_pins_state_missing_identity_or_guards_prevent_start(self):
        for operation in ("pins", "enrollment", "identity", "inactive"):
            adapter = FixtureAdapter()
            if operation == "pins":
                adapter.fail = operation
            else:
                adapter.values[operation] = False
            result = diag.diagnose(adapter)
            self.assertFalse(result["completed"])
            self.assertNotIn("start", adapter.calls)
            self.assertTrue(result["report_written"])
            self.assertNotIn("PRIVATE", json.dumps(result))
        native = diag.NativeAdapter.__new__(diag.NativeAdapter)
        native.files = SimpleNamespace(read=lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError()))
        native.runtime = vars(runtime)
        self.assertFalse(native.identity())
        self.assertFalse(native.enrollment())

    def test_firstboot_state_change_stops_before_probes(self):
        adapter = FixtureAdapter()
        adapter.values["unchanged"] = False
        result = diag.diagnose(adapter)
        self.assertEqual(result["error"], "state_changed")
        self.assertIn("start", adapter.calls)
        self.assertNotIn("probes", adapter.calls)

    def test_firstboot_is_only_started_command_and_dropins_refused(self):
        native = diag.NativeAdapter.__new__(diag.NativeAdapter)
        native.properties = lambda unit, wanted: wanted
        calls = []
        native.run = lambda argv, timeout: calls.append((argv, timeout)) or (0, b"")
        self.assertTrue(native.start_firstboot())
        self.assertEqual(calls, [(("/usr/bin/systemctl", "start", "inkyos-firstboot.service"), 12)])
        native.properties = lambda unit, wanted: {**wanted, "DropInPaths": "/unreviewed"}
        calls.clear()
        self.assertFalse(native.start_firstboot())
        self.assertEqual(calls, [])

    def test_native_guards_require_enrollment_and_keygen_masks_and_inactive_nm(self):
        native = diag.NativeAdapter.__new__(diag.NativeAdapter)
        native.runtime = vars(runtime)
        native.radio = {"PreparedGuard": lambda: SimpleNamespace(collect=lambda: {key: True for key in diag.GUARD_CHECKS})}
        marker = runtime.canonical({"source_commit": runtime.SOURCE, "manifest_sha256": runtime.MANIFEST_HASH})
        def read(path, **kwargs):
            if path == runtime.MARKER_PATH:
                return marker
            if path == "/var/lib/NetworkManager/NetworkManager.state":
                return b"[main]\nNetworkingEnabled=true\nWirelessEnabled=false\nWWANEnabled=true\n"
            raise AssertionError("Unexpected read; no key or identity may be opened")
        def absent(*args, **kwargs):
            raise FileNotFoundError()
        native.files = SimpleNamespace(read=read, directory=absent)
        calls = []
        def properties(unit, wanted):
            calls.append(unit)
            if unit == "NetworkManager.service":
                return {"ActiveState": "inactive", "SubState": "dead"}
            result = dict(wanted)
            if unit == "inkyos-test-enrollment.service":
                result["UnitFileState"] = "masked-runtime"
            return result
        native.properties = properties
        self.assertTrue(native.inactive_guards())
        self.assertIn("regenerate_ssh_host_keys.service", calls)
        self.assertIn("sshd-keygen.service", calls)
        self.assertIn("inkyos-test-enrollment.service", calls)
        for unsafe in ("inkyos-test-enrollment.service", "NetworkManager.service"):
            native.properties = lambda unit, wanted: {"ActiveState": "active"} if unit == unsafe else properties(unit, wanted)
            self.assertFalse(native.inactive_guards())

    def test_native_bad_source_pin_fails_before_any_helper_import(self):
        native = diag.NativeAdapter.__new__(diag.NativeAdapter)
        native.files = SimpleNamespace(read=lambda path, **kwargs: b"raise Exception('SECRET')")
        with self.assertRaisesRegex(diag.DiagnosticError, "source_pin_invalid"):
            native.pin_sources()
        self.assertFalse(hasattr(native, "helpers"))
        self.assertFalse(hasattr(native, "radio"))

    def test_radio_complete_observations_still_require_exit_one_and_remain_blocked(self):
        value = observed("radio")
        value.update(observations_complete=True, live_evidence=True,
            firmware={"country_abbrev": "FR", "ccode": "FR", "revision": 1},
            kernel={"global_country": "FR", "phy_country_label": "99", "phy_custom": True, "phy_self_managed": False},
            channels_2_4ghz=[{"frequency_mhz": 2412, "channel": 1, "disabled": False,
                             "max_tx_power_mbm": 2000, "flags": []}])
        for name in diag.RADIO_CHECKS:
            yes = name != "firmware_tuple_qualified"
            value["checks"][name] = {"passed": yes, "status": "PASS" if yes else "BLOCKED"}
        result = diag.projected_probe(vars(runtime), "radio", (1, runtime.canonical(value)))
        self.assertEqual(result["outcome"], "reported")
        self.assertEqual(result["status"], "BLOCKED")
        self.assertTrue(result["observations_complete"])
        self.assertEqual(result["observation"]["status"], "observed-unqualified")
        self.assertEqual(diag.projected_probe(vars(runtime), "radio", (0, runtime.canonical(value)))["outcome"], "invalid_output")

    def test_complete_diagnostic_keeps_blocked_probes_and_never_qualifies(self):
        adapter = FixtureAdapter()
        result = diag.diagnose(adapter)
        self.assertTrue(result["completed"])
        self.assertTrue(result["report_written"])
        self.assertFalse(result["live_evidence"])
        for field in ("activation_authorized", "hardware_qualified", "release_qualified"):
            self.assertFalse(result[field])
        for probe in result["probes"].values():
            self.assertEqual(probe["status"], "BLOCKED")
            self.assertEqual(probe["error"], "observation_unavailable")
        self.assertEqual(adapter.calls.count("start"), 1)
        self.assertEqual(adapter.calls.count("unchanged"), 2)
        self.assertLess(adapter.calls.index("fresh"), adapter.calls.index("pins"))
        self.assertLess(adapter.calls.index("identity"), adapter.calls.index("start"))

    def test_cli_rejects_alternate_root_and_command_without_leaking_arguments(self):
        for args in (["--root", "/PRIVATE_PATH"], ["--command", "SECRET"], ["--live"]):
            output = io.StringIO()
            with patch.object(diag, "NativeAdapter") as constructor, patch("sys.stdout", output):
                self.assertEqual(diag.main(args), 1)
            constructor.assert_not_called()
            result = json.loads(output.getvalue())
            self.assertEqual(result["error"], "invalid_arguments")
            self.assertNotIn("SECRET", output.getvalue())
            self.assertNotIn("PRIVATE_PATH", output.getvalue())


if __name__ == "__main__":
    unittest.main()
