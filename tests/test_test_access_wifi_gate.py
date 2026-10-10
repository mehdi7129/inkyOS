"""Closed TEST Wi-Fi gate fixtures; never operate a host service or radio."""
import contextlib
import hashlib
import io
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("test_access_wifi_gate", ROOT / "scripts/test-access-wifi-gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
SELF_RAW = (ROOT / "scripts/test-access-wifi-gate.py").read_bytes()
HELPER_RAW = (ROOT / "scripts/wifi-boot-gate.py").read_bytes()
BOOT_RAW = (ROOT / "scripts/test-access-boot.py").read_bytes()


def manifest():
    return {"schema_version": 1, "kind": "test-access-runtime",
            "application_source_commit": gate.SOURCE, "application_manifest_sha256": gate.APPLICATION_MANIFEST,
            "parent_image_sha256": gate.PARENT, "files": {
                gate.SELF[1:]: {"sha256": hashlib.sha256(SELF_RAW).hexdigest(), "mode": "0555"},
                gate.HELPER[1:]: {"sha256": gate.HELPER_SHA256, "mode": "0555"},
                gate.BOOT[1:]: {"sha256": hashlib.sha256(BOOT_RAW).hexdigest(), "mode": "0555"},
                "etc/sudoers.d/inkyos-test-access": {"sha256": "a" * 64, "mode": "0440"}}}


class Fixture:
    def __init__(self, fail=None, value=False):
        self.events = []
        self.fail, self.value = fail, value

    def called(self, name):
        self.events.append(name)
        if self.fail == len(self.events):
            if isinstance(self.value, BaseException):
                raise self.value
            return self.value
        return True

    def target(self): return self.called("target")
    def bind(self): return self.called("bind")
    def nm_start_pre(self): return self.called("nm_start_pre")
    def block_wlan(self): return self.called("block_wlan")
    def wlan_blocked(self): return self.called("wlan_blocked")
    def write_state(self): return self.called("write_state")
    def state_disabled(self): return self.called("state_disabled")
    def unchanged(self): return self.called("unchanged")


class GateTests(unittest.TestCase):
    def test_success_order_is_repeatable_and_fixture_is_never_live(self):
        expected = ["target", "bind", "nm_start_pre", "block_wlan", "wlan_blocked", "write_state",
                    "state_disabled", "wlan_blocked", "unchanged", "nm_start_pre"]
        for _ in range(2):
            fixture = Fixture()
            result = gate.guard(fixture)
            self.assertTrue(result["passed"])
            self.assertEqual(fixture.events, expected)
            self.assertEqual(result["checks"], dict.fromkeys(gate.CHECKS, True))
            for field in ("live_evidence", "connection_authorized", "activation_authorized", "hardware_qualified", "release_qualified"):
                self.assertIs(result[field], False)

    def test_each_failed_or_ambiguous_guard_stops_before_subsequent_mutations(self):
        errors = ["target_unverified", "source_pin_invalid", "networkmanager_not_starting", "wlan_block_failed",
                  "wlan_not_blocked", "state_write_failed", "state_readback_invalid", "wlan_not_blocked",
                  "state_changed", "networkmanager_not_starting"]
        for index, error in enumerate(errors, 1):
            for value in (False, None, 1, "yes", RuntimeError("private-input-must-not-leak")):
                with self.subTest(index=index, value=type(value).__name__):
                    fixture = Fixture(index, value)
                    result = gate.guard(fixture)
                    self.assertFalse(result["passed"])
                    self.assertEqual(len(fixture.events), index)
                    self.assertEqual(result["error"], "observation_unavailable" if isinstance(value, BaseException) else error)
                    self.assertNotIn("private-input", json.dumps(result))
                    self.assertFalse(result["live_evidence"])

    def test_deadline_stops_before_any_mutation(self):
        fixture = Fixture()
        with patch.object(gate.time, "monotonic", side_effect=[0, gate.BUDGET + 1]):
            result = gate.guard(fixture)
        self.assertEqual(result["error"], "runtime_timeout")
        self.assertEqual(fixture.events, [])

    def test_native_subclass_injection_remains_fixture_evidence(self):
        class Injected(Fixture, gate.NativeAdapter):
            pass
        result = gate.guard(Injected())
        self.assertTrue(result["passed"])
        self.assertFalse(result["live_evidence"])

    def test_manifest_accepts_exact_pins_and_other_static_mode_without_reading_paths(self):
        value = manifest()
        self.assertEqual(gate.validate_manifest(json.dumps(value).encode(), SELF_RAW, HELPER_RAW, BOOT_RAW), value)
        self.assertEqual(hashlib.sha256(HELPER_RAW).hexdigest(), gate.HELPER_SHA256)

    def test_manifest_closed_types_metadata_and_source_bindings(self):
        changes = [("schema_version", True), ("schema_version", 1.0), ("kind", "other"),
                   ("application_source_commit", "0" * 40), ("application_manifest_sha256", "0" * 64),
                   ("parent_image_sha256", "0" * 64), ("files", []), ("extra", False)]
        for field, value in changes:
            with self.subTest(field=field, value=value):
                candidate = manifest()
                candidate[field] = value
                with self.assertRaises(gate.GateError):
                    gate.validate_manifest(json.dumps(candidate).encode(), SELF_RAW, HELPER_RAW, BOOT_RAW)
        for name in (gate.SELF, gate.HELPER, gate.BOOT):
            for entry in (None, {"sha256": "0" * 64, "mode": "0555"},
                          {"sha256": manifest()["files"][name[1:]]["sha256"], "mode": "0644"}):
                candidate = manifest()
                if entry is None:
                    del candidate["files"][name[1:]]
                else:
                    candidate["files"][name[1:]] = entry
                with self.assertRaises(gate.GateError):
                    gate.validate_manifest(json.dumps(candidate).encode(), SELF_RAW, HELPER_RAW, BOOT_RAW)
        candidate = manifest()
        changed = HELPER_RAW + b"\n# changed\n"
        candidate["files"][gate.HELPER[1:]]["sha256"] = hashlib.sha256(changed).hexdigest()
        with self.assertRaisesRegex(gate.GateError, "source_pin_invalid"):
            gate.validate_manifest(json.dumps(candidate).encode(), SELF_RAW, changed, BOOT_RAW)

    def test_manifest_rejects_noncanonical_paths_duplicates_and_unknown_modes(self):
        for path in ("/etc/x", "../x", "etc/../x", "./x", "etc//x", "etc/./x", "etc/x/", "etc/\nx", "etc/é"):
            candidate = manifest()
            candidate["files"][path] = {"sha256": "a" * 64, "mode": "0644"}
            with self.subTest(path=path), self.assertRaises(gate.GateError):
                gate.validate_manifest(json.dumps(candidate).encode(), SELF_RAW, HELPER_RAW, BOOT_RAW)
        for mode in ("0600", "0777", 555, True):
            candidate = manifest()
            candidate["files"][gate.SELF[1:]]["mode"] = mode
            with self.assertRaises(gate.GateError):
                gate.validate_manifest(json.dumps(candidate).encode(), SELF_RAW, HELPER_RAW, BOOT_RAW)
        raw = json.dumps(manifest()).encode().replace(b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1')
        with self.assertRaises(gate.GateError):
            gate.validate_manifest(raw, SELF_RAW, HELPER_RAW, BOOT_RAW)

    def test_native_bind_refuses_helper_change_before_exec(self):
        values = {gate.MANIFEST: json.dumps(manifest()).encode(), gate.SELF: SELF_RAW,
                  gate.HELPER: b"raise RuntimeError('must never execute')\n", gate.BOOT: BOOT_RAW}
        adapter = gate.NativeAdapter()
        with patch.object(gate, "read_file", side_effect=lambda path, **_kwargs: values[path]):
            with self.assertRaisesRegex(gate.GateError, "source_pin_invalid"):
                adapter.bind()
        self.assertFalse(hasattr(adapter, "helper"))

    def test_native_bind_refuses_unpinned_boot_before_any_module_exec(self):
        values = {gate.MANIFEST: json.dumps(manifest()).encode(), gate.SELF: SELF_RAW,
                  gate.HELPER: HELPER_RAW, gate.BOOT: b"raise RuntimeError('must never execute')\n"}
        adapter = gate.NativeAdapter()
        with patch.object(gate, "read_file", side_effect=lambda path, **_kwargs: values[path]), \
                patch.object(gate, "exec", create=True) as execute:
            with self.assertRaisesRegex(gate.GateError, "source_pin_invalid"):
                adapter.bind()
        execute.assert_not_called()
        self.assertFalse(hasattr(adapter, "save_diagnostic"))
        self.assertFalse(hasattr(adapter, "helper"))

    def test_native_bind_uses_only_four_fixed_files_and_detects_boot_change(self):
        values = {gate.MANIFEST: json.dumps(manifest()).encode(), gate.SELF: SELF_RAW, gate.HELPER: HELPER_RAW, gate.BOOT: BOOT_RAW}
        adapter = gate.NativeAdapter()
        with patch.object(gate, "read_file", side_effect=lambda path, **_kwargs: values[path]) as reader:
            self.assertTrue(adapter.bind())
            self.assertTrue(callable(adapter.save_diagnostic))
            self.assertTrue(adapter.unchanged())
            self.assertEqual({call.args[0] for call in reader.call_args_list}, set(values))
            values[gate.BOOT] += b"\n"
            self.assertFalse(adapter.unchanged())

    def test_native_diagnostic_module_is_bound_without_running_its_cli(self):
        boot_raw = (b"def save_gate_diagnostic(result):\n    return False\n"
                    b"if __name__ == '__main__':\n    raise RuntimeError('CLI must not execute')\n")
        candidate = manifest()
        candidate["files"][gate.BOOT[1:]]["sha256"] = hashlib.sha256(boot_raw).hexdigest()
        values = {gate.MANIFEST: json.dumps(candidate).encode(), gate.SELF: SELF_RAW,
                  gate.HELPER: HELPER_RAW, gate.BOOT: boot_raw}
        adapter = gate.NativeAdapter()
        with patch.object(gate, "read_file", side_effect=lambda path, **_kwargs: values[path]):
            self.assertTrue(adapter.bind())
        self.assertFalse(adapter.save_diagnostic(gate.empty_result()))

    def test_guard_does_not_persist_inside_radio_deadline(self):
        fixture = Fixture()
        with patch.object(fixture, "save_diagnostic", create=True) as writer:
            self.assertTrue(gate.guard(fixture)["passed"])
        writer.assert_not_called()

    def test_main_persists_success_and_refusal_only_after_signal_restoration(self):
        for fail in (None, 4, 10):
            fixture = Fixture(fail)
            saved = []
            old_handler, old_timer = object(), (7.0, 2.0)
            with patch.object(gate, "NativeAdapter", return_value=fixture), \
                    patch.object(gate.signal, "signal", return_value=old_handler) as handler, \
                    patch.object(gate.signal, "setitimer", return_value=old_timer) as timer:
                def save(result):
                    self.assertEqual(handler.call_count, 2)
                    self.assertEqual(handler.call_args.args, (gate.signal.SIGALRM, old_handler))
                    self.assertEqual(timer.call_count, 2)
                    self.assertEqual(timer.call_args_list[0].args, (gate.signal.ITIMER_REAL, gate.BUDGET))
                    self.assertEqual(timer.call_args.args, (gate.signal.ITIMER_REAL, *old_timer))
                    saved.append(json.loads(json.dumps(result)))
                    return True
                fixture.save_diagnostic = save
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = gate.main([])
            result = json.loads(output.getvalue())
            self.assertEqual(code, 0 if fail is None else 1)
            self.assertEqual(saved, [result])
            self.assertEqual(result["error"], {None: None, 4: "wlan_block_failed",
                                              10: "networkmanager_not_starting"}[fail])

    def test_diagnostic_failure_does_not_change_gate_status_or_radio_calls(self):
        for fail in (None, 4):
            for writer_failure in (False, RuntimeError("private-error-must-not-leak")):
                fixture = Fixture(fail)
                expected = gate.guard(Fixture(fail))
                def save(_result):
                    if isinstance(writer_failure, Exception):
                        raise writer_failure
                    return writer_failure
                fixture.save_diagnostic = save
                with patch.object(gate, "NativeAdapter", return_value=fixture), \
                        patch.object(gate.signal, "signal"), \
                        patch.object(gate.signal, "setitimer", return_value=(0.0, 0.0)):
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        code = gate.main([])
                self.assertEqual(json.loads(output.getvalue()), expected)
                self.assertEqual(code, 0 if fail is None else 1)
                self.assertNotIn("private-error", output.getvalue())

    def test_invalid_arguments_never_instantiate_adapter_or_persist(self):
        with patch.object(gate, "NativeAdapter") as adapter, \
                patch.object(gate.signal, "signal") as handler, \
                patch.object(gate.signal, "setitimer") as timer:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(gate.main(["--unexpected"]), 1)
        self.assertEqual(json.loads(output.getvalue())["error"], "invalid_arguments")
        adapter.assert_not_called()
        handler.assert_not_called()
        timer.assert_not_called()

    def test_native_only_blocks_wlan_and_command_ack_is_not_a_readback(self):
        adapter = gate.NativeAdapter()
        with patch.object(adapter, "command", return_value=(0, b"")) as command:
            self.assertTrue(adapter.block_wlan())
        command.assert_called_once_with(("/usr/sbin/rfkill", "block", "wlan"))
        self.assertNotIn("all", gate.BLOCK_WLAN)
        self.assertFalse(gate.wlan_blocked([(b"wlan\n", b"0\n")]))

    def test_sysfs_policy_requires_at_least_one_wlan_and_every_wlan_blocked(self):
        self.assertTrue(gate.wlan_blocked([(b"wlan\n", b"1\n"), (b"bluetooth\n", b"0\n")]))
        for rows in ([], [(b"bluetooth\n", b"1\n")], [(b"wlan\n", b"1\n"), (b"wlan\n", b"0\n")],
                     [(b"wlan\n", b"true\n")], [(b"unknown\n", b"1\n")], [(b"wlan\n", True)],
                     [[b"wlan\n", b"1\n"]], [(b"wlan\n", b"1\n")] * 65):
            with self.subTest(rows=rows):
                self.assertFalse(gate.wlan_blocked(rows))

    def test_native_refuses_running_nm_or_ambiguous_start_pre(self):
        adapter = gate.NativeAdapter()
        valid = b"MainPID=0\nActiveState=activating\nSubState=start-pre\n"
        with patch.object(adapter, "command", return_value=(0, valid)) as command:
            self.assertTrue(adapter.nm_start_pre())
        command.assert_called_once_with(gate.NM_STATUS)
        for code, raw in ((1, valid), (0, valid + b"MainPID=0\n"),
                          (0, valid.replace(b"MainPID=0", b"MainPID=25")),
                          (0, valid.replace(b"activating", b"active")), (0, b"")):
            with patch.object(adapter, "command", return_value=(code, raw)):
                self.assertFalse(adapter.nm_start_pre())

    def test_command_output_limit_and_timeout_use_only_disposable_python_children(self):
        adapter = gate.NativeAdapter()
        adapter.deadline = time.monotonic() + 3
        with self.assertRaisesRegex(gate.GateError, "observation_unavailable"):
            adapter.command((sys.executable, "-c", "import os; os.write(1, b'x' * 4097)"))
        adapter.deadline = time.monotonic() + 0.1
        with self.assertRaisesRegex(gate.GateError, "runtime_timeout"):
            adapter.command((sys.executable, "-c", "import time; time.sleep(5)"))

    def test_native_writer_fixed_root_and_verified_readback(self):
        adapter = gate.NativeAdapter()
        namespace = {"__name__": "fixture_pinned_writer"}
        exec(compile(HELPER_RAW, gate.HELPER, "exec"), namespace)
        adapter.helper = namespace
        with patch.dict(namespace, {"set_wireless_disabled": lambda root: {
                "durably_written": root == "/", "wireless_enabled": False}}):
            self.assertTrue(adapter.write_state())
        for raw, expected in ((b"[main]\nWirelessEnabled=false\n", True),
                              (b"[main]\nWirelessEnabled=true\n", False),
                              (b"[main]\nNetworkingEnabled=false\n", False)):
            with patch.object(gate, "read_file", return_value=raw) as reader:
                self.assertIs(adapter.state_disabled(), expected)
            reader.assert_called_once_with(gate.STATE, mode=0o600)

    def test_cli_wrong_arguments_and_wrong_target_refuse_without_mutations(self):
        for args in ([], ["--root", "/fixture"], ["--live"], ["--help"]):
            # This process has neither target hardware nor a fixed runtime manifest.
            result = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/test-access-wifi-gate.py"), *args],
                                    capture_output=True, timeout=4, check=False)
            self.assertEqual(result.returncode, 1)
            report = json.loads(result.stdout)
            self.assertFalse(report["passed"])
            self.assertFalse(any(report["checks"].values()))
            self.assertEqual(report["error"], "invalid_arguments" if args else "target_unverified")
            self.assertEqual(result.stderr, b"")

    def test_dropin_orders_rfkill_and_executes_fixed_entry_on_every_start(self):
        raw = (ROOT / "overlay-test-access/NetworkManager.service.d/10-inkyos-test-wifi.conf").read_text()
        self.assertIn("Wants=systemd-rfkill.service\nAfter=systemd-rfkill.service", raw)
        self.assertIn("ExecStartPre=/usr/bin/python3 -I " + gate.SELF + "\n", raw)
        self.assertIn("StateDirectory=inkyos-test-diagnostics\nStateDirectoryMode=0700\n", raw)
        for forbidden in ("ExecStartPre=-", "ExecCondition", "RemainAfterExit", "rfkill block all", "bluetooth"):
            self.assertNotIn(forbidden, raw)


if __name__ == "__main__":
    unittest.main()
