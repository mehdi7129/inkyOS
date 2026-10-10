"""Boot phase ordering and failure isolation; never invoke a real service."""
import importlib.util
import copy
import json
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "scripts/test-access-boot.py"
spec = importlib.util.spec_from_file_location("access_boot", SOURCE)
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


def load_script(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), SOURCE.parent / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


connect = load_script("test-access-connect")
importer = load_script("test-access-import")
gate = load_script("test-access-wifi-gate")
country = load_script("test-access-network")
legacy = load_script("test-enrollment-firstboot")


class Fixture:
    def __init__(self, phase="enrolled", fail=None):
        self.phase, self.fail, self.calls = phase, fail, []

    def call(self, name, value=True):
        self.calls.append(name)
        if name == self.fail:
            raise OSError("private fixture detail must never reach result")
        return value

    def bind(self):
        return self.call("bind", self.phase)

    def enroll(self):
        return self.call("enroll", {"passed": True, "poweroff_requested": True})

    def import_cache(self):
        return self.call("import", {"passed": True})

    def connect(self):
        return self.call("connect", {"passed": True})

    def operator_config(self):
        return self.call("config")

    def publish_ready(self):
        return self.call("publish")

    def verify_ready(self):
        return self.call("verify")

    def start_ssh(self):
        return self.call("ssh")

    def close_wifi(self):
        return self.call("off")

    def close(self):
        return self.call("close")


class BootTests(unittest.TestCase):
    def test_fresh_only_enrolls_and_stops(self):
        adapter = Fixture("fresh")
        result = boot.boot(adapter)
        self.assertTrue(result["passed"])
        self.assertTrue(result["poweroff_requested"])
        self.assertEqual(adapter.calls, ["bind", "enroll", "close"])
        self.assertFalse(result["ssh_start_requested"])
        self.assertFalse(result["live_evidence"])

    def test_complete_access_never_claims_daemon_started_or_app_authorized(self):
        adapter = Fixture()
        result = boot.boot(adapter)
        self.assertTrue(result["passed"])
        self.assertEqual(adapter.calls, ["bind", "import", "connect", "config", "publish", "verify", "ssh", "close"])
        self.assertTrue(result["ssh_start_requested"])
        for key in ("ssh_start_verified", "application_activation_authorized", "hardware_qualified", "release_qualified"):
            self.assertFalse(result[key])

    def test_all_failures_stop_sequence_and_hide_details(self):
        sequence = ["bind", "import", "connect", "config", "publish", "verify", "ssh"]
        for index, stage in enumerate(sequence):
            with self.subTest(stage=stage):
                adapter = Fixture(fail=stage)
                result = boot.boot(adapter)
                self.assertFalse(result["passed"])
                self.assertNotIn("private fixture", repr(result))
                self.assertEqual(adapter.calls[:index+1], sequence[:index+1])
                self.assertEqual(adapter.calls[index+1:], (["off"] if index >= 2 else []) + ["close"])

    def test_failed_import_result_never_connects(self):
        adapter = Fixture()
        adapter.import_cache = lambda: {"passed": False, "error": "private-data"}
        result = boot.boot(adapter)
        self.assertEqual(result["error"], "import_failed")
        self.assertEqual(adapter.calls, ["bind", "close"])

    def test_ssh_condition_does_not_import_connect_publish_or_start(self):
        adapter = Fixture()
        self.assertTrue(boot.boot(adapter, verify_ssh=True)["passed"])
        self.assertEqual(adapter.calls, ["bind", "verify", "close"])
        adapter = Fixture("fresh")
        self.assertFalse(boot.boot(adapter, verify_ssh=True)["passed"])
        self.assertEqual(adapter.calls, ["bind", "close"])

    def test_unknown_existing_state_is_not_fresh(self):
        adapter = Fixture("pending")
        self.assertEqual(boot.boot(adapter)["error"], "enrollment_invalid")
        self.assertEqual(adapter.calls, ["bind", "close"])

    def test_failed_enrollment_does_not_fall_through(self):
        adapter = Fixture("fresh", fail="enroll")
        self.assertFalse(boot.boot(adapter)["passed"])
        self.assertEqual(adapter.calls, ["bind", "enroll", "close"])

    def test_cli_has_no_root_or_pin_override(self):
        with patch.object(boot, "NativeAdapter", side_effect=AssertionError("must remain inert")), patch("builtins.print"):
            self.assertEqual(boot.main(["--root", "/tmp"]), 1)

    def test_close_failure_after_ssh_ack_requests_radio_off(self):
        adapter = Fixture(fail="close")
        result = boot.boot(adapter)
        self.assertFalse(result["passed"])
        self.assertTrue(result["wifi_off_requested_on_failure"])
        self.assertTrue(result["ssh_start_requested"])
        self.assertEqual(adapter.calls[-3:], ["ssh", "close", "off"])


class DiagnosticFixture(Fixture):
    def __init__(self, *args, writer_failure=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []
        self.writer_failure = writer_failure
        self.import_result = {"passed": True, "imported": True, "reused_committed_cache": True,
                              "state": "imported", "error": None}
        self.connect_result = connect.empty_result()
        self.connect_result.update(passed=True, connected=True)

    def import_cache(self):
        return self.call("import", self.import_result)

    def connect(self):
        return self.call("connect", self.connect_result)

    def save_diagnostic(self, result, **kwargs):
        self.calls.append("diagnostic")
        self.records.append(copy.deepcopy({"result": result, **kwargs}))
        if self.writer_failure:
            raise OSError("PRIVATE_WRITER_ERROR")
        return True


class BootDiagnosticSequenceTests(unittest.TestCase):
    def test_started_report_precedes_bind_and_final_follows_close(self):
        fixture = DiagnosticFixture()
        result = boot.boot(fixture)
        self.assertTrue(result["passed"])
        self.assertEqual(fixture.calls, ["diagnostic", "bind", "import", "connect", "config", "publish",
                                         "verify", "ssh", "close", "diagnostic"])
        started, final = fixture.records
        self.assertFalse(started["complete"])
        self.assertEqual(started["stage"], "bind")
        self.assertIsNone(started["imported"])
        self.assertIsNone(started["connected"])
        self.assertFalse(started["result"]["passed"])
        self.assertTrue(final["complete"])
        self.assertEqual(final["stage"], "complete")
        self.assertEqual(final["result"], result)
        self.assertEqual(final["imported"], fixture.import_result)
        self.assertEqual(final["connected"], fixture.connect_result)

    def test_failure_stage_retained_after_cleanup_and_before_final_report(self):
        sequence = [("bind", "bind"), ("import", "import"), ("connect", "connect"),
                    ("config", "operator_config"), ("publish", "publish_ready"),
                    ("verify", "verify_ready"), ("ssh", "start_ssh")]
        for index, (method, stage) in enumerate(sequence):
            with self.subTest(method=method):
                fixture = DiagnosticFixture(fail=method)
                result = boot.boot(fixture)
                self.assertFalse(result["passed"])
                self.assertEqual(fixture.calls[-(3 if index >= 2 else 2):],
                                 (["off"] if index >= 2 else []) + ["close", "diagnostic"])
                final = fixture.records[-1]
                self.assertTrue(final["complete"])
                self.assertEqual(final["stage"], stage)
                self.assertEqual(final["result"], result)
                if index <= 2:
                    self.assertIsNone(final["connected"])
                else:
                    self.assertEqual(final["connected"], fixture.connect_result)
                if index <= 1:
                    self.assertIsNone(final["imported"])

    def test_fresh_enrollment_report_never_contains_import_or_connect(self):
        for fail in (None, "enroll"):
            fixture = DiagnosticFixture("fresh", fail=fail)
            result = boot.boot(fixture)
            self.assertEqual(fixture.calls, ["diagnostic", "bind", "enroll", "close", "diagnostic"])
            final = fixture.records[-1]
            self.assertEqual(final["stage"], "complete" if fail is None else "enroll")
            self.assertEqual(final["result"], result)
            self.assertIsNone(final["imported"])
            self.assertIsNone(final["connected"])

    def test_failed_import_and_connection_receipts_preserved_for_projection(self):
        for failed in ("import", "connect"):
            fixture = DiagnosticFixture()
            receipt = fixture.import_result if failed == "import" else fixture.connect_result
            receipt.update(passed=False, error="cache_invalid" if failed == "import" else "country_unconfirmed")
            result = boot.boot(fixture)
            final = fixture.records[-1]
            self.assertEqual(final["stage"], failed)
            self.assertEqual(final["result"], result)
            self.assertEqual(final["imported"], fixture.import_result)
            if failed == "connect":
                self.assertEqual(final["connected"], receipt)
                self.assertEqual(fixture.calls[-3:], ["off", "close", "diagnostic"])
            else:
                self.assertIsNone(final["connected"])
                self.assertNotIn("connect", fixture.calls)

    def test_cleanup_failure_is_reflected_in_last_record(self):
        fixture = DiagnosticFixture(fail="close")
        result = boot.boot(fixture)
        self.assertEqual(fixture.calls[-4:], ["ssh", "close", "off", "diagnostic"])
        self.assertEqual(fixture.records[-1]["stage"], "cleanup")
        self.assertEqual(fixture.records[-1]["result"], result)
        self.assertFalse(result["passed"])
        self.assertTrue(result["wifi_off_requested_on_failure"])

    def test_cleanup_error_after_connection_failure_keeps_original_stage(self):
        fixture = DiagnosticFixture(fail="connect")
        def close():
            fixture.calls.append("close")
            raise OSError("PRIVATE_SECONDARY_CLEANUP_ERROR")
        fixture.close = close
        result = boot.boot(fixture)
        self.assertEqual(fixture.calls[-3:], ["off", "close", "diagnostic"])
        self.assertEqual(fixture.records[-1]["stage"], "connect")
        self.assertEqual(fixture.records[-1]["result"], result)
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_writers_are_best_effort_without_changing_success_or_failure(self):
        for phase, failure in (("fresh", None), ("enrolled", None), ("enrolled", "connect"), ("enrolled", "close")):
            expected = boot.boot(Fixture(phase, fail=failure))
            fixture = DiagnosticFixture(phase, fail=failure, writer_failure=True)
            self.assertEqual(boot.boot(fixture), expected)
            self.assertEqual(len(fixture.records), 2)
            self.assertEqual(fixture.calls[-1], "diagnostic")
        fixture = Fixture()
        fixture.save_diagnostic = "PRIVATE_NOT_CALLABLE"
        self.assertTrue(boot.boot(fixture)["passed"])
        fixture.save_diagnostic = lambda *_args, **_kwargs: False
        self.assertTrue(boot.boot(fixture)["passed"])

    def test_ssh_condition_never_writes_or_replaces_diagnostics(self):
        for phase, failure in (("enrolled", None), ("fresh", None), ("enrolled", "verify")):
            fixture = DiagnosticFixture(phase, fail=failure, writer_failure=True)
            boot.boot(fixture, verify_ssh=True)
            self.assertEqual(fixture.records, [])
            self.assertNotIn("diagnostic", fixture.calls)


class DiagnosticProjectionTests(unittest.TestCase):
    def setUp(self):
        self.result = boot.boot(Fixture())
        self.imported = DiagnosticFixture().import_result
        self.connected = connect.empty_result()
        self.country = {"status": "available", "error": "country_unconfirmed", "test_country_ready": False,
                        "live_evidence": False, "country_set_attempted": True, "country_request_acknowledged": True,
                        "wifi_closed_verified": True, "checks": dict.fromkeys(country.POLICY_CHECKS, False)}
        self.connected["country_diagnostic"] = self.country

    def project(self):
        return boot.boot_diagnostic(self.result, complete=True, stage="connect",
                                    imported=self.imported, connected=self.connected)

    def test_projection_keeps_only_closed_diagnostic_fields(self):
        for item in (self.result, self.imported, self.connected, self.country):
            item.update(ssid="PRIVATE_SSID", psk="PRIVATE_PSK", identifier="PRIVATE_IDENTIFIER",
                        stdout="PRIVATE_STDOUT", stderr="PRIVATE_STDERR", firmware="PRIVATE_FIRMWARE",
                        kernel="PRIVATE_KERNEL", PRIVATE_KEY="PRIVATE_VALUE")
        report = self.project()
        self.assertNotIn("PRIVATE", json.dumps(report))
        self.assertEqual(report["stage"], "connect")
        self.assertEqual(report["import"]["state"], "imported")
        self.assertEqual(report["connection"]["country"]["error"], "country_unconfirmed")
        self.assertEqual(report["connection"]["cleanup"], self.connected["cleanup"])
        for key in ("connection_authorized", "application_activation_authorized", "hardware_qualified"):
            self.assertIs(report[key], False)
        self.country["checks"]["firmware_country_fr"] = True
        self.connected["cleanup"]["required"] = True
        self.assertFalse(report["connection"]["country"]["checks"]["firmware_country_fr"])
        self.assertFalse(report["connection"]["cleanup"]["required"])

    def test_closed_errors_types_and_unknown_stages_rejected_without_reflection(self):
        for source, output in ((self.result, "boot"), (self.imported, "import"), (self.connected, "connection")):
            original = dict(source)
            for field, bad in (("error", "PRIVATE_ERROR"), ("error", []), ("passed", 1), ("passed", "PRIVATE_BOOL")):
                source[field] = bad
                report = self.project()
                self.assertEqual(report[output], {"status": "unavailable"})
                self.assertNotIn("PRIVATE", json.dumps(report))
                source.clear(); source.update(original)
            del source["error"]
            self.assertEqual(self.project()[output], {"status": "unavailable"})
            source.clear(); source.update(original)
        self.result["phase"] = "PRIVATE_PHASE"
        self.imported["state"] = "PRIVATE_STATE"
        self.assertEqual(self.project()["boot"], {"status": "unavailable"})
        self.assertEqual(self.project()["import"], {"status": "unavailable"})
        for complete, stage in ((1, "connect"), (True, "PRIVATE_STAGE"), (False, [])):
            with self.assertRaisesRegex(boot.BootError, "invalid_arguments"):
                boot.boot_diagnostic(self.result, complete=complete, stage=stage)

    def test_connection_country_and_cleanup_validation_cannot_export_raw_values(self):
        original = copy.deepcopy(self.connected)
        mutations = [("checks", {**self.connected["checks"], "PRIVATE_CHECK": True}),
                     ("checks", {**self.connected["checks"], "country_live_verified": 1}),
                     ("cleanup", {**self.connected["cleanup"], "radio_off_verified": "PRIVATE"}),
                     ("cleanup", None)]
        for key, value in mutations:
            self.connected[key] = value
            self.assertEqual(self.project()["connection"], {"status": "unavailable"})
            self.connected.clear(); self.connected.update(copy.deepcopy(original))
        for value in ("PRIVATE_COUNTRY", {"status": "PRIVATE"},
                      {**self.country, "error": "PRIVATE_ERROR"},
                      {**self.country, "wifi_closed_verified": 1},
                      {**self.country, "checks": {**self.country["checks"], "PRIVATE_CHECK": True}}):
            self.connected["country_diagnostic"] = value
            self.assertEqual(self.project()["connection"]["country"], {"status": "unavailable"})
            self.assertNotIn("PRIVATE", json.dumps(self.project()))
        self.connected["country_diagnostic"] = None
        self.assertIsNone(self.project()["connection"]["country"])

    def test_native_saves_projection_and_gate_uses_independent_closed_contract(self):
        with patch.object(boot, "persist_diagnostic", return_value=True) as persist:
            self.assertTrue(boot.NativeAdapter().save_diagnostic(self.result, complete=True, stage="connect",
                           imported=self.imported, connected=self.connected))
            self.assertEqual(persist.call_args.args, ("last-boot.json", self.project()))
            value = {"passed": False, "error": "state_changed", "checks": dict.fromkeys(gate.CHECKS, False),
                     "stdout": "PRIVATE_STDOUT", "ssid": "PRIVATE_SSID"}
            self.assertTrue(boot.save_gate_diagnostic(value))
            name, record = persist.call_args.args
            self.assertEqual(name, "last-wifi-gate.json")
            self.assertEqual(record["gate"]["error"], "state_changed")
            self.assertEqual(record["gate"]["checks"], value["checks"])
            self.assertNotIn("PRIVATE", json.dumps(record))

    def test_independent_allowlists_match_producer_contracts(self):
        self.assertEqual(boot.IMPORT_ERRORS, importer.ERRORS)
        self.assertEqual(boot.CONNECT_ERRORS, connect.ERRORS)
        self.assertEqual(boot.CONNECT_CHECKS, connect.CHECKS)
        self.assertEqual(boot.COUNTRY_ERRORS, country.ERRORS | {"interrupted"})
        self.assertEqual(boot.COUNTRY_CHECKS, country.POLICY_CHECKS)
        self.assertEqual(boot.GATE_ERRORS, gate.ERRORS)
        self.assertEqual(boot.GATE_CHECKS, gate.CHECKS)


class DiagnosticPersistenceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix=".inkyos-diagnostic-fixture-", dir=Path.home().resolve())
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.root.chmod(0o700)
        self.directory = self.root / boot.DIAGNOSTICS.lstrip("/")
        self.directory.mkdir(parents=True, mode=0o700)
        # mkdir(parents=True) applies the leaf mode only. Match the real
        # non-writable system parents independently of the host's umask.
        for parent in self.directory.parents:
            if parent == self.root:
                break
            parent.chmod(0o755)
        self.directory.chmod(0o700)
        self.owner = os.getuid()
        self.files = legacy.Files(str(self.root), owner=self.owner)
        self.addCleanup(self.files.close)
        native_rename = os.sys.platform.startswith("linux")
        def rename(directory, source, target):
            if native_rename:
                return legacy.rename_noreplace(directory, source, target)
            os.link(source, target, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
            os.unlink(source, dir_fd=directory)
        def write(directory, name, raw, **kwargs):
            return legacy.write_atomic(directory, name, raw, rename=rename, **kwargs)
        self.lib = {"_metadata": legacy._metadata, "_stamp": legacy._stamp, "write_atomic": write,
                    "Files": lambda: legacy.Files(str(self.root), owner=self.owner)}
        self.payload = boot.boot_diagnostic(boot.boot(Fixture()), complete=True, stage="complete")

    def write(self, name="last-boot.json", payload=None):
        return boot.write_diagnostic(self.lib, self.files, name, self.payload if payload is None else payload)

    def test_first_write_and_replacement_are_private_and_read_back(self):
        self.assertTrue(self.write())
        target = self.directory / "last-boot.json"
        self.assertEqual(target.read_bytes(), boot.canonical(self.payload))
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        first_inode = target.stat().st_ino
        self.payload["complete"] = False
        self.assertTrue(self.write())
        self.assertEqual(target.read_bytes(), boot.canonical(self.payload))
        self.assertNotEqual(target.stat().st_ino, first_inode)
        self.assertEqual(sorted(path.name for path in self.directory.iterdir()), ["last-boot.json"])

    def test_symlink_target_is_refused_and_never_overwritten(self):
        other = self.root / "outside.json"
        other.write_bytes(b"PRIVATE_OLD_CONTENT")
        other.chmod(0o600)
        target = self.directory / "last-boot.json"
        target.symlink_to(other)
        with self.assertRaises(legacy.EnrollmentError):
            self.write()
        self.assertTrue(target.is_symlink())
        self.assertEqual(other.read_bytes(), b"PRIVATE_OLD_CONTENT")
        self.assertFalse((self.directory / ".last-boot.json.tmp").exists())

    def test_interrupted_temp_blocks_first_write_and_replacement_without_repair(self):
        for existing in (False, True):
            with self.subTest(existing=existing):
                if existing:
                    self.assertTrue(self.write())
                temporary = self.directory / ".last-boot.json.tmp"
                temporary.write_bytes(b"PRIVATE_INTERRUPTED")
                temporary.chmod(0o600)
                original = (self.directory / "last-boot.json").read_bytes() if existing else None
                with self.assertRaises(FileExistsError):
                    self.write(payload={"complete": False})
                self.assertEqual(temporary.read_bytes(), b"PRIVATE_INTERRUPTED")
                if existing:
                    self.assertEqual((self.directory / "last-boot.json").read_bytes(), original)
                else:
                    self.assertFalse((self.directory / "last-boot.json").exists())
                temporary.unlink()

    def test_writer_rejects_unknown_name_oversized_payload_and_unsafe_existing_mode(self):
        for name, payload in (("PRIVATE_NAME", self.payload), ("last-boot.json", {"data": "X" * boot.DIAGNOSTIC_LIMIT})):
            with self.assertRaisesRegex(boot.BootError, "invalid_arguments"):
                self.write(name, payload)
        self.assertEqual(list(self.directory.iterdir()), [])
        self.assertTrue(self.write())
        target = self.directory / "last-boot.json"
        original = target.read_bytes()
        target.chmod(0o644)
        with self.assertRaises(legacy.EnrollmentError):
            self.write()
        self.assertEqual(target.read_bytes(), original)

    def test_persist_is_native_only_and_catches_storage_failure(self):
        with patch.object(boot.sys, "platform", "darwin"), patch.object(boot, "bootstrap") as bootstrap:
            self.assertFalse(boot.persist_diagnostic("last-boot.json", self.payload))
            bootstrap.assert_not_called()
        with patch.object(boot.sys, "platform", "linux"), patch.object(boot.platform, "machine", return_value="aarch64"), \
                patch.object(boot.os, "getuid", return_value=0), patch.object(boot.os, "geteuid", return_value=0), \
                patch.object(boot, "bootstrap", return_value=self.lib), \
                patch.object(boot, "diagnostic_boot_id", return_value="00000000-0000-0000-0000-000000000001"):
            self.assertTrue(boot.persist_diagnostic("last-boot.json", self.payload))
            saved = json.loads((self.directory / "last-boot.json").read_bytes())
            self.assertEqual(saved.pop("boot_id"), "00000000-0000-0000-0000-000000000001")
            self.assertEqual(saved, self.payload)
            with patch.object(boot, "write_diagnostic", side_effect=OSError("PRIVATE_STORAGE_ERROR")):
                self.assertFalse(boot.persist_diagnostic("last-boot.json", self.payload))

    @unittest.skipUnless(hasattr(os, "fork"), "POSIX fork fixture required")
    def test_slow_storage_cannot_hold_up_boot_and_preserves_partial_temp(self):
        partial = self.directory / ".last-boot.json.tmp"
        late = self.directory / "late-write-must-not-happen"
        children = []
        real_fork = os.fork
        def fork():
            pid = real_fork()
            if pid > 0:
                children.append(pid)
            return pid
        def slow_writer(*_args):
            with partial.open("xb") as stream:
                stream.write(b"PRIVATE_PARTIAL_FIXTURE")
                stream.flush()
            time.sleep(2)
            late.write_bytes(b"must never reach this operation")
            return True
        def reap_fixture_children():
            deadline = time.monotonic() + 1
            pending = set(children)
            while pending and time.monotonic() < deadline:
                for pid in tuple(pending):
                    try:
                        reaped, _status = os.waitpid(pid, os.WNOHANG)
                    except ChildProcessError:
                        pending.remove(pid)
                    else:
                        if reaped == pid:
                            pending.remove(pid)
                if pending:
                    time.sleep(0.01)
            self.assertFalse(pending, "fixture children were not reaped after SIGKILL")
        self.addCleanup(reap_fixture_children)
        fixture = Fixture()
        fixture.save_diagnostic = lambda result, **observations: boot.persist_diagnostic(
            "last-boot.json", boot.boot_diagnostic(result, **observations))
        bind_times = []
        original_bind = fixture.bind
        def bind():
            bind_times.append(time.monotonic())
            return original_bind()
        fixture.bind = bind
        with patch.object(boot.sys, "platform", "linux"), patch.object(boot.platform, "machine", return_value="aarch64"), \
                patch.object(boot.os, "getuid", return_value=0), patch.object(boot.os, "geteuid", return_value=0), \
                patch.object(boot, "DIAGNOSTIC_TIMEOUT", 0.08), patch.object(boot.os, "fork", side_effect=fork), \
                patch.object(boot, "_persist_diagnostic", side_effect=slow_writer):
            started = time.monotonic()
            result = boot.boot(fixture)
            elapsed = time.monotonic() - started
        self.assertTrue(result["passed"])
        self.assertEqual(fixture.calls, ["bind", "import", "connect", "config", "publish", "verify", "ssh", "close"])
        self.assertLess(bind_times[0] - started, 0.75)
        self.assertLess(elapsed, 0.75)
        self.assertEqual(len(children), 2)
        self.assertEqual(partial.read_bytes(), b"PRIVATE_PARTIAL_FIXTURE")
        self.assertFalse(late.exists())
        self.assertFalse((self.directory / "last-boot.json").exists())

    def test_timeout_kills_child_and_uses_only_nonblocking_wait(self):
        with patch.object(boot.sys, "platform", "linux"), patch.object(boot.platform, "machine", return_value="aarch64"), \
                patch.object(boot.os, "getuid", return_value=0), patch.object(boot.os, "geteuid", return_value=0), \
                patch.object(boot.os, "fork", return_value=12345), \
                patch.object(boot.os, "waitpid", return_value=(0, 0)) as waitpid, \
                patch.object(boot.os, "kill") as kill, patch.object(boot.time, "sleep"), \
                patch.object(boot.time, "monotonic", side_effect=[0.0, 0.0, 0.01, 2.0]):
            self.assertFalse(boot.persist_diagnostic("last-boot.json", self.payload))
        self.assertEqual([row.args for row in waitpid.call_args_list], [(12345, os.WNOHANG)] * 2)
        kill.assert_called_once_with(12345, boot.signal.SIGKILL)

    def test_fork_failure_returns_without_storage_or_child_signal(self):
        with patch.object(boot.sys, "platform", "linux"), patch.object(boot.platform, "machine", return_value="aarch64"), \
                patch.object(boot.os, "getuid", return_value=0), patch.object(boot.os, "geteuid", return_value=0), \
                patch.object(boot.os, "fork", side_effect=OSError("PRIVATE_FORK_ERROR")), \
                patch.object(boot.os, "kill") as kill, patch.object(boot, "_persist_diagnostic") as store:
            self.assertFalse(boot.persist_diagnostic("last-boot.json", self.payload))
        kill.assert_not_called()
        store.assert_not_called()

    def test_already_reaped_child_is_never_signalled(self):
        with patch.object(boot.sys, "platform", "linux"), patch.object(boot.platform, "machine", return_value="aarch64"), \
                patch.object(boot.os, "getuid", return_value=0), patch.object(boot.os, "geteuid", return_value=0), \
                patch.object(boot.os, "fork", return_value=12345), \
                patch.object(boot.os, "waitpid", side_effect=ChildProcessError), patch.object(boot.os, "kill") as kill:
            self.assertFalse(boot.persist_diagnostic("last-boot.json", self.payload))
        kill.assert_not_called()


if __name__ == "__main__":
    unittest.main()
