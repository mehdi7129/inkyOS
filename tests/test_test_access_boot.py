"""Boot phase ordering and failure isolation; never invoke a real service."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "scripts/test-access-boot.py"
spec = importlib.util.spec_from_file_location("access_boot", SOURCE)
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


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


if __name__ == "__main__":
    unittest.main()
