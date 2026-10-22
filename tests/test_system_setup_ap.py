"""Real AP controller lifecycle with inert ports; no radio, filesystem or clock effects."""

import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "setup_ap_test", ROOT / "staging/bootstrap/system-setup-ap.py"
)
ap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ap)
U = lambda n: f"00000000-0000-0000-0000-{n:012d}"
WF = {
    "initialization_intent": U(1),
    "initialization_receipt_digest": "a" * 64,
    "frame_id": U(2),
    "spki_sha256": "b" * 64,
}
CONTEXT = {
    "boot_id": U(3),
    "candidate_sha256": "c" * 64,
    "context_sha256": "d" * 64,
    "main_invocation_id": "e" * 32,
}


class CheckError(ValueError):
    reason = "session_closed"


class Check:
    allowed = True

    def __call__(self):
        if not self.allowed:
            raise CheckError("session_closed")


class Clock:
    def __init__(self):
        self.now = 1_000_000_000

    def __call__(self):
        return self.now


class NativeError(ValueError):
    def __init__(self, record=None, reason="ap_timeout"):
        self.reason, self.record, self.reconciliation = reason, record, True
        super().__init__("adapter errors may contain secrets")


class Adapter:
    def __init__(self):
        self.starts, self.verifies, self.stops = [], [], []
        self.closed = False
        self.owned_record = None
        self.start_hook = self.verify_hook = self.stop_hook = None
        self.current_config = None

    def start(self, config, check):
        check()
        self.starts.append(copy.deepcopy(config))
        self.current_config = config
        self.owned_record = {
            "ap_id": config["ap_id"], "boot_id": config["boot_id"],
            "profile_uuid": U(10),
            "active_path": "/org/freedesktop/NetworkManager/ActiveConnection/1",
        }
        if self.start_hook:
            self.start_hook(config)
        return self.owned_record

    def verify(self, record, check):
        check()
        self.verifies.append(record)
        value = {
            "active": True, "state": "active",
            **{key: self.current_config[key] for key in ("ap_id", "country", "interface", "host", "prefix", "port", "channel")},
        }
        if self.verify_hook:
            self.verify_hook(value)
        return value

    def stop(self, record, check):
        check()
        self.stops.append(record)
        if self.stop_hook:
            self.stop_hook(record)
        self.owned_record = None

    def apply_evidence(self, record, context, proof, check):
        check()
        return {"gate": {"boot_id": context["boot_id"]}, "country": {"requested_country": "FR"}, "radio": {"wireless_enabled": True}}

    def close(self, check):
        check()
        self.closed = True


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.adapter, self.clock, self.check = Adapter(), Clock(), Check()
        self.random_calls = []

        def random(count):
            self.random_calls.append(count)
            return bytes(range(count))

        self.core = ap.Controller(self.adapter, ap.POLICY, boottime_ns=self.clock, random=random)

    def start(self):
        return self.core.start(copy.deepcopy(WF), copy.deepcopy(CONTEXT), self.check)

    def status(self):
        return self.core.status(WF, CONTEXT, self.check)

    def stop(self):
        return self.core.stop(WF, CONTEXT, self.check)

    def refused(self, reason, call):
        with self.assertRaises(ap.APError) as caught:
            call()
        self.assertEqual(caught.exception.reason, reason)
        return caught.exception

    def test_explicit_policy_file_is_exact_fr_prototype(self):
        self.assertEqual(json.loads((ROOT / "staging/bootstrap/softap-region.json").read_bytes()), ap.POLICY)

    def test_policy_is_closed_and_exact_type(self):
        for key in ap.POLICY:
            with self.subTest(missing=key):
                value = ap.POLICY.copy()
                del value[key]
                self.refused("policy_invalid", lambda: ap.Controller(self.adapter, value, boottime_ns=self.clock))
        for key, value in {"channel": True, "ttl_seconds": 1800.0, "country": "US", "host": "10.42.0.1", "extra": 1}.items():
            with self.subTest(changed=key):
                policy = {**ap.POLICY, key: value}
                self.refused("policy_invalid", lambda: ap.Controller(self.adapter, policy, boottime_ns=self.clock))
        self.assertEqual(self.adapter.starts, [])

    def test_initial_status_and_stop_do_not_create_credentials(self):
        self.refused("not_found", self.status)
        self.refused("not_found", self.stop)
        self.assertFalse(self.core.has_started)
        self.assertFalse(self.core.record_active)
        self.assertEqual(self.random_calls, [])

    def test_reserve_is_pure_ram_and_start_consumes_exact_reserved_identity(self):
        self.assertIsNone(self.core.reserve(WF, CONTEXT, self.check))
        self.assertTrue(self.core.has_started)
        self.assertFalse(self.core.record_active)
        self.assertEqual(self.adapter.starts, [])
        self.assertEqual(self.adapter.verifies, [])
        self.assertEqual(self.adapter.stops, [])
        reserved = self.status()
        self.assertEqual(reserved["state"], "stopped")
        self.clock.now += 200 * 10**9
        self.assertIsNone(self.core.reserve(WF, CONTEXT, self.check))
        self.assertEqual(self.status(), reserved)
        self.assertEqual(self.random_calls, [4, 12, 16])
        self.assertEqual(self.start(), {**reserved, "state": "active"})
        self.assertEqual(self.adapter.starts[0]["expires_boottime_ns"], reserved["expires_boottime_ns"])

    def test_reserve_rejects_bad_binding_before_entropy_or_effect(self):
        self.refused("invalid_request", lambda: self.core.reserve({**WF, "extra": True}, CONTEXT, self.check))
        self.assertEqual(self.random_calls, [])
        self.core.reserve(WF, CONTEXT, self.check)
        self.refused("conflict", lambda: self.core.reserve(WF, {**CONTEXT, "boot_id": U(99)}, self.check))
        self.assertEqual(self.adapter.starts, [])
        self.assertEqual(self.random_calls, [4, 12, 16])

    def test_reserve_rejects_clock_or_entropy_before_any_native_effect(self):
        self.clock.now = float("nan")
        self.refused("invalid_clock", lambda: self.core.reserve(WF, CONTEXT, self.check))
        self.assertEqual(self.random_calls, [])
        bad = ap.Controller(self.adapter, ap.POLICY, boottime_ns=lambda: 1, random=lambda _: b"")
        self.refused("random_unavailable", lambda: bad.reserve(WF, CONTEXT, self.check))
        self.refused("random_unavailable", lambda: bad.reserve(WF, CONTEXT, self.check))
        self.assertEqual(self.adapter.starts, [])
        self.assertEqual(self.adapter.stops, [])

    def test_reserve_expiry_seals_without_native_cleanup_or_new_authority(self):
        value = self.start()
        record = self.adapter.owned_record
        self.clock.now = value["expires_boottime_ns"]
        self.refused("expired", lambda: self.core.reserve(WF, CONTEXT, self.check))
        self.assertEqual(self.adapter.stops, [])
        self.assertEqual(len(self.adapter.verifies), 1)
        self.assertTrue(self.core.expire_owned(self.check))
        self.assertEqual(self.adapter.stops, [record])
        self.refused("expired", lambda: self.core.reserve(WF, CONTEXT, self.check))
        self.assertEqual(len(self.adapter.starts), 1)
        self.assertEqual(self.random_calls, [4, 12, 16])

    def test_reserve_during_uncertain_activation_never_replays_or_reconciles(self):
        self.adapter.start_hook = lambda _: (_ for _ in ()).throw(NativeError(self.adapter.owned_record))
        self.refused("ap_timeout", self.start)
        self.refused("reconciliation_required", lambda: self.core.reserve(WF, CONTEXT, self.check))
        self.assertEqual(len(self.adapter.starts), 1)
        self.assertEqual(self.adapter.verifies, [])
        self.assertEqual(self.adapter.stops, [])

    def test_reserve_slow_entropy_cannot_admit_radio_after_original_deadline(self):
        def slow(count):
            self.clock.now += 1800 * 10**9
            return bytes(count)
        self.core = ap.Controller(self.adapter, ap.POLICY, boottime_ns=self.clock, random=slow)
        self.refused("expired", lambda: self.core.reserve(WF, CONTEXT, self.check))
        self.assertTrue(self.core.has_started)
        self.assertEqual(self.adapter.starts, [])
        self.refused("expired", self.start)

    def test_start_generates_one_bounded_identity(self):
        value = self.start()
        self.assertEqual(set(value), ap.RESULT_KEYS)
        self.assertEqual(value["state"], "active")
        self.assertEqual(value["ssid"], "Inky-00010203")
        self.assertEqual(value["passphrase"], "000102030405060708090a0b")
        self.assertEqual(len(value["passphrase"]), 24)
        self.assertEqual(value["expires_boottime_ns"], self.clock.now + 1800 * 10**9)
        self.assertEqual(self.random_calls, [4, 12, 16])
        self.assertEqual(self.adapter.starts[0]["channel"], 6)
        self.assertEqual(self.adapter.starts[0]["prefix"], 24)
        self.assertTrue(self.core.has_started)
        self.assertTrue(self.core.record_active)
        self.assertEqual(ap.uuid.UUID(value["ap_id"]).version, 4)

    def test_active_start_is_idempotent_and_reattests_without_effect(self):
        first = self.start()
        self.clock.now += 100_000_000
        self.assertEqual(self.start(), first)
        self.assertEqual(len(self.adapter.starts), 1)
        self.assertEqual(len(self.adapter.verifies), 2)
        self.assertEqual(self.random_calls, [4, 12, 16])

    def test_stop_restart_keeps_exact_identity_and_original_deadline(self):
        first = self.start()
        record = self.adapter.owned_record
        self.clock.now += 100 * 10**9
        stopped = self.stop()
        self.assertEqual(stopped, {**first, "state": "stopped"})
        self.assertEqual(self.adapter.stops, [record])
        self.assertFalse(self.core.record_active)
        self.assertEqual(self.stop(), stopped)
        self.assertEqual(len(self.adapter.stops), 1)
        self.clock.now += 100 * 10**9
        self.assertEqual(self.start(), first)
        self.assertEqual(self.adapter.starts[0], self.adapter.starts[1])
        self.assertEqual(self.random_calls, [4, 12, 16])

    def test_result_and_inputs_are_copied(self):
        workflow, context = copy.deepcopy(WF), copy.deepcopy(CONTEXT)
        first = self.core.start(workflow, context, self.check)
        first["passphrase"] = "changed"
        workflow["frame_id"] = U(20)
        context["main_invocation_id"] = "f" * 32
        self.assertNotEqual(self.status()["passphrase"], "changed")

    def test_workflow_and_context_are_exact_closed_schemas(self):
        for field in WF:
            for bad in (None, True, "A" * 64, U(1).upper() + "x"):
                value = {**WF, field: bad}
                with self.subTest(field=field, bad=bad):
                    self.refused("invalid_request", lambda: self.core.start(value, CONTEXT, self.check))
        for field in CONTEXT:
            value = {**CONTEXT, field: None}
            self.refused("invalid_request", lambda: self.core.start(WF, value, self.check))
        self.refused("invalid_request", lambda: self.core.start({**WF, "owner_id": U(5)}, CONTEXT, self.check))
        self.refused("invalid_request", lambda: self.core.start(WF, {**CONTEXT, "extra": True}, self.check))
        self.assertFalse(self.core.has_started)
        self.assertEqual(self.random_calls, [])

    def test_every_bound_field_change_refuses_before_releasing_credentials(self):
        self.start()
        for scope, original in (("workflow", WF), ("context", CONTEXT)):
            for field, old in original.items():
                changed = {**original, field: U(99) if "_id" in field or field == "initialization_intent" else "f" * len(old)}
                if field == "main_invocation_id":
                    changed[field] = "f" * 32
                wf = changed if scope == "workflow" else WF
                ctx = changed if scope == "context" else CONTEXT
                for name in ("start", "status", "stop"):
                    with self.subTest(scope=scope, field=field, operation=name):
                        self.refused("conflict", lambda: getattr(self.core, name)(wf, ctx, self.check))
        self.assertEqual(len(self.adapter.starts), 1)
        self.assertEqual(self.adapter.stops, [])

    def test_context_service_invocation_change_is_rejected(self):
        self.start()
        self.refused("conflict", lambda: self.core.status(WF, {**CONTEXT, "main_invocation_id": "a" * 32}, self.check))

    def test_expiry_boundary_stops_exact_owned_record_and_never_recreates(self):
        value = self.start()
        record = self.adapter.owned_record
        self.clock.now = value["expires_boottime_ns"] - 1
        self.assertFalse(self.core.expire_owned(self.check))
        self.assertEqual(self.adapter.stops, [])
        self.clock.now += 1
        expired = self.status()
        self.assertEqual(expired, {**value, "state": "expired"})
        self.assertEqual(self.adapter.stops, [record])
        self.refused("expired", self.start)
        self.assertEqual(self.stop(), expired)
        self.assertTrue(self.core.expire_owned(self.check))
        self.assertEqual(len(self.adapter.starts), 1)
        self.assertEqual(self.random_calls, [4, 12, 16])

    def test_expiry_after_stopped_state_does_not_touch_station(self):
        value = self.start()
        self.stop()
        self.clock.now = value["expires_boottime_ns"]
        self.assertTrue(self.core.expire_owned(self.check))
        self.assertEqual(len(self.adapter.stops), 1)
        self.refused("expired", self.start)

    def test_start_finishing_after_ttl_is_drained_and_refused(self):
        def delay(config):
            self.clock.now = config["expires_boottime_ns"]
        self.adapter.start_hook = delay
        self.refused("expired", self.start)
        self.assertEqual(len(self.adapter.starts), 1)
        self.assertEqual(len(self.adapter.stops), 1)
        self.assertEqual(self.status()["state"], "expired")

    def test_status_crossing_deadline_returns_expired_after_drain(self):
        value = self.start()
        self.adapter.verify_hook = lambda _: setattr(self.clock, "now", value["expires_boottime_ns"])
        self.assertEqual(self.status()["state"], "expired")
        self.assertEqual(len(self.adapter.stops), 1)

    def test_start_timeout_keeps_record_blocks_replay_until_targeted_stop(self):
        def fail(_):
            raise NativeError(self.adapter.owned_record)
        self.adapter.start_hook = fail
        error = self.refused("ap_timeout", self.start)
        self.assertTrue(error.reconciliation)
        record = self.adapter.owned_record
        self.refused("reconciliation_required", self.start)
        self.assertEqual(len(self.adapter.starts), 1)
        self.adapter.start_hook = None
        stopped = self.stop()
        self.assertEqual(self.adapter.stops, [record])
        restarted = self.start()
        self.assertEqual(restarted, {**stopped, "state": "active"})
        self.assertEqual(self.random_calls, [4, 12, 16])

    def test_verified_status_can_reconcile_successful_activation(self):
        self.adapter.start_hook = lambda _: (_ for _ in ()).throw(NativeError(self.adapter.owned_record))
        self.refused("ap_timeout", self.start)
        self.assertEqual(self.status()["state"], "active")
        self.assertTrue(self.core.record_active)
        self.adapter.start_hook = None
        self.start()
        self.assertEqual(len(self.adapter.starts), 1)

    def test_timeout_without_received_record_is_not_replayed(self):
        def fail(_):
            self.adapter.owned_record = None
            raise NativeError()
        self.adapter.start_hook = fail
        self.refused("ap_timeout", self.start)
        self.refused("reconciliation_required", self.start)
        self.refused("reconciliation_required", self.status)
        self.stop()
        self.assertEqual(self.adapter.stops, [None])
        self.adapter.start_hook = None
        self.start()
        self.assertEqual(len(self.adapter.starts), 2)

    def test_stop_failure_retains_exact_record_and_blocks_reactivation(self):
        self.start()
        record = self.adapter.owned_record
        self.adapter.stop_hook = lambda _: (_ for _ in ()).throw(NativeError(record))
        self.refused("ap_timeout", self.stop)
        self.refused("reconciliation_required", self.start)
        self.adapter.stop_hook = None
        self.stop()
        self.assertEqual(self.adapter.stops, [record, record])
        self.start()
        self.assertEqual(len(self.adapter.starts), 2)

    def test_expiry_cleanup_failure_retains_expired_identity_for_retry(self):
        value = self.start()
        record = self.adapter.owned_record
        self.clock.now = value["expires_boottime_ns"]
        self.adapter.stop_hook = lambda _: (_ for _ in ()).throw(NativeError(record))
        self.refused("ap_timeout", lambda: self.core.expire_owned(self.check))
        self.adapter.stop_hook = None
        self.assertTrue(self.core.expire_owned(self.check))
        self.refused("expired", self.start)
        self.assertEqual(self.adapter.stops, [record, record])

    def test_false_or_mismatched_native_observation_refuses_and_keeps_ownership(self):
        for key, bad in (("active", 1), ("state", "stopped"), ("ap_id", U(99)), ("host", "192.168.4.2"), ("channel", True), ("port", 1)):
            with self.subTest(field=key):
                self.setUp()
                self.adapter.verify_hook = lambda obs: obs.update({key: bad})
                with self.assertRaises(ap.APError):
                    self.start()
                self.refused("reconciliation_required", self.start)
                self.assertEqual(len(self.adapter.starts), 1)
                self.adapter.verify_hook = None
                self.stop()
                self.assertEqual(len(self.adapter.stops), 1)

    def test_revocation_before_start_has_no_generation_or_effect(self):
        self.check.allowed = False
        with self.assertRaises(CheckError):
            self.start()
        self.assertEqual(self.random_calls, [])
        self.assertEqual(self.adapter.starts, [])

    def test_revocation_after_start_preserves_cleanup_handle_and_no_replay(self):
        self.adapter.start_hook = lambda _: setattr(self.check, "allowed", False)
        self.refused("session_closed", self.start)
        record = self.adapter.owned_record
        self.check.allowed = True
        self.refused("reconciliation_required", self.start)
        self.stop()
        self.assertEqual(self.adapter.stops, [record])

    def test_bad_entropy_poisoned_without_radio_or_regeneration(self):
        for bad in (b"", "abcd", None, bytearray(4)):
            with self.subTest(bad=bad):
                self.core = ap.Controller(self.adapter, ap.POLICY, boottime_ns=self.clock, random=lambda _: bad)
                self.refused("random_unavailable", self.start)
                self.refused("random_unavailable", self.start)
        self.assertEqual(self.adapter.starts, [])

    def test_bad_clock_never_generates_credentials(self):
        for bad in (True, 1.0, float("nan"), float("inf"), -1, ap.MAX_BOOTTIME + 1):
            with self.subTest(bad=bad):
                core = ap.Controller(self.adapter, ap.POLICY, boottime_ns=lambda: bad)
                self.refused("invalid_clock", lambda: core.start(WF, CONTEXT, self.check))
        self.assertEqual(self.adapter.starts, [])

    def test_deadline_overflow_refused_before_radio(self):
        self.clock.now = ap.MAX_BOOTTIME - 1
        self.refused("invalid_clock", self.start)
        self.assertEqual(self.adapter.starts, [])

    def test_clock_rollback_is_sticky_and_cleanup_remains_available(self):
        self.start()
        self.clock.now -= 1
        self.refused("invalid_clock", self.status)
        self.clock.now += 100
        self.refused("invalid_clock", self.start)
        self.assertEqual(self.stop()["state"], "expired")
        self.assertEqual(len(self.adapter.stops), 1)

    def test_invalid_observed_clock_then_restore_cannot_reopen(self):
        self.start()
        self.clock.now = float("nan")
        self.refused("invalid_clock", self.status)
        self.clock.now = 1_000_000_000
        self.refused("invalid_clock", self.start)
        self.assertTrue(self.core.expire_owned(self.check))
        self.assertEqual(len(self.adapter.stops), 1)

    def test_apply_evidence_exposes_only_schema_objects_not_record(self):
        self.start()
        proof = SimpleNamespace()
        result = self.core.apply_evidence(WF, CONTEXT, proof, self.check)
        self.assertEqual(set(result), {"gate", "country", "radio"})
        self.assertNotIn("passphrase", json.dumps(result))
        self.stop()
        self.refused("ap_unavailable", lambda: self.core.apply_evidence(WF, CONTEXT, proof, self.check))

    def test_bad_apply_evidence_cannot_return_native_arbitrary_data(self):
        self.start()
        self.adapter.apply_evidence = lambda *args: {"passphrase": self.status()["passphrase"]}
        self.refused("unavailable", lambda: self.core.apply_evidence(WF, CONTEXT, None, self.check))
        self.refused("reconciliation_required", self.start)

    def test_close_drains_exact_handle_once_and_seals_controller(self):
        self.start()
        record = self.adapter.owned_record
        self.core.close(self.check)
        self.assertEqual(self.adapter.stops, [record])
        self.assertTrue(self.adapter.closed)
        self.core.close(self.check)
        self.assertEqual(self.adapter.stops, [record])
        self.refused("closed", self.start)
        self.refused("closed", self.status)

    def test_close_failure_can_be_retried_before_adapter_disposal(self):
        self.start()
        self.adapter.stop_hook = lambda _: (_ for _ in ()).throw(NativeError(self.adapter.owned_record))
        self.refused("ap_timeout", lambda: self.core.close(self.check))
        self.assertFalse(self.adapter.closed)
        self.adapter.stop_hook = None
        self.core.close(self.check)
        self.assertTrue(self.adapter.closed)

    def test_expire_or_close_without_start_never_creates_ap(self):
        self.assertFalse(self.core.expire_owned(self.check))
        self.core.close(self.check)
        self.assertEqual(self.adapter.starts, [])
        self.assertEqual(self.random_calls, [])

    def test_error_repr_str_and_diagnostic_record_do_not_leak_secrets(self):
        value = self.start()
        secret = value["passphrase"]
        self.assertNotIn(secret, repr(self.core))
        error = ap.APError(secret, record={"passphrase": secret, "ssid": value["ssid"], "ap_id": value["ap_id"]}, owned_record={"passphrase": secret})
        self.assertEqual(error.reason, "unavailable")
        self.assertEqual(error.record, {"ap_id": value["ap_id"]})
        self.assertNotIn(secret, str(error))
        self.assertNotIn(secret, repr(error))
        self.assertNotIn(secret, repr(error.record))
        self.assertEqual(error.args, ("unavailable",))
        malformed = ap.APError([secret], record={
            "active_path": "/org/freedesktop/NetworkManager/ActiveConnection/" + secret,
            "device_path": "/org/freedesktop/NetworkManager/Devices/" + secret,
        })
        self.assertEqual(malformed.reason, "unavailable")
        self.assertIsNone(malformed.record)


if __name__ == "__main__":
    unittest.main()
