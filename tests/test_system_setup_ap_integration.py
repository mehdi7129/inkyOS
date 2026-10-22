"""AP integration through the real setup state machine; no host radio effects."""

import copy
import unittest
from unittest.mock import patch

from test_system_setup import (
    BINDING, CONTEXT, SCHEMA, Session, SetupFixture, U, WF,
    module, policy, setup,
)

ap_core = module("system-setup-ap.py")


class APAdapter:
    """Inert native boundary; state-machine ownership is the production Core."""

    def __init__(self, native):
        self.native = native
        self.config = self.record = self.evidence = None
        self.fail_verify = False
        self.stop_failures = 0
        self.stop_calls = 0
        self.closed = False
        self.station_active = False

    def preflight(self, check):
        check()
        self.native.events.append("ap_preflight")
        if self.station_active:
            raise ap_core.APError("ap_unavailable")
        return {"ap_capable": True}

    def start(self, config, check):
        check()
        self.native.events.append("ap_start")
        if self.station_active:
            raise ap_core.APError("ap_unavailable")
        self.config = copy.deepcopy(config)
        self.record = {"ap_id": config["ap_id"], "boot_id": config["boot_id"]}
        if not self.native.prepared:
            raise ap_core.APError("radio_unconfirmed")
        self.evidence = copy.deepcopy(self.native.prepared)
        return copy.deepcopy(self.record)

    def verify(self, record, check):
        check()
        if self.fail_verify:
            raise ap_core.APError("ap_profile_changed", owned_record=self.record)
        if record != self.record:
            raise ap_core.APError("ap_ownership_changed", owned_record=self.record)
        return {
            "active": True, "state": "active",
            **{key: self.config[key] for key in
               ("ap_id", "country", "interface", "host", "prefix", "port", "channel")},
        }

    def apply_evidence(self, record, context, proof, check):
        self.verify(record, check)
        self.native.events.append("ap_evidence")
        return copy.deepcopy(self.evidence)

    def stop(self, record, check):
        check()
        self.stop_calls += 1
        if self.stop_failures:
            self.stop_failures -= 1
            raise ap_core.APError("ap_effect_uncertain", owned_record=self.record)
        self.native.events.append("ap_stop")
        self.record = None

    def close(self, check):
        check()
        self.closed = True


class APIntegrationTests(SetupFixture):
    def setUp(self):
        super().setUp()
        self.native.prepared = None
        gate = self.native.gate
        country = self.native.country
        radio = self.native.enable_wlan

        def inventory(proof):
            self.native.events.append("inventory")
            return set()

        def gate_evidence(context):
            value = gate(context)
            self.native.prepared = {"gate": value}
            return value

        def country_evidence(requested, check):
            value = country(requested, check)
            self.native.prepared["country"] = value
            return value

        def radio_evidence(value, check):
            result = radio(value, check)
            self.native.prepared["radio"] = result
            return result

        self.native.inventory = inventory
        self.native.gate = gate_evidence
        self.native.country = country_evidence
        self.native.enable_wlan = radio_evidence
        self.adapter = APAdapter(self.native)
        self.ap = ap_core.Controller(
            self.adapter, ap_core.POLICY,
            boottime_ns=self.native.boottime, random=lambda count: bytes([count]) * count,
        )
        self.service = setup.Setup(
            self.journal, self.native, policy, SCHEMA,
            ap_controller=self.ap, _root=self.root,
        )

    def started(self):
        return self.call("ap.start", workflow=WF)

    def test_closed_request_and_success_schemas_reject_unknown_fields(self):
        for op in ("ap.start", "ap.status", "ap.stop"):
            with self.subTest(op=op):
                with self.assertRaises(setup.Refused):
                    self.call(op, workflow=WF, passphrase="not allowed")
        value = self.started()
        self.assertEqual(set(value), ap_core.RESULT_KEYS)
        self.assertEqual(value["state"], "active")
        bad = {**value, "password": value["passphrase"]}
        with self.assertRaises(setup.Refused):
            SCHEMA.named(bad, "APState")
        self.assertNotIn(value["passphrase"].encode(), (self.directory / "journal.json").read_bytes()
                         if (self.directory / "journal.json").exists() else b"")

    def test_preclaim_requires_consumed_workflow_and_live_peer(self):
        bad = {**WF, "initialization_intent": U(90)}
        with self.assertRaises(setup.Refused):
            self.call("ap.start", workflow=bad)
        self.assertEqual(self.native.events, [])
        self.session.closed = True
        with self.assertRaises(setup.Refused):
            self.started()
        self.assertFalse(self.ap.has_started)

    def test_ap_read_hint_preserves_deadline_and_strict_fixture_fallback(self):
        calls = []
        original = self.session.check

        def full():
            calls.append("full")
            original()

        self.session.check = full
        check = self.service._ap_check(self.session)
        check.read_check()
        self.assertEqual(calls, ["full"])
        self.session.read_check = lambda: calls.append("read")
        deadline = self.native.now + 1000
        check = self.service._ap_check(self.session, deadline=deadline)
        calls.clear()
        check.read_check()
        self.assertEqual(calls, ["read"])
        check()
        self.assertEqual(calls, ["read", "full"])
        self.native.now = deadline + 1
        with self.assertRaisesRegex(setup.Refused, "effect_uncertain"):
            check.read_check()
        self.assertEqual(calls, ["read", "full", "read"])

    def test_effects_lock_prevents_parallel_ap_admission(self):
        self.service.effects.acquire()
        try:
            with self.assertRaisesRegex(setup.Refused, "conflict"):
                self.started()
            self.assertFalse(self.ap.has_started)
        finally:
            self.service.effects.release()

    def test_initial_start_prepares_fr_before_radio_and_native_ap(self):
        self.started()
        self.assertEqual(self.native.events, [
            "gate", "inventory", "ap_preflight", "country", "inventory", "radio", "ap_start",
        ])
        self.assertEqual(self.native.prepared["country"]["requested_country"], "FR")

    def test_invalid_entropy_prevents_all_initial_radio_effects(self):
        self.ap._random = lambda count: b""
        with self.assertRaises(ap_core.APError):
            self.started()
        self.assertEqual(self.native.events, [])
        # Sticky entropy refusal cannot repeat preparation on a second call.
        with self.assertRaises(ap_core.APError):
            self.started()
        self.assertEqual(self.native.events, [])

    def test_invalid_boottime_prevents_all_initial_radio_effects(self):
        self.native.now = float("nan")
        with self.assertRaises(ap_core.APError):
            self.started()
        self.assertEqual(self.native.events, [])

    def test_unapproved_station_profile_prevents_initial_radio_and_ap_effects(self):
        def unapproved(proof):
            raise setup.Refused("network_unconfirmed")
        self.native.inventory = unapproved
        with self.assertRaisesRegex(setup.Refused, "network_unconfirmed"):
            self.started()
        self.assertEqual(self.native.events, ["gate"])
        self.assertIsNone(self.adapter.record)
        self.assertFalse(self.service.ap_radio_prepared)

    def test_initial_radio_failure_closes_wlan_without_creating_ap(self):
        def failed(*args):
            self.native.events.append("radio_failed")
            raise setup.Refused("network_unconfirmed")

        self.native.enable_wlan = failed
        with self.assertRaisesRegex(setup.Refused, "network_unconfirmed"):
            self.started()
        self.assertEqual(self.native.events, [
            "gate", "inventory", "ap_preflight", "country", "inventory", "radio_failed", "ap_preflight", "close",
        ])
        self.assertTrue(self.ap.has_started)
        self.assertFalse(self.service.ap_radio_prepared)
        self.assertIsNone(self.adapter.record)

    def test_station_autoconnect_during_enable_is_preserved_on_ap_refusal(self):
        original = self.native.enable_wlan

        def connected(*args):
            result = original(*args)
            self.adapter.station_active = True
            return result

        self.native.enable_wlan = connected
        self.native.events.clear()
        with self.assertRaises(ap_core.APError):
            self.started()
        self.assertTrue(self.adapter.station_active)
        self.assertNotIn("close", self.native.events)
        self.assertFalse(self.service.ap_radio_prepared)
        self.assertIsNone(self.adapter.record)
        self.native.check_network(self.native.network_latest(self.session.proof), ready=True)

    def test_retry_after_initial_preparation_failure_keeps_reserved_identity(self):
        original = self.native.enable_wlan

        def failed(*args):
            raise setup.Refused("network_unconfirmed")

        self.native.enable_wlan = failed
        with self.assertRaises(setup.Refused):
            self.started()
        reserved = self.call("ap.status", workflow=WF)
        self.assertEqual(reserved["state"], "stopped")
        self.native.enable_wlan = original
        result = self.started()
        self.assertEqual(result, {**reserved, "state": "active"})
        self.assertTrue(self.service.ap_radio_prepared)

    def test_adopted_workflow_can_recover_transport_without_new_owner_authority(self):
        self.opened()
        self.challenged()
        before = copy.deepcopy(self.journal.data)
        self.session = Session()
        self.assertFalse(self.ap.has_started)
        value = self.started()
        self.assertEqual(value["state"], "active")
        self.assertIsNone(self.session.binding)
        self.assertEqual(self.journal.data, before)
        self.assertEqual(self.call("ap.status", workflow=WF), value)
        with self.assertRaisesRegex(setup.Refused, "forbidden"):
            self.call("ap.stop", workflow=WF)

    def test_completed_workflow_recovers_transport_on_a_new_boot_only_while_idle(self):
        self.started()
        self.completed()
        before = copy.deepcopy(self.journal.data)
        self.adapter = APAdapter(self.native)
        self.ap = ap_core.Controller(
            self.adapter, ap_core.POLICY, boottime_ns=self.native.boottime,
            random=lambda count: bytes([count + 1]) * count,
        )
        self.service = setup.Setup(
            self.journal, self.native, policy, SCHEMA,
            ap_controller=self.ap, _root=self.root,
        )
        self.session = Session()
        self.session.context["boot_id"] = U(99)
        self.native.inventory = lambda proof: {U(8)}  # approved persistent STA, idle
        value = self.started()
        self.assertEqual(value["boot_id"], U(99))
        self.assertIsNone(self.session.binding)
        self.assertEqual(self.journal.data, before)
        self.assertEqual(self.call("ap.status", workflow=WF), value)

    def test_ready_station_prevents_ap_preparation_even_for_completed_workflow(self):
        self.started()
        self.completed()
        self.adapter = APAdapter(self.native)
        self.adapter.station_active = True
        self.ap = ap_core.Controller(
            self.adapter, ap_core.POLICY, boottime_ns=self.native.boottime,
            random=lambda count: bytes([count + 1]) * count,
        )
        self.service = setup.Setup(
            self.journal, self.native, policy, SCHEMA,
            ap_controller=self.ap, _root=self.root,
        )
        self.session = Session()
        self.native.events.clear()
        with self.assertRaises(ap_core.APError):
            self.started()
        self.assertEqual(self.native.events, ["gate", "inventory", "ap_preflight"])
        self.assertFalse(self.service.ap_radio_prepared)
        self.assertIsNone(self.adapter.record)

    def test_after_owner_challenge_transport_recovery_is_public_but_stop_owner_bound(self):
        self.started()
        self.opened()
        self.challenged()
        self.session = Session()
        self.assertEqual(self.call("ap.status", workflow=WF)["state"], "active")
        with self.assertRaisesRegex(setup.Refused, "forbidden"):
            self.call("ap.stop", workflow=WF)
        self.opened({**BINDING, "credential_epoch": "2" * 64, "session_id": U(91)})
        self.assertEqual(self.call("ap.status", workflow=WF)["state"], "active")
        with self.assertRaisesRegex(setup.Refused, "forbidden"):
            self.call("ap.stop", workflow=WF)
        self.session = Session()
        self.opened({**BINDING, "session_id": U(92)})
        value = self.call("ap.status", workflow=WF)
        self.assertEqual(value["state"], "active")

    def test_owner_adoption_between_requests_is_checked_after_effects_admission(self):
        self.started()
        self.opened()
        self.challenged()
        adopted = copy.deepcopy(self.journal.data)
        self.journal.data["challenges"] = []
        self.journal.data["workflow"] = None
        self.journal.save()
        self.session = Session()
        real_lock = self.service.effects

        class AdoptBeforeAcquiring:
            def acquire(inner, blocking=False):
                acquired = real_lock.acquire(blocking=blocking)
                if acquired:
                    self.journal.data = copy.deepcopy(adopted)
                    self.journal.save()
                return acquired

            def release(inner):
                real_lock.release()

        self.service.effects = AdoptBeforeAcquiring()
        try:
            # The AP request entered while preclaim was still observable, but
            # an owner challenge committed before its effect lease was gained.
            with self.assertRaisesRegex(setup.Refused, "forbidden"):
                self.call("ap.stop", workflow=WF)
        finally:
            self.service.effects = real_lock

    def test_stop_restart_preserves_identity_and_deadline_without_closing_sta(self):
        first = self.started()
        stopped = self.call("ap.stop", workflow=WF)
        again = self.started()
        self.assertEqual(stopped, {**first, "state": "stopped"})
        self.assertEqual(again, first)
        self.assertNotIn("close", self.native.events)
        self.assertEqual(self.native.events.count("ap_start"), 2)

    def test_apply_preserves_owned_ap_and_only_sets_clock_after_durable_pending(self):
        first = self.started()
        self.opened()
        original = self.native.clock

        def observed_clock(*args):
            self.assertEqual(self.journal.data["operations"][-1]["state"], "pending")
            disk = setup.decode((self.directory / "journal.json").read_bytes(), setup.LIMIT)
            self.assertEqual(disk["operations"][-1]["state"], "pending")
            self.assertNotIn(first["passphrase"], str(disk))
            return original(*args)

        self.native.clock = observed_clock
        self.native.events.clear()
        result, args = self.applied()
        self.assertEqual(result["state"], "effects_completed")
        self.assertEqual(self.native.events, ["ap_evidence", "clock", "ap_evidence"])
        self.assertEqual(self.call("ap.status", workflow=WF), first)
        # Idempotent apply never runs clock or AP setup again.
        self.native.events.clear()
        self.call("apply", **args, utc_seconds=1_800_000_000, country="FR")
        self.assertEqual(self.native.events, [])

    def test_ap_apply_wrong_country_or_stopped_ap_never_falls_back_to_ble(self):
        self.started()
        self.opened()
        challenge = self.challenged()
        args = {key: challenge[key] for key in
                ("operation_id", "supersedes_operation_id", "challenge_id", "nonce")}
        self.native.events.clear()
        with self.assertRaisesRegex(setup.Refused, "country_unconfirmed"):
            self.call("apply", **args, utc_seconds=1_800_000_000, country="US")
        self.assertEqual(self.native.events, [])
        self.call("ap.stop", workflow=WF)
        self.native.events.clear()
        with self.assertRaises(ap_core.APError):
            self.call("apply", **args, utc_seconds=1_800_000_000, country="FR")
        self.assertEqual(self.native.events, [])
        self.assertEqual(self.journal.data["operations"], [])

    def test_ap_changed_during_clock_becomes_uncertain_and_drains_target_only(self):
        self.started()
        self.opened()
        original = self.native.clock

        def changed(*args):
            result = original(*args)
            self.adapter.fail_verify = True
            return result

        self.native.clock = changed
        self.native.events.clear()
        with self.assertRaises(ap_core.APError):
            self.applied()
        self.assertEqual(self.journal.data["operations"][-1]["state"], "uncertain")
        self.assertEqual(self.native.events, ["ap_evidence", "clock", "ap_stop"])
        self.assertIsNone(self.adapter.record)
        self.assertNotIn("close", self.native.events)

    def test_session_loss_during_clock_drains_using_original_binding(self):
        self.started()
        self.opened()
        original = self.native.clock

        def disconnected(*args):
            result = original(*args)
            self.session.closed = True
            return result

        self.native.clock = disconnected
        self.native.events.clear()
        with self.assertRaisesRegex(setup.Refused, "session_closed"):
            self.applied()
        self.assertEqual(self.native.events, ["ap_evidence", "clock", "ap_stop"])
        self.assertIsNone(self.adapter.record)
        self.assertEqual(self.journal.data["operations"][-1]["state"], "uncertain")

    def test_expiry_cleanup_and_shutdown_retain_identity_and_drain_uncertainty(self):
        first = self.started()
        self.native.now = first["expires_boottime_ns"]
        self.service.expire_ap()
        value = self.call("ap.status", workflow=WF)
        self.assertEqual(value, {**first, "state": "expired"})
        with self.assertRaisesRegex(ap_core.APError, "expired"):
            self.started()
        self.assertEqual(self.native.events.count("ap_start"), 1)
        self.service.close_ap()
        self.assertTrue(self.adapter.closed)

    def test_shutdown_retries_targeted_readback_before_releasing_effects(self):
        self.started()
        self.adapter.stop_failures = 1
        with patch.object(setup.time, "sleep", return_value=None):
            self.service.close_ap()
        self.assertEqual(self.adapter.stop_calls, 2)
        self.assertTrue(self.adapter.closed)
        self.assertIsNone(self.adapter.record)
        self.assertTrue(self.service.effects.acquire(blocking=False))
        self.service.effects.release()

    def test_recovery_challenge_verifies_active_ap_and_preserves_radio(self):
        self.started()
        self.opened()
        self.applied()
        self.session = Session()
        self.opened({**BINDING, "session_id": U(98)})
        self.native.events.clear()
        self.challenged(U(11), U(10))
        self.assertEqual(self.native.events, ["ap_evidence"])
        self.assertNotIn("close", self.native.events)


class SessionContinuityTests(unittest.TestCase):
    def setUp(self):
        import socket
        import threading
        self.local, self.peer = socket.socketpair()
        self.addCleanup(self.local.close)
        self.addCleanup(self.peer.close)
        testcase = self

        class Proof:
            def __init__(inner):
                inner._lock = threading.RLock()
                inner._state = "ACTIVE"
                inner.full_checks = 0

            @property
            def state(inner):
                testcase.assertTrue(inner._lock._is_owned())
                return inner._state

            def check(inner):
                inner.full_checks += 1

        self.proof = Proof()
        self.stopping = threading.Event()
        self.session = setup.Session(self.local, self.proof, self.stopping)

    def test_read_check_uses_locked_active_state_without_full_source_walk(self):
        self.session.read_check()
        self.assertEqual(self.proof.full_checks, 0)
        self.session.check()
        self.assertEqual(self.proof.full_checks, 1)

    def test_read_check_refuses_peer_eof_and_stop_without_admitting_effect(self):
        self.peer.close()
        with self.assertRaisesRegex(setup.Refused, "session_closed"):
            self.session.read_check()
        self.assertEqual(self.proof.full_checks, 0)
        self.stopping.set()
        with self.assertRaisesRegex(setup.Refused, "session_closed"):
            self.session.read_check()

    def test_read_check_refuses_invalid_or_closed_graph(self):
        for state in ("INVALID", "CLOSED", "BINDING"):
            with self.subTest(state=state):
                with self.proof._lock:
                    self.proof._state = state
                with self.assertRaisesRegex(setup.Refused, "session_closed"):
                    self.session.read_check()
        self.assertEqual(self.proof.full_checks, 0)


class APNativeIntegrationTests(unittest.TestCase):
    def test_gate_receipt_is_historical_but_original_gate_requires_live_closed_radio(self):
        native_module = module("system-setup-native.py")
        value = native_module.Native.__new__(native_module.Native)
        receipt = setup.sealed({
            "boot_id": CONTEXT["boot_id"], "candidate_sha256": CONTEXT["candidate_sha256"],
            "closed_boottime_ns": 1, "nm_wireless_enabled": False,
            "wlan_soft_blocked": True, "restore_policy": "systemd-rfkill-masked",
        })
        from contextlib import contextmanager
        from types import SimpleNamespace

        @contextmanager
        def tree():
            yield SimpleNamespace(read=lambda *args: setup.canonical(receipt))

        value.contract = SimpleNamespace(tree=tree)
        value.rfkill = lambda: (0, False, False)
        value.wireless = lambda: True
        self.assertEqual(value.gate_receipt(CONTEXT), receipt)
        with self.assertRaises(native_module.ObservationError):
            value.gate(CONTEXT)
        with self.assertRaises(native_module.ObservationError):
            value.gate_receipt({**CONTEXT, "boot_id": U(90)})

    def test_committed_station_inventory_accepts_only_exact_verified_active_ap(self):
        native_module = module("system-setup-native.py")
        value = native_module.Native.__new__(native_module.Native)
        observation = {
            "boot_id": CONTEXT["boot_id"], "nm_unique_owner": ":1.2",
            "profile_uuid": U(8), "active_profile_uuid": U(9),
            "ipv4": ["192.168.4.1"],
        }
        value.network_latest = lambda proof: copy.deepcopy(observation)

        class Commands:
            def __init__(self):
                self.active = U(9)
                self.unsaved = False

            def owner(inner, name):
                return ":1.2"

            def bus(inner, destination, path, interface, method, signature, identifier):
                self.assertEqual(method, "GetConnectionByUuid")
                self.assertEqual(identifier, U(8))
                return b'o "/org/freedesktop/NetworkManager/Settings/8"'

            def prop(inner, destination, path, interface, name, kind):
                self.assertEqual(name, "Unsaved")
                return inner.unsaved

            def run(inner, argv):
                values = argv[argv.index("--get-values") + 1]
                if values == "UUID,TYPE":
                    return f"{U(8)}:802-11-wireless\n{U(9)}:802-11-wireless\n".encode()
                if values == "connection.uuid,connection.type,connection.interface-name":
                    return f"{U(8)}\n802-11-wireless\nwlan0\n".encode()
                if values == "GENERAL.CON-UUID,IP4.ADDRESS":
                    return f"{inner.active}\n192.168.4.1/24\n".encode()
                raise AssertionError(values)

        value.command = Commands()
        with patch.object(native_module.Path, "read_text", return_value=CONTEXT["boot_id"]):
            self.assertEqual(value.inventory(None, ap_uuid=U(9)), {U(8), U(9)})
            # Public station/readiness validation is deliberately unchanged.
            for ready in (False, True):
                with self.subTest(ready=ready):
                    with self.assertRaises(native_module.ObservationError):
                        value.check_network(observation, ready=ready)
            with self.assertRaises(native_module.ObservationError):
                value._check_network(observation, ready=True, verified_ap_uuid=U(9))
            # A different AP, changed actual active profile, or nonpersistent
            # committed station cannot use the private inventory exception.
            with self.assertRaises(native_module.ObservationError):
                value.inventory(None, ap_uuid=U(10))
            value.command.active = U(10)
            with self.assertRaises(native_module.ObservationError):
                value.inventory(None, ap_uuid=U(9))
            value.command.active = U(9)
            value.command.unsaved = True
            with self.assertRaises(native_module.ObservationError):
                value.inventory(None, ap_uuid=U(9))

    def test_inventory_only_adds_explicit_verified_ap_uuid_to_approved_sta(self):
        native_module = module("system-setup-native.py")
        from types import SimpleNamespace
        value = native_module.Native.__new__(native_module.Native)
        value.network_latest = lambda proof: {"profile_uuid": U(8)}
        value.check_network = lambda *args, **kwargs: None
        value._check_network = lambda *args, **kwargs: None
        raw = [f"{U(8)}:802-11-wireless\n{U(9)}:802-11-wireless\n".encode()]
        value.command = SimpleNamespace(run=lambda *args: raw[0])
        self.assertEqual(value.inventory(None, ap_uuid=U(9)), {U(8), U(9)})
        with self.assertRaises(native_module.ObservationError):
            value.inventory(None)
        with self.assertRaises(native_module.ObservationError):
            value.inventory(None, ap_uuid=U(8))
        raw[0] += f"{U(10)}:802-11-wireless\n".encode()
        with self.assertRaises(native_module.ObservationError):
            value.inventory(None, ap_uuid=U(9))


if __name__ == "__main__":
    unittest.main()
