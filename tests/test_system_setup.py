"""Mac fixtures for the real setter state machine; no host clock/radio/VM effect."""

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import socket
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(
        "setup_test_" + name.replace("-", "_"), ROOT / "staging/bootstrap" / name
    )
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


setup = module("system-setup.py")
native = module("system-setup-native.py")
policy = module("time-policy.py")
gate = module("system-setup-gate.py")
SCHEMA = setup.Schema(
    json.loads((ROOT / "staging/bootstrap/system-setup-contract.json").read_bytes())
)
U = lambda n: f"00000000-0000-0000-0000-{n:012d}"
WF = {
    "initialization_intent": U(1),
    "initialization_receipt_digest": "a" * 64,
    "frame_id": U(2),
    "spki_sha256": "b" * 64,
}
BINDING = {
    **WF,
    "credential_epoch": "c" * 64,
    "owner_id": U(3),
    "claim_request_id": U(4),
    "session_id": U(5),
}
CONTEXT = {
    "boot_id": U(6),
    "candidate_sha256": "d" * 64,
    "context_sha256": "e" * 64,
    "main_invocation_id": "f" * 32,
}
OBS = {
    "id": U(7),
    "owner_id": U(3),
    "state": "committed",
    "profile_uuid": U(8),
    "device": "wlan0",
    "nm_unique_owner": ":1.2",
    "boot_id": U(6),
    "ipv4": ["192.168.1.2"],
    "active_profile_uuid": U(8),
    "profile_persistent": True,
    "commit_boot_id": U(6),
    "commit_nm_unique_owner": ":1.2",
}
OBS["observation_sha256"] = setup.digest(OBS)


class Session:
    def __init__(self):
        self.binding = None
        self.proof = self
        self.closed = False
        self.context = copy.deepcopy(CONTEXT)

    def check(self):
        setup.require(not self.closed, "session_closed")

    def observed_context(self):
        self.check()
        return self.context.copy()


class Native:
    def __init__(self):
        self.now = 1_000_000
        self.events = []
        self.hook = None
        self.observation = copy.deepcopy(OBS)
        self.missing = False

    def boottime(self):
        self.now += 100
        return self.now

    def consumed(self, value):
        setup.require(value == WF, "forbidden")

    def gate(self, context):
        self.events.append("gate")
        return setup.sealed(
            {
                "boot_id": context["boot_id"],
                "candidate_sha256": context["candidate_sha256"],
                "closed_boottime_ns": self.boottime(),
                "nm_wireless_enabled": False,
                "wlan_soft_blocked": True,
                "restore_policy": "systemd-rfkill-masked",
            }
        )

    def clock(self, seconds, numeric):
        self.events.append("clock")
        return {
            "utc_seconds": seconds,
            "effect_start_boottime_ns": self.boottime(),
            "effect_end_boottime_ns": self.boottime(),
            "read_start_boottime_ns": self.boottime(),
            "read_end_boottime_ns": self.boottime(),
            "realtime_ns": seconds * 10**9,
            "error_lower_ns": -300,
            "error_upper_ns": 0,
            "time_policy_sha256": setup.POLICY_SHA,
        }

    def country(self, country, check):
        self.events.append("country")
        check()
        if self.hook:
            self.hook()
        return {
            "requested_country": country,
            "firmware_country": country,
            "firmware_ccode": country,
            "firmware_revision": 1,
            "global_country": country,
            "phy_label": "99",
            "wiphy_index": 0,
            "interface": "wlan0",
            "channel_evidence_sha256": "1" * 64,
            "observed_boottime_ns": self.boottime(),
        }

    def enable_wlan(self, country, check):
        self.events.append("radio")
        check()
        return {
            "wireless_enabled": True,
            "wlan_soft_blocked": False,
            "wlan_hard_blocked": False,
            "wiphy_index": 0,
            "interface": "wlan0",
            "nm_unique_owner": ":1.2",
            "observed_boottime_ns": self.boottime(),
        }

    def observe_live(self, country, radio):
        return country, radio

    def closed(self, context):
        return True

    def inventory(self, proof):
        self.events.append("inventory")

    def close_wlan(self):
        self.events.append("close")

    def network_latest(self, proof):
        if self.missing:
            raise setup.Refused("not_found")
        return copy.deepcopy(self.observation)

    def network_exact(self, identifier, owner, proof):
        setup.require(
            identifier == self.observation["id"]
            and owner == self.observation["owner_id"],
            "network_unconfirmed",
        )
        return copy.deepcopy(self.observation)

    def check_network(self, value, *, ready):
        setup.require(
            value == self.observation and (not ready or value["ipv4"]),
            "network_unconfirmed",
        )

    def origin(self):
        return "https://inky-" + ("a" * 32) + ".local:8443"


class SetupFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.directory = self.root / "journal"
        self.directory.mkdir(mode=0o700)
        # macOS does not accept FDs for listxattr. This seam is explicit and local
        # to non-/ synthetic storage; production requires the real Linux API.
        self.xattrs = patch.object(setup.os, "listxattr", return_value=[], create=True)
        self.xattrs.start()
        self.addCleanup(self.xattrs.stop)
        self.journal = setup.Journal(self.directory, SCHEMA, _root=self.root)
        self.addCleanup(lambda: self.journal.close())
        self.native = Native()
        self.service = setup.Setup(
            self.journal, self.native, policy, SCHEMA, _root=self.root
        )
        self.session = Session()

    def call(self, op, **args):
        request = SCHEMA.request(
            setup.canonical({"v": 1, "id": U(50), "op": "setup." + op, "args": args})
        )
        result = self.service.handle(self.session, request)
        SCHEMA.check(
            {"v": 1, "id": U(50), "ok": True, "result": result},
            SCHEMA.value["success_response_schemas"]["setup." + op],
        )
        return result

    def opened(self, binding=None):
        return self.call("open", binding=binding or BINDING)

    def challenged(self, identifier=U(10), supersedes=None):
        return self.call(
            "challenge", operation_id=identifier, supersedes_operation_id=supersedes
        )

    def applied(self, identifier=U(10), supersedes=None):
        challenge = self.challenged(identifier, supersedes)
        args = {
            key: challenge[key]
            for key in (
                "operation_id",
                "supersedes_operation_id",
                "challenge_id",
                "nonce",
            )
        }
        return self.call("apply", **args, utc_seconds=1_800_000_000, country="FR"), args

    def completed(self):
        self.opened()
        self.applied()
        publication = {
            "publication_operation_id": U(20),
            "initial_setup_operation_id": U(10),
            "initial_certificate_sha256": "9" * 64,
            "frame_id": WF["frame_id"],
            "spki_sha256": WF["spki_sha256"],
        }
        return self.call(
            "complete",
            operation_id=U(10),
            publication=publication,
            network_transaction_id=U(7),
        )


class SetupTests(SetupFixture):
    def test_first_effect_follows_durable_pending_and_ordered_receipt(self):
        self.opened()
        original = self.native.clock

        def clock(*args):
            state = json.loads((self.directory / "journal.json").read_bytes())
            self.assertEqual(state["operations"][0]["state"], "pending")
            return original(*args)

        self.native.clock = clock
        operation, _ = self.applied()
        self.assertEqual(operation["state"], "effects_completed")
        self.assertEqual(
            self.native.events,
            ["gate", "clock", "inventory", "country", "inventory", "radio"],
        )
        setup.verify_seal(operation["receipt"])
        before = list(self.native.events)
        status = self.call("status", operation_id=U(10))
        self.assertEqual(status["operation"], operation)
        self.assertEqual(self.native.events, before)

    def test_identical_apply_does_not_repeat_effect_and_conflict_never_mutates(self):
        self.opened()
        operation, args = self.applied()
        before = list(self.native.events)
        self.assertEqual(
            self.call("apply", **args, utc_seconds=1_800_000_000, country="FR"),
            operation,
        )
        with self.assertRaisesRegex(setup.Refused, "conflict"):
            self.call("apply", **args, utc_seconds=1_800_000_001, country="FR")
        self.assertEqual(self.native.events, before)

    def test_eof_between_effects_closes_wlan_and_becomes_uncertain(self):
        self.opened()
        self.native.hook = lambda: setattr(self.session, "closed", True)
        with self.assertRaisesRegex(setup.Refused, "session_closed"):
            self.applied()
        self.assertEqual(
            self.native.events, ["gate", "clock", "inventory", "country", "close"]
        )
        self.assertEqual(self.journal.operation(U(10))["state"], "uncertain")

    def test_restart_pending_is_uncertain_without_effect_replay(self):
        self.opened()
        self.applied()
        operation = self.journal.operation(U(10))
        operation.update(state="pending", receipt=None)
        self.journal.save()
        self.journal.close()
        self.journal = setup.Journal(self.directory, SCHEMA, _root=self.root)
        self.assertEqual(self.journal.operation(U(10))["state"], "uncertain")
        self.assertEqual(len(self.native.events), 6)

    def test_fresh_explicit_recovery_retains_initial_publication_lineage(self):
        self.opened()
        self.applied()
        old = copy.deepcopy(self.journal.operation(U(10)))
        self.session = Session()
        self.opened({**BINDING, "session_id": U(11)})
        self.applied(U(12), U(10))
        self.assertEqual(self.journal.operation(U(10))["state"], "superseded")
        self.assertEqual(self.journal.operation(U(10))["receipt"], old["receipt"])
        publication = {
            "publication_operation_id": U(20),
            "initial_setup_operation_id": U(10),
            "initial_certificate_sha256": "9" * 64,
            "frame_id": WF["frame_id"],
            "spki_sha256": WF["spki_sha256"],
        }
        completion = self.call(
            "complete",
            operation_id=U(12),
            publication=publication,
            network_transaction_id=U(7),
        )
        self.assertNotEqual(
            completion["operation_id"],
            completion["publication"]["initial_setup_operation_id"],
        )

    def test_lost_completion_reply_is_found_without_phone_or_old_session(self):
        completion = self.completed()
        self.session = Session()
        snapshot = self.call("inspect", workflow=WF)
        self.assertEqual(snapshot["completion"], completion)
        self.assertEqual(snapshot["latest_operation_id"], U(10))
        self.assertEqual(snapshot["state"], "completed")

    def test_reboot_resume_never_sets_clock_and_uses_latest_network(self):
        completion = self.completed()
        self.service.live_radio = self.service.live_clock = (
            self.service.live_country
        ) = None
        self.session = Session()
        self.session.context["boot_id"] = U(60)
        self.native.observation.update(
            id=U(61), profile_uuid=U(62), active_profile_uuid=U(62), boot_id=U(60)
        )
        self.native.observation["observation_sha256"] = setup.digest(
            {
                k: v
                for k, v in self.native.observation.items()
                if k != "observation_sha256"
            }
        )
        self.native.events.clear()
        result = self.call("resume", completion_id=completion["completion_id"])
        self.assertNotIn("clock", self.native.events)
        self.assertEqual(result["live"]["clock_status"], "not_attested_current_boot")
        self.assertEqual(result["network_head"]["profile_uuid"], U(62))
        self.assertEqual(result["completion"]["initial_profile_uuid"], U(8))

    def test_absent_helper_keeps_normal_completion_with_wlan_closed(self):
        completion = self.completed()
        self.service.live_radio = None
        self.native.missing = True
        self.native.events.clear()
        self.session = Session()
        result = self.call("resume", completion_id=completion["completion_id"])
        self.assertEqual(result["completion"], completion)
        self.assertEqual(result["live"]["readiness"], "wlan_closed")
        self.assertEqual(self.native.events, ["gate", "close"])

    def test_expired_challenge_is_refused_without_native_effect(self):
        self.opened()
        challenge = self.challenged()
        self.native.now = challenge["expires_boottime_ns"]
        args = {
            key: challenge[key]
            for key in (
                "operation_id",
                "supersedes_operation_id",
                "challenge_id",
                "nonce",
            )
        }
        with self.assertRaisesRegex(setup.Refused, "challenge_expired"):
            self.call("apply", **args, utc_seconds=1_800_000_000, country="FR")
        self.assertEqual(self.native.events, [])

    def test_corrupt_root_journal_or_replaced_lock_never_adopted(self):
        self.opened()
        self.applied()
        self.journal.close()
        path = self.directory / "journal.json"
        value = json.loads(path.read_bytes())
        value["operations"][0]["receipt"]["clock"]["utc_seconds"] += 1
        path.write_bytes(setup.canonical(value))
        with self.assertRaises(setup.Refused):
            setup.Journal(self.directory, SCHEMA, _root=self.root)

    def test_explicit_postcompletion_recovery_creates_new_immutable_completion(self):
        old = self.completed()
        self.session = Session()
        self.opened({**BINDING, "session_id": U(21)})
        challenge = self.challenged(U(22), U(10))
        snapshot = self.call("inspect", workflow=WF)
        self.assertEqual(snapshot["latest_operation_id"], U(22))
        self.assertEqual(snapshot["state"], "challenged")
        self.assertEqual(snapshot["completion"], old)
        args = {
            key: challenge[key]
            for key in (
                "operation_id",
                "supersedes_operation_id",
                "challenge_id",
                "nonce",
            )
        }
        self.call("apply", **args, utc_seconds=1_800_000_010, country="DE")
        snapshot = self.call("inspect", workflow=WF)
        self.assertEqual(snapshot["state"], "effects_completed")
        self.assertEqual(snapshot["completion"], old)
        current = self.call(
            "complete",
            operation_id=U(22),
            publication=old["publication"],
            network_transaction_id=U(7),
        )
        self.assertNotEqual(current["completion_id"], old["completion_id"])
        self.assertEqual(current["operation_id"], U(22))
        self.assertEqual(current["country"], "DE")
        self.assertEqual(current["publication"], old["publication"])
        self.assertEqual(self.journal.data["completions"], [old, current])
        self.assertEqual(self.call("inspect", workflow=WF)["state"], "completed")

    def test_stale_radio_or_country_receipt_cannot_authorize_wifi(self):
        self.opened()
        self.applied()
        before = list(self.native.events)

        def stale(*_):
            raise setup.Refused("country_unconfirmed")

        self.native.observe_live = stale
        status = self.call("status", operation_id=U(10))
        self.assertEqual(status["live"]["readiness"], "unavailable")
        self.assertIsNone(status["live"]["country_receipt_sha256"])
        self.assertIsNone(status["live"]["radio_receipt_sha256"])
        self.assertIsNone(status["live"]["https_origin"])
        self.assertEqual(self.native.events, before)

    def test_no_fixture_seam_for_host_root(self):
        with self.assertRaises(setup.Refused):
            setup.Journal(Path("/var/lib/inkyos/system-setup"), SCHEMA, _root=Path("/"))
        with self.assertRaises(setup.Refused):
            setup.Setup(self.journal, self.native, policy, SCHEMA, _root=Path("/"))


class WireAndNativeTests(unittest.TestCase):
    def test_nonminimal_numbers_duplicate_names_booleans_and_unknown_keys_refused(self):
        request = setup.canonical(
            {"v": 1, "id": U(1), "op": "setup.status", "args": {"operation_id": U(2)}}
        )
        for raw in (
            request.replace(b'"v":1', b'"v":1.0'),
            request.replace(b'"v":1', b'"v":true'),
            request.replace(b'"v":1', b'"v":-0'),
            b'{"v":1,' + request[1:],
            request.replace(b'"args":', b'"extra":0,"args":'),
            request + b"\n",
        ):
            with self.subTest(raw=raw[:50]), self.assertRaises(setup.Refused):
                SCHEMA.request(raw)

    def test_real_clock_adapter_calls_settime_then_checks_actual_readback(self):
        adapter = object.__new__(native.Native)
        values = iter([100, 200, 300, 400])
        adapter.boottime = lambda: next(values)
        with (
            patch.object(native.time, "clock_settime_ns") as setter,
            patch.object(
                native.time, "clock_gettime_ns", return_value=1_800_000_000_000_000_100
            ),
        ):
            record = adapter.clock(1_800_000_000, policy)
        setter.assert_called_once_with(
            native.time.CLOCK_REALTIME, 1_800_000_000_000_000_000
        )
        SCHEMA.named(record, "Clock")
        self.assertEqual(record["error_lower_ns"], -200)

    def test_clock_readback_outside_policy_is_refused(self):
        adapter = object.__new__(native.Native)
        values = iter([100, 200, 300, 400])
        adapter.boottime = lambda: next(values)
        with (
            patch.object(native.time, "clock_settime_ns"),
            patch.object(
                native.time, "clock_gettime_ns", return_value=1_800_000_010_000_000_000
            ),
            self.assertRaises(native.ObservationError),
        ):
            adapter.clock(1_800_000_000, policy)

    def test_nm_state_gate_changes_only_wireless_and_refuses_unknown_input(self):
        raw = (
            b"[main]\nNetworkingEnabled=true\nWirelessEnabled=true\nWWANEnabled=false\n"
        )
        self.assertEqual(
            gate.state_bytes(raw),
            b"[main]\nNetworkingEnabled=true\nWWANEnabled=false\nWirelessEnabled=false\n",
        )
        for raw in (
            b"[main]\nWirelessEnabled=yes\n",
            b"[main]\nUnknown=true\n",
            b"[main]\nWirelessEnabled=true\nWirelessEnabled=false\n",
        ):
            with self.assertRaises((gate.Refused, gate.configparser.Error)):
                gate.state_bytes(raw)

    def test_ready_notification_is_a_real_datagram_and_missing_environment_refuses(
        self,
    ):
        with tempfile.TemporaryDirectory(
            prefix="setup-ready-", dir="/tmp"
        ) as directory:
            path = str(Path(directory) / "notify")
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as receiver:
                receiver.bind(path)
                receiver.settimeout(1)
                with patch.dict(setup.os.environ, {"NOTIFY_SOCKET": path}, clear=True):
                    setup.notify_ready()
                self.assertEqual(receiver.recv(32), b"READY=1")
        with (
            patch.dict(setup.os.environ, {}, clear=True),
            self.assertRaises(setup.Refused),
        ):
            setup.notify_ready()

    def test_current_native_observation_rejects_changed_nm_owner_and_blocked_radio(
        self,
    ):
        adapter = object.__new__(native.Native)
        country = {"requested_country": "FR", "wiphy_index": 0}
        radio = {"wiphy_index": 0, "nm_unique_owner": ":1.2"}
        adapter.observe_country = lambda cc: {**country, "requested_country": cc}
        adapter.wireless = lambda: True
        adapter.rfkill = lambda: (0, False, False)
        adapter.command = SimpleNamespace(owner=lambda _: ":1.3")
        with self.assertRaises(native.ObservationError):
            adapter.observe_live(country, radio)
        adapter.command.owner = lambda _: ":1.2"
        adapter.rfkill = lambda: (0, True, False)
        with self.assertRaises(native.ObservationError):
            adapter.observe_live(country, radio)

    def test_late_rfkill_restore_refuses_gate_before_nm_state_mutation(self):
        class Command:
            def run(self, args):
                return b"LoadState=masked\nActiveState=active\nSubState=running\nMainPID=123\n"

        info = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0, st_gid=0)
        with (
            patch.object(gate.os, "lstat", return_value=info),
            patch.object(gate.os, "readlink", return_value="/dev/null"),
            patch.object(gate, "close_state") as write,
        ):
            with self.assertRaises(gate.Refused):
                gate.close_gate(SimpleNamespace(command=Command()), "a" * 64, U(1))
            write.assert_not_called()

    def test_frozen_contract_and_policy_bytes_are_exact(self):
        import hashlib

        self.assertEqual(
            hashlib.sha256(
                (ROOT / "staging/bootstrap/system-setup-contract.json").read_bytes()
            ).hexdigest(),
            setup.CONTRACT_SHA,
        )
        self.assertEqual(
            hashlib.sha256(
                (ROOT / "staging/bootstrap/time-policy.py").read_bytes()
            ).hexdigest(),
            setup.POLICY_SHA,
        )
