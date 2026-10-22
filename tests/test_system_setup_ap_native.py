"""Inert NM fixtures: no dbus import, network, RF, VM or SD access."""

import copy
import importlib.util
import io
from pathlib import Path
import stat
import types
import unittest
import uuid
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "ap_native", Path(__file__).resolve().parents[1] / "staging/bootstrap/system-setup-ap-native.py"
)
ap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ap)
BOOT = "d5b49d5a-bc31-4cd3-980a-0ca386a5c9d0"
UUID = "cd02c58f-84c1-4271-9027-05739abf32ab"
DEV, CON, ACT, IP = (ap.ROOT + suffix for suffix in (
    "/Devices/2", "/Settings/19", "/ActiveConnection/13", "/IP4Config/8"
))
FILENAME = ap.RUNTIME_PROFILES + "/InkyOS setup " + UUID + ".nmconnection"
CONFIG = {
    "boot_id": BOOT, "ap_id": UUID, "ssid": "Inky-12345678", "passphrase": "8b0de935048c40da94a8750d",
    "interface": "wlan0", "country": "FR", "channel": 6, "host": "192.168.4.1", "prefix": 24,
    "port": 9443, "expires_boottime_ns": 1_801_000_000_000,
}


class Clock:
    def __init__(self):
        self.now = 1.0

    def __call__(self):
        self.now += 0.001
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class Guard:
    """A full walk costs 250 ms; lightweight reads detect EOF/revocation."""

    def __init__(self, clock):
        self.clock = clock
        self.full = self.light = 0
        self.graph_valid = True
        self.connected = True

    def __call__(self):
        self.full += 1
        self.clock.now += 0.25
        if not self.graph_valid:
            raise ValueError("source_changed")
        if not self.connected:
            raise ValueError("session_closed")

    def read_check(self):
        self.light += 1
        if not self.connected:
            raise ValueError("session_closed")


class Native:
    def __init__(self):
        self.owner = ":1.42"
        self.index = 0
        self.enabled = True
        self.soft = self.hard = False
        self.now = 1_000_000_000
        self.country = "FR"
        self.mapping = types.SimpleNamespace(sample=lambda: self.index)
        self.command = types.SimpleNamespace(owner=lambda name: self.owner)

    def boottime(self):
        return self.now

    def wireless(self):
        return self.enabled

    def observe_country(self, requested):
        if requested != self.country:
            raise ValueError("country_unconfirmed")
        return {"requested_country": requested, "wiphy_index": self.index}

    def rfkill(self):
        return self.index, self.soft, self.hard


class Bus:
    def __init__(self):
        self.owner_value = ":1.42"
        self.profile = None
        self.active = []
        self.calls = []
        self.add_error = None
        self.create_before_error = False
        self.ready = True
        self.device_active = "/"
        self.device_state = 30
        self.version = "1.52.1"
        self.capabilities = 0x40
        self.managed = True
        self.flags = 5  # NM 1.52.1: UNSAVED|VOLATILE for this user-created AP.
        self.filename = FILENAME
        self.address = [{"address": "192.168.4.1", "prefix": 24}]
        self.settings_edit = None
        self.applied_edit = None
        self.secret_edit = None
        self.delete_error = None
        self.deactivate_error = None
        self.renew_count = self.close_count = 0
        self.auto_delete = True
        self.on_call = None

    def owner(self, timeout):
        assert 0 < timeout <= 2
        return self.owner_value

    def call(self, destination, path, interface, method, arguments, timeout):
        assert destination == self.owner_value
        assert 0 < timeout <= 2
        self.calls.append((path, method, copy.deepcopy(arguments)))
        if self.on_call:
            self.on_call(method)
        if method == "GetDeviceByIpIface":
            return DEV
        if method == "GetConnectionByUuid":
            if self.profile is None:
                raise ap.BusError("org.freedesktop.NetworkManager.Settings.InvalidConnection")
            return CON
        if method == "AddAndActivateConnection2":
            if self.add_error is None or self.create_before_error:
                self.profile = copy.deepcopy(arguments[0])
                self.active = [ACT]
                self.device_active, self.device_state = ACT, 100
            if self.add_error:
                raise ap.BusError(self.add_error)
            return [CON, ACT, {}]
        if method in {"GetSettings", "GetAppliedConnection"}:
            profile = copy.deepcopy(self.profile)
            del profile["802-11-wireless-security"]["psk"]
            # NM 1.52.1 wire serialization and normalization, not an echo of the
            # caller's profile: security_to_dbus and permanent MAC -> NEVER.
            profile["802-11-wireless"]["security"] = "802-11-wireless-security"
            profile["802-11-wireless"]["mac-address-randomization"] = 1
            profile["802-11-wireless"].pop("hidden")
            profile["802-11-wireless-security"].pop("psk-flags")
            profile["connection"]["permissions"] = []
            profile["ipv4"].update(addresses=[[17082560, 24, 0]], routes=[], **{"route-data": []})
            profile["ipv6"].update(addresses=[], routes=[], **{"address-data": [], "route-data": []})
            profile["proxy"] = {}
            edit = self.applied_edit if method == "GetAppliedConnection" else self.settings_edit
            if edit:
                edit(profile)
            return [profile, 1] if method == "GetAppliedConnection" else profile
        if method == "GetSecrets":
            secrets = {section: {} for section in self.profile}
            secrets["802-11-wireless-security"] = {"psk": self.profile["802-11-wireless-security"]["psk"]}
            if self.secret_edit:
                self.secret_edit(secrets)
            return secrets
        if method == "DeactivateConnection":
            if self.deactivate_error:
                raise ap.BusError(self.deactivate_error)
            self.active.remove(arguments[0])
            self.device_active, self.device_state = "/", 30
            if self.auto_delete:
                self.profile = None
            return None
        if method == "Delete":
            if self.delete_error:
                raise ap.BusError(self.delete_error)
            self.profile = None
            return None
        raise AssertionError(method)

    def prop(self, destination, path, interface, name, timeout):
        assert destination == self.owner_value
        self.calls.append((path, "Get:" + name, ()))
        if self.on_call:
            self.on_call("Get:" + name)
        if path == ap.ROOT:
            return {"Version": self.version, "ActiveConnections": list(self.active)}[name]
        if path == DEV:
            return {"Interface": "wlan0", "DeviceType": 2, "Managed": self.managed,
                    "State": self.device_state, "ActiveConnection": self.device_active,
                    "WirelessCapabilities": self.capabilities, "Mode": 3}[name]
        if path == CON:
            return {"Unsaved": True, "Flags": self.flags, "Filename": self.filename}[name]
        if path == IP:
            return copy.deepcopy(self.address)
        if path == ACT:
            return {"Uuid": UUID, "Connection": CON, "Devices": [DEV],
                    "State": 2 if self.ready else 1, "Ip4Config": IP}[name]
        if path == ap.ROOT + "/ActiveConnection/99":
            return {"Uuid": "38edeedf-d8e4-43d6-a7f9-488daf123a94"}[name]
        raise AssertionError((path, name))

    def renew(self):
        self.renew_count += 1
        self.close_count += 1
        self.profile = None
        self.active = [path for path in self.active if path != ACT]
        if self.device_active == ACT:
            self.device_active, self.device_state = "/", 30

    def close(self):
        self.close_count += 1

    def mutations(self, method):
        return [call for call in self.calls if call[1] == method]


class NativeAPTests(unittest.TestCase):
    def setUp(self):
        self.clock, self.native, self.bus = Clock(), Native(), Bus()
        self.adapter = ap.NativeAP(self.native, bus_adapter=self.bus, clock=self.clock,
                                   sleep=self.clock.sleep, boot_id_reader=lambda: BOOT,
                                   file_observer=lambda filename, check: check())
        self.checks = 0

    def check(self):
        self.checks += 1

    def start(self):
        return self.adapter.start(copy.deepcopy(CONFIG), self.check)

    def test_success_is_one_volatile_client_bound_activation_then_current_evidence(self):
        record = self.start()
        observation = self.adapter.verify(record, self.check)
        self.assertTrue(observation["active"])
        self.assertEqual(observation["ap_id"], UUID)
        call = self.bus.mutations("AddAndActivateConnection2")
        self.assertEqual(len(call), 1)
        profile, device, specific, options = call[0][2]
        self.assertEqual((device, specific), (DEV, "/"))
        self.assertEqual(options, {"persist": "volatile", "bind-activation": "dbus-client"})
        self.assertFalse(profile["connection"]["autoconnect"])
        self.assertEqual(profile["802-11-wireless"]["assigned-mac-address"], "permanent")
        self.assertEqual(profile["802-11-wireless-security"]["proto"], ["rsn"])
        self.assertEqual(profile["802-11-wireless-security"]["pairwise"], ["ccmp"])
        self.assertGreater(self.checks, 30)
        self.assertNotIn(CONFIG["passphrase"], repr(record) + repr(observation))

    def test_preflight_accepts_closed_radio_without_country_or_radio_setters(self):
        self.native.enabled = False
        self.native.soft = True
        self.native.country = "00"
        self.bus.device_state = 20
        observation = self.adapter.preflight(self.check)
        self.assertEqual(observation["wiphy_index"], 0)
        self.assertTrue(observation["ap_capable"])
        self.assertIsNone(self.adapter.owned_record)
        self.assertIsNone(self.adapter._config)
        self.assertEqual({call[1] for call in self.bus.calls} - {
            "GetDeviceByIpIface", "Get:Version", "Get:Interface", "Get:DeviceType",
            "Get:WirelessCapabilities", "Get:Managed", "Get:State", "Get:ActiveConnection",
        }, set())

    def test_preflight_refuses_station_or_incapable_device_without_mutations(self):
        for attribute, value, reason in (
            ("device_state", 40, "ap_device_busy"),
            ("device_active", ACT, "ap_device_busy"),
            ("capabilities", 0, "ap_capability_unavailable"),
            ("version", "1.50.0", "ap_nm_version_unconfirmed"),
            ("managed", False, "ap_device_busy"),
        ):
            with self.subTest(attribute=attribute):
                self.setUp()
                setattr(self.bus, attribute, value)
                with self.assertRaisesRegex(ap.APError, reason):
                    self.adapter.preflight(self.check)
                self.assertIsNone(self.adapter.owned_record)
                self.assertFalse(self.bus.mutations("AddAndActivateConnection2"))
                self.assertFalse(self.bus.mutations("DeactivateConnection"))

    def test_preflight_owner_or_mapping_change_refuses_stale_observation(self):
        def replace(method):
            if method == "Get:ActiveConnection":
                self.native.index = 1

        self.bus.on_call = replace
        with self.assertRaisesRegex(ap.APError, "ap_device_changed"):
            self.adapter.preflight(self.check)
        self.assertIsNone(self.adapter.owned_record)

    def test_preflight_success_never_authorizes_later_start_on_changed_device(self):
        self.adapter.preflight(self.check)
        self.bus.capabilities = 0
        with self.assertRaisesRegex(ap.APError, "ap_capability_unavailable"):
            self.start()
        self.assertFalse(self.bus.mutations("AddAndActivateConnection2"))

    def test_invalid_closed_configuration_refuses_before_bus_or_mutation(self):
        for edit in (
            lambda c: c.update(extra=1), lambda c: c.pop("ssid"),
            lambda c: c.update(channel=True), lambda c: c.update(channel=11),
            lambda c: c.update(prefix=True), lambda c: c.update(country="US"),
            lambda c: c.update(interface="wlan1"), lambda c: c.update(port=8443),
            lambda c: c.update(ap_id=UUID.upper()), lambda c: c.update(ssid="é" * 17),
            lambda c: c.update(ssid="bad\x00ssid"), lambda c: c.update(passphrase="x" * 7),
            lambda c: c.update(passphrase="é" * 24), lambda c: c.update(host="192.168.5.1"),
        ):
            with self.subTest(edit=edit):
                config = copy.deepcopy(CONFIG)
                edit(config)
                with self.assertRaisesRegex(ap.APError, "ap_config_invalid"):
                    self.adapter.start(config, self.check)
                self.assertEqual(self.bus.calls, [])

    def test_expired_and_prior_boot_config_never_activate(self):
        for key, value, reason in (("expires_boottime_ns", self.native.now, "ap_expired"),
                                   ("expires_boottime_ns", True, "ap_expired"),
                                   ("boot_id", UUID, "ap_boot_changed")):
            config = dict(CONFIG, **{key: value})
            with self.assertRaisesRegex(ap.APError, reason):
                self.adapter.start(config, self.check)
        self.assertFalse(self.bus.calls)

    def test_wrong_country_or_blocked_radio_cannot_be_enabled_by_adapter(self):
        for attribute, value in (("country", "US"), ("enabled", False), ("soft", True), ("hard", True)):
            with self.subTest(attribute=attribute):
                setattr(self.native, attribute, value)
                with self.assertRaises(ap.APError):
                    self.start()
                self.assertFalse(self.bus.mutations("AddAndActivateConnection2"))
                setattr(self.native, attribute, "FR" if attribute == "country" else attribute == "enabled")

    def test_capability_and_version_are_required_before_mutation(self):
        for attribute, value in (("capabilities", 0), ("capabilities", True), ("version", "1.50.0"), ("managed", False)):
            with self.subTest(attribute=attribute):
                old = getattr(self.bus, attribute)
                setattr(self.bus, attribute, value)
                with self.assertRaises(ap.APError):
                    self.start()
                self.assertFalse(self.bus.mutations("AddAndActivateConnection2"))
                setattr(self.bus, attribute, old)

    def test_active_station_is_not_replaced(self):
        self.bus.device_active = ap.ROOT + "/ActiveConnection/99"
        self.bus.device_state = 100
        with self.assertRaisesRegex(ap.APError, "ap_device_busy"):
            self.start()
        self.assertFalse(self.bus.mutations("AddAndActivateConnection2"))
        self.assertFalse(self.bus.mutations("DeactivateConnection"))

    def test_unavailable_to_disconnected_transition_can_wait_before_activation(self):
        self.bus.device_state = 20
        reads = 0

        def ready(method):
            nonlocal reads
            if method == "Get:State":
                reads += 1
                if reads == 3:
                    self.bus.device_state = 30

        self.bus.on_call = ready
        self.start()
        self.assertEqual(len(self.bus.mutations("AddAndActivateConnection2")), 1)
        self.assertGreaterEqual(reads, 3)

    def test_station_preparing_state_is_refused_without_wait(self):
        self.bus.device_state = 40
        with self.assertRaisesRegex(ap.APError, "ap_device_busy"):
            self.start()
        self.assertLess(self.clock.now, 2)
        self.assertFalse(self.bus.mutations("AddAndActivateConnection2"))

    def test_existing_uuid_is_neither_adopted_nor_deleted(self):
        self.bus.profile = ap.NativeAP._profile(CONFIG)
        with self.assertRaisesRegex(ap.APError, "ap_uuid_exists"):
            self.start()
        self.assertIsNotNone(self.bus.profile)
        self.assertFalse(self.bus.mutations("Delete"))

    def test_second_start_cannot_replay_existing_activation(self):
        self.start()
        with self.assertRaisesRegex(ap.APError, "ap_reconciliation_required"):
            self.start()
        self.assertEqual(len(self.bus.mutations("AddAndActivateConnection2")), 1)

    def test_timeout_preserves_secret_free_record_and_stop_drains_owned_bus(self):
        self.bus.add_error = "org.freedesktop.DBus.Error.NoReply"
        self.bus.create_before_error = True
        with self.assertRaisesRegex(ap.APError, "ap_activation_uncertain") as caught:
            self.start()
        record = caught.exception.record
        self.assertTrue(caught.exception.reconciliation)
        self.assertIs(record, self.adapter.owned_record)
        self.assertNotIn(CONFIG["passphrase"], repr(caught.exception) + repr(record))
        self.adapter.stop(record, self.check)
        self.assertEqual(self.bus.renew_count, 1)
        self.assertIsNone(self.adapter.owned_record)
        self.assertEqual(len(self.bus.mutations("AddAndActivateConnection2")), 1)

    def test_explicit_activation_rejection_has_no_retry_and_clears_owned_record(self):
        self.bus.add_error = "org.freedesktop.DBus.Error.AccessDenied"
        with self.assertRaisesRegex(ap.APError, "ap_activation_rejected") as caught:
            self.start()
        self.assertIsNone(caught.exception.record)
        self.assertEqual(len(self.bus.mutations("AddAndActivateConnection2")), 1)

    def test_changed_owner_prevents_targeting_replacement_daemon(self):
        record = self.start()
        self.bus.owner_value = ":1.43"
        self.native.owner = ":1.43"
        with self.assertRaisesRegex(ap.APError, "ap_nm_owner_changed"):
            self.adapter.stop(record, self.check)
        self.assertFalse(self.bus.mutations("DeactivateConnection"))
        self.assertFalse(self.bus.mutations("Delete"))

    def test_changed_physical_mapping_prevents_cleanup_mutations(self):
        record = self.start()
        self.native.index = 1
        with self.assertRaisesRegex(ap.APError, "ap_device_changed"):
            self.adapter.stop(record, self.check)
        self.assertFalse(self.bus.mutations("DeactivateConnection"))

    def test_profile_readback_forbids_weak_security_or_unexpected_settings(self):
        edits = (
            lambda p: p["802-11-wireless-security"].update(proto=["wpa"]),
            lambda p: p["802-11-wireless-security"].update(pairwise=["tkip"]),
            lambda p: p["802-11-wireless"].update(mode="infrastructure"),
            lambda p: p["connection"].update(autoconnect=True),
            lambda p: p["ipv4"].update(gateway="192.168.4.254"),
            lambda p: p["ipv4"].update(**{"routing-rules": [{"priority": 1}]}),
            lambda p: p.update(vpn={}),
        )
        for edit in edits:
            with self.subTest(edit=edit):
                self.setUp()
                record = self.start()
                self.bus.settings_edit = edit
                with self.assertRaisesRegex(ap.APError, "ap_profile_changed"):
                    self.adapter.verify(record, self.check)

    def test_applied_profile_is_checked_independently(self):
        record = self.start()
        self.bus.applied_edit = lambda p: p["802-11-wireless"].update(channel=11)
        with self.assertRaisesRegex(ap.APError, "ap_profile_changed"):
            self.adapter.verify(record, self.check)

    def test_normalized_mac_and_security_aliases_do_not_relax_profile(self):
        for key, value in (("security", "802-1x"), ("security", ""),
                           ("mac-address-randomization", 0),
                           ("mac-address-randomization", 2),
                           ("mac-address-randomization", True)):
            for applied in (False, True):
                with self.subTest(key=key, value=value, applied=applied):
                    self.setUp()
                    record = self.start()
                    edit = lambda profile: profile["802-11-wireless"].update({key: value})
                    if applied:
                        self.bus.applied_edit = edit
                    else:
                        self.bus.settings_edit = edit
                    with self.assertRaisesRegex(ap.APError, "ap_profile_changed"):
                        self.adapter.verify(record, self.check)

    def test_changed_secret_refuses_without_exposing_psk(self):
        record = self.start()
        self.bus.secret_edit = lambda p: p["802-11-wireless-security"].update(psk="othersecret")
        with self.assertRaisesRegex(ap.APError, "ap_profile_changed") as caught:
            self.adapter.verify(record, self.check)
        self.assertNotIn("othersecret", str(caught.exception))
        self.assertNotIn(CONFIG["passphrase"], repr(caught.exception))

    def test_real_getsecrets_empty_known_sections_are_accepted_only_when_empty(self):
        for edit in (lambda p: p.update(vpn={}),
                     lambda p: p["ipv4"].update(method="shared"),
                     lambda p: p["802-11-wireless-security"].update(password="foreign"),
                     lambda p: p.update(connection=[])):
            with self.subTest(edit=edit):
                self.setUp()
                record = self.start()
                self.bus.secret_edit = edit
                with self.assertRaisesRegex(ap.APError, "ap_profile_changed"):
                    self.adapter.verify(record, self.check)

    def test_settings_comparison_is_pure_and_accepts_real_sparse_serialization(self):
        self.start()
        settings = self.bus.call(self.bus.owner_value, CON, ap.CONNECTION, "GetSettings", (), 1)
        self.bus.calls.clear()
        self.adapter._settings_exact(settings)
        self.assertEqual(self.bus.calls, [])
        settings["802-11-wireless-security"]["pairwise"] = ["tkip"]
        with self.assertRaisesRegex(ap.APError, "ap_profile_changed"):
            self.adapter._settings_exact(settings)
        self.assertEqual(self.bus.calls, [])

    def test_wrong_ipv4_is_not_readiness(self):
        record = self.start()
        self.bus.address = [{"address": "192.168.4.2", "prefix": 24}]
        with self.assertRaisesRegex(ap.APError, "ap_address_unconfirmed"):
            self.adapter.verify(record, self.check)

    def test_profile_persistence_is_verified(self):
        record = self.start()
        invalid = [("flags", value) for value in (0, 1, 2, 3, 4, 6, 13, True)]
        invalid.append(("filename", "/etc/NetworkManager/system-connections/ap.nmconnection"))
        for attribute, value in invalid:
            old = getattr(self.bus, attribute)
            setattr(self.bus, attribute, value)
            with self.assertRaisesRegex(ap.APError, "ap_profile_persistence_changed"):
                self.adapter.verify(record, self.check)
            setattr(self.bus, attribute, old)

    def test_profile_filename_is_runtime_only_and_cannot_change_between_reads(self):
        for filename in ("", "/etc/NetworkManager/system-connections/ap.nmconnection",
                         "/usr/lib/NetworkManager/system-connections/ap.nmconnection",
                         ap.RUNTIME_PROFILES + "/../escape.nmconnection",
                         ap.RUNTIME_PROFILES + "/nested/ap.nmconnection"):
            with self.subTest(filename=filename):
                self.setUp()
                record = self.start()
                self.bus.filename = filename
                with self.assertRaisesRegex(ap.APError, "ap_profile_persistence_changed"):
                    self.adapter.verify(record, self.check)
        self.setUp()
        record = self.start()
        self.bus.filename = ap.RUNTIME_PROFILES + "/other.nmconnection"
        with self.assertRaisesRegex(ap.APError, "ap_profile_persistence_changed"):
            self.adapter.verify(record, self.check)

    def test_filename_property_change_during_metadata_probe_is_refused(self):
        record = self.start()

        def observe(filename, check):
            check()
            self.bus.filename = ap.RUNTIME_PROFILES + "/changed.nmconnection"

        self.adapter._file_observer = observe
        with self.assertRaisesRegex(ap.APError, "ap_profile_persistence_changed"):
            self.adapter.verify(record, self.check)

    def test_not_ready_is_bounded_and_cleanup_occurs_once(self):
        self.bus.ready = False
        with self.assertRaisesRegex(ap.APError, "ap_observation_timeout"):
            self.start()
        self.assertLess(self.clock.now, 34)
        self.assertEqual(len(self.bus.mutations("AddAndActivateConnection2")), 1)
        self.assertEqual(len(self.bus.mutations("DeactivateConnection")), 1)
        self.assertIsNone(self.adapter.owned_record)

    def test_stop_removes_only_owned_profile_and_preserves_station(self):
        record = self.start()
        unrelated = ap.ROOT + "/ActiveConnection/99"
        self.bus.active.append(unrelated)
        self.bus.auto_delete = False
        self.adapter.stop(record, self.check)
        self.assertEqual(self.bus.active, [unrelated])
        self.assertEqual(self.bus.mutations("DeactivateConnection")[0][2], (ACT,))
        self.assertEqual(len(self.bus.mutations("Delete")), 1)
        self.assertIsNone(self.bus.profile)
        self.assertIsNone(self.adapter.owned_record)

    def test_stop_after_expiry_does_not_reactivate_or_set_radio(self):
        record = self.start()
        self.native.now = CONFIG["expires_boottime_ns"]
        with self.assertRaisesRegex(ap.APError, "ap_expired"):
            self.adapter.verify(record, self.check)
        self.adapter.stop(record, self.check)
        self.assertEqual(len(self.bus.mutations("AddAndActivateConnection2")), 1)

    def test_uncertain_deactivation_is_not_replayed(self):
        record = self.start()
        self.bus.deactivate_error = "org.freedesktop.DBus.Error.NoReply"
        with self.assertRaisesRegex(ap.APError, "ap_cleanup_unconfirmed"):
            self.adapter.stop(record, self.check)
        self.bus.deactivate_error = None
        self.adapter.stop(record, self.check)
        self.assertEqual(len(self.bus.mutations("DeactivateConnection")), 1)
        self.assertEqual(self.bus.renew_count, 1)
        self.assertIsNone(self.adapter.owned_record)

    def test_unknown_record_cannot_delete_an_owned_profile(self):
        record = self.start()
        with self.assertRaisesRegex(ap.APError, "ap_record_invalid"):
            self.adapter.stop(dict(record), self.check)
        self.assertFalse(self.bus.mutations("DeactivateConnection"))

    def test_controller_can_drain_pre_effect_failure_without_record(self):
        self.adapter.stop(None, self.check)
        self.assertEqual(self.bus.calls, [])

    def test_close_is_idempotent_and_does_not_claim_cleanup_receipt(self):
        record = self.start()
        self.adapter.close(self.check)
        self.adapter.close(self.check)
        self.assertEqual(self.bus.close_count, 1)
        self.assertIs(record, self.adapter.owned_record)
        self.assertIsNone(self.adapter._config)
        with self.assertRaisesRegex(ap.APError, "ap_unavailable"):
            self.adapter.verify(record, self.check)

    def test_full_checks_surround_operations_and_effects_without_per_property_walks(self):
        guard = Guard(self.clock)
        before = self.clock.now
        self.adapter.preflight(guard)
        self.assertEqual(guard.full, 2)
        self.assertLess(self.clock.now - before, 0.6)
        guard.full = guard.light = 0
        before = self.clock.now
        record = self.adapter.start(copy.deepcopy(CONFIG), guard)
        self.assertEqual(guard.full, 4)  # entry, before/after AddActivate, exit
        self.assertGreater(guard.light, 50)
        self.assertLess(self.clock.now - before, 1.3)
        guard.full = guard.light = 0
        self.adapter.verify(record, guard)
        self.assertEqual(guard.full, 2)
        guard.full = guard.light = 0
        self.adapter.stop(record, guard)
        self.assertEqual(guard.full, 4)  # entry, before/after targeted deactivate, exit

    def test_graph_changed_during_reads_is_refused_before_activation(self):
        guard = Guard(self.clock)

        def change(method):
            if method == "Get:Version":
                guard.graph_valid = False

        self.bus.on_call = change
        with self.assertRaises(ap.APError):
            self.adapter.start(copy.deepcopy(CONFIG), guard)
        self.assertFalse(self.bus.mutations("AddAndActivateConnection2"))

    def test_station_starting_during_full_admission_guard_cannot_be_replaced(self):
        fixture = self
        unrelated = ap.ROOT + "/ActiveConnection/99"

        class StationRace(Guard):
            def __call__(self):
                super().__call__()
                if self.full == 2:
                    fixture.bus.device_state = 100
                    fixture.bus.device_active = unrelated
                    fixture.bus.active = [unrelated]

        with self.assertRaisesRegex(ap.APError, "ap_device_busy"):
            self.adapter.start(copy.deepcopy(CONFIG), StationRace(self.clock))
        self.assertIsNone(self.adapter.owned_record)
        self.assertFalse(self.bus.mutations("AddAndActivateConnection2"))
        self.assertFalse(self.bus.mutations("DeactivateConnection"))
        self.assertFalse(self.bus.mutations("Delete"))
        self.assertEqual(self.bus.close_count, 0)
        self.assertEqual(self.bus.active, [unrelated])

    def test_expiry_during_full_admission_guard_cannot_dispatch_activation(self):
        fixture = self

        class ExpiryRace(Guard):
            def __call__(self):
                super().__call__()
                if self.full == 2:
                    fixture.native.now = CONFIG["expires_boottime_ns"]

        with self.assertRaisesRegex(ap.APError, "ap_expired"):
            self.adapter.start(copy.deepcopy(CONFIG), ExpiryRace(self.clock))
        self.assertIsNone(self.adapter.owned_record)
        self.assertFalse(self.bus.mutations("AddAndActivateConnection2"))
        self.assertFalse(self.bus.mutations("DeactivateConnection"))
        self.assertEqual(self.bus.close_count, 0)

    def test_eof_ends_read_only_probing_before_activation(self):
        guard = Guard(self.clock)

        def disconnect(method):
            if method == "Get:Version":
                guard.connected = False

        self.bus.on_call = disconnect
        with self.assertRaises(ap.APError):
            self.adapter.start(copy.deepcopy(CONFIG), guard)
        self.assertFalse(self.bus.mutations("AddAndActivateConnection2"))

    def test_graph_changed_during_verification_cannot_return_readiness(self):
        record = self.start()
        guard = Guard(self.clock)

        def change(method):
            if method == "GetSettings":
                guard.graph_valid = False

        self.bus.on_call = change
        with self.assertRaisesRegex(ap.APError, "ap_observation_unavailable"):
            self.adapter.verify(record, guard)
        self.assertEqual(guard.full, 2)

    def test_close_checks_full_graph_before_and_after_client_lifetime_effect(self):
        guard = Guard(self.clock)
        self.adapter.start(copy.deepcopy(CONFIG), guard)
        guard.full = guard.light = 0
        self.adapter.close(guard)
        self.assertEqual(guard.full, 3)  # entry + before/after close (also exit)
        self.assertEqual(self.bus.close_count, 1)

    def test_core_close_uses_current_journal_guard_after_stopped_peer_disconnects(self):
        spec = importlib.util.spec_from_file_location(
            "ap_close_core", Path(__file__).resolve().parents[1] / "staging/bootstrap/system-setup-ap.py"
        )
        core_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(core_module)
        controller = core_module.Controller(
            self.adapter, core_module.POLICY, boottime_ns=self.native.boottime,
            random=lambda count: uuid.UUID(UUID).bytes if count == 16 else bytes(count),
        )
        workflow = {"initialization_intent": BOOT, "initialization_receipt_digest": "a" * 64,
                    "frame_id": BOOT, "spki_sha256": "b" * 64}
        context = {"boot_id": BOOT, "candidate_sha256": "c" * 64,
                   "context_sha256": "d" * 64, "main_invocation_id": "e" * 32}
        connected = True

        def peer():
            if not connected:
                raise ValueError("session_closed")

        controller.start(workflow, context, peer)
        controller.stop(workflow, context, peer)
        self.assertIsNone(self.adapter.owned_record)
        connected = False
        controller.close(self.check)  # service journal guard, not the old peer
        self.assertTrue(controller._closed)
        self.assertTrue(self.adapter._closed)
        self.assertEqual(self.bus.close_count, 1)

    def test_close_without_any_ap_or_bus_checks_journal_without_opening_bus(self):
        adapter = ap.NativeAP(self.native, clock=self.clock, sleep=self.clock.sleep)
        adapter.close(self.check)
        self.assertTrue(adapter._closed)
        self.assertIsNone(adapter._bus)
        self.assertIsNone(adapter.owned_record)

    def test_setup_evidence_is_bounded_by_exact_ap_and_existing_gate(self):
        record = self.start()
        calls = []
        self.native.gate_receipt = lambda context: {"gate": context}
        self.native.observe_live = lambda country, radio: (country, dict(radio, wireless_enabled=True))
        self.native.inventory = lambda proof, **kwargs: calls.append((proof, kwargs))
        evidence = self.adapter.apply_evidence(record, "context", "proof", self.check)
        self.assertEqual(set(evidence), {"gate", "country", "radio"})
        self.assertEqual(evidence["gate"], {"gate": "context"})
        self.assertEqual(calls, [("proof", {"ap_uuid": UUID})])
        self.assertEqual(len(self.bus.mutations("AddAndActivateConnection2")), 1)

    def test_setup_inventory_failure_cannot_relax_other_network_profiles(self):
        record = self.start()
        self.native.gate_receipt = lambda context: {}
        self.native.observe_live = lambda country, radio: (country, radio)

        def refuse(proof, **kwargs):
            raise ValueError("inventory_not_closed")

        self.native.inventory = refuse
        with self.assertRaisesRegex(ap.APError, "ap_setup_evidence_unconfirmed"):
            self.adapter.apply_evidence(record, {}, object(), self.check)

    def test_expiration_during_preflight_cannot_activate(self):
        def expire(method):
            if method == "Get:Version":
                self.native.now = CONFIG["expires_boottime_ns"]

        self.bus.on_call = expire
        with self.assertRaisesRegex(ap.APError, "ap_expired"):
            self.start()
        self.assertFalse(self.bus.mutations("AddAndActivateConnection2"))

    def test_cancellation_after_dispatch_keeps_pending_mutation_for_drain(self):
        dispatched = False

        def cancel_after_add(method):
            nonlocal dispatched
            if method == "AddAndActivateConnection2":
                dispatched = True

        def check():
            if dispatched:
                raise ValueError("cancelled")

        self.bus.on_call = cancel_after_add
        with self.assertRaises(ap.APError) as caught:
            self.adapter.start(copy.deepcopy(CONFIG), check)
        self.assertTrue(caught.exception.reconciliation)
        self.assertTrue(caught.exception.record["uncertain"])
        self.adapter.stop(caught.exception.record, self.check)
        self.assertEqual(self.bus.renew_count, 1)
        self.assertEqual(len(self.bus.mutations("AddAndActivateConnection2")), 1)


class DBusShapeTests(unittest.TestCase):
    def test_private_bus_is_created_lazily_and_stays_open_until_close(self):
        bus = types.SimpleNamespace(close=lambda: None)
        create = []
        fake = types.SimpleNamespace(SystemBus=lambda **kwargs: create.append(kwargs) or bus)
        with patch.dict("sys.modules", dbus=fake), patch.object(ap.sys, "path", list(ap.sys.path)):
            adapter = ap.NativeAP(Native())
            self.assertEqual(create, [])
            real = ap._DBusAdapter()
            self.assertEqual(create, [{"private": True}])
            real.close()
            self.assertIsNone(adapter.owned_record)

    def test_no_site_loader_appends_only_closed_system_package_path(self):
        fake = types.SimpleNamespace(SystemBus=lambda **kwargs: types.SimpleNamespace(close=lambda: None))
        initial = ["/usr/lib/python313.zip", "/usr/lib/python3.13", "/usr/lib/python3.13/lib-dynload"]
        with patch.dict("sys.modules", dbus=fake), patch.object(ap.sys, "path", initial.copy()):
            real = ap._DBusAdapter()
            self.assertEqual(ap.sys.path, initial + ["/usr/lib/python3/dist-packages"])
            second = ap._DBusAdapter()
            self.assertEqual(ap.sys.path, initial + ["/usr/lib/python3/dist-packages"])
            real.close()
            second.close()

    def test_byte_arrays_decode_as_ssid_bytes_in_default_dbus_python_mode(self):
        class Array(list):
            signature = "y"

        self.assertEqual(ap._plain(Array(b"Inky-1234")), b"Inky-1234")

    def test_profile_uses_matching_dbus_signedness_and_container_signatures(self):
        class Dictionary(dict):
            def __init__(self, value, *, signature):
                super().__init__(value)
                self.signature = signature

        class Array(list):
            def __init__(self, value, *, signature):
                super().__init__(value)
                self.signature = signature

        real = ap._DBusAdapter.__new__(ap._DBusAdapter)
        real.dbus = types.SimpleNamespace(
            Dictionary=Dictionary, Array=Array,
            UInt32=lambda value: ("u", value), Int32=lambda value: ("i", value),
            Boolean=lambda value: ("b", value), ByteArray=lambda value: ("ay", value),
        )
        typed = real._profile(ap.NativeAP._profile(CONFIG))
        self.assertEqual(typed.signature, "sa{sv}")
        self.assertEqual(typed["802-11-wireless"].signature, "sv")
        self.assertEqual(typed["802-11-wireless"]["channel"], ("u", 6))
        self.assertEqual(typed["802-11-wireless"]["powersave"], ("u", 2))
        self.assertEqual(typed["802-11-wireless"]["ap-isolation"], ("i", 1))
        self.assertEqual(typed["proxy"]["method"], ("i", 0))
        self.assertEqual(typed["802-11-wireless-security"]["psk-flags"], ("u", 0))
        address = typed["ipv4"]["address-data"]
        self.assertEqual(address.signature, "a{sv}")
        self.assertEqual(address[0]["prefix"], ("u", 24))


class RuntimeMetadataTests(unittest.TestCase):
    MOUNTS = b"1 0 8:2 / / rw - ext4 /dev/root rw\n2 1 0:42 / /run rw,nosuid - tmpfs tmpfs rw\n"

    def setUp(self):
        self.info = {}
        for number in (10, 11, 12, 13):
            self.info[number] = types.SimpleNamespace(
                st_dev=42, st_ino=number, st_mode=(stat.S_IFREG | 0o600) if number == 13 else (stat.S_IFDIR | 0o755),
                st_uid=0, st_gid=0, st_nlink=1, st_size=1024,
                st_mtime_ns=5, st_ctime_ns=6,
            )
        self.opened, self.closed = [], []

    def opened_fd(self, path, flags, **kwargs):
        self.opened.append((path, flags, kwargs))
        return {"/run": 10, "NetworkManager": 11, "system-connections": 12}.get(path, 13)

    def named(self, path, **kwargs):
        number = {"/run": 10, "NetworkManager": 11, "system-connections": 12}.get(path, 13)
        return self.info[number]

    def observe(self, mounts=None):
        with patch.object(ap.os, "open", self.opened_fd), patch.object(ap.os, "fstat", lambda fd: self.info[fd]), \
                patch.object(ap.os, "stat", self.named), patch.object(ap.os, "close", self.closed.append), \
                patch.object(ap.Path, "open", lambda *args, **kwargs: io.BytesIO(self.MOUNTS if mounts is None else mounts)):
            return ap._observe_runtime_file(FILENAME, lambda: None)

    def test_runtime_tmpfs_file_metadata_is_observed_without_content_read(self):
        self.assertEqual(self.observe(), {"device": 42, "inode": 13, "mode": 0o600})
        self.assertEqual(self.closed, [13, 12, 11, 10])
        self.assertTrue(all(flags & ap.os.O_NOFOLLOW for _, flags, _ in self.opened))

    def test_more_restrictive_root_private_profile_directory_is_also_allowed(self):
        self.info[12].st_mode = stat.S_IFDIR | 0o700
        self.observe()

    def test_wrong_owner_modes_symlink_or_hardlink_refuse_and_close_fds(self):
        for number, field, value in ((13, "st_uid", 1000), (13, "st_gid", 1000),
                                     (13, "st_mode", stat.S_IFREG | 0o644),
                                     (13, "st_mode", stat.S_IFLNK | 0o777),
                                     (13, "st_nlink", 2), (12, "st_mode", stat.S_IFDIR | 0o775),
                                     (11, "st_uid", 1000)):
            with self.subTest(number=number, field=field):
                self.setUp()
                setattr(self.info[number], field, value)
                with self.assertRaisesRegex(ap.APError, "ap_runtime_metadata_unconfirmed"):
                    self.observe()
                self.assertEqual(len(self.opened), len(self.closed))

    def test_non_tmpfs_readonly_or_overmount_refuses(self):
        mounts = (
            self.MOUNTS.replace(b"- tmpfs tmpfs", b"- ext4 /dev/root"),
            self.MOUNTS.replace(b"/run rw,nosuid", b"/run ro,nosuid"),
            self.MOUNTS + b"3 2 8:2 / /run/NetworkManager rw - ext4 /dev/root rw\n",
            self.MOUNTS.replace(b"0:42", b"0:43"),
        )
        for data in mounts:
            with self.subTest(mounts=data):
                with self.assertRaisesRegex(ap.APError, "ap_runtime_metadata_unconfirmed"):
                    self.observe(data)

    def test_replaced_leaf_or_parent_binding_is_refused(self):
        initial = self.info[13]
        original = self.named
        calls = 0

        def replaced(path, **kwargs):
            nonlocal calls
            if path.endswith(".nmconnection"):
                calls += 1
                if calls == 2:
                    return types.SimpleNamespace(**{**vars(initial), "st_ino": 99})
            return original(path, **kwargs)

        self.named = replaced
        with self.assertRaisesRegex(ap.APError, "ap_runtime_metadata_unconfirmed"):
            self.observe()


if __name__ == "__main__":
    unittest.main()
