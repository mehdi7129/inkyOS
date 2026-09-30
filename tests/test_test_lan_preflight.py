"""Offline adapters, public manifests and synthetic rootfs; no LAN/radio/app activation."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/test-lan-preflight.py"
spec = importlib.util.spec_from_file_location("inkyos_test_lan_preflight", SCRIPT)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)
REFERENCE = 1790800000


def panel_inventory():
    return {"schema_version": 1, "display_variant": 20, "panel_reference": "AC073TC1A",
            "width": 800, "height": 480, "physical_label_confirmed": True}


class FixtureAdapter:
    def __init__(self, facts=None):
        self.facts = {key: True for key in preflight.CHECKS} if facts is None else facts
        self.calls = 0

    def collect(self, _request):
        self.calls += 1
        return self.facts


class PreflightTests(unittest.TestCase):
    def test_allowlist_is_exactly_two_reviewed_source_manifest_pairs(self):
        self.assertEqual(preflight.REVIEWED_APPLICATIONS, {
            "6a697d134290ced0214fc74b903f4b3c336d70fa": "2424fb9c32234ad7d359799f6b137e98298734023f0039afd1a57fbf265c250f",
            "758a2bf7ed099aad41ef35316e53228e797b0b2b": "0d587792433d924ad1c4e71af19c2a46279f573791cb690571fa1019e7703551",
        })

    def inputs(self):
        return {"live": True, "operator_access_confirmed": True, "country": "FR", "country_confirmed": True,
                "utc_reference": REFERENCE, "utc_reference_age": 10,
                "utc_reference_source": "independent-device", "panel_inventory": "PRIVATE_PANEL_PATH"}

    def test_default_is_blocked_without_calling_adapter_or_host(self):
        adapter = FixtureAdapter()
        with mock.patch.object(preflight.os, "open", side_effect=AssertionError("No default reads")):
            value = preflight.preflight(adapter)
        self.assertEqual(adapter.calls, 0)
        self.assertFalse(value["passed"])
        self.assertFalse(value["activation_authorized"])
        self.assertEqual(value["observation_source"], "inactive")
        self.assertTrue(all(item["reason"] == "live_not_selected" for item in value["checks"].values()))

    def test_positive_fixture_is_observation_only_and_never_activation_or_live_evidence(self):
        value = preflight.preflight(FixtureAdapter(), **self.inputs())
        self.assertTrue(value["passed"])
        self.assertEqual(value["observation_source"], "fixture")
        self.assertTrue(all(item["passed"] for item in value["checks"].values()))
        for key in ("activation_authorized", "hardware_qualified", "release_qualified", "live_evidence"):
            self.assertFalse(value[key])
        text = json.dumps(value)
        self.assertNotIn("PRIVATE_PANEL_PATH", text)
        self.assertNotIn(str(REFERENCE), text)
        self.assertEqual(value["limitations"], list(preflight.LIMITATIONS))

    def test_every_missing_fact_and_nonboolean_adversarial_fact_blocks(self):
        for key in preflight.CHECKS:
            # Three operator input checks are independently validated below.
            if key in {"operator_access_confirmed", "country_operator_confirmed"}:
                continue
            for invalid in (False, "yes", 1, {"PRIVATE_SECRET": True}):
                with self.subTest(key=key, invalid=invalid):
                    facts = {name: True for name in preflight.CHECKS}
                    facts[key] = invalid
                    value = preflight.preflight(FixtureAdapter(facts), **self.inputs())
                    self.assertFalse(value["passed"])
                    self.assertFalse(value["checks"][key]["passed"])
                    self.assertNotIn("PRIVATE_SECRET", json.dumps(value))

    def test_operator_country_time_and_access_assertions_are_required_and_bounded(self):
        changes = ({"operator_access_confirmed": False}, {"country_confirmed": False}, {"country": "fr"},
                   {"country": "PRIVATE_COUNTRY"}, {"utc_reference": True}, {"utc_reference": 0},
                   {"utc_reference_age": True}, {"utc_reference_age": -1}, {"utc_reference_age": 61},
                   {"utc_reference_source": "same-system-ntp"}, {"utc_reference_source": {"PRIVATE_ID": 1}})
        for change in changes:
            with self.subTest(change=change):
                inputs = self.inputs()
                inputs.update(change)
                value = preflight.preflight(FixtureAdapter(), **inputs)
                self.assertFalse(value["passed"])
                self.assertNotIn("PRIVATE", json.dumps(value))

    def test_adapter_errors_unknown_keys_and_raw_errors_never_escape(self):
        class Broken:
            def collect(self, _request):
                raise OSError("PRIVATE_PASSWORD PRIVATE_IP PRIVATE_KEY")
        value = preflight.preflight(Broken(), **self.inputs())
        self.assertEqual(value["error"], "observations_unavailable")
        self.assertNotIn("PRIVATE_", json.dumps(value))
        value = preflight.preflight(FixtureAdapter({"PRIVATE_ID": True}), **self.inputs())
        self.assertFalse(value["passed"])
        self.assertNotIn("PRIVATE_ID", json.dumps(value))

    def test_country_requires_global_and_correct_phy_observation_not_exit_success(self):
        interface = "Interface wlan0\n\taddr PRIVATE_MAC\n\tssid PRIVATE_SSID\n\twiphy 0\n"
        good = "global\ncountry FR: DFS-ETSI\n\t(2400 - 2483 @ 40), (N/A, 20), (N/A)\nphy#0 (self-managed)\ncountry FR: DFS-ETSI\n"
        self.assertEqual(preflight.country_observed(interface, good, "FR"), (True, True))
        for regulatory, expected in (
            ("", (False, False)),
            ("global\ncountry FR: DFS-ETSI\n", (True, False)),
            ("global\ncountry FR: DFS-ETSI\nphy#0 (self-managed)\ncountry 99: DFS-UNSET\n", (True, False)),
            ("global\ncountry US: DFS-FCC\nphy#0\ncountry FR: DFS-ETSI\n", (False, True)),
            ("global\ncountry FR: DFS-ETSI\nphy#1\ncountry FR: DFS-ETSI\n", (True, False)),
            (good + "country FR: DFS-ETSI\n", (False, False)),
        ):
            self.assertEqual(preflight.country_observed(interface, regulatory, "FR"), expected)
        self.assertEqual(preflight.country_observed("", "", None), (False, False))
        self.assertEqual(preflight.country_observed(interface + "wiphy 1\n", good, "FR"), (False, False))

    def test_panel_inventory_rejects_types_wrong_mapping_and_unreviewed_extra_evidence(self):
        self.assertTrue(preflight.valid_panel_inventory(panel_inventory()))
        for change in ({"schema_version": True}, {"display_variant": True}, {"panel_reference": "E673"},
                       {"panel_reference": {}}, {"physical_label_confirmed": 1}, {"width": 800.0},
                       {"PRIVATE_SERIAL": "PRIVATE_DATA"}):
            value = panel_inventory()
            value.update(change)
            self.assertFalse(preflight.valid_panel_inventory(value))

    def test_panel_inventory_accepts_only_reviewed_variant_reference_and_dimensions(self):
        layouts = ((20, "AC073TC1A", 800, 480), (21, "EL133UF1", 1600, 1200),
                   (22, "E673", 800, 480), (25, "E640", 600, 400))
        for variant, reference, width, height in layouts:
            with self.subTest(variant=variant):
                value = dict(panel_inventory(), display_variant=variant, panel_reference=reference,
                             width=width, height=height)
                self.assertTrue(preflight.valid_panel_inventory(value))
                for change in ({"width": width + 1}, {"height": height + 1}, {"width": True},
                               {"height": float(height)}, {"panel_reference": reference.lower()},
                               {"display_variant": 26}):
                    self.assertFalse(preflight.valid_panel_inventory(dict(value, **change)))
                for other_variant, other_reference, other_width, other_height in layouts:
                    if other_variant != variant:
                        crossed = dict(value, panel_reference=other_reference,
                                       width=other_width, height=other_height)
                        self.assertFalse(preflight.valid_panel_inventory(crossed))

    def test_cli_defaults_and_argument_errors_only_emit_closed_json(self):
        for args, expected in (([], 1), (["--PRIVATE_PASSWORD=" + "SECRET"], 2),
                               (["--live", "--utc-reference", "PRIVATE_VALUE"], 2),
                               (["--live", "--panel-inventory", "PRIVATE_PATH"], 2),
                               (["--live", "--panel-inventory", "/etc/shadow"], 2),
                               (["--panel-inventory", "/etc/inkyos-panel.json"], 1)):
            result = subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, expected)
            self.assertEqual(result.stderr, "")
            self.assertEqual(len(result.stdout.splitlines()), 1)
            value = json.loads(result.stdout)
            self.assertFalse(value["passed"])
            self.assertFalse(value["activation_authorized"])
            self.assertNotIn("PRIVATE_", result.stdout)
            self.assertNotIn("/etc/shadow", result.stdout)


class FilesystemLiveAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o755)
        fixture = Path(__file__).resolve().parent / "fixtures/application-manifest-758a2bf7.json"
        self.manifest = fixture.read_bytes()
        self.hash = hashlib.sha256(self.manifest).hexdigest()
        self.assertEqual(self.hash, preflight.MANIFEST_HASH)
        self.marker = {"schema_version": 1, "kind": "test-lan-prepared", "state": "prepared-inactive",
                       "application_runtime": "masked", "activation_authorized": False,
                       "ready_for_activation": False, "factory_authority": False,
                       "source_commit": preflight.SOURCE, "manifest_sha256": self.hash}
        self.put(preflight.MARKER, json.dumps(self.marker).encode())
        self.put(preflight.MANIFEST, self.manifest)
        self.put(preflight.SOURCE_FILE, (preflight.SOURCE + "\n").encode())
        self.put("etc/passwd", b"inky:x:1000:1000:app:/home/inky:/usr/sbin/nologin\ninky-network:x:990:991:helper:/nonexistent:/usr/sbin/nologin\n")
        self.put("etc/group", b"inky:x:1000:\nspi:x:997:inky\ni2c:x:996:inky\ngpio:x:995:inky\ninky-provisioning:x:991:inky\n")
        site = "home/inky/inky-studio/server/.venv/lib/python3.13/site-packages"
        for name in ("inky-2.3.0.dist-info", "spidev-3.8.dist-info", "gpiod-2.3.0.dist-info", "gpiodevice-0.0.8.dist-info", "dbus_fast-2.44.5.dist-info", "cryptography-50.0.1.dist-info", "pillow-12.0.0.dist-info"):
            self.make_directories(self.root / site / name)
        self.make_directories(self.root / "dev")
        self.panel = self.put(preflight.PANEL_INVENTORY, json.dumps(panel_inventory()).encode())
        self.panel.chmod(0o600)
        self.calls = []
        self.store = preflight.ReadStore(self.root, owner_uid=os.getuid(), app_uid=os.getuid())
        self.addCleanup(self.store.close)
        self.adapter = preflight.LiveAdapter(store=self.store, command=self.command, utc=lambda: REFERENCE + 10, monotonic=lambda: 0)
        self.inputs = {"live": True, "operator_access_confirmed": True, "country": "FR", "country_confirmed": True,
                       "utc_reference": REFERENCE, "utc_reference_age": 10,
                       "utc_reference_source": "independent-device", "panel_inventory": str(self.panel)}

    def make_directories(self, path):
        # Path.mkdir(parents=True) uses 0777 for missing ancestors. Make every
        # new fixture component explicitly 0755 under both umask 0002 and 0022;
        # preserve existing modes so unsafe-parent tests remain meaningful.
        current = self.root
        for part in path.relative_to(self.root).parts:
            current /= part
            try:
                current.mkdir(mode=0o755)
            except FileExistsError:
                pass
            else:
                current.chmod(0o755)

    def put(self, path, content):
        item = self.root / path
        self.make_directories(item.parent)
        item.write_bytes(content)
        item.chmod(0o644)
        return item

    def command(self, argv, *, timeout, limit):
        self.assertIn(argv, preflight.COMMANDS.values())
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 2)
        self.assertEqual(limit, preflight.MAX_OUTPUT)
        key = next(key for key, value in preflight.COMMANDS.items() if value == argv)
        self.calls.append(key)
        outputs = {
            "firstboot": "ActiveState=active\nSubState=exited\nLoadState=loaded\nResult=success\nExecMainStatus=0\n",
            "app": "ActiveState=inactive\nSubState=dead\nLoadState=masked\nUnitFileState=masked\n",
            "helper": "ActiveState=inactive\nSubState=dead\nLoadState=masked\nUnitFileState=masked\n",
            "nm_service": "ActiveState=active\nSubState=running\nLoadState=loaded\n",
            "nm": "100 (connected)\nyes\n", "iw_interface": "Interface wlan0\n\taddr PRIVATE_MAC\n\tssid PRIVATE_SSID\n\twiphy 0\n",
            "iw_reg": "global\ncountry FR: DFS-ETSI\nphy#0 (self-managed)\ncountry FR: DFS-ETSI\n",
            "utc_sync": "v b true\n", "bluez": "ActiveState=active\nSubState=running\nLoadState=loaded\n",
            "powered": "v b true\n", "rfkill": "wlan unblocked unblocked\nbluetooth unblocked unblocked\n",
            "packages": "installed\n" * 7,
        }
        return outputs[key]

    def test_prepared_fixture_uses_readonly_argv_and_stays_blocked_for_real_panel_evidence(self):
        value = preflight.preflight(self.adapter, **self.inputs)
        self.assertTrue(value["checks"]["prepared_profile"]["passed"])
        self.assertTrue(value["checks"]["exact_payload_pin"]["passed"])
        for key in ("firstboot_success", "app_stopped_and_masked", "helper_stopped_and_masked", "country_global_matches", "country_phy_matches", "utc_synchronized", "utc_matches_independent_reference", "hci0_powered", "bluetooth_unblocked", "service_accounts_and_groups", "application_hardware_metadata_present", "panel_inventory_supplied_and_valid"):
            self.assertTrue(value["checks"][key]["passed"], key)
        self.assertFalse(value["checks"]["panel_runtime_evidence_verified"]["passed"])
        self.assertEqual(value["checks"]["panel_runtime_evidence_verified"]["status"], "BLOCKED")
        self.assertFalse(value["passed"])
        self.assertNotIn("PRIVATE_", json.dumps(value))
        self.assertEqual(set(self.calls), set(preflight.COMMANDS))

    def test_missing_unsafe_marker_or_wrong_pin_stops_all_commands(self):
        marker = self.root / preflight.MARKER
        original = marker.read_bytes()
        marker.unlink()
        value = preflight.preflight(self.adapter, **self.inputs)
        self.assertFalse(value["checks"]["prepared_profile"]["passed"])
        self.assertEqual(self.calls, [])
        marker.symlink_to(self.panel)
        self.assertFalse(preflight.preflight(self.adapter, **self.inputs)["passed"])
        self.assertEqual(self.calls, [])
        marker.unlink()
        marker.write_bytes(original)
        self.put(preflight.SOURCE_FILE, b"PRIVATE_UNREVIEWED_SOURCE")
        value = preflight.preflight(self.adapter, **self.inputs)
        self.assertFalse(value["checks"]["exact_payload_pin"]["passed"])
        self.assertEqual(self.calls, [])

    def test_both_exact_pins_pass_and_crossed_unknown_or_source_declaration_mismatches_block(self):
        cases = (("6a697d134290ced0214fc74b903f4b3c336d70fa", "application-manifest-6a697d1.json"),
                 ("758a2bf7ed099aad41ef35316e53228e797b0b2b", "application-manifest-758a2bf7.json"))
        for source, filename in cases:
            with self.subTest(source=source):
                raw = (Path(__file__).resolve().parent / "fixtures" / filename).read_bytes()
                digest = hashlib.sha256(raw).hexdigest()
                self.assertEqual(digest, preflight.REVIEWED_APPLICATIONS[source])
                marker = dict(self.marker, source_commit=source, manifest_sha256=digest)
                self.put(preflight.MARKER, json.dumps(marker).encode())
                self.put(preflight.MANIFEST, raw)
                self.put(preflight.SOURCE_FILE, (source + "\n").encode())
                self.assertTrue(preflight.preflight(self.adapter, **self.inputs)["checks"]["exact_payload_pin"]["passed"])
                other = next(value for value in preflight.REVIEWED_APPLICATIONS if value != source)
                changes = (
                    (dict(marker, manifest_sha256=preflight.REVIEWED_APPLICATIONS[other]), (source + "\n").encode(), raw),
                    (dict(marker, source_commit=other), (source + "\n").encode(), raw),
                    (dict(marker, source_commit="f" * 40), b"f" * 40 + b"\n", raw),
                    (marker, (other + "\n").encode(), raw),
                    (marker, (source + "\n").encode(), raw + b"\n"),
                )
                for bad_marker, declaration, manifest in changes:
                    self.put(preflight.MARKER, json.dumps(bad_marker).encode())
                    self.put(preflight.SOURCE_FILE, declaration)
                    self.put(preflight.MANIFEST, manifest)
                    self.calls.clear()
                    value = preflight.preflight(self.adapter, **self.inputs)
                    self.assertFalse(value["checks"]["exact_payload_pin"]["passed"])
                    self.assertEqual(self.calls, [])

    def test_prepared_data_755_with_only_empty_photos_755_is_virgin_extra_db_or_photo_blocks(self):
        data = self.root / "var/lib/inky-studio"
        photos = data / "photos"
        self.make_directories(photos)
        data.chmod(0o755)
        photos.chmod(0o755)
        self.assertTrue(self.store.application_state_virgin(os.getuid()))
        self.assertFalse(self.store.application_state_virgin(os.getuid() + 1))
        database = data / "inky_studio.db"
        database.write_text("PRIVATE_DATABASE_ID")
        original = os.open
        def guarded(path, *args, **kwargs):
            if str(path) in {"inky_studio.db", str(database)}:
                raise AssertionError("Database content must never be opened")
            return original(path, *args, **kwargs)
        with mock.patch.object(preflight.os, "open", side_effect=guarded):
            self.assertFalse(self.store.application_state_virgin(os.getuid()))
        database.unlink()
        (photos / "PRIVATE_PHOTO.png").write_bytes(b"PRIVATE_PHOTO_CONTENT")
        self.assertFalse(self.store.application_state_virgin(os.getuid()))
        (photos / "PRIVATE_PHOTO.png").unlink()
        photos.chmod(0o700)
        self.assertFalse(self.store.application_state_virgin(os.getuid()))

    def test_readstore_refuses_hardlinks_symlinks_specials_and_writable_parents(self):
        item = self.root / preflight.MANIFEST
        before = item.read_bytes()
        outside = self.root / "PRIVATE_OUTSIDE"
        outside.write_bytes(before)
        for kind in ("symlink", "hardlink", "fifo"):
            item.unlink()
            if kind == "symlink":
                item.symlink_to(outside)
            elif kind == "hardlink":
                os.link(outside, item)
            else:
                os.mkfifo(item)
            self.assertFalse(preflight.preflight(self.adapter, **self.inputs)["checks"]["exact_payload_pin"]["passed"])
            item.unlink()
            item.write_bytes(before)
        item.parent.chmod(0o777)
        self.assertFalse(preflight.preflight(self.adapter, **self.inputs)["checks"]["exact_payload_pin"]["passed"])

    def test_existing_application_state_is_only_listed_never_opened_and_requires_review(self):
        directory = self.root / "var/lib/inky-studio"
        self.make_directories(directory)
        directory.chmod(0o700)
        credential = directory / "credentials.json"
        credential.write_text("PRIVATE_PASSWORD PRIVATE_KEY PRIVATE_ID")
        original = os.open
        def guarded(path, *args, **kwargs):
            if str(path) in {"credentials.json", str(credential)}:
                raise AssertionError("App credentials must never be opened")
            return original(path, *args, **kwargs)
        with mock.patch.object(preflight.os, "open", side_effect=guarded):
            value = preflight.preflight(self.adapter, **self.inputs)
        self.assertFalse(value["checks"]["application_state_virgin"]["passed"])
        self.assertEqual(value["checks"]["application_state_virgin"]["reason"], "existing_or_unsafe_state_requires_explicit_review")
        self.assertEqual(credential.read_text(), "PRIVATE_PASSWORD PRIVATE_KEY PRIVATE_ID")
        self.assertNotIn("PRIVATE_", json.dumps(value))

    def test_utc_requires_synchronized_flag_current_reference_and_independent_source(self):
        for now in (REFERENCE - 200, REFERENCE + 200, float("nan"), float("inf")):
            self.adapter.utc = lambda: now
            value = preflight.preflight(self.adapter, **self.inputs)
            self.assertFalse(value["checks"]["utc_matches_independent_reference"]["passed"])
        self.adapter.utc = lambda: REFERENCE + 10
        original = self.command
        self.adapter.command = lambda argv, **kwargs: "v b false\n" if argv == preflight.COMMANDS["utc_sync"] else original(argv, **kwargs)
        self.assertFalse(preflight.preflight(self.adapter, **self.inputs)["checks"]["utc_synchronized"]["passed"])

    def test_helper_extra_privilege_group_and_hardware_node_metadata_are_checked(self):
        group = self.root / "etc/group"
        original_group = group.read_bytes()
        group.write_bytes(original_group + b"sudo:x:27:inky-network\n")
        value = preflight.preflight(self.adapter, **self.inputs)
        self.assertFalse(value["checks"]["service_accounts_and_groups"]["passed"])
        group.write_bytes(original_group)
        original = os.stat
        node_groups = {"spidev0.0": 997, "i2c-1": 996, "gpiochip0": 995}
        for mode, valid in ((stat.S_IFCHR | 0o660, True), (stat.S_IFCHR | 0o666, False),
                            (stat.S_IFLNK | 0o660, False)):
            def metadata(path, *args, **kwargs):
                if path in node_groups:
                    return SimpleNamespace(st_mode=mode, st_uid=os.getuid(), st_gid=node_groups[path])
                return original(path, *args, **kwargs)
            with mock.patch.object(preflight.os, "stat", side_effect=metadata):
                value = preflight.preflight(self.adapter, **self.inputs)
            self.assertEqual(value["checks"]["spi_i2c_gpio_nodes"]["passed"], valid)

    def test_reference_becoming_stale_during_collection_and_global_budget_expiry_block(self):
        count = 0
        def monotonic():
            nonlocal count
            count += 1
            return 0 if count == 1 else 19
        self.adapter.monotonic = monotonic
        self.inputs["utc_reference_age"] = 50
        value = preflight.preflight(self.adapter, **self.inputs)
        self.assertFalse(value["checks"]["independent_reference_recent"]["passed"])
        self.adapter.monotonic = mock.Mock(side_effect=[0] + [21] * 30)
        self.calls.clear()
        value = preflight.preflight(self.adapter, **self.inputs)
        self.assertEqual(self.calls, [])
        self.assertFalse(value["checks"]["firstboot_success"]["passed"])

    def test_failures_and_oversized_command_outputs_are_closed_and_bluez_not_autostarted(self):
        original = self.command
        for bad in (None, "PRIVATE_PASSWORD" * 2000, "ActiveState=active\nActiveState=active\n"):
            self.adapter.command = lambda _argv, **_kwargs: bad
            value = preflight.preflight(self.adapter, **self.inputs)
            self.assertFalse(value["passed"])
            self.assertNotIn("PRIVATE_PASSWORD", json.dumps(value))
        self.adapter.command = lambda argv, **kwargs: "ActiveState=inactive\nSubState=dead\nLoadState=loaded\n" if argv == preflight.COMMANDS["bluez"] else original(argv, **kwargs)
        self.calls.clear()
        value = preflight.preflight(self.adapter, **self.inputs)
        self.assertFalse(value["checks"]["hci0_powered"]["passed"])
        self.assertNotIn("powered", self.calls)
        self.assertIn("--auto-start=no", preflight.COMMANDS["powered"])
        self.assertIn("--auto-start=no", preflight.COMMANDS["utc_sync"])
        for name in ("powered", "utc_sync"):
            self.assertIn("call", preflight.COMMANDS[name])
            self.assertNotIn("get-property", preflight.COMMANDS[name])
            self.assertIn("--allow-interactive-authorization=no", preflight.COMMANDS[name])
        self.adapter.command = lambda argv, **kwargs: "ActiveState=inactive\nSubState=dead\nLoadState=loaded\n" if argv == preflight.COMMANDS["nm_service"] else original(argv, **kwargs)
        self.calls.clear()
        value = preflight.preflight(self.adapter, **self.inputs)
        self.assertFalse(value["checks"]["networkmanager_manages_connected_wlan0"]["passed"])
        self.assertNotIn("nm", self.calls)

    def test_panel_file_symlink_duplicate_json_and_untrusted_assertion_never_verify_hardware(self):
        for raw in ('{"schema_version":1,"schema_version":1}', json.dumps(panel_inventory())[:-1] + ',"runtime_verified":true}'):
            self.panel.write_text(raw)
            value = preflight.preflight(self.adapter, **self.inputs)
            self.assertFalse(value["checks"]["panel_inventory_supplied_and_valid"]["passed"])
            self.assertFalse(value["checks"]["panel_runtime_evidence_verified"]["passed"])
        self.panel.unlink()
        self.panel.symlink_to(self.root / preflight.MARKER)
        value = preflight.preflight(self.adapter, **self.inputs)
        self.assertFalse(value["checks"]["panel_inventory_supplied_and_valid"]["passed"])

    def test_panel_inventory_parent_symlink_and_mutation_during_read_are_refused(self):
        link = self.root / "etc"
        actual = self.root / "actual-panel-directory"
        link.rename(actual)
        link.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(OSError):
            self.store.read_external(str(self.panel))
        link.unlink()
        actual.rename(link)
        original = os.read
        modified = False
        def mutate(fd, count):
            nonlocal modified
            raw = original(fd, count)
            if not modified:
                modified = True
                with self.panel.open("ab") as stream:
                    stream.write(b" ")
            return raw
        with mock.patch.object(preflight.os, "read", side_effect=mutate):
            with self.assertRaises(preflight.UnsafeInput):
                self.store.read_external(str(self.panel))

    def test_panel_inventory_other_paths_are_refused_before_any_file_open(self):
        # No secret file is created or read: the spy rejects every open and the
        # path allowlist must stop these inputs before filesystem traversal.
        paths = (self.root / "etc/shadow", self.root / "var/lib/inky-studio/credentials.json",
                 self.root / "etc/other-panel.json", self.root / "etc/../etc/inkyos-panel.json")
        with mock.patch.object(preflight.os, "open", side_effect=AssertionError("No arbitrary opens")) as opened:
            for path in paths:
                with self.subTest(path=path.name), self.assertRaises(preflight.UnsafeInput):
                    self.store.read_external(str(path))
            with self.assertRaises(preflight.UnsafeInput):
                self.store.read_external("/etc/inkyos-panel.json\x00PRIVATE_SECRET")
        opened.assert_not_called()

    def test_fixed_panel_inventory_refuses_hardlink_fifo_wrong_owner_and_writable_mode(self):
        original = os.fstat
        def wrong_owner(fd):
            info = original(fd)
            if stat.S_ISREG(info.st_mode):
                return SimpleNamespace(st_mode=info.st_mode, st_uid=os.getuid() + 1, st_nlink=info.st_nlink)
            return info
        with mock.patch.object(preflight.os, "fstat", side_effect=wrong_owner):
            with self.assertRaises(preflight.UnsafeInput):
                self.store.read_external(str(self.panel))
        self.panel.chmod(0o666)
        with self.assertRaises(preflight.UnsafeInput):
            self.store.read_external(str(self.panel))
        self.panel.chmod(0o600)
        os.link(self.panel, self.root / "linked-panel.json")
        with self.assertRaises(preflight.UnsafeInput):
            self.store.read_external(str(self.panel))
        self.panel.unlink()
        os.mkfifo(self.panel)
        with self.assertRaises(preflight.UnsafeInput):
            self.store.read_external(str(self.panel))


class BoundedCommandTests(unittest.TestCase):
    def test_real_timeout_output_bound_and_failure_hide_outputs(self):
        started = time.monotonic()
        result = preflight.bounded_command((sys.executable, "-c", "import time; print('PRIVATE_SECRET', flush=True); time.sleep(5)"), timeout=0.05, limit=128)
        self.assertIsNone(result)
        self.assertLess(time.monotonic() - started, 2)
        self.assertIsNone(preflight.bounded_command((sys.executable, "-c", "print('PRIVATE_SECRET' * 1000)"), timeout=2, limit=128))
        self.assertIsNone(preflight.bounded_command((sys.executable, "-c", "import sys; sys.stderr.write('PRIVATE_SECRET'); sys.exit(1)"), timeout=2, limit=128))


if __name__ == "__main__":
    unittest.main()
