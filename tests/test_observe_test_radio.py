"""Synthetic firmware/sysfs/rootfs fixtures only; never invoke iw or a radio."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/observe-test-radio.py"
def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
observer = load(SCRIPT, "inkyos_test_radio_observer")
preflight = load(ROOT / "scripts/test-lan-preflight.py", "inkyos_test_radio_preflight")


def nla(kind, payload, padding=None):
    raw = struct.pack("<HH", len(payload) + 4, kind) + payload
    count = (-len(raw)) % 4
    return raw + (bytes(count) if padding is None else padding)


def frame(abbrev=b"FR\0\0", ccode=b"FR\0\0", revision=0, tail=b"PRIVATE!"):
    data = struct.pack("<4si4s", abbrev, revision, ccode) + tail
    return nla(2, data) + nla(1, struct.pack("<H", 20))


def regulatory(global_country="FR", phy="99", index=0):
    return (f"global\ncountry {global_country}: DFS-ETSI\n"
            "\t(2400 - 2483 @ 40), (N/A, 20), (N/A)\n\n"
            f"phy#{index} (custom)\ncountry {phy}: DFS-UNSET\n"
            "\t(2402 - 2482 @ 40), (6, 20), (N/A)\n").encode()


def channels(index=0):
    return (f"Wiphy phy{index}\n\tPRIVATE_TEXT_IGNORED\n\tBand 1:\n\t\tFrequencies:\n"
            "\t\t\t* 2412 MHz [1] (20.0 dBm)\n"
            "\t\t\t* 2467 MHz [12] (18.5 dBm) (no IR, radar detection)\n"
            "\t\t\t* 2472 MHz [13] (disabled)\n"
            "\t\t\t* 2484 MHz [14] (disabled)\n"
            "\tBand 2:\n\t\t\t* 5180 MHz [36] (20.0 dBm)\n").encode()


def sample(index=0, **overrides):
    value = {"wiphy_index": index, "firmware": frame(), "regulatory": regulatory(index=index),
             "channels": channels(index=index)}
    value.update(overrides)
    return value


class FixtureGuard:
    def __init__(self, facts=None):
        self.facts = {key: True for key in observer.GUARD_CHECKS} if facts is None else facts
        self.calls = 0
    def collect(self):
        self.calls += 1
        return self.facts


class FixtureAdapter:
    def __init__(self, value=None):
        self.value = sample() if value is None else value
        self.calls = 0
    def sample(self):
        self.calls += 1
        return self.value


class FirmwareParserTests(unittest.TestCase):
    def test_exact_nla_frame_decodes_only_country_tuple_and_discards_tail(self):
        self.assertEqual(observer.parse_country(frame()), {"country_abbrev": "FR", "ccode": "FR", "revision": 0})
        self.assertNotIn("PRIVATE", json.dumps(observer.parse_country(frame())))
        reordered = nla(1, struct.pack("<H", 20)) + nla(2, struct.pack("<4si4s", b"FR\0\0", 14, b"Q2\0\0") + bytes(8))
        self.assertEqual(observer.parse_country(reordered), {"country_abbrev": "FR", "ccode": "Q2", "revision": 14})
        for revision in (-1, 65535):
            self.assertEqual(observer.parse_country(frame(revision=revision))["revision"], revision)
        self.assertEqual(observer.parse_country(frame(abbrev=b"00\0\0", ccode=b"X2\0\0"))["country_abbrev"], "00")

    def test_truncation_padding_duplicate_unknown_flags_lengths_and_bare_struct_are_rejected(self):
        data = struct.pack("<4si4s", b"FR\0\0", 0, b"FR\0\0") + bytes(8)
        invalid = [b"", bytearray(frame()), "PRIVATE", data[:12], frame() + b"\0", frame() + nla(1, b"\x14\0"),
                   nla(2, data) + nla(1, b"\x14\0", padding=b"\0\1"),
                   nla(2, data) + nla(1, b"\x13\0"), nla(2, data) + nla(1, b"\x14\0\0"),
                   nla(2, data[:-1]) + nla(1, b"\x14\0"), nla(2, data + b"x") + nla(1, b"\x14\0"),
                   nla(2, data), nla(1, b"\x14\0"), frame() + nla(3, b"PRIVATE"),
                   nla(0x8002, data) + nla(1, b"\x14\0"), struct.pack("<HH", 3, 2) + frame(),
                   frame(revision=-2), frame(revision=65536), frame(abbrev=b"fr\0\0"),
                   frame(abbrev=b"FR\0x"), frame(abbrev=b"F\0\0\0"), frame(ccode=b"\xffR\0\0"),
                   frame(ccode=b"FRX\0")]
        invalid.extend(frame()[:size] for size in range(1, len(frame())))
        for raw in invalid:
            with self.subTest(kind=type(raw).__name__, length=len(raw)), self.assertRaises(observer.ObservationError):
                observer.parse_country(raw)


class KernelParserTests(unittest.TestCase):
    def test_phy_99_and_98_are_preserved_separately_from_global_country(self):
        for phy in ("99", "98", "FR", "US"):
            value = observer.parse_regulatory(regulatory(phy=phy), 0)
            self.assertEqual(value, {"global_country": "FR", "phy_country_label": phy,
                                    "phy_custom": True, "phy_self_managed": False})
        raw = regulatory(index=3) + b"\nphy#4 (self-managed)\ncountry US: DFS-FCC\n"
        self.assertEqual(observer.parse_regulatory(raw, 3)["phy_country_label"], "99")

    def test_regulatory_missing_duplicate_unknown_section_and_invalid_country_are_rejected(self):
        for raw in (regulatory().replace(b"global", b"other", 1), regulatory().replace(b"phy#0", b"phy#1"),
                    regulatory() + regulatory(), regulatory().replace(b"FR:", b"fr:"),
                    regulatory().replace(b"phy#0", b"phy#00"), regulatory().replace(b"phy#0", b"phy#256"),
                    regulatory().replace(b"(custom)", b"(PRIVATE)"),
                    regulatory().replace(b"country FR:", b"country FR: DFS-ETSI\ncountry US:"),
                    b"\xff", b"x" * 16385):
            with self.subTest(raw=raw[:20]), self.assertRaises(observer.ObservationError):
                observer.parse_regulatory(raw, 0)

    def test_channels_extract_only_bounded_24ghz_observations_without_country_inference(self):
        value = observer.parse_channels(channels(), 0)
        self.assertEqual([item["channel"] for item in value], [1, 12, 13, 14])
        self.assertEqual(value[0], {"frequency_mhz": 2412, "channel": 1, "disabled": False,
                                   "max_tx_power_mbm": 2000, "flags": []})
        self.assertEqual(value[1]["max_tx_power_mbm"], 1850)
        self.assertEqual(value[1]["flags"], ["no IR", "radar detection"])
        self.assertIsNone(value[-1]["max_tx_power_mbm"])
        self.assertNotIn("PRIVATE", json.dumps(value))
        # 30 dBm is reported faithfully; the observer does not certify these
        # channel observations as FR rules merely because global says FR.
        self.assertEqual(observer.parse_channels(channels().replace(b"20.0", b"30.0"), 0)[0]["max_tx_power_mbm"], 3000)

    def test_malformed_missing_duplicate_frequency_channel_power_flags_and_wiphy_are_rejected(self):
        invalid = [channels().replace(b"phy0", b"phy1"), b"Wiphy phy0\n", channels() + b"Wiphy phy0\n",
                   channels() + b"\t* 2412 MHz [1] (20.0 dBm)\n", channels().replace(b"2412 MHz", b"2413 MHz"),
                   channels().replace(b"[1]", b"[15]"), channels().replace(b"20.0", b"40.1"),
                   channels().replace(b"no IR, radar detection", b"no IR, PRIVATE"),
                   channels().replace(b"no IR, radar detection", b"no IR, no IR"),
                   channels().replace(b"20.0 dBm", b"N/A"), channels().replace(b"2412 MHz", b"2412.5 MHz"),
                   b"Wiphy phy0\n\t* 2412 MHz [1] (disabled) (no IR)\n",
                   b"Wiphy phy0\n\t* 2412 MHz [1] (disabled)\n"]
        for raw in invalid:
            with self.subTest(raw=raw[:40]), self.assertRaises(observer.ObservationError):
                observer.parse_channels(raw, 0)

    def test_iw_zero_khz_offset_and_absent_offset_preserve_exact_observations(self):
        # iw 6.9-1 info.c:409-415 emits %d.%d for present OFFSET=0,
        # including disabled rows; absent OFFSET emits only %d.
        zero_offset = (b"Wiphy phy0\n"
            b"\t\t\t* 2412.0 MHz [1] (20.0 dBm)\n"
            b"\t\t\t* 2467.0 MHz [12] (18.5 dBm) (no IR, radar detection)\n"
            b"\t\t\t* 2472.0 MHz [13] (disabled)\n"
            b"\t\t\t* 2484.0 MHz [14] (disabled)\n"
            b"\t\t\t* 5180.0 MHz [36] (20.0 dBm)\n")
        self.assertEqual(observer.parse_channels(zero_offset, 0), observer.parse_channels(channels(), 0))
        self.assertEqual(observer.frequency_mhz("0.0"), 0)
        self.assertEqual(observer.frequency_mhz("4294967295.0"), 4294967295)

    def test_iw_ht_capability_prose_is_not_a_frequency_row(self):
        # iw 6.9-1 info.c prints these entries under HT Capability overrides.
        raw = (b"Wiphy phy0\n\tFrequencies:\n"
               b"\t\t\t* 2412.0 MHz [1] (20.0 dBm)\n"
               b"\tHT Capability overrides:\n"
               b"\t\t * short GI for 20 MHz\n\t\t * short GI for 40 MHz\n")
        result = observer.parse_channels(raw, 0)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["frequency_mhz"], 2412)

    def test_nonzero_khz_offset_noncanonical_tokens_and_mixed_duplicates_are_rejected(self):
        invalid = ("2412.1", "2412.5", "2412.100", "2412.00", "2412.", "2412.0.0",
                   "+2412", "-2412", "2412e0", "2.412e3", "02412", " 2412", "2412 ",
                   "4294967296", "9" * 5000, "٢٤١٢", "NaN", "", None, 2412.0)
        for token in invalid:
            with self.subTest(token_type=type(token).__name__), self.assertRaises(observer.ObservationError):
                observer.frequency_mhz(token)
            if type(token) is str:
                # A malformed row must not disappear behind other valid rows.
                raw = channels() + ("\t* " + token + " MHz [1] (20.0 dBm)\n").encode()
                with self.assertRaises(observer.ObservationError):
                    observer.parse_channels(raw, 0)
        for row in (b"\t* 2412.0 MHz [1] (20.0 dBm)\n", b"\t* 2412.0MHz [1] (20.0 dBm)\n"):
            with self.assertRaises(observer.ObservationError):
                observer.parse_channels(channels() + row, 0)


class ObserverTests(unittest.TestCase):
    def test_default_and_missing_country_never_touch_host_or_adapters(self):
        for kwargs in ({}, {"country": "FR"}, {"live": True}, {"live": True, "country": "fr"}):
            guard, adapter = FixtureGuard(), FixtureAdapter()
            with mock.patch.object(observer.os, "open", side_effect=AssertionError("No host files")), \
                    mock.patch.object(observer.subprocess, "Popen", side_effect=AssertionError("No commands")):
                value = observer.observe(adapter, guard, **kwargs)
            self.assertEqual((guard.calls, adapter.calls), (0, 0))
            self.assertFalse(value["observations_complete"])
            self.assertFalse(value["passed"])

    def test_complete_fixture_never_claims_live_or_tuple_qualification_or_gate_pass(self):
        output = observer.observe(FixtureAdapter(), FixtureGuard(), live=True, country="FR")
        self.assertTrue(output["observations_complete"])
        self.assertEqual(output["observation_source"], "fixture")
        self.assertEqual(output["kernel"]["phy_country_label"], "99")
        self.assertTrue(output["checks"]["firmware_country_matches"]["passed"])
        for key in ("passed", "live_evidence", "firmware_tuple_qualified", "activation_authorized", "hardware_qualified", "release_qualified"):
            self.assertFalse(output[key])
        self.assertFalse(output["checks"]["firmware_tuple_qualified"]["passed"])
        self.assertEqual(output["status"], "BLOCKED")
        self.assertNotIn("PRIVATE", json.dumps(output))

    def test_country_mismatch_and_unqualified_ccode_are_independent_observations(self):
        for observed, ccode, expected in ((b"US\0\0", b"US\0\0", False), (b"FR\0\0", b"Q2\0\0", True)):
            output = observer.observe(FixtureAdapter(sample(firmware=frame(abbrev=observed, ccode=ccode))),
                                      FixtureGuard(), live=True, country="FR")
            self.assertTrue(output["observations_complete"])
            self.assertEqual(output["checks"]["firmware_country_matches"]["passed"], expected)
            self.assertTrue(output["checks"]["kernel_global_country_matches"]["passed"])
            self.assertFalse(output["firmware_tuple_qualified"])

    def test_all_guard_failures_and_nonbooleans_prevent_radio_adapter(self):
        for key in observer.GUARD_CHECKS:
            for invalid in (False, 1, "yes", {"PRIVATE": True}):
                facts = {name: True for name in observer.GUARD_CHECKS}
                facts[key] = invalid
                adapter = FixtureAdapter()
                output = observer.observe(adapter, FixtureGuard(facts), live=True, country="FR")
                self.assertEqual(adapter.calls, 0)
                self.assertFalse(output["checks"][key]["passed"])
                self.assertNotIn("PRIVATE", json.dumps(output))

    def test_closed_errors_never_export_command_bytes_paths_or_exception_details(self):
        class Broken:
            def sample(self):
                raise OSError("PRIVATE_SECRET /PRIVATE_PATH")
        for adapter, expected in ((Broken(), "observation_unavailable"),
                                  (FixtureAdapter(sample(firmware=b"PRIVATE_SECRET")), "firmware_response_invalid"),
                                  (FixtureAdapter(sample(wiphy_index=True)), "wlan0_mapping_unverified")):
            value = observer.observe(adapter, FixtureGuard(), live=True, country="FR")
            self.assertEqual(value["error"], expected)
            self.assertNotIn("PRIVATE", json.dumps(value))

    def test_cli_inert_and_disallowed_arguments_have_closed_json_and_no_default_country(self):
        for args, code in (([], 1), (["--country", "FR"], 1), (["--live"], 2),
                           (["--live", "--country", "fr"], 2), (["--liv", "--country", "FR"], 2),
                           (["--payload", "PRIVATE"], 2), (["--vendor", "PRIVATE"], 2),
                           (["--rootfs", "PRIVATE"], 2), (["--country", "FR; id"], 2)):
            value = subprocess.run([sys.executable, "-I", str(SCRIPT), *args], capture_output=True, text=True, timeout=3)
            self.assertEqual(value.returncode, code)
            self.assertEqual(value.stderr, "")
            self.assertEqual(len(value.stdout.splitlines()), 1)
            output = json.loads(value.stdout)
            self.assertFalse(output["passed"])
            self.assertEqual(output["observation_source"], "inactive")
            self.assertNotIn("PRIVATE", value.stdout)

    def test_live_requires_linux_root_before_native_adapter_use(self):
        with mock.patch.object(observer.sys, "platform", "linux"), mock.patch.object(observer.os, "geteuid", return_value=1000), \
                mock.patch.object(observer.os, "open", side_effect=AssertionError("No host files")), \
                mock.patch.object(observer.subprocess, "Popen", side_effect=AssertionError("No commands")), \
                mock.patch("builtins.print") as printed:
            self.assertEqual(observer.main(["--live", "--country", "FR"]), 1)
        output = json.loads(printed.call_args.args[0])
        self.assertEqual(output["error"], "linux_root_required")
        self.assertFalse(output["live_evidence"])


class AdapterTests(unittest.TestCase):
    def test_only_exact_get_payload_and_readonly_iw_commands_are_sent_and_fixture_cannot_claim_live(self):
        calls = []
        mapping = mock.Mock()
        mapping.sample.return_value = 3
        def command(argv, *, data, timeout, limit):
            calls.append((argv, data))
            self.assertEqual((timeout, limit), (2.0, 16384))
            if argv == observer.INTERFACE_COMMAND:
                return b"Interface wlan0\n\taddr PRIVATE_MAC\n\twiphy 3\n"
            if argv == observer.GET_COMMAND:
                return frame()
            if argv == observer.REG_COMMAND:
                return regulatory(index=3)
            self.assertEqual(argv, ("/usr/sbin/iw", "phy", "phy3", "info"))
            return channels(index=3)
        adapter = observer.ProductionAdapter(command=command, mapping=mapping)
        output = observer.observe(adapter, FixtureGuard(), live=True, country="FR")
        self.assertTrue(output["observations_complete"])
        self.assertFalse(output["live_evidence"])
        self.assertEqual([item[0] for item in calls], [observer.INTERFACE_COMMAND, observer.GET_COMMAND,
                                                      observer.REG_COMMAND, ("/usr/sbin/iw", "phy", "phy3", "info")])
        self.assertEqual([item[1] for item in calls], [None, observer.GET_PAYLOAD, None, None])
        self.assertEqual(len(observer.GET_PAYLOAD), 40)
        self.assertEqual(struct.unpack("<IiIII", observer.GET_PAYLOAD[:20]), (262, 20, 20, 0, 0))
        self.assertEqual(observer.GET_PAYLOAD[20:], b"country\0" + bytes(12))
        self.assertEqual(mapping.sample.call_count, 2)
        self.assertNotIn("PRIVATE", json.dumps(output))

    def test_mapping_and_interface_mismatch_prevent_firmware_get(self):
        for index, raw in ((True, b""), (-1, b""), (256, b""), (0, b"Interface wlan0\n\twiphy 1\n"),
                           (0, b"Interface PRIVATE\n\twiphy 0\n"), (0, b"Interface wlan0\n\twiphy 0\n\twiphy 0\n")):
            mapping = mock.Mock()
            mapping.sample.return_value = index
            command = mock.Mock(return_value=raw)
            output = observer.observe(observer.ProductionAdapter(command=command, mapping=mapping),
                                      FixtureGuard(), live=True, country="FR")
            self.assertFalse(output["observations_complete"])
            self.assertLessEqual(command.call_count, 1)
            self.assertNotIn("PRIVATE", json.dumps(output))

    def test_failed_or_oversized_command_blocks_remaining_commands(self):
        for raw in (None, b"", b"x" * 16385, "PRIVATE"):
            command = mock.Mock(return_value=raw)
            mapping = mock.Mock()
            mapping.sample.return_value = 0
            value = observer.observe(observer.ProductionAdapter(command=command, mapping=mapping), FixtureGuard(), live=True, country="FR")
            self.assertFalse(value["observations_complete"])
            self.assertEqual(command.call_count, 1)
            self.assertNotIn("PRIVATE", json.dumps(value))

    def test_bounded_command_bytes_success_failure_overflow_timeout_and_stderr_discard(self):
        # Only local synthetic Python child processes, no iw/device commands.
        run = lambda program, **kw: observer.bounded_command((sys.executable, "-I", "-c", program), **kw)
        self.assertEqual(run("import sys; sys.stdout.buffer.write(sys.stdin.buffer.read()); sys.stderr.write('PRIVATE')", data=b"fixture"), b"fixture")
        self.assertIsNone(run("raise SystemExit(1)"))
        self.assertIsNone(run("import sys; sys.stdout.buffer.write(b'x'*33)", limit=32))
        start = time.monotonic()
        self.assertIsNone(run("import time; time.sleep(5)", timeout=0.05))
        self.assertLess(time.monotonic() - start, 1)


class FakeSysfs:
    """FD simulator; no /sys entry or host device is ever opened."""
    def __init__(self):
        self.device = "devices/platform/mock/mmc1/mmc1:0001:1"
        self.net = self.device + "/net/wlan0"
        self.phy = self.device + "/ieee80211/phy0"
        self.links = {"class/net/wlan0": "../../" + self.net,
                      self.net + "/device": "../..", self.device + "/driver": "/sys/bus/sdio/drivers/brcmfmac",
                      self.net + "/phy80211": "../../ieee80211/phy0",
                      "class/ieee80211/phy0": "../../" + self.phy}
        self.directories = {""}
        for path in list(self.links) + [self.phy + "/index"]:
            for parent in Path(path).parents:
                self.directories.add("" if str(parent) == "." else str(parent))
        self.fds, self.counter, self.index, self.calls = {}, 10, b"0\n", []
        self.link_uid, self.directory_uid = 0, 0
    def open(self, path, flags, *, dir_fd=None):
        relative = "" if path == "/sys" and dir_fd is None else "/".join(filter(None, (self.fds[dir_fd], path)))
        self.calls.append(relative)
        if flags & os.O_DIRECTORY:
            if relative not in self.directories:
                raise OSError("not a directory")
        elif relative != self.phy + "/index":
            raise AssertionError("Only the fixed index attribute may be read")
        if not flags & os.O_NOFOLLOW:
            raise AssertionError("All opens must refuse symlinks")
        self.counter += 1
        self.fds[self.counter] = relative
        return self.counter
    def dup(self, fd):
        self.counter += 1
        self.fds[self.counter] = self.fds[fd]
        return self.counter
    def close(self, fd):
        self.fds.pop(fd)
    def fstat(self, fd):
        mode = stat.S_IFDIR | 0o755 if self.fds[fd] in self.directories else stat.S_IFREG | 0o444
        return SimpleNamespace(st_mode=mode, st_uid=self.directory_uid)
    def stat(self, name, *, dir_fd, follow_symlinks):
        self.assert_false(follow_symlinks)
        path = self.fds[dir_fd] + "/" + name
        if path not in self.links:
            raise OSError("not a link")
        return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=self.link_uid, st_dev=1,
                               st_ino=sorted(self.links).index(path), st_mtime_ns=1, st_ctime_ns=1)
    def readlink(self, name, *, dir_fd):
        return self.links[self.fds[dir_fd] + "/" + name]
    def read(self, fd, limit):
        if self.fds[fd] != self.phy + "/index" or limit != 33:
            raise AssertionError("Unexpected sysfs read")
        return self.index
    @staticmethod
    def assert_false(value):
        if value:
            raise AssertionError("No stat traversal")


class SysfsTests(unittest.TestCase):
    def collect(self, tree):
        with mock.patch.multiple(observer.os, open=tree.open, dup=tree.dup, close=tree.close,
                                 fstat=tree.fstat, stat=tree.stat, readlink=tree.readlink, read=tree.read):
            return observer.SysfsMapping().sample()
    def test_exact_fixed_sdio_brcmfmac_wlan0_phy_and_index_mapping(self):
        tree = FakeSysfs()
        self.assertEqual(self.collect(tree), 0)
        self.assertEqual(tree.fds, {})
        self.assertFalse(any("PRIVATE" in item for item in tree.calls))
    def test_wrong_driver_escaped_link_other_phy_owner_and_index_fail_closed(self):
        cases = [lambda t: t.links.__setitem__(t.device + "/driver", "/sys/bus/usb/drivers/brcmfmac"),
                 lambda t: t.links.__setitem__(t.device + "/driver", "/sys/bus/sdio/drivers/PRIVATE"),
                 lambda t: t.links.__setitem__("class/net/wlan0", "/etc/PRIVATE"),
                 lambda t: t.links.__setitem__(t.net + "/device", "/sys/devices/other"),
                 lambda t: t.links.__setitem__(t.net + "/phy80211", "/sys/devices/other/ieee80211/phy0"),
                 lambda t: t.links.__setitem__("class/ieee80211/phy0", "/sys/devices/other/ieee80211/phy0"),
                 lambda t: setattr(t, "link_uid", 1000), lambda t: setattr(t, "directory_uid", 1000),
                 lambda t: setattr(t, "index", b"1\n"), lambda t: setattr(t, "index", b"00\n")]
        for change in cases:
            tree = FakeSysfs()
            change(tree)
            with self.assertRaises((observer.ObservationError, OSError)):
                self.collect(tree)
            self.assertEqual(tree.fds, {})


class GuardTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.root.chmod(0o755)
        candidates = list((ROOT / "tests/fixtures").glob("application-manifest-*.json"))
        self.manifest = next(path.read_bytes() for path in candidates
                             if hashlib.sha256(path.read_bytes()).hexdigest() == preflight.MANIFEST_HASH)
        self.marker = {"schema_version": 1, "kind": "test-lan-prepared", "state": "prepared-inactive",
            "application_runtime": "masked", "activation_authorized": False, "ready_for_activation": False,
            "factory_authority": False, "source_commit": preflight.SOURCE, "manifest_sha256": preflight.MANIFEST_HASH}
        self.put(preflight.MARKER, json.dumps(self.marker).encode())
        self.put(preflight.MANIFEST, self.manifest)
        self.put(preflight.SOURCE_FILE, (preflight.SOURCE + "\n").encode())
        self.store = preflight.ReadStore(self.root, owner_uid=os.getuid(), app_uid=os.getuid())
        self.addCleanup(self.store.close)
        self.calls = []
        self.guard = observer.PreparedGuard(helpers=vars(preflight), store=self.store, command=self.command, monotonic=lambda: 0)
    def put(self, relative, raw):
        path = self.root / relative
        parent = self.root
        for part in path.parent.relative_to(self.root).parts:
            parent /= part
            parent.mkdir(mode=0o755, exist_ok=True)
            parent.chmod(0o755)
        path.write_bytes(raw)
        path.chmod(0o644)
        return path
    def command(self, argv, *, timeout, limit):
        keys = [key for key in ("firstboot", "app", "helper") if argv == preflight.COMMANDS[key]]
        self.assertEqual(len(keys), 1, "Only the three service observations are allowed")
        self.assertEqual((timeout, limit), (2.0, 16384))
        self.calls.append(keys[0])
        return ("ActiveState=active\nSubState=exited\nLoadState=loaded\nResult=success\nExecMainStatus=0\n" if keys[0] == "firstboot" else
                "ActiveState=inactive\nSubState=dead\nLoadState=masked\nUnitFileState=masked\n")
    def test_current_closed_pin_pair_and_prepared_service_guards(self):
        self.assertTrue(all(self.guard.collect().values()))
        self.assertEqual(self.calls, ["firstboot", "app", "helper"])
        self.assertFalse(self.guard.native_live)
    def test_unknown_pin_marker_changed_manifest_or_source_prevents_service_and_radio_queries(self):
        cases = [(preflight.MARKER, dict(self.marker, state="personalized")),
                 (preflight.MARKER, dict(self.marker, source_commit="f" * 40)),
                 (preflight.MARKER, dict(self.marker, activation_authorized=True)),
                 (preflight.MANIFEST, b"PRIVATE"), (preflight.SOURCE_FILE, b"PRIVATE")]
        originals = {path: (self.root / path).read_bytes() for path, _value in cases}
        for path, changed in cases:
            self.calls.clear()
            self.put(path, json.dumps(changed).encode() if type(changed) is dict else changed)
            adapter = FixtureAdapter()
            value = observer.observe(adapter, self.guard, live=True, country="FR")
            self.assertEqual(adapter.calls, 0)
            self.assertEqual(self.calls, [])
            self.assertNotIn("PRIVATE", json.dumps(value))
            self.put(path, originals[path])
    def test_root_marker_symlink_or_writable_parent_is_refused(self):
        marker = self.root / preflight.MARKER
        marker.unlink()
        marker.symlink_to(self.root / preflight.MANIFEST)
        self.assertFalse(self.guard.collect()["prepared_profile"])
        self.assertEqual(self.calls, [])
        marker.unlink()
        self.put(preflight.MARKER, json.dumps(self.marker).encode())
        marker.parent.chmod(0o777)
        self.assertFalse(self.guard.collect()["prepared_profile"])
        self.assertEqual(self.calls, [])
    def test_failed_duplicate_or_active_service_prevents_radio(self):
        for raw in ("ActiveState=active\nSubState=running\nLoadState=loaded\nUnitFileState=enabled\n",
                    "ActiveState=inactive\nActiveState=inactive\nSubState=dead\nLoadState=masked\nUnitFileState=masked\n", None):
            guard = observer.PreparedGuard(helpers=vars(preflight), store=self.store,
                command=lambda *_args, **_kw: raw, monotonic=lambda: 0)
            adapter = FixtureAdapter()
            self.assertFalse(observer.observe(adapter, guard, live=True, country="FR")["observations_complete"])
            self.assertEqual(adapter.calls, 0)
    def test_unsafe_public_helper_never_read_or_executed(self):
        for change in ({"st_uid": 1000}, {"st_mode": stat.S_IFREG | 0o755}, {"st_mode": stat.S_IFREG | 0o777},
                       {"st_nlink": 2}, {"st_size": 65537}, {"st_mode": stat.S_IFLNK | 0o555}):
            info = {"st_mode": stat.S_IFREG | 0o555, "st_uid": 0, "st_nlink": 1, "st_size": 16}
            info.update(change)
            def metadata(fd):
                return SimpleNamespace(**info) if fd == 15 else SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
            with mock.patch.object(observer.os, "open", side_effect=[10, 11, 12, 13, 14, 15]) as opened, \
                    mock.patch.object(observer.os, "fstat", side_effect=metadata), mock.patch.object(observer.os, "close"), \
                    mock.patch.object(observer.os, "read", side_effect=AssertionError("No unsafe source read")) as read:
                with self.assertRaises(observer.ObservationError):
                    observer.load_helpers()
            read.assert_not_called()
            self.assertEqual([call.args[0] for call in opened.call_args_list], ["/", "usr", "local", "lib", "inkyos", "test-lan-preflight.py"])


if __name__ == "__main__":
    unittest.main()
