#!/usr/bin/python3 -I
"""Explicit TEST-only FR setup while NetworkManager keeps Wi-Fi disabled.

No connection, radio enable, rfkill, clock, SSH, app or helper activation. No
persisted authorization: test_country_ready describes this call only. A future
orchestrator must revalidate immediately before connecting, under its own lock.
This process lock serializes these setters, not NetworkManager or other root
clients. Firmware/channel readback is a conservative TEST gate, not RF or
regulatory certification; firmware_tuple_qualified always stays false.

Reviewed primary sources (no vendor SET command is used):
https://sources.debian.org/src/iw/6.9-1/reg.c/#L76
https://github.com/raspberrypi/linux/blob/cff533aec2fa601846766b32ff57204e0a61bed7/drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c#L7489
https://github.com/NetworkManager/NetworkManager/blob/1.52.1/src/core/nm-config.c
iw requests NL80211_CMD_REQ_SET_REG. brcmfmac's notifier can reject it; readback
is required. Its custom PHY domain is 99, distinct from the firmware country.
The TEST policy below accepts only FR/FR plus conservative 2.4 GHz limits; it
does not translate alternative firmware codes or claim bandwidth equivalence.
"""
import sys
sys.dont_write_bytecode = True

import fcntl
import hashlib
import json
import os
import platform
import stat
import time


RADIO = "/usr/local/lib/inkyos/observe-test-radio.py"
HELPER = "/usr/local/lib/inkyos/test-lan-preflight.py"
PINS = {RADIO: "8423207c905abbfb6f7fd4e75125e11f794b063034fee4e9a8346cf449391315",
        HELPER: "fdf5a12b7b2c13dce3456531816d634e5bb235e37fdeff8d2efd4edcdb45209b"}
MODEL = "/sys/firmware/devicetree/base/model"
PI_MODEL = b"Raspberry Pi Zero 2 W Rev 1.0\0"
LOCK = "inkyos-test-country.lock"
BUDGET = 25.0
MAX_OUTPUT = 16384
SET_FR = ("/usr/sbin/iw", "reg", "set", "FR")
NM_SERVICE = ("/usr/bin/systemctl", "--no-pager", "show", "NetworkManager.service",
              "--property=ActiveState,SubState,LoadState")
BUS_GET = ("/usr/bin/busctl", "--system", "--auto-start=no", "--allow-interactive-authorization=no",
           "call", "org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager",
           "org.freedesktop.DBus.Properties", "Get", "ss", "org.freedesktop.NetworkManager")
WIFI_STATE = BUS_GET + ("WirelessEnabled",)
ACTIVE_CONNECTIONS = BUS_GET + ("ActiveConnections",)
LINK_STATE = ("/usr/sbin/iw", "dev", "wlan0", "link")
POLICY_CHECKS = ("firmware_country_fr", "firmware_ccode_fr", "kernel_global_fr",
                 "phy_label_reviewed", "channels_test_fr")
ERRORS = {"target_unverified", "source_pin_invalid", "lock_busy", "lock_invalid", "guards_blocked",
          "wifi_not_closed", "wlan0_mapping_unverified", "country_request_failed", "country_unconfirmed",
          "observation_unavailable", "runtime_timeout", "state_changed", "invalid_arguments"}


class AccessError(ValueError):
    pass


def require(condition, error):
    if condition is not True:
        raise AccessError(error)


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory(path):
    require(type(path) is str and path.startswith("/") and ".." not in path.split("/"), "source_pin_invalid")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.strip("/").split("/"):
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022, "source_pin_invalid")
            if part:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
        info = os.fstat(fd)
        require(info.st_uid == 0 and not info.st_mode & 0o022, "source_pin_invalid")
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_source(path, *, limit=65536, mode=0o555):
    parent, name = path.rsplit("/", 1)
    fd, source = directory(parent), None
    try:
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        before = os.fstat(source)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and not before.st_mode & 0o6022 and (mode is None or stat.S_IMODE(before.st_mode) == mode)
                and 0 < before.st_size <= limit, "source_pin_invalid")
        raw = bytearray()
        while len(raw) <= limit:
            block = os.read(source, min(4096, limit + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        require(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(source))
                and stamp(before) == stamp(os.stat(name, dir_fd=fd, follow_symlinks=False)), "source_pin_invalid")
        return bytes(raw)
    finally:
        if source is not None:
            os.close(source)
        os.close(fd)


def compile_source(raw, path):
    require(path in PINS and type(raw) is bytes and hashlib.sha256(raw).hexdigest() == PINS[path], "source_pin_invalid")
    namespace = {"__name__": "inkyos_test_country_source", "__file__": path}
    exec(compile(raw, path, "exec"), namespace)
    return namespace


def evaluate(firmware, kernel, channels):
    """Closed TEST policy; no implicit country alias, floating point or coercion."""
    checks = {name: False for name in POLICY_CHECKS}
    if (type(firmware) is dict and set(firmware) == {"country_abbrev", "ccode", "revision"}
            and type(firmware["revision"]) is int and -1 <= firmware["revision"] <= 65535):
        checks["firmware_country_fr"] = type(firmware["country_abbrev"]) is str and firmware["country_abbrev"] == "FR"
        checks["firmware_ccode_fr"] = type(firmware["ccode"]) is str and firmware["ccode"] == "FR"
    if (type(kernel) is dict and set(kernel) == {"global_country", "phy_country_label", "phy_custom", "phy_self_managed"}
            and type(kernel["phy_custom"]) is bool and type(kernel["phy_self_managed"]) is bool):
        checks["kernel_global_fr"] = type(kernel["global_country"]) is str and kernel["global_country"] == "FR"
        checks["phy_label_reviewed"] = (type(kernel["phy_country_label"]) is str
            and kernel["phy_country_label"] in {"FR", "99"} and not kernel["phy_self_managed"])
    if type(channels) is not list or len(channels) != 14:
        return checks
    usable = False
    for number, row in enumerate(channels, 1):
        if (type(row) is not dict or set(row) != {"channel", "frequency_mhz", "disabled", "max_tx_power_mbm", "flags"}
                or type(row["channel"]) is not int or row["channel"] != number
                or type(row["frequency_mhz"]) is not int or row["frequency_mhz"] != (2484 if number == 14 else 2407 + 5 * number)
                or type(row["disabled"]) is not bool or type(row["flags"]) is not list
                or any(type(flag) is not str or flag not in {"no IR", "passive scan", "no ibss", "radar detection"} for flag in row["flags"])
                or len(set(row["flags"])) != len(row["flags"])):
            return checks
        if row["disabled"]:
            if row["max_tx_power_mbm"] is not None or row["flags"]:
                return checks
        elif (number == 14 or type(row["max_tx_power_mbm"]) is not int
              or not 0 <= row["max_tx_power_mbm"] <= 2000):
            return checks
        elif not set(row["flags"]) & {"no IR", "passive scan", "radar detection"}:
            usable = True
    checks["channels_test_fr"] = usable
    return checks


class NativeAdapter:
    """Fixed target and commands only. Tests inject a separate fixture adapter."""
    def __init__(self):
        self.lockfd = self.lockdir = None
        self.deadline = 0
        self.monotonic = time.monotonic

    def target(self):
        return (sys.platform.startswith("linux") and os.geteuid() == 0 and sys.byteorder == "little"
                and platform.machine() == "aarch64" and read_source(MODEL, limit=128, mode=None) == PI_MODEL)

    def pin_sources(self):
        self.sources = {path: read_source(path) for path in PINS}
        self.radio = compile_source(self.sources[RADIO], RADIO)
        self.helper = compile_source(self.sources[HELPER], HELPER)

    def unchanged(self):
        return all(read_source(path) == raw for path, raw in self.sources.items())

    def lock(self):
        self.lockdir = directory("/run")
        self.lockfd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                              0o600, dir_fd=self.lockdir)
        info = os.fstat(self.lockfd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == 0, "lock_invalid")
        try:
            fcntl.flock(self.lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise AccessError("lock_busy") from None
        require(stamp(info) == stamp(os.stat(LOCK, dir_fd=self.lockdir, follow_symlinks=False)), "lock_invalid")

    def command(self, argv, *, data=None, timeout=2.0, limit=MAX_OUTPUT):
        remaining = self.deadline - self.monotonic()
        require(remaining > 0, "runtime_timeout")
        raw = self.radio["bounded_command"](argv, data=data, timeout=min(timeout, remaining), limit=min(limit, MAX_OUTPUT))
        require(self.monotonic() < self.deadline, "runtime_timeout")
        require(type(raw) is bytes and len(raw) <= min(limit, MAX_OUTPUT), "observation_unavailable")
        return raw

    def prepared(self):
        def text_command(argv, *, timeout, limit):
            return self.command(argv, timeout=timeout, limit=limit).decode("ascii")
        facts = self.radio["PreparedGuard"](helpers=self.helper, command=text_command).collect()
        return type(facts) is dict and all(facts.get(key) is True for key in self.radio["GUARD_CHECKS"])

    def wifi_closed(self):
        service = self.helper["_properties"](self.command(NM_SERVICE).decode("ascii"), {"ActiveState", "SubState", "LoadState"})
        return (service == {"ActiveState": "active", "SubState": "running", "LoadState": "loaded"}
                and self.command(WIFI_STATE) == b"v b false\n"
                and self.command(ACTIVE_CONNECTIONS) == b"v ao 0\n"
                and self.command(LINK_STATE) == b"Not connected.\n")

    def mapping(self):
        return self.radio["SysfsMapping"]().sample()

    def apply_country(self):
        return self.command(SET_FR) == b""

    def observe(self):
        values = self.radio["ProductionAdapter"](command=self.command).sample()
        index = values["wiphy_index"]
        return (index, self.radio["parse_country"](values["firmware"]),
                self.radio["parse_regulatory"](values["regulatory"], index),
                self.radio["parse_channels"](values["channels"], index))

    def close(self):
        if self.lockfd is not None:
            os.close(self.lockfd)
            self.lockfd = None
        if self.lockdir is not None:
            os.close(self.lockdir)
            self.lockdir = None


def setup_country(adapter, *, country, monotonic=time.monotonic):
    """One explicit country attempt. Fixture success never becomes live evidence."""
    result = {"schema_version": 1, "kind": "test-access-country-setup", "scope": "ephemeral-test-fr-readback",
        "test_country_ready": False, "live_evidence": False, "country_set_attempted": False,
        "country_request_acknowledged": False, "wifi_closed_verified": False, "error": None,
        "checks": {name: False for name in POLICY_CHECKS}, "firmware": None, "kernel": None,
        "channels_2_4ghz": None, "firmware_tuple_qualified": False, "connection_authorized": False,
        "activation_authorized": False, "hardware_qualified": False, "release_qualified": False,
        "limits": ["Ephemeral readback only: never consume persisted JSON as permission to connect.",
                   "No clock, radio enable, scan, connection, SSH, application or helper activation is performed.",
                   "Snapshots and this process lock do not exclude concurrent NetworkManager or privileged clients.",
                   "Channel flags and power are kernel observations, not RF measurements or full regulatory equivalence."]}
    try:
        require(type(country) is str and country == "FR", "invalid_arguments")
        adapter.monotonic, adapter.deadline = monotonic, monotonic() + BUDGET
        def within(operation):
            require(monotonic() < adapter.deadline, "runtime_timeout")
            value = operation()
            require(monotonic() < adapter.deadline, "runtime_timeout")
            return value
        require(within(adapter.target) is True, "target_unverified")
        within(adapter.pin_sources)
        within(adapter.lock)
        require(within(adapter.prepared) is True, "guards_blocked")
        require(within(adapter.wifi_closed) is True, "wifi_not_closed")
        index = within(adapter.mapping)
        require(type(index) is int and 0 <= index <= 255, "wlan0_mapping_unverified")
        require(within(adapter.unchanged) is True, "source_pin_invalid")
        result["country_set_attempted"] = True
        require(within(adapter.apply_country) is True, "country_request_failed")
        result["country_request_acknowledged"] = True
        require(within(adapter.wifi_closed) is True, "wifi_not_closed")
        observed_index, firmware, kernel, channels = within(adapter.observe)
        require(type(observed_index) is int and observed_index == index, "wlan0_mapping_unverified")
        result["checks"] = evaluate(firmware, kernel, channels)
        # Only export data satisfying the complete closed TEST schema/policy.
        # Unreviewed observations remain in memory; no raw text or identifiers.
        if all(result["checks"].values()):
            result.update(firmware=firmware, kernel=kernel, channels_2_4ghz=channels)
        require(within(adapter.prepared) is True, "guards_blocked")
        require(within(adapter.wifi_closed) is True, "wifi_not_closed")
        final_index = within(adapter.mapping)
        require(type(final_index) is int and final_index == index, "wlan0_mapping_unverified")
        require(within(adapter.unchanged) is True, "state_changed")
        result["wifi_closed_verified"] = True
        require(all(result["checks"].values()), "country_unconfirmed")
        result["test_country_ready"] = True
        result["live_evidence"] = type(adapter) is NativeAdapter and monotonic is time.monotonic
    except (KeyboardInterrupt, SystemExit):
        result["error"] = "interrupted"
    except Exception as error:
        result["error"] = str(error) if type(error) is AccessError and str(error) in ERRORS else "observation_unavailable"
    finally:
        try:
            adapter.close()
        except BaseException:
            result.update(test_country_ready=False, live_evidence=False, error="observation_unavailable")
    return result


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args != ["--apply-country", "FR"]:
        result = {"schema_version": 1, "kind": "test-access-country-setup", "test_country_ready": False,
                  "error": "explicit_test_country_required" if not args else "invalid_arguments",
                  "live_evidence": False, "connection_authorized": False, "activation_authorized": False,
                  "firmware_tuple_qualified": False, "hardware_qualified": False, "release_qualified": False}
    else:
        result = setup_country(NativeAdapter(), country="FR")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["test_country_ready"] else 1


if __name__ == "__main__":
    sys.exit(main())
