"""Bounded, single-owner NetworkManager SoftAP effects for the FR prototype.

No radio/country setter lives here. Setup must authorize those effects first.
The PSK crosses only a private D-Bus connection; no shell, file or log receives
it. The volatile activation is tied to that connection's lifetime. NM 1.52 API:
https://networkmanager.dev/docs/api/1.52.0/gdbus-org.freedesktop.NetworkManager.html
"""

import copy
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
import uuid

NM = "org.freedesktop.NetworkManager"
ROOT = "/org/freedesktop/NetworkManager"
SETTINGS = ROOT + "/Settings"
DEVICE = NM + ".Device"
WIRELESS = DEVICE + ".Wireless"
ACTIVE = NM + ".Connection.Active"
CONNECTION = NM + ".Settings.Connection"
SYSTEM_PACKAGES = "/usr/lib/python3/dist-packages"
RUNTIME_PROFILES = "/run/NetworkManager/system-connections"
CONFIG_KEYS = frozenset({
    "boot_id", "ap_id", "ssid", "passphrase", "interface", "country",
    "channel", "host", "prefix", "port", "expires_boottime_ns",
})
MISSING_NAMES = frozenset({
    "org.freedesktop.NetworkManager.Settings.InvalidConnection",
    "org.freedesktop.DBus.Error.UnknownObject",
})
REJECTED_NAMES = frozenset({
    "org.freedesktop.DBus.Error.InvalidArgs",
    "org.freedesktop.DBus.Error.AccessDenied",
    "org.freedesktop.DBus.Error.UnknownMethod",
    "org.freedesktop.NetworkManager.PermissionDenied",
    "org.freedesktop.NetworkManager.UnknownConnection",
    "org.freedesktop.NetworkManager.UnknownDevice",
    "org.freedesktop.NetworkManager.ConnectionNotAvailable",
    "org.freedesktop.NetworkManager.Device.NotAllowed",
    "org.freedesktop.NetworkManager.Settings.InvalidConnection",
})


class APError(ValueError):
    """Public errors contain a coarse code and an opaque, secret-free record."""

    def __init__(self, reason, record=None, *, reconciliation=False):
        self.reason, self.record = reason, record
        self.reconciliation = bool(reconciliation)
        super().__init__(reason)


class BusError(Exception):
    """Adapter errors expose only the D-Bus error name, never its message."""

    def __init__(self, name):
        self.name = name
        super().__init__("ap_bus_error")


def _runtime_filename(value):
    if type(value) is not str or not value.startswith(RUNTIME_PROFILES + "/"):
        raise APError("ap_profile_persistence_changed", reconciliation=True)
    name = value[len(RUNTIME_PROFILES) + 1:]
    if (not name or "/" in name or not name.endswith(".nmconnection")
            or len(name.encode("utf-8")) > 255 or name in {".", ".."}
            or any(ord(char) < 32 or ord(char) == 127 for char in name)):
        raise APError("ap_profile_persistence_changed", reconciliation=True)
    return name


def _runtime_mount(raw, filename):
    """Identify the deepest visible mount covering this one runtime pathname."""
    if type(raw) is not bytes or len(raw) > 1024 * 1024:
        raise APError("ap_runtime_metadata_unconfirmed", reconciliation=True)
    candidates = []
    for line in raw.decode("utf-8").splitlines():
        before, separator, after = line.partition(" - ")
        fields, filesystem = before.split(), after.split()
        if not separator or len(fields) < 6 or len(filesystem) < 3:
            raise APError("ap_runtime_metadata_unconfirmed", reconciliation=True)
        mount = fields[4]
        for encoded, decoded in ((r"\040", " "), (r"\011", "\t"), (r"\012", "\n"), (r"\134", "\\")):
            mount = mount.replace(encoded, decoded)
        if filename == mount or filename.startswith(mount.rstrip("/") + "/"):
            candidates.append((len(mount), mount, fields[2], filesystem[0], fields[5]))
    if not candidates:
        raise APError("ap_runtime_metadata_unconfirmed", reconciliation=True)
    deepest = max(item[0] for item in candidates)
    matches = [item for item in candidates if item[0] == deepest]
    if len(matches) != 1:
        raise APError("ap_runtime_metadata_unconfirmed", reconciliation=True)
    selected = matches[0]
    if selected[3] != "tmpfs" or "rw" not in selected[4].split(","):
        raise APError("ap_runtime_metadata_unconfirmed", reconciliation=True)
    return selected


def _observe_runtime_file(filename, check):
    """Metadata only: never read the root-only PSK-bearing keyfile contents."""
    name = _runtime_filename(filename)
    handles, bindings = [], []

    def identity(info):
        return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid

    def stable(info):
        return identity(info) + (info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def mount():
        check()
        with Path("/proc/self/mountinfo").open("rb") as stream:
            return _runtime_mount(stream.read(1024 * 1024 + 1), filename)

    selected = mount()
    try:
        parent = None
        for component in ("/run", "NetworkManager", "system-connections"):
            check()
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            fd = os.open(component, flags, **({} if parent is None else {"dir_fd": parent}))
            handles.append(fd)
            info = os.fstat(fd)
            # NM 1.52.1 nms-keyfile-writer.c creates keyfile_dir with 0755;
            # the PSK-bearing leaf remains root-only 0600 below.
            modes = {0o700, 0o755}
            if (not stat.S_ISDIR(info.st_mode) or (info.st_uid, info.st_gid) != (0, 0)
                    or stat.S_IMODE(info.st_mode) not in modes):
                raise APError("ap_runtime_metadata_unconfirmed", reconciliation=True)
            bindings.append((component, parent, fd, identity(info)))
            parent = fd
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or (before.st_uid, before.st_gid) != (0, 0)
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 1 <= before.st_size <= 65536
                or selected[2] != str(os.major(before.st_dev)) + ":" + str(os.minor(before.st_dev))):
            raise APError("ap_runtime_metadata_unconfirmed", reconciliation=True)
        check()
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        handles.append(fd)
        if stable(os.fstat(fd)) != stable(before):
            raise APError("ap_runtime_metadata_unconfirmed", reconciliation=True)
        for component, ancestor, opened, stamp in bindings:
            check()
            named = os.stat(component, follow_symlinks=False, **({} if ancestor is None else {"dir_fd": ancestor}))
            if identity(named) != stamp or identity(os.fstat(opened)) != stamp:
                raise APError("ap_runtime_metadata_unconfirmed", reconciliation=True)
        if stable(os.stat(name, dir_fd=parent, follow_symlinks=False)) != stable(before) or selected != mount():
            raise APError("ap_runtime_metadata_unconfirmed", reconciliation=True)
        return {"device": before.st_dev, "inode": before.st_ino, "mode": 0o600}
    finally:
        for fd in reversed(handles):
            os.close(fd)


def _plain(value):
    """Drop dbus scalar subclasses without importing dbus at module load."""
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, list) and str(getattr(value, "signature", "")) == "y":
        return bytes(value)
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    # dbus.Boolean subclasses int, not bool.
    if type(value).__name__ == "Boolean" or type(value) is bool:
        return bool(value)
    if isinstance(value, str):
        return str(value)
    if isinstance(value, int):
        return int(value)
    return value


class _DBusAdapter:
    def __init__(self):
        # Setup runs with -I -B -S. Its entry Graph check has already verified
        # this exact closed support tree (including native extensions). Append
        # that one fixed Debian path without executing site or any .pth file.
        # Never prepend it ahead of the interpreter's stdlib search paths.
        if SYSTEM_PACKAGES not in sys.path:
            sys.path.append(SYSTEM_PACKAGES)
        import dbus  # python3-dbus is already in the pinned image.

        self.dbus = dbus
        self.bus = dbus.SystemBus(private=True)

    def owner(self, timeout):
        return str(self.call(
            "org.freedesktop.DBus", "/org/freedesktop/DBus",
            "org.freedesktop.DBus", "GetNameOwner", (NM,), timeout,
        ))

    def call(self, destination, path, interface, method, arguments, timeout):
        try:
            proxy = self.bus.get_object(destination, path, introspect=False)
            function = self.dbus.Interface(proxy, interface).get_dbus_method(method)
            if method == "AddAndActivateConnection2":
                profile, device, specific, options = arguments
                arguments = (
                    self._profile(profile), self.dbus.ObjectPath(device),
                    self.dbus.ObjectPath(specific),
                    self.dbus.Dictionary(options, signature="sv"),
                )
            elif method == "DeactivateConnection":
                arguments = (self.dbus.ObjectPath(arguments[0]),)
            elif method == "GetAppliedConnection":
                arguments = (self.dbus.UInt32(0),)
            return _plain(function(*arguments, timeout=timeout))
        except self.dbus.DBusException as error:
            raise BusError(error.get_dbus_name()) from None

    def _profile(self, profile):
        dbus = self.dbus
        typed = {}
        for section, properties in profile.items():
            values = {}
            for key, value in properties.items():
                if type(value) is bool:
                    value = dbus.Boolean(value)
                elif type(value) is int:
                    signed = key == "ap-isolation" or (section == "proxy" and key == "method")
                    value = dbus.Int32(value) if signed else dbus.UInt32(value)
                elif type(value) is bytes:
                    value = dbus.ByteArray(value)
                elif key == "address-data":
                    value = dbus.Array([
                        dbus.Dictionary({"address": item["address"], "prefix": dbus.UInt32(item["prefix"])}, signature="sv")
                        for item in value
                    ], signature="a{sv}")
                elif type(value) is list:
                    value = dbus.Array(value, signature="s")
                values[key] = value
            typed[section] = dbus.Dictionary(values, signature="sv")
        return dbus.Dictionary(typed, signature="sa{sv}")

    def prop(self, destination, path, interface, name, timeout):
        return self.call(destination, path, "org.freedesktop.DBus.Properties", "Get", (interface, name), timeout)

    def renew(self):
        self.close()
        self.bus = self.dbus.SystemBus(private=True)

    def close(self):
        self.bus.close()


class NativeAP:
    """Synchronous effects. Callers serialize operations and own the TTL policy.

    A record is accepted only by the instance which created it. No activation is
    retried after an uncertain reply. stop() drains that private bus first and
    reconciles the UUID originally proved absent. Closing that bus affects only
    activations bound to it, never a separate station connection.
    """

    def __init__(self, native, *, bus_adapter=None, clock=time.monotonic,
                 sleep=time.sleep, boot_id_reader=None, file_observer=None):
        self.native = native
        self._bus = bus_adapter
        self._clock, self._sleep = clock, sleep
        self._boot_id = boot_id_reader or (lambda: Path("/proc/sys/kernel/random/boot_id").read_text().strip())
        self._file_observer = file_observer or _observe_runtime_file
        self.owned_record = None
        self._config = None
        self._closed = False
        self._deadline = None
        self._check = None
        self._read_check = None

    def _fail(self, reason, *, reconciliation=False):
        raise APError(reason, self.owned_record, reconciliation=reconciliation)

    def _begin(self, check, seconds):
        if self._closed or not callable(check):
            self._fail("ap_unavailable")
        now = self._clock()
        if not math.isfinite(now):
            self._fail("ap_clock_invalid")
        self._deadline, self._check = now + seconds, check
        light = getattr(check, "read_check", None)
        self._read_check = light if callable(light) else check
        self._full_boundary()
        if self._bus is None:
            try:
                self._bus = _DBusAdapter()
            except Exception:
                self._fail("ap_bus_unavailable")

    def _boundary(self):
        self._read_check()
        return self._time_boundary()

    def _full_boundary(self):
        self._check()
        return self._time_boundary()

    def _time_boundary(self):
        now = self._clock()
        if not math.isfinite(now) or now >= self._deadline:
            self._fail("ap_observation_timeout", reconciliation=self.owned_record is not None)
        return min(2.0, self._deadline - now)

    def _effect(self, operation):
        self._full_boundary()
        try:
            return operation()
        finally:
            # A lost reply or changed graph cannot silently become permission
            # to retry a mutation. The owned record remains available to stop.
            self._full_boundary()

    def _effect_call(self, path, interface, method, *arguments):
        return self._effect(lambda: self._call(path, interface, method, *arguments))

    def _call(self, path, interface, method, *arguments):
        return self._read_call(self.owned_record["nm_unique_owner"], path, interface, method, *arguments)

    def _read_call(self, owner, path, interface, method, *arguments):
        timeout = self._boundary()
        result = self._bus.call(owner, path, interface, method, arguments, timeout)
        self._boundary()
        return result

    def _prop(self, path, interface, name):
        return self._read_prop(self.owned_record["nm_unique_owner"], path, interface, name)

    def _read_prop(self, owner, path, interface, name):
        timeout = self._boundary()
        result = self._bus.prop(owner, path, interface, name, timeout)
        self._boundary()
        return result

    def _owner(self):
        owner = self._bus.owner(self._boundary())
        if type(owner) is not str or re.fullmatch(r":[0-9]+\.[0-9]+", owner) is None:
            self._fail("ap_nm_owner_changed", reconciliation=True)
        return owner

    def _identity(self, *, radio=True):
        record = self.owned_record
        if self._owner() != record["nm_unique_owner"] or self.native.command.owner(NM) != record["nm_unique_owner"]:
            self._fail("ap_nm_owner_changed", reconciliation=True)
        if self.native.mapping.sample() != record["wiphy_index"]:
            self._fail("ap_device_changed", reconciliation=True)
        device = self._call(ROOT, NM, "GetDeviceByIpIface", "wlan0")
        if device != record["device"]:
            self._fail("ap_device_changed", reconciliation=True)
        if self._prop(device, DEVICE, "Interface") != "wlan0" or self._prop(device, DEVICE, "DeviceType") != 2:
            self._fail("ap_device_changed", reconciliation=True)
        if radio:
            country = self.native.observe_country("FR")
            index, soft, hard = self.native.rfkill()
            if (country["wiphy_index"] != record["wiphy_index"] or index != record["wiphy_index"]
                    or soft or hard or not self.native.wireless()):
                self._fail("ap_radio_unconfirmed", reconciliation=True)
        self._boundary()

    def preflight(self, check):
        """Read-only AP feasibility before Setup changes country or RF state.

        UNAVAILABLE (20) is permitted while the radio remains closed. This is
        only an observation, never authority for activation: start() repeats
        every relevant owner/device/country/radio/profile check afterwards.
        """
        if self.owned_record is not None:
            self._fail("ap_reconciliation_required", reconciliation=True)
        self._begin(check, 15.0)
        try:
            owner = self._owner()
            index = self.native.mapping.sample()
            if (type(index) is not int or index < 0
                    or self.native.command.owner(NM) != owner):
                self._fail("ap_device_unconfirmed")
            device = self._read_call(owner, ROOT, NM, "GetDeviceByIpIface", "wlan0")
            if type(device) is not str or re.fullmatch(re.escape(ROOT) + r"/Devices/[0-9]+", device) is None:
                self._fail("ap_device_unconfirmed")
            if self._read_prop(owner, ROOT, NM, "Version") != "1.52.1":
                self._fail("ap_nm_version_unconfirmed")
            if (self._read_prop(owner, device, DEVICE, "Interface") != "wlan0"
                    or self._read_prop(owner, device, DEVICE, "DeviceType") != 2):
                self._fail("ap_device_unconfirmed")
            capabilities = self._read_prop(owner, device, WIRELESS, "WirelessCapabilities")
            if type(capabilities) is not int or capabilities & 0x40 == 0:
                self._fail("ap_capability_unavailable")
            managed = self._read_prop(owner, device, DEVICE, "Managed")
            state = self._read_prop(owner, device, DEVICE, "State")
            active = self._read_prop(owner, device, DEVICE, "ActiveConnection")
            if managed is not True or type(state) is not int or state not in {20, 30} or active != "/":
                self._fail("ap_device_busy")
            if (self._owner() != owner or self.native.command.owner(NM) != owner
                    or self.native.mapping.sample() != index):
                self._fail("ap_device_changed")
            self._boundary()
            self._full_boundary()
            return {"nm_unique_owner": owner, "wiphy_index": index, "device": device,
                    "ap_capable": True, "nm_version": "1.52.1",
                    "observed_boottime_ns": self.native.boottime()}
        except APError:
            raise
        except Exception:
            self._fail("ap_preflight_unconfirmed")

    def _validate(self, config):
        valid = type(config) is dict and set(config) == CONFIG_KEYS
        if not valid:
            self._fail("ap_config_invalid")
        for key in ("boot_id", "ap_id"):
            try:
                valid = type(config[key]) is str and str(uuid.UUID(config[key])) == config[key]
            except (ValueError, TypeError, AttributeError):
                valid = False
            if not valid:
                self._fail("ap_config_invalid")
        ssid, psk = config["ssid"], config["passphrase"]
        try:
            ssid_size = len(ssid.encode("utf-8")) if type(ssid) is str else 0
        except UnicodeError:
            self._fail("ap_config_invalid")
        if (type(ssid) is not str or not 1 <= ssid_size <= 32
                or any(ord(c) < 32 or ord(c) == 127 for c in ssid)
                or type(psk) is not str or not 8 <= len(psk) <= 63
                or any(not 32 <= ord(c) <= 126 for c in psk)):
            self._fail("ap_config_invalid")
        fixed = {"interface": "wlan0", "country": "FR", "channel": 6,
                 "host": "192.168.4.1", "prefix": 24, "port": 9443}
        if any(type(config[key]) is not type(value) or config[key] != value for key, value in fixed.items()):
            self._fail("ap_config_invalid")
        if type(config["expires_boottime_ns"]) is not int or config["expires_boottime_ns"] <= self.native.boottime():
            self._fail("ap_expired")
        if config["boot_id"] != self._boot_id():
            self._fail("ap_boot_changed")

    @staticmethod
    def _profile(config):
        return {
            "connection": {"id": "InkyOS setup " + config["ap_id"], "uuid": config["ap_id"],
                           "type": "802-11-wireless", "interface-name": "wlan0", "autoconnect": False},
            "802-11-wireless": {"ssid": config["ssid"].encode("utf-8"), "mode": "ap", "band": "bg", "channel": 6,
                                "hidden": False, "assigned-mac-address": "permanent", "ap-isolation": 1, "powersave": 2},
            "802-11-wireless-security": {"key-mgmt": "wpa-psk", "proto": ["rsn"], "pairwise": ["ccmp"], "group": ["ccmp"],
                                         "psk": config["passphrase"], "psk-flags": 0, "wps-method": 1},
            "ipv4": {"method": "shared", "address-data": [{"address": "192.168.4.1", "prefix": 24}],
                     "never-default": True, "may-fail": False},
            "ipv6": {"method": "disabled"},
            "proxy": {"method": 0},
        }

    def _lookup(self):
        try:
            path = self._call(SETTINGS, NM + ".Settings", "GetConnectionByUuid", self._config["ap_id"])
        except BusError as error:
            if error.name in MISSING_NAMES:
                return None
            raise
        if type(path) is not str or re.fullmatch(re.escape(SETTINGS) + r"/[0-9]+", path) is None:
            self._fail("ap_profile_unconfirmed", reconciliation=True)
        old = self.owned_record["profile"]
        if old is not None and old != path:
            self._fail("ap_profile_changed", reconciliation=True)
        self.owned_record["profile"] = path
        return path

    def _profile_exact(self, path, *, applied=False):
        if applied:
            result = self._call(self.owned_record["device"], DEVICE, "GetAppliedConnection", 0)
            if not isinstance(result, (list, tuple)) or len(result) != 2:
                self._fail("ap_profile_unconfirmed", reconciliation=True)
            settings = result[0]
        else:
            # NM 1.52.1 marks AddAndActivateConnection2(persist=volatile)
            # UNSAVED|VOLATILE. NM_GENERATED is not set for this user profile.
            flags = self._prop(path, CONNECTION, "Flags")
            if (self._prop(path, CONNECTION, "Unsaved") is not True
                    or type(flags) is not int or flags not in {5, 7}):
                self._fail("ap_profile_persistence_changed", reconciliation=True)
            filename = self._prop(path, CONNECTION, "Filename")
            _runtime_filename(filename)
            previous = self.owned_record.get("filename")
            if previous is not None and previous != filename:
                self._fail("ap_profile_persistence_changed", reconciliation=True)
            self._file_observer(filename, self._boundary)
            if self._prop(path, CONNECTION, "Filename") != filename:
                self._fail("ap_profile_persistence_changed", reconciliation=True)
            self.owned_record["filename"] = filename
            settings = self._call(path, CONNECTION, "GetSettings")
        self._settings_exact(settings)
        if not applied:
            self._secrets_exact(self._call(path, CONNECTION, "GetSecrets", "802-11-wireless-security"))

    def _settings_exact(self, settings):
        """Pure comparison of actual NM serialization; no properties or I/O."""
        expected = self._profile(self._config)
        del expected["802-11-wireless-security"]["psk"]
        if type(settings) is not dict or set(settings) != set(expected):
            self._fail("ap_profile_changed", reconciliation=True)
        # NM may serialize neutral defaults and legacy equivalents. Everything
        # else must match the requested profile; new policy-bearing keys refuse.
        neutral = {
            "connection": {"timestamp": 0, "permissions": [], "autoconnect-priority": 0,
                           "autoconnect-retries": -1, "auth-retries": -1, "metered": 0, "multi-connect": 0},
            # NM 1.52.1 security_to_dbus emits the section name, and permanent
            # assigned MAC normalizes mac-address-randomization to NEVER (1).
            "802-11-wireless": {"seen-bssids": [], "mac-address-blacklist": [],
                                "security": "802-11-wireless-security", "mac-address-randomization": 1},
            "802-11-wireless-security": {"auth-alg": "open", "pmf": 0},
            "ipv4": {"dns": [], "dns-data": [], "dns-search": [], "routes": [], "route-data": [],
                     "gateway": "", "route-metric": -1, "dns-priority": 0},
            "ipv6": {"address-data": [], "dns": [], "dns-search": [], "routes": [], "route-data": [],
                     "gateway": "", "addr-gen-mode": 1, "route-metric": -1, "dns-priority": 0},
            "proxy": {},
        }
        for section, wanted in expected.items():
            actual = settings[section]
            if type(actual) is not dict:
                self._fail("ap_profile_changed", reconciliation=True)
            actual = dict(actual)
            # Legacy addresses is emitted alongside address-data by NM 1.52.
            if section == "ipv4" and "addresses" in actual:
                if actual.pop("addresses") != [[17082560, 24, 0]]:  # network-order uint32, little-endian host
                    self._fail("ap_profile_changed", reconciliation=True)
            if section == "ipv6" and actual.get("addresses") == []:
                actual.pop("addresses")
            # Zero/default fields can be omitted in GetSettings serialization.
            defaults = {"hidden": False, "psk-flags": 0, "method": 0}
            for key, value in wanted.items():
                if key not in actual and key in defaults and value == defaults[key]:
                    actual[key] = value
                if key not in actual or type(actual[key]) is not type(value) or actual[key] != value:
                    self._fail("ap_profile_changed", reconciliation=True)
                actual.pop(key)
            for key, value in actual.items():
                if section == "connection" and key == "timestamp" and type(value) is int and value >= 0:
                    continue
                if (key not in neutral[section] or type(value) is not type(neutral[section][key])
                        or value != neutral[section][key]):
                    self._fail("ap_profile_changed", reconciliation=True)
    def _secrets_exact(self, secret):
        # NM 1.52.1 serializes known non-secret settings as empty sections even
        # when the request names only wireless-security. Never accept an extra
        # credential, non-empty unrelated section, or unknown setting.
        known = set(self._profile(self._config))
        if (type(secret) is not dict or not set(secret) <= known
                or secret.get("802-11-wireless-security") != {"psk": self._config["passphrase"]}):
            self._fail("ap_profile_changed", reconciliation=True)
        for section, values in secret.items():
            if section != "802-11-wireless-security" and (type(values) is not dict or values != {}):
                self._fail("ap_profile_changed", reconciliation=True)

    def _active_exact(self, path):
        record = self.owned_record
        if (self._prop(path, ACTIVE, "Uuid") != record["ap_id"]
                or self._prop(path, ACTIVE, "Connection") != record["profile"]
                or self._prop(path, ACTIVE, "Devices") != [record["device"]]):
            self._fail("ap_activation_changed", reconciliation=True)

    def _idle(self, *, wait):
        device = self.owned_record["device"]
        while True:
            managed = self._prop(device, DEVICE, "Managed")
            state = self._prop(device, DEVICE, "State")
            active = self._prop(device, DEVICE, "ActiveConnection")
            if managed is True and state == 30 and active == "/":
                return
            # Enabling RF can leave NM briefly UNAVAILABLE. Only that transition
            # may wait; PREPARE/CONFIG/ACTIVATED or any active object refuses.
            if not wait or managed is not True or state != 20 or active != "/":
                self._fail("ap_device_busy")
            self._validate(self._config)
            self._boundary()
            self._sleep(0.1)

    def _verify(self):
        self._validate(self._config)
        self._identity()
        record = self.owned_record
        profile = self._lookup()
        if profile is None:
            self._fail("ap_profile_missing", reconciliation=True)
        self._profile_exact(profile)
        active = record["active"]
        if active is None:
            self._fail("ap_activation_unconfirmed", reconciliation=True)
        self._active_exact(active)
        if (self._prop(active, ACTIVE, "State") != 2
                or self._prop(record["device"], DEVICE, "State") != 100
                or self._prop(record["device"], DEVICE, "ActiveConnection") != active
                or self._prop(record["device"], WIRELESS, "Mode") != 3):
            self._fail("ap_not_ready")
        self._profile_exact(profile, applied=True)
        ipv4 = self._prop(active, ACTIVE, "Ip4Config")
        if type(ipv4) is not str or re.fullmatch(re.escape(ROOT) + r"/IP4Config/[0-9]+", ipv4) is None:
            self._fail("ap_not_ready")
        if self._prop(ipv4, NM + ".IP4Config", "AddressData") != [{"address": "192.168.4.1", "prefix": 24}]:
            self._fail("ap_address_unconfirmed", reconciliation=True)
        self._identity()
        self._validate(self._config)
        return {"active": True, "state": "active", "ap_id": record["ap_id"], "country": "FR",
                "interface": "wlan0", "host": "192.168.4.1", "prefix": 24, "port": 9443,
                "channel": 6, "observed_boottime_ns": self.native.boottime()}

    def start(self, config, check):
        if self.owned_record is not None:
            self._fail("ap_reconciliation_required", reconciliation=True)
        self._validate(config)
        self._begin(check, 30.0)
        try:
            owner = self._owner()
            self._config = copy.deepcopy(config)
            self.owned_record = {"ap_id": config["ap_id"], "nm_unique_owner": owner,
                                 "wiphy_index": self.native.mapping.sample(), "device": None,
                                 "profile": None, "active": None, "filename": None, "uncertain": False,
                                 "activation_issued": False, "deactivation_issued": False,
                                 "delete_issued": False, "bus_drained": False}
            record = self.owned_record
            record["device"] = self._call(ROOT, NM, "GetDeviceByIpIface", "wlan0")
            if type(record["device"]) is not str or re.fullmatch(re.escape(ROOT) + r"/Devices/[0-9]+", record["device"]) is None:
                self._fail("ap_device_unconfirmed")
            self._identity()
            if self._prop(ROOT, NM, "Version") != "1.52.1":
                self._fail("ap_nm_version_unconfirmed")
            capabilities = self._prop(record["device"], WIRELESS, "WirelessCapabilities")
            if type(capabilities) is not int or capabilities & 0x40 == 0:
                self._fail("ap_capability_unavailable")
            self._idle(wait=True)
            if self._lookup() is not None:
                self._fail("ap_uuid_exists")
            self._identity()
            self._validate(self._config)
            self._idle(wait=False)

            def activate():
                # A full Graph walk can take time. Re-read live authorization
                # and the idle device after that walk, before dispatching NM.
                self._validate(self._config)
                self._identity()
                self._idle(wait=False)
                self._validate(self._config)
                record["activation_issued"] = True
                record["uncertain"] = True
                return self._call(ROOT, NM, "AddAndActivateConnection2", self._profile(config), record["device"], "/",
                                  {"persist": "volatile", "bind-activation": "dbus-client"})

            try:
                result = self._effect(activate)
            except BusError as error:
                if error.name not in REJECTED_NAMES:
                    self._fail("ap_activation_uncertain", reconciliation=True)
                record["uncertain"] = False
                self._fail("ap_activation_rejected")
            if not isinstance(result, (list, tuple)) or len(result) != 3 or result[2] != {}:
                record["uncertain"] = True
                self._fail("ap_activation_uncertain", reconciliation=True)
            profile, active, _ = result
            if (type(profile) is not str or re.fullmatch(re.escape(SETTINGS) + r"/[0-9]+", profile) is None
                    or type(active) is not str or re.fullmatch(re.escape(ROOT) + r"/ActiveConnection/[0-9]+", active) is None):
                record["uncertain"] = True
                self._fail("ap_activation_uncertain", reconciliation=True)
            record["profile"], record["active"] = profile, active
            record["uncertain"] = False
            while True:
                try:
                    self._verify()
                    self._full_boundary()
                    return record
                except APError as error:
                    if error.reason != "ap_not_ready":
                        raise
                self._boundary()
                self._sleep(0.1)
        except Exception as error:
            record = self.owned_record
            if record is not None and not record["activation_issued"]:
                self.owned_record = self._config = None
            elif record is not None and not record["uncertain"]:
                try:
                    self.stop(record, check)
                except Exception:
                    raise APError("ap_cleanup_unconfirmed", self.owned_record, reconciliation=True) from None
            if isinstance(error, APError):
                raise APError(error.reason, self.owned_record, reconciliation=self.owned_record is not None) from None
            raise APError("ap_unavailable", self.owned_record, reconciliation=self.owned_record is not None) from None

    def verify(self, record, check):
        if record is not self.owned_record or record is None:
            self._fail("ap_record_invalid")
        if record["uncertain"]:
            self._fail("ap_reconciliation_required", reconciliation=True)
        self._begin(check, 15.0)
        try:
            observation = self._verify()
            self._full_boundary()
            return observation
        except APError:
            raise
        except Exception:
            self._fail("ap_observation_unavailable", reconciliation=True)

    def apply_evidence(self, record, context, proof, check):
        """Reuse the existing Setup evidence, with an exact active-AP gate.

        gate_receipt verifies the boot's initialization seal without requiring
        the radio to still be closed. inventory permits only this proved UUID
        plus an independently authenticated station helper transaction.
        """
        if record is not self.owned_record or record is None:
            self._fail("ap_record_invalid")
        self._begin(check, 30.0)
        try:
            self._verify()
            self._boundary()
            gate = self.native.gate_receipt(context)
            self._boundary()
            country = self.native.observe_country("FR")
            country, radio = self.native.observe_live(country, {
                "wiphy_index": record["wiphy_index"],
                "nm_unique_owner": record["nm_unique_owner"],
            })
            self._boundary()
            self.native.inventory(proof, ap_uuid=record["ap_id"])
            self._verify()
            self._full_boundary()
            return {"gate": gate, "country": country, "radio": radio}
        except APError:
            raise
        except Exception:
            self._fail("ap_setup_evidence_unconfirmed", reconciliation=True)

    def stop(self, record, check):
        if record is None and self.owned_record is None:
            check()
            check()
            return
        if record is not self.owned_record or record is None:
            self._fail("ap_record_invalid")
        self._begin(check, 15.0)
        try:
            if record["uncertain"] and not record["bus_drained"]:
                self._effect(self._bus.renew)  # closes only our client-bound activation.
                record["bus_drained"] = True
            self._identity(radio=False)
            profile = self._lookup()
            if profile is not None:
                self._profile_exact(profile)
            active_paths = self._prop(ROOT, NM, "ActiveConnections")
            if type(active_paths) is not list or len(active_paths) > 64:
                self._fail("ap_activation_unconfirmed", reconciliation=True)
            owned = []
            for active in active_paths:
                if self._prop(active, ACTIVE, "Uuid") == record["ap_id"]:
                    self._active_exact(active)
                    if record["active"] not in {None, active}:
                        self._fail("ap_activation_changed", reconciliation=True)
                    record["active"] = active
                    owned.append(active)
            if len(owned) > 1:
                self._fail("ap_activation_changed", reconciliation=True)
            if owned and not record["deactivation_issued"]:
                self._identity(radio=False)
                record["deactivation_issued"] = True
                self._effect_call(ROOT, NM, "DeactivateConnection", owned[0])
            while True:
                self._identity(radio=False)
                active_paths = self._prop(ROOT, NM, "ActiveConnections")
                if record["active"] not in active_paths:
                    break
                self._boundary()
                self._sleep(0.1)
            profile = self._lookup()
            if profile is not None and not record["delete_issued"]:
                self._profile_exact(profile)
                self._identity(radio=False)
                record["delete_issued"] = True
                self._effect_call(profile, CONNECTION, "Delete")
            while self._lookup() is not None:
                self._identity(radio=False)
                self._boundary()
                self._sleep(0.1)
            self._identity(radio=False)
            self._full_boundary()
            self.owned_record = self._config = None
        except APError:
            if record["deactivation_issued"] or record["delete_issued"]:
                record["uncertain"] = True
                record["bus_drained"] = False
            raise
        except Exception:
            if record["deactivation_issued"] or record["delete_issued"]:
                record["uncertain"] = True
                record["bus_drained"] = False
            self._fail("ap_cleanup_unconfirmed", reconciliation=True)

    def close(self, check):
        if not self._closed:
            if self._bus is not None:
                # Cleanup belongs to the service's current journal guard. The
                # last requesting peer can already be gone after stop().
                self._begin(check, 15.0)
                try:
                    self._effect(self._bus.close)
                finally:
                    # close() must never be replayed after a lost result.
                    self._closed = True
                    self._config = None
            else:
                if not callable(check):
                    self._fail("ap_unavailable")
                check()
                check()
                self._closed = True
                self._config = None
        # Deliberately retain a secret-free record: close() is lifetime safety,
        # not proof that NM finished reconciling a previously uncertain request.
