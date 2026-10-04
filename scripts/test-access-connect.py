#!/usr/bin/python3 -I
"""Connect the authenticated TEST cache on wlan0; never start SSH or the app.

One fixed UUID, one exact private runtime profile, no autoconnect and no secret
in argv or output. Country is requested/read back during this invocation with
Wi-Fi off. Failed activation attempts request radio off, then observe its state.
Snapshots and these process locks cannot exclude unrelated privileged clients.
"""
import sys
sys.dont_write_bytecode = True

import hashlib
import json
import os
import platform
import stat
import time


BASE = "/usr/local/lib/inkyos/"
SELF = BASE + "test-access-connect.py"
IMPORTER = BASE + "test-access-import.py"
COUNTRY = BASE + "test-access-network.py"
LEGACY = BASE + "test-enrollment-firstboot.py"
LEGACY_SHA256 = "081bac2c04d4e72a6e74a365664b72941fa4d1e84d1ccc32cf0dc25d9e8a337a"
MANIFEST = "/usr/local/share/inkyos/test-access-manifest.json"
PROFILE_NAME = "inkyos-test-access.nmconnection"
PROFILE_DIR = "/run/NetworkManager/system-connections"
PROFILE = PROFILE_DIR + "/" + PROFILE_NAME
PROFILE_DIRS = ("/etc/NetworkManager/system-connections", "/usr/lib/NetworkManager/system-connections", PROFILE_DIR)
UUID = "ea14df0f-8d69-4f38-8716-16576575e39f"
NMCLI = "/usr/bin/nmcli"
KNOWN = (NMCLI, "-t", "-f", "UUID", "connection", "show")
ACTIVE = (NMCLI, "-t", "-f", "UUID,DEVICE", "connection", "show", "--active")
LOAD = (NMCLI, "connection", "load", PROFILE)
PROPERTIES = (NMCLI, "-g", "connection.uuid,connection.type,connection.interface-name,connection.autoconnect,802-11-wireless.band,802-11-wireless.mode",
              "connection", "show", "uuid", UUID)
PROPERTY_BYTES = (UUID + "\n802-11-wireless\nwlan0\nno\nbg\ninfrastructure\n").encode()
RADIO_ON = (NMCLI, "radio", "wifi", "on")
RADIO_OFF = (NMCLI, "radio", "wifi", "off")
UP = (NMCLI, "--wait", "35", "connection", "up", "uuid", UUID, "ifname", "wlan0")
DEVICE = (NMCLI, "-g", "GENERAL.STATE,GENERAL.NM-MANAGED,GENERAL.CON-UUID", "device", "show", "wlan0")
BUDGET, CLEANUP_RESERVE = 90.0, 6.0
CHECKS = ("target_verified", "sources_and_enrollment_bound", "cache_authenticated", "bindings_unchanged_before_profile",
          "profile_inventory_closed", "wifi_initially_closed", "runtime_profile_exact", "profile_loaded",
          "loaded_profile_restricted", "country_live_verified", "bindings_unchanged_before_radio",
          "profile_inventory_still_closed", "loaded_profile_still_restricted", "country_guard_immediately_before_radio",
          "radio_enable_acknowledged", "connection_acknowledged", "bindings_unchanged_after_connection",
          "profile_inventory_unchanged_after_connection", "loaded_profile_restricted_after_connection",
          "unique_wlan_connection_verified")
ERRORS = {"target_unverified", "sources_invalid", "cache_invalid", "operation_busy", "state_changed",
          "other_profile_present", "wifi_not_closed", "profile_write_failed", "profile_load_failed",
          "profile_unconfirmed", "country_unconfirmed", "radio_enable_failed", "connection_failed",
          "connection_unconfirmed", "runtime_timeout", "connect_failed", "invalid_arguments"}


class ConnectError(ValueError):
    pass


def require(value, error):
    if value is not True:
        raise ConnectError(error)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def bootstrap():
    """Authenticate the immutable legacy safe reader before opening a manifest."""
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    source = None
    try:
        for part in LEGACY.strip("/").split("/")[:-1]:
            info = os.fstat(directory)
            require(info.st_uid == 0 and not info.st_mode & 0o022, "sources_invalid")
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.fstat(directory)
        require(info.st_uid == 0 and not info.st_mode & 0o022, "sources_invalid")
        name = LEGACY.rsplit("/", 1)[1]
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        info = os.fstat(source)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o555 and 0 < info.st_size <= 65536, "sources_invalid")
        raw = os.read(source, 65537)
        def stamp(value):
            return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_nlink,
                    value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        require(len(raw) == info.st_size and digest(raw) == LEGACY_SHA256
                and stamp(info) == stamp(os.fstat(source))
                and stamp(info) == stamp(os.stat(name, dir_fd=directory, follow_symlinks=False)), "sources_invalid")
    finally:
        if source is not None:
            os.close(source)
        os.close(directory)
    namespace = {"__name__": "inkyos_connect_legacy", "__file__": LEGACY}
    exec(compile(raw, LEGACY, "exec"), namespace)
    return namespace


class NativeAdapter:
    def __init__(self):
        self.auth = self.country = None

    def target(self):
        if not (sys.platform.startswith("linux") and platform.machine() == "aarch64"
                and sys.byteorder == "little" and os.getuid() == os.geteuid() == 0):
            return False
        self.lib = bootstrap()
        files = self.lib["Files"]()
        try:
            return files.read(self.lib["MODEL_PATH"], limit=128) == self.lib["PI_MODEL"]
        finally:
            files.close()

    def bind(self):
        files = self.lib["Files"]()
        try:
            raw = files.read(MANIFEST, mode=0o644, limit=65536)
            manifest = self.lib["strict_json"](raw)
            require(type(manifest) is dict and type(manifest.get("files")) is dict, "sources_invalid")
            sources = {}
            for path in (SELF, IMPORTER, COUNTRY):
                data = files.read(path, mode=0o555, limit=65536)
                require(manifest["files"].get(path[1:]) == {"sha256": digest(data), "mode": "0555"}, "sources_invalid")
                sources[path] = data
        finally:
            files.close()
        self.importer = {"__name__": "inkyos_connect_import", "__file__": IMPORTER}
        exec(compile(sources[IMPORTER], IMPORTER, "exec"), self.importer)
        self.auth = self.importer["NativeAdapter"]()
        require(self.auth.target() is True, "target_unverified")
        self.expected = self.auth.bind()
        require(self.auth.snapshot[MANIFEST][0] == raw
                and all(self.auth.snapshot[path][0] == data for path, data in sources.items()), "state_changed")
        self.country_module = {"__name__": "inkyos_connect_country", "__file__": COUNTRY}
        exec(compile(sources[COUNTRY], COUNTRY, "exec"), self.country_module)
        self.country = self.country_module["NativeAdapter"]()
        self.country.pin_sources()
        return True

    def authenticate_cache(self):
        self.auth.acquire()
        previous = self.auth.state()
        require(self.importer["valid_state"](previous, self.expected)
                and previous["state"] == "imported", "cache_invalid")
        raw, signature = self.auth.capsule(cached=True)
        value = self.auth.authenticate(raw, signature)
        self.network = self.importer["network_profile"](value["wifi"])
        final = self.importer["state_record"](self.expected, raw, signature, self.network, "imported")
        require(previous == final and self.auth.read_cache(self.importer["NETWORK"]) == self.network, "cache_invalid")
        self.cache = (final, raw, signature)
        return True

    def unchanged(self):
        return (self.auth.unchanged() is True and self.auth.state() == self.cache[0]
                and self.auth.capsule(cached=True) == self.cache[1:]
                and self.auth.read_cache(self.importer["NETWORK"]) == self.network)

    def command(self, argv, *, timeout=2.0, cleanup=False):
        remaining = (self.deadline if cleanup else self.work_deadline) - time.monotonic()
        if remaining <= 0:
            return None
        return self.lib["command"](argv, timeout=min(timeout, remaining), limit=4096)

    def profiles_closed(self):
        for path in PROFILE_DIRS:
            try:
                directory = self.auth.files.directory(path)
            except FileNotFoundError:
                continue
            try:
                names = set(os.listdir(directory))
                if names and (path != PROFILE_DIR or names != {PROFILE_NAME}
                              or self.auth.files.read(PROFILE, mode=0o600, limit=4096) != self.network):
                    return False
            finally:
                os.close(directory)
        result = self.command(KNOWN)
        return result in {(0, b""), (0, (UUID + "\n").encode())}

    def wifi_closed(self):
        self.country.deadline = self.work_deadline
        return self.country.wifi_closed() is True

    def publish_profile(self):
        parent = self.auth.files.directory("/run/NetworkManager")
        try:
            try:
                os.mkdir("system-connections", 0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                pass
        finally:
            os.close(parent)
        directory = self.auth.files.directory(PROFILE_DIR)
        try:
            names = set(os.listdir(directory))
            require(names in (set(), {PROFILE_NAME}), "other_profile_present")
            if not names:
                self.lib["write_atomic"](directory, PROFILE_NAME, self.network)
            return self.auth.files.read(PROFILE, mode=0o600, limit=4096) == self.network
        finally:
            os.close(directory)

    def load_profile(self):
        result = self.command(LOAD, timeout=3)
        return result is not None and result[0] == 0

    def profile_restricted(self):
        return self.command(PROPERTIES) == (0, PROPERTY_BYTES)

    def country_ready(self):
        require(self.work_deadline - time.monotonic() >= self.country_module["BUDGET"], "runtime_timeout")
        self.country.deadline = self.work_deadline
        self.wiphy = self.country.mapping()
        require(type(self.wiphy) is int and 0 <= self.wiphy <= 255, "country_unconfirmed")
        value = self.country_module["setup_country"](self.country, country="FR")
        require(type(value) is dict and value.get("test_country_ready") is True
                and value.get("live_evidence") is True and value.get("error") is None
                and value.get("wifi_closed_verified") is True, "country_unconfirmed")
        # setup_country closes its own lock. Reacquire before the final live gates
        # and hold through activation; it still cannot exclude unrelated root clients.
        self.country.deadline = self.work_deadline
        self.country.lock()
        return True

    def immediately_ready(self):
        self.country.deadline = self.work_deadline
        if self.country.prepared() is not True or self.country.wifi_closed() is not True:
            return False
        index = self.country.mapping()
        if type(index) is not int or index != self.wiphy or self.country.unchanged() is not True:
            return False
        # nmcli radio wifi on is global to WLAN. Refuse a second PHY rather
        # than enabling an additional radio which has not been reviewed here.
        directory = self.auth.files.directory("/sys/class/ieee80211")
        try:
            with os.scandir(directory) as entries:
                first, second = next(entries, None), next(entries, None)
            return first is not None and first.name == "phy" + str(index) and second is None
        finally:
            os.close(directory)

    def radio_on(self):
        return self.command(RADIO_ON) == (0, b"")

    def activate(self):
        result = self.command(UP, timeout=37)
        return result is not None and result[0] == 0

    def connected(self):
        return (self.command(ACTIVE) == (0, (UUID + ":wlan0\n").encode())
                and self.command(DEVICE) == (0, ("100 (connected)\nyes\n" + UUID + "\n").encode()))

    def radio_off(self):
        return self.command(RADIO_OFF, timeout=3, cleanup=True) == (0, b"")

    def radio_off_verified(self):
        return self.command(self.country_module["WIFI_STATE"], timeout=2, cleanup=True) == (0, b"v b false\n")

    def close(self):
        try:
            if self.country is not None:
                self.country.close()
        finally:
            if self.auth is not None:
                self.auth.close()


def empty_result():
    return {"schema_version": 1, "kind": "test-access-connect-result", "passed": False,
            "connected": False, "error": None, "live_evidence": False,
            "checks": dict.fromkeys(CHECKS, False), "radio_enable_attempted": False,
            "cleanup": {"required": False, "radio_off_attempted": False, "radio_off_acknowledged": False,
                        "radio_off_verified": False},
            "ssh_started": False, "application_activation_authorized": False,
            "hardware_qualified": False, "release_qualified": False,
            "limits": ["Country is observed during this invocation; no persisted receipt authorizes radio enable.",
                       "Locks and snapshots cannot exclude unrelated privileged clients or kernel changes.",
                       "Command timeout does not attest cancellation of a NetworkManager activation request.",
                       "Radio-off acknowledgement/readback is not an RF measurement.",
                       "No SSH, application or display operation is performed."]}


def connect(adapter):
    result = empty_result()
    try:
        adapter.deadline = time.monotonic() + BUDGET
        adapter.work_deadline = adapter.deadline - CLEANUP_RESERVE
        def checked(name, operation, error):
            require(time.monotonic() < adapter.work_deadline, "runtime_timeout")
            require(operation() is True, error)
            require(time.monotonic() < adapter.work_deadline, "runtime_timeout")
            result["checks"][name] = True
        for name, operation, error in (
                ("target_verified", adapter.target, "target_unverified"),
                ("sources_and_enrollment_bound", adapter.bind, "sources_invalid"),
                ("cache_authenticated", adapter.authenticate_cache, "cache_invalid"),
                ("bindings_unchanged_before_profile", adapter.unchanged, "state_changed"),
                ("profile_inventory_closed", adapter.profiles_closed, "other_profile_present"),
                ("wifi_initially_closed", adapter.wifi_closed, "wifi_not_closed"),
                ("runtime_profile_exact", adapter.publish_profile, "profile_write_failed"),
                ("profile_loaded", adapter.load_profile, "profile_load_failed"),
                ("loaded_profile_restricted", adapter.profile_restricted, "profile_unconfirmed"),
                ("country_live_verified", adapter.country_ready, "country_unconfirmed"),
                ("bindings_unchanged_before_radio", adapter.unchanged, "state_changed"),
                ("profile_inventory_still_closed", adapter.profiles_closed, "other_profile_present"),
                ("loaded_profile_still_restricted", adapter.profile_restricted, "profile_unconfirmed"),
                ("country_guard_immediately_before_radio", adapter.immediately_ready, "country_unconfirmed")):
            checked(name, operation, error)
        result["radio_enable_attempted"] = True
        checked("radio_enable_acknowledged", adapter.radio_on, "radio_enable_failed")
        checked("connection_acknowledged", adapter.activate, "connection_failed")
        checked("bindings_unchanged_after_connection", adapter.unchanged, "state_changed")
        checked("profile_inventory_unchanged_after_connection", adapter.profiles_closed, "other_profile_present")
        checked("loaded_profile_restricted_after_connection", adapter.profile_restricted, "profile_unconfirmed")
        checked("unique_wlan_connection_verified", adapter.connected, "connection_unconfirmed")
        result.update(passed=True, connected=True, live_evidence=type(adapter) is NativeAdapter)
    except (KeyboardInterrupt, SystemExit):
        result["error"] = "connect_failed"
    except Exception as error:
        result["error"] = str(error) if type(error) is ConnectError and str(error) in ERRORS else "connect_failed"
    finally:
        def close_radio():
            result["cleanup"].update(required=True, radio_off_attempted=True)
            try:
                result["cleanup"]["radio_off_acknowledged"] = adapter.radio_off() is True
            except BaseException:
                pass
            try:
                result["cleanup"]["radio_off_verified"] = adapter.radio_off_verified() is True
            except BaseException:
                pass
        if result["radio_enable_attempted"] and not result["passed"]:
            close_radio()
        try:
            adapter.close()
        except BaseException:
            if result["passed"] and result["radio_enable_attempted"]:
                close_radio()
            result.update(passed=False, connected=False, live_evidence=False, error="connect_failed")
    return result


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args:
        result = empty_result()
        result["error"] = "invalid_arguments"
    else:
        result = connect(NativeAdapter())
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
