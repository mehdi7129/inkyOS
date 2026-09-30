#!/usr/bin/env python3
"""Read-only observations for the prepared TEST LAN image, never activation.

Without --live no system observations are collected. The live entry point has
fixed command argv and no alternate root, imports no application code, and
never starts services, scans networks, refreshes a panel or changes state.
Panel runtime verification is deliberately pending a reviewed hardware method.
"""

import argparse
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import selectors
import stat
import subprocess
import sys
import time


SOURCE = "758a2bf7ed099aad41ef35316e53228e797b0b2b"
MANIFEST_HASH = "0d587792433d924ad1c4e71af19c2a46279f573791cb690571fa1019e7703551"
REVIEWED_APPLICATIONS = {
    "6a697d134290ced0214fc74b903f4b3c336d70fa": "2424fb9c32234ad7d359799f6b137e98298734023f0039afd1a57fbf265c250f",
    SOURCE: MANIFEST_HASH,
}
MARKER = "etc/inkyos-test-lan.json"
MANIFEST = "usr/local/share/inkyos/inky-studio-manifest-v1.json"
SOURCE_FILE = "home/inky/inky-studio/server/SOURCE_COMMIT"
PANEL_INVENTORY = "etc/inkyos-panel.json"
MAX_OUTPUT = 16384
COMMAND_TIMEOUT = 2.0
COMMAND_BUDGET = 20.0
TIME_TOLERANCE = 30
MAX_REFERENCE_AGE = 60
CHECKS = (
    "prepared_profile", "exact_payload_pin", "operator_access_confirmed",
    "firstboot_success", "app_stopped_and_masked", "helper_stopped_and_masked",
    "networkmanager_manages_connected_wlan0", "country_operator_confirmed",
    "country_global_matches", "country_phy_matches", "utc_synchronized",
    "independent_reference_recent", "utc_matches_independent_reference",
    "bluez_running", "hci0_powered", "bluetooth_unblocked", "system_packages_present",
    "application_hardware_metadata_present", "service_accounts_and_groups",
    "spi_i2c_gpio_nodes", "application_state_virgin", "helper_state_virgin",
    "panel_inventory_supplied_and_valid", "panel_runtime_evidence_verified",
)
COMMANDS = {
    "firstboot": ("/usr/bin/systemctl", "--no-pager", "show", "inkyos-firstboot.service", "--property=ActiveState,SubState,LoadState,Result,ExecMainStatus"),
    "app": ("/usr/bin/systemctl", "--no-pager", "show", "inky-studio.service", "--property=ActiveState,SubState,LoadState,UnitFileState"),
    "helper": ("/usr/bin/systemctl", "--no-pager", "show", "inky-network.service", "--property=ActiveState,SubState,LoadState,UnitFileState"),
    "nm_service": ("/usr/bin/systemctl", "--no-pager", "show", "NetworkManager.service", "--property=ActiveState,SubState,LoadState"),
    "nm": ("/usr/bin/nmcli", "--get-values", "GENERAL.STATE,GENERAL.NM-MANAGED", "device", "show", "wlan0"),
    "iw_interface": ("/usr/sbin/iw", "dev", "wlan0", "info"),
    "iw_reg": ("/usr/sbin/iw", "reg", "get"),
    # busctl --auto-start applies to call, not get-property. Properties.Get is
    # read-only and returns a variant; no service may be implicitly activated.
    "utc_sync": ("/usr/bin/busctl", "--system", "--auto-start=no", "--allow-interactive-authorization=no", "call", "org.freedesktop.timedate1", "/org/freedesktop/timedate1", "org.freedesktop.DBus.Properties", "Get", "ss", "org.freedesktop.timedate1", "NTPSynchronized"),
    "bluez": ("/usr/bin/systemctl", "--no-pager", "show", "bluetooth.service", "--property=ActiveState,SubState,LoadState"),
    "powered": ("/usr/bin/busctl", "--system", "--auto-start=no", "--allow-interactive-authorization=no", "call", "org.bluez", "/org/bluez/hci0", "org.freedesktop.DBus.Properties", "Get", "ss", "org.bluez.Adapter1", "Powered"),
    "rfkill": ("/usr/sbin/rfkill", "--noheadings", "--raw", "--output", "TYPE,SOFT,HARD"),
    "packages": ("/usr/bin/dpkg-query", "--show", "--showformat=${db:Status-Status}\\n", "bluez", "dbus", "python3-dbus", "network-manager", "iw", "rfkill", "i2c-tools"),
}
LIMITATIONS = (
    "Read-only observations never authorize activation, credentials or an initial display refresh.",
    "Operator assertions and local unsigned files are not attestations or independent provenance.",
    "Installed pin declarations and manifest hash do not rehash all installed payload files.",
    "Panel runtime evidence awaits a separately reviewed hardware observation without app import or refresh.",
    "The inventory parser supports reviewed variants 20/21/22/25 and their exact layouts only; it does not identify physical hardware.",
    "Custom PHY domains (98/99) remain unverified, not evidence that the operator country is wrong.",
    "These checks do not qualify TLS, HTTP, GATT, Wi-Fi transactions, recovery, hardware or a release.",
)


class UnsafeInput(ValueError):
    pass


class SafeParser(argparse.ArgumentParser):
    def error(self, _message):
        raise UnsafeInput("invalid_arguments")


def _json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise UnsafeInput("invalid_input")
            result[key] = value
        return result
    def invalid(_value):
        raise UnsafeInput("invalid_input")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=invalid, parse_float=invalid)
    except (ValueError, UnicodeError, RecursionError):
        raise UnsafeInput("invalid_input") from None


def _metadata(info, owners, *, directory=False):
    if (not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or info.st_uid not in owners or info.st_mode & 0o022
            or (not directory and info.st_nlink != 1)):
        raise UnsafeInput("unsafe_input")


class ReadStore:
    """Fixture-capable FD traversal; never open application data contents."""
    def __init__(self, root, *, owner_uid=0, app_uid=1000):
        self.owner_uid, self.app_uid = owner_uid, app_uid
        self.root_path = PurePosixPath(os.path.abspath(root))
        self.root = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            _metadata(os.fstat(self.root), {owner_uid}, directory=True)
        except BaseException:
            os.close(self.root)
            raise

    def close(self):
        os.close(self.root)

    def directory(self, path, *, owners=None):
        owners = owners or {self.owner_uid}
        parts = PurePosixPath(path).parts
        if PurePosixPath(path).is_absolute() or ".." in parts:
            raise UnsafeInput("unsafe_input")
        fd = os.dup(self.root)
        try:
            for part in parts:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                _metadata(os.fstat(fd), owners, directory=True)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def read(self, path, *, limit=65536, app_owned=False):
        owners = {self.owner_uid, self.app_uid} if app_owned else {self.owner_uid}
        item = PurePosixPath(path)
        parent = fd = None
        try:
            parent = self.directory(str(item.parent), owners=owners)
            fd = os.open(item.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(fd)
            _metadata(before, owners)
            if before.st_size > limit:
                raise UnsafeInput("invalid_input")
            chunks = bytearray()
            while len(chunks) <= limit:
                chunk = os.read(fd, min(4096, limit + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
            after = os.fstat(fd)
            _metadata(after, owners)
            current = os.stat(item.name, dir_fd=parent, follow_symlinks=False)
            _metadata(current, owners)
            if (len(chunks) > limit or
                    (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns)):
                raise UnsafeInput("invalid_input")
            return bytes(chunks)
        finally:
            if fd is not None:
                os.close(fd)
            if parent is not None:
                os.close(parent)

    def read_external(self, path, *, limit=4096):
        """Read only the fixed inventory path through secure root FDs."""
        # Reject arbitrary inputs before opening anything, including other
        # root-owned files that could contain credentials or private data.
        if type(path) is not str or path != str(self.root_path / PANEL_INVENTORY):
            raise UnsafeInput("unsafe_input")
        return self.read(PANEL_INVENTORY, limit=limit)

    def empty_state(self, path, owner):
        fd = None
        try:
            fd = self.directory(path, owners={self.owner_uid, owner})
            info = os.fstat(fd)
            if info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700:
                return False
            # Only names are counted. No credentials, database, keys, image or
            # helper journal is opened, copied, hashed or returned.
            with os.scandir(fd) as entries:
                return next(entries, None) is None
        except FileNotFoundError:
            return True
        except (OSError, UnsafeInput):
            return False
        finally:
            if fd is not None:
                os.close(fd)

    def application_state_virgin(self, owner):
        """Prepared layout: app-owned 0755 data with only empty 0755 photos/."""
        data = photos = None
        try:
            data = self.directory("var/lib/inky-studio", owners={self.owner_uid, owner})
            info = os.fstat(data)
            if info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o755:
                return False
            with os.scandir(data) as entries:
                first = next(entries, None)
                if first is None or first.name != "photos" or next(entries, None) is not None:
                    return False
            photos = os.open("photos", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=data)
            info = os.fstat(photos)
            _metadata(info, {owner}, directory=True)
            if stat.S_IMODE(info.st_mode) != 0o755:
                return False
            with os.scandir(photos) as entries:
                return next(entries, None) is None
        except (OSError, UnsafeInput):
            return False
        finally:
            if photos is not None:
                os.close(photos)
            if data is not None:
                os.close(data)


def bounded_command(argv, *, timeout, limit):
    process = None
    selector = selectors.DefaultSelector()
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, cwd="/", close_fds=True,
                                   env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C",
                                        "SYSTEMD_PAGER": "", "SYSTEMD_COLORS": "0"})
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        output = bytearray()
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            for key, _events in selector.select(remaining):
                chunk = os.read(key.fd, min(4096, limit + 1 - len(output)))
                if not chunk:
                    selector.unregister(key.fileobj)
                else:
                    output.extend(chunk)
                    if len(output) > limit:
                        return None
        remaining = deadline - time.monotonic()
        if remaining <= 0 or process.wait(timeout=remaining) != 0:
            return None
        return output.decode("utf-8")
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        return None
    finally:
        selector.close()
        if process is not None:
            if process.poll() is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                pass
            process.stdout.close()


def _properties(text, keys):
    if type(text) is not str or len(text) > MAX_OUTPUT:
        return None
    parsed = {}
    for line in text.splitlines():
        key, equals, value = line.partition("=")
        if not equals or key not in keys or key in parsed:
            return None
        parsed[key] = value
    return parsed if set(parsed) == set(keys) else None


def country_observed(interface, regulatory, expected):
    """Require explicit global AND matching wiphy country, never just exit 0."""
    if (type(interface) is not str or type(regulatory) is not str
            or type(expected) is not str or not re.fullmatch(r"[A-Z]{2}", expected)):
        return False, False
    phys = re.findall(r"(?m)^[ \t]*wiphy ([0-9]{1,3})$", interface)
    if len(phys) != 1:
        return False, False
    sections = {}
    current = None
    for line in regulatory.splitlines():
        if line == "global":
            current = "global"
        else:
            match = re.fullmatch(r"phy#([0-9]{1,3})(?: \(self-managed\))?", line)
            if match:
                current = match.group(1)
            elif line.startswith("phy#"):
                return False, False
        match = re.fullmatch(r"[ \t]*country ([A-Z0-9]{2}):[ A-Z0-9-]*", line)
        if match:
            if current is None or current in sections:
                return False, False
            sections[current] = match.group(1)
    return sections.get("global") == expected, sections.get(phys[0]) == expected


def valid_panel_inventory(value):
    keys = {"schema_version", "display_variant", "panel_reference", "width", "height", "physical_label_confirmed"}
    if type(value) is not dict or set(value) != keys:
        return False
    return (type(value["schema_version"]) is int and value["schema_version"] == 1
            and type(value["display_variant"]) is int
            and type(value["panel_reference"]) is str
            and type(value["width"]) is int and type(value["height"]) is int
            and (value["display_variant"], value["panel_reference"], value["width"], value["height"]) in {
                (20, "AC073TC1A", 800, 480), (21, "EL133UF1", 1600, 1200),
                (22, "E673", 800, 480), (25, "E640", 600, 400),
            }
            and value["physical_label_confirmed"] is True)


class LiveAdapter:
    def __init__(self, *, store=None, command=bounded_command, utc=time.time, monotonic=time.monotonic):
        self.store = store
        self.command = command
        self.utc = utc
        self.monotonic = monotonic
        self.native_live = (store is None and command is bounded_command
                            and utc is time.time and monotonic is time.monotonic)

    def _accounts(self, store):
        passwd = store.read("etc/passwd", limit=256 * 1024).decode("utf-8").splitlines()
        groups = store.read("etc/group", limit=256 * 1024).decode("utf-8").splitlines()
        users = [line.split(":") for line in passwd]
        rows = [line.split(":") for line in groups]
        if not all(len(row) == 7 for row in users) or not all(len(row) == 4 for row in rows):
            raise UnsafeInput("invalid_input")
        selected = {}
        for name in ("inky", "inky-network"):
            matches = [row for row in users if row[0] == name]
            if len(matches) != 1 or not all(re.fullmatch(r"[0-9]{1,10}", matches[0][index]) for index in (2, 3)):
                raise UnsafeInput("invalid_input")
            selected[name] = matches[0]
        names = ("spi", "i2c", "gpio", "inky-provisioning")
        selected_groups = {}
        for name in names:
            matches = [row for row in rows if row[0] == name]
            if len(matches) != 1 or not re.fullmatch(r"[0-9]{1,10}", matches[0][2]):
                raise UnsafeInput("invalid_input")
            selected_groups[name] = matches[0]
        app, helper = selected["inky"], selected["inky-network"]
        membership = {row[0] for row in rows if row[2] == app[3] or "inky" in row[3].split(",")}
        helper_membership = {row[0] for row in rows if row[2] == helper[3] or "inky-network" in row[3].split(",")}
        safe = (int(app[2]) == 1000 and 0 < int(helper[2]) < 1000
                and app[6] == helper[6] == "/usr/sbin/nologin"
                and set(names) <= membership and not {"root", "sudo", "admin", "netdev"} & membership
                and helper_membership == {"inky-provisioning"}
                and sum(row[2] == app[2] for row in users) == 1
                and sum(row[2] == helper[2] for row in users) == 1
                and helper[3] == selected_groups["inky-provisioning"][2])
        return safe, int(app[2]), int(helper[2]), {key: int(row[2]) for key, row in selected_groups.items()}

    def collect(self, request):
        facts = {key: False for key in CHECKS}
        owns_store = self.store is None
        store = self.store or ReadStore("/")
        started = self.monotonic()
        deadline = started + COMMAND_BUDGET
        def query(key):
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                return None
            value = self.command(COMMANDS[key], timeout=min(COMMAND_TIMEOUT, remaining), limit=MAX_OUTPUT)
            return value if type(value) is str and len(value) <= MAX_OUTPUT else None
        def safe_read(path, **kwargs):
            try:
                return store.read(path, **kwargs)
            except (OSError, UnsafeInput, UnicodeError):
                return None
        try:
            marker_raw = safe_read(MARKER)
            try:
                marker = _json(marker_raw) if marker_raw is not None else None
            except UnsafeInput:
                marker = None
            facts["prepared_profile"] = (type(marker) is dict and type(marker.get("schema_version")) is int
                and marker["schema_version"] == 1 and marker.get("kind") == "test-lan-prepared"
                and marker.get("state") == "prepared-inactive" and marker.get("application_runtime") == "masked"
                and marker.get("activation_authorized") is False and marker.get("ready_for_activation") is False
                and marker.get("factory_authority") is False)
            # Wrong/missing profile: no commands run against an unrelated host.
            if not facts["prepared_profile"]:
                return facts
            manifest, source = safe_read(MANIFEST), safe_read(SOURCE_FILE, limit=256, app_owned=True)
            source_pin, manifest_pin = marker.get("source_commit"), marker.get("manifest_sha256")
            facts["exact_payload_pin"] = (
                type(source_pin) is str and type(manifest_pin) is str
                and REVIEWED_APPLICATIONS.get(source_pin) == manifest_pin
                and manifest is not None and source in {source_pin.encode(), (source_pin + "\n").encode()}
                and hashlib.sha256(manifest).hexdigest() == manifest_pin)
            if not facts["exact_payload_pin"]:
                return facts
            firstboot = _properties(query("firstboot"), {"ActiveState", "SubState", "LoadState", "Result", "ExecMainStatus"})
            facts["firstboot_success"] = firstboot == {"ActiveState": "active", "SubState": "exited", "LoadState": "loaded", "Result": "success", "ExecMainStatus": "0"}
            for key, check in (("app", "app_stopped_and_masked"), ("helper", "helper_stopped_and_masked")):
                values = _properties(query(key), {"ActiveState", "SubState", "LoadState", "UnitFileState"})
                facts[check] = values == {"ActiveState": "inactive", "SubState": "dead", "LoadState": "masked", "UnitFileState": "masked"}
            nm_service = _properties(query("nm_service"), {"ActiveState", "SubState", "LoadState"})
            if nm_service == {"ActiveState": "active", "SubState": "running", "LoadState": "loaded"}:
                facts["networkmanager_manages_connected_wlan0"] = query("nm") == "100 (connected)\nyes\n"
            interface, regulatory = query("iw_interface"), query("iw_reg")
            facts["country_global_matches"], facts["country_phy_matches"] = country_observed(interface, regulatory, request["country"])
            facts["utc_synchronized"] = query("utc_sync") == "v b true\n"
            if request["reference_valid"]:
                age = request["utc_reference_age"] + max(0, self.monotonic() - started)
                facts["independent_reference_recent"] = age <= MAX_REFERENCE_AGE
                current = self.utc()
                facts["utc_matches_independent_reference"] = (type(current) in {int, float}
                    and facts["independent_reference_recent"]
                    and abs(current - (request["utc_reference"] + age)) <= TIME_TOLERANCE)
            bluez = _properties(query("bluez"), {"ActiveState", "SubState", "LoadState"})
            facts["bluez_running"] = bluez == {"ActiveState": "active", "SubState": "running", "LoadState": "loaded"}
            if facts["bluez_running"]:
                facts["hci0_powered"] = query("powered") == "v b true\n"
            rfkill = query("rfkill")
            if type(rfkill) is str:
                rows = [line.split() for line in rfkill.splitlines()]
                entries = [row for row in rows if row and row[0] == "bluetooth"]
                facts["bluetooth_unblocked"] = entries == [["bluetooth", "unblocked", "unblocked"]]
            packages = query("packages")
            facts["system_packages_present"] = packages == "installed\n" * 7
            try:
                accounts, app_uid, helper_uid, groups = self._accounts(store)
                facts["service_accounts_and_groups"] = accounts
                facts["application_state_virgin"] = store.application_state_virgin(app_uid)
                facts["helper_state_virgin"] = (store.empty_state("var/lib/inky-network", helper_uid)
                    and store.empty_state("run/inky-network", helper_uid))
                node_ok = []
                for path, group in (("dev/spidev0.0", "spi"), ("dev/i2c-1", "i2c"), ("dev/gpiochip0", "gpio")):
                    directory = store.directory("dev")
                    try:
                        info = os.stat(PurePosixPath(path).name, dir_fd=directory, follow_symlinks=False)
                        node_ok.append(stat.S_ISCHR(info.st_mode) and info.st_uid == store.owner_uid
                            and info.st_gid == groups[group] and info.st_mode & 0o660 == 0o660 and not info.st_mode & 0o007)
                    finally:
                        os.close(directory)
                facts["spi_i2c_gpio_nodes"] = all(node_ok)
            except (OSError, UnsafeInput, UnicodeError, ValueError):
                pass
            directory = None
            try:
                directory = store.directory("home/inky/inky-studio/server/.venv/lib/python3.13/site-packages", owners={store.owner_uid, store.app_uid})
                names = []
                with os.scandir(directory) as entries:
                    for entry in entries:
                        if len(names) == 2048:
                            raise UnsafeInput("invalid_input")
                        names.append(entry.name)
                required = ("inky-2.3.0.dist-info", "spidev-", "gpiod-", "gpiodevice-", "dbus_fast-", "cryptography-", "pillow-")
                present = []
                for prefix in required:
                    candidates = [name for name in names if (name == prefix if prefix.endswith(".dist-info") else name.startswith(prefix) and name.endswith(".dist-info"))]
                    present.append(len(candidates) == 1 and stat.S_ISDIR(os.stat(candidates[0], dir_fd=directory, follow_symlinks=False).st_mode))
                facts["application_hardware_metadata_present"] = all(present)
            except (OSError, UnsafeInput):
                pass
            finally:
                if directory is not None:
                    os.close(directory)
            if request["panel_inventory"] is not None:
                try:
                    facts["panel_inventory_supplied_and_valid"] = valid_panel_inventory(
                        _json(store.read_external(request["panel_inventory"], limit=4096)))
                except (OSError, UnsafeInput, ValueError, TypeError):
                    pass
            # No known sysfs EEPROM client exists at this pin. A file claiming
            # evidence is insufficient. Never import inky.auto or open buses.
            facts["panel_runtime_evidence_verified"] = False
            return facts
        finally:
            if owns_store:
                store.close()


def preflight(adapter=None, *, live=False, operator_access_confirmed=False,
              country=None, country_confirmed=False, utc_reference=None,
              utc_reference_age=None, utc_reference_source=None, panel_inventory=None):
    facts = {key: False for key in CHECKS}
    output = {"schema_version": 1, "kind": "test-lan-preflight", "live_selected": live is True,
              "scope": "test_lan_preconditions_only",
              "checks": {}, "passed": False, "activation_authorized": False,
              "live_evidence": False,
              "observation_source": "inactive",
              "hardware_qualified": False, "release_qualified": False,
              "limitations": list(LIMITATIONS), "error": None}
    reference_valid = (type(utc_reference) is int and 1767225600 <= utc_reference <= 2524608000
                       and type(utc_reference_age) is int and 0 <= utc_reference_age <= MAX_REFERENCE_AGE
                       and type(utc_reference_source) is str and utc_reference_source in {"independent-device", "gnss"})
    country_valid = type(country) is str and re.fullmatch(r"[A-Z]{2}", country) is not None
    request = {"country": country if country_valid else None, "reference_valid": reference_valid,
               "utc_reference": utc_reference, "utc_reference_age": utc_reference_age,
               "panel_inventory": panel_inventory}
    if live is True and adapter is not None:
        output["observation_source"] = ("live-system" if type(adapter) is LiveAdapter and adapter.native_live else "fixture")
        try:
            observed = adapter.collect(request)
            if type(observed) is dict:
                facts = {key: observed.get(key) is True for key in CHECKS}
                output["live_evidence"] = output["observation_source"] == "live-system"
        except Exception:
            output["error"] = "observations_unavailable"
    facts["operator_access_confirmed"] = live is True and operator_access_confirmed is True
    facts["country_operator_confirmed"] = live is True and country_valid and country_confirmed is True
    facts["independent_reference_recent"] = live is True and reference_valid and facts["independent_reference_recent"]
    reasons = {"panel_runtime_evidence_verified": "panel_runtime_observation_pending",
               "application_state_virgin": "existing_or_unsafe_state_requires_explicit_review",
               "helper_state_virgin": "existing_or_unsafe_state_requires_explicit_review"}
    for key in CHECKS:
        ok = facts[key]
        reason = None if ok else ("live_not_selected" if live is not True else reasons.get(key, "precondition_unverified"))
        output["checks"][key] = {"passed": ok, "status": "PASS" if ok else "BLOCKED", "reason": reason}
    output["passed"] = all(facts.values())
    return output


def main(argv=None):
    parser = SafeParser(prog="test-lan-preflight.py", description=__doc__, allow_abbrev=False)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--operator-access-confirmed", action="store_true")
    parser.add_argument("--country")
    parser.add_argument("--country-confirmed", action="store_true")
    parser.add_argument("--utc-reference", type=int)
    parser.add_argument("--utc-reference-age", type=int)
    parser.add_argument("--utc-reference-source", choices=("independent-device", "gnss"))
    parser.add_argument("--panel-inventory", choices=("/" + PANEL_INVENTORY,))
    try:
        args = parser.parse_args(argv)
        adapter = None
        if args.live and sys.platform.startswith("linux") and os.geteuid() == 0:
            adapter = LiveAdapter()
        result = preflight(adapter, live=args.live, operator_access_confirmed=args.operator_access_confirmed,
                           country=args.country, country_confirmed=args.country_confirmed,
                           utc_reference=args.utc_reference, utc_reference_age=args.utc_reference_age,
                           utc_reference_source=args.utc_reference_source, panel_inventory=args.panel_inventory)
        if args.live and adapter is None:
            result["error"] = "linux_root_required"
        code = 0 if result["passed"] else 1
    except UnsafeInput:
        result = preflight()
        result["error"] = "invalid_arguments"
        code = 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    sys.exit(main())
