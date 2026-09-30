#!/usr/bin/python3 -I
"""Private TEST enrollment: fresh host key, local FAT report, then power off.

Inactive by default. No network profile, radio setter, app/SSH start or private
key read. Incomplete artifacts are preserved and require explicit review.
"""
import sys
sys.dont_write_bytecode = True

import argparse
import base64
import ctypes
import hashlib
import json
import os
import platform
import re
import selectors
import stat
import struct
import subprocess
import time


SOURCE = "758a2bf7ed099aad41ef35316e53228e797b0b2b"
MANIFEST_HASH = "0d587792433d924ad1c4e71af19c2a46279f573791cb690571fa1019e7703551"
PARENT_IMAGE_SHA256 = "4cd9d6fa8183dfb8a7a04c350ab3d3366900264fab2fa0dff90192a7e4cc9a04"
PROFILE_PATH = "/etc/inkyos-test-enrollment/profile.json"
STATE_PATH = "/var/lib/inkyos-test-enrollment/state.json"
PUBLIC_REPORT_PATH = "/boot/firmware/inkyos-test-enrollment.json"
SCRIPT_PATH = "/usr/local/lib/inkyos/test-enrollment-firstboot.py"
PANEL_PATH = "/usr/local/lib/inkyos/observe-test-panel.py"
RADIO_PATH = "/usr/local/lib/inkyos/observe-test-radio.py"
HOST_KEY_PATH = "/etc/inkyos-test-enrollment/ssh_host_ed25519_key"
MODEL_PATH = "/sys/firmware/devicetree/base/model"
MARKER_PATH = "/etc/inkyos-test-lan.json"
PI_MODEL = b"Raspberry Pi Zero 2 W Rev 1.0\x00"
GUARDS = ("prepared_profile", "exact_payload_pin", "firstboot_success",
          "app_stopped_and_masked", "helper_stopped_and_masked")
FALSE_FIELDS = ("network_profile_present", "ssh_access_enabled",
                "application_activation_authorized", "hardware_qualified", "release_qualified")
PROFILE_FIELDS = {"schema_version", "kind", "purpose", "state", "application_source_commit",
                  "application_manifest_sha256", "parent_image_sha256", "operator_public_key",
                  "challenge", "country_requested", *FALSE_FIELDS}
KEYGEN = ("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "inkyos-test-host", "-f", HOST_KEY_PATH)
SYNC = ("/usr/bin/sync",)
POWEROFF = ("/usr/bin/systemctl", "--no-block", "poweroff")
MAX_OBSERVER_OUTPUT = 32768
RUNTIME_BUDGET = 85.0


class EnrollmentError(ValueError):
    pass


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise EnrollmentError("invalid_input")
            result[key] = value
        return result
    def invalid(_value):
        raise EnrollmentError("invalid_input")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=invalid, parse_float=invalid)
    except (ValueError, UnicodeError, RecursionError, AttributeError):
        raise EnrollmentError("invalid_input") from None


def public_key(value):
    if type(value) is not str or not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]{68}", value):
        return None
    try:
        wire = base64.b64decode(value.split(" ")[1], validate=True)
    except (ValueError, base64.binascii.Error):
        return None
    if (len(wire) != 51 or wire[:19] != struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32)
            or base64.b64encode(wire).decode("ascii") != value.split(" ")[1]):
        return None
    return wire


def validate_profile(data):
    return (type(data) is dict and set(data) == PROFILE_FIELDS
            and type(data["schema_version"]) is int and data["schema_version"] == 1
            and all(type(data[key]) is str for key in ("kind", "purpose", "state", "application_source_commit",
                    "application_manifest_sha256", "parent_image_sha256", "country_requested"))
            and data["kind"] == "test-lan-enrollment" and data["purpose"] == "test-enroll-and-stop"
            and data["state"] == "enrollment-pending"
            and data["application_source_commit"] == SOURCE and data["application_manifest_sha256"] == MANIFEST_HASH
            and data["parent_image_sha256"] == PARENT_IMAGE_SHA256 and data["country_requested"] == "FR"
            and public_key(data["operator_public_key"]) is not None
            and type(data["challenge"]) is str and re.fullmatch(r"[0-9a-f]{64}", data["challenge"]) is not None
            and data["challenge"] != "0" * 64 and all(data[name] is False for name in FALSE_FIELDS))


def _metadata(info, owner=0, *, directory=False, mode=None, fat=False):
    if (not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or info.st_uid != owner or not directory and info.st_nlink != 1
            or not fat and info.st_mode & 0o022
            or mode is not None and stat.S_IMODE(info.st_mode) != mode):
        raise EnrollmentError("unsafe_path")


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class Files:
    """Fixed runtime paths; fixture root is available only to Python tests."""
    def __init__(self, root="/", *, owner=0):
        self.owner = owner
        self.root = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            _metadata(os.fstat(self.root), owner, directory=True)
        except BaseException:
            os.close(self.root)
            raise

    def close(self):
        os.close(self.root)

    def directory(self, path, *, private=False, fat=False):
        parts = path.lstrip("/").split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise EnrollmentError("unsafe_path")
        fd = os.dup(self.root)
        try:
            for index, part in enumerate(parts):
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                _metadata(os.fstat(fd), self.owner, directory=True,
                          mode=0o700 if private and index == len(parts) - 1 else None,
                          fat=fat and index == len(parts) - 1)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def read(self, path, *, limit=4096, mode=None, private=False):
        parent = self.directory(path.rsplit("/", 1)[0], private=private)
        fd = None
        name = path.rsplit("/", 1)[1]
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(fd)
            _metadata(before, self.owner, mode=mode)
            if before.st_size > limit:
                raise EnrollmentError("oversized_input")
            raw = bytearray()
            while len(raw) <= limit:
                chunk = os.read(fd, min(4096, limit + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            after = os.fstat(fd)
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            _metadata(after, self.owner, mode=mode)
            _metadata(current, self.owner, mode=mode)
            if len(raw) > limit or _stamp(before) != _stamp(after) or _stamp(after) != _stamp(current):
                raise EnrollmentError("unstable_input")
            return bytes(raw)
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent)


def mount_is_fat(mountinfo, fdinfo, device):
    """Select the record for the open FD, including legitimate sandbox binds."""
    try:
        rows = [line for line in fdinfo.splitlines() if line.startswith(b"mnt_id:")]
        if len(rows) != 1:
            return False
        matched = re.fullmatch(rb"mnt_id:[ \t]+([0-9]{1,10})", rows[0])
        if matched is None:
            return False
        selected = int(matched[1])
        records = []
        for line in mountinfo.decode("ascii").splitlines():
            head, tail = line.split(" - ", 1)
            left, right = head.split(), tail.split()
            if len(left) < 6 or len(right) < 3:
                return False
            if int(left[0]) == selected:
                records.append((left, right))
        if len(records) != 1:
            return False
        left, right = records[0]
        return (left[4] == "/boot/firmware" and right[0] == "vfat" and "rw" in left[5].split(",")
                and left[2] == f"{os.major(device)}:{os.minor(device)}")
    except (ValueError, UnicodeError, TypeError):
        return False


def rename_noreplace(directory, source, target):
    # Linux renameat2(RENAME_NOREPLACE), supported by vfat since Linux 4.9.
    # Refuse unsupported ABI/filesystems; never fall back to replacing a file.
    libc = ctypes.CDLL(None, use_errno=True)
    operation = getattr(libc, "renameat2", None)
    if operation is None:
        raise EnrollmentError("atomic_unsupported")
    operation.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    operation.restype = ctypes.c_int
    if operation(directory, source.encode(), directory, target.encode(), 1) != 0:
        raise EnrollmentError("atomic_write_refused")


def write_atomic(directory, name, raw, *, mode=0o600, replace_stamp=None, owner=0,
                 rename=rename_noreplace, fat=False, published=None):
    temporary = "." + name + ".tmp"
    fd = None
    if replace_stamp is None:
        try:
            os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise EnrollmentError("existing_artifact")
    else:
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        _metadata(info, owner, mode=0o600)
        if _stamp(info) != replace_stamp:
            raise EnrollmentError("state_changed")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK,
                     mode, dir_fd=directory)
        if not fat:
            os.fchmod(fd, mode)
        info = os.fstat(fd)
        _metadata(info, owner, mode=None if fat else mode, fat=fat)
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            if count <= 0:
                raise EnrollmentError("write_failed")
            offset += count
        os.fsync(fd)
        os.close(fd)
        fd = None
        if replace_stamp is None:
            rename(directory, temporary, name)
        else:
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            _metadata(current, owner, mode=0o600)
            if _stamp(current) != replace_stamp:
                raise EnrollmentError("state_changed")
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        stamp = _stamp(os.stat(name, dir_fd=directory, follow_symlinks=False))
        if published is not None:
            published(stamp)
        os.fsync(directory)
        return stamp
    finally:
        if fd is not None:
            os.close(fd)
        # Partial files, including our exclusive temp, are preserved for review.


def command(argv, *, timeout, limit=MAX_OBSERVER_OUTPUT):
    child = None
    selector = selectors.DefaultSelector()
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, cwd="/", close_fds=True,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C"})
        os.set_blocking(child.stdout.fileno(), False)
        selector.register(child.stdout, selectors.EVENT_READ)
        deadline, raw = time.monotonic() + timeout, bytearray()
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            for key, _events in selector.select(remaining):
                chunk = os.read(key.fd, min(4096, limit + 1 - len(raw)))
                if not chunk:
                    selector.unregister(key.fileobj)
                else:
                    raw.extend(chunk)
                    if len(raw) > limit:
                        return None
        remaining = deadline - time.monotonic()
        return (child.wait(timeout=max(0.01, remaining)), bytes(raw)) if remaining > 0 else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    finally:
        selector.close()
        if child is not None:
            if child.poll() is None:
                child.kill()
                try:
                    child.wait(timeout=0.2)
                except subprocess.TimeoutExpired:
                    pass
            child.stdout.close()


def reduced_observation(value, kind):
    """Only validated public fields survive; arbitrary JSON/logs never pass."""
    empty = {"status": "blocked", "live_evidence": False, "data": None}
    if type(value) is not dict or value.get("schema_version") != 1 or type(value.get("schema_version")) is not int:
        return empty
    expected_kind = "test-panel-observation" if kind == "panel" else "test-radio-observation"
    if (value.get("kind") != expected_kind or value.get("observation_source") != "live-system"
            or any(value.get(key) is not False for key in ("activation_authorized", "hardware_qualified", "release_qualified"))
            or type(value.get("live_evidence")) is not bool):
        return empty
    if kind == "panel":
        panel = value.get("panel")
        fields = {"display_variant", "panel_reference", "width", "height", "color_code", "color", "driver_class"}
        catalogue = {
            (20, "AC073TC1A", 800, 480, 5, "7colour", "inky.inky_ac073tc1a.Inky"),
            (21, "EL133UF1", 1600, 1200, 6, "spectra6", "inky.inky_el133uf1.Inky"),
            (22, "E673", 800, 480, 6, "spectra6", "inky.inky_e673.Inky"),
            (25, "E640", 600, 400, 6, "spectra6", "inky.inky_e640.Inky"),
        }
        if (type(panel) is not dict or set(panel) != fields or value.get("passed") is not True
                or value.get("live_evidence") is not True or value.get("status") != "PASS"
                or any(type(panel[key]) is not int for key in ("display_variant", "width", "height", "color_code"))
                or any(type(panel[key]) is not str for key in ("panel_reference", "color", "driver_class"))
                or tuple(panel[key] for key in ("display_variant", "panel_reference", "width", "height", "color_code", "color", "driver_class")) not in catalogue):
            return empty
        return {"status": "observed", "live_evidence": True, "data": panel}
    if (value.get("passed") is not False or value.get("firmware_tuple_qualified") is not False
            or value.get("status") != "BLOCKED" or value.get("observations_complete") is not True
            or value.get("live_evidence") is not True):
        return empty
    firmware, kernel, channels = value.get("firmware"), value.get("kernel"), value.get("channels_2_4ghz")
    if (type(firmware) is not dict or set(firmware) != {"country_abbrev", "ccode", "revision"}
            or any(type(firmware[key]) is not str or re.fullmatch(r"[A-Z0-9]{2}", firmware[key]) is None for key in ("country_abbrev", "ccode"))
            or type(firmware["revision"]) is not int or not -1 <= firmware["revision"] <= 65535
            or type(kernel) is not dict or set(kernel) != {"global_country", "phy_country_label", "phy_custom", "phy_self_managed"}
            or any(type(kernel[key]) is not str or re.fullmatch(r"[A-Z0-9]{2}", kernel[key]) is None for key in ("global_country", "phy_country_label"))
            or any(type(kernel[key]) is not bool for key in ("phy_custom", "phy_self_managed"))
            or type(channels) is not list or not 1 <= len(channels) <= 14):
        return empty
    frequencies = set()
    for row in channels:
        if (type(row) is not dict or set(row) != {"frequency_mhz", "channel", "disabled", "max_tx_power_mbm", "flags"}
                or type(row["frequency_mhz"]) is not int or type(row["channel"]) is not int or not 1 <= row["channel"] <= 14
                or row["frequency_mhz"] != (2484 if row["channel"] == 14 else 2407 + 5 * row["channel"])
                or row["frequency_mhz"] in frequencies or type(row["disabled"]) is not bool
                or type(row["flags"]) is not list or any(type(flag) is not str for flag in row["flags"])
                or len(set(row["flags"])) != len(row["flags"]) or not set(row["flags"]) <= {"no IR", "passive scan", "no ibss", "radar detection"}
                or row["disabled"] and (row["max_tx_power_mbm"] is not None or row["flags"])
                or not row["disabled"] and (type(row["max_tx_power_mbm"]) is not int or not 0 <= row["max_tx_power_mbm"] <= 4000)):
            return empty
        frequencies.add(row["frequency_mhz"])
    return {"status": "observed-unqualified", "live_evidence": True,
            "data": {"firmware": firmware, "kernel": kernel, "channels_2_4ghz": channels}}


class NativeAdapter:
    def __init__(self):
        self.files = Files()
        self.fds = []
        self.state_stamp = None
        self.deadline = time.monotonic() + RUNTIME_BUDGET

    def environment(self):
        return (sys.platform.startswith("linux") and os.geteuid() == 0 and platform.machine() == "aarch64"
                and sys.byteorder == "little" and self.files.read(MODEL_PATH, limit=128) == PI_MODEL)

    def profile(self):
        return self.files.read(PROFILE_PATH, limit=4096, mode=0o600, private=True)

    def source(self, path):
        return self.files.read(path, limit=65536, mode=0o555)

    def guards(self):
        marker_raw = self.files.read(MARKER_PATH, limit=4096, mode=0o644)
        marker = strict_json(marker_raw)
        # The shared observer guard also supports a historical application.
        # Enrollment only declares the final pin, so constrain that guard to it.
        blocked = {key: False for key in GUARDS}
        if (type(marker) is not dict or marker.get("source_commit") != SOURCE
                or marker.get("manifest_sha256") != MANIFEST_HASH):
            return blocked
        namespace = {"__name__": "inkyos_enrollment_radio_guard", "__file__": RADIO_PATH}
        exec(compile(self.source(RADIO_PATH), RADIO_PATH, "exec"), namespace)
        facts = namespace["PreparedGuard"]().collect()
        # The shared guard recouples this marker against the installed manifest
        # and app-owned declaration through its own safe readers, not execution.
        if self.files.read(MARKER_PATH, limit=4096, mode=0o644) != marker_raw:
            return blocked
        return facts

    def run(self, argv, timeout, limit=MAX_OBSERVER_OUTPUT):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise EnrollmentError("runtime_timeout")
        return command(argv, timeout=min(timeout, remaining), limit=limit)

    def fresh(self):
        self.private = self.files.directory(PROFILE_PATH.rsplit("/", 1)[0], private=True)
        self.fds.append(self.private)
        self.state = self.files.directory(STATE_PATH.rsplit("/", 1)[0], private=True)
        self.fds.append(self.state)
        self.boot = self.files.directory("/boot/firmware", fat=True)
        self.fds.append(self.boot)
        with os.scandir(self.private) as items:
            first = next(items, None)
            if first is None or first.name != "profile.json" or next(items, None) is not None:
                raise EnrollmentError("existing_artifact")
        with os.scandir(self.state) as items:
            if next(items, None) is not None:
                raise EnrollmentError("existing_artifact")
        for name in ("inkyos-test-enrollment.json", ".inkyos-test-enrollment.json.tmp"):
            try:
                os.stat(name, dir_fd=self.boot, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise EnrollmentError("existing_artifact")
        pid = os.getpid()
        if not mount_is_fat(self.files.read(f"/proc/{pid}/mountinfo", limit=1024 * 1024),
                            self.files.read(f"/proc/{pid}/fdinfo/{self.boot}", limit=4096), os.fstat(self.boot).st_dev):
            raise EnrollmentError("boot_mount_unverified")
        self.runtime_hash = hashlib.sha256(self.source(SCRIPT_PATH)).hexdigest()
        for path in (PANEL_PATH, RADIO_PATH):
            self.source(path)

    def write_state(self, state, profile_hash):
        value = {"schema_version": 1, "kind": "test-lan-enrollment-state", "state": state,
                 "profile_sha256": profile_hash, "application_activation_authorized": False}
        write_atomic(self.state, "state.json", canonical(value), replace_stamp=self.state_stamp,
                     published=lambda stamp: setattr(self, "state_stamp", stamp))

    def key(self):
        for name in ("ssh_host_ed25519_key", "ssh_host_ed25519_key.pub"):
            try:
                os.stat(name, dir_fd=self.private, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise EnrollmentError("existing_artifact")
        if self.run(KEYGEN, 8, limit=4096) != (0, b""):
            raise EnrollmentError("host_key_incomplete")
        # Only stat the PRIVATE key; never open/read/hash/copy its contents.
        info = os.stat("ssh_host_ed25519_key", dir_fd=self.private, follow_symlinks=False)
        _metadata(info, mode=0o600)
        if not 0 < info.st_size <= 4096:
            raise EnrollmentError("host_key_incomplete")
        public_fd = os.open("ssh_host_ed25519_key.pub", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.private)
        try:
            _metadata(os.fstat(public_fd))
            os.fchmod(public_fd, 0o644)
            os.fsync(public_fd)
        finally:
            os.close(public_fd)
        raw = self.files.read(HOST_KEY_PATH + ".pub", limit=256, mode=0o644, private=True)
        match = re.fullmatch(rb"(ssh-ed25519 [A-Za-z0-9+/]{68}) inkyos-test-host\n", raw)
        if match is None:
            raise EnrollmentError("host_key_incomplete")
        value = match[1].decode("ascii")
        if public_key(value) is None:
            raise EnrollmentError("host_key_incomplete")
        os.fsync(self.private)
        return value

    def observations(self):
        output = {}
        for kind, path, options, timeout in (("panel", PANEL_PATH, ("--live",), 15),
                                             ("radio", RADIO_PATH, ("--live", "--country", "FR"), 20)):
            try:
                result = self.run(("/usr/bin/python3", "-I", path, *options), timeout)
                value = strict_json(result[1]) if result is not None and result[0] in {0, 1} else None
                output[kind] = reduced_observation(value, kind)
            except Exception:
                output[kind] = {"status": "blocked", "live_evidence": False, "data": None}
        return output

    def report(self, value):
        write_atomic(self.boot, "inkyos-test-enrollment.json", canonical(value), fat=True)

    def sync(self):
        if self.run(SYNC, 3, limit=4096) != (0, b""):
            raise EnrollmentError("sync_failed")

    def poweroff(self):
        result = self.run(POWEROFF, 3, limit=4096)
        return result is not None and result[0] == 0

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.files.close()


def enroll(adapter=None, *, live=False):
    summary = {"schema_version": 1, "kind": "test-enrollment-runtime", "live_selected": live is True,
               "live_evidence": False, "state": "blocked", "report_written": False,
               "poweroff_requested": False, "passed": False, "error": None,
               **{key: False for key in FALSE_FIELDS}}
    if live is not True or adapter is None:
        return summary
    eligible = own_state = False
    profile_hash = profile = host = None
    native = type(adapter) is NativeAdapter
    try:
        if adapter.environment() is not True:
            raise EnrollmentError("target_unverified")
        raw = adapter.profile()
        profile = strict_json(raw)
        if not validate_profile(profile) or raw != canonical(profile):
            raise EnrollmentError("profile_invalid")
        profile_hash = hashlib.sha256(raw).hexdigest()
        guards = adapter.guards()
        if type(guards) is not dict or any(guards.get(key) is not True for key in GUARDS):
            raise EnrollmentError("prepared_guards_blocked")
        eligible = native
        adapter.fresh()
        adapter.write_state("pending", profile_hash)
        own_state = True
        host = adapter.key()
        wire = public_key(host)
        if wire is None:
            raise EnrollmentError("host_key_incomplete")
        observed = adapter.observations()
        # The trusted runtime adapter already reduces native outputs. Fixtures
        # cannot inject identity data into the report or claim native evidence.
        if type(observed) is not dict or set(observed) != {"panel", "radio"}:
            raise EnrollmentError("observations_invalid")
        if not native:
            observed = {key: {"status": "blocked", "live_evidence": False, "data": None} for key in ("panel", "radio")}
        report = {"schema_version": 1, "kind": "test-lan-enrollment-report", "state": "enrolled",
            "challenge": profile["challenge"], "application_source_commit": SOURCE,
            "application_manifest_sha256": MANIFEST_HASH, "parent_image_sha256": PARENT_IMAGE_SHA256,
            "profile_sha256": profile_hash, "host_public_key": host,
            "host_public_key_sha256": hashlib.sha256(wire).hexdigest(),
            "runtime_source_sha256": adapter.runtime_hash, "observations": observed,
            "live_evidence": native, **{key: False for key in FALSE_FIELDS}}
        if type(report["runtime_source_sha256"]) is not str or re.fullmatch(r"[0-9a-f]{64}", report["runtime_source_sha256"]) is None:
            raise EnrollmentError("runtime_source_invalid")
        adapter.report(report)
        summary["report_written"] = True
        adapter.write_state("enrolled", profile_hash)
        summary.update(state="enrolled", passed=True, live_evidence=native)
    except Exception as error:
        allowed = {"target_unverified", "profile_invalid", "prepared_guards_blocked", "existing_artifact",
                   "boot_mount_unverified", "host_key_incomplete", "observations_invalid", "runtime_source_invalid"}
        summary["error"] = str(error) if type(error) is EnrollmentError and str(error) in allowed else "enrollment_failed"
        if own_state or native and getattr(adapter, "state_stamp", None) is not None:
            summary["state"] = "review-required"
            try:
                adapter.write_state("review-required", profile_hash)
            except Exception:
                pass
    finally:
        if eligible:
            try:
                adapter.sync()
                summary["poweroff_requested"] = adapter.poweroff() is True
                if not summary["poweroff_requested"]:
                    raise EnrollmentError("shutdown_unavailable")
            except Exception:
                summary["error"] = "shutdown_unavailable"
                summary["passed"] = False
                if own_state or getattr(adapter, "state_stamp", None) is not None:
                    summary["state"] = "review-required"
                    try:
                        adapter.write_state("review-required", profile_hash)
                    except Exception:
                        pass
        adapter.close()
    # Console output never includes profile/challenge/public key/fingerprints.
    return summary


class SafeParser(argparse.ArgumentParser):
    def error(self, _message):
        raise EnrollmentError("invalid_arguments")


def main(argv=None):
    parser = SafeParser(prog="test-enrollment-firstboot.py", description=__doc__, allow_abbrev=False)
    parser.add_argument("--live", action="store_true")
    try:
        args = parser.parse_args(argv)
        if args.live and sys.platform.startswith("linux") and os.geteuid() == 0 and platform.machine() == "aarch64":
            try:
                result = enroll(NativeAdapter(), live=True)
            except Exception:
                result = enroll(live=True)
                result["error"] = "runtime_unavailable"
        else:
            result = enroll(live=args.live)
            if args.live:
                result["error"] = "linux_arm64_root_required"
        code = 0 if result["passed"] else 1
    except EnrollmentError:
        result = enroll()
        result["error"] = "invalid_arguments"
        code = 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    sys.exit(main())
