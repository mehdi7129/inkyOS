#!/usr/bin/python3 -I
"""Close WLAN before each TEST NetworkManager start, including restarts.

Only the fixed-root CLI is a runtime entrypoint. The unchanged pinned helper
commits NM's disabled state; this wrapper also requests and reads back a WLAN
soft block. systemd-rfkill must be ordered before this ExecStartPre. Neither the
ordering nor these snapshots prove RF silence before the gate or exclude a
concurrent privileged client/device re-registration. Bluetooth is not changed.
"""
import sys
sys.dont_write_bytecode = True

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import stat
import subprocess
import time


SELF = "/usr/local/lib/inkyos/test-access-wifi-gate.py"
HELPER = "/usr/local/lib/inkyos/wifi-boot-gate.py"
BOOT = "/usr/local/lib/inkyos/test-access-boot.py"
HELPER_SHA256 = "96b251196cff66c60868bfafde738e9b07f528f00a98abf0e944f4af023eb6c4"
MANIFEST = "/usr/local/share/inkyos/test-access-manifest.json"
MODEL = "/sys/firmware/devicetree/base/model"
PI_MODEL = b"Raspberry Pi Zero 2 W Rev 1.0\0"
STATE = "/var/lib/NetworkManager/NetworkManager.state"
SOURCE = "c31b13afdc957425571810c46230eaaf52fa5d14"
APPLICATION_MANIFEST = "c4183e7304e3ff979450977b36e4a007b30016de68bb23ef121c7ca733cd26a1"
PARENT = "0854663168acf7986d26a473e9116dddeb7d6fbef8226f5d1d96cf190f77e286"
BLOCK_WLAN = ("/usr/sbin/rfkill", "block", "wlan")
NM_STATUS = ("/usr/bin/systemctl", "--no-pager", "show", "NetworkManager.service",
             "--property=ActiveState,SubState,MainPID")
BUDGET = 20.0
MAX_BYTES = 65536
CHECKS = ("target_verified", "sources_bound", "networkmanager_start_pre",
          "wlan_block_request_acknowledged", "wlan_blocked_before_state",
          "state_durably_written", "state_disabled_readback", "wlan_blocked_after_state",
          "sources_unchanged", "networkmanager_still_start_pre")
ERRORS = {"target_unverified", "manifest_invalid", "source_pin_invalid", "networkmanager_not_starting",
          "wlan_block_failed", "wlan_not_blocked", "state_write_failed", "state_readback_invalid",
          "state_changed", "runtime_timeout", "observation_unavailable", "invalid_arguments"}


class GateError(ValueError):
    pass


def require(condition, error):
    if condition is not True:
        raise GateError(error)


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory(path):
    require(type(path) is str and path.startswith("/") and
            (path == "/" or all(p not in {"", ".", ".."} for p in path[1:].split("/"))), "source_pin_invalid")
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


def read_file(path, *, mode, limit=MAX_BYTES, virtual=False):
    parent, name = path.rsplit("/", 1)
    root, fd = directory(parent), None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and not before.st_mode & 0o6022 and (mode is None or stat.S_IMODE(before.st_mode) == mode)
                and 0 <= before.st_size <= (MAX_BYTES if virtual else limit), "source_pin_invalid")
        raw = bytearray()
        while len(raw) <= limit:
            block = os.read(fd, min(4096, limit + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        require(0 < len(raw) <= limit and (virtual or len(raw) == before.st_size)
                and stamp(before) == stamp(os.fstat(fd))
                and stamp(before) == stamp(os.stat(name, dir_fd=root, follow_symlinks=False)), "source_pin_invalid")
        return bytes(raw)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(root)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "manifest_invalid")
            result[key] = value
        return result
    def invalid(_value):
        raise GateError("manifest_invalid")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    except (TypeError, ValueError, UnicodeError):
        raise GateError("manifest_invalid") from None


def validate_manifest(raw, self_raw, helper_raw, boot_raw):
    value = strict_json(raw)
    require(type(value) is dict and set(value) == {"schema_version", "kind", "application_source_commit",
            "application_manifest_sha256", "parent_image_sha256", "files"}
            and type(value["schema_version"]) is int and value["schema_version"] == 1
            and value["kind"] == "test-access-runtime" and value["application_source_commit"] == SOURCE
            and value["application_manifest_sha256"] == APPLICATION_MANIFEST
            and value["parent_image_sha256"] == PARENT
            and type(value["files"]) is dict and 3 <= len(value["files"]) <= 128, "manifest_invalid")
    for path, entry in value["files"].items():
        require(type(path) is str and 0 < len(path) <= 256
                and re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", path) is not None
                and all(part not in {".", ".."} for part in path.split("/"))
                and type(entry) is dict and set(entry) == {"sha256", "mode"}
                and type(entry["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is not None
                and type(entry["mode"]) is str and entry["mode"] in {"0555", "0644", "0440"}, "manifest_invalid")
    for path, content in ((SELF, self_raw), (HELPER, helper_raw), (BOOT, boot_raw)):
        require(type(content) is bytes and value["files"].get(path[1:]) ==
                {"sha256": hashlib.sha256(content).hexdigest(), "mode": "0555"}, "source_pin_invalid")
    require(hashlib.sha256(helper_raw).hexdigest() == HELPER_SHA256, "source_pin_invalid")
    return value


def wlan_blocked(rows):
    """Interpret bounded kernel attributes only; never export device names."""
    if type(rows) is not list or not 0 < len(rows) <= 64:
        return False
    found = False
    for row in rows:
        if (type(row) is not tuple or len(row) != 2 or type(row[0]) is not bytes
                or row[0] not in {b"wlan\n", b"bluetooth\n", b"uwb\n", b"wimax\n",
                                  b"wwan\n", b"gps\n", b"fm\n", b"nfc\n"}
                or type(row[1]) is not bytes or row[1] not in {b"0\n", b"1\n"}):
            return False
        if row[0] == b"wlan\n":
            found = True
            if row[1] != b"1\n":
                return False
    return found


class NativeAdapter:
    def target(self):
        if not (sys.platform.startswith("linux") and os.getuid() == os.geteuid() == 0
                and platform.machine() == "aarch64" and sys.byteorder == "little"):
            return False
        try:
            return read_file(MODEL, mode=None, limit=128, virtual=True) == PI_MODEL
        except (OSError, GateError):
            return False

    def bind(self):
        self.snapshot = {MANIFEST: (read_file(MANIFEST, mode=0o644), 0o644),
                         SELF: (read_file(SELF, mode=0o555), 0o555),
                         HELPER: (read_file(HELPER, mode=0o555), 0o555),
                         BOOT: (read_file(BOOT, mode=0o555), 0o555)}
        validate_manifest(*(self.snapshot[path][0] for path in (MANIFEST, SELF, HELPER, BOOT)))
        diagnostic = {"__name__": "inkyos_pinned_gate_diagnostic", "__file__": BOOT}
        exec(compile(self.snapshot[BOOT][0], BOOT, "exec"), diagnostic)
        require(callable(diagnostic.get("save_gate_diagnostic")), "source_pin_invalid")
        self.save_diagnostic = diagnostic["save_gate_diagnostic"]
        self.helper = {"__name__": "inkyos_pinned_wifi_writer", "__file__": HELPER}
        exec(compile(self.snapshot[HELPER][0], HELPER, "exec"), self.helper)
        return True

    def unchanged(self):
        return all(read_file(path, mode=mode) == raw for path, (raw, mode) in self.snapshot.items())

    def command(self, argv):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "runtime_timeout")
        deadline = time.monotonic() + min(3.0, remaining)
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        selector, out = selectors.DefaultSelector(), bytearray()
        try:
            selector.register(child.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, "runtime_timeout")
                for key, _mask in selector.select(remaining):
                    block = os.read(key.fd, 4097 - len(out))
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        out.extend(block)
                        require(len(out) <= 4096, "observation_unavailable")
            try:
                code = child.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise GateError("runtime_timeout") from None
            return code, bytes(out)
        finally:
            selector.close()
            if child.poll() is None:
                try:
                    child.kill()
                except OSError:
                    pass
            child.stdout.close()
            try:
                child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass

    def nm_start_pre(self):
        code, raw = self.command(NM_STATUS)
        if code != 0:
            return False
        lines = raw.decode("ascii").splitlines()
        return len(lines) == 3 and set(lines) == {"ActiveState=activating", "SubState=start-pre", "MainPID=0"}

    def block_wlan(self):
        # util-linux's exit status alone does not attest the write: readback is mandatory.
        return self.command(BLOCK_WLAN) == (0, b"")

    def wlan_blocked(self):
        root = directory("/sys/class/rfkill")
        try:
            names = sorted(os.listdir(root))
            require(0 < len(names) <= 64 and all(re.fullmatch(r"rfkill[0-9]+", name) for name in names), "wlan_not_blocked")
            rows = []
            for name in names:
                # Kernel class entries are symlinks; resolve only inside /sys/devices,
                # then use the same no-follow/owner/stability checks for attributes.
                entry = Path("/sys/class/rfkill") / name
                resolved = str(entry.resolve(strict=True))
                require(resolved.startswith("/sys/devices/"), "wlan_not_blocked")
                rows.append(tuple(read_file(resolved + "/" + attr, mode=None, limit=32, virtual=True)
                                  for attr in ("type", "soft")))
                require(str(entry.resolve(strict=True)) == resolved, "wlan_not_blocked")
            require(sorted(os.listdir(root)) == names, "wlan_not_blocked")
            return wlan_blocked(rows)
        finally:
            os.close(root)

    def write_state(self):
        result = self.helper["set_wireless_disabled"]("/")
        return (type(result) is dict and result.get("durably_written") is True
                and result.get("wireless_enabled") is False)

    def state_disabled(self):
        raw = read_file(STATE, mode=0o600)
        return self.helper["disabled_state"](raw) == raw


def empty_result():
    return {"schema_version": 1, "kind": "test-access-wifi-gate", "passed": False,
            "error": None, "live_evidence": False, "checks": {key: False for key in CHECKS},
            "connection_authorized": False, "activation_authorized": False,
            "hardware_qualified": False, "release_qualified": False,
            "limits": ["Only WLAN is soft-blocked; Bluetooth is not changed.",
                       "Snapshots do not prove RF silence before this gate or exclude privileged clients and device re-registration.",
                       "The state writer and this gate authorize no country, scan, connection or application start."]}


def guard(adapter):
    result = empty_result()
    try:
        deadline = time.monotonic() + BUDGET
        adapter.deadline = deadline
        steps = (("target_verified", adapter.target, "target_unverified"),
                 ("sources_bound", adapter.bind, "source_pin_invalid"),
                 ("networkmanager_start_pre", adapter.nm_start_pre, "networkmanager_not_starting"),
                 ("wlan_block_request_acknowledged", adapter.block_wlan, "wlan_block_failed"),
                 ("wlan_blocked_before_state", adapter.wlan_blocked, "wlan_not_blocked"),
                 ("state_durably_written", adapter.write_state, "state_write_failed"),
                 ("state_disabled_readback", adapter.state_disabled, "state_readback_invalid"),
                 ("wlan_blocked_after_state", adapter.wlan_blocked, "wlan_not_blocked"),
                 ("sources_unchanged", adapter.unchanged, "state_changed"),
                 ("networkmanager_still_start_pre", adapter.nm_start_pre, "networkmanager_not_starting"))
        for name, operation, error in steps:
            require(time.monotonic() < deadline, "runtime_timeout")
            require(operation() is True, error)
            require(time.monotonic() < deadline, "runtime_timeout")
            result["checks"][name] = True
        result["passed"] = True
        result["live_evidence"] = type(adapter) is NativeAdapter
    except Exception as error:
        result["error"] = str(error) if type(error) is GateError and str(error) in ERRORS else "observation_unavailable"
    return result


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args:
        result = empty_result()
        result["error"] = "invalid_arguments"
    else:
        # Bound the unchanged helper's blocking directory flock as well as commands.
        def expired(_signum, _frame):
            raise GateError("runtime_timeout")
        old_handler = signal.signal(signal.SIGALRM, expired)
        old_timer = signal.setitimer(signal.ITIMER_REAL, BUDGET)
        try:
            adapter = NativeAdapter()
            result = guard(adapter)
        finally:
            signal.setitimer(signal.ITIMER_REAL, *old_timer)
            signal.signal(signal.SIGALRM, old_handler)
        # Persist only after the radio guard and its deadline have ended. A
        # missing/refused writer cannot change the gate result or radio state.
        writer = getattr(adapter, "save_diagnostic", None)
        if writer is not None:
            try:
                writer(result)
            except Exception:
                pass
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
