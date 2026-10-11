#!/usr/bin/python3 -I
"""Bounded Bluetooth preparation, called only by the authenticated TEST boot.

The caller verifies this module's manifest pin and the connected signed profile
before prepare(). No CLI grants authority. Only the unique hci0 controller is
prepared; no scan, advertising, application, WLAN or clock operation is issued.
"""
import sys
sys.dont_write_bytecode = True

import json
import math
import os
from pathlib import Path
import platform
import re
import selectors
import stat
import subprocess
import time


BUDGET, READY_TIMEOUT, POLL = 20.0, 10.0, 0.25
TEARDOWN = 0.2
MODEL = "/sys/firmware/devicetree/base/model"
PI_MODEL = b"Raspberry Pi Zero 2 W Rev 1.0\0"
UNBLOCK = ("/usr/sbin/rfkill", "unblock", "bluetooth")
BUSCTL = ("/usr/bin/busctl", "--system", "--auto-start=no",
          "--allow-interactive-authorization=no", "call", "org.bluez", "/org/bluez/hci0",
          "org.freedesktop.DBus.Properties")
POWER_ON = BUSCTL + ("Set", "ssv", "org.bluez.Adapter1", "Powered", "b", "true")
POWERED = BUSCTL + ("Get", "ss", "org.bluez.Adapter1", "Powered")
CHECKS = ("target_verified", "controller_verified", "not_hard_blocked", "bluez_available",
          "unblock_acknowledged", "unblocked", "power_acknowledged", "powered", "controller_unchanged")
ERRORS = {"target_unverified", "controller_unavailable", "controller_changed", "hard_blocked",
          "bluez_unavailable", "unblock_failed", "unblock_unconfirmed", "power_failed",
          "power_unconfirmed", "runtime_timeout", "observation_unavailable", "invalid_arguments"}


class BluetoothError(ValueError):
    pass


def require(value, error):
    if value is not True:
        raise BluetoothError(error)


def identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def directory(path):
    require(type(path) is str and path.startswith("/") and
            all(part not in {"", ".", ".."} for part in path[1:].split("/")), "controller_unavailable")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path[1:].split("/"):
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022, "controller_unavailable")
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        require(info.st_uid == 0 and not info.st_mode & 0o022, "controller_unavailable")
        return fd
    except BaseException:
        os.close(fd)
        raise


def attribute(path, limit=32):
    parent, name = path.rsplit("/", 1)
    root, fd = directory(parent), None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=root)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and not before.st_mode & 0o6022 and 0 <= before.st_size <= 65536, "controller_unavailable")
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(fd, min(128, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        require(0 < len(raw) <= limit and identity(before) == identity(os.fstat(fd))
                and identity(before) == identity(os.stat(name, dir_fd=root, follow_symlinks=False)),
                "controller_changed")
        return bytes(raw)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(root)


def class_entry(path):
    """Resolve only kernel class links into owned, no-follow /sys/devices paths."""
    before = path.lstat()
    require(stat.S_ISLNK(before.st_mode) and before.st_uid == 0, "controller_unavailable")
    resolved = str(path.resolve(strict=True))
    require(resolved.startswith("/sys/devices/"), "controller_unavailable")
    fd = directory(resolved)
    try:
        stamp = identity(os.fstat(fd))
    finally:
        os.close(fd)
    require(identity(before) == identity(path.lstat()) and str(path.resolve(strict=True)) == resolved,
            "controller_changed")
    return resolved, stamp, identity(before)


def observe_controller():
    """Private identity remains in memory; only soft/hard booleans leave here."""
    hci_root, rf_root = directory("/sys/class/bluetooth"), None
    try:
        require(os.listdir(hci_root) == ["hci0"], "controller_unavailable")
        hci = class_entry(Path("/sys/class/bluetooth/hci0"))
        rf_root = directory("/sys/class/rfkill")
        names = sorted(os.listdir(rf_root))
        require(0 < len(names) <= 64 and all(re.fullmatch(r"rfkill[0-9]+", name) for name in names),
                "controller_unavailable")
        matches = []
        for name in names:
            entry = class_entry(Path("/sys/class/rfkill") / name)
            kind = attribute(entry[0] + "/type")
            if kind == b"bluetooth\n":
                matches.append(entry)
        require(len(matches) == 1, "controller_unavailable")
        rf = matches[0]
        require(str(Path(rf[0]).parent) == hci[0] and attribute(rf[0] + "/name") == b"hci0\n",
                "controller_unavailable")
        hard, soft = (attribute(rf[0] + "/" + name) for name in ("hard", "soft"))
        require(hard in {b"0\n", b"1\n"} and soft in {b"0\n", b"1\n"}, "controller_unavailable")
        require(os.listdir(hci_root) == ["hci0"] and sorted(os.listdir(rf_root)) == names
                and class_entry(Path("/sys/class/bluetooth/hci0")) == hci
                and class_entry(Path("/sys/class/rfkill") / Path(rf[0]).name) == rf, "controller_changed")
        return {"identity": (hci, rf), "hard": hard == b"1\n", "soft": soft == b"1\n"}
    finally:
        if rf_root is not None:
            os.close(rf_root)
        os.close(hci_root)


def command(argv, *, timeout):
    require(argv in (UNBLOCK, POWER_ON, POWERED), "invalid_arguments")
    require(timeout > TEARDOWN, "runtime_timeout")
    deadline = time.monotonic() + timeout - TEARDOWN
    child, selector = None, selectors.DefaultSelector()
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, cwd="/", close_fds=True,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        os.set_blocking(child.stdout.fileno(), False)
        selector.register(child.stdout, selectors.EVENT_READ)
        output = bytearray()
        while selector.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, "runtime_timeout")
            for key, _ in selector.select(remaining):
                raw = os.read(key.fd, 4097 - len(output))
                if not raw:
                    selector.unregister(key.fileobj)
                else:
                    output.extend(raw)
                    require(len(output) <= 4096, "observation_unavailable")
        remaining = deadline - time.monotonic()
        require(remaining > 0, "runtime_timeout")
        return child.wait(timeout=remaining), bytes(output)
    except subprocess.TimeoutExpired:
        raise BluetoothError("runtime_timeout") from None
    finally:
        selector.close()
        if child is not None:
            if child.poll() is None:
                try:
                    child.kill()
                except OSError:
                    pass
            child.stdout.close()
            try:
                child.wait(timeout=TEARDOWN)
            except subprocess.TimeoutExpired:
                pass


class NativeAdapter:
    def target(self):
        try:
            return (sys.platform.startswith("linux") and os.getuid() == os.geteuid() == 0
                    and platform.machine() == "aarch64" and sys.byteorder == "little"
                    and attribute(MODEL, 128) == PI_MODEL)
        except (OSError, BluetoothError):
            return False

    def observe(self):
        try:
            return observe_controller()
        except OSError:
            raise BluetoothError("controller_unavailable") from None

    def call(self, argv, timeout):
        return command(argv, timeout=timeout)


def empty_result():
    return {"schema_version": 1, "kind": "test-access-bluetooth", "passed": False,
            "live_evidence": False, "error": None, "checks": dict.fromkeys(CHECKS, False),
            "unblock_attempted": False, "power_attempted": False,
            "application_activation_authorized": False, "hardware_qualified": False,
            "release_qualified": False,
            "limits": ["The authenticated boot caller verifies source pins and signed network prerequisites before this helper.",
                       "Only the unique hci0 controller is prepared; no scan, advertising, WLAN, clock or application operation is issued.",
                       "Readbacks are observations; concurrent privileged changes or device replacement cannot be excluded.",
                       "Deadlines cannot interrupt kernel-blocked filesystem I/O; the enclosing boot unit retains its timeout.",
                       "Failure may leave Bluetooth unblocked or powered; it must not prevent diagnostic SSH access."]}


def prepare(adapter=None, *, timeout=BUDGET):
    result = empty_result()
    adapter = NativeAdapter() if adapter is None else adapter
    original = None
    try:
        require(type(timeout) in {int, float} and math.isfinite(timeout) and 0 < timeout <= BUDGET,
                "invalid_arguments")
        deadline = time.monotonic() + timeout
        def within(operation):
            require(time.monotonic() < deadline, "runtime_timeout")
            value = operation()
            require(time.monotonic() < deadline, "runtime_timeout")
            return value

        def observe():
            row = within(adapter.observe)
            require(type(row) is dict and set(row) == {"identity", "soft", "hard"}
                    and row["identity"] is not None and type(row["soft"]) is bool and type(row["hard"]) is bool,
                    "controller_unavailable")
            require(original is None or row["identity"] == original, "controller_changed")
            require(row["hard"] is False, "hard_blocked")
            return row

        def call(argv, cap):
            remaining = deadline - time.monotonic()
            require(remaining > TEARDOWN, "runtime_timeout")
            reply = within(lambda: adapter.call(argv, min(cap, remaining)))
            require(type(reply) is tuple and len(reply) == 2 and type(reply[0]) is int
                    and type(reply[1]) is bytes and len(reply[1]) <= 4096, "observation_unavailable")
            return reply

        require(within(adapter.target) is True, "target_unverified")
        result["checks"]["target_verified"] = True
        row = observe()
        original = row["identity"]
        result["checks"]["controller_verified"] = result["checks"]["not_hard_blocked"] = True
        require(call(POWERED, 2.0) in ((0, b"v b true\n"), (0, b"v b false\n")), "bluez_unavailable")
        result["checks"]["bluez_available"] = True
        observe()
        require(deadline - time.monotonic() > 3.0 + 5.0 + TEARDOWN, "runtime_timeout")
        result["unblock_attempted"] = True
        require(call(UNBLOCK, 3.0) == (0, b""), "unblock_failed")
        result["checks"]["unblock_acknowledged"] = True
        ready_deadline = min(time.monotonic() + READY_TIMEOUT, deadline - 5.0)
        while True:
            require(time.monotonic() < ready_deadline, "unblock_unconfirmed")
            row = observe()
            require(time.monotonic() < ready_deadline, "unblock_unconfirmed")
            if row["soft"] is False:
                break
            remaining = ready_deadline - time.monotonic()
            require(remaining > 0, "unblock_unconfirmed")
            time.sleep(min(POLL, remaining))
        result["checks"]["unblocked"] = True
        require(observe()["soft"] is False, "unblock_unconfirmed")
        result["power_attempted"] = True
        require(call(POWER_ON, 3.0) == (0, b""), "power_failed")
        result["checks"]["power_acknowledged"] = True
        require(call(POWERED, 2.0) == (0, b"v b true\n"), "power_unconfirmed")
        result["checks"]["powered"] = True
        require(observe()["soft"] is False, "unblock_unconfirmed")
        result["checks"]["controller_unchanged"] = True
        result["passed"] = True
        result["live_evidence"] = type(adapter) is NativeAdapter
    except Exception as error:
        result["error"] = str(error) if type(error) is BluetoothError and str(error) in ERRORS else "observation_unavailable"
    return result


def main():
    # Only the manifest-bound boot caller may select the native mutation path.
    result = empty_result()
    result["error"] = "invalid_arguments"
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 1


if __name__ == "__main__":
    sys.exit(main())
