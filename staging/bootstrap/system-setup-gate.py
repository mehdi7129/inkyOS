#!/usr/bin/python3.13
"""Every-boot WLAN close gate. No factory grant, Bluetooth change or app import."""

import configparser
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time
import types

SELF = "/usr/lib/inkyos/system-setup-gate.py"
MANIFEST = "/etc/inkyos/factory-runtime-v1.json"
RUNTIME = "/usr/lib/inkyos/factory-runtime-contract.py"
NATIVE = "usr/lib/inkyos/system-setup-native.py"
STATE = "/var/lib/NetworkManager/NetworkManager.state"
PARENT = "/run/inkyos-wlan-gate"


class Refused(ValueError):
    pass


def require(value):
    if not value:
        raise Refused("wlan_gate_refused")


def canonical(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("ascii")


def read_fixed(path, mode, limit):
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in Path(path).parts[1:-1]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
            )
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            require(
                info.st_uid == info.st_gid == 0
                and not stat.S_IMODE(info.st_mode) & 0o7022
                and not os.listxattr(parent)
            )
        fd = os.open(
            Path(path).name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent
        )
        try:
            before = os.fstat(fd)
            require(
                stat.S_ISREG(before.st_mode)
                and before.st_uid == before.st_gid == 0
                and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == mode
                and not os.listxattr(fd)
            )
            raw = os.read(fd, limit + 1)
            require(before.st_size == len(raw) <= limit and os.fstat(fd) == before)
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def verify_restore_closed(command):
    for suffix in ("service", "socket"):
        path = "/etc/systemd/system/systemd-rfkill." + suffix
        info = os.lstat(path)
        require(
            stat.S_ISLNK(info.st_mode)
            and info.st_uid == info.st_gid == 0
            and os.readlink(path) == "/dev/null"
        )
        wanted = ("LoadState", "ActiveState", "SubState") + (
            ("MainPID",) if suffix == "service" else ()
        )
        raw = command.run(
            (
                "/usr/bin/systemctl",
                "show",
                "systemd-rfkill." + suffix,
                "--property=" + ",".join(wanted),
            )
        ).decode("ascii")
        rows = dict(line.split("=", 1) for line in raw.splitlines())
        require(
            rows
            == {
                "LoadState": "masked",
                "ActiveState": "inactive",
                "SubState": "dead",
                **({"MainPID": "0"} if suffix == "service" else {}),
            }
        )


def state_bytes(raw):
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    if raw:
        parser.read_string(raw.decode("ascii"))
    require(not parser.defaults() and set(parser.sections()) <= {"main"})
    if not parser.has_section("main"):
        parser.add_section("main")
    require(
        set(parser["main"]) <= {"NetworkingEnabled", "WirelessEnabled", "WWANEnabled"}
    )
    for value in parser["main"].values():
        require(value in {"true", "false"})
    parser["main"]["WirelessEnabled"] = "false"
    return (
        "[main]\n"
        + "".join(
            key + "=" + value + "\n" for key, value in sorted(parser["main"].items())
        )
    ).encode("ascii")


def close_state():
    parent = os.open(
        "/var/lib/NetworkManager", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    try:
        info = os.fstat(parent)
        require(
            info.st_uid == info.st_gid == 0
            and not stat.S_IMODE(info.st_mode) & 0o7022
            and not os.listxattr(parent)
        )
        try:
            raw = read_fixed(STATE, 0o600, 4096)
        except FileNotFoundError:
            raw = b""
        expected = state_bytes(raw)
        fd = os.open(
            ".inkyos-wlan-close",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent,
        )
        try:
            require(os.write(fd, expected) == len(expected))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(
            ".inkyos-wlan-close",
            "NetworkManager.state",
            src_dir_fd=parent,
            dst_dir_fd=parent,
        )
        os.fsync(parent)
        require(read_fixed(STATE, 0o600, 4096) == expected)
    finally:
        os.close(parent)


def close_gate(native, candidate, boot):
    verify_restore_closed(native.command)
    raw = native.command.run(
        (
            "/usr/bin/systemctl",
            "show",
            "NetworkManager.service",
            "--property=ActiveState,SubState,MainPID",
        )
    ).decode("ascii")
    require(
        dict(line.split("=", 1) for line in raw.splitlines())
        == {"ActiveState": "inactive", "SubState": "dead", "MainPID": "0"}
    )
    close_state()
    deadline = time.monotonic() + 25
    while True:
        try:
            native.rfkill(True)
            _, soft, _ = native.rfkill()
            require(soft)
            break
        except Exception:
            require(time.monotonic() < deadline)
            time.sleep(0.1)
    verify_restore_closed(native.command)
    record = {
        "boot_id": boot,
        "candidate_sha256": candidate,
        "closed_boottime_ns": native.boottime(),
        "nm_wireless_enabled": False,
        "wlan_soft_blocked": True,
        "restore_policy": "systemd-rfkill-masked",
    }
    record["record_sha256"] = hashlib.sha256(canonical(record)).hexdigest()
    os.mkdir(PARENT, 0o755)
    parent = os.open(PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(
            "closed.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o644,
            dir_fd=parent,
        )
        try:
            os.fchmod(fd, 0o644)
            raw = canonical(record)
            require(os.write(fd, raw) == len(raw))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
        require(read_fixed(PARENT + "/closed.json", 0o644, 4096) == raw)
    finally:
        os.close(parent)
    return record


def main():
    require(
        sys.argv == [SELF]
        and str(Path(__file__)) == SELF
        and sys.platform == "linux"
        and sys.flags.isolated
        and sys.dont_write_bytecode
        and os.geteuid() == 0
    )
    # Signals request no new effects; an admitted close operation is drained.
    stopping = []
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, lambda *_: stopping.append(True))
    manifest = json.loads(read_fixed(MANIFEST, 0o644, 16384))
    raw = read_fixed(RUNTIME, 0o555, 1024 * 1024)
    require(
        hashlib.sha256(raw).hexdigest()
        == manifest["os_module_pins"]["factory-runtime-contract.py"]
    )
    runtime = types.ModuleType("inkyos_gate_runtime")
    runtime.__file__ = RUNTIME
    exec(compile(raw, RUNTIME, "exec"), runtime.__dict__)
    contract = runtime.load_contract()
    _, _, support, records = runtime.inventories(contract)
    with contract.tree() as tree:
        require(NATIVE in support["paths"])
        runtime.check_path(tree, SELF[1:], records)
        runtime.check_path(tree, NATIVE, records)
        raw = tree.read(NATIVE, 0o555, 1024 * 1024)
    module = types.ModuleType("inkyos_gate_native")
    module.__file__ = "/" + NATIVE
    exec(compile(raw, module.__file__, "exec"), module.__dict__)
    require(not stopping)
    native = module.Native(runtime, contract)
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    close_gate(native, contract.candidate_sha256, boot)
    require(not stopping)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit(78) from None
