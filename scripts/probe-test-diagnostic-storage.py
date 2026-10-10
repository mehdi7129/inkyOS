#!/usr/bin/env python3
"""Exercise diagnostic persistence in an inert systemd unit in the marked VM.

Run as root in the dedicated Linux ARM64 builder, from a copy of scripts/.
No hardware, NetworkManager or application service is invoked. The unique
fixture directory and its small receipts are retained for inspection.
"""
import sys
sys.dont_write_bytecode = True

import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess


PREFIX = "inkyos-diagnostic-probe-"
SOURCES = ("probe-test-diagnostic-storage.py", "test-access-boot.py", "test-enrollment-firstboot.py")


def require(value):
    if not value:
        raise ValueError("fixture_failed")


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def worker(name):
    require(re.fullmatch(PREFIX + "[0-9a-f]{16}", name))
    work = Path("/var/lib/inkyos-build") / name
    require(Path(__file__).resolve().parent == work)
    state = Path("/var/lib") / name
    boot = load(work / "test-access-boot.py", "diagnostic_probe_boot")
    require(hashlib.sha256((work / "test-enrollment-firstboot.py").read_bytes()).hexdigest() == boot.LEGACY_SHA256)
    legacy = load(work / "test-enrollment-firstboot.py", "diagnostic_probe_files")
    boot.DIAGNOSTICS = str(state)
    result = {"passed": False, "poweroff_requested": False, "ssh_start_requested": False,
              "wifi_off_requested_on_failure": False, "error": None, "phase": "blocked"}
    files = legacy.Files()
    try:
        first = boot.boot_diagnostic(result, complete=False, stage="bind")
        first["boot_id"] = boot.diagnostic_boot_id()
        require(first["boot_id"] is not None)
        require(boot.write_diagnostic(vars(legacy), files, "last-boot.json", first))
        result["error"] = "connection_failed"
        final = boot.boot_diagnostic(result, complete=True, stage="connect")
        final["boot_id"] = first["boot_id"]
        require(boot.write_diagnostic(vars(legacy), files, "last-boot.json", final))
        require(json.loads((state / "last-boot.json").read_bytes()) == final)
        gate = {"schema_version": 1, "kind": "test-access-wifi-gate-diagnostic",
                "complete": True, "gate": {"status": "unavailable"},
                "connection_authorized": False, "application_activation_authorized": False,
                "hardware_qualified": False, "boot_id": first["boot_id"]}
        require(boot.write_diagnostic(vars(legacy), files, "last-wifi-gate.json", gate))
    finally:
        files.close()
    protected = work / "protected-sentinel"
    try:
        protected.write_bytes(b"must-not-write\n")
    except OSError as error:
        require(error.errno == errno.EROFS)
    else:
        raise ValueError("sandbox_not_readonly")
    require(protected.read_bytes() == b"unchanged\n")
    require({line.split(":", 1)[0].strip() for line in Path("/proc/net/dev").read_text().splitlines()[2:]} == {"lo"})


def controller():
    name = PREFIX + os.urandom(8).hex()
    work = Path("/var/lib/inkyos-build") / name
    state = Path("/var/lib") / name
    require(not state.exists())
    work.mkdir(mode=0o700)
    hashes = {}
    for source in SOURCES:
        path = Path(__file__).resolve().parent / source
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
        raw = path.read_bytes()
        hashes[source] = hashlib.sha256(raw).hexdigest()
        destination = work / source
        with destination.open("xb") as stream:
            stream.write(raw)
        destination.chmod(0o444)
    (work / "protected-sentinel").write_bytes(b"unchanged\n")
    command = ["/usr/bin/systemd-run", "--quiet", "--wait", "--collect", "--pipe", "--unit=" + name,
        "--property=Type=oneshot", "--property=User=root", "--property=Group=root",
        "--property=UMask=0077", "--property=StateDirectory=" + name,
        "--property=StateDirectoryMode=0700", "--property=ProtectSystem=strict",
        "--property=ProtectHome=read-only", "--property=PrivateTmp=yes", "--property=PrivateNetwork=yes",
        "--property=NoNewPrivileges=yes", "--property=TimeoutStartSec=25s",
        "/usr/bin/python3", "-I", str(work / SOURCES[0]), "--worker", name]
    # The unit is inert and bounded. Keep raw failure details in this fixture only.
    timed_out, stopped = False, False
    try:
        ran = subprocess.run(command, capture_output=True, timeout=40)
        worker_passed, output = ran.returncode == 0, ran.stdout + ran.stderr
    except subprocess.TimeoutExpired as error:
        timed_out, worker_passed = True, False
        output = (error.stdout or b"") + (error.stderr or b"")
    except OSError:
        worker_passed, output = False, b"unit_runner_unavailable\n"
    finally:
        try:
            subprocess.run(["/usr/bin/systemctl", "stop", name + ".service"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            stopped = True
        except (OSError, subprocess.TimeoutExpired):
            pass
    (work / "unit-output.txt").write_bytes(output)
    checks = {"sandbox_worker_passed": worker_passed, "runner_completed": not timed_out,
              "private_state_directory": False, "private_bounded_reports": False,
              "replacement_survived_unit_exit": False, "unit_inactive": False}
    if state.is_dir():
        info = state.lstat()
        checks["private_state_directory"] = info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700
        names = {path.name for path in state.iterdir()}
        checks["private_bounded_reports"] = names == {"last-boot.json", "last-wifi-gate.json"} and all(
            stat.S_ISREG((info := path.lstat()).st_mode) and info.st_uid == info.st_gid == 0
            and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 8192
            for path in state.iterdir())
        if checks["private_bounded_reports"]:
            saved = json.loads((state / "last-boot.json").read_bytes())
            checks["replacement_survived_unit_exit"] = saved["complete"] is True and saved["stage"] == "connect" and saved["boot"]["error"] == "connection_failed"
    if stopped:
        try:
            active = subprocess.run(["/usr/bin/systemctl", "show", name + ".service", "--property=ActiveState", "--value"],
                                    capture_output=True, timeout=5)
            checks["unit_inactive"] = active.returncode == 0 and active.stdout.strip() == b"inactive"
        except (OSError, subprocess.TimeoutExpired):
            pass
    report = {"schema_version": 1, "scope": "inert-systemd-diagnostic-storage-fixture",
        "passed": all(checks.values()), "checks": checks, "sources": hashes,
        "hardware_qualified": False, "network_connection_tested": False, "target_boot_tested": False}
    (work / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] else 1


def main():
    require(sys.platform.startswith("linux") and platform.machine() == "aarch64" and os.getuid() == os.geteuid() == 0)
    require(Path("/var/lib/inkyos-build/owner").read_bytes() == b"inkyos-builder-v1\n")
    os.umask(0o077)
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        worker(sys.argv[2])
        return 0
    require(len(sys.argv) == 1)
    return controller()


if __name__ == "__main__":
    sys.exit(main())
