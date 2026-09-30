#!/usr/bin/env python3
"""Export a fixed, redacted SD boot report; never change system configuration.

The runtime entry point accepts no paths or commands and requires Linux root.
Fixture tests call export_report with an alternate root and explicit adapters.
Reports on FAT are readable diagnostics, not private Unix-permission storage.
"""

import argparse
import hashlib
import itertools
import json
import os
import re
import selectors
import stat
import subprocess
import sys
import time
from pathlib import PurePosixPath


UNITS = (
    "inkyos-firstboot.service", "NetworkManager.service", "bluetooth.service",
    "ssh.service", "avahi-daemon.service", "inky-studio.service", "inky-network.service",
    "inkyos-sd-diagnostic.service", "rpi-resize.service", "systemd-growfs-root.service",
    "rpi-eeprom-update.service", "apt-daily.service", "apt-daily.timer",
    "apt-daily-upgrade.service", "apt-daily-upgrade.timer",
)
PROPERTIES = ("ActiveState", "SubState", "Result", "ExecMainStatus", "LoadState", "UnitFileState")
PROPERTY_VALUES = {
    "ActiveState": {"active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance", "refreshing"},
    "SubState": {"running", "exited", "dead", "failed", "start-pre", "start", "start-post", "auto-restart", "auto-restart-queued", "stop", "stop-sigterm", "stop-sigkill", "stop-post", "final-sigterm", "final-sigkill", "cleaning", "condition", "waiting", "listening", "reload", "reload-signal", "reload-notify"},
    "Result": {"", "success", "resources", "protocol", "timeout", "exit-code", "signal", "core-dump", "watchdog", "start-limit-hit", "exec-condition", "oom-kill", "skipped"},
    "LoadState": {"loaded", "error", "not-found", "bad-setting", "masked", "stub", "merged"},
    "UnitFileState": {"", "enabled", "enabled-runtime", "linked", "linked-runtime", "alias", "masked", "masked-runtime", "static", "disabled", "indirect", "generated", "transient", "bad"},
}
HOSTNAME = re.compile(r"inky-[0-9a-f]{32}\Z")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
MACHINE_ID = re.compile(r"[0-9a-f]{32}\Z")
KERNEL_RELEASE = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:\+rpt-rpi-(?:v6|v7|v7l|v8|2712)|-(?:v6|v7|v7l|v8)\+)?\Z")
MAX_OUTPUT = 4096
COMMAND_TIMEOUT = 2.0
COMMAND_BUDGET = 35.0
_counter = itertools.count()


class DiagnosticError(RuntimeError):
    """Only fixed diagnostic codes are carried across the CLI boundary."""


def _failure(code):
    return {"status": code}


def _sha(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _single_line(content):
    if content.endswith("\n"):
        content = content[:-1]
    return content


def _metadata(info, owner_uid, *, directory=False, fat=False, private=False):
    if (not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or info.st_uid != owner_uid or (not directory and info.st_nlink != 1)):
        raise DiagnosticError("unsafe_path")
    if not fat and info.st_mode & 0o022:
        raise DiagnosticError("unsafe_path")
    if private and stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600):
        raise DiagnosticError("unsafe_path")


class Files:
    def __init__(self, root, owner_uid):
        self.owner_uid = owner_uid
        try:
            self.root = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            _metadata(os.fstat(self.root), owner_uid, directory=True)
        except OSError as exc:
            raise DiagnosticError("unsafe_root") from exc
        except BaseException:
            os.close(self.root)
            raise

    def close(self):
        os.close(self.root)

    def directory(self, path, *, fat=False):
        parts = PurePosixPath(path).parts
        if PurePosixPath(path).is_absolute() or ".." in parts:
            raise DiagnosticError("unsafe_path")
        fd = os.dup(self.root)
        try:
            for index, part in enumerate(parts):
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                _metadata(os.fstat(fd), self.owner_uid, directory=True,
                          fat=fat and index == len(parts) - 1)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def read(self, path, *, limit=4096, private=False):
        directory = fd = None
        try:
            item = PurePosixPath(path)
            directory = self.directory(str(item.parent))
            if private:
                _metadata(os.fstat(directory), self.owner_uid, directory=True, private=True)
            before = os.stat(item.name, dir_fd=directory, follow_symlinks=False)
            _metadata(before, self.owner_uid, private=private)
            fd = os.open(item.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            after = os.fstat(fd)
            _metadata(after, self.owner_uid, private=private)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise DiagnosticError("unsafe_path")
            result = bytearray()
            while len(result) <= limit:
                chunk = os.read(fd, min(4096, limit + 1 - len(result)))
                if not chunk:
                    break
                result.extend(chunk)
            if len(result) > limit:
                return _failure("too_large"), None
            return {"status": "ok"}, result.decode("utf-8")
        except FileNotFoundError:
            return _failure("missing"), None
        except UnicodeError:
            return _failure("invalid"), None
        except DiagnosticError:
            return _failure("unsafe_path"), None
        except OSError:
            return _failure("read_error"), None
        finally:
            if fd is not None:
                os.close(fd)
            if directory is not None:
                os.close(directory)


def bounded_command(argv, *, timeout=COMMAND_TIMEOUT, limit=MAX_OUTPUT):
    """Fixed callers; cap captured bytes and deadline, discard stderr entirely."""
    process = None
    selector = selectors.DefaultSelector()
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, close_fds=True, cwd="/",
                                   env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C",
                                        "SYSTEMD_COLORS": "0", "SYSTEMD_PAGER": ""})
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        captured = bytearray()
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return _failure("timeout"), None
            for key, _events in selector.select(remaining):
                chunk = os.read(key.fd, min(4096, limit + 1 - len(captured)))
                if not chunk:
                    selector.unregister(key.fileobj)
                else:
                    captured.extend(chunk)
                    if len(captured) > limit:
                        return _failure("too_large"), None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return _failure("timeout"), None
        try:
            code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            return _failure("timeout"), None
        if code != 0:
            return _failure("command_error"), None
        return {"status": "ok"}, captured.decode("ascii")
    except FileNotFoundError:
        return _failure("missing"), None
    except UnicodeError:
        return _failure("invalid"), None
    except OSError:
        return _failure("command_error"), None
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


class Adapters:
    def __init__(self, *, command=bounded_command, uname=os.uname, statvfs=os.fstatvfs,
                 process_id=None, mount_id=None, checkpoint=None):
        self.command = command
        self.uname = uname
        self.statvfs = statvfs
        self.process_id = os.getpid() if process_id is None else process_id
        self.mount_id = mount_id
        self.checkpoint = checkpoint or (lambda _stage: None)


def _fd_mount_id(files, adapters, fd):
    if adapters.mount_id is not None:
        value = adapters.mount_id(fd)
    else:
        status, content = files.read(f"proc/{adapters.process_id}/fdinfo/{fd}", limit=4096)
        if content is None:
            raise DiagnosticError("boot_mount_unavailable")
        rows = [row for row in content.splitlines() if row.startswith("mnt_id:")]
        if len(rows) != 1:
            raise DiagnosticError("invalid_mountinfo")
        match = re.fullmatch(r"mnt_id:[ \t]+([0-9]{1,10})", rows[0])
        if not match:
            raise DiagnosticError("invalid_mountinfo")
        value = int(match.group(1))
    if type(value) is not int or not 0 < value <= (1 << 32) - 1:
        raise DiagnosticError("invalid_mountinfo")
    return value


def _mounts(content, root_mount_id, boot_mount_id):
    """Only fixed mountpoints and generic types leave this parser."""
    found = {}
    ids = set()
    for line in content.splitlines():
        fields = line.split()
        try:
            split = fields.index("-")
        except ValueError:
            raise DiagnosticError("invalid_mountinfo") from None
        if split < 6 or len(fields) < split + 4:
            raise DiagnosticError("invalid_mountinfo")
        if not re.fullmatch(r"[0-9]{1,10}", fields[0]):
            raise DiagnosticError("invalid_mountinfo")
        mount_id = int(fields[0])
        if not 0 < mount_id <= (1 << 32) - 1 or mount_id in ids:
            raise DiagnosticError("invalid_mountinfo")
        ids.add(mount_id)
        if mount_id not in {root_mount_id, boot_mount_id}:
            continue
        expected_point = "/boot/firmware" if mount_id == boot_mount_id else "/"
        if fields[4] != expected_point or not re.fullmatch(r"[0-9]{1,7}:[0-9]{1,7}", fields[2]):
            raise DiagnosticError("invalid_mountinfo")
        major, minor = map(int, fields[2].split(":"))
        if major > (1 << 20) or minor > (1 << 20):
            raise DiagnosticError("invalid_mountinfo")
        found[fields[4]] = {"device": (major, minor), "type": fields[split + 1],
                             "source": fields[split + 2], "options": fields[5].split(",")}
    if "/boot/firmware" not in found or found["/boot/firmware"]["type"] != "vfat":
        raise DiagnosticError("boot_mount_refused")
    if "rw" not in found["/boot/firmware"]["options"]:
        raise DiagnosticError("boot_mount_refused")
    return found


def _filesystem(fd, mount, adapters):
    try:
        values = adapters.statvfs(fd)
        total = values.f_frsize * values.f_blocks
        free = values.f_frsize * values.f_bavail
        if (type(total) is not int or type(free) is not int
                or not 0 <= free <= total <= (1 << 63) - 1):
            return _failure("invalid")
        fs_type = mount["type"] if mount and mount["type"] in {"vfat", "ext4", "ext3", "ext2", "btrfs", "xfs", "overlay"} else "other"
        source = mount["source"] if mount else ""
        if re.fullmatch(r"/dev/mmcblk[0-9]{1,2}(?:p[0-9]{1,2})?", source):
            device = "mmc"
        elif re.fullmatch(r"/dev/sd[a-z]{1,2}[0-9]{0,2}", source):
            device = "usb_or_scsi"
        elif re.fullmatch(r"/dev/vd[a-z][0-9]{0,2}", source):
            device = "virtio"
        elif re.fullmatch(r"/dev/loop[0-9]{1,3}(?:p[0-9]{1,2})?", source):
            device = "loop"
        else:
            device = "other"
        return {"status": "ok", "type": fs_type, "device": device,
                "total_bytes": total, "available_bytes": free}
    except (OSError, ValueError, OverflowError):
        return _failure("read_error")


def _command(adapters, argv, *, limit, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return _failure("timeout"), None
    return adapters.command(argv, timeout=min(COMMAND_TIMEOUT, remaining), limit=limit)


def _service(unit, adapters, deadline):
    properties = ("ActiveState", "SubState", "LoadState", "UnitFileState") if unit.endswith(".timer") else PROPERTIES
    status, content = _command(adapters, ("/usr/bin/systemctl", "--no-pager", "show", unit,
                                        "--property=" + ",".join(properties)),
                              deadline=deadline, limit=MAX_OUTPUT)
    if status != {"status": "ok"}:
        return _failure(status["status"] if status.get("status") in {"missing", "timeout", "too_large", "command_error", "invalid"} else "command_error")
    if not isinstance(content, str) or len(content) > MAX_OUTPUT:
        return _failure("invalid")
    values = {}
    for line in content.splitlines():
        key, equal, value = line.partition("=")
        if not equal or key not in properties or key in values:
            return _failure("invalid")
        if key == "ExecMainStatus":
            if not re.fullmatch(r"0|[1-9][0-9]{0,2}", value) or int(value) > 255:
                return _failure("invalid")
            values[key] = int(value)
        elif value not in PROPERTY_VALUES[key]:
            return _failure("invalid")
        else:
            values[key] = value
    if set(values) != set(properties):
        return _failure("invalid")
    if unit.endswith(".timer"):
        values["Result"] = values["ExecMainStatus"] = None
    return {"status": "ok", **values}


def _identity(files):
    result = {}
    names = {}
    for label, path, pattern in (
        ("machine_id", "etc/machine-id", MACHINE_ID),
        ("hostname", "etc/hostname", HOSTNAME),
        ("kernel_hostname", "proc/sys/kernel/hostname", HOSTNAME),
    ):
        status, content = files.read(path, limit=256)
        if content is None:
            result[label] = status
            continue
        value = _single_line(content)
        if not pattern.fullmatch(value) or (label == "machine_id" and value == "0" * 32):
            result[label] = _failure("invalid")
            continue
        result[label] = {"status": "ok", "sha256": _sha(value)}
        names[label] = value
    status, content = files.read("var/lib/inkyos/system.json", limit=4096, private=True)
    state_name = None
    if content is None:
        result["firstboot_state"] = status
    else:
        try:
            def unique_pairs(pairs):
                parsed = {}
                for key, value in pairs:
                    if key in parsed:
                        raise ValueError()
                    parsed[key] = value
                return parsed
            value = json.loads(content, object_pairs_hook=unique_pairs)
            if (not isinstance(value, dict) or set(value) != {"version", "hostname"}
                    or type(value["version"]) is not int or value["version"] != 1
                    or not isinstance(value["hostname"], str) or not HOSTNAME.fullmatch(value["hostname"])):
                raise ValueError()
            state_name = value["hostname"]
            result["firstboot_state"] = {"status": "ok", "version": 1, "hostname_sha256": _sha(state_name)}
        except (ValueError, TypeError, RecursionError):
            result["firstboot_state"] = _failure("invalid")
    hosts_status, hosts = files.read("etc/hosts", limit=65536)
    if state_name is None or "hostname" not in names or "kernel_hostname" not in names or hosts is None:
        result["coherence"] = _failure("unavailable")
    else:
        host_rows = [line.split("#", 1)[0].split() for line in hosts.splitlines()]
        local_rows = [row for row in host_rows if row and row[0] == "127.0.1.1"]
        result["coherence"] = {"status": "ok", "state_matches_hostname": state_name == names["hostname"],
                               "state_matches_kernel": state_name == names["kernel_hostname"],
                               "state_matches_hosts": local_rows == [["127.0.1.1", state_name]]}
    result["hosts_file"] = hosts_status
    return result


def _hardware(files, adapters, deadline):
    result = {}
    try:
        info = adapters.uname()
        result["kernel"] = ({"status": "ok", "release": info.release}
                            if isinstance(info.release, str) and KERNEL_RELEASE.fullmatch(info.release)
                            else _failure("invalid"))
        result["architecture"] = ({"status": "ok", "value": info.machine}
                                  if info.machine in {"aarch64", "armv7l", "armv6l", "x86_64"}
                                  else _failure("invalid"))
    except OSError:
        result["kernel"] = result["architecture"] = _failure("read_error")
    status, model = files.read("sys/firmware/devicetree/base/model", limit=256)
    if model is None:
        result["model"] = status
    else:
        # Device-tree model properties end in one NUL; never inspect serial.
        value = model[:-1] if model.endswith("\0") else model
        match = re.fullmatch(r"Raspberry Pi (Zero 2 W|Zero W|Zero|[2345] Model [AB](?: Plus)?|400|500|Compute Module [345](?: Lite)?)(?: Rev [0-9]\.[0-9])?", value)
        result["model"] = {"status": "ok", "value": "Raspberry Pi " + match.group(1)} if match else _failure("invalid")
    status, uptime = files.read("proc/uptime", limit=128)
    if uptime is None:
        result["uptime_seconds"] = status
    else:
        match = re.fullmatch(r"([0-9]{1,10})\.[0-9]{1,3} [0-9]{1,12}\.[0-9]{1,3}\n?", uptime)
        result["uptime_seconds"] = ({"status": "ok", "value": int(match.group(1))}
                                    if match and int(match.group(1)) <= 315576000
                                    else _failure("invalid"))
    status, memory = files.read("proc/meminfo", limit=16384)
    if memory is None:
        result["memory"] = status
    else:
        matches = {}
        for line in memory.splitlines():
            match = re.fullmatch(r"(MemTotal|MemAvailable):[ \t]+([0-9]{1,12}) kB", line)
            if match:
                if match.group(1) in matches:
                    matches = {}
                    break
                matches[match.group(1)] = int(match.group(2)) * 1024
        result["memory"] = ({"status": "ok", "total_bytes": matches["MemTotal"], "available_bytes": matches["MemAvailable"]}
                            if set(matches) == {"MemTotal", "MemAvailable"} and 0 <= matches["MemAvailable"] <= matches["MemTotal"] <= (1 << 50)
                            else _failure("invalid"))
    status, temperature = files.read("sys/devices/virtual/thermal/thermal_zone0/temp", limit=128)
    if temperature is None:
        result["temperature_millicelsius"] = status
    else:
        value = _single_line(temperature)
        result["temperature_millicelsius"] = ({"status": "ok", "value": int(value)}
                                              if re.fullmatch(r"-?[0-9]{1,6}", value) and -40000 <= int(value) <= 150000
                                              else _failure("invalid"))
    status, throttling = _command(adapters, ("/usr/bin/vcgencmd", "get_throttled"), deadline=deadline, limit=128)
    if status != {"status": "ok"}:
        result["throttling"] = _failure(status["status"] if status.get("status") in {"missing", "timeout", "too_large", "command_error", "invalid"} else "command_error")
    else:
        match = (re.fullmatch(r"throttled=0x([0-9a-f]{1,8})\n?", throttling)
                 if isinstance(throttling, str) and len(throttling) <= 128 else None)
        value = int(match.group(1), 16) if match else None
        result["throttling"] = ({"status": "ok", "value": value}
                                if value is not None and value & ~0xF000F == 0 else _failure("invalid"))
    return result


def _write_report(directory, filename, content, owner_uid, checkpoint):
    temporary = fd = None
    try:
        try:
            target = os.stat(filename, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            _metadata(target, owner_uid, fat=True)
        for _attempt in range(100):
            temporary = f".{filename}.{os.getpid()}.{next(_counter)}"
            try:
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o644, dir_fd=directory)
                break
            except FileExistsError:
                temporary = None
        if fd is None:
            raise DiagnosticError("report_write_failed")
        _metadata(os.fstat(fd), owner_uid, fat=True)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
        os.fsync(fd)
        checkpoint("report:temp_fsynced")
        os.close(fd)
        fd = None
        os.replace(temporary, filename, src_dir_fd=directory, dst_dir_fd=directory)
        temporary = None
        checkpoint("report:replaced")
        os.fsync(directory)
        checkpoint("report:directory_fsynced")
    except (OSError, DiagnosticError) as exc:
        raise DiagnosticError("report_write_failed") from exc
    finally:
        if fd is not None:
            os.close(fd)
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass


def export_report(root, *, owner_uid=0, adapters=None):
    """Only reports below the verified boot mount are created or replaced."""
    adapters = adapters or Adapters()
    deadline = time.monotonic() + COMMAND_BUDGET
    if type(adapters.process_id) is not int or adapters.process_id <= 0:
        raise DiagnosticError("invalid_adapter")
    files = Files(root, owner_uid)
    boot = output = None
    try:
        # /proc/self is a kernel symlink. The numeric process directory names
        # the same mount namespace without permitting symlink traversal.
        status, mountinfo = files.read(f"proc/{adapters.process_id}/mountinfo", limit=1024 * 1024)
        if mountinfo is None:
            raise DiagnosticError("boot_mount_unavailable")
        boot = files.directory("boot/firmware", fat=True)
        mounts = _mounts(mountinfo, _fd_mount_id(files, adapters, files.root),
                         _fd_mount_id(files, adapters, boot))
        mounted_device = os.fstat(boot).st_dev
        if (os.major(mounted_device), os.minor(mounted_device)) != mounts["/boot/firmware"]["device"]:
            raise DiagnosticError("boot_mount_refused")
        status, boot_id = files.read("proc/sys/kernel/random/boot_id", limit=128)
        if (boot_id is None or not UUID.fullmatch(_single_line(boot_id))
                or _single_line(boot_id) == "00000000-0000-0000-0000-000000000000"):
            raise DiagnosticError("boot_identity_unavailable")
        boot_hash = _sha(_single_line(boot_id))
        filename = "boot-" + boot_hash + ".json"
        report = {"schema_version": 1, "boot_id_sha256": boot_hash,
                  "hardware": _hardware(files, adapters, deadline), "identity": _identity(files),
                  "filesystems": {"root": _filesystem(files.root, mounts.get("/"), adapters),
                                  "boot": _filesystem(boot, mounts["/boot/firmware"], adapters)},
                  "services": {unit: _service(unit, adapters, deadline) for unit in UNITS}}
        content = (json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
        try:
            os.mkdir("inkyos-diagnostics", 0o755, dir_fd=boot)
        except FileExistsError:
            pass
        os.fsync(boot)
        output = os.open("inkyos-diagnostics", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=boot)
        _metadata(os.fstat(output), owner_uid, directory=True, fat=True)
        _write_report(output, filename, content, owner_uid, adapters.checkpoint)
        return {"filename": filename, "report": report}
    except OSError as exc:
        raise DiagnosticError("diagnostic_failed") from exc
    finally:
        if output is not None:
            os.close(output)
        if boot is not None:
            os.close(boot)
        files.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        print("InkyOS diagnostic refused: Linux root required.", file=sys.stderr)
        return 1
    try:
        export_report("/")
    except DiagnosticError as exc:
        # All constructor sites use fixed strings; never render nested errors.
        print("InkyOS diagnostic failed: " + str(exc) + ".", file=sys.stderr)
        return 1
    print("InkyOS SD diagnostic exported.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
