#!/usr/bin/env python3
"""Exact-parent NM/libnm bench: disposable image, namespaces, synthetic profile.

Host CLI: probe-test-access-network.py PARENT_EXPORT
The --inside entry requires the sealed marked build VM and isolated namespaces.
Only this bench's new image may be removed, after verified report export.
"""
import sys
sys.dont_write_bytecode = True

import hashlib
import importlib.util
import configparser
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time

IMAGE_SHA256 = "0854663168acf7986d26a473e9116dddeb7d6fbef8226f5d1d96cf190f77e286"
IMAGE_SIZE = 3061841920
APPLICATION_SOURCE = "c31b13afdc957425571810c46230eaaf52fa5d14"
APPLICATION_MANIFEST = "c4183e7304e3ff979450977b36e4a007b30016de68bb23ef121c7ca733cd26a1"
VM = "inkyos-build"
LO_CONFIG = "10-inkyos-test-loopback.conf"
LO_CONFIG_PATH = "etc/NetworkManager/conf.d/" + LO_CONFIG
SOURCES = ("probe-test-access-network.py", "probe-test-access-network-linux.sh", "test-access-import.py", LO_CONFIG)
PROGRAMS = ("usr/sbin/NetworkManager", "usr/bin/nmcli", "usr/bin/dbus-daemon",
            "usr/lib/aarch64-linux-gnu/libnm.so.0.1.0")
CHECKS = ("parent_bytes_pinned", "sources_sealed", "private_namespaces", "loopback_only",
          "programs_match_parent", "networkmanager_package_exact", "parent_nm_configuration_preserved",
          "private_run_and_device_tree", "libnm_profile_verified", "libnm_binary_ssid_exact",
          "libnm_hex_psk_exact", "libnm_autoconnect_disabled", "libnm_band_bg", "libnm_rsn_only",
          "dbus_started_in_namespace", "networkmanager_started_in_namespace", "baseline_observed",
          "keyfile_loaded_by_daemon", "daemon_profile_properties_exact", "wireless_remained_disabled",
          "test_loopback_configuration_applied", "effective_loopback_configuration", "loopback_still_kernel_up", "loopback_unmanaged_in_nm",
          "zero_profiles_after_override", "zero_active_after_override", "only_test_profile_after_override",
          "restricted_profile_after_override", "wireless_still_disabled_after_override",
          "application_still_masked", "processes_stopped", "mounts_removed", "loop_detached")
NM_PROFILE = "/run/NetworkManager/system-connections/inkyos-test-access.nmconnection"
FIXTURE_SSID = bytes((0, 1, 9, 10, 59, 61, 92, 127, 128, 255))
FIXTURE_PSK = "ab" * 32
UUID = "ea14df0f-8d69-4f38-8716-16576575e39f"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C"}

LIBNM = r'''
import ctypes as c,json,pathlib,sys
raw=pathlib.Path(sys.argv[1]).read_bytes()
g=c.CDLL('libglib-2.0.so.0'); n=c.CDLL('libnm.so.0')
def fn(lib,name,restype,args):
 f=getattr(lib,name); f.restype=restype; f.argtypes=args; return f
P=c.c_void_p; S=c.c_char_p; I=c.c_int; U=c.c_uint; E=c.POINTER(P)
err=P(); k=fn(g,'g_key_file_new',P,[])()
assert fn(g,'g_key_file_load_from_data',I,[P,S,c.c_size_t,I,E])(k,raw,len(raw),0,c.byref(err)) and not err.value
conn=fn(n,'nm_keyfile_read',P,[P,S,I,P,P,E])(k,b'/',0,None,None,c.byref(err))
assert conn and not err.value
sc=fn(n,'nm_connection_get_setting_connection',P,[P])(conn)
sw=fn(n,'nm_connection_get_setting_wireless',P,[P])(conn)
ss=fn(n,'nm_connection_get_setting_wireless_security',P,[P])(conn)
assert sc and sw and ss
size=c.c_size_t(); b=fn(n,'nm_setting_wireless_get_ssid',P,[P])(sw)
p=fn(g,'g_bytes_get_data',P,[P,c.POINTER(c.c_size_t)])(b,c.byref(size))
out={
 'libnm_profile_verified':bool(fn(n,'nm_connection_verify',I,[P,E])(conn,c.byref(err))) and not err.value,
 'libnm_binary_ssid_exact':c.string_at(p,size.value)==bytes((0,1,9,10,59,61,92,127,128,255)),
 'libnm_hex_psk_exact':fn(n,'nm_setting_wireless_security_get_psk',S,[P])(ss)==b'ab'*32,
 'libnm_autoconnect_disabled':fn(n,'nm_setting_connection_get_autoconnect',I,[P])(sc)==0,
 'libnm_band_bg':fn(n,'nm_setting_wireless_get_band',S,[P])(sw)==b'bg',
 'libnm_rsn_only':fn(n,'nm_setting_wireless_security_get_key_mgmt',S,[P])(ss)==b'wpa-psk' and fn(n,'nm_setting_wireless_security_get_num_protos',U,[P])(ss)==1 and fn(n,'nm_setting_wireless_security_get_proto',S,[P,U])(ss,0)==b'rsn',
}
print(json.dumps(out,sort_keys=True))
'''


def require(value, label="probe_refused"):
    if value is not True:
        raise ValueError(label)


def sha(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024**2), b""):
            value.update(block)
    return value.hexdigest()


def read(path, *, mode=None, owner=None, limit=32 * 1024**2):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit
                and (owner is None or info.st_uid == info.st_gid == owner)
                and (mode is None or stat.S_IMODE(info.st_mode) == mode))
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        stamp = lambda v: (v.st_dev, v.st_ino, v.st_size, v.st_mtime_ns, v.st_ctime_ns)
        require(len(raw) == info.st_size and stamp(info) == stamp(os.fstat(fd))
                and stamp(info) == stamp(os.stat(path, follow_symlinks=False)))
        return raw
    finally:
        os.close(fd)


def command(argv, *, data=None, timeout=15):
    return subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env=ENV if sys.platform.startswith("linux") else None, timeout=timeout)


def must(argv, **kwargs):
    result = command(argv, **kwargs)
    require(result.returncode == 0, "command_failed")
    return result.stdout


def json_write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n"); stream.flush(); os.fsync(stream.fileno())


def inside(work):
    require(sys.platform.startswith("linux") and os.geteuid() == 0
            and re.fullmatch(r"/var/tmp/inkyos-work/test-access-network\.[0-9a-f]{8}", str(work)) is not None)
    require(Path("/var/lib/inkyos-build/owner").read_text().strip() == "inkyos-builder-v1")
    require(all(os.readlink("/proc/self/ns/" + n) != os.readlink("/proc/1/ns/" + n)
                for n in ("pid", "net", "mnt", "uts")))
    info = work.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700)
    inputs = json.loads(read(work / "inputs.json", mode=0o444, owner=0))
    require(set(work.iterdir()) == {work / name for name in inputs["files"]} | {work / "inputs.json", work / "probe.img"})
    for name, expected in inputs["files"].items():
        require(Path(name).name == name and hashlib.sha256(read(work / name, mode=0o444, owner=0)).hexdigest() == expected)
    report = {"schema_version": 1, "scope": "isolated-exact-parent-networkmanager-probe", "passed": False,
              "checks": dict.fromkeys(CHECKS, False), "error_stage": None, "baseline": None, "with_loopback_override": None,
              "source_sha256": {name: inputs["files"][name] for name in SOURCES},
              "parent_image_sha256": IMAGE_SHA256, "program_sha256": {}, "configuration_sha256": {},
              "networkmanager_package": None, "real_radio_present": False, "real_wifi_connected": False,
              "application_activated": False, "hardware_qualified": False, "release_qualified": False}
    checks, root, mounts, children, loop = report["checks"], work / "root", [], [], None
    stage = "parent"
    def interrupted(_number, _frame): raise InterruptedError("probe_interrupted")
    signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
    def target(argv, **kwargs): return command(["chroot", str(root), *argv], **kwargs)
    def target_must(argv, **kwargs):
        result = target(argv, **kwargs); require(result.returncode == 0); return result.stdout
    def mount(kind, source, relative, options):
        path = root / relative
        require(path.is_dir() and not path.is_symlink())
        must(["mount", "-t", kind, "-o", options, source, str(path)])
        mounts.append(path)
    def create(relative, raw, mode=0o600):
        path = root / relative.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode); stream.write(raw)
    def interfaces(): return {row.split(":", 1)[0].strip() for row in Path("/proc/net/dev").read_text().splitlines()[2:]}
    try:
        parent = json.loads(read(work / "parent-manifest.json", mode=0o444, owner=0))
        require(parent["kind"] == "test-lan-prepared" and parent["image"]["sha256"] == IMAGE_SHA256
                and parent["image"]["size_bytes"] == IMAGE_SIZE
                and parent["application"]["source_commit"] == APPLICATION_SOURCE
                and parent["application"]["manifest_sha256"] == APPLICATION_MANIFEST)
        inventory_raw = read(work / "filesystem-manifest.json", mode=0o444, owner=0)
        require(hashlib.sha256(inventory_raw).hexdigest() == parent["reports"]["filesystem-manifest.json"])
        inventory = json.loads(inventory_raw)["rootfs"]
        image = work / "probe.img"
        info = image.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == IMAGE_SIZE and sha(image) == IMAGE_SHA256)
        checks.update(parent_bytes_pinned=True, sources_sealed=True, private_namespaces=True)
        require(interfaces() == {"lo"}); checks["loopback_only"] = True
        must(["ip", "link", "set", "lo", "up"]); must(["hostname", "inkyos-nm-probe"])
        stage = "mount"
        root.mkdir(mode=0o700)
        loop = must(["losetup", "--find", "--show", "--partscan", "--", str(image)]).decode().strip()
        require(re.fullmatch(r"/dev/loop[0-9]+", loop) is not None)
        for _ in range(20):
            if Path(loop + "p2").exists(): break
            time.sleep(0.1)
        require(must(["lsblk", "-nr", "-o", "TYPE", loop]).splitlines() == [b"loop", b"part", b"part"])
        require(must(["blkid", "-p", "-s", "TYPE", "-o", "value", loop + "p2"]).strip() == b"ext4")
        mount("ext4", loop + "p2", "", "rw,noatime,nosuid,nodev")
        stage = "inventory"
        for name in PROGRAMS:
            require(inventory[name]["type"] == "file" and sha(root / name) == inventory[name]["sha256"])
            report["program_sha256"][name] = inventory[name]["sha256"]
        checks["programs_match_parent"] = True
        config = {name: meta for name, meta in inventory.items() if meta["type"] == "file"
                  and (name.startswith("etc/NetworkManager/") or name.startswith("usr/lib/NetworkManager/conf.d/"))}
        for name, meta in config.items():
            require(sha(root / name) == meta["sha256"])
            report["configuration_sha256"][name] = meta["sha256"]
        checks["parent_nm_configuration_preserved"] = True
        package = target_must(["/usr/bin/dpkg-query", "-W", "-f=${Version}", "network-manager"]).decode()
        require(package == "1.52.1-1+rpt4")
        report["networkmanager_package"] = package; checks["networkmanager_package_exact"] = True
        mount("tmpfs", "tmpfs", "run", "mode=0755,nosuid,nodev,noexec")
        mount("tmpfs", "tmpfs", "dev", "mode=0755,nosuid,noexec")
        mount("proc", "proc", "proc", "nosuid,nodev,noexec")
        mount("sysfs", "sysfs", "sys", "ro,nosuid,nodev,noexec")
        for name, minor in (("null", 3), ("zero", 5), ("random", 8), ("urandom", 9)):
            os.mknod(root / "dev" / name, stat.S_IFCHR | 0o666, os.makedev(1, minor))
        require(not (root / "dev/rfkill").exists() and not (root / "run/dbus/system_bus_socket").exists())
        require({p.name for p in (root / "sys/class/net").iterdir()} == {"lo"})
        phys = root / "sys/class/ieee80211"
        require(not phys.exists() or not any(phys.iterdir()))
        checks["private_run_and_device_tree"] = True
        # Only this never-booted disposable image receives a fixed synthetic machine ID.
        identity = root / "etc/machine-id"
        require(identity.is_file() and not identity.is_symlink() and identity.read_bytes() == b"uninitialized\n")
        identity.write_bytes(b"0123456789abcdef0123456789abcdef\n")
        (root / "run/dbus").mkdir(mode=0o755)
        (root / "run/NetworkManager/system-connections").mkdir(parents=True, mode=0o700)
        module = {"__name__": "network_probe_importer", "__file__": str(work / "test-access-import.py")}
        exec(compile(read(work / "test-access-import.py", mode=0o444, owner=0), "test-access-import.py", "exec"), module)
        profile = module["network_profile"]({"security": "wpa2-personal", "band": "2.4GHz",
                                             "ssid_hex": FIXTURE_SSID.hex(), "psk": FIXTURE_PSK})
        create("run/inkyos-nm-probe/fixture.nmconnection", profile)
        stage = "libnm"
        parsed = json.loads(target_must(["/usr/bin/python3", "-I", "-c", LIBNM, "/run/inkyos-nm-probe/fixture.nmconnection"]))
        names = {name for name in CHECKS if name.startswith("libnm_")}
        require(type(parsed) is dict and set(parsed) == names and all(type(value) is bool for value in parsed.values()))
        checks.update(parsed); require(all(parsed.values()))
        stage = "dbus"
        dbus = subprocess.Popen(["chroot", str(root), "/usr/bin/dbus-daemon", "--system", "--nofork", "--nopidfile"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV)
        children.append(dbus)
        for _ in range(50):
            if (root / "run/dbus/system_bus_socket").exists(): break
            require(dbus.poll() is None); time.sleep(0.1)
        require((root / "run/dbus/system_bus_socket").is_socket()); checks["dbus_started_in_namespace"] = True
        stage = "networkmanager"
        nm = subprocess.Popen(["chroot", str(root), "/usr/sbin/NetworkManager", "--no-daemon", "--log-level", "WARN"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV)
        children.append(nm)
        for _ in range(50):
            observed = target(["/usr/bin/nmcli", "-g", "RUNNING", "general"], timeout=2)
            if observed.returncode == 0 and observed.stdout == b"running\n": break
            require(nm.poll() is None); time.sleep(0.1)
        require(observed.returncode == 0 and observed.stdout == b"running\n")
        checks["networkmanager_started_in_namespace"] = True
        time.sleep(2)
        stage = "baseline"
        known = target_must(["/usr/bin/nmcli", "-t", "-f", "UUID,TYPE,DEVICE", "connection", "show"]).decode().splitlines()
        active = target_must(["/usr/bin/nmcli", "-t", "-f", "UUID,TYPE,DEVICE", "connection", "show", "--active"]).decode().splitlines()
        lo = target_must(["/usr/bin/nmcli", "-g", "GENERAL.STATE,GENERAL.NM-MANAGED", "device", "show", "lo"])
        def loopback(rows):
            return len(rows) == 1 and re.fullmatch(r"[0-9a-f-]{36}:loopback:lo", rows[0]) is not None
        report["baseline"] = {"known_profiles": len(known), "active_connections": len(active),
            "only_loopback_profile": loopback(known), "only_loopback_active": loopback(active),
            "loopback_managed": lo.splitlines()[-1:] == [b"yes"],
            "zero_profile_gate_would_pass": known == [], "zero_active_gate_would_pass": active == []}
        checks["baseline_observed"] = True
        stage = "daemon_keyfile"
        create(NM_PROFILE, profile)
        require(target(["/usr/bin/nmcli", "connection", "load", NM_PROFILE]).returncode == 0)
        checks["keyfile_loaded_by_daemon"] = True
        values = target_must(["/usr/bin/nmcli", "-g", "connection.uuid,connection.type,connection.interface-name,connection.autoconnect,802-11-wireless.band,802-11-wireless.mode", "connection", "show", "uuid", UUID])
        checks["daemon_profile_properties_exact"] = values == (UUID + "\n802-11-wireless\nwlan0\nno\nbg\ninfrastructure\n").encode()
        checks["wireless_remained_disabled"] = target_must(["/usr/bin/nmcli", "radio", "wifi"]) == b"disabled\n"
        stage = "loopback_override"
        nm.terminate(); nm.wait(timeout=5)
        fixture_path = root / NM_PROFILE.lstrip("/")
        require(read(fixture_path, mode=0o600, owner=0) == profile)
        fixture_path.unlink()  # Only the synthetic runtime profile created above.
        override = read(work / LO_CONFIG, mode=0o444, owner=0)
        require(override == b"[keyfile]\nunmanaged-devices=interface-name:lo\n")
        create(LO_CONFIG_PATH, override, 0o644)
        require(all(sha(root / name) == value for name, value in report["configuration_sha256"].items()))
        checks["test_loopback_configuration_applied"] = True
        effective = target_must(["/usr/sbin/NetworkManager", "--print-config"])
        parsed_config = configparser.ConfigParser(interpolation=None)
        try:
            parsed_config.read_string(effective.decode("utf-8"))
            checks["effective_loopback_configuration"] = parsed_config.get("keyfile", "unmanaged-devices", fallback=None) == "interface-name:lo"
        except (configparser.Error, UnicodeError):
            pass
        require(checks["effective_loopback_configuration"])
        nm = subprocess.Popen(["chroot", str(root), "/usr/sbin/NetworkManager", "--no-daemon", "--log-level", "WARN"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=ENV)
        children.append(nm)
        for _ in range(50):
            observed = target(["/usr/bin/nmcli", "-g", "RUNNING", "general"], timeout=2)
            if observed.returncode == 0 and observed.stdout == b"running\n": break
            require(nm.poll() is None); time.sleep(0.1)
        require(observed.returncode == 0 and observed.stdout == b"running\n")
        time.sleep(2)
        known = target_must(["/usr/bin/nmcli", "-t", "-f", "UUID", "connection", "show"])
        active = target_must(["/usr/bin/nmcli", "-t", "-f", "UUID", "connection", "show", "--active"])
        managed = target_must(["/usr/bin/nmcli", "-g", "GENERAL.NM-MANAGED", "device", "show", "lo"])
        link = json.loads(must(["ip", "-j", "link", "show", "lo"]))
        checks["loopback_still_kernel_up"] = len(link) == 1 and "UP" in link[0]["flags"]
        checks["loopback_unmanaged_in_nm"] = managed == b"no\n"
        checks["zero_profiles_after_override"] = known == b""
        checks["zero_active_after_override"] = active == b""
        report["with_loopback_override"] = {"known_profiles": len(known.splitlines()), "active_connections": len(active.splitlines()),
              "loopback_managed": managed == b"yes\n", "loopback_kernel_up": checks["loopback_still_kernel_up"]}
        stage = "override_keyfile"
        create(NM_PROFILE, profile)
        require(target(["/usr/bin/nmcli", "connection", "load", NM_PROFILE]).returncode == 0)
        checks["only_test_profile_after_override"] = target_must(["/usr/bin/nmcli", "-t", "-f", "UUID", "connection", "show"]) == (UUID + "\n").encode()
        values = target_must(["/usr/bin/nmcli", "-g", "connection.uuid,connection.type,connection.interface-name,connection.autoconnect,802-11-wireless.band,802-11-wireless.mode", "connection", "show", "uuid", UUID])
        checks["restricted_profile_after_override"] = values == (UUID + "\n802-11-wireless\nwlan0\nno\nbg\ninfrastructure\n").encode()
        checks["wireless_still_disabled_after_override"] = target_must(["/usr/bin/nmcli", "radio", "wifi"]) == b"disabled\n"
        checks["application_still_masked"] = all((root / "etc/systemd/system" / name).is_symlink()
              and os.readlink(root / "etc/systemd/system" / name) == "/dev/null" for name in
              ("inky-studio.service", "inky-network.service", "ssh.service", "ssh.socket", "sshswitch.service"))
        require(interfaces() == {"lo"})
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        report["error_stage"] = stage
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN); signal.signal(signal.SIGINT, signal.SIG_IGN)
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
                try: child.wait(timeout=3)
                except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=3)
        def live_children():
            result = []
            if root / "proc" not in mounts: return result
            for path in (root / "proc").iterdir():
                if not path.name.isdigit() or int(path.name) == 1: continue
                try:
                    if os.readlink(path / "ns/pid") == os.readlink("/proc/self/ns/pid") and not re.search(r"^State:\s+Z\b", (path / "status").read_text(), re.M):
                        result.append(int(path.name))
                except (FileNotFoundError, ProcessLookupError): pass
            return result
        # Here Python is PID 1 in the new namespace (the wrapper used exec).
        for pid in live_children():
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
        for _ in range(20):
            if not live_children(): break
            time.sleep(0.05)
        checks["processes_stopped"] = all(child.poll() is not None for child in children) and not live_children()
        for path in reversed(mounts[:]):
            if command(["umount", str(path)], timeout=5).returncode != 0: break
            mounts.remove(path)
        checks["mounts_removed"] = not mounts
        checks["loop_detached"] = loop is None or (not mounts and command(["losetup", "-d", loop]).returncode == 0)
        if not mounts and root.exists(): root.rmdir()
        report["passed"] = all(checks.values()) and report["error_stage"] is None
        json_write(work / "report.json", report)
    return 0 if report["passed"] else 1


def host(parent):
    require(sys.platform == "darwin")
    repo = Path(__file__).resolve().parents[1]
    require(parent.is_dir() and not parent.is_symlink())
    vm = lambda *args: ["limactl", "shell", "--workdir=/tmp", VM, *args]
    require(must(vm("cat", "/var/lib/inkyos-build/owner")).strip() == b"inkyos-builder-v1")
    parent_raw = read(parent / "manifest.json")
    manifest = json.loads(parent_raw)
    image = parent / manifest["image"]["filename"]
    require(image.parent == parent and image.name.endswith(".img") and image.lstat().st_size == IMAGE_SIZE
            and stat.S_ISREG(image.lstat().st_mode) and image.lstat().st_nlink == 1
            and manifest["image"]["sha256"] == IMAGE_SHA256 and sha(image) == IMAGE_SHA256)
    work = repo / "build" / ("test-access-network." + os.urandom(4).hex())
    work.mkdir(mode=0o700)
    blobs = {name: read(repo / "scripts" / name) for name in SOURCES if name != LO_CONFIG}
    blobs[LO_CONFIG] = read(repo / "overlay-test-access/NetworkManager.conf.d" / LO_CONFIG)
    blobs.update({"parent-manifest.json": parent_raw, "filesystem-manifest.json": read(parent / "filesystem-manifest.json")})
    for name, raw in blobs.items(): (work / name).write_bytes(raw)
    inputs = {"schema_version": 1, "scope": "exact-parent-networkmanager-inputs", "parent_image_sha256": IMAGE_SHA256,
              "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in blobs.items()}}
    json_write(work / "inputs.json", inputs)
    guest = "/var/tmp/inkyos-work/" + work.name
    must(vm("mkdir", "-m", "700", guest))
    for name in (*blobs, "inputs.json"):
        must(["limactl", "copy", str(work / name), VM + ":" + guest + "/" + name], timeout=60)
    must(["limactl", "copy", str(image), VM + ":" + guest + "/probe.img"], timeout=180)
    seal = r'''
import hashlib,json,os,pathlib,stat,sys
p=pathlib.Path(sys.argv[1]); raw=(p/'inputs.json').read_bytes(); assert hashlib.sha256(raw).hexdigest()==sys.argv[2]
inputs=json.loads(raw); expected=set(inputs['files'])|{'inputs.json','probe.img'}
assert set(x.name for x in p.iterdir())==expected
for f in [p,*p.iterdir()]:
 i=f.lstat(); assert stat.S_ISDIR(i.st_mode) if f==p else stat.S_ISREG(i.st_mode) and i.st_nlink==1
 os.chown(f,0,0,follow_symlinks=False); os.chmod(f,0o700 if f==p else 0o600 if f.name=='probe.img' else 0o444,follow_symlinks=False)
for name,pin in inputs['files'].items(): assert hashlib.sha256((p/name).read_bytes()).hexdigest()==pin
'''
    must(vm("sudo", "python3", "-I", "-c", seal, guest, sha(work / "inputs.json")))
    result = command(vm("sudo", "bash", guest + "/probe-test-access-network-linux.sh", guest), timeout=220)
    raw = must(vm("sudo", "cat", guest + "/report.json"))
    report = json.loads(raw)
    require(type(report) is dict and set(report["checks"]) == set(CHECKS)
            and all(type(value) is bool for value in report["checks"].values())
            and report["source_sha256"] == {name: inputs["files"][name] for name in SOURCES}
            and report["parent_image_sha256"] == IMAGE_SHA256)
    (work / "report.json").write_bytes(raw)
    require(read(work / "report.json") == raw)
    cleaned = False
    if all(report["checks"][name] for name in ("processes_stopped", "mounts_removed", "loop_detached")):
        cleanup = r'''
import json,os,pathlib,stat,subprocess,sys
p=pathlib.Path(sys.argv[1]); r=json.loads((p/'report.json').read_text()); f=p/'probe.img'; i=f.lstat()
assert all(r['checks'][k] is True for k in ('processes_stopped','mounts_removed','loop_detached'))
assert stat.S_ISREG(i.st_mode) and i.st_nlink==1 and i.st_uid==i.st_gid==0 and i.st_size==3061841920
assert not (p/'root').exists()
assert subprocess.check_output(['losetup','-j',str(f)])==b''
f.unlink(); print('copy-removed')
'''
        cleaned = must(vm("sudo", "python3", "-I", "-c", cleanup, guest)).strip() == b"copy-removed"
    json_write(work / "receipt.json", {"schema_version": 1, "scope": "exact-parent-networkmanager-export",
               "report_sha256": hashlib.sha256(raw).hexdigest(), "inputs_sha256": sha(work / "inputs.json"),
               "probe_exit_status": result.returncode, "report_passed": report["passed"],
               "disposable_image_removed_after_verified_export": cleaned, "hardware_qualified": False})
    print(json.dumps({"report_directory": str(work.relative_to(repo)), "passed": report["passed"],
                      "baseline": report["baseline"], "with_loopback_override": report["with_loopback_override"],
                      "error_stage": report["error_stage"], "copy_removed": cleaned}, sort_keys=True))
    return 0 if report["passed"] and cleaned else 1


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--inside":
        sys.exit(inside(Path(sys.argv[2])))
    if len(sys.argv) == 2:
        sys.exit(host(Path(sys.argv[1])))
    raise SystemExit("Usage: probe-test-access-network.py PARENT_EXPORT")
