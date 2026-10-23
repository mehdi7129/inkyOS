#!/usr/bin/python3 -I
"""Import inkyImager's Wi-Fi data before NetworkManager, never appair a phone.

The public fixture seam is configure(root, owner_uid=..., radio=..., checkpoint=...).
The runtime entrypoint accepts no paths and runs only as Linux root. Errors are
stable codes: neither SSIDs nor network secrets are printed.
"""
import sys
sys.dont_write_bytecode = True

import fcntl
import hashlib
import itertools
import json
import os
from pathlib import PurePosixPath
import re
import stat
import subprocess

CAPSULE = "boot/firmware/inky-imager.json"
PROFILE = "etc/NetworkManager/system-connections/inky-home.nmconnection"
COUNTRY = "etc/modprobe.d/inky-imager-wifi-country.conf"
STATE = "var/lib/inkyos/imager-network.json"
COUNTRY_BYTES = b"options cfg80211 ieee80211_regdom=FR\n"
PROFILE_UUID = "cdb16d16-dace-4383-bfd4-03082e69726c"
MAX_CAPSULE = 4096
_counter = itertools.count()


class ImportProblem(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise ImportProblem(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def strict_json(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, "invalid_configuration")
            result[key] = value
        return result
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ImportProblem("invalid_configuration")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ImportProblem("invalid_configuration") from exc


def parse_wifi(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_CAPSULE, "invalid_configuration")
    value = strict_json(raw)
    require(type(value) is dict and set(value) == {"schema_version", "wifi"}
            and type(value["schema_version"]) is int and value["schema_version"] == 1,
            "invalid_configuration")
    wifi = value["wifi"]
    require(type(wifi) is dict and set(wifi) == {"ssid", "password", "country"},
            "invalid_configuration")
    require(type(wifi["ssid"]) is str and "\0" not in wifi["ssid"], "invalid_configuration")
    try:
        ssid = wifi["ssid"].encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ImportProblem("invalid_configuration") from exc
    require(1 <= len(ssid) <= 32, "invalid_configuration")
    password = wifi["password"]
    require(type(password) is str and (re.fullmatch(r"[\x20-\x7e]{8,63}", password)
            or re.fullmatch(r"[0-9A-Fa-f]{64}", password)), "invalid_configuration")
    require(wifi["country"] == "FR" and type(wifi["country"]) is str, "unsupported_country")
    psk = password.lower() if len(password) == 64 else hashlib.pbkdf2_hmac(
        "sha1", password.encode("ascii"), ssid, 4096, 32).hex()
    return ssid, psk


def network_profile(raw):
    """Private NM bytes. Numeric SSID bytes + hex PSK avoid INI interpolation."""
    ssid, psk = parse_wifi(raw)
    return ("[connection]\nid=inky-home\nuuid=" + PROFILE_UUID
            + "\ntype=wifi\ninterface-name=wlan0\nautoconnect=true\nautoconnect-priority=100\n"
            "\n[wifi]\nmode=infrastructure\nband=bg\nssid="
            + ";".join(str(byte) for byte in ssid)
            + ";\n\n[wifi-security]\nkey-mgmt=wpa-psk\nproto=rsn;\npsk=" + psk
            + "\npsk-flags=0\n\n[ipv4]\nmethod=auto\n\n[ipv6]\nmethod=auto\n").encode("ascii")


def signature(info):
    return tuple(getattr(info, key) for key in ("st_dev", "st_ino", "st_mode", "st_uid",
                 "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"))


class Files:
    """Small fd-relative root; installed paths cannot traverse filesystem links."""
    def __init__(self, root, owner_uid):
        self.owner_uid = owner_uid
        self.root = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self.check(os.fstat(self.root), directory=True)
        except BaseException:
            os.close(self.root)
            raise

    def close(self):
        os.close(self.root)

    def check(self, info, *, directory=False, mode=None):
        require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
                and info.st_uid == self.owner_uid and not info.st_mode & 0o022,
                "unsafe_configuration_path")
        if not directory:
            require(info.st_nlink == 1, "unsafe_configuration_path")
        if mode is not None:
            require(stat.S_IMODE(info.st_mode) == mode, "unsafe_configuration_path")

    def directory(self, relative, *, create=False, mode=0o755):
        parts = PurePosixPath(relative).parts
        require(parts and not PurePosixPath(relative).is_absolute() and ".." not in parts,
                "unsafe_configuration_path")
        fd = os.dup(self.root)
        try:
            for index, name in enumerate(parts):
                if create:
                    try:
                        os.mkdir(name, mode if index == len(parts) - 1 else 0o755, dir_fd=fd)
                        os.fsync(fd)
                    except FileExistsError:
                        pass
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                self.check(os.fstat(fd), directory=True)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def read(self, path, *, limit=MAX_CAPSULE, mode=None):
        parent, name = path.rsplit("/", 1)
        directory = self.directory(parent)
        fd = None
        try:
            try:
                before = os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                return None, None
            self.check(before, mode=mode)
            require(0 <= before.st_size <= limit, "invalid_configuration")
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            self.check(os.fstat(fd), mode=mode)
            require(signature(before) == signature(os.fstat(fd)), "configuration_changed")
            raw = bytearray()
            while chunk := os.read(fd, min(65536, limit + 1 - len(raw))):
                raw.extend(chunk)
                require(len(raw) <= limit, "invalid_configuration")
            require(signature(before) == signature(os.fstat(fd))
                    == signature(os.stat(name, dir_fd=directory, follow_symlinks=False))
                    and len(raw) == before.st_size, "configuration_changed")
            return bytes(raw), signature(before)
        finally:
            if fd is not None:
                os.close(fd)
            os.close(directory)

    def write_new(self, path, raw, mode):
        parent, name = path.rsplit("/", 1)
        directory = self.directory(parent, create=True, mode=0o700 if parent == "var/lib/inkyos" else 0o755)
        temporary = None
        fd = None
        try:
            try:
                os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ImportProblem("configuration_conflict")
            for _ in range(100):
                temporary = ".imager-" + str(os.getpid()) + "-" + str(next(_counter))
                try:
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 mode, dir_fd=directory)
                    break
                except FileExistsError:
                    temporary = None
            require(fd is not None, "temporary_configuration_unavailable")
            os.fchmod(fd, mode)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(fd)
            os.close(fd)
            fd = None
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            if fd is not None:
                os.close(fd)
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
            os.close(directory)

    def remove_capsule(self, expected):
        directory = self.directory("boot/firmware")
        try:
            current = os.stat("inky-imager.json", dir_fd=directory, follow_symlinks=False)
            self.check(current)
            require(signature(current) == expected, "configuration_changed")
            os.unlink("inky-imager.json", dir_fd=directory)
            os.fsync(directory)
        finally:
            os.close(directory)


def activate_radio():
    # Both commands have fixed arguments. No secret or SSID enters argv or logs.
    for argv in (("/usr/sbin/iw", "reg", "set", "FR"),
                 ("/usr/sbin/rfkill", "unblock", "wlan")):
        try:
            subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=10, check=True,
                           env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"})
        except (OSError, subprocess.SubprocessError) as exc:
            raise ImportProblem("radio_setup_failed") from exc


def configure(root="/", *, owner_uid=0, radio=activate_radio, checkpoint=lambda _: None):
    files = Files(root, owner_uid)
    lock = None
    try:
        state_dir = files.directory("var/lib/inkyos", create=True, mode=0o700)
        try:
            files.check(os.fstat(state_dir), directory=True, mode=0o700)
            lock = os.open(".imager-network.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                           0o600, dir_fd=state_dir)
            files.check(os.fstat(lock), mode=0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ImportProblem("configuration_busy") from exc
        finally:
            os.close(state_dir)
        raw, capsule_stamp = files.read(CAPSULE)
        state_raw, _ = files.read(STATE, mode=0o600)
        profile, _ = files.read(PROFILE, limit=8192, mode=0o600)
        country, _ = files.read(COUNTRY, mode=0o644)
        reused = state_raw is not None
        if reused:
            state = strict_json(state_raw)
            require(type(state) is dict and set(state) == {"schema_version", "kind", "country",
                    "capsule_sha256", "profile_sha256"} and type(state["schema_version"]) is int
                    and state["schema_version"] == 1 and state["kind"] == "inky-imager-network"
                    and state["country"] == "FR"
                    and all(type(state[key]) is str and re.fullmatch(r"[0-9a-f]{64}", state[key])
                            for key in ("capsule_sha256", "profile_sha256"))
                    and profile is not None and digest(profile) == state["profile_sha256"]
                    and country == COUNTRY_BYTES, "configuration_conflict")
            require(raw is None or digest(raw) == state["capsule_sha256"], "configuration_conflict")
        else:
            require(raw is not None, "network_configuration_missing")
            expected = network_profile(raw)
            require(profile is None or profile == expected, "configuration_conflict")
            require(country is None or country == COUNTRY_BYTES, "configuration_conflict")
            if profile is None:
                files.write_new(PROFILE, expected, 0o600)
            checkpoint("profile_committed")
            if country is None:
                files.write_new(COUNTRY, COUNTRY_BYTES, 0o644)
            checkpoint("country_committed")
            # This receipt contains only hashes, never SSID or password/PSK.
            state = {"schema_version": 1, "kind": "inky-imager-network", "country": "FR",
                     "capsule_sha256": digest(raw), "profile_sha256": digest(expected)}
            files.write_new(STATE, canonical(state), 0o600)
            checkpoint("state_committed")
        # Reapply on every boot. systemd-rfkill restoration is masked by the
        # image profile, so no late saved soft-block can undo this command.
        radio()
        checkpoint("radio_configured")
        if raw is not None:
            files.remove_capsule(capsule_stamp)
            checkpoint("capsule_removed")
        return {"status": "configured", "reused": reused, "country": "FR"}
    finally:
        if lock is not None:
            os.close(lock)
        files.close()


def main():
    if sys.argv[1:] or sys.platform != "linux" or os.getuid() != os.geteuid() or os.geteuid() != 0:
        print('{"status":"error","error":"linux_root_required"}', file=sys.stderr)
        return 2
    try:
        result = configure()
    except (ImportProblem, OSError) as exc:
        code = str(exc) if isinstance(exc, ImportProblem) else "network_import_failed"
        print(json.dumps({"status": "error", "error": code}), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
