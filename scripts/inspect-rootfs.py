#!/usr/bin/env python3
"""Inspect mounted image files without executing them or following symlinks.

Normally invoked by inspect-image.sh. For synthetic fixtures:
  python3 scripts/inspect-rootfs.py --rootfs ROOT --bootfs BOOT --output report.json
The output must be a new file outside both trees. Password fields, private keys,
machine identifiers, Wi-Fi profiles and application data are never serialized.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


class UnsafePath(ValueError):
    pass


class SafeTree:
    """Every component is opened relative to an fd with O_NOFOLLOW."""

    def __init__(self, root):
        self.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def close(self):
        os.close(self.fd)

    def _parent(self, path):
        parts = PurePosixPath(path).parts
        if ".." in parts:
            raise UnsafePath("parent traversal refused")
        parts = tuple(p for p in parts if p not in ("/", "."))
        fd = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=fd)
                os.close(fd)
                fd = next_fd
            return fd, parts[-1] if parts else "."
        except BaseException:
            os.close(fd)
            raise

    def metadata(self, path):
        fd, name = self._parent(path)
        try:
            return os.stat(name, dir_fd=fd, follow_symlinks=False)
        finally:
            os.close(fd)

    def read(self, path, limit=8 * 1024 * 1024):
        fd, name = self._parent(path)
        try:
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode):
                raise UnsafePath("not a regular file")
            # O_NONBLOCK also prevents a hostile FIFO from blocking inspection.
            item = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                           dir_fd=fd)
        finally:
            os.close(fd)
        try:
            info = os.fstat(item)
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise UnsafePath("not a bounded regular file")
            with os.fdopen(item, "rb", closefd=False) as stream:
                data = stream.read(limit + 1)
            if len(data) > limit:
                raise UnsafePath("file exceeds size limit")
            return data.decode("utf-8", errors="replace")
        finally:
            os.close(item)

    def entries(self, path):
        fd, name = self._parent(path)
        try:
            directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=fd)
        finally:
            os.close(fd)
        try:
            with os.scandir(directory) as entries:
                result = [(entry.name, entry.stat(follow_symlinks=False))
                          for entry in entries]
            return sorted(result)
        finally:
            os.close(directory)


SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+:~_/-]{0,200}$")
CRITICAL_UNITS = (
    "NetworkManager.service", "NetworkManager-wait-online.service",
    "systemd-networkd.service", "systemd-resolved.service", "iwd.service",
    "wpa_supplicant.service", "bluetooth.service", "hciuart.service",
    "ssh.service", "sshd.service", "ssh.socket", "ssh-hostkeys-generate.service",
    "sshd-keygen.service", "avahi-daemon.service", "avahi-daemon.socket",
    "systemd-timesyncd.service", "chrony.service", "fake-hwclock.service",
    "rpi-eeprom-update.service", "userconfig.service", "regenerate_ssh_host_keys.service",
    "resize2fs_once.service", "firstboot.service", "cloud-init.service",
    "cloud-init-local.service", "cloud-init-network.service", "cloud-config.service",
    "cloud-final.service", "cloud-init.target",
    "inky-studio.service", "inky-network.service", "inkyos-firstboot.service",
)


def path_state(tree, path):
    try:
        info = tree.metadata(path)
    except FileNotFoundError:
        return {"present": False}
    except (OSError, UnsafePath):
        return {"present": None, "inspection": "blocked_or_unreadable"}
    kind = ("regular" if stat.S_ISREG(info.st_mode) else
            "directory" if stat.S_ISDIR(info.st_mode) else
            "symlink" if stat.S_ISLNK(info.st_mode) else "other")
    return {"present": True, "type": kind, "mode": f"{stat.S_IMODE(info.st_mode):04o}",
            "uid": info.st_uid, "gid": info.st_gid,
            "group_or_world_writable": bool(info.st_mode & 0o022)}


def safe_read(tree, path, limit=8 * 1024 * 1024):
    try:
        return tree.read(path, limit)
    except (OSError, UnsafePath):
        return None


def entries_or_none(tree, path):
    try:
        return tree.entries(path)
    except (OSError, UnsafePath):
        return None


def count_tree(tree, path, depth=5, limit=10000):
    """Count state without exposing filenames or reading file contents."""
    state = path_state(tree, path)
    if state.get("type") != "directory":
        return state
    counts = {"regular_files": 0, "directories": 0, "symlinks": 0, "other": 0,
              "truncated_or_unreadable": False}
    pending = [(path, 0)]
    seen = 0
    while pending:
        current, level = pending.pop()
        entries = entries_or_none(tree, current)
        if entries is None:
            counts["truncated_or_unreadable"] = True
            continue
        for name, info in entries:
            seen += 1
            if seen > limit:
                counts["truncated_or_unreadable"] = True
                return {**state, **counts}
            if stat.S_ISDIR(info.st_mode):
                counts["directories"] += 1
                if level < depth:
                    pending.append((f"{current}/{name}", level + 1))
                else:
                    counts["truncated_or_unreadable"] = True
            elif stat.S_ISREG(info.st_mode):
                counts["regular_files"] += 1
            elif stat.S_ISLNK(info.st_mode):
                counts["symlinks"] += 1
            else:
                counts["other"] += 1
    return {**state, **counts}


def machine_id_state(tree, path):
    state = path_state(tree, path)
    if state.get("type") != "regular":
        return state
    content = safe_read(tree, path, 256)
    if content is None:
        classification = "unreadable"
    elif not content.strip():
        classification = "empty"
    elif content.strip() == "uninitialized":
        classification = "uninitialized"
    elif re.fullmatch(r"[0-9a-f]{32}", content.strip()) and int(content.strip(), 16) != 0:
        classification = "populated_valid_format"
    else:
        classification = "populated_invalid_format"
    return {**state, "state": classification}


def inspect_os(tree):
    values = {}
    source = None
    for path in ("etc/os-release", "usr/lib/os-release"):
        content = safe_read(tree, path, 64 * 1024)
        if content is None:
            continue
        source = "/" + path
        for line in content.splitlines():
            key, separator, value = line.partition("=")
            if separator and key in {"ID", "ID_LIKE", "VERSION_ID", "VERSION_CODENAME",
                                     "NAME", "PRETTY_NAME", "IMAGE_ID", "IMAGE_VERSION"}:
                # Data only: no shell parsing, expansion, sourcing or subprocess.
                values[key] = value.strip().strip("\"'")[:256]
        break
    return {"source": source, "fields": values}


def inspect_packages(tree):
    content = safe_read(tree, "var/lib/dpkg/status", 32 * 1024 * 1024)
    if content is None:
        return {"available": False, "installed": []}
    installed = []
    for paragraph in re.split(r"\n\s*\n", content):
        fields = {}
        for line in paragraph.splitlines():
            key, separator, value = line.partition(":")
            if separator and key in {"Package", "Version", "Architecture", "Status"}:
                fields[key] = value.strip()
        if fields.get("Status") != "install ok installed":
            continue
        if all(SAFE_TOKEN.fullmatch(fields.get(key, ""))
               for key in ("Package", "Version", "Architecture")):
            installed.append({"name": fields["Package"], "version": fields["Version"],
                              "architecture": fields["Architecture"]})
    installed.sort(key=lambda package: (package["name"], package["architecture"]))
    return {"available": True, "count": len(installed), "installed": installed}


def inspect_accounts(tree):
    passwd = safe_read(tree, "etc/passwd", 1024 * 1024)
    shadow = safe_read(tree, "etc/shadow", 1024 * 1024)
    states = {}
    if shadow is not None:
        for line in shadow.splitlines():
            fields = line.split(":")
            if len(fields) >= 2:
                password = fields[1]
                states[fields[0]] = ("locked" if password.startswith(("!", "*")) else
                                    "empty" if not password else "password_set")
    accounts = []
    for line in (passwd or "").splitlines():
        fields = line.split(":")
        if len(fields) != 7 or not fields[2].isdigit() or not fields[3].isdigit():
            continue
        uid = int(fields[2])
        accounts.append({"name": fields[0], "uid": uid, "gid": int(fields[3]),
                         "password_state": states.get(fields[0], "unknown"),
                         "interactive_shell": fields[6].rsplit("/", 1)[-1]
                         not in {"nologin", "false", ""},
                         "regular_user": 1000 <= uid < 65534})
    return {"passwd_readable": passwd is not None, "shadow_readable": shadow is not None,
            "accounts": accounts,
            "note": "Password state alone does not determine SSH/PAM/public-key access."}


def inspect_services(tree):
    directories = ("etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system")
    installed, enabled, local_links = set(), set(), set()
    for directory in directories:
        for name, info in entries_or_none(tree, directory) or []:
            if name in CRITICAL_UNITS:
                installed.add(name)
                if directory.startswith("etc/") and stat.S_ISLNK(info.st_mode):
                    local_links.add(name)
            if name.endswith((".wants", ".requires")) and stat.S_ISDIR(info.st_mode):
                for unit, member in entries_or_none(tree, f"{directory}/{name}") or []:
                    if unit in CRITICAL_UNITS and stat.S_ISLNK(member.st_mode):
                        enabled.add(unit)
    return {unit: {"unit_present": unit in installed,
                   "enablement_link_present": unit in enabled,
                   "local_override_symlink_present": unit in local_links}
            for unit in CRITICAL_UNITS}


def inspect(rootfs, bootfs):
    root, boot = SafeTree(rootfs), SafeTree(bootfs)
    try:
        packages = inspect_packages(root)
        identities = {path: machine_id_state(root, path)
                      for path in ("etc/machine-id", "var/lib/dbus/machine-id")}
        random_seeds = {}
        for path in ("var/lib/systemd/random-seed", "var/lib/urandom/random-seed"):
            state = path_state(root, path)
            if state.get("type") == "regular":
                state["size_bytes"] = root.metadata(path).st_size
            random_seeds["/" + path] = state
        private_paths = ("etc/NetworkManager/system-connections", "var/lib/NetworkManager",
                         "var/lib/bluetooth", "var/lib/inky-studio", "var/lib/inky-network")
        private_state = {"/" + path: count_tree(root, path) for path in private_paths}
        ssh_keys = []
        for name, info in entries_or_none(root, "etc/ssh") or []:
            if re.fullmatch(r"ssh_host_[a-z0-9]+_key(?:\.pub)?", name):
                ssh_keys.append({"kind": "public" if name.endswith(".pub") else "private",
                                 "type": "regular" if stat.S_ISREG(info.st_mode) else "other",
                                 "mode": f"{stat.S_IMODE(info.st_mode):04o}"})
        kernels = set()
        for path in ("usr/lib/modules", "lib/modules"):
            for name, info in entries_or_none(root, path) or []:
                if stat.S_ISDIR(info.st_mode) and SAFE_TOKEN.fullmatch(name):
                    kernels.add(name)
        boot_files = {name: path_state(boot, name) for name in
                      ("config.txt", "cmdline.txt", "kernel8.img", "initramfs8",
                       "firstrun.sh", "userconf", "userconf.txt", "ssh", "ssh.txt",
                       "user-data", "network-config", "meta-data")}
        cmdline = safe_read(boot, "cmdline.txt", 64 * 1024)
        hooks = {key: bool(cmdline and re.search(r"(?:^|\s)" + re.escape(key) + "=", cmdline))
                 for key in ("init", "systemd.run", "systemd.unit")}
        services = inspect_services(root)
        permissions = {"/" + path: path_state(root, path) for path in
                       ("etc/shadow", "etc/ssh", "etc/NetworkManager/system-connections",
                        "var/lib/inky-studio", "var/lib/inky-network",
                        "usr/local/lib/inky-studio", "usr/local/bin/inky-studio")}
        accounts = inspect_accounts(root)
        risks = []
        def risk(code, message):
            risks.append({"code": code, "message": message})
        for path, identity in identities.items():
            if identity.get("state", "").startswith("populated"):
                risk("PRESEEDED_MACHINE_ID", f"/{path} contains an identifier; value suppressed.")
        if any(key["kind"] == "private" for key in ssh_keys):
            risk("PRESEEDED_SSH_HOST_KEY", "SSH private host key entry exists; contents not read.")
        for path, seed in random_seeds.items():
            if seed.get("size_bytes", 0) > 0:
                risk("PRESEEDED_RANDOM_SEED", f"{path} is non-empty; contents not read.")
        for path, state in private_state.items():
            if state.get("regular_files", 0) or state.get("symlinks", 0):
                risk("PERSISTENT_STATE_PRESENT", f"{path} contains state; names and contents suppressed.")
            if (state.get("truncated_or_unreadable") or state.get("present") is None
                    or state.get("type") in {"symlink", "other"}):
                risk("STATE_INSPECTION_INCOMPLETE", f"{path} could not be fully inventoried.")
        for account in accounts["accounts"]:
            if account["password_state"] in {"password_set", "empty"}:
                risk("ACCOUNT_PASSWORD_PRESENT_OR_EMPTY",
                     f"Account {account['name']} has password state {account['password_state']}.")
        if not accounts["shadow_readable"]:
            risk("SHADOW_UNREADABLE", "Account lock state cannot be established.")
        for name in ("firstrun.sh", "userconf", "userconf.txt", "user-data", "network-config"):
            if boot_files[name].get("present"):
                risk("BOOT_PROVISIONING_FILE", f"Boot file {name} exists; contents not read.")
        for path, permission in permissions.items():
            if permission.get("group_or_world_writable") and permission.get("type") != "symlink":
                risk("WRITABLE_SENSITIVE_PATH", f"{path} is writable by group or others.")
        return {"schema_version": 1, "scope": "offline-system-baseline",
                "qualification": "not-qualified",
                "method": {"image_code_executed": False, "symlinks_followed": False,
                           "secret_values_included": False},
                "os": inspect_os(root), "packages": packages,
                "architectures": sorted({p["architecture"] for p in packages["installed"]
                                         if p["architecture"] != "all"}),
                "kernel": {"module_directories": sorted(kernels),
                           "packages": [p for p in packages["installed"]
                                        if p["name"].startswith(("linux-image", "raspberrypi-kernel", "raspi-firmware"))]},
                "boot": {"files": boot_files, "cmdline_hook_keys_present": hooks,
                         "metadata_note": "For a FAT boot filesystem, mode/uid/gid reflect mount metadata, not stored Unix permissions."},
                "services": services, "permissions": permissions, "accounts": accounts,
                "identities": {"machine_id": identities, "ssh_host_keys": ssh_keys,
                               "random_seeds": random_seeds},
                "persistent_state": private_state, "risks": risks,
                "limitations": ["Static presence/enablement is not runtime health or hardware qualification.",
                                "Symlinks are inventoried but never resolved, including absolute links.",
                                "No proof of first-boot uniqueness, idempotence or Bluetooth/app behavior.",
                                "Known sensitive paths are inventoried; this is not an exhaustive secret scan.",
                                "A service enablement link does not account for masks, presets or all dependencies."]}
    finally:
        root.close()
        boot.close()


def image_metadata(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise UnsafePath("image must be a regular file")
        digest = hashlib.sha256()
        with os.fdopen(fd, "rb", closefd=False) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return {"size_bytes": info.st_size, "sha256": digest.hexdigest()}
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--bootfs", type=Path, required=True)
    parser.add_argument("--image", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.absolute()
    for tree in (args.rootfs, args.bootfs):
        if output.resolve().is_relative_to(tree.resolve()):
            parser.error("output must be outside the inspected trees")
    try:
        report = inspect(args.rootfs, args.bootfs)
        if args.image:
            report["image"] = image_metadata(args.image)
        # Refuse replacing any file, symlink, device or FIFO at the output path.
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
    except (OSError, UnsafePath) as exc:
        print(f"Inspection failed ({type(exc).__name__}); no image code was executed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
