#!/usr/bin/env python3
"""Fail closed on the static system-prototype contract; never execute image code."""

import argparse
import configparser
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("_inkyos_inspect_rootfs", ROOT / "scripts/inspect-rootfs.py")
inspection = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inspection)

MASKS = (
    "cloud-init-local.service", "cloud-init-network.service", "cloud-config.service",
    "cloud-final.service", "cloud-init.target", "userconfig.service", "ssh.service",
    "ssh.socket", "regenerate_ssh_host_keys.service", "sshd-keygen.service",
    "NetworkManager-wait-online.service", "systemd-firstboot.service", "sshswitch.service",
)
FIRSTBOOT = "inkyos-firstboot.service"
ORDERED_SERVICES = ("NetworkManager.service", "avahi-daemon.service", "bluetooth.service")
DROPIN = "10-inkyos-firstboot.conf"


def readlink(tree, path):
    """Read a link's text without resolving it, using SafeTree's no-follow parents."""
    fd, name = tree._parent(path)
    try:
        return os.readlink(name, dir_fd=fd)
    finally:
        os.close(fd)


def missing(tree, path):
    try:
        tree.metadata(path)
    except FileNotFoundError:
        return True
    return False


def regular_secure(tree, path, owner_uid, executable=False):
    info = tree.metadata(path)
    return (stat.S_ISREG(info.st_mode) and info.st_uid == owner_uid
            and not info.st_mode & 0o022 and (not executable or bool(info.st_mode & 0o100)))


def empty_or_missing(tree, path, depth=0):
    if missing(tree, path):
        return True
    if depth > 5 or not stat.S_ISDIR(tree.metadata(path).st_mode):
        return False
    entries = tree.entries(path)
    if len(entries) > 256:
        return False
    return all(stat.S_ISDIR(info.st_mode) and empty_or_missing(tree, f"{path}/{name}", depth + 1)
               for name, info in entries)


def unit_values(content):
    """Read simple systemd assignments, preserving reset semantics for dependencies."""
    result, section = {}, None
    for original in content.splitlines():
        line = original.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.endswith("\\"):
            raise ValueError("continued unit directives are outside this verifier's contract")
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        key, separator, value = line.partition("=")
        if separator:
            entry = (section, key.strip())
            if entry[1] in {"Requires", "After", "Before", "WantedBy"}:
                if not value.strip():
                    result[entry] = []
                else:
                    result.setdefault(entry, []).extend(value.split())
            else:
                result[entry] = value.strip()
    return result


def all_section_lines(content):
    active, lines = True, []
    for original in content.splitlines():
        line = original.split("#", 1)[0].strip()
        if line.startswith("[") and line.endswith("]"):
            active = line == "[all]"
        elif line and active:
            lines.append(line)
    return lines


def account_contract(root):
    users = [line.split(":") for line in root.read("etc/passwd", 1024 * 1024).splitlines()]
    if any(len(row) != 7 for row in users):
        return False
    if any(row[0] == "pi" for row in users):
        return False
    matching = [row for row in users if row[0] == "inky"]
    if len(matching) != 1:
        return False
    account = matching[0]
    if account[2] != "1000" or account[6].rsplit("/", 1)[-1] != "nologin":
        return False
    if sum(row[2] == "1000" for row in users) != 1:
        return False
    shadow = [line.split(":") for line in root.read("etc/shadow", 1024 * 1024).splitlines()]
    passwords = [row[1] for row in shadow if len(row) >= 2 and row[0] == "inky"]
    if len(passwords) != 1 or not passwords[0].startswith(("!", "*")):
        return False
    groups = [line.split(":") for line in root.read("etc/group", 1024 * 1024).splitlines()]
    if any(len(row) != 4 for row in groups):
        return False
    membership = {row[0] for row in groups if row[2] == account[3] or "inky" in row[3].split(",")}
    return {"spi", "i2c", "gpio"} <= membership and not {"sudo", "admin", "netdev"} & membership


def nm_state_contract(root, enabled=True):
    entries = root.entries("var/lib/NetworkManager")
    if [name for name, _ in entries] != ["NetworkManager.state"]:
        return False
    state = configparser.ConfigParser(interpolation=None)
    state.read_string(root.read("var/lib/NetworkManager/NetworkManager.state", 4096))
    if state.defaults() or state.sections() != ["main"]:
        return False
    expected = {"wirelessenabled"}
    return set(state["main"]) == expected and all(state["main"][key].lower() == str(enabled).lower() for key in expected)


def no_ssh_host_keys(root):
    if missing(root, "etc/ssh"):
        return True
    return not any(name.startswith("ssh_host_") for name, _ in root.entries("etc/ssh"))


def verify(rootfs, bootfs, package_lock, *, application=None, _owner_uid=0):
    """_owner_uid supports unprivileged fixtures; the CLI always requires root-owned files."""
    checks = []

    def check(identifier, predicate, requirement):
        try:
            passed = bool(predicate())
        except (OSError, ValueError, KeyError, TypeError, configparser.Error):
            passed = False
        checks.append({"id": identifier, "passed": passed, "requirement": requirement})

    root = inspection.SafeTree(rootfs)
    try:
        boot = inspection.SafeTree(bootfs)
        try:
            def metadata_contract():
                data = json.loads(root.read("etc/inkyos-release.json", 64 * 1024))
                return (isinstance(data, dict) and type(data.get("schema_version")) is int
                        and data["schema_version"] == 1
                        and data.get("kind") == ("application-prototype" if application else "system-prototype")
                        and "application" in data and data["application"] == application)

            check("RELEASE_METADATA", metadata_contract, "schema_version=1, explicit prototype kind and matching application pin")
            for path, executable in (("etc/inkyos-release.json", False),
                                     ("usr/local/lib/inkyos/firstboot.py", False),
                                     (f"etc/systemd/system/{FIRSTBOOT}", False)):
                check("SECURE_" + path.upper().replace("/", "_"),
                      lambda p=path, x=executable: regular_secure(root, p, _owner_uid, x),
                      f"/{path}: root-owned regular file, not writable by group/others" + (", owner-executable" if executable else ""))
            check("FIRSTBOOT_ENABLED", lambda: readlink(root, f"etc/systemd/system/multi-user.target.wants/{FIRSTBOOT}")
                  in {f"/etc/systemd/system/{FIRSTBOOT}", f"../{FIRSTBOOT}"},
                  "multi-user.target enables the expected firstboot unit")

            def firstboot_unit():
                unit = unit_values(root.read(f"etc/systemd/system/{FIRSTBOOT}", 64 * 1024))
                return (unit.get(("Service", "Type")) == "oneshot"
                        and unit.get(("Service", "User")) == "root"
                        and unit.get(("Service", "ExecStart")) == "/usr/bin/python3 /usr/local/lib/inkyos/firstboot.py")

            check("FIRSTBOOT_COMMAND", firstboot_unit, "root oneshot invokes only the expected system firstboot script")
            check("MACHINE_ID_UNINITIALIZED", lambda: root.read("etc/machine-id", 256).strip() == "uninitialized",
                  "machine-id retains systemd's uninitialized first-boot marker")
            check("NO_DBUS_MACHINE_ID", lambda: missing(root, "var/lib/dbus/machine-id"), "no cloned D-Bus machine-id")
            check("HOSTNAME_GENERIC", lambda: root.read("etc/hostname", 256).strip() == "inky-unconfigured", "generic pre-boot hostname")
            check("INKY_ACCOUNT", lambda: account_contract(root),
                  "unique UID 1000 inky, locked nologin, spi/i2c/gpio membership, no sudo/admin/netdev, no pi account")
            check("NO_SSH_HOST_KEYS", lambda: no_ssh_host_keys(root), "no SSH host key entries; contents are never read")
            for path in ("var/lib/systemd/random-seed", "var/lib/urandom/random-seed", "var/lib/inkyos/system.json"):
                check("ABSENT_" + path.upper().replace("/", "_"), lambda p=path: missing(root, p), f"/{path} absent")
            for path in ("var/lib/inkyos", "var/lib/inky-studio", "var/lib/inky-network",
                         "home/inky/inky-studio/server/data", "opt/inky-studio/server/data",
                         "root/.ssh", "home/inky/.ssh", "etc/NetworkManager/system-connections",
                         "run/NetworkManager/system-connections", "var/lib/bluetooth"):
                check("EMPTY_" + path.upper().replace("/", "_"), lambda p=path: empty_or_missing(root, p),
                      f"/{path}: absent or empty directories only; no content values disclosed")
            check("NETWORKMANAGER_GENERIC_STATE", lambda: nm_state_contract(root, enabled=application is None),
                  "only NetworkManager.state; Wi-Fi disabled for application prototype pending country contract")
            check("NO_BUILD_POLICY_RC", lambda: missing(root, "usr/sbin/policy-rc.d"), "temporary build policy-rc.d removed")
            for unit in MASKS:
                check("MASK_" + unit, lambda u=unit: readlink(root, f"etc/systemd/system/{u}") == "/dev/null",
                      f"{unit} masked by an exact /dev/null symlink")
            check("CLOUD_INIT_DISABLED", lambda: regular_secure(root, "etc/cloud/cloud-init.disabled", _owner_uid),
                  "root-owned cloud-init.disabled marker exists")
            for name in ("user-data", "network-config", "meta-data", "userconf", "userconf.txt", "firstrun.sh", "ssh", "ssh.txt"):
                check("BOOT_ABSENT_" + name, lambda p=name: missing(boot, p), f"boot/{name} absent")
            check("BOOT_RESIZE", lambda: "resize" in boot.read("cmdline.txt", 64 * 1024).split(), "boot cmdline retains resize token")
            if application:
                check('BOOT_NO_COUNTRY', lambda: not any(token.startswith('cfg80211.ieee80211_regdom=')
                      for token in boot.read('cmdline.txt', 64 * 1024).split()),
                      'application prototype has no preselected country in kernel cmdline')
            check("BOOT_INCLUDE", lambda: "include inkyos.txt" in all_section_lines(boot.read("config.txt", 64 * 1024)),
                  "config.txt includes inkyos.txt in the unconditional configuration")

            def overlay_contract():
                content = boot.read("inkyos.txt", 64 * 1024)
                return ("[all]" in content.splitlines()
                        and {"dtparam=i2c_arm=on", "dtparam=spi=on", "dtoverlay=spi0-0cs"}
                        <= set(all_section_lines(content)))

            check("BOOT_INTERFACES", overlay_contract, "inkyos.txt sets [all], I2C and SPI on, SPI chip selects released")
            check("I2C_MODULE", lambda: "i2c-dev" in all_section_lines(root.read("etc/modules-load.d/inkyos.conf", 4096)),
                  "i2c-dev module is requested")
            for unit in ("rpi-resize.service", "systemd-growfs-root.service"):
                check("GROW_UNIT_" + unit, lambda u=unit: regular_secure(root, f"usr/lib/systemd/system/{u}", _owner_uid),
                      f"{unit}: vendor unit remains a root-owned, non-writable regular file")
                check("GROW_NOT_MASKED_" + unit, lambda u=unit: missing(root, f"etc/systemd/system/{u}"),
                      f"{unit}: no local override or mask")
            check("RPI_RESIZE_ENABLED", lambda: readlink(root, "etc/systemd/system/sysinit.target.wants/rpi-resize.service")
                  in {"/usr/lib/systemd/system/rpi-resize.service", "../../../../usr/lib/systemd/system/rpi-resize.service"},
                  "sysinit.target retains the vendor rpi-resize link")
            for service in ORDERED_SERVICES:
                path = f"etc/systemd/system/{service}.d/{DROPIN}"

                def dropin_contract(p=path):
                    unit = unit_values(root.read(p, 64 * 1024))
                    return (regular_secure(root, p, _owner_uid)
                            and FIRSTBOOT in unit.get(("Unit", "Requires"), [])
                            and FIRSTBOOT in unit.get(("Unit", "After"), []))

                check("FIRSTBOOT_ORDER_" + service, dropin_contract, f"{service}: root-owned drop-in Requires and After firstboot")

            def package_contract():
                expected = package_lock["packages"]
                if not isinstance(expected, list) or not any(p.get("name") == "python3-dbus" for p in expected):
                    return False
                actual = inspection.inspect_packages(root)
                installed = {(p["name"], p["architecture"]): p["version"] for p in actual["installed"]}
                return actual["available"] and all(installed.get((p["name"], p["architecture"])) == p["version"] for p in expected)

            check("LOCKED_SYSTEM_PACKAGES", package_contract, "every locked delta package, including python3-dbus, is installed at its exact version/architecture")
        finally:
            boot.close()
    finally:
        root.close()
    failures = [check["id"] for check in checks if not check["passed"]]
    return {"schema_version": 1, "scope": "offline-system-prototype-contract", "passed": not failures,
            "qualification": "not-hardware-qualified", "checks": checks, "failed_checks": failures,
            "method": {"image_code_executed": False, "symlinks_followed": False, "secret_values_included": False},
            "limitations": ["Static contract only; no proof of boot, service health, hardware or application behavior.",
                            "Known sensitive paths are checked; this is not an exhaustive secret scan.",
                            "Vendor grow-unit presence and modes are checked; byte-for-byte preservation is verified separately."]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--bootfs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--packages-lock", type=Path, default=ROOT / "config/system-packages.lock.json")
    parser.add_argument("--application-manifest", type=Path)
    parser.add_argument("--application-sha256")
    args = parser.parse_args(argv)
    try:
        output = args.output.absolute()
        if any(output.resolve().is_relative_to(tree.resolve()) for tree in (args.rootfs, args.bootfs)):
            raise ValueError("output must be outside the inspected trees")
        with args.packages_lock.open("r", encoding="utf-8") as stream:
            lock = json.load(stream)
        application = None
        if args.application_manifest or args.application_sha256:
            if not (args.application_manifest and args.application_sha256):
                raise ValueError("Both application manifest and SHA-256 are required")
            spec = importlib.util.spec_from_file_location("_application_config", ROOT / "scripts/configure-application-rootfs.py")
            config = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(config)
            application = config.application_metadata(
                config.load_manifest(args.application_manifest, args.application_sha256), args.application_sha256)
        report = verify(args.rootfs, args.bootfs, lock, application=application)
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        print(f"Prototype verification: {'PASS' if report['passed'] else 'FAIL'} ({len(report['failed_checks'])} failed checks)")
        return 0 if report["passed"] else 1
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"Prototype verification failed ({type(error).__name__}); no image code executed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
