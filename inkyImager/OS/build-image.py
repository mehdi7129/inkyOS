#!/usr/bin/env python3
"""One offline ARM64 composition: pristine Lite + Studio bundle + Imager LAN.

No SD, radio, app startup, exporter or factory runtime is used. Inputs are a
closed hash-pinned workspace. Failures retain their new candidate and logs;
inspect them rather than automatically restarting this command.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys

BASE = {"sha256": "49fafba626ec00e0f9800349b9edae6caf8cfc223f673b875b72ac2797ed9576",
        "size_bytes": 3061841920}
FIELDS = {"schema_version", "kind", "files", "backend", "backend_exec_start", "backend_environment",
          "os_commit", "studio_commit"}
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"}


def require(value, message):
    if not value:
        raise ValueError(message)


def safe_name(name):
    require(type(name) is str and name and not PurePosixPath(name).is_absolute()
            and str(PurePosixPath(name)) == name and ".." not in PurePosixPath(name).parts,
            "unsafe input name")
    return name


def file_hash(path):
    for parent in path.parents:
        require(stat.S_ISDIR(parent.lstat().st_mode), "linked input ancestry")
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == 0
            and not before.st_mode & 0o022, "ordinary root-owned input required")
    with path.open("rb") as stream:
        result = {"sha256": hashlib.file_digest(stream, "sha256").hexdigest(), "size_bytes": before.st_size}
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    require(tuple(getattr(before, k) for k in fields) == tuple(getattr(path.lstat(), k) for k in fields),
            "input changed")
    return result


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def write_json(path, value):
    with path.open("x") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, sort_keys=True, separators=(",", ":")); stream.write("\n")
        stream.flush(); os.fsync(stream.fileno())


def inputs(work, pin):
    require(re.fullmatch("[0-9a-f]{64}", pin), "input manifest SHA required")
    path = work / "imager-inputs.json"
    require(file_hash(path)["sha256"] == pin, "input manifest hash mismatch")
    def unique(rows):
        out = {}
        for key, value in rows:
            require(key not in out, "duplicate input field"); out[key] = value
        return out
    value = json.loads(path.read_bytes(), object_pairs_hook=unique)
    require(type(value) is dict and set(value) == FIELDS and type(value["schema_version"]) is int
            and value["schema_version"] == 1 and value["kind"] == "inky-imager-image-inputs"
            and type(value["files"]) is dict and 20 <= len(value["files"]) <= 1000,
            "closed imager inputs required")
    for key in ("os_commit", "studio_commit"):
        require(type(value[key]) is str and re.fullmatch("[0-9a-f]{40}", value[key]), "source commit required")
    require(value["files"].get("base.img") == BASE, "pristine official base required")
    require(type(value["backend"]) is dict and set(value["backend"]) == {"inputs", "sources", "wheels"},
            "backend input paths required")
    for name, expected in value["files"].items():
        require(type(expected) is dict and set(expected) == {"sha256", "size_bytes"}
                and type(expected["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", expected["sha256"])
                and type(expected["size_bytes"]) is int and expected["size_bytes"] >= 0, "invalid input pin")
        require(file_hash(work / safe_name(name)) == expected, "input hash mismatch: " + name)
    for name in value["backend"].values():
        safe_name(name)
        require(name.startswith("backend/"), "backend must stay in its input namespace")
    require(value["backend"]["inputs"] in value["files"], "backend manifest must be pinned")
    for namespace in ("recipe", "backend", "imager-os", "packages"):
        root = work / namespace
        actual = {str(p.relative_to(work)) for p in root.rglob("*") if p.is_file()}
        require(actual == {p for p in value["files"] if p.startswith(namespace + "/")}
                and not any(p.is_symlink() for p in root.rglob("*")), "unclosed input namespace: " + namespace)
    return value


def build(work, pin):
    require(sys.platform == "linux" and platform.machine() == "aarch64"
            and os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0, "Linux ARM64 root required")
    require(work.is_absolute() and re.fullmatch(r"/var/lib/inkyos-build/factory-image\.imager[0-9]+", str(work)),
            "dedicated imager workspace required")
    require(stat.S_IMODE(work.lstat().st_mode) == 0o700 and work.lstat().st_uid == 0
            and not work.is_symlink(), "private root-owned workspace required")
    require(Path("/var/lib/inkyos-build/owner").read_bytes() == b"inkyos-builder-v1\n", "builder marker required")
    value = inputs(work, pin)
    b = load(work / "recipe/scripts/build-factory-active-linux.py", "imager_existing_mount_tools")
    b.workspace(work)
    if not b.private_namespaces():
        args = ["unshare", "--mount", "--net", "--uts", "--propagation", "private", "--",
                sys.executable, "-I", "-B", "-S", str(Path(__file__).absolute()),
                "--work", str(work), "--inputs-sha256", pin]
        os.execvpe(args[0], args, ENV)
    require(not any(os.path.lexists(work / name) for name in
                    ("build-started.json", "candidate.img", "imager-candidate.json", "root", "boot")),
            "fresh composition required; inspect any prior failed workspace")
    write_json(work / "build-started.json", {"scope": "inky-imager-normal-lan", "input_sha256": pin})
    with (work / "base.img").open("rb") as source, (work / "candidate.img").open("xb") as target:
        os.fchmod(target.fileno(), 0o600); shutil.copyfileobj(source, target); target.flush(); os.fsync(target.fileno())
    require(file_hash(work / "candidate.img") == BASE, "base copy mismatch")
    native = b.Commands()
    def run(argv, **kwargs):
        result = native(argv, **kwargs)
        if argv[0] == "losetup" and "--partscan" in argv:
            native(["udevadm", "settle", "--timeout=10"])
        return result
    with b.MountedImage(work, "prepare", run) as mounted:
        root = work / "root"; preserved = b.preserved(work); mounted.device_tree()
        policy = root / "usr/sbin/policy-rc.d"
        require(not os.path.lexists(policy), "unexpected policy-rc.d")
        policy.write_bytes(b"#!/bin/sh\nexit 101\n"); policy.chmod(0o755)
        packages = json.loads((work / "recipe/config/system-packages.lock.json").read_bytes())
        scratch = root / "var/tmp/inkyos-packages"; scratch.mkdir(mode=0o700)
        for package in packages["packages"]:
            source = work / "packages" / package["filename"]
            require(file_hash(source) == {"sha256": package["sha256"], "size_bytes": package["size_bytes"]}, "package pin mismatch")
            destination = scratch / package["filename"]; shutil.copyfile(source, destination); destination.chmod(0o600)
            b.target(run, work, ["/usr/bin/dpkg", "--install", "/var/tmp/inkyos-packages/" + package["filename"]],
                     "system-package-" + package["name"] + ".log")
            destination.unlink()
        scratch.rmdir()
        b.target(run, work, ["/usr/bin/dpkg", "--audit"], "system-package-audit.log")
        require((work / "system-package-audit.log").read_bytes() == b"", "dpkg audit failed")
        b.load("install-test-access-packages.py").install(root, work / "recipe", work)
        commands = (["/usr/sbin/usermod", "--login", "inky", "--home", "/home/inky", "--move-home", "pi"],
                    ["/usr/sbin/groupmod", "--new-name", "inky", "pi"],
                    ["/usr/sbin/usermod", "--groups", "spi,i2c,gpio", "--shell", "/usr/sbin/nologin", "--lock", "inky"])
        for index, command in enumerate(commands):
            b.target(run, work, command, "account-" + str(index) + ".log")
        old_umask = os.umask(0o022)
        try:
            b.load("configure-rootfs.py").configure(root, work / "boot", work / "recipe", factory=None)
            backend = value["backend"]; manifest = work / backend["inputs"]
            bundle = b.load("install-factory-studio-bundle-rootfs.py")
            bundle.install_bundle(root, manifest, value["files"][backend["inputs"]]["sha256"],
                                  work / backend["sources"], work / backend["wheels"],
                                  receipt_output=work / "studio-installation.json")
            bundle.verify_bundle(root, manifest, value["files"][backend["inputs"]]["sha256"],
                                 work / backend["sources"], work / backend["wheels"])
            profile = load(work / "imager-os/configure-imager-rootfs.py", "imager_profile")
            profile.configure(root, work / "boot", work / "recipe", work / "imager-os",
                              backend_exec_start=value["backend_exec_start"], backend_environment=value["backend_environment"])
            release = json.loads((root / "etc/inkyos-release.json").read_bytes())
            release.update(kind="imager-lan", application={"studio_commit": value["studio_commit"]},
                           os_commit=value["os_commit"], image_inputs_sha256=pin)
            (root / "etc/inkyos-release.json").write_text(json.dumps(release, sort_keys=True, indent=2) + "\n")
        finally:
            os.umask(old_umask)
        b.target(run, work, ["/usr/bin/systemd-analyze", "verify", "inkyos-firstboot.service",
                            "inkyos-imager-firstboot.service", "inky-studio.service", "NetworkManager.service"], "systemd-verify.log")
        require(not any(os.path.lexists(root / p) for p in profile.FORBIDDEN)
                and not (work / "boot/inky-imager.json").exists(), "distributed image contains forbidden state")
        require(b.preserved(work) == preserved, "official boot/resize/fstab changed")
        require(policy.read_bytes() == b"#!/bin/sh\nexit 101\n", "policy-rc.d changed"); policy.unlink()
        run(["umount", str(root / "dev")]); mounted.mounted.remove("root/dev")
        mounted.freeze_inventory("imager")
    require(inputs(work, pin) == value, "inputs changed during composition")
    result = {"schema_version": 1, "kind": "inky-imager-image-candidate", "input_sha256": pin,
              "image": file_hash(work / "candidate.img"), "os_commit": value["os_commit"],
              "studio_commit": value["studio_commit"], "backend_code_executed": False,
              "wifi_preconfigured": False, "factory_runtime": False, "boot_qualified": False,
              "hardware_qualified": False, "preserved_boot_and_resize": True}
    write_json(work / "imager-candidate.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--inputs-sha256", required=True)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        print(json.dumps(build(args.work, args.inputs_sha256), sort_keys=True))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print("imager_image_refused: " + str(exc), file=sys.stderr); return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
