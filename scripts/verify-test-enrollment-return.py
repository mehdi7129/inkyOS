#!/usr/bin/env python3
"""Compare an enrollment return through existing READ ONLY ext4/FAT mounts.

Never mount, flash, read private keys, trust a report alone, or contact a device.
The expected private export is checked without reading image bytes. Local
unsigned files establish consistency, never authenticity or activation rights.
"""
import sys
sys.dont_write_bytecode = True

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


runtime = module("_return_fixed_enrollment_contract", "test-enrollment-firstboot.py")
export_contract = module("_return_private_export_contract", "verify-test-enrollment.py")
PROFILE = runtime.PROFILE_PATH.lstrip("/")
STATE = runtime.STATE_PATH.lstrip("/")
PUBLIC_KEY = runtime.HOST_KEY_PATH.lstrip("/") + ".pub"
PRIVATE_KEY = runtime.HOST_KEY_PATH.lstrip("/")
RUNTIME = runtime.SCRIPT_PATH.lstrip("/")
REPORT = "inkyos-test-enrollment.json"
MAX_PROOF = 64 * 1024**2
MAX_TOTAL = 128 * 1024**2
MAX_ARCHIVE = 8 * 1024**2
READ_BUDGET = 30.0
CHECKS = (
    "rootfs_readonly_ext4", "bootfs_readonly_vfat", "expected_export_consistent",
    "expected_image_stat_checked", "profile_private_metadata", "profile_canonical",
    "profile_matches_expected_bytes", "state_private_metadata", "state_enrolled",
    "state_profile_binding", "public_report_schema", "public_report_live_claim",
    "report_profile_binding", "host_public_metadata", "host_public_binding",
    "host_private_metadata_only", "runtime_metadata", "runtime_binding",
    "observations_closed", "no_partial_artifacts", "reads_stable",
)
LIMITS = [
    "Unsigned local files establish consistency, not independent authenticity.",
    "Expected image bytes are not read or hashed; only file metadata and size are checked.",
    "Inventories are not regenerated from image bytes; the installed payload is not fully rehashed.",
    "Runtime execution, boot duration, shutdown and hardware operation are not attested.",
    "Radio and panel observations do not qualify country application or hardware.",
    "No network access, SSH binding, application activation or release is authorized.",
    "Read-only applies to the observed mounts; other writable views are not excluded.",
    "Read bounds and deadline checks do not interrupt a kernel-blocked filesystem read.",
]


class InvalidInput(ValueError):
    pass


def require(value):
    if value is not True:
        raise InvalidInput("invalid_input")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def metadata(info, owner, group, *, directory=False, mode=None, fat=False):
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == owner and info.st_gid == group
            and (directory or info.st_nlink == 1)
            and (fat or not info.st_mode & 0o022)
            and (mode is None or stat.S_IMODE(info.st_mode) == mode))


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class ReadTree:
    """No-follow FD walk, stable bounded regular files; never open private keys."""
    def __init__(self, path, *, owner=0, group=0, fat=False, private=False,
                 deadline=None, _fixture=False):
        self.owner, self.group, self.fat = owner, group, fat
        self.deadline = deadline or time.monotonic() + READ_BUDGET
        self.seen = {}
        self.path = os.fspath(path)
        require(type(self.path) is str and self.path.startswith("/") and "\x00" not in self.path
                and self.path != "/" and str(Path(self.path)) == self.path
                and ".." not in PurePosixPath(self.path).parts)
        if _fixture:
            self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        else:
            self.fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                parts = PurePosixPath(self.path).parts[1:]
                for index, part in enumerate(parts):
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fd)
                    os.close(self.fd)
                    self.fd = child
                    metadata(os.fstat(child), owner, group, directory=True,
                             fat=fat and index == len(parts) - 1)
            except BaseException:
                os.close(self.fd)
                raise
        try:
            metadata(os.fstat(self.fd), owner, group, directory=True, fat=fat,
                     mode=0o700 if private else None)
            self.root_stamp = stamp(os.fstat(self.fd))
            self.directories = {".": self.root_stamp}
        except BaseException:
            os.close(self.fd)
            raise

    def close(self):
        os.close(self.fd)

    def timely(self):
        require(time.monotonic() < self.deadline)

    def directory(self, relative=".", *, private=False):
        self.timely()
        require(type(relative) is str and "\x00" not in relative
                and (relative == "." or relative and str(PurePosixPath(relative)) == relative
                     and not relative.startswith("/") and ".." not in PurePosixPath(relative).parts))
        fd = os.dup(self.fd)
        try:
            parts = () if relative == "." else PurePosixPath(relative).parts
            prefix = []
            for part in parts:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                info = os.fstat(fd)
                metadata(info, self.owner, self.group, directory=True)
                prefix.append(part)
                name = "/".join(prefix)
                current = stamp(info)
                require(name not in self.directories or self.directories[name] == current)
                self.directories.setdefault(name, current)
            if private:
                metadata(os.fstat(fd), self.owner, self.group, directory=True, mode=0o700)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def info(self, relative, *, mode=None, private=False):
        item = PurePosixPath(relative)
        parent = self.directory(str(item.parent), private=private)
        try:
            info = os.stat(item.name, dir_fd=parent, follow_symlinks=False)
            metadata(info, self.owner, self.group, mode=mode, fat=self.fat)
            self.seen[relative] = stamp(info)
            return info
        finally:
            os.close(parent)

    def read(self, relative, *, limit, mode=None, private=False):
        require(relative != PRIVATE_KEY)
        item = PurePosixPath(relative)
        parent = self.directory(str(item.parent), private=private)
        fd = None
        try:
            fd = os.open(item.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(fd)
            metadata(before, self.owner, self.group, mode=mode, fat=self.fat)
            require(before.st_size <= limit)
            raw = bytearray()
            while len(raw) <= limit:
                self.timely()
                chunk = os.read(fd, min(1024 * 1024, limit + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            after = os.fstat(fd)
            current = os.stat(item.name, dir_fd=parent, follow_symlinks=False)
            require(len(raw) == before.st_size and len(raw) <= limit
                    and stamp(before) == stamp(after) == stamp(current))
            self.seen[relative] = stamp(before)
            return bytes(raw)
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent)

    def names(self, relative, *, limit, private=False):
        fd = self.directory(relative, private=private)
        try:
            output = set()
            with os.scandir(fd) as items:
                for item in items:
                    self.timely()
                    output.add(item.name)
                    if len(output) > limit:
                        return None
            return output
        finally:
            os.close(fd)

    def absent(self, relative):
        item = PurePosixPath(relative)
        parent = self.directory(str(item.parent))
        try:
            try:
                os.stat(item.name, dir_fd=parent, follow_symlinks=False)
                return False
            except FileNotFoundError:
                return True
        finally:
            os.close(parent)

    def stable(self):
        require(stamp(os.fstat(self.fd)) == self.root_stamp)
        for relative in list(self.directories):
            fd = self.directory(relative)
            os.close(fd)
        for relative, original in list(self.seen.items()):
            require(stamp(self.info(relative)) == original)
        return True


def unescape_mount(value):
    def replace(match):
        return {"040": " ", "011": "\t", "012": "\n", "134": "\\"}[match[1]]
    require(not re.search(r"\\(?!040|011|012|134)", value))
    return re.sub(r"\\(040|011|012|134)", replace, value)


def readonly_mount(mountinfo, fdinfo, *, device, path, filesystem):
    """Observe the mount selected by an open root FD, including sandbox binds."""
    try:
        identifiers = [line for line in fdinfo.splitlines() if line.startswith(b"mnt_id:")]
        if len(identifiers) != 1:
            return False
        matched = re.fullmatch(rb"mnt_id:[ \t]+([0-9]{1,10})", identifiers[0])
        if matched is None:
            return False
        selected, records = int(matched[1]), []
        for line in mountinfo.decode("ascii").splitlines():
            head, tail = line.split(" - ", 1)
            left, right = head.split(), tail.split()
            if len(left) < 6 or len(right) < 3:
                return False
            if int(left[0]) == selected:
                records.append((left, right))
        if len(records) != 1:
            return False
        left, right = records[0]
        options = set(left[5].split(","))
        return (unescape_mount(left[3]) == "/" and unescape_mount(left[4]) == path
                and right[0] == filesystem and "ro" in options and "rw" not in options
                and left[2] == f"{os.major(device)}:{os.minor(device)}")
    except (ValueError, TypeError, UnicodeError, IndexError):
        return False


def expected_export(tree):
    """Reuse local export validators with strict bounded reads and image stat only."""
    contract, artifacts, lan = export_contract, export_contract.artifacts, export_contract.lan
    manifest_raw = tree.read("manifest.json", limit=1024 * 1024)
    manifest = contract.validate_manifest(runtime.strict_json(manifest_raw))
    recipe_raw = tree.read("recipe-inputs.json", limit=1024 * 1024)
    recipe = artifacts.validate_recipe(runtime.strict_json(recipe_raw))
    require(recipe == manifest["recipe"])
    names = set(manifest["reports"]) | {"manifest.json", "recipe-inputs.json"}
    sizes = {name: tree.info(name).st_size for name in names}
    require(all(size <= (MAX_ARCHIVE if name == "recipe.tar" else MAX_PROOF)
                for name, size in sizes.items()) and sum(sizes.values()) <= MAX_TOTAL)
    reports = {name: tree.read(name, limit=MAX_ARCHIVE if name == "recipe.tar" else MAX_PROOF,
                              mode=0o600 if name == "recipe.tar" else None)
               for name in manifest["reports"]}
    require(all(digest(raw) == manifest["reports"][name] for name, raw in reports.items()))
    for name, raw in reports.items():
        if name.endswith(".json"):
            runtime.strict_json(raw)
    contract.diagnostic.validate_archive(reports["recipe.tar"], recipe)
    # The shared load_export entry point opens an image even when not hashing.
    # Here it is deliberately replaced by metadata-only stat, never an open.
    parent, inventory = contract.validate_parent(reports, manifest)
    require(all(recipe["files"].get(name) == parent["recipe"]["files"].get(name)
                for name in contract.INHERITED_RECIPE_FILES))
    contract.diagnostic.validate_static(reports, manifest)
    contract.validate_prepared_constraints(reports["qualification-prepared.json"], inventory)
    configuration = contract.validate_configuration(reports, manifest, recipe_raw)
    blobs = lan.archived_bytes(reports["recipe.tar"], set(contract.overlay.PAYLOADS) | {contract.overlay.PRIVATE_PROFILE})
    # Enforce the private tar member metadata as in load_export, without extraction.
    import io
    import tarfile
    with tarfile.open(fileobj=io.BytesIO(reports["recipe.tar"]), mode="r:") as archive:
        private = archive.getmember("recipe/" + contract.overlay.PRIVATE_PROFILE)
        require(private.mode == 0o600 and private.uid == private.gid == 0)
    raw_profile = contract.private_profile(blobs, reports, manifest_raw, recipe_raw)
    filesystem = artifacts.validate_filesystem(runtime.strict_json(reports["filesystem-manifest.json"]))
    contract.validate_inventory(inventory, filesystem, configuration, blobs)
    inspection = runtime.strict_json(reports["image-inspection.json"])
    image = inspection.get("image") if type(inspection) is dict else None
    require(type(image) is dict and image.get("sha256") == manifest["image"]["sha256"]
            and type(image.get("size_bytes")) is int and image["size_bytes"] == manifest["image"]["size_bytes"])
    info = tree.info(manifest["image"]["filename"], mode=0o600)
    require(info.st_size == manifest["image"]["size_bytes"])
    return {"profile_bytes": raw_profile, "profile_sha256": digest(raw_profile),
            "runtime_sha256": recipe["files"]["scripts/test-enrollment-firstboot.py"]}


def public_observations(value):
    if type(value) is not dict or set(value) != {"panel", "radio"}:
        return False
    empty = {"status": "blocked", "live_evidence": False, "data": None}
    for kind, item in value.items():
        if type(item) is not dict or set(item) != set(empty) or type(item["live_evidence"]) is not bool:
            return False
        if item == empty:
            continue
        base = {"schema_version": 1, "kind": "test-" + kind + "-observation",
                "observation_source": "live-system", "live_evidence": True,
                "activation_authorized": False, "hardware_qualified": False, "release_qualified": False}
        if kind == "panel":
            base.update(passed=True, status="PASS", panel=item["data"])
        else:
            if type(item["data"]) is not dict or set(item["data"]) != {"firmware", "kernel", "channels_2_4ghz"}:
                return False
            base.update(passed=False, status="BLOCKED", firmware_tuple_qualified=False,
                        observations_complete=True, **item["data"])
        if runtime.reduced_observation(base, kind) != item:
            return False
    return True


def validate_state(value):
    require(type(value) is dict and set(value) == {"schema_version", "kind", "state", "profile_sha256",
                                                "application_activation_authorized"}
            and type(value["schema_version"]) is int and value["schema_version"] == 1
            and value["kind"] == "test-lan-enrollment-state"
            and type(value["state"]) is str and value["state"] in {"pending", "enrolled", "review-required"}
            and type(value["profile_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", value["profile_sha256"]) is not None
            and value["application_activation_authorized"] is False)


def validate_report(value):
    fields = {"schema_version", "kind", "state", "challenge", "application_source_commit",
              "application_manifest_sha256", "parent_image_sha256", "profile_sha256", "host_public_key",
              "host_public_key_sha256", "runtime_source_sha256", "observations", "live_evidence", *runtime.FALSE_FIELDS}
    require(type(value) is dict and set(value) == fields
            and type(value["schema_version"]) is int and value["schema_version"] == 1
            and value["kind"] == "test-lan-enrollment-report" and value["state"] == "enrolled"
            and type(value["live_evidence"]) is bool and all(value[key] is False for key in runtime.FALSE_FIELDS)
            and runtime.public_key(value["host_public_key"]) is not None
            and all(type(value[key]) is str and re.fullmatch(r"[0-9a-f]{64}", value[key]) is not None
                    for key in ("challenge", "profile_sha256", "host_public_key_sha256", "runtime_source_sha256"))
            and value["challenge"] != "0" * 64
            and all(type(value[key]) is str for key in ("application_source_commit", "application_manifest_sha256", "parent_image_sha256")))


def proc_read(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode))
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(fd, min(4096, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        require(len(raw) <= limit)
        return bytes(raw)
    finally:
        os.close(fd)


class NativeAdapter:
    def __init__(self, rootfs, bootfs, expected):
        self.paths, self.trees = (rootfs, bootfs, expected), []

    def environment(self):
        return sys.platform.startswith("linux") and os.geteuid() == 0

    def open(self):
        paths = [Path(os.fspath(path)) for path in self.paths]
        require(all(a != b and a not in b.parents and b not in a.parents
                    for i, a in enumerate(paths) for b in paths[i + 1:]))
        deadline = time.monotonic() + READ_BUDGET
        for path, fat, private in zip(self.paths, (False, True, False), (False, False, True)):
            self.trees.append(ReadTree(path, fat=fat, private=private, deadline=deadline))
        self.root, self.boot, self.export = self.trees

    def mounts(self):
        pid = os.getpid()
        info = proc_read(f"/proc/{pid}/mountinfo", 1024 * 1024)
        return {key: readonly_mount(info, proc_read(f"/proc/{pid}/fdinfo/{tree.fd}", 4096),
                    device=os.fstat(tree.fd).st_dev, path=tree.path, filesystem=filesystem)
                for key, tree, filesystem in ((CHECKS[0], self.root, "ext4"), (CHECKS[1], self.boot, "vfat"))}

    def expected(self):
        return expected_export(self.export)

    def returned(self):
        root, boot = self.root, self.boot
        private_info = root.info(PRIVATE_KEY, mode=0o600, private=True)
        require(0 < private_info.st_size <= 4096)
        raw = {
            "profile": root.read(PROFILE, limit=4096, mode=0o600, private=True),
            "state": root.read(STATE, limit=4096, mode=0o600, private=True),
            "pub": root.read(PUBLIC_KEY, limit=256, mode=0o644, private=True),
            "runtime": root.read(RUNTIME, limit=65536, mode=0o555),
            "report": boot.read(REPORT, limit=32768),
        }
        clean = (root.names(str(PurePosixPath(PROFILE).parent), limit=3, private=True)
                    == {"profile.json", "ssh_host_ed25519_key", "ssh_host_ed25519_key.pub"}
                 and root.names(str(PurePosixPath(STATE).parent), limit=1, private=True) == {"state.json"}
                 and boot.absent("." + REPORT + ".tmp"))
        return raw, clean

    def stable(self):
        return all(tree.stable() for tree in self.trees) and all(self.mounts().values())

    def close(self):
        for tree in reversed(self.trees):
            tree.close()


def summary(*, native=False):
    return {"schema_version": 1, "kind": "test-enrollment-return-comparison",
            "scope": "offline-readonly-enrollment-consistency", "status": "INVALID", "passed": False,
            "observation_source": "native-read-only" if native else "fixture",
            "native_readonly_evidence": False, "checks": {key: False for key in CHECKS}, "error": None,
            "application_activation_authorized": False, "ssh_access_enabled": False,
            "network_profile_present": False, "hardware_qualified": False, "release_qualified": False,
            "authenticity_verified": False, "runtime_execution_attested": False,
            "image_sha256_verified": False, "shutdown_observed": False, "limits": list(LIMITS)}


def compare(adapter):
    native = type(adapter) is NativeAdapter
    result = summary(native=native)
    checks = result["checks"]
    try:
        if adapter.environment() is not True:
            raise InvalidInput("invalid_input")
        adapter.open()
        mounted = adapter.mounts()
        require(type(mounted) is dict and set(mounted) == set(CHECKS[:2])
                and all(type(value) is bool for value in mounted.values()))
        checks.update(mounted)
        if not all(mounted.values()):
            result.update(status="FAIL", error="readonly_mount_required")
            return result, 1
        result["native_readonly_evidence"] = native
        expected = adapter.expected()
        checks["expected_export_consistent"] = checks["expected_image_stat_checked"] = True
        raw, clean = adapter.returned()
        require(type(raw) is dict and set(raw) == {"profile", "state", "pub", "runtime", "report"}
                and all(type(value) is bytes for value in raw.values()) and type(clean) is bool)
        profile, state, report = (runtime.strict_json(raw[key]) for key in ("profile", "state", "report"))
        require(runtime.validate_profile(profile))
        validate_state(state)
        validate_report(report)
        checks["profile_private_metadata"] = checks["state_private_metadata"] = True
        checks["host_public_metadata"] = checks["host_private_metadata_only"] = checks["runtime_metadata"] = True
        checks["profile_canonical"] = raw["profile"] == runtime.canonical(profile)
        checks["profile_matches_expected_bytes"] = raw["profile"] == expected["profile_bytes"]
        checks["state_enrolled"] = state["state"] == "enrolled"
        profile_hash = digest(raw["profile"])
        checks["state_profile_binding"] = state["profile_sha256"] == profile_hash == expected["profile_sha256"]
        checks["public_report_schema"] = True
        checks["public_report_live_claim"] = report["live_evidence"] is True
        checks["report_profile_binding"] = (report["profile_sha256"] == profile_hash == expected["profile_sha256"]
            and report["challenge"] == profile["challenge"]
            and report["application_source_commit"] == profile["application_source_commit"]
            and report["application_manifest_sha256"] == profile["application_manifest_sha256"]
            and report["parent_image_sha256"] == profile["parent_image_sha256"])
        match = re.fullmatch(rb"(ssh-ed25519 [A-Za-z0-9+/]{68}) inkyos-test-host\n", raw["pub"])
        require(match is not None)
        host = match[1].decode("ascii")
        wire = runtime.public_key(host)
        require(wire is not None)
        checks["host_public_binding"] = (host == report["host_public_key"]
            and digest(wire) == report["host_public_key_sha256"])
        checks["runtime_binding"] = digest(raw["runtime"]) == expected["runtime_sha256"] == report["runtime_source_sha256"]
        checks["observations_closed"] = public_observations(report["observations"])
        checks["no_partial_artifacts"] = clean
        checks["reads_stable"] = adapter.stable() is True
        result["passed"] = all(value is True for value in checks.values())
        result["status"] = "PASS" if result["passed"] else "FAIL"
        result["error"] = None if result["passed"] else "return_inconsistent"
        return result, 0 if result["passed"] else 1
    except FileNotFoundError:
        result.update(status="FAIL", error="return_incomplete")
        return result, 1
    except Exception:
        result.update(status="INVALID", error="invalid_input")
        return result, 2
    finally:
        adapter.close()


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise InvalidInput("invalid_input")


def main(argv=None):
    try:
        parser = Parser(description=__doc__)
        for name in ("rootfs", "bootfs", "expected-export"):
            parser.add_argument("--" + name, required=True)
        args = parser.parse_args(argv)
        result, code = compare(NativeAdapter(args.rootfs, args.bootfs, args.expected_export))
    except Exception:
        result, code = summary(), 2
        result["error"] = "invalid_input"
    import json
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
