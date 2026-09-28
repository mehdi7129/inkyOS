#!/usr/bin/env python3
"""Revalidate a local prototype export's integrity without mounting or running it."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


MAX_REPORT_BYTES = 64 * 1024**2
MAX_IMAGE_BYTES = 64 * 1024**3
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MODE = re.compile(r"[0-7]{4}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
REQUIRED_REPORTS = frozenset({
    "builder.json", "firstboot-smoke.json", "qualification-static.json",
    "filesystem-manifest.json", "image-inspection.json", "systemd-verify.txt",
    "boot-preserved.sha256", "fsck-ext4.txt", "fsck-fat.txt",
})
REQUIRED_SMOKE_CHECKS = frozenset({
    "linux_arm64_builder", "private_uts_namespace", "kernel_entropy",
    "runtime_hostname_applied", "two_distinct_identities", "repeat_stable_without_entropy",
    "private_permissions", "machine_id_unchanged", "fixture_files_reconciled",
    "child_completed", "parent_hostname_unchanged", "parent_namespace_unchanged", "fixtures_removed",
})
REQUIRED_STATIC_CHECKS = frozenset({
    "RELEASE_METADATA", "FIRSTBOOT_ENABLED", "FIRSTBOOT_COMMAND", "MACHINE_ID_UNINITIALIZED",
    "HOSTNAME_GENERIC", "INKY_ACCOUNT", "NO_SSH_HOST_KEYS", "NETWORKMANAGER_GENERIC_STATE",
    "CLOUD_INIT_DISABLED", "BOOT_RESIZE", "BOOT_INCLUDE", "BOOT_INTERFACES", "I2C_MODULE",
    "RPI_RESIZE_ENABLED", "LOCKED_SYSTEM_PACKAGES",
})
APPLICATION_REPORTS = frozenset({
    'application-manifest.json', 'application-archives.json', 'application-installation.json',
    'qualification-application.json', 'sudoers-verify.txt',
    'application-install-venv.txt', 'application-install-dependencies.txt',
    'application-install-editable.txt', 'application-install-pip-check.txt',
})
APPLICATION_CHECKS = frozenset({
    'APPLICATION_METADATA', 'REVIEWED_INSTALLER_SOURCES', 'SOURCE_COMMIT_PIN',
    'APPLICATION_ACCOUNTS', 'APP_MASK_inky-studio.service', 'APP_MASK_inky-network.service',
    'WIFI_DISABLED', 'NO_PRESEEDED_COUNTRY', 'APP_VENV', 'NO_APP_RUNTIME_STATE', 'NO_PYTHON_BYTECODE',
    'APP_DATA_DIRECTORIES',
})


class ArtifactError(ValueError):
    pass


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ArtifactError("Duplicate JSON key")
        value[key] = item
    return value


def _invalid_constant(_value):
    raise ArtifactError("Non-finite JSON number")


def parse_json(raw):
    return json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def valid_hash(value):
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def integer(value):
    return type(value) is int and value >= 0


def relative_path(value, *, allow_root=False):
    if not isinstance(value, str) or not value or "\x00" in value:
        return False
    if allow_root and value == ".":
        return True
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts and value != "." and str(path) == value


def basename(value):
    return isinstance(value, str) and NAME.fullmatch(value) is not None


class ExportDirectory:
    """Open only simple names relative to one real directory; never follow links."""
    def __init__(self, path):
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def close(self):
        os.close(self.fd)

    def open_regular(self, name):
        if not basename(name):
            raise ArtifactError("Artifact filename must be a simple basename")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ArtifactError("Artifact must be a regular file")
            return os.fdopen(fd, "rb"), info
        except BaseException:
            os.close(fd)
            raise

    def read(self, name):
        stream, before = self.open_regular(name)
        with stream:
            if before.st_size > MAX_REPORT_BYTES:
                raise ArtifactError("Report exceeds 64 MiB")
            raw = stream.read(MAX_REPORT_BYTES + 1)
            after = os.fstat(stream.fileno())
        if len(raw) != before.st_size or before != after:
            # Ignore atime, which may change merely because we read the file.
            if (len(raw) != before.st_size or before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns or before.st_ctime_ns != after.st_ctime_ns):
                raise ArtifactError("Report changed while being read")
        if len(raw) > MAX_REPORT_BYTES:
            raise ArtifactError("Report exceeds 64 MiB")
        return raw

    def image(self, record, *, verify_hash):
        stream, before = self.open_regular(record["filename"])
        with stream:
            if before.st_size != record["size_bytes"]:
                raise ArtifactError("Image size differs from export manifest")
            if not verify_hash:
                return
            digest, count = hashlib.sha256(), 0
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                count += len(block)
                if count > record["size_bytes"]:
                    raise ArtifactError("Image grew during verification")
                digest.update(block)
            after = os.fstat(stream.fileno())
        if (count != before.st_size or after.st_size != before.st_size
                or before.st_mtime_ns != after.st_mtime_ns or before.st_ctime_ns != after.st_ctime_ns):
            raise ArtifactError("Image changed while being read")
        if digest.hexdigest() != record["sha256"]:
            raise ArtifactError("Image SHA-256 differs from export manifest")


def validate_recipe(recipe):
    if (not isinstance(recipe, dict) or type(recipe.get("schema_version")) is not int
            or recipe["schema_version"] != 1 or not isinstance(recipe.get("source_commit"), str)
            or re.fullmatch(r"[0-9a-f]{40}", recipe["source_commit"]) is None
            or type(recipe.get("worktree_dirty")) is not bool
            or not isinstance(recipe.get("files"), dict) or not recipe["files"]):
        raise ArtifactError("Recipe must contain schema 1, commit, dirty flag and non-empty files")
    if any(not relative_path(path) or not valid_hash(digest) for path, digest in recipe["files"].items()):
        raise ArtifactError("Invalid recipe file path or SHA-256")
    return recipe


def validate_build(value):
    if (not isinstance(value, dict) or type(value.get("schema_version")) is not int
            or value["schema_version"] != 1 or value.get("kind") not in {"system-prototype", "application-prototype"}
            or value.get("hardware_qualified") is not False
            or "application" not in value):
        raise ArtifactError("Expected schema 1 prototype with explicit application and hardware_qualified=false")
    validate_recipe(value.get("recipe"))
    application = value['application']
    required_reports = REQUIRED_REPORTS
    if value['kind'] == 'system-prototype':
        if application is not None:
            raise ArtifactError('System prototype requires application=null')
    else:
        if (not isinstance(application, dict) or set(application) != {
                'source_commit', 'application_version', 'manifest_sha256', 'startup', 'release_qualified'}
                or not isinstance(application['source_commit'], str)
                or re.fullmatch(r'[0-9a-f]{40}', application['source_commit']) is None
                or not isinstance(application['application_version'], str)
                or re.fullmatch(r'\d+\.\d+\.\d+(?:(?:a|b|rc)\d+|-[0-9A-Za-z.-]+)?', application['application_version']) is None
                or not valid_hash(application['manifest_sha256'])
                or application['startup'] != 'masked-pending-firstboot-contract'
                or application['release_qualified'] is not False
                or value['recipe']['files'].get('application-manifest.json') != application['manifest_sha256']):
            raise ArtifactError('Application prototype requires a pinned recipe input and masked, unqualified startup')
        required_reports |= APPLICATION_REPORTS
    image = value.get("image")
    if (not isinstance(image, dict) or not basename(image.get("filename"))
            or not image["filename"].endswith(".img") or not valid_hash(image.get("sha256"))
            or not integer(image.get("size_bytes")) or not 0 < image["size_bytes"] <= MAX_IMAGE_BYTES):
        raise ArtifactError("Image requires a regular .img basename, bounded size and SHA-256")
    reports = value.get("reports")
    if (not isinstance(reports, dict) or not required_reports <= set(reports) or len(reports) > 128
            or any(not basename(name) or not valid_hash(digest) for name, digest in reports.items())
            or {"manifest.json", image["filename"]} & set(reports)):
        raise ArtifactError("Invalid report names/hashes or required build reports are missing")
    return value


def validate_filesystem(value):
    if not isinstance(value, dict) or set(value) != {"schema_version", "scope", "rootfs", "bootfs"}:
        raise ArtifactError("Incomplete filesystem manifest")
    version = value.get("schema_version")
    scopes = {1: "content-without-timestamps", 2: "content-and-metadata-without-timestamps"}
    if type(version) is not int or version not in scopes or value.get("scope") != scopes[version]:
        raise ArtifactError("Unsupported filesystem manifest schema/scope")
    for section in ("rootfs", "bootfs"):
        entries = value[section]
        if not isinstance(entries, dict) or not entries:
            raise ArtifactError("Filesystem manifest entries must be non-empty objects")
        if version == 2 and (not isinstance(entries.get("."), dict) or entries["."].get("type") != "directory"):
            raise ArtifactError("Filesystem v2 must include the root directory")
        for path, record in entries.items():
            if (not relative_path(path, allow_root=version == 2) or not isinstance(record, dict)
                    or not isinstance(record.get("mode"), str) or MODE.fullmatch(record["mode"]) is None
                    or not integer(record.get("uid")) or not integer(record.get("gid"))):
                raise ArtifactError("Invalid filesystem path, mode or ownership")
            kind = record.get("type")
            if kind == "file":
                valid = integer(record.get("size_bytes")) and valid_hash(record.get("sha256"))
            elif kind == "symlink":
                valid = isinstance(record.get("target"), str) and bool(record["target"]) and "\x00" not in record["target"]
            elif kind == "directory" or (version == 2 and kind in {"fifo", "socket"}):
                valid = True
            elif version == 1 and kind == "special":
                valid = integer(record.get("device"))
            elif version == 2 and kind in {"char", "block"}:
                device = record.get("device")
                valid = isinstance(device, dict) and set(device) == {"major", "minor"} and all(integer(n) for n in device.values())
            else:
                valid = False
            if not valid:
                raise ArtifactError("Invalid filesystem record type or content")
            if version == 1:
                continue
            attrs = record.get("xattrs")
            if not isinstance(attrs, dict):
                raise ArtifactError("Filesystem v2 requires xattr inspection status")
            if attrs.get("status") == "unsupported":
                if set(attrs) != {"status", "reason"} or attrs["reason"] not in {"filesystem", "platform"}:
                    raise ArtifactError("Invalid unsupported-xattrs record")
            elif attrs.get("status") == "inspected":
                if set(attrs) != {"status", "entries"} or not isinstance(attrs["entries"], dict):
                    raise ArtifactError("Invalid inspected-xattrs record")
                for name, attr in attrs["entries"].items():
                    if (not isinstance(name, str) or not name or "\x00" in name or not isinstance(attr, dict)
                            or set(attr) != {"size_bytes", "sha256"} or not integer(attr["size_bytes"])
                            or not valid_hash(attr["sha256"])):
                        raise ArtifactError("Invalid xattr digest record")
            else:
                raise ArtifactError("Unknown xattr inspection status")
            if "hardlinks" in record:
                links = record["hardlinks"]
                if (kind == "directory" or not isinstance(links, list) or len(links) < 2
                        or any(not relative_path(p) for p in links) or links != sorted(set(links)) or path not in links):
                    raise ArtifactError("Invalid hardlink group")
                for member in links:
                    if member not in entries or canonical(entries[member]) != canonical(record):
                        raise ArtifactError("Incomplete or inconsistent hardlink group")
    return value


def validate_gates(reports, manifest):
    gate = parse_json(reports["qualification-static.json"])
    if (not isinstance(gate, dict) or type(gate.get("schema_version")) is not int or gate["schema_version"] != 1
            or gate.get("scope") != "offline-system-prototype-contract" or gate.get("passed") is not True
            or gate.get("failed_checks") != [] or not isinstance(gate.get("checks"), list)):
        raise ArtifactError("Static gate is missing or does not report a valid PASS")
    checks = gate["checks"]
    if (not checks or any(not isinstance(c, dict) or not isinstance(c.get("id"), str) or c.get("passed") is not True for c in checks)
            or len({c["id"] for c in checks}) != len(checks)
            or not REQUIRED_STATIC_CHECKS <= {c["id"] for c in checks}):
        raise ArtifactError("Static PASS contradicts its checks or omits core checks")
    smoke = parse_json(reports["firstboot-smoke.json"])
    if (not isinstance(smoke, dict) or smoke.get("passed") is not True
            or not isinstance(smoke.get("checks"), dict) or not REQUIRED_SMOKE_CHECKS <= set(smoke["checks"])
            or any(value is not True for value in smoke["checks"].values())):
        raise ArtifactError("Firstboot smoke PASS contradicts or omits its checks")
    image_report = parse_json(reports["image-inspection.json"])
    image = image_report.get("image") if isinstance(image_report, dict) else None
    if (not isinstance(image, dict) or image.get("sha256") != manifest["image"]["sha256"]
            or type(image.get("size_bytes")) is not int or image["size_bytes"] != manifest["image"]["size_bytes"]):
        raise ArtifactError("Image-inspection metadata differs from export manifest")
    if manifest['kind'] == 'application-prototype':
        if 'BOOT_NO_COUNTRY' not in {check['id'] for check in checks}:
            raise ArtifactError('Application prototype omits the boot country check')
        validate_application_gates(reports, manifest)


def validate_application_gates(reports, manifest):
    application = manifest['application']
    pin = {key: application[key] for key in ('manifest_sha256', 'source_commit', 'application_version')}
    raw = reports['application-manifest.json']
    source = parse_json(raw)
    if (hashlib.sha256(raw).hexdigest() != pin['manifest_sha256']
            or any(source.get(key) != pin[key] for key in ('source_commit', 'application_version'))):
        raise ArtifactError('Application source manifest differs from recipe pin')
    for name, scope in (
            ('application-archives.json', 'pinned-application-archive-structure'),
            ('application-installation.json', 'offline-application-rootfs-install'),
            ('qualification-application.json', 'offline-application-prototype-contract')):
        value = parse_json(reports[name])
        if (not isinstance(value, dict) or type(value.get('schema_version')) is not int
                or value['schema_version'] != 1 or value.get('scope') != scope
                or value.get('passed') is not True or any(value.get(key) != expected for key, expected in pin.items())):
            raise ArtifactError('Application report does not match the pinned candidate or PASS scope')
    inspection = parse_json(reports['application-archives.json'])
    if inspection.get('target_code_executed') is not False or inspection.get('qualification_granted') is not False:
        raise ArtifactError('Archive report exceeds its inert qualification scope')
    install = parse_json(reports['application-installation.json'])
    if (install.get('app_started') is not False or install.get('hardware_qualified') is not False
            or install.get('release_qualified') is not False):
        raise ArtifactError('Installation must not start the app or assert release/hardware qualification')
    if (any(install.get(key) is not True for key in
            ('scratch_removed', 'input_snapshot_removed', 'inputs_snapshotted_root_only'))
            or type(install.get('build_uid')) is not int or install['build_uid'] != 1000
            or type(install.get('build_gid')) is not int or install['build_gid'] != 1000
            or install.get('network_interfaces') != ['lo']
            or not valid_hash(install.get('recipe_sha256'))
            or install['recipe_sha256'] != manifest['recipe']['files'].get('scripts/install-application-rootfs.py')):
        raise ArtifactError('Installation isolation, cleanup or recipe hash contradicts the build contract')
    steps = install.get('steps')
    if (not isinstance(steps, list) or len(steps) != 4
            or [step.get('name') for step in steps if isinstance(step, dict)] != ['venv', 'dependencies', 'editable', 'pip-check']):
        raise ArtifactError('Incomplete application installation steps')
    for step in steps:
        log = reports['application-install-' + step['name'] + '.txt']
        if type(step.get('exit_code')) is not int or step['exit_code'] != 0 or step.get('log_sha256') != hashlib.sha256(log).hexdigest():
            raise ArtifactError('Application step or exported log is inconsistent')
    static = parse_json(reports['qualification-application.json'])
    checks = static.get('checks')
    if (static.get('failed_checks') != [] or not isinstance(checks, list) or not checks
            or any(not isinstance(check, dict) or not isinstance(check.get('id'), str)
                   or check.get('passed') is not True for check in checks)
            or len({check['id'] for check in checks}) != len(checks)
            or not APPLICATION_CHECKS <= {check['id'] for check in checks}):
        raise ArtifactError('Application static PASS contradicts its checks or omits core checks')


def load_export(directory, *, verify_images=True):
    """Return validated records plus a public integrity report for comparison tools."""
    export = ExportDirectory(directory)
    try:
        manifest_raw = export.read("manifest.json")
        manifest = validate_build(parse_json(manifest_raw))
        recipe_raw = export.read("recipe-inputs.json")
        recipe = validate_recipe(parse_json(recipe_raw))
        if canonical(recipe) != canonical(manifest["recipe"]):
            raise ArtifactError("recipe-inputs.json differs from manifest recipe")
        reports = {}
        for name, expected in manifest["reports"].items():
            raw = export.read(name)
            if hashlib.sha256(raw).hexdigest() != expected:
                raise ArtifactError(f"Report SHA-256 mismatch: {name}")
            reports[name] = raw
        validate_gates(reports, manifest)
        filesystem = validate_filesystem(parse_json(reports["filesystem-manifest.json"]))
        export.image(manifest["image"], verify_hash=verify_images)
    finally:
        export.close()
    result = {"schema_version": 1, "scope": "local-export-integrity", "passed": True,
              "image_sha256_verified": verify_images, "image_regular_file_and_size_verified": True,
              "declared_reports_verified": sorted(reports), "recipe_inputs_consistent": True,
              "filesystem_manifest_schema": filesystem["schema_version"],
              "static_gate_consistent_pass": True, "firstboot_smoke_consistent_pass": True,
              "authenticity_verified": False, "hardware_qualified": False,
              "limits": ["Hashes are checked against this unsigned local manifest, not an independent trust anchor.",
                         "Reports are checked for integrity and consistency; their tests are not rerun.",
                         "Filesystem records are not regenerated from the image; no mounting, extraction or image execution occurs.",
                         "No boot or hardware qualification is established."]}
    if not verify_images:
        result["limits"].append("Image bytes were not hashed; only file type and size were checked.")
    if filesystem["schema_version"] == 1:
        result["limits"].append("Filesystem schema 1 does not represent xattrs, ACLs or hardlink groups.")
    return {"manifest": manifest, "filesystem": filesystem, "report": result}


def write_report(path, result, input_directories):
    output = Path(path).absolute()
    if any(output.resolve().is_relative_to(Path(directory).resolve()) for directory in input_directories):
        raise ArtifactError("Output must be outside the input export directories")
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="Prototype export directory")
    parser.add_argument("--output", type=Path, metavar="NEW.json", help="New report outside the export; default stdout")
    args = parser.parse_args(argv)
    try:
        result = load_export(args.directory, verify_images=True)["report"]
        if args.output:
            write_report(args.output, result, [args.directory])
        else:
            print(json.dumps(result, indent=2, sort_keys=True))
    except (ArtifactError, OSError, ValueError, TypeError, KeyError) as error:
        print(f"verify-artifacts: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
