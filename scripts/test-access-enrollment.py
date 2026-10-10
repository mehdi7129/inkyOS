#!/usr/bin/python3 -I
"""Fresh c31 TEST enrollment and stop, before any signed access capsule.

The historical runtime is loaded by immutable pin for its safe filesystem and
key-generation primitives. Its policy and state machine are never patched.
Default execution is inert; the live CLI has no configurable paths or pins.
"""
import sys
sys.dont_write_bytecode = True

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import time
import types


LEGACY_PATH = "/usr/local/lib/inkyos/test-enrollment-firstboot.py"
LEGACY_SHA256 = "081bac2c04d4e72a6e74a365664b72941fa4d1e84d1ccc32cf0dc25d9e8a337a"
POLICY_PATH = "/usr/local/lib/inkyos/test-access-policy.py"
POLICY_SHA256 = "7d3676fde6434235be4d66592da41996c5973aed5b1f226c0fd78462ffb355a9"
SCRIPT_PATH = "/usr/local/lib/inkyos/test-access-enrollment.py"
MANIFEST_PATH = "/usr/local/share/inkyos/test-access-manifest.json"
ACCESS_DIRECTORY = "/var/lib/inkyos-test-access"
PROFILE_PATH = "/etc/inkyos-test-enrollment/profile.json"
STATE_PATH = "/var/lib/inkyos-test-enrollment/state.json"
PUBLIC_REPORT_PATH = "/boot/firmware/inkyos-test-enrollment.json"
HOST_KEY_PATH = "/etc/inkyos-test-enrollment/ssh_host_ed25519_key"
MARKER_PATH = "/etc/inkyos-test-lan.json"
PANEL_PATH = "/usr/local/lib/inkyos/observe-test-panel.py"
RADIO_PATH = "/usr/local/lib/inkyos/observe-test-radio.py"
PREFLIGHT_PATH = "/usr/local/lib/inkyos/test-lan-preflight.py"
SOURCE_PINS = {
    LEGACY_PATH: LEGACY_SHA256, POLICY_PATH: POLICY_SHA256,
    PANEL_PATH: "6fc6b93e30beeb6c03a3867efeb88cfe30ed7e1fe58f2ea6e5c35db9a4c29164",
    RADIO_PATH: "8423207c905abbfb6f7fd4e75125e11f794b063034fee4e9a8346cf449391315",
    PREFLIGHT_PATH: "9cda15bfeaef8ed5bc7c0a2d0b71f470a1411d13dda4e2043f800e9ca37e5fba",
}
MANIFEST_FIELDS = {"schema_version", "kind", "application_source_commit", "application_manifest_sha256",
                   "parent_image_sha256", "files"}
STATIC_PATHS = frozenset({
    *("usr/local/lib/inkyos/" + name + ".py" for name in (
        "test-enrollment-firstboot", "test-access-policy", "test-access-enrollment",
        "test-access-contract", "test-access-import", "test-access-connect", "test-access-boot",
        "test-access-network", "test-access-wifi-gate", "wifi-boot-gate", "test-lan-preflight",
        "test-access-activation-gate", "test-access-activation", "test-access-drain",
        "observe-test-panel", "observe-test-radio")),
    "usr/local/lib/inkyos-test-ssh/dispatch.py", "usr/local/lib/inkyos-test-ssh/runner",
    "usr/lib/systemd/system/inkyos-test-access.service", "usr/lib/systemd/system/inkyos-test-ssh.service",
    "etc/systemd/system/NetworkManager.service.d/10-inkyos-test-wifi.conf",
    "etc/NetworkManager/conf.d/10-inkyos-test-loopback.conf",
    "etc/inkyos-test-ssh/sshd_config", "etc/sudoers.d/inkyos-test-ssh",
    "usr/lib/systemd/system/inkyos-test-activate.service", "usr/lib/systemd/system/inkyos-test-drain.service",
    "usr/local/share/inkyos/test-access/inky-studio.conf", "usr/local/share/inkyos/test-access/inky-network.conf",
})
GUARDS = ("prepared_profile", "exact_payload_pin", "firstboot_success",
          "app_stopped_and_masked", "helper_stopped_and_masked")
FALSE_FIELDS = ("network_profile_present", "ssh_access_enabled",
                "application_activation_authorized", "hardware_qualified", "release_qualified")
REPORT_FIELDS = {"schema_version", "kind", "state", "challenge", "application_source_commit",
                 "application_manifest_sha256", "parent_image_sha256", "profile_sha256",
                 "host_public_key", "host_public_key_sha256", "runtime_source_sha256", "observations",
                 "access_runtime_manifest_sha256", "live_evidence", *FALSE_FIELDS}
ERRORS = {"target_unverified", "profile_invalid", "runtime_manifest_invalid", "source_pin_invalid",
          "prepared_guards_blocked", "existing_artifact", "boot_mount_unverified", "host_key_incomplete",
          "observations_invalid", "runtime_source_invalid", "state_changed"}


class EnrollmentError(ValueError):
    pass


def require(value, error):
    if value is not True:
        raise EnrollmentError(error)


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _bootstrap_source(path, *, root="/", owner=0):
    """Root/owner arguments are fixture seams; production callers use defaults."""
    require(type(path) is str and path.startswith("/")
            and all(part not in {"", ".", ".."} for part in path[1:].split("/")), "source_pin_invalid")
    directory, source = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW), None
    try:
        parts = path[1:].split("/")
        for part in parts[:-1]:
            info = os.fstat(directory)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and not info.st_mode & 0o022,
                    "source_pin_invalid")
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.fstat(directory)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and not info.st_mode & 0o022,
                "source_pin_invalid")
        source = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        before = os.fstat(source)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == owner and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == 0o555 and 0 < before.st_size <= 65536, "source_pin_invalid")
        raw = bytearray()
        while len(raw) <= 65536:
            block = os.read(source, min(4096, 65537 - len(raw)))
            if not block:
                break
            raw.extend(block)
        require(len(raw) == before.st_size and _stamp(before) == _stamp(os.fstat(source))
                == _stamp(os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)), "source_pin_invalid")
        return bytes(raw)
    finally:
        if source is not None:
            os.close(source)
        os.close(directory)


def _module(raw, path, digest):
    require(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == digest, "source_pin_invalid")
    module = types.ModuleType("inkyos_test_access_" + path.rsplit("/", 1)[1].replace("-", "_"))
    module.__file__ = path
    exec(compile(raw, path, "exec"), module.__dict__)
    return module


def load_legacy():
    """Load only the immutable root-owned legacy runtime, without running its CLI."""
    return _module(_bootstrap_source(LEGACY_PATH), LEGACY_PATH, LEGACY_SHA256)


class NativeAdapter:
    """Explicit new policy around the legacy's unchanged filesystem primitives."""
    def __init__(self):
        self.legacy = load_legacy()
        self.policy = _module(_bootstrap_source(POLICY_PATH), POLICY_PATH, POLICY_SHA256)
        self.files = self.legacy.Files()
        self.fds, self.state_stamp = [], None
        self.deadline = time.monotonic() + self.legacy.RUNTIME_BUDGET
        self.sources = {}

    def environment(self):
        return self.legacy.NativeAdapter.environment(self)

    def profile(self):
        return self.legacy.NativeAdapter.profile(self)

    def source(self, path):
        return self.legacy.NativeAdapter.source(self, path)

    def runtime_manifest(self, profile):
        """Only fixed reviewed paths are opened; manifest paths never select reads."""
        raw = self.files.read(MANIFEST_PATH, limit=65536, mode=0o644)
        value = self.policy.strict_json(raw)
        require(type(value) is dict and set(value) == MANIFEST_FIELDS and raw == self.policy.canonical(value)
                and type(value["schema_version"]) is int and value["schema_version"] == 1
                and value["kind"] == "test-access-runtime"
                and value["application_source_commit"] == self.policy.SOURCE
                and value["application_manifest_sha256"] == self.policy.MANIFEST_HASH
                and value["parent_image_sha256"] == self.policy.PARENT_IMAGE_SHA256
                and hashlib.sha256(raw).hexdigest() == profile["access_runtime_manifest_sha256"],
                "runtime_manifest_invalid")
        entries = value["files"]
        require(type(entries) is dict and 6 <= len(entries) <= 128, "runtime_manifest_invalid")
        for path, row in entries.items():
            require(type(path) is str and path in STATIC_PATHS
                    and type(row) is dict and set(row) == {"sha256", "mode"}
                    and type(row["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None
                    and type(row["mode"]) is str and row["mode"] in {"0444", "0440", "0555", "0644", "0600"},
                    "runtime_manifest_invalid")
        require(MANIFEST_PATH[1:] not in entries, "runtime_manifest_invalid")
        sources = {}
        for path in (*SOURCE_PINS, SCRIPT_PATH):
            row = entries.get(path[1:])
            require(type(row) is dict and row["mode"] == "0555", "runtime_manifest_invalid")
            source = self.source(path)
            digest = hashlib.sha256(source).hexdigest()
            require(row["sha256"] == digest and (path == SCRIPT_PATH or digest == SOURCE_PINS[path]),
                    "source_pin_invalid")
            sources[path] = source
        self.sources, self.manifest_raw = sources, raw
        self.runtime_hash = hashlib.sha256(sources[SCRIPT_PATH]).hexdigest()
        return True

    def guards(self):
        marker_raw = self.files.read(MARKER_PATH, limit=4096, mode=0o644)
        marker = self.policy.strict_json(marker_raw)
        blocked = {key: False for key in GUARDS}
        if (type(marker) is not dict or marker.get("source_commit") != self.policy.SOURCE
                or marker.get("manifest_sha256") != self.policy.MANIFEST_HASH):
            return blocked
        helper = _module(self.sources[PREFLIGHT_PATH], PREFLIGHT_PATH, SOURCE_PINS[PREFLIGHT_PATH])
        radio = _module(self.sources[RADIO_PATH], RADIO_PATH, SOURCE_PINS[RADIO_PATH])
        def command(argv, *, timeout, limit):
            result = self.run(argv, timeout, limit=limit)
            require(result is not None and result[0] == 0, "prepared_guards_blocked")
            return result[1].decode("ascii")
        facts = radio.PreparedGuard(helpers=helper.__dict__, command=command).collect()
        if self.files.read(MARKER_PATH, limit=4096, mode=0o644) != marker_raw:
            return blocked
        return facts

    def run(self, argv, timeout, limit=32768):
        return self.legacy.NativeAdapter.run(self, argv, timeout, limit)

    def access_absent(self):
        access = self.files.directory(ACCESS_DIRECTORY, private=True)
        try:
            with os.scandir(access) as items:
                require(next(items, None) is None, "existing_artifact")
        finally:
            os.close(access)
        with os.scandir(self.boot) as items:
            for index, item in enumerate(items):
                require(index < 4096, "existing_artifact")
                name = item.name.lower()
                require(not name.startswith(("inkyacc.", ".inkyacc.")), "existing_artifact")

    def fresh(self):
        self.private = self.files.directory(PROFILE_PATH.rsplit("/", 1)[0], private=True)
        self.fds.append(self.private)
        self.state = self.files.directory(STATE_PATH.rsplit("/", 1)[0], private=True)
        self.fds.append(self.state)
        self.boot = self.files.directory("/boot/firmware", fat=True)
        self.fds.append(self.boot)
        with os.scandir(self.private) as items:
            first = next(items, None)
            require(first is not None and first.name == "profile.json" and next(items, None) is None,
                    "existing_artifact")
        with os.scandir(self.state) as items:
            require(next(items, None) is None, "existing_artifact")
        with os.scandir(self.boot) as items:
            for index, item in enumerate(items):
                require(index < 4096 and item.name.lower() not in {
                    "inkyos-test-enrollment.json", ".inkyos-test-enrollment.json.tmp"}, "existing_artifact")
        self.access_absent()
        pid = os.getpid()
        require(self.legacy.mount_is_fat(self.files.read(f"/proc/{pid}/mountinfo", limit=1024 * 1024),
                    self.files.read(f"/proc/{pid}/fdinfo/{self.boot}", limit=4096), os.fstat(self.boot).st_dev),
                "boot_mount_unverified")

    def write_state(self, state, profile_hash):
        return self.legacy.NativeAdapter.write_state(self, state, profile_hash)

    def key(self):
        return self.legacy.NativeAdapter.key(self)

    def observations(self):
        return self.legacy.NativeAdapter.observations(self)

    def unchanged(self, profile_raw):
        if (self.profile() != profile_raw
                or self.files.read(MANIFEST_PATH, limit=65536, mode=0o644) != self.manifest_raw
                or any(self.source(path) != raw for path, raw in self.sources.items())):
            return False
        self.access_absent()
        return True

    def report(self, value):
        return self.legacy.NativeAdapter.report(self, value)

    def sync(self):
        return self.legacy.NativeAdapter.sync(self)

    def poweroff(self):
        return self.legacy.NativeAdapter.poweroff(self)

    def close(self):
        return self.legacy.NativeAdapter.close(self)


def enroll(adapter=None, *, live=False):
    summary = {"schema_version": 2, "kind": "test-enrollment-runtime", "live_selected": live is True,
               "live_evidence": False, "state": "blocked", "report_written": False,
               "poweroff_requested": False, "passed": False, "error": None,
               **{key: False for key in FALSE_FIELDS}}
    if live is not True or adapter is None:
        return summary
    eligible = own_state = False
    profile_hash = None
    native = type(adapter) is NativeAdapter
    try:
        require(adapter.environment() is True, "target_unverified")
        raw, policy = adapter.profile(), adapter.policy
        profile = policy.strict_json(raw)
        require(policy.validate_profile(profile) and raw == policy.canonical(profile), "profile_invalid")
        profile_hash = hashlib.sha256(raw).hexdigest()
        require(adapter.runtime_manifest(profile) is True, "runtime_manifest_invalid")
        guards = adapter.guards()
        require(type(guards) is dict and all(guards.get(key) is True for key in GUARDS), "prepared_guards_blocked")
        eligible = native
        adapter.fresh()
        adapter.write_state("pending", profile_hash)
        own_state = True
        host = adapter.key()
        wire = policy.public_key(host)
        require(wire is not None, "host_key_incomplete")
        observed = adapter.observations()
        require(type(observed) is dict and set(observed) == {"panel", "radio"}, "observations_invalid")
        if not native:
            observed = {key: {"status": "blocked", "live_evidence": False, "data": None} for key in ("panel", "radio")}
        require(adapter.unchanged(raw) is True, "state_changed")
        report = {"schema_version": 2, "kind": "test-lan-enrollment-report", "state": "enrolled",
            "challenge": profile["challenge"], "application_source_commit": policy.SOURCE,
            "application_manifest_sha256": policy.MANIFEST_HASH, "parent_image_sha256": policy.PARENT_IMAGE_SHA256,
            "profile_sha256": profile_hash, "host_public_key": host,
            "host_public_key_sha256": hashlib.sha256(wire).hexdigest(),
            "runtime_source_sha256": adapter.runtime_hash, "observations": observed,
            "access_runtime_manifest_sha256": profile["access_runtime_manifest_sha256"],
            "live_evidence": native, **{key: False for key in FALSE_FIELDS}}
        require(set(report) == REPORT_FIELDS and type(report["runtime_source_sha256"]) is str
                and re.fullmatch(r"[0-9a-f]{64}", report["runtime_source_sha256"]) is not None, "runtime_source_invalid")
        adapter.report(report)
        summary["report_written"] = True
        adapter.write_state("enrolled", profile_hash)
        summary.update(state="enrolled", passed=True, live_evidence=native)
    except Exception as error:
        summary["error"] = str(error) if type(error) is EnrollmentError and str(error) in ERRORS else "enrollment_failed"
        if own_state or getattr(adapter, "state_stamp", None) is not None:
            summary["state"] = "review-required"
            try:
                adapter.write_state("review-required", profile_hash)
            except Exception:
                pass
    finally:
        if eligible:
            try:
                adapter.sync()
                summary["poweroff_requested"] = adapter.poweroff() is True
                if not summary["poweroff_requested"]:
                    raise EnrollmentError("shutdown_unavailable")
            except Exception:
                summary.update(error="shutdown_unavailable", passed=False)
                if own_state or getattr(adapter, "state_stamp", None) is not None:
                    summary["state"] = "review-required"
                    try:
                        adapter.write_state("review-required", profile_hash)
                    except Exception:
                        pass
        adapter.close()
    return summary


class SafeParser(argparse.ArgumentParser):
    def error(self, _message):
        raise EnrollmentError("invalid_arguments")


def main(argv=None):
    parser = SafeParser(prog="test-access-enrollment.py", description=__doc__, allow_abbrev=False)
    parser.add_argument("--live", action="store_true")
    try:
        args = parser.parse_args(argv)
        result = enroll(live=args.live)
        if args.live:
            if sys.platform.startswith("linux") and os.geteuid() == 0 and platform.machine() == "aarch64":
                try:
                    result = enroll(NativeAdapter(), live=True)
                except Exception:
                    result["error"] = "runtime_unavailable"
            else:
                result["error"] = "linux_arm64_root_required"
        code = 0 if result["passed"] else 1
    except EnrollmentError:
        result = enroll()
        result["error"] = "invalid_arguments"
        code = 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    sys.exit(main())
