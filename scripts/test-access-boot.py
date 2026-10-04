#!/usr/bin/python3 -I
"""One explicit boot path: fresh enrollment/stop, or signed TEST LAN access.

The SSH start is asynchronous because its unit is ordered after this oneshot.
Its ExecCondition independently checks the cache, connection and current boot.
No application activation, private-key read, or automatic partial-state repair.
"""
import sys
sys.dont_write_bytecode = True

import hashlib
import json
import os
import platform
import re
import stat
import time

BASE = "/usr/local/lib/inkyos/"
LEGACY = BASE + "test-enrollment-firstboot.py"
LEGACY_SHA256 = "081bac2c04d4e72a6e74a365664b72941fa4d1e84d1ccc32cf0dc25d9e8a337a"
ENROLLMENT = BASE + "test-access-enrollment.py"
ENROLLMENT_SHA256 = "dc51b263f9c532ddbe97235118ef0455e2a903777d296c87a84bac250538e6e5"
MANIFEST = "/usr/local/share/inkyos/test-access-manifest.json"
PROFILE = "/etc/inkyos-test-enrollment/profile.json"
STATE = "/var/lib/inkyos-test-enrollment/state.json"
CONFIG = "/etc/inkyos-test-operator.json"
RUNTIME = "/run/inkyos-test-access"
READY = RUNTIME + "/ssh-ready.json"
ERRORS = {"target_unverified", "sources_invalid", "enrollment_invalid", "enrollment_failed",
          "import_failed", "connection_failed", "operator_config_invalid", "connection_changed",
          "ssh_start_failed", "ssh_not_ready", "boot_failed", "invalid_arguments"}


class BootError(ValueError):
    pass


def require(value, error):
    if value is not True:
        raise BootError(error)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def bootstrap():
    directory, source = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW), None
    try:
        for name in LEGACY.strip("/").split("/")[:-1]:
            info = os.fstat(directory)
            require(info.st_uid == 0 and not info.st_mode & 0o022, "sources_invalid")
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.fstat(directory)
        require(info.st_uid == 0 and not info.st_mode & 0o022, "sources_invalid")
        name = LEGACY.rsplit("/", 1)[1]
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        before = os.fstat(source)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == 0o555 and 0 < before.st_size <= 65536, "sources_invalid")
        raw = os.read(source, 65537)
        stamp = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                              value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        require(len(raw) == before.st_size and digest(raw) == LEGACY_SHA256
                and stamp(before) == stamp(os.fstat(source))
                and stamp(before) == stamp(os.stat(name, dir_fd=directory, follow_symlinks=False)), "sources_invalid")
    finally:
        if source is not None:
            os.close(source)
        os.close(directory)
    ns = {"__name__": "inkyos_boot_legacy", "__file__": LEGACY}
    exec(compile(raw, LEGACY, "exec"), ns)
    return ns


class NativeAdapter:
    def __init__(self):
        self.files = self.connection = None
        self.snapshots = {}

    def bind(self):
        require(sys.platform.startswith("linux") and platform.machine() == "aarch64"
                and os.getuid() == os.geteuid() == 0 and sys.byteorder == "little", "target_unverified")
        self.lib = bootstrap()
        self.files = self.lib["Files"]()
        require(self.files.read(self.lib["MODEL_PATH"], limit=128) == self.lib["PI_MODEL"], "target_unverified")
        raw = self.files.read(ENROLLMENT, mode=0o555, limit=65536)
        require(digest(raw) == ENROLLMENT_SHA256, "sources_invalid")
        self.enrollment = {"__name__": "inkyos_boot_enrollment", "__file__": ENROLLMENT}
        exec(compile(raw, ENROLLMENT, "exec"), self.enrollment)
        probe = self.enrollment["NativeAdapter"]()
        try:
            self.policy = probe.policy
            self.profile_raw = probe.profile()
            self.profile = self.policy.strict_json(self.profile_raw)
            require(self.policy.validate_profile(self.profile)
                    and self.profile_raw == self.policy.canonical(self.profile), "enrollment_invalid")
            require(probe.runtime_manifest(self.profile) is True, "sources_invalid")
            self.manifest_raw = probe.manifest_raw
            manifest = self.policy.strict_json(self.manifest_raw)
            # All reviewed static payloads, never a key or arbitrary manifest path.
            self.sources = {}
            for path, row in manifest["files"].items():
                require(path in self.enrollment["STATIC_PATHS"] and row["mode"] in {"0555", "0644", "0440"},
                        "sources_invalid")
                content = self.files.read("/" + path, mode=int(row["mode"], 8), limit=65536)
                require(digest(content) == row["sha256"], "sources_invalid")
                self.sources["/" + path] = content
                self.snapshots["/" + path] = (content, int(row["mode"], 8), False)
            require(BASE + "test-access-boot.py" in self.sources, "sources_invalid")
            self.snapshots[MANIFEST] = (self.manifest_raw, 0o644, False)
            self.snapshots[PROFILE] = (self.profile_raw, 0o600, True)
        finally:
            probe.close()
        try:
            state = self.files.read(STATE, mode=0o600, private=True, limit=4096)
        except FileNotFoundError:
            return "fresh"
        require(self.policy.validate_enrolled_state(state, self.profile_raw), "enrollment_invalid")
        self.snapshots[STATE] = (state, 0o600, True)
        return "enrolled"

    def module(self, name):
        path = BASE + "test-access-" + name + ".py"
        require(path in self.sources, "sources_invalid")
        namespace = {"__name__": "inkyos_boot_" + name, "__file__": path}
        exec(compile(self.sources[path], path, "exec"), namespace)
        return namespace

    def unchanged(self):
        return all(self.files.read(path, mode=mode, private=private, limit=65536) == raw
                   for path, (raw, mode, private) in self.snapshots.items())

    def enroll(self):
        return self.enrollment["enroll"](self.enrollment["NativeAdapter"](), live=True)

    def import_cache(self):
        module = self.module("import")
        return module["import_access"](module["NativeAdapter"]())

    def connect(self):
        module = self.module("connect")
        return module["connect"](module["NativeAdapter"]())

    def connected(self):
        if self.connection is None:
            module = self.module("connect")
            self.connection = module["NativeAdapter"]()
            self.connection.deadline = time.monotonic() + 20
            self.connection.work_deadline = self.connection.deadline
            require(self.connection.target() is True and self.connection.bind() is True, "connection_changed")
            require(self.connection.authenticate_cache() is True, "connection_changed")
        return (self.connection.unchanged() is True and self.connection.profiles_closed() is True
                and self.connection.profile_restricted() is True and self.connection.connected() is True
                and self.unchanged() is True)

    def operator_config(self):
        require(self.connected() is True, "connection_changed")
        auth = self.connection.auth
        specs = {PROFILE: "profile_sha256", STATE: "state_sha256",
                 "/var/lib/inkyos/system.json": "system_identity_sha256",
                 "/etc/inkyos-test-enrollment/ssh_host_ed25519_key.pub": "host_public_key_sha256",
                 BASE + "test-lan-preflight.py": "preflight_sha256", LEGACY: "enrollment_source_sha256",
                 "/usr/local/lib/inkyos-test-ssh/dispatch.py": "dispatcher_sha256",
                 "/usr/local/lib/inkyos-test-ssh/runner": "runner_sha256"}
        config = {"schema_version": 1, "kind": "test-operator-runtime", "operator_uid": 1001,
                  "operator_gid": 1001, "country_confirmed": True,
                  **{key: digest(auth.snapshot[path][0]) for path, key in specs.items()}}
        rows = self.files.read("/etc/passwd", limit=262144).decode().splitlines()
        require(rows.count("inky-test:x:1001:1001:InkyOS TEST operator:/nonexistent:/bin/sh") == 1
                and sum(row.split(":")[2] == "1001" for row in rows) == 1, "operator_config_invalid")
        raw = canonical(config)
        try:
            existing = self.files.read(CONFIG, mode=0o600, limit=4096)
        except FileNotFoundError:
            parent = self.files.directory("/etc")
            try:
                self.lib["write_atomic"](parent, CONFIG.rsplit("/", 1)[1], raw)
            finally:
                os.close(parent)
        else:
            require(existing == raw, "operator_config_invalid")
        require(self.files.read(CONFIG, mode=0o600, limit=4096) == raw, "operator_config_invalid")
        self.config_raw = raw
        return True

    def ready_record(self):
        boot_id = self.files.read("/proc/sys/kernel/random/boot_id", limit=64).decode().strip()
        require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot_id) is not None, "ssh_not_ready")
        reply = self.lib["command"](("/usr/bin/systemctl", "--no-pager", "show", "NetworkManager.service",
             "--property=ActiveState,SubState,MainPID"), timeout=2, limit=4096)
        require(reply is not None and reply[0] == 0, "ssh_not_ready")
        fields = dict(row.split("=", 1) for row in reply[1].decode("ascii").splitlines())
        require(set(fields) == {"ActiveState", "SubState", "MainPID"} and fields["ActiveState"] == "active"
                and fields["SubState"] == "running" and re.fullmatch(r"[1-9][0-9]{0,9}", fields["MainPID"]) is not None,
                "ssh_not_ready")
        return {"schema_version": 1, "kind": "test-access-ssh-ready", "boot_id": boot_id,
                "networkmanager_pid": int(fields["MainPID"]), "profile_sha256": digest(self.profile_raw),
                "access_runtime_manifest_sha256": digest(self.manifest_raw), "config_sha256": digest(self.config_raw)}

    def publish_ready(self):
        require(self.connected() is True, "connection_changed")
        raw = canonical(self.ready_record())
        directory = self.files.directory(RUNTIME, private=True)
        try:
            try:
                existing = self.files.read(READY, mode=0o600, private=True, limit=4096)
            except FileNotFoundError:
                self.lib["write_atomic"](directory, "ssh-ready.json", raw)
            else:
                require(existing == raw, "ssh_not_ready")
            require(self.files.read(READY, mode=0o600, private=True, limit=4096) == raw, "ssh_not_ready")
        finally:
            os.close(directory)
        return True

    def verify_ready(self):
        require(self.connected() is True, "connection_changed")
        # This path never creates the config or grants readiness.
        self.config_raw = self.files.read(CONFIG, mode=0o600, limit=4096)
        return (self.files.read(READY, mode=0o600, private=True, limit=4096) == canonical(self.ready_record())
                and self.connected() is True)

    def start_ssh(self):
        return self.lib["command"](("/usr/bin/systemctl", "--no-block", "start", "inkyos-test-ssh.service"),
                                   timeout=3, limit=4096) == (0, b"")

    def close_wifi(self):
        # Called only following a connection attempt by this invocation.
        return self.lib["command"](("/usr/bin/nmcli", "radio", "wifi", "off"), timeout=3, limit=4096) == (0, b"")

    def close(self):
        try:
            if self.connection is not None:
                self.connection.close()
        finally:
            if self.files is not None:
                self.files.close()


def boot(adapter, *, verify_ssh=False):
    result = {"schema_version": 1, "kind": "test-access-boot-result", "passed": False, "phase": "blocked",
              "error": None, "live_evidence": False, "poweroff_requested": False,
              "ssh_start_requested": False, "ssh_start_verified": False, "wifi_off_requested_on_failure": False,
              "application_activation_authorized": False, "hardware_qualified": False, "release_qualified": False}
    connecting = False
    try:
        phase = adapter.bind()
        require(phase in {"fresh", "enrolled"}, "enrollment_invalid")
        if verify_ssh:
            require(phase == "enrolled" and adapter.verify_ready() is True, "ssh_not_ready")
            result.update(passed=True, phase="ssh-condition-passed")
        elif phase == "fresh":
            enrolled = adapter.enroll()
            result["poweroff_requested"] = enrolled.get("poweroff_requested") is True
            require(enrolled.get("passed") is True, "enrollment_failed")
            result.update(passed=True, phase="enrolled-stop-requested")
        else:
            require(adapter.import_cache().get("passed") is True, "import_failed")
            connecting = True
            require(adapter.connect().get("passed") is True, "connection_failed")
            require(adapter.operator_config() is True, "operator_config_invalid")
            require(adapter.publish_ready() is True and adapter.verify_ready() is True, "ssh_not_ready")
            require(adapter.start_ssh() is True, "ssh_start_failed")
            result.update(passed=True, phase="ssh-start-requested", ssh_start_requested=True)
        result["live_evidence"] = type(adapter) is NativeAdapter
    except Exception as error:
        result["error"] = str(error) if type(error) is BootError and str(error) in ERRORS else "boot_failed"
    finally:
        def close_radio():
            try:
                result["wifi_off_requested_on_failure"] = adapter.close_wifi() is True
            except Exception:
                pass
        if connecting and not result["passed"]:
            close_radio()
        try:
            adapter.close()
        except Exception:
            if connecting and result["passed"]:
                close_radio()
            result.update(passed=False, error="boot_failed", live_evidence=False)
    return result


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args not in ([], ["--verify-ssh"]):
        result = {"passed": False, "error": "invalid_arguments"}
    else:
        result = boot(NativeAdapter(), verify_ssh=bool(args))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
