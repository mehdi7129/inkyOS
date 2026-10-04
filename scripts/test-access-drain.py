#!/usr/bin/python3 -I
"""One fixed, asynchronous TEST drain job; no device, path or command inputs.

The SSH runner submits a boot-bound request and starts the fixed systemd unit.
Only this worker waits for the SPI owner's exit. It has no drain deadline and
never cancels a systemd job or forcibly signals a service. An unconfirmed command
submission is an error, not evidence that an already submitted job was cancelled.
Poweroff acknowledgement is not proof of shutdown or physical qualification.
"""
import sys
sys.dont_write_bytecode = True

import fcntl
import hashlib
import json
import os
import platform
import re
import stat
import time


BASE = "/usr/local/lib/inkyos/"
SELF = BASE + "test-access-drain.py"
LEGACY = BASE + "test-enrollment-firstboot.py"
LEGACY_SHA256 = "081bac2c04d4e72a6e74a365664b72941fa4d1e84d1ccc32cf0dc25d9e8a337a"
POLICY = BASE + "test-access-policy.py"
POLICY_SHA256 = "4f493e5fe1948b7f5c4c4db8d7ba6814a04af07da5e265cd4044f2d6b6139b89"
ACTIVATION = BASE + "test-access-activation.py"
MANIFEST = "/usr/local/share/inkyos/test-access-manifest.json"
PROFILE = "/etc/inkyos-test-enrollment/profile.json"
STATE = "/var/lib/inkyos-test-enrollment/state.json"
APPLICATION_MANIFEST = "/usr/local/share/inkyos/inky-studio-manifest-v1.json"
DIRECTORY = "/run/inkyos-test-operator"
REQUEST = "drain-request.json"
STATUS = "drain-status.json"
PERMIT = "activation-permit.json"
BOOT_ID = "/proc/sys/kernel/random/boot_id"
APP, HELPER = "inky-studio.service", "inky-network.service"
SERVICE = "/usr/lib/systemd/system/inkyos-test-drain.service"
SERVICE_NAME = "inkyos-test-drain.service"
TEMPLATE_DIRECTORY = "/usr/local/share/inkyos/test-access/"
TEMPLATES = {unit: TEMPLATE_DIRECTORY + unit.removesuffix(".service") + ".conf" for unit in (APP, HELPER)}
RUNTIME_DROPINS = {unit: "/run/systemd/system/" + unit + ".d/10-inkyos-test-access.conf" for unit in (APP, HELPER)}
VENDOR = {unit: "/usr/lib/systemd/system/" + unit for unit in (APP, HELPER)}
FIRSTBOOT = {unit: "/etc/systemd/system/" + unit + ".d/10-inkyos-firstboot.conf" for unit in (APP, HELPER)}
BLUETOOTH = "/etc/systemd/system/inky-studio.service.d/bluetooth.conf"
DROPINS = {APP: {FIRSTBOOT[APP], BLUETOOTH, RUNTIME_DROPINS[APP]},
           HELPER: {FIRSTBOOT[HELPER], RUNTIME_DROPINS[HELPER]}}
PINS = {
    LEGACY: (LEGACY_SHA256, 0o555), POLICY: (POLICY_SHA256, 0o555),
    VENDOR[APP]: ("c9d7e4c16ec08c3b5e51af584a2ed1d70f66ebd3dcfd1d9e42d2d5abd751aef8", 0o644),
    VENDOR[HELPER]: ("6fae02fbef586060085882325e43346d18889f5a73a3dfae407d2df95cf547bb", 0o644),
    BLUETOOTH: ("50621d3ee8c2fa6b9afb58d174c32dcdbc73d939ead0bd6ad1d84f36f34c263d", 0o644),
    **{path: ("abe954d0381202ad9f4388256575fa1a63f75814cf7b4c28a50708c624dbddfc", 0o644)
       for path in FIRSTBOOT.values()},
}
REQUEST_FIELDS = {"schema_version", "kind", "boot_id", "profile_sha256", "access_runtime_manifest_sha256"}
BOOL_FIELDS = {"permit_invalidated", "application_stop_acknowledged", "application_inactive",
               "application_masked", "helper_stop_acknowledged", "helper_inactive", "helper_masked",
               "bindings_unchanged", "poweroff_requested", "passed", "hardware_qualified", "release_qualified"}
STATUS_FIELDS = {"schema_version", "kind", "boot_id", "phase", "error", *BOOL_FIELDS}
PHASES = {"accepted", "waiting-activation", "stopping-application", "waiting-application", "stopping-helper", "waiting-helper",
          "ready-for-poweroff", "poweroff-requested", "blocked"}
ERRORS = {"invalid_arguments", "target_unverified", "binding_invalid", "request_invalid", "operation_busy",
          "existing_drain", "state_changed", "unsafe_unit", "permit_invalid", "stop_submission_unconfirmed",
          "unit_observation_unavailable", "unit_state_unexpected", "mask_unconfirmed", "status_write_failed",
          "poweroff_unconfirmed", "worker_submission_unconfirmed", "status_invalid", "drain_failed"}
STATE_PROPERTIES = {"ActiveState", "SubState", "MainPID", "ControlPID", "Job", "LoadState", "UnitFileState"}
SAFETY_PROPERTIES = {"FragmentPath", "DropInPaths", "Restart", "KillSignal", "KillMode", "TimeoutStopUSec", "SendSIGKILL"}
DRAIN_PROPERTIES = {"Restart": "no", "KillSignal": "15", "KillMode": "mixed",
                    "TimeoutStopUSec": "infinity", "SendSIGKILL": "no"}


class DrainError(ValueError):
    pass


def require(value, error):
    if value is not True:
        raise DrainError(error)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def valid_boot_id(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value) is not None


def status_projection(value):
    """Closed polling projection: no boot identity, paths, logs or application data."""
    require(type(value) is dict and set(value) == STATUS_FIELDS
            and type(value["schema_version"]) is int and value["schema_version"] == 1
            and value["kind"] == "test-access-drain-status" and valid_boot_id(value["boot_id"])
            and type(value["phase"]) is str and value["phase"] in PHASES
            and (value["error"] is None or type(value["error"]) is str and value["error"] in ERRORS)
            and all(type(value[name]) is bool for name in BOOL_FIELDS)
            and value["hardware_qualified"] is value["release_qualified"] is False
            and (value["error"] is not None) == (value["phase"] == "blocked")
            and value["passed"] == (value["phase"] == "poweroff-requested")
            and (not value["poweroff_requested"] or value["phase"] in {"poweroff-requested", "blocked"})
            and (not value["passed"] or (value["phase"] == "poweroff-requested"
                 and all(value[name] for name in BOOL_FIELDS - {"hardware_qualified", "release_qualified"}))),
            "binding_invalid")
    return {key: item for key, item in value.items() if key != "boot_id"}


def initial_status(boot_id):
    return {"schema_version": 1, "kind": "test-access-drain-status", "boot_id": boot_id,
            "phase": "accepted", "error": None, **dict.fromkeys(BOOL_FIELDS, False)}


def properties(raw, names):
    try:
        rows = [line.split("=", 1) for line in raw.decode("ascii").splitlines()]
        require(all(len(row) == 2 for row in rows) and len(rows) == len(names)
                and {row[0] for row in rows} == names, "unit_observation_unavailable")
        return dict(rows)
    except (UnicodeError, AttributeError):
        raise DrainError("unit_observation_unavailable") from None


def inactive(value):
    return (value["ActiveState"] == "inactive" and value["SubState"] == "dead"
            and value["MainPID"] == value["ControlPID"] == "0" and value["Job"] in {"", "0"})


def bootstrap():
    """Load only the pinned safe reader; no manifest-selected code is executed."""
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    source = None
    try:
        for part in LEGACY.strip("/").split("/")[:-1]:
            info = os.fstat(directory)
            require(info.st_uid == 0 and not info.st_mode & 0o022, "binding_invalid")
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.fstat(directory)
        require(info.st_uid == 0 and not info.st_mode & 0o022, "binding_invalid")
        name = LEGACY.rsplit("/", 1)[1]
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        before = os.fstat(source)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == 0o555 and 0 < before.st_size <= 65536, "binding_invalid")
        raw = os.read(source, 65537)
        def stamp(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        require(len(raw) == before.st_size and digest(raw) == LEGACY_SHA256
                and stamp(before) == stamp(os.fstat(source))
                == stamp(os.stat(name, dir_fd=directory, follow_symlinks=False)), "binding_invalid")
    finally:
        if source is not None:
            os.close(source)
        os.close(directory)
    namespace = {"__name__": "inkyos_drain_legacy", "__file__": LEGACY}
    exec(compile(raw, LEGACY, "exec"), namespace)
    return namespace


class NativeAdapter:
    def __init__(self):
        self.files = self.directory = self.operation = self.lock = self.activation = None
        self.sources, self.status_stamp = {}, None
        self.boot_id = None
        self.runtime_active = None

    def target(self):
        require(sys.platform.startswith("linux") and platform.machine() == "aarch64"
                and sys.byteorder == "little" and os.getuid() == os.geteuid() == 0, "target_unverified")
        self.lib = bootstrap()
        self.files = self.lib["Files"]()
        require(self.files.read(self.lib["MODEL_PATH"], limit=128) == self.lib["PI_MODEL"], "target_unverified")
        raw = self.files.read(BOOT_ID, limit=64)
        self.boot_id = raw.decode("ascii").removesuffix("\n")
        require(valid_boot_id(self.boot_id) and raw == (self.boot_id + "\n").encode(), "target_unverified")
        return True

    def _lock(self, name):
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=self.directory)
        try:
            self.lib["_metadata"](os.fstat(fd), self.files.owner, mode=0o600)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            require(self.lib["_stamp"](os.fstat(fd)) == self.lib["_stamp"](
                os.stat(name, dir_fd=self.directory, follow_symlinks=False)), "operation_busy")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def acquire(self):
        self.directory = self.files.directory(DIRECTORY, private=True)
        try:
            self.lock = self._lock("drain.lock")
        except BlockingIOError:
            raise DrainError("operation_busy") from None
        # The submitting runner still holds this short lock until systemctl's
        # asynchronous acknowledgement returns. Starting faster than that reply
        # must not make the already admitted worker fail spuriously.
        while self.operation is None:
            try:
                self.operation = self._lock("operation.lock")
            except BlockingIOError:
                self.wait()
        for name in (STATUS, "." + STATUS + ".tmp"):
            try:
                os.stat(name, dir_fd=self.directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise DrainError("existing_drain")
        return True

    def snapshot(self, path, mode, *, private=False):
        raw = self.files.read(path, limit=65536, mode=mode, private=private)
        self.sources[path] = (raw, mode, private)
        return raw

    def bind(self):
        for path, (expected, mode) in PINS.items():
            require(digest(self.snapshot(path, mode)) == expected, "binding_invalid")
        policy = {"__name__": "inkyos_drain_policy", "__file__": POLICY}
        exec(compile(self.sources[POLICY][0], POLICY, "exec"), policy)
        profile_raw = self.snapshot(PROFILE, 0o600, private=True)
        state_raw = self.snapshot(STATE, 0o600, private=True)
        require(policy["validate_enrolled_state"](state_raw, profile_raw), "binding_invalid")
        profile = policy["strict_json"](profile_raw)
        manifest_raw = self.snapshot(MANIFEST, 0o644)
        manifest = policy["strict_json"](manifest_raw)
        require(digest(manifest_raw) == profile["access_runtime_manifest_sha256"]
                and type(manifest) is dict and set(manifest) == {"schema_version", "kind", "application_source_commit",
                    "application_manifest_sha256", "parent_image_sha256", "files"}
                and type(manifest["schema_version"]) is int and manifest["schema_version"] == 1
                and manifest["kind"] == "test-access-runtime"
                and (manifest["application_source_commit"], manifest["application_manifest_sha256"], manifest["parent_image_sha256"])
                    == (policy["SOURCE"], policy["MANIFEST_HASH"], policy["PARENT_IMAGE_SHA256"])
                and type(manifest["files"]) is dict and 6 <= len(manifest["files"]) <= 64
                and manifest_raw == canonical(manifest), "binding_invalid")
        # Only these fixed paths are opened. Other manifest members cannot cause
        # a read of a host key, application data or an attacker-selected pathname.
        for path, mode in {SELF: 0o555, ACTIVATION: 0o555, LEGACY: 0o555, POLICY: 0o555,
                           SERVICE: 0o644, **{path: 0o644 for path in TEMPLATES.values()}}.items():
            raw = self.snapshot(path, mode)
            require(manifest["files"].get(path[1:]) == {"sha256": digest(raw), "mode": f"{mode:04o}"}, "binding_invalid")
        require(digest(self.snapshot(APPLICATION_MANIFEST, 0o444)) == policy["MANIFEST_HASH"], "binding_invalid")
        request_raw = self.snapshot(DIRECTORY + "/" + REQUEST, 0o600, private=True)
        request = policy["strict_json"](request_raw)
        require(type(request) is dict and set(request) == REQUEST_FIELDS
                and type(request["schema_version"]) is int and request["schema_version"] == 1
                and request["kind"] == "test-access-drain-request" and request["boot_id"] == self.boot_id
                and request["profile_sha256"] == digest(profile_raw)
                and request["access_runtime_manifest_sha256"] == digest(manifest_raw)
                and request_raw == canonical(request), "request_invalid")
        return True

    def unchanged(self):
        return (self.files.read(BOOT_ID, limit=64) == (self.boot_id + "\n").encode()
                and (self.runtime_active is not False or not self.runtime_present())
                and all(self.files.read(path, limit=65536, mode=mode, private=private) == raw
                        for path, (raw, mode, private) in self.sources.items()))

    def acquire_activation(self):
        try:
            self.activation = self._lock("activation.lock")
        except BlockingIOError:
            return False
        return True

    def runtime_present(self):
        present = []
        for unit, path in RUNTIME_DROPINS.items():
            try:
                directory = self.files.directory(path.rsplit("/", 1)[0])
            except FileNotFoundError:
                continue
            try:
                try:
                    os.stat(path.rsplit("/", 1)[1], dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                present.append(unit)
            finally:
                os.close(directory)
        return present

    def runtime_mode(self):
        present = self.runtime_present()
        require(len(present) in {0, 2}, "unsafe_unit")
        self.runtime_active = bool(present)
        if self.runtime_active:
            for unit in (APP, HELPER):
                require(self.snapshot(RUNTIME_DROPINS[unit], 0o644) == self.sources[TEMPLATES[unit]][0], "binding_invalid")
        else:
            # A never-started installation has no per-boot overrides. It is
            # admissible only with no process/job in either persistently masked
            # unit; this does not relax active display drain requirements.
            for unit in (APP, HELPER):
                value = self.observe(unit)
                require(inactive(value) and value["LoadState"] == value["UnitFileState"] == "masked", "unsafe_unit")
        return self.runtime_active

    def write_status(self, value):
        status_projection(value)
        self.lib["write_atomic"](self.directory, STATUS, canonical(value), owner=self.files.owner,
            replace_stamp=self.status_stamp, published=lambda stamp: setattr(self, "status_stamp", stamp))
        return True

    def invalidate_permit(self):
        try:
            info = os.stat(PERMIT, dir_fd=self.directory, follow_symlinks=False)
        except FileNotFoundError:
            return True
        self.lib["_metadata"](info, self.files.owner, mode=0o600)
        os.unlink(PERMIT, dir_fd=self.directory)
        os.fsync(self.directory)
        return True

    def permit_absent(self):
        try:
            os.stat(PERMIT, dir_fd=self.directory, follow_symlinks=False)
        except FileNotFoundError:
            return True
        return False

    def release_operation(self):
        if self.operation is not None:
            os.close(self.operation)
            self.operation = None
        return True

    def command(self, argv):
        return self.lib["command"](argv, timeout=5.0, limit=8192)

    def observe(self, unit, *, safety=False):
        require(unit in (APP, HELPER), "unsafe_unit")
        names = STATE_PROPERTIES | SAFETY_PROPERTIES if safety else STATE_PROPERTIES
        result = self.command(("/usr/bin/systemctl", "--no-pager", "--all", "show", unit,
                               "--property=" + ",".join(sorted(names))))
        require(result is not None and result[0] == 0, "unit_observation_unavailable")
        value = properties(result[1], names)
        require(value["MainPID"].isdigit() and value["ControlPID"].isdigit()
                and (value["Job"] == "" or value["Job"].isdigit()), "unit_observation_unavailable")
        if safety:
            require(value["LoadState"] == "loaded" and value["FragmentPath"] == VENDOR[unit]
                    and set(value["DropInPaths"].split()) == DROPINS[unit]
                    and value["Restart"] == "no", "unsafe_unit")
            require(all(value[name] == expected for name, expected in DRAIN_PROPERTIES.items()), "unsafe_unit")
        return value

    def stop_unit(self, unit):
        require(unit in (APP, HELPER), "unsafe_unit")
        result = self.command(("/usr/bin/systemctl", "--no-block", "stop", unit))
        return result is not None and result[0] == 0

    def mask_unit(self, unit):
        require(unit in (APP, HELPER), "unsafe_unit")
        # Only after inactive + PID zero + no job. No --force and no --now.
        result = self.command(("/usr/bin/systemctl", "mask", unit))
        return result is not None and result[0] == 0

    def wait(self):
        time.sleep(1.0)

    def poweroff(self):
        result = self.command(("/usr/bin/systemctl", "--no-block", "poweroff"))
        return result is not None and result[0] == 0

    def close(self):
        for name in ("operation", "activation", "lock", "directory"):
            fd = getattr(self, name)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)
        if self.files is not None:
            self.files.close()
            self.files = None


def drain(adapter):
    """Fixture adapter API; the CLI never accepts alternate paths or adapters."""
    result, can_write = None, False
    code = 1
    try:
        require(adapter.target() is True, "target_unverified")
        require(adapter.acquire() is True, "operation_busy")
        result = initial_status(adapter.boot_id)
        can_write = True
        require(adapter.bind() is True, "binding_invalid")

        def save(phase):
            result["phase"] = phase
            require(adapter.write_status(result) is True, "status_write_failed")

        save("accepted")
        require(adapter.unchanged() is True, "state_changed")
        require(adapter.invalidate_permit() is True, "permit_invalid")
        result["permit_invalidated"] = True
        save("waiting-activation")
        require(adapter.release_operation() is True, "operation_busy")
        # The activation worker may need operation.lock to notice our immutable
        # request and abandon admission. Never wait for its long lock while
        # holding operation.lock. Hold both long locks until this worker exits.
        while adapter.acquire_activation() is not True:
            require(adapter.unchanged() is True and adapter.permit_absent() is True, "state_changed")
            adapter.wait()
        active_mode = adapter.runtime_mode()
        require(type(active_mode) is bool, "unsafe_unit")
        require(adapter.unchanged() is True and adapter.permit_absent() is True, "state_changed")
        # This observation authenticates the *loaded* drain configuration before
        # SIGTERM. Do not mask/reload the running SPI owner's unit first.
        for unit in (APP, HELPER):
            value = adapter.observe(unit, safety=active_mode)
            require(active_mode or (inactive(value) and value["LoadState"] == value["UnitFileState"] == "masked"), "unsafe_unit")
        save("stopping-application")
        require(adapter.stop_unit(APP) is True, "stop_submission_unconfirmed")
        result["application_stop_acknowledged"] = True

        def await_inactive(unit, prefix, phase):
            save(phase)
            while True:
                require(adapter.unchanged() is True and adapter.permit_absent() is True, "state_changed")
                value = adapter.observe(unit, safety=active_mode)
                require(active_mode or (inactive(value) and value["LoadState"] == value["UnitFileState"] == "masked"), "unsafe_unit")
                if inactive(value):
                    result[prefix + "_inactive"] = True
                    return
                require(value["ActiveState"] in {"active", "activating", "deactivating", "reloading", "inactive"},
                        "unit_state_unexpected")
                # There is deliberately no elapsed-time limit or escalation.
                adapter.wait()

        await_inactive(APP, "application", "waiting-application")
        require(adapter.mask_unit(APP) is True, "mask_unconfirmed")
        value = adapter.observe(APP)
        require(inactive(value) and value["LoadState"] == value["UnitFileState"] == "masked", "mask_unconfirmed")
        result["application_masked"] = True
        require(adapter.unchanged() is True and adapter.permit_absent() is True, "state_changed")
        value = adapter.observe(HELPER, safety=active_mode)
        require(active_mode or (inactive(value) and value["LoadState"] == value["UnitFileState"] == "masked"), "unsafe_unit")
        save("stopping-helper")
        require(adapter.stop_unit(HELPER) is True, "stop_submission_unconfirmed")
        result["helper_stop_acknowledged"] = True
        await_inactive(HELPER, "helper", "waiting-helper")
        require(adapter.mask_unit(HELPER) is True, "mask_unconfirmed")
        for unit in (APP, HELPER):
            value = adapter.observe(unit)
            require(inactive(value) and value["LoadState"] == value["UnitFileState"] == "masked", "mask_unconfirmed")
        result["helper_masked"] = True
        require(adapter.unchanged() is True and adapter.permit_absent() is True, "state_changed")
        result["bindings_unchanged"] = True
        save("ready-for-poweroff")
        # Publishing a status includes fsync and may take time. Observe again
        # after that write, immediately before the irreversible poweroff request.
        for unit in (APP, HELPER):
            value = adapter.observe(unit)
            require(inactive(value) and value["LoadState"] == value["UnitFileState"] == "masked", "mask_unconfirmed")
        require(adapter.unchanged() is True and adapter.permit_absent() is True, "state_changed")
        require(adapter.poweroff() is True, "poweroff_unconfirmed")
        result["poweroff_requested"] = result["passed"] = True
        save("poweroff-requested")
        code = 0
    except Exception as error:
        reason = str(error) if type(error) is DrainError and str(error) in ERRORS else "drain_failed"
        if result is not None:
            # A successful poweroff request remains an acknowledgement even if
            # the following status write fails. Never misreport its cancellation.
            result.update(phase="blocked", passed=False, error=reason)
            if reason == "state_changed":
                result["bindings_unchanged"] = False
            if can_write:
                try:
                    adapter.write_status(result)
                except Exception:
                    pass
        else:
            result = {"schema_version": 1, "kind": "test-access-drain-refusal", "error": reason,
                      "poweroff_requested": False, "hardware_qualified": False, "release_qualified": False}
    finally:
        try:
            adapter.close()
        except Exception:
            code = 1
    return code, result


def _operator_context(operator):
    """Recheck the already authenticated runner's v2 binding under its short lock."""
    lib, files = operator.runtime, operator.files
    lib["_metadata"](os.fstat(operator.directory), files.owner, directory=True, mode=0o700)
    lib["_metadata"](os.fstat(operator.lock), files.owner, mode=0o600)
    require(lib["_stamp"](os.fstat(operator.lock)) == lib["_stamp"](
            os.stat("operation.lock", dir_fd=operator.directory, follow_symlinks=False)), "operation_busy")
    try:
        fcntl.flock(operator.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise DrainError("operation_busy") from None
    require(files.read(lib["MODEL_PATH"], limit=128) == lib["PI_MODEL"], "target_unverified")
    require(operator.unchanged() is True, "state_changed")
    raw_boot = files.read(BOOT_ID, limit=64)
    boot_id = raw_boot.decode("ascii").removesuffix("\n")
    require(valid_boot_id(boot_id) and raw_boot == (boot_id + "\n").encode(), "target_unverified")
    raw_policy = files.read(POLICY, mode=0o555, limit=65536)
    require(digest(raw_policy) == POLICY_SHA256, "binding_invalid")
    policy = {"__name__": "inkyos_drain_operator_policy", "__file__": POLICY}
    exec(compile(raw_policy, POLICY, "exec"), policy)
    raw_profile = files.read(PROFILE, mode=0o600, private=True, limit=65536)
    raw_state = files.read(STATE, mode=0o600, private=True, limit=65536)
    require(policy["validate_enrolled_state"](raw_state, raw_profile)
            and digest(raw_profile) == operator.config["profile_sha256"]
            and raw_profile == operator.snapshot[PROFILE][0] and raw_state == operator.snapshot[STATE][0], "binding_invalid")
    profile = policy["strict_json"](raw_profile)
    raw_manifest = files.read(MANIFEST, mode=0o644, limit=65536)
    require(profile == operator.profile and digest(raw_manifest) == profile["access_runtime_manifest_sha256"]
            and raw_manifest == operator.snapshot[MANIFEST][0], "binding_invalid")
    manifest = policy["strict_json"](raw_manifest)
    require(type(manifest) is dict and type(manifest.get("files")) is dict, "binding_invalid")
    for path, mode in ((SELF, 0o555), (SERVICE, 0o644), (POLICY, 0o555)):
        raw = files.read(path, mode=mode, limit=65536)
        require(manifest["files"].get(path[1:]) == {"sha256": digest(raw), "mode": f"{mode:04o}"}, "binding_invalid")
        if path in operator.snapshot:
            require(operator.snapshot[path] == (raw, mode, False), "state_changed")
        operator.snapshot[path] = (raw, mode, False)
    return {"schema_version": 1, "kind": "test-access-drain-request", "boot_id": boot_id,
            "profile_sha256": digest(raw_profile), "access_runtime_manifest_sha256": digest(raw_manifest)}


def _operator_request(operator, expected):
    try:
        raw = operator.files.read(DIRECTORY + "/" + REQUEST, mode=0o600, private=True, limit=4096)
    except FileNotFoundError:
        return False
    require(raw == canonical(expected), "request_invalid")
    operator.snapshot[DIRECTORY + "/" + REQUEST] = (raw, 0o600, True)
    return True


def _operator_status(operator, expected):
    try:
        raw = operator.files.read(DIRECTORY + "/" + STATUS, mode=0o600, private=True, limit=8192)
    except FileNotFoundError:
        return None
    try:
        value = operator.runtime["strict_json"](raw)
        projected = status_projection(value)
        require(value["boot_id"] == expected["boot_id"] and raw == canonical(value), "status_invalid")
    except Exception:
        raise DrainError("status_invalid") from None
    return projected


def _operator_unchanged(operator, expected):
    require(operator.unchanged() is True
            and operator.files.read(BOOT_ID, limit=64) == (expected["boot_id"] + "\n").encode(), "state_changed")


def enqueue(operator):
    """Called by the authenticated runner while it owns operation.lock.

    A duplicate request is observable but never resubmitted. Ambiguous command
    acknowledgement leaves the immutable request for review and blocks activation.
    This API does not release the caller's descriptors or wait for the drain.
    """
    report = {"schema_version": 1, "kind": "test-access-drain-enqueue", "passed": False,
              "status": "BLOCKED", "error": None, "request_present": False, "request_created": False,
              "job_acknowledged": False, "drain": None, "hardware_qualified": False, "release_qualified": False}
    try:
        expected = _operator_context(operator)
        if _operator_request(operator, expected):
            report["request_present"] = True
            report["drain"] = _operator_status(operator, expected)
            _operator_unchanged(operator, expected)
            report.update(passed=True, status="EXISTING")
            return 0, report
        require(_operator_status(operator, expected) is None, "existing_drain")
        raw = canonical(expected)
        def published(_stamp):
            report["request_present"] = report["request_created"] = True
        operator.runtime["write_atomic"](operator.directory, REQUEST, raw, owner=operator.files.owner, published=published)
        require(_operator_request(operator, expected), "request_invalid")
        _operator_unchanged(operator, expected)
        answer = operator.runtime["command"](("/usr/bin/systemctl", "--no-block", "start", SERVICE_NAME),
                                               timeout=3.0, limit=4096)
        require(answer is not None and answer[0] == 0, "worker_submission_unconfirmed")
        report["job_acknowledged"] = True
        _operator_unchanged(operator, expected)
        report.update(passed=True, status="QUEUED")
        return 0, report
    except Exception as error:
        report["error"] = str(error) if type(error) is DrainError and str(error) in ERRORS else "drain_failed"
        return 1, report


def status(operator):
    """Read a bounded observation while holding no activation/drain long lock."""
    report = {"schema_version": 1, "kind": "test-access-drain-observation", "passed": False,
              "status": "BLOCKED", "error": None, "request_present": False,
              "drain": None, "hardware_qualified": False, "release_qualified": False}
    try:
        expected = _operator_context(operator)
        report["request_present"] = _operator_request(operator, expected)
        report["drain"] = _operator_status(operator, expected)
        require(report["request_present"] or report["drain"] is None, "status_invalid")
        _operator_unchanged(operator, expected)
        report.update(passed=True, status="OBSERVED" if report["drain"] is not None
                      else "REQUESTED" if report["request_present"] else "ABSENT")
        return 0, report
    except Exception as error:
        report["error"] = str(error) if type(error) is DrainError and str(error) in ERRORS else "drain_failed"
        return 1, report


def main(argv=None):
    if sys.argv[1:] if argv is None else argv:
        return 64
    code, _result = drain(NativeAdapter())
    return code


if __name__ == "__main__":
    sys.exit(main())
