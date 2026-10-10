#!/usr/bin/python3 -I
"""Authenticated TEST operator with manifest-bound asynchronous lifecycle.

Only the API accepts fixture adapters. The production CLI has zero arguments.
Neither a command-client timeout nor a poweroff acknowledgement proves shutdown.
"""
import sys
sys.dont_write_bytecode = True

import fcntl
import hashlib
import json
import os
import platform
import re
import select
import stat
import time


CONFIG = "/etc/inkyos-test-operator.json"
DISPATCH = "/usr/local/lib/inkyos-test-ssh/dispatch.py"
RUNNER = "/usr/local/lib/inkyos-test-ssh/runner"
ENROLLMENT = "/usr/local/lib/inkyos/test-enrollment-firstboot.py"
ENROLLMENT_SHA256 = "081bac2c04d4e72a6e74a365664b72941fa4d1e84d1ccc32cf0dc25d9e8a337a"
PREFLIGHT = "/usr/local/lib/inkyos/test-lan-preflight.py"
PREFLIGHT_SHA256 = "9cda15bfeaef8ed5bc7c0a2d0b71f470a1411d13dda4e2043f800e9ca37e5fba"
ACCESS_POLICY = "/usr/local/lib/inkyos/test-access-policy.py"
ACCESS_POLICY_SHA256 = "7d3676fde6434235be4d66592da41996c5973aed5b1f226c0fd78462ffb355a9"
ACCESS_MANIFEST = "/usr/local/share/inkyos/test-access-manifest.json"
LIFECYCLE_PATHS = {
    **{"/usr/local/lib/inkyos/test-access-" + name + ".py": 0o555
       for name in ("activation", "activation-gate", "drain")},
    **{"/usr/lib/systemd/system/inkyos-test-" + name + ".service": 0o644
       for name in ("activate", "drain")},
    **{"/usr/local/share/inkyos/test-access/" + name + ".conf": 0o644
       for name in ("inky-studio", "inky-network")},
}
PROFILE = "/etc/inkyos-test-enrollment/profile.json"
STATE = "/var/lib/inkyos-test-enrollment/state.json"
SYSTEM = "/var/lib/inkyos/system.json"
HOST_PUBLIC = "/etc/inkyos-test-enrollment/ssh_host_ed25519_key.pub"
LOCK_DIRECTORY = "/run/inkyos-test-operator"
PERMIT = "activation-permit.json"
UNITS = ("inky-studio.service", "inky-network.service")
CONFIG_FIELDS = {"schema_version", "kind", "operator_uid", "operator_gid", "country_confirmed",
    "profile_sha256", "state_sha256", "system_identity_sha256", "host_public_key_sha256",
    "preflight_sha256", "enrollment_source_sha256", "dispatcher_sha256", "runner_sha256"}
LIMIT = 4096
STOP_BUDGET = 24.0
ERRORS = {"invalid_request", "target_unverified", "caller_unverified", "binding_invalid", "operation_busy",
          "preflight_unavailable", "preflight_blocked", "activation_unavailable", "stop_incomplete", "state_changed",
          "stop_requires_inactive_runtime"}
ERRORS |= {"lifecycle_unavailable", "lifecycle_failed"}
PREFLIGHT_CHECKS = (
    "prepared_profile", "exact_payload_pin", "operator_access_confirmed", "firstboot_success",
    "app_stopped_and_masked", "helper_stopped_and_masked", "networkmanager_manages_connected_wlan0",
    "country_operator_confirmed", "country_global_matches", "country_phy_matches", "utc_synchronized",
    "independent_reference_recent", "utc_matches_independent_reference", "bluez_running", "hci0_powered",
    "bluetooth_unblocked", "system_packages_present", "application_hardware_metadata_present",
    "service_accounts_and_groups", "spi_i2c_gpio_nodes", "application_state_virgin", "helper_state_virgin",
    "panel_inventory_supplied_and_valid", "panel_runtime_evidence_verified")


class Refused(ValueError):
    pass


def require(value, reason="binding_invalid"):
    if not value:
        raise Refused(reason)


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "invalid_request")
            value[key] = item
        return value
    def invalid(_):
        raise Refused("invalid_request")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    except (ValueError, UnicodeError, AttributeError, RecursionError):
        raise Refused("invalid_request") from None


def parse_envelope(raw):
    require(type(raw) is bytes and 0 < len(raw) <= LIMIT, "invalid_request")
    value = strict_json(raw)
    require(type(value) is dict and set(value) == {"schema_version", "operation", "request"}
            and type(value["schema_version"]) is int and value["schema_version"] == 1
            and type(value["operation"]) is str and value["operation"] in {"preflight", "activate", "stop", "status"}, "invalid_request")
    request = value["request"]
    base, utc = {"schema_version"}, {"utc_reference", "utc_reference_age", "utc_reference_source"}
    allowed = ([base, base | utc] if value["operation"] == "preflight" else
               [base, base | utc | {"confirm_test_refresh"}] if value["operation"] == "activate" else [base])
    require(type(request) is dict and set(request) in allowed
            and ("confirm_test_refresh" not in request or request["confirm_test_refresh"] is True)
            and type(request.get("schema_version")) is int and request["schema_version"] == 1, "invalid_request")
    if utc <= set(request):
        require(type(request["utc_reference"]) is int and 1767225600 <= request["utc_reference"] <= 2524608000
                and type(request["utc_reference_age"]) is int and 0 <= request["utc_reference_age"] <= 60
                and type(request["utc_reference_source"]) is str
                and request["utc_reference_source"] in {"independent-device", "gnss"}, "invalid_request")
    return value


def receive(fd, *, clock=time.monotonic, wait=select.select, read=os.read):
    deadline, raw = clock() + 5.0, bytearray()
    while True:
        remaining = deadline - clock()
        require(remaining > 0 and bool(wait([fd], [], [], remaining)[0]), "invalid_request")
        block = read(fd, min(1024, LIMIT + 1 - len(raw)))
        if not block:
            return bytes(raw)
        raw.extend(block)
        require(len(raw) <= LIMIT, "invalid_request")


def bootstrap():
    """Load one reviewed safe reader before interpreting the trusted marker."""
    fd, source = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW), None
    try:
        for part in ENROLLMENT.strip("/").split("/")[:-1]:
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022)
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        require(info.st_uid == 0 and not info.st_mode & 0o022)
        name = ENROLLMENT.rsplit("/", 1)[1]
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        before = os.fstat(source)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == 0o555 and 0 < before.st_size <= 65536)
        raw = bytearray()
        while len(raw) <= 65536:
            chunk = os.read(source, min(4096, 65537 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        stamp = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
        require(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(source))
                == stamp(os.stat(name, dir_fd=fd, follow_symlinks=False))
                and hashlib.sha256(raw).hexdigest() == ENROLLMENT_SHA256)
        namespace = {"__name__": "inkyos_operator_enrollment", "__file__": ENROLLMENT}
        exec(compile(bytes(raw), ENROLLMENT, "exec"), namespace)
        return namespace
    finally:
        if source is not None:
            os.close(source)
        os.close(fd)


def valid_config(value):
    return (type(value) is dict and set(value) == CONFIG_FIELDS
        and type(value["schema_version"]) is int and value["schema_version"] == 1
        and value["kind"] == "test-operator-runtime" and type(value["country_confirmed"]) is bool
        and all(type(value[k]) is int and 0 < value[k] < 2**32 - 1 for k in ("operator_uid", "operator_gid"))
        and all(type(value[k]) is str and re.fullmatch(r"[0-9a-f]{64}", value[k]) is not None
                for k in CONFIG_FIELDS if k.endswith("_sha256"))
        and value["preflight_sha256"] == PREFLIGHT_SHA256
        and value["enrollment_source_sha256"] == ENROLLMENT_SHA256)


class NativeAdapter:
    def __init__(self):
        self.files = self.runtime = self.directory = self.lock = None
        self.snapshot = {}

    def authenticate(self):
        require(sys.platform.startswith("linux") and platform.machine() == "aarch64"
                and sys.byteorder == "little" and os.getuid() == os.geteuid() == 0, "target_unverified")
        self.runtime = bootstrap()
        self.files = self.runtime["Files"]()
        self.config_raw = self.files.read(CONFIG, mode=0o600)
        self.config = strict_json(self.config_raw)
        require(valid_config(self.config))
        rows = [row.split(":") for row in self.files.read("/etc/passwd", limit=262144).decode("utf-8").splitlines()]
        require(all(len(row) == 7 for row in rows), "caller_unverified")
        selected = [row for row in rows if row[0] == "inky-test"]
        uid, gid = str(self.config["operator_uid"]), str(self.config["operator_gid"])
        require(len(selected) == 1 and selected[0][2:4] == [uid, gid]
                and sum(row[2] == uid for row in rows) == 1
                and os.environ.get("SUDO_USER") == "inky-test"
                and os.environ.get("SUDO_UID") == uid and os.environ.get("SUDO_GID") == gid, "caller_unverified")
        return True

    def _bind_v2_profile(self):
        """Extend bindings for c31 without changing legacy files or config schema."""
        policy_raw = self.files.read(ACCESS_POLICY, limit=65536, mode=0o555)
        require(hashlib.sha256(policy_raw).hexdigest() == ACCESS_POLICY_SHA256)
        manifest_raw = self.files.read(ACCESS_MANIFEST, limit=65536, mode=0o644)
        require(self.profile.get("access_runtime_manifest_sha256") == hashlib.sha256(manifest_raw).hexdigest())
        self.snapshot[ACCESS_POLICY] = (policy_raw, 0o555, False)
        self.snapshot[ACCESS_MANIFEST] = (manifest_raw, 0o644, False)
        policy = {"__name__": "inkyos_operator_access_policy", "__file__": ACCESS_POLICY}
        exec(compile(policy_raw, ACCESS_POLICY, "exec"), policy)
        require(policy["validate_enrolled_state"](self.snapshot[STATE][0], self.snapshot[PROFILE][0]))
        manifest = self.runtime["strict_json"](manifest_raw)
        require(type(manifest) is dict and set(manifest) == {"schema_version", "kind", "application_source_commit",
                "application_manifest_sha256", "parent_image_sha256", "files"}
                and type(manifest["schema_version"]) is int and manifest["schema_version"] == 1
                and manifest["kind"] == "test-access-runtime"
                and (manifest["application_source_commit"], manifest["application_manifest_sha256"], manifest["parent_image_sha256"])
                    == (policy["SOURCE"], policy["MANIFEST_HASH"], policy["PARENT_IMAGE_SHA256"])
                and type(manifest["files"]) is dict and 5 <= len(manifest["files"]) <= 40
                and manifest_raw == self.runtime["canonical"](manifest))
        for path, item in manifest["files"].items():
            require(type(path) is str and 0 < len(path) <= 256
                    and re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", path) is not None
                    and all(part not in {".", ".."} for part in path.split("/"))
                    and type(item) is dict and set(item) == {"sha256", "mode"}
                    and type(item["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None
                    and type(item["mode"]) is str and item["mode"] in {"0555", "0644", "0440"})
        # Other manifest entries are metadata only here, never caller-selected
        # paths to open. The importer verifies the complete access installation.
        for path in (ACCESS_POLICY, ENROLLMENT, PREFLIGHT, DISPATCH, RUNNER):
            require(manifest["files"].get(path[1:]) == {
                "sha256": hashlib.sha256(self.snapshot[path][0]).hexdigest(), "mode": "0555"})
        return True

    def bind(self):
        specs = {PROFILE: ("profile_sha256", 0o600, True), STATE: ("state_sha256", 0o600, True),
            SYSTEM: ("system_identity_sha256", 0o600, True), HOST_PUBLIC: ("host_public_key_sha256", 0o644, True),
            PREFLIGHT: ("preflight_sha256", 0o555, False), ENROLLMENT: ("enrollment_source_sha256", 0o555, False),
            DISPATCH: ("dispatcher_sha256", 0o555, False), RUNNER: ("runner_sha256", 0o555, False)}
        for path, (key, mode, private) in specs.items():
            data = self.files.read(path, limit=65536, mode=mode, private=private)
            require(hashlib.sha256(data).hexdigest() == self.config[key])
            self.snapshot[path] = (data, mode, private)
        self.snapshot[CONFIG] = (self.config_raw, 0o600, False)
        self.profile = self.runtime["strict_json"](self.snapshot[PROFILE][0])
        state = self.runtime["strict_json"](self.snapshot[STATE][0])
        identity = self.runtime["strict_json"](self.snapshot[SYSTEM][0])
        profile_valid = (self._bind_v2_profile() if type(self.profile) is dict
                         and type(self.profile.get("schema_version")) is int and self.profile["schema_version"] == 2
                         else self.runtime["validate_profile"](self.profile))
        require(profile_valid
                and self.snapshot[PROFILE][0] == self.runtime["canonical"](self.profile)
                and type(state) is dict and set(state) == {"schema_version", "kind", "state", "profile_sha256", "application_activation_authorized"}
                and type(state["schema_version"]) is int and state["schema_version"] == 1
                and state["kind"] == "test-lan-enrollment-state" and state["state"] == "enrolled"
                and state["profile_sha256"] == self.config["profile_sha256"] and state["application_activation_authorized"] is False
                and type(identity) is dict and set(identity) == {"version", "hostname"}
                and type(identity["version"]) is int and identity["version"] == 1
                and type(identity["hostname"]) is str and re.fullmatch(r"inky-[0-9a-f]{32}", identity["hostname"]) is not None)
        match = re.fullmatch(rb"(ssh-ed25519 [A-Za-z0-9+/]{68}) inkyos-test-host\n", self.snapshot[HOST_PUBLIC][0])
        require(match is not None and self.runtime["public_key"](match[1].decode("ascii")) is not None)
        self.preflight_module = {"__name__": "inkyos_operator_preflight", "__file__": PREFLIGHT}
        exec(compile(self.snapshot[PREFLIGHT][0], PREFLIGHT, "exec"), self.preflight_module)
        return True

    def acquire(self):
        parent = self.files.directory("/run")
        try:
            try:
                os.mkdir("inkyos-test-operator", 0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                pass
        finally:
            os.close(parent)
        self.directory = self.files.directory(LOCK_DIRECTORY, private=True)
        self.lock = os.open("operation.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                            0o600, dir_fd=self.directory)
        self.runtime["_metadata"](os.fstat(self.lock), mode=0o600)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused("operation_busy") from None
        return True

    def unchanged(self):
        return all(data == self.files.read(path, limit=65536, mode=mode, private=private)
                   for path, (data, mode, private) in self.snapshot.items())

    def preflight(self, request):
        ns = self.preflight_module
        return ns["preflight"](ns["LiveAdapter"](), live=True, operator_access_confirmed=True,
            country=self.profile["country_requested"], country_confirmed=self.config["country_confirmed"],
            panel_inventory="/" + ns["PANEL_INVENTORY"],
            **{k: request[k] for k in ("utc_reference", "utc_reference_age", "utc_reference_source") if k in request})

    def lifecycle_available(self):
        if self.profile["schema_version"] != 2:
            return False
        manifest = self.runtime["strict_json"](self.snapshot[ACCESS_MANIFEST][0])
        present = {path for path in LIFECYCLE_PATHS if path[1:] in manifest["files"]}
        if not present:
            return False  # The previous v2 access-only image remains verifiable.
        require(present == set(LIFECYCLE_PATHS))
        for path, mode in LIFECYCLE_PATHS.items():
            raw = self.files.read(path, mode=mode, limit=65536)
            require(manifest["files"][path[1:]] == {"sha256": hashlib.sha256(raw).hexdigest(),
                    "mode": f"{mode:04o}"})
            self.snapshot[path] = (raw, mode, False)
        return True

    def lifecycle(self, operation, request):
        def load(name):
            path = "/usr/local/lib/inkyos/test-access-" + name + ".py"
            require(path in self.snapshot and self.unchanged() is True, "state_changed")
            namespace = {"__name__": "inkyos_operator_" + name, "__file__": path}
            exec(compile(self.snapshot[path][0], path, "exec"), namespace)
            return namespace
        if operation == "activate":
            return load("activation")["enqueue"](request, self)
        if operation == "stop":
            return load("drain")["enqueue"](self)
        require(operation == "status", "invalid_request")
        activation_code, activation = load("activation")["status"](self)
        drain_code, drain = load("drain")["status"](self)
        require(type(activation_code) is int and activation_code in {0, 1}
                and type(drain_code) is int and drain_code in {0, 1}, "lifecycle_failed")
        return (0 if activation_code == drain_code == 0 else 1), {
            "schema_version": 1, "kind": "test-access-lifecycle-status",
            "activation": activation, "drain": drain,
            "hardware_qualified": False, "release_qualified": False}

    def stop_ready(self):
        # An active refresh cannot safely use the current service stop timeout.
        # Include these observations in the single budget for this operation.
        self.stop_deadline = time.monotonic() + STOP_BUDGET
        return all(self.verify_unit(unit) is True for unit in UNITS)

    def invalidate_permit(self):
        try:
            info = os.stat(PERMIT, dir_fd=self.directory, follow_symlinks=False)
        except FileNotFoundError:
            return True
        self.runtime["_metadata"](info, mode=0o600)
        os.unlink(PERMIT, dir_fd=self.directory)
        os.fsync(self.directory)
        return True

    def command(self, argv, timeout, *, poweroff=False):
        remaining = self.stop_deadline - time.monotonic() - (0 if poweroff else 3.0)
        if remaining <= 0:
            return None
        return self.runtime["command"](argv, timeout=min(timeout, remaining), limit=4096)

    def stop_unit(self, unit):
        return self.command(("/usr/bin/systemctl", "stop", unit), 3) == (0, b"")

    def mask_unit(self, unit):
        # No --force: never replace an unknown administrator unit file.
        result = self.command(("/usr/bin/systemctl", "mask", unit), 2)
        return result is not None and result[0] == 0

    def verify_unit(self, unit):
        result = self.command(("/usr/bin/systemctl", "--no-pager", "show", unit,
            "--property=ActiveState,SubState,LoadState,UnitFileState,MainPID,ControlPID,Job"), 2)
        if result is None or result[0] != 0:
            return False
        value = self.preflight_module["_properties"](result[1].decode("ascii"),
                    {"ActiveState", "SubState", "LoadState", "UnitFileState", "MainPID", "ControlPID", "Job"})
        return (type(value) is dict and value.get("Job") in {"", "0"} and {k: v for k, v in value.items() if k != "Job"} == {
            "ActiveState": "inactive", "SubState": "dead", "LoadState": "masked", "UnitFileState": "masked",
            "MainPID": "0", "ControlPID": "0"})

    def poweroff(self):
        return self.command(("/usr/bin/systemctl", "--no-block", "poweroff"), 3, poweroff=True) == (0, b"")

    def close(self):
        for descriptor in (self.lock, self.directory):
            if descriptor is not None:
                os.close(descriptor)
        if self.files is not None:
            self.files.close()


def preflight_projection(value, live):
    fields = {"schema_version", "kind", "live_selected", "scope", "checks", "passed", "activation_authorized",
              "live_evidence", "observation_source", "hardware_qualified", "release_qualified", "limitations", "error"}
    require(type(value) is dict and set(value) == fields and type(value["schema_version"]) is int
            and value["schema_version"] == 1 and value["kind"] == "test-lan-preflight"
            and value["scope"] == "test_lan_preconditions_only" and value["live_selected"] is True
            and type(value["passed"]) is bool and type(value["live_evidence"]) is bool
            and value["observation_source"] in {"fixture", "live-system"}
            and all(value[k] is False for k in ("activation_authorized", "hardware_qualified", "release_qualified"))
            and value["error"] in {None, "observations_unavailable"}
            and type(value["checks"]) is dict and set(value["checks"]) == set(PREFLIGHT_CHECKS), "preflight_unavailable")
    checks = {}
    reasons = {"precondition_unverified", "panel_runtime_observation_pending", "existing_or_unsafe_state_requires_explicit_review"}
    for name, row in value["checks"].items():
        require(type(row) is dict and set(row) == {"passed", "status", "reason"}
                and type(row["passed"]) is bool and row["status"] == ("PASS" if row["passed"] else "BLOCKED")
                and (row["reason"] is None if row["passed"] else row["reason"] in reasons), "preflight_unavailable")
        checks[name] = dict(row)
    require(value["passed"] == all(row["passed"] for row in checks.values()), "preflight_unavailable")
    # Do not forward producer prose, arbitrary fields or fixture provenance.
    return {"kind": "test-lan-preflight", "passed": value["passed"], "error": value["error"],
            "checks": checks, "live_evidence": live and value["live_evidence"],
            "observation_source": "live-system" if live and value["live_evidence"] else "fixture"}


def operate(envelope, adapter):
    result = {"schema_version": 1, "kind": "test-operator-result", "operation": None,
        "passed": False, "status": "BLOCKED", "error": None, "live_evidence": False,
        "preflight": None, "stop": None, "activation": None, "lifecycle_status": None, "activation_authorized": False,
        "hardware_qualified": False, "release_qualified": False,
        "limits": ["Lifecycle admission is not application readiness, refresh completion or physical shutdown.",
            "Activation requires an explicit refresh request and manifest-bound lifecycle workers; older images refuse it.",
            "Legacy stop requires inactive masked services; lifecycle stop queues a separate unbounded drain worker.",
            "Command client timeouts do not attest cancellation of systemd jobs.",
            "Poweroff acknowledgement does not attest shutdown or delivery of this reply.",
            "The runtime lock and permit are coordination artifacts; no key or application data is removed."]}
    code = 64
    try:
        envelope = parse_envelope(json.dumps(envelope, separators=(",", ":")).encode())
        result["operation"] = envelope["operation"]
        require(adapter is not None and adapter.authenticate() is True, "caller_unverified")
        require(adapter.bind() is True)
        require(adapter.acquire() is True, "operation_busy")
        require(adapter.unchanged() is True, "state_changed")
        result["live_evidence"] = type(adapter) is NativeAdapter
        verb = envelope["operation"]
        code = 1
        lifecycle = (verb in {"activate", "stop", "status"}
                     and getattr(adapter, "lifecycle_available", lambda: False)() is True)
        if lifecycle and (verb != "activate" or envelope["request"].get("confirm_test_refresh") is True):
            lifecycle_code, payload = adapter.lifecycle(verb, envelope["request"])
            require(type(lifecycle_code) is int and lifecycle_code in {0, 1}
                    and type(payload) is dict and type(payload.get("schema_version")) is int and payload["schema_version"] == 1
                    and payload.get("kind") == {"activate": "test-access-activation-result",
                        "stop": "test-access-drain-enqueue", "status": "test-access-lifecycle-status"}[verb]
                    and payload.get("hardware_qualified") is False and payload.get("release_qualified") is False
                    and len(json.dumps(payload).encode()) <= 16384, "lifecycle_failed")
            require(adapter.unchanged() is True, "state_changed")
            result[{"activate": "activation", "stop": "stop", "status": "lifecycle_status"}[verb]] = payload
            result["passed"] = lifecycle_code == 0
            result["error"] = None if result["passed"] else "lifecycle_failed"
        elif verb == "activate":
            result["error"] = "activation_unavailable"
        elif verb == "status":
            result["error"] = "lifecycle_unavailable"
        elif verb == "preflight":
            result["preflight"] = preflight_projection(adapter.preflight(envelope["request"]), result["live_evidence"])
            require(adapter.unchanged() is True, "state_changed")
            result["passed"] = result["preflight"]["passed"]
            result["error"] = None if result["passed"] else "preflight_blocked"
        else:
            try:
                ready = adapter.stop_ready() is True
            except Exception:
                ready = False
            require(ready, "stop_requires_inactive_runtime")
            stopped = {"permit_invalidated": False, "units": {unit: {"stop_acknowledged": False,
                "mask_acknowledged": False, "inactive_and_persistently_masked": False} for unit in UNITS},
                "bindings_unchanged": False, "poweroff_requested": False}
            result["stop"] = stopped
            def attempt(call):
                try:
                    return call() is True
                except Exception:
                    return False
            stopped["permit_invalidated"] = attempt(adapter.invalidate_permit)
            for name, action in (("stop_acknowledged", adapter.stop_unit), ("mask_acknowledged", adapter.mask_unit),
                                 ("inactive_and_persistently_masked", adapter.verify_unit)):
                for unit in UNITS:
                    stopped["units"][unit][name] = attempt(lambda unit=unit, action=action: action(unit))
            stopped["bindings_unchanged"] = attempt(adapter.unchanged)
            safe = (stopped["permit_invalidated"] and stopped["bindings_unchanged"]
                    and all(all(row.values()) for row in stopped["units"].values()))
            stopped["poweroff_requested"] = safe and attempt(adapter.poweroff)
            result["passed"] = (stopped["permit_invalidated"] and stopped["bindings_unchanged"]
                and stopped["poweroff_requested"] and all(all(row.values()) for row in stopped["units"].values()))
            result["error"] = None if result["passed"] else "stop_incomplete"
        if result["passed"]:
            result["status"], code = "PASS", 0
    except Exception as error:
        result["error"] = str(error) if type(error) is Refused and str(error) in ERRORS else "binding_invalid"
    finally:
        if adapter is not None:
            try:
                adapter.close()
            except Exception:
                result.update(passed=False, status="BLOCKED", error="binding_invalid")
                code = 64
    return code, result


def main(argv=None):
    try:
        require(not (sys.argv[1:] if argv is None else argv), "invalid_request")
        envelope = parse_envelope(receive(0))
    except Exception:
        code, result = operate(None, None)
    else:
        code, result = operate(envelope, NativeAdapter())
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    sys.exit(main())
