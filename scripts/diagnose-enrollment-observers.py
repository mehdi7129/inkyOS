#!/usr/bin/python3 -I
"""One-shot FAT diagnostic of the pinned observers on an already enrolled Pi.

No arguments, network setters, key generation, activation or cmdline cleanup.
systemd.run_success_action/run_failure_action must arrange poweroff externally.
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
RUNTIME = BASE + "test-enrollment-firstboot.py"
FIRSTBOOT = BASE + "firstboot.py"
UNIT = "/etc/systemd/system/inkyos-firstboot.service"
HELPER = BASE + "test-lan-preflight.py"
PANEL = BASE + "observe-test-panel.py"
RADIO = BASE + "observe-test-radio.py"
PINS = {
    RUNTIME: "081bac2c04d4e72a6e74a365664b72941fa4d1e84d1ccc32cf0dc25d9e8a337a",
    FIRSTBOOT: "a76a68c1554b279dbf8a95e690a9179e8769def4c3d361f1d5bdeb630a585a35",
    UNIT: "a707eadd71f2a1dd57d3e83e2bcfd868485660b94391d645435ef3e105555ab6",
    HELPER: "fdf5a12b7b2c13dce3456531816d634e5bb235e37fdeff8d2efd4edcdb45209b",
    PANEL: "6fc6b93e30beeb6c03a3867efeb88cfe30ed7e1fe58f2ea6e5c35db9a4c29164",
    RADIO: "8423207c905abbfb6f7fd4e75125e11f794b063034fee4e9a8346cf449391315",
}
REPORT = "inkyos-observer-diag.json"
CLAIM = ".inkyos-observer-diag.started"
SYSTEM_STATE = "/var/lib/inkyos/system.json"
MASKED = ("inky-studio.service", "inky-network.service", "ssh.service", "ssh.socket",
          "sshswitch.service", "regenerate_ssh_host_keys.service", "sshd-keygen.service",
          "inkyos-test-enrollment.service")
GUARD_CHECKS = ("prepared_profile", "exact_payload_pin", "firstboot_success",
                "app_stopped_and_masked", "helper_stopped_and_masked")
RADIO_CHECKS = GUARD_CHECKS + ("wlan0_driver_and_wiphy_verified", "firmware_response_valid",
    "firmware_country_matches", "kernel_global_country_matches", "kernel_2_4ghz_limits_observed",
    "firmware_tuple_qualified")
CHECKS = ("target_verified", "fresh_diagnostic", "sources_pinned", "existing_enrollment",
          "existing_firstboot_identity", "inactive_guards_before", "firstboot_started",
          "firstboot_success", "inactive_guards_after", "state_unchanged")
ERRORS = {"target_unverified", "source_pin_invalid", "existing_diagnostic", "boot_mount_unverified",
          "enrollment_invalid", "firstboot_identity_invalid", "inactive_guards_blocked",
          "firstboot_start_failed", "firstboot_guard_blocked", "state_changed", "runtime_timeout",
          "diagnostic_unavailable", "report_unavailable", "invalid_arguments"}
COMMON_FIELDS = {"schema_version", "kind", "scope", "live_selected", "observation_source",
                 "live_evidence", "checks", "passed", "status", "activation_authorized",
                 "hardware_qualified", "release_qualified", "error", "limitations"}
PROBE_ERRORS = {
    "panel": {None, "eeprom_invalid", "eeprom_unreviewed", "eeprom_timeout", "eeprom_unavailable",
              "observation_unavailable", "linux_root_required", "invalid_arguments"},
    "radio": {None, "firmware_response_invalid", "kernel_observation_invalid",
              "wlan0_mapping_unverified", "linux_root_required", "observation_unavailable",
              "invalid_arguments"},
}


class DiagnosticError(ValueError):
    pass


def load_runtime():
    """Bootstrap only the pinned root-owned runtime, before using its safe Files API."""
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    source_fd = None
    try:
        for part in RUNTIME.strip("/").split("/")[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise DiagnosticError("source_pin_invalid")
        source_fd = os.open(RUNTIME.rsplit("/", 1)[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                            dir_fd=fd)
        before = os.fstat(source_fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o555 or not 0 < before.st_size <= 65536):
            raise DiagnosticError("source_pin_invalid")
        raw = bytearray()
        while len(raw) <= 65536:
            block = os.read(source_fd, 65537 - len(raw))
            if not block:
                break
            raw.extend(block)
        stamp = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        after = os.fstat(source_fd)
        current = os.stat(RUNTIME.rsplit("/", 1)[1], dir_fd=fd, follow_symlinks=False)
        if (stamp(before) != stamp(after) or stamp(after) != stamp(current)
                or hashlib.sha256(raw).hexdigest() != PINS[RUNTIME]):
            raise DiagnosticError("source_pin_invalid")
        namespace = {"__name__": "inkyos_diagnostic_runtime", "__file__": RUNTIME}
        exec(compile(bytes(raw), RUNTIME, "exec"), namespace)
        return namespace
    finally:
        if source_fd is not None:
            os.close(source_fd)
        os.close(fd)


def valid_enrollment(runtime, profile_raw, state_raw):
    try:
        profile = runtime["strict_json"](profile_raw)
        state = runtime["strict_json"](state_raw)
        return (runtime["validate_profile"](profile) and profile_raw == runtime["canonical"](profile)
            and type(state) is dict and set(state) == {"schema_version", "kind", "state",
                "profile_sha256", "application_activation_authorized"}
            and type(state["schema_version"]) is int and state["schema_version"] == 1
            and state["kind"] == "test-lan-enrollment-state" and state["state"] == "enrolled"
            and state["profile_sha256"] == hashlib.sha256(profile_raw).hexdigest()
            and state["application_activation_authorized"] is False)
    except Exception:
        return False


def valid_identity(runtime, raw):
    try:
        value = runtime["strict_json"](raw)
        return (type(value) is dict and set(value) == {"version", "hostname"}
                and type(value["version"]) is int and value["version"] == 1
                and type(value["hostname"]) is str
                and re.fullmatch(r"inky-[0-9a-f]{32}", value["hostname"]) is not None)
    except Exception:
        return False


def valid_wifi_state(raw):
    try:
        lines = [line for line in raw.decode("ascii").splitlines() if line]
        if not lines or lines.pop(0) != "[main]":
            return False
        values = {}
        for line in lines:
            key, separator, value = line.partition("=")
            if (separator != "=" or key in values
                    or key not in {"NetworkingEnabled", "WirelessEnabled", "WWANEnabled"}
                    or value not in {"true", "false"}):
                return False
            values[key] = value
        return values.get("WirelessEnabled") == "false"
    except (AttributeError, UnicodeError):
        return False


def projected_probe(runtime, kind, result):
    """Export only closed checks/errors and already reviewed successful data."""
    output = {"outcome": "timeout_or_unavailable", "exit_code": None, "status": None,
              "error": None, "live_selected": False, "observation_source": None,
              "live_evidence": False, "observations_complete": False, "checks": None,
              "observation": {"status": "blocked", "live_evidence": False, "data": None}}
    if result is None:
        return output
    if (type(result) is not tuple or len(result) != 2 or type(result[0]) is not int
            or result[0] not in {0, 1, 2} or type(result[1]) is not bytes):
        output["outcome"] = "invalid_result"
        return output
    output.update(outcome="invalid_output", exit_code=result[0])
    try:
        value = runtime["strict_json"](result[1])
        extra = {"panel"} if kind == "panel" else {"observations_complete", "firmware_tuple_qualified",
            "firmware", "kernel", "channels_2_4ghz", "source_reference"}
        names = GUARD_CHECKS if kind == "panel" else RADIO_CHECKS
        if (type(value) is not dict or set(value) != COMMON_FIELDS | extra
                or type(value["schema_version"]) is not int or value["schema_version"] != 1
                or value["kind"] != "test-" + kind + "-observation"
                or value["live_selected"] is not True or value["observation_source"] != "live-system"
                or type(value["live_evidence"]) is not bool or type(value["passed"]) is not bool
                or value["status"] != ("PASS" if value["passed"] else "BLOCKED")
                or any(value[key] is not False for key in ("activation_authorized", "hardware_qualified", "release_qualified"))
                or value["error"] not in PROBE_ERRORS[kind]
                or type(value["checks"]) is not dict or set(value["checks"]) != set(names)):
            return output
        checks = {}
        for name in names:
            row = value["checks"][name]
            if (type(row) is not dict or set(row) != {"passed", "status"}
                    or type(row["passed"]) is not bool
                    or row["status"] != ("PASS" if row["passed"] else "BLOCKED")):
                return output
            checks[name] = dict(row)
        observation = runtime["reduced_observation"](value, kind)
        if kind == "panel":
            if result[0] != (0 if value["passed"] else 1) or value["passed"] and observation["status"] != "observed":
                return output
            complete = value["passed"]
        else:
            if (result[0] != 1 or value["passed"] is not False or value["firmware_tuple_qualified"] is not False
                    or type(value["observations_complete"]) is not bool
                    or value["observations_complete"] and observation["status"] != "observed-unqualified"):
                return output
            complete = value["observations_complete"]
        output.update(outcome="reported", status=value["status"], error=value["error"],
                      live_selected=True, observation_source="live-system", live_evidence=value["live_evidence"],
                      observations_complete=complete, checks=checks, observation=observation)
    except Exception:
        pass
    return output


class NativeAdapter:
    def __init__(self):
        self.runtime = load_runtime()
        self.files = self.runtime["Files"]()
        self.boot = None
        self.deadline = time.monotonic() + 90

    def environment(self):
        return (sys.platform.startswith("linux") and os.geteuid() == 0 and platform.machine() == "aarch64"
                and sys.byteorder == "little"
                and self.files.read(self.runtime["MODEL_PATH"], limit=128) == self.runtime["PI_MODEL"])

    def fresh(self):
        self.boot = self.files.directory("/boot/firmware", fat=True)
        for name in (REPORT, "." + REPORT + ".tmp", CLAIM, "." + CLAIM + ".tmp"):
            try:
                os.stat(name, dir_fd=self.boot, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise DiagnosticError("existing_diagnostic")
        pid = os.getpid()
        if not self.runtime["mount_is_fat"](self.files.read(f"/proc/{pid}/mountinfo", limit=1024**2),
                self.files.read(f"/proc/{pid}/fdinfo/{self.boot}"), os.fstat(self.boot).st_dev):
            raise DiagnosticError("boot_mount_unverified")
        self.runtime["write_atomic"](self.boot, CLAIM,
            self.runtime["canonical"]({"schema_version": 1, "kind": "observer-diagnostic-started"}), fat=True)

    def pin_sources(self):
        sources = {}
        for path, digest in PINS.items():
            raw = self.files.read(path, limit=65536, mode=None if path in {FIRSTBOOT, UNIT} else 0o555)
            if hashlib.sha256(raw).hexdigest() != digest:
                raise DiagnosticError("source_pin_invalid")
            sources[path] = raw
        self.sources = sources
        self.helpers = {"__name__": "inkyos_diagnostic_helpers", "__file__": HELPER}
        exec(compile(sources[HELPER], HELPER, "exec"), self.helpers)
        self.radio = {"__name__": "inkyos_diagnostic_radio", "__file__": RADIO}
        exec(compile(sources[RADIO], RADIO, "exec"), self.radio)

    def enrollment(self):
        try:
            self.profile_raw = self.files.read(self.runtime["PROFILE_PATH"], mode=0o600, private=True)
            self.state_raw = self.files.read(self.runtime["STATE_PATH"], mode=0o600, private=True)
            return valid_enrollment(self.runtime, self.profile_raw, self.state_raw)
        except Exception:
            return False

    def identity(self):
        try:
            self.identity_raw = self.files.read(SYSTEM_STATE, mode=0o600, private=True)
            return valid_identity(self.runtime, self.identity_raw)
        except Exception:
            return False

    def run(self, argv, timeout, limit=32768):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise DiagnosticError("runtime_timeout")
        return self.runtime["command"](argv, timeout=min(timeout, remaining), limit=limit)

    def properties(self, unit, wanted):
        result = self.run(("/usr/bin/systemctl", "--no-pager", "show", unit,
                           "--property=" + ",".join(wanted)), 2)
        if result is None or result[0] != 0:
            return None
        return self.helpers["_properties"](result[1].decode("ascii"), set(wanted))

    def inactive_guards(self):
        marker = self.runtime["strict_json"](self.files.read(self.runtime["MARKER_PATH"], mode=0o644))
        if (marker.get("source_commit") != self.runtime["SOURCE"]
                or marker.get("manifest_sha256") != self.runtime["MANIFEST_HASH"]):
            return False
        facts = self.radio["PreparedGuard"]().collect()
        if any(facts.get(key) is not True for key in GUARD_CHECKS if key != "firstboot_success"):
            return False
        for unit in MASKED:
            wanted = {"ActiveState": "inactive", "SubState": "dead", "LoadState": "masked", "UnitFileState": "masked"}
            observed = self.properties(unit, wanted)
            if unit == "inkyos-test-enrollment.service" and observed is not None and observed.get("UnitFileState") == "masked-runtime":
                observed["UnitFileState"] = "masked"
            if observed != wanted:
                return False
        if self.properties("NetworkManager.service", ("ActiveState", "SubState")) != {"ActiveState": "inactive", "SubState": "dead"}:
            return False
        if not valid_wifi_state(self.files.read("/var/lib/NetworkManager/NetworkManager.state", mode=0o600)):
            return False
        for path in ("/etc/NetworkManager/system-connections", "/run/NetworkManager/system-connections"):
            try:
                fd = self.files.directory(path)
            except FileNotFoundError:
                continue
            try:
                with os.scandir(fd) as entries:
                    if next(entries, None) is not None:
                        return False
            finally:
                os.close(fd)
        return True

    def start_firstboot(self):
        wanted = {"LoadState": "loaded", "FragmentPath": UNIT, "DropInPaths": ""}
        if self.properties("inkyos-firstboot.service", wanted) != wanted:
            return False
        return self.run(("/usr/bin/systemctl", "start", "inkyos-firstboot.service"), 12) == (0, b"")

    def firstboot_success(self):
        wanted = {"ActiveState": "active", "SubState": "exited", "LoadState": "loaded",
                  "Result": "success", "ExecMainStatus": "0"}
        return self.properties("inkyos-firstboot.service", wanted) == wanted

    def wait_devices(self):
        deadline = min(self.deadline, time.monotonic() + 8)
        while True:
            try:
                info = os.stat("/dev/i2c-1", follow_symlinks=False)
                i2c = stat.S_ISCHR(info.st_mode) and os.major(info.st_rdev) == 89 and os.minor(info.st_rdev) == 1
            except FileNotFoundError:
                i2c = False
            wlan = os.path.exists("/sys/class/net/wlan0")
            if i2c and wlan or time.monotonic() >= deadline:
                return {"i2c1_present": i2c, "wlan0_present": wlan}
            time.sleep(0.25)

    def probes(self):
        return {kind: projected_probe(self.runtime, kind, self.run(argv, timeout))
                for kind, argv, timeout in (
                    ("panel", ("/usr/bin/python3", "-I", PANEL, "--live"), 15),
                    ("radio", ("/usr/bin/python3", "-I", RADIO, "--live", "--country", "FR"), 20))}

    def unchanged(self):
        return (self.identity_raw == self.files.read(SYSTEM_STATE, mode=0o600, private=True)
                and self.profile_raw == self.files.read(self.runtime["PROFILE_PATH"], mode=0o600, private=True)
                and self.state_raw == self.files.read(self.runtime["STATE_PATH"], mode=0o600, private=True)
                and all(raw == self.files.read(path, limit=65536) for path, raw in self.sources.items()))

    def report(self, result):
        self.runtime["write_atomic"](self.boot, REPORT, self.runtime["canonical"](result), fat=True)

    def close(self):
        if self.boot is not None:
            os.close(self.boot)
        self.files.close()


def diagnose(adapter=None):
    result = {"schema_version": 1, "kind": "enrollment-observer-diagnostic", "completed": False,
              "live_evidence": False, "checks": {key: False for key in CHECKS},
              "devices": None, "probes": None, "error": None, "report_written": False,
              "activation_authorized": False, "hardware_qualified": False, "release_qualified": False,
              "limits": ["Probe fields are a closed projection, not complete raw output.",
                         "Partial radio data is omitted; null data does not mean no firmware response.",
                         "Timeout and unavailable output are not distinguished by the pinned runner.",
                         "A systemctl client timeout does not attest cancellation of its firstboot job.",
                         "Completed means the diagnostic finished, including blocked or invalid probes.",
                         "Systemd handles poweroff; this report does not attest shutdown."]}
    eligible = False
    try:
        if adapter is None or adapter.environment() is not True:
            raise DiagnosticError("target_unverified")
        result["checks"]["target_verified"] = True
        result["live_evidence"] = type(adapter) is NativeAdapter
        adapter.fresh()
        eligible = True
        result["checks"]["fresh_diagnostic"] = True
        adapter.pin_sources()
        result["checks"]["sources_pinned"] = True
        for operation, key, error in (
            (adapter.enrollment, "existing_enrollment", "enrollment_invalid"),
            (adapter.identity, "existing_firstboot_identity", "firstboot_identity_invalid"),
            (adapter.inactive_guards, "inactive_guards_before", "inactive_guards_blocked"),
            (adapter.start_firstboot, "firstboot_started", "firstboot_start_failed"),
            (adapter.firstboot_success, "firstboot_success", "firstboot_guard_blocked")):
            if operation() is not True:
                raise DiagnosticError(error)
            result["checks"][key] = True
        # firstboot must have reconciled the existing identity, never replaced it.
        if adapter.unchanged() is not True:
            raise DiagnosticError("state_changed")
        result["devices"] = adapter.wait_devices()
        result["probes"] = adapter.probes()
        if adapter.inactive_guards() is not True:
            raise DiagnosticError("inactive_guards_blocked")
        result["checks"]["inactive_guards_after"] = True
        if adapter.unchanged() is not True:
            raise DiagnosticError("state_changed")
        result["checks"]["state_unchanged"] = True
        result["completed"] = True
    except Exception as error:
        result["error"] = str(error) if type(error) is DiagnosticError and str(error) in ERRORS else "diagnostic_unavailable"
    finally:
        if eligible:
            try:
                result["report_written"] = True
                adapter.report(result)
            except Exception:
                result.update(completed=False, report_written=False, error="report_unavailable")
        if adapter is not None:
            adapter.close()
    return result


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args:
        result = diagnose()
        result["error"] = "invalid_arguments"
    elif not sys.platform.startswith("linux") or os.geteuid() != 0 or platform.machine() != "aarch64":
        result = diagnose()
    else:
        try:
            adapter = NativeAdapter()
        except Exception:
            result = diagnose()
            result["error"] = "source_pin_invalid"
        else:
            result = diagnose(adapter)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["completed"] and result["report_written"] else 1


if __name__ == "__main__":
    sys.exit(main())
