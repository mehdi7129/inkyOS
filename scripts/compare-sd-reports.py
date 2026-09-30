#!/usr/bin/env python3
"""Compare two local SD diagnostic v1 reports without exporting identities.

The reports are untrusted snapshots. This read-only comparison does not attest
their origin or qualify the image, hardware, application or release.
"""

import argparse
import errno
import hashlib
import json
import math
import os
import re
import stat
import sys


MAX_REPORT_BYTES = 128 * 1024
HASH = re.compile(r"[0-9a-f]{64}\Z")
MODES = ("same-card", "different-cards")
TOP_KEYS = {"schema_version", "boot_id_sha256", "hardware", "identity", "filesystems", "services"}
IDENTITY_KEYS = {"machine_id", "hostname", "kernel_hostname", "firstboot_state", "coherence", "hosts_file"}
IDENTITY_ERRORS = {"missing", "invalid", "too_large", "unsafe_path", "read_error"}
SERVICE_ERRORS = {"missing", "invalid", "too_large", "timeout", "command_error"}
COHERENCE_KEYS = {"state_matches_hostname", "state_matches_kernel", "state_matches_hosts"}
SERVICE_VALUES = {
    "ActiveState": {"active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance", "refreshing"},
    "SubState": {"running", "exited", "dead", "failed", "start-pre", "start", "start-post", "auto-restart", "auto-restart-queued", "stop", "stop-sigterm", "stop-sigkill", "stop-post", "final-sigterm", "final-sigkill", "cleaning", "condition", "waiting", "listening", "reload", "reload-signal", "reload-notify"},
    "Result": {"", "success", "resources", "protocol", "timeout", "exit-code", "signal", "core-dump", "watchdog", "start-limit-hit", "exec-condition", "oom-kill", "skipped"},
    "LoadState": {"loaded", "error", "not-found", "bad-setting", "masked", "stub", "merged"},
    "UnitFileState": {"", "enabled", "enabled-runtime", "linked", "linked-runtime", "alias", "masked", "masked-runtime", "static", "disabled", "indirect", "generated", "transient", "bad"},
}
LIMITATIONS = (
    "Unsigned local snapshots are not attestations; their origin is unverified.",
    "Image provenance and artifact verification require separate evidence.",
    "Distinct boot identifiers do not prove an observed reboot or separate physical cards.",
    "Identity comparison does not qualify complete boot, hardware, services, application or release.",
)


class InputError(ValueError):
    """Fixed error codes only; never store paths, values or nested exceptions."""


class SafeParser(argparse.ArgumentParser):
    def error(self, _message):
        raise InputError("invalid_arguments")


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_nlink)


def _regular(info):
    return stat.S_ISREG(info.st_mode) and info.st_nlink == 1


def _unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise InputError("invalid_json")
        value[key] = item
    return value


def _nonfinite(_value):
    raise InputError("invalid_json")


def _finite_float(value):
    parsed = float(value)
    if not math.isfinite(parsed):
        raise InputError("invalid_json")
    return parsed


def read_report(path):
    """Open before inspecting metadata; never follow a final symlink or FIFO."""
    fd = None
    try:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except (OSError, ValueError, TypeError) as exc:
            code = "unsafe_input" if isinstance(exc, OSError) and exc.errno in {errno.ELOOP, errno.ENXIO} else "input_unavailable"
            raise InputError(code) from None
        initial = os.fstat(fd)
        if not _regular(initial):
            raise InputError("unsafe_input")
        if not 0 <= initial.st_size <= MAX_REPORT_BYTES:
            raise InputError("input_too_large")
        content = bytearray()
        while len(content) <= MAX_REPORT_BYTES:
            chunk = os.read(fd, min(65536, MAX_REPORT_BYTES + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        final = os.fstat(fd)
        try:
            current = os.stat(path, follow_symlinks=False)
        except OSError:
            raise InputError("input_changed") from None
        if (_signature(initial) != _signature(final) or _signature(final) != _signature(current)
                or not _regular(final) or not _regular(current) or len(content) != final.st_size):
            raise InputError("input_changed")
        if len(content) > MAX_REPORT_BYTES:
            raise InputError("input_too_large")
        artifact_hash = hashlib.sha256(content).hexdigest()
        try:
            report = json.loads(content.decode("utf-8"), object_pairs_hook=_unique_pairs,
                                parse_constant=_nonfinite, parse_float=_finite_float)
        except (UnicodeError, ValueError, RecursionError):
            raise InputError("invalid_json") from None
        validate_report(report)
        return report, artifact_hash
    except OSError:
        raise InputError("input_unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)


def _object(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise InputError("invalid_schema")


def _hash(value):
    if type(value) is not str or not HASH.fullmatch(value):
        raise InputError("invalid_schema")


def _metric(value, ok_keys, errors):
    if type(value) is not dict or type(value.get("status")) is not str:
        raise InputError("invalid_schema")
    if value["status"] == "ok":
        _object(value, {"status", *ok_keys})
        return True
    if value["status"] not in errors:
        raise InputError("invalid_schema")
    _object(value, {"status"})
    return False


def validate_report(report):
    """Strict v1 envelope and fields used by this identity-only comparison.

    Hardware/filesystem metrics and unrelated units remain outside this tool's
    qualification scope, and their container types are checked only.
    """
    _object(report, TOP_KEYS)
    if type(report["schema_version"]) is not int or report["schema_version"] != 1:
        raise InputError("invalid_schema")
    _hash(report["boot_id_sha256"])
    for field in ("hardware", "filesystems", "services"):
        if type(report[field]) is not dict:
            raise InputError("invalid_schema")
    identity = report["identity"]
    _object(identity, IDENTITY_KEYS)
    for field in ("machine_id", "hostname", "kernel_hostname"):
        if _metric(identity[field], {"sha256"}, IDENTITY_ERRORS):
            _hash(identity[field]["sha256"])
    state = identity["firstboot_state"]
    if _metric(state, {"version", "hostname_sha256"}, IDENTITY_ERRORS):
        if type(state["version"]) is not int or state["version"] != 1:
            raise InputError("invalid_schema")
        _hash(state["hostname_sha256"])
    if _metric(identity["coherence"], COHERENCE_KEYS, {"unavailable"}):
        if any(type(identity["coherence"][key]) is not bool for key in COHERENCE_KEYS):
            raise InputError("invalid_schema")
    _metric(identity["hosts_file"], set(), IDENTITY_ERRORS)
    firstboot = report["services"].get("inkyos-firstboot.service")
    if _metric(firstboot, {*SERVICE_VALUES, "ExecMainStatus"}, SERVICE_ERRORS):
        for key, allowed in SERVICE_VALUES.items():
            if type(firstboot[key]) is not str or firstboot[key] not in allowed:
                raise InputError("invalid_schema")
        if type(firstboot["ExecMainStatus"]) is not int or not 0 <= firstboot["ExecMainStatus"] <= 255:
            raise InputError("invalid_schema")


def _identity_checks(report):
    identity = report["identity"]
    values = {}
    for field in ("machine_id", "hostname", "kernel_hostname"):
        metric = identity[field]
        values[field] = metric["sha256"] if metric["status"] == "ok" else None
    state = identity["firstboot_state"]
    values["state_hostname"] = state["hostname_sha256"] if state["status"] == "ok" else None
    ready = all(value is not None for value in values.values())
    coherent_hashes = ready and values["state_hostname"] == values["hostname"] == values["kernel_hostname"]
    coherence = identity["coherence"]
    hosts_ok = identity["hosts_file"]["status"] == "ok"
    assertions_consistent = (
        ready and hosts_ok and coherence["status"] == "ok"
        and coherence["state_matches_hostname"] == (values["state_hostname"] == values["hostname"])
        and coherence["state_matches_kernel"] == (values["state_hostname"] == values["kernel_hostname"])
    )
    reported_coherent = coherence["status"] == "ok" and all(coherence[key] for key in COHERENCE_KEYS)
    service = report["services"]["inkyos-firstboot.service"]
    firstboot_ok = (
        service["status"] == "ok" and service["LoadState"] == "loaded"
        and service["ActiveState"] == "active" and service["SubState"] == "exited"
        and service["Result"] == "success" and service["ExecMainStatus"] == 0
    )
    return values, {"identity_ready": ready, "hashes_coherent": coherent_hashes,
                    "coherence_assertions_consistent": assertions_consistent,
                    "reported_coherent": reported_coherent, "hosts_readable": hosts_ok,
                    "firstboot_success": firstboot_ok}


def _result(mode):
    return {"schema_version": 1, "mode": mode, "input_artifact_sha256": [None, None], "checks": {},
            "comparisons": {}, "passed": False, "error": None,
            "hardware_qualified": False, "release_qualified": False,
            "scope": "identity_comparison_only", "limitations": list(LIMITATIONS)}


def compare_reports(mode, left, right, artifact_hashes):
    """Inputs are parsed snapshots, not proof of card possession or a reboot."""
    if mode not in MODES:
        raise InputError("invalid_arguments")
    validate_report(left)
    validate_report(right)
    if type(artifact_hashes) not in {tuple, list} or len(artifact_hashes) != 2:
        raise InputError("invalid_schema")
    for value in artifact_hashes:
        _hash(value)
    left_values, left_checks = _identity_checks(left)
    right_values, right_checks = _identity_checks(right)
    output = _result(mode)
    output["input_artifact_sha256"] = list(artifact_hashes)
    output["checks"] = {"distinct_boots": left["boot_id_sha256"] != right["boot_id_sha256"]}
    for prefix, checks in (("left", left_checks), ("right", right_checks)):
        output["checks"].update({prefix + "_" + key: value for key, value in checks.items()})
    for field in ("machine_id", "hostname", "kernel_hostname", "state_hostname"):
        output["comparisons"][field + "_equal"] = (
            left_values[field] is not None and right_values[field] is not None
            and left_values[field] == right_values[field]
        )
    expected_equal = mode == "same-card"
    output["checks"]["expected_machine_id_relationship"] = (
        left_checks["identity_ready"] and right_checks["identity_ready"]
        and output["comparisons"]["machine_id_equal"] == expected_equal
    )
    output["checks"]["expected_hostname_relationship"] = (
        left_checks["identity_ready"] and right_checks["identity_ready"]
        and output["comparisons"]["hostname_equal"] == expected_equal
    )
    output["passed"] = all(output["checks"].values())
    return output


def main(argv=None):
    output = _result(None)
    parser = SafeParser(prog="compare-sd-reports.py", description=__doc__, allow_abbrev=False)
    parser.add_argument("--mode", choices=MODES, required=True)
    parser.add_argument("left_report")
    parser.add_argument("right_report")
    try:
        arguments = parser.parse_args(argv)
        output["mode"] = arguments.mode
        left, left_hash = read_report(arguments.left_report)
        output["input_artifact_sha256"][0] = left_hash
        right, right_hash = read_report(arguments.right_report)
        output["input_artifact_sha256"][1] = right_hash
        output = compare_reports(arguments.mode, left, right, (left_hash, right_hash))
        code = 0 if output["passed"] else 1
    except InputError as exc:
        output["error"] = str(exc)
        code = 2
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    sys.exit(main())
