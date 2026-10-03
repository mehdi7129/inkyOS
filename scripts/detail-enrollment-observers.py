#!/usr/bin/python3 -I
"""One additional FAT diagnostic; no new activation, catalogue entry or setter."""
import sys
sys.dont_write_bytecode = True

import hashlib
import json
import os
import platform
import re
import stat
import struct


V1_PATH = "/boot/firmware/inkyos-observer-diag.py"
V1_SHA256 = "1a7e96e5ff9a307bc8ae967ddcb2021af79650088abfef5bcbd5450c0e9478ee"
REPORT = "inkyos-observer-detail.json"
CLAIM = ".inkyos-observer-detail.started"
KIND = "enrollment-observer-detail"
MAX_OUTPUT = 16384
KNOWN_FLAGS = {"no IR": "no_ir", "passive scan": "passive_scan",
               "no ibss": "no_ibss", "radar detection": "radar_detection"}


class DetailError(ValueError):
    pass


def compile_v1(raw):
    if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != V1_SHA256:
        raise DetailError("v1_pin_invalid")
    namespace = {"__name__": "inkyos_observer_detail_v1", "__file__": V1_PATH}
    exec(compile(raw, V1_PATH, "exec"), namespace)
    # Only diagnostic output names change in this private namespace. The v1
    # file and its service/state guards remain unchanged on disk.
    namespace.update(REPORT=REPORT, CLAIM=CLAIM)
    return namespace


def load_v1():
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    source = None
    try:
        for part in ("boot", "firmware"):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or part != "firmware" and info.st_mode & 0o022:
                raise DetailError("v1_pin_invalid")
        name = V1_PATH.rsplit("/", 1)[1]
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or not 0 < before.st_size <= 65536):
            raise DetailError("v1_pin_invalid")
        raw = bytearray()
        while len(raw) <= 65536:
            block = os.read(source, 65537 - len(raw))
            if not block:
                break
            raw.extend(block)
        stamp = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if (stamp(before) != stamp(os.fstat(source))
                or stamp(before) != stamp(os.stat(name, dir_fd=fd, follow_symlinks=False))):
            raise DetailError("v1_pin_invalid")
        return compile_v1(bytes(raw))
    finally:
        if source is not None:
            os.close(source)
        os.close(fd)


def ascii_lines(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_OUTPUT:
        return None
    try:
        return raw.decode("ascii").splitlines()
    except UnicodeError:
        return None


def regulatory_structure(raw, index):
    output = {"input_valid": False, "global_header_count": 0, "mapped_phy_header_count": 0,
              "other_phy_header_count": 0, "malformed_phy_header_count": 0,
              "country_without_section_count": 0, "duplicate_country_count": 0,
              "malformed_country_count": 0, "global_country": None,
              "mapped_phy_country": None, "mapped_phy_header_style": None}
    lines = ascii_lines(raw)
    if lines is None:
        return output
    output["input_valid"] = True
    current, countries = None, set()
    for line in lines:
        value = line.strip()
        if value == "global":
            output["global_header_count"] += 1
            current = "global"
        elif value.startswith("phy#"):
            matched = re.fullmatch(r"phy#(0|[1-9][0-9]{0,2})(?: \((custom|self-managed)\))?", value)
            if matched is None or int(matched[1]) > 255:
                output["malformed_phy_header_count"] += 1
                prefix = re.match(r"phy#([0-9]{1,3})(?:[^0-9]|$)", value)
                if prefix and int(prefix[1]) == index:
                    output["mapped_phy_header_style"] = "unrecognized"
                current = None
                continue
            mapped = int(matched[1]) == index
            output["mapped_phy_header_count" if mapped else "other_phy_header_count"] += 1
            current = "mapped" if mapped else ("other", int(matched[1]))
            if mapped:
                output["mapped_phy_header_style"] = matched[2] or "plain"
        elif value.startswith("country "):
            matched = re.fullmatch(r"country ([A-Z0-9]{2}):[ A-Z0-9-]*", value)
            if matched is None:
                output["malformed_country_count"] += 1
            if current is None:
                output["country_without_section_count"] += 1
            elif current in countries:
                output["duplicate_country_count"] += 1
            else:
                countries.add(current)
                if matched and current in {"global", "mapped"}:
                    output["global_country" if current == "global" else "mapped_phy_country"] = matched[1]
    return output


def channel_structure(raw, index):
    names = ("wiphy_header_count", "mapped_header_count", "rows_2_4ghz_count", "enabled_rows",
             "disabled_rows", "malformed_row_count", "noninteger_frequency_count",
             "duplicate_frequency_count", "channel_frequency_mismatch_count", "power_out_of_range_count",
             "disabled_with_flags_count", "unknown_flag_count", "duplicate_flag_count", "multiple_flag_groups_count")
    output = {"input_valid": False, **{name: 0 for name in names},
              "known_flag_counts": {name: 0 for name in KNOWN_FLAGS.values()}}
    lines = ascii_lines(raw)
    if lines is None:
        return output
    output["input_valid"] = True
    frequencies = set()
    for line in lines:
        if line.startswith("Wiphy "):
            output["wiphy_header_count"] += 1
            output["mapped_header_count"] += line == "Wiphy phy" + str(index)
        prefix = re.match(r"[ \t]*\* ([0-9.]+) MHz", line)
        if prefix is None:
            continue
        if len(prefix[1]) > 8 or not prefix[1].isdigit():
            output["noninteger_frequency_count"] += 1
            continue
        frequency = int(prefix[1])
        if not 2400 <= frequency <= 2500:
            continue
        output["rows_2_4ghz_count"] += 1
        if frequency in frequencies:
            output["duplicate_frequency_count"] += 1
        frequencies.add(frequency)
        row = re.fullmatch(r"[ \t]*\* ([0-9]+) MHz \[([0-9]+)\] \((disabled|[0-9]{1,2}\.[0-9] dBm)\)(.*)", line)
        if row is None:
            output["malformed_row_count"] += 1
            continue
        channel = int(row[2]) if len(row[2]) <= 3 else -1
        if not 1 <= channel <= 14 or frequency != (2484 if channel == 14 else 2407 + channel * 5):
            output["channel_frequency_mismatch_count"] += 1
        disabled = row[3] == "disabled"
        output["disabled_rows" if disabled else "enabled_rows"] += 1
        if not disabled:
            integer, decimal = row[3].split(" ", 1)[0].split(".")
            if int(integer) * 100 + int(decimal) * 10 > 4000:
                output["power_out_of_range_count"] += 1
        groups = re.findall(r"\(([^()]*)\)", row[4])
        if row[4] != "" and re.fullmatch(r"(?: \([^()]*\))+", row[4]) is None:
            output["malformed_row_count"] += 1
        if len(groups) > 1:
            output["multiple_flag_groups_count"] += 1
        flags = [flag for group in groups for flag in group.split(", ") if flag]
        output["duplicate_flag_count"] += len(flags) - len(set(flags))
        if disabled and flags:
            output["disabled_with_flags_count"] += 1
        for flag in flags:
            if flag in KNOWN_FLAGS:
                output["known_flag_counts"][KNOWN_FLAGS[flag]] += 1
            else:
                output["unknown_flag_count"] += 1
    return output


def panel_detail(panel, reader=None):
    output = {"error": None, "data": None}
    try:
        raw = (reader or (lambda: panel["bounded_sample"](panel["LinuxI2C"]().sample)))()
        if type(raw) is not bytes or len(raw) != 29:
            raise DetailError("eeprom_invalid")
        width, height = struct.unpack_from("<HH", raw)
        color, variant = raw[4], raw[6]
        output["data"] = {"width": width, "height": height, "color_code": color,
                          "display_variant": variant,
                          "reviewed_catalogue_match": (width, height, color, variant) in panel["CATALOGUE"]}
        if not output["data"]["reviewed_catalogue_match"]:
            output["error"] = "eeprom_unreviewed"
    except Exception as error:
        allowed = {"eeprom_invalid", "eeprom_unreviewed", "eeprom_timeout", "eeprom_unavailable"}
        output["error"] = str(error) if str(error) in allowed else "observation_unavailable"
    return output


def radio_detail(radio, sample=None):
    output = {"sample_error": None, "firmware": {"error": None, "data": None},
              "regulatory": {"error": None, "data": None, "structure": None},
              "channels": {"error": None, "data": None, "structure": None},
              "firmware_tuple_qualified": False}
    try:
        values = (sample or radio["ProductionAdapter"]().sample)()
        if (type(values) is not dict or set(values) != {"wiphy_index", "firmware", "regulatory", "channels"}
                or any(type(values[key]) is not bytes or not 0 < len(values[key]) <= MAX_OUTPUT
                       for key in ("firmware", "regulatory", "channels"))):
            raise DetailError("observation_unavailable")
        index = values["wiphy_index"]
        if type(index) is not int or not 0 <= index <= 255:
            raise DetailError("wlan0_mapping_unverified")
    except Exception as error:
        output["sample_error"] = str(error) if str(error) in {"wlan0_mapping_unverified", "linux_root_required"} else "observation_unavailable"
        return output
    for kind, field, parser in (("firmware", "firmware", "parse_country"),
                                ("regulatory", "regulatory", "parse_regulatory"),
                                ("channels", "channels", "parse_channels")):
        try:
            output[kind]["data"] = radio[parser](values[field], *(() if kind == "firmware" else (index,)))
        except Exception as error:
            allowed = {"firmware_response_invalid", "kernel_observation_invalid"}
            output[kind]["error"] = str(error) if str(error) in allowed else "observation_unavailable"
        if kind != "firmware":
            output[kind]["structure"] = (regulatory_structure if kind == "regulatory" else channel_structure)(values.get(field), index)
    return output


def decorate(result):
    result["kind"] = KIND
    result["v1_source_sha256"] = V1_SHA256
    result["limits"] = ["EEPROM integers are unsigned declarations, not a catalogue extension or driver qualification.",
        "Radio parsers run independently; one failed parser does not discard other validated fields.",
        "Structural summaries contain only fixed counters, reviewed flags and country labels; raw output is omitted.",
        "The unchanged ProductionAdapter sample is all-or-error if any read-only query is unavailable.",
        "Completed means diagnostic traversal, including blocked observations; no activation or qualification follows.",
        "A systemctl client timeout does not attest cancellation of its firstboot job; systemd handles poweroff."]
    return result


def attach_details(v1, adapter):
    original_report = adapter.report
    def probes():
        panel = {"__name__": "inkyos_observer_detail_panel", "__file__": v1["PANEL"]}
        exec(compile(adapter.sources[v1["PANEL"]], v1["PANEL"], "exec"), panel)
        # Keep the installed per-observer gates as well as all v1 outer gates.
        facts = adapter.radio["PreparedGuard"]().collect()
        guards = {key: facts.get(key) is True for key in v1["GUARD_CHECKS"]}
        if not all(guards.values()):
            return {"guards": guards, "panel": {"error": "guards_blocked", "data": None},
                    "radio": {"sample_error": "guards_blocked", "firmware_tuple_qualified": False}}
        return {"guards": guards, "panel": panel_detail(panel), "radio": radio_detail(adapter.radio)}
    adapter.probes = probes
    adapter.report = lambda result: original_report(decorate(result))
    return adapter


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args or not sys.platform.startswith("linux") or os.geteuid() != 0 or platform.machine() != "aarch64":
        result = {"schema_version": 1, "kind": KIND, "completed": False,
                  "error": "invalid_arguments" if args else "target_unverified",
                  "activation_authorized": False, "hardware_qualified": False, "release_qualified": False}
    else:
        try:
            v1 = load_v1()
            adapter = attach_details(v1, v1["NativeAdapter"]())
            result = decorate(v1["diagnose"](adapter))
        except Exception:
            result = {"schema_version": 1, "kind": KIND, "completed": False, "error": "detail_unavailable",
                      "activation_authorized": False, "hardware_qualified": False, "release_qualified": False}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result.get("completed") and result.get("report_written") else 1


if __name__ == "__main__":
    sys.exit(main())
