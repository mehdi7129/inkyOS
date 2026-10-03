#!/usr/bin/python3 -I
"""Compare two pinned parsers on one historical-adapter sample; no setters."""
import sys
sys.dont_write_bytecode = True

import hashlib
import json
import os
import platform
import stat


V2_PATH = "/boot/firmware/inkyos-observer-detail.py"
V2_SHA256 = "33421c00f8368ef92e09141b10f28ec33c3392afbba9e53bf6bf776c3e858512"
# Explicit 8.3 name: the previous Mac-written long-name entry was recovered
# as FSCK0000.000 on the bench. Do not rely on its generated short-name alias.
SELF_PATH = "/boot/firmware/INKYCMP.PY"
PARSER_PATH = "/boot/firmware/inkyos-radio-parser.py"
PARSER_SHA256 = "8423207c905abbfb6f7fd4e75125e11f794b063034fee4e9a8346cf449391315"
REPORT = "inkyos-radio-compare.json"
CLAIM = ".inkyos-radio-compare.started"
KIND = "enrollment-radio-compare"
MAX_SOURCE = 65536


class ComparisonError(ValueError):
    pass


def read_pinned(path, digest):
    """Read a stable root-owned FAT source through no-follow parent descriptors."""
    if not path.startswith("/boot/firmware/") or "/" in path[len("/boot/firmware/"):]:
        raise ComparisonError("source_pin_invalid")
    if digest is None and path != SELF_PATH:
        raise ComparisonError("source_pin_invalid")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    source = None
    try:
        for part in ("boot", "firmware"):
            info = os.fstat(directory)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ComparisonError("source_pin_invalid")
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        if os.fstat(directory).st_uid != 0:
            raise ComparisonError("source_pin_invalid")
        name = path.rsplit("/", 1)[1]
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or not 0 < before.st_size <= MAX_SOURCE):
            raise ComparisonError("source_pin_invalid")
        raw = bytearray()
        while len(raw) <= MAX_SOURCE:
            block = os.read(source, MAX_SOURCE + 1 - len(raw))
            if not block:
                break
            raw.extend(block)
        stamp = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
                             item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if (len(raw) != before.st_size or stamp(before) != stamp(os.fstat(source))
                or stamp(before) != stamp(os.stat(name, dir_fd=directory, follow_symlinks=False))
                or digest is not None and hashlib.sha256(raw).hexdigest() != digest):
            raise ComparisonError("source_pin_invalid")
        return bytes(raw)
    finally:
        if source is not None:
            os.close(source)
        os.close(directory)


def compile_pinned(raw, path, digest):
    if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != digest:
        raise ComparisonError("source_pin_invalid")
    namespace = {"__name__": "inkyos_radio_compare_source", "__file__": path}
    exec(compile(raw, path, "exec"), namespace)
    return namespace


def compare_radio(original, corrected, radio, sample=None):
    captured = {}
    def once():
        values = (sample or radio["ProductionAdapter"]().sample)()
        # The historical validator receives its own mapping. The shared values
        # accepted by it are only immutable bytes and an integer wiphy index.
        captured["values"] = dict(values) if type(values) is dict else values
        return dict(values) if type(values) is dict else values
    result = original(radio, once)
    result["same_sample"] = False
    result["corrected_channels"] = {"error": "observation_unavailable", "data": None}
    if result["sample_error"] is None:
        values = captured["values"]
        result["same_sample"] = True
        try:
            data = corrected(values["channels"], values["wiphy_index"])
            result["corrected_channels"] = {"error": None, "data": data}
        except Exception as error:
            result["corrected_channels"]["error"] = ("kernel_observation_invalid"
                if str(error) == "kernel_observation_invalid" else "observation_unavailable")
    return result


def configure(v2, corrected, self_sha256):
    """Wrap the private v2 namespace; preserve the exact native v1 adapter type."""
    if (type(self_sha256) is not str or len(self_sha256) != 64
            or any(char not in "0123456789abcdef" for char in self_sha256)):
        raise ComparisonError("source_pin_invalid")
    original_radio, original_decorate = v2["radio_detail"], v2["decorate"]
    v2.update(REPORT=REPORT, CLAIM=CLAIM, KIND=KIND)
    pins = {V2_PATH: V2_SHA256, PARSER_PATH: PARSER_SHA256,
            v2["V1_PATH"]: v2["V1_SHA256"], SELF_PATH: self_sha256}
    def decorate(result):
        result = original_decorate(result)
        result.update(v2_source_sha256=V2_SHA256, corrected_parser_sha256=PARSER_SHA256,
                      comparison_source_sha256=self_sha256)
        result["limits"].extend([
            "Both channel parsers receive the same read-only sample; neither applies a country or qualifies the radio.",
            "The corrected parser is loaded only for comparison; the installed rootfs observer is unchanged.",
            "Panel observation is not requested; no EEPROM or display driver is accessed by these probes."])
        return result
    def attach(v1, adapter):
        original_unchanged, original_pins, original_report = adapter.unchanged, adapter.pin_sources, adapter.report
        def check_sources():
            for path, digest in pins.items():
                read_pinned(path, digest)
        def pin_sources():
            original_pins()
            try:
                check_sources()
            except Exception:
                raise v1["DiagnosticError"]("source_pin_invalid") from None
        def unchanged():
            if original_unchanged() is not True:
                return False
            try:
                check_sources()
            except Exception:
                return False
            return True
        def probes():
            facts = adapter.radio["PreparedGuard"]().collect()
            guards = {key: facts.get(key) is True for key in v1["GUARD_CHECKS"]}
            panel = {"error": "not_requested", "data": None}
            if not all(guards.values()):
                return {"guards": guards, "panel": panel,
                        "radio": {"sample_error": "guards_blocked", "firmware_tuple_qualified": False}}
            return {"guards": guards, "panel": panel,
                    "radio": compare_radio(original_radio, corrected, adapter.radio)}
        adapter.pin_sources, adapter.unchanged, adapter.probes = pin_sources, unchanged, probes
        adapter.report = lambda result: original_report(decorate(result))
        return adapter
    v2.update(decorate=decorate, attach_details=attach)
    return v2


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    error = None
    if args:
        error = "invalid_arguments"
    elif not sys.platform.startswith("linux") or os.geteuid() != 0 or platform.machine() != "aarch64":
        error = "target_unverified"
    else:
        try:
            self_sha256 = hashlib.sha256(read_pinned(SELF_PATH, None)).hexdigest()
            v2 = compile_pinned(read_pinned(V2_PATH, V2_SHA256), V2_PATH, V2_SHA256)
            parser = compile_pinned(read_pinned(PARSER_PATH, PARSER_SHA256), PARSER_PATH, PARSER_SHA256)
            return configure(v2, parser["parse_channels"], self_sha256)["main"]([])
        except Exception:
            error = "comparison_unavailable"
    print(json.dumps({"schema_version": 1, "kind": KIND, "completed": False, "error": error,
        "live_evidence": False, "activation_authorized": False, "hardware_qualified": False,
        "release_qualified": False}, sort_keys=True, separators=(",", ":")))
    return 1


if __name__ == "__main__":
    sys.exit(main())
