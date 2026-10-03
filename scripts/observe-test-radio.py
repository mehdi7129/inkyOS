#!/usr/bin/python3 -I
"""Read-only TEST radio observations; inactive unless --live and --country CC.

No scan, connect, country setter, rfkill, service activation or app import.
The fixed GET route is reviewed against Raspberry Pi Linux 6.18.50 commit
cff533aec2fa601846766b32ff57204e0a61bed7, brcmfmac/{vendor.c,vendor.h,
fwil.c,fwil.h,fwil_types.h,cfg80211.c}, and Debian iw 6.9-1/vendor.c.
These source references do not attest the installed module or firmware. The
firmware country/ccode/revision tuple remains UNQUALIFIED until a real bench.
"""

import sys
sys.dont_write_bytecode = True

import argparse
import hashlib
import json
import os
import posixpath
import re
import selectors
import stat
import struct
import subprocess
import time


HELPER_PATH = "/usr/local/lib/inkyos/test-lan-preflight.py"
KERNEL_SOURCE = "cff533aec2fa601846766b32ff57204e0a61bed7"
MAX_OUTPUT = 16384
COMMAND_TIMEOUT = 2.0
GUARD_BUDGET = 6.0
GET_COMMAND = ("/usr/sbin/iw", "dev", "wlan0", "vendor", "recvbin", "0x001018", "0x1", "-")
# Five native 32-bit fields on the reviewed little-endian ARM64 target. Mirror
# fwil.c's iovar buffer: name including NUL plus the 12-byte country struct.
GET_PAYLOAD = struct.pack("<IiIII", 262, 20, 20, 0, 0) + b"country\0" + bytes(12)
INTERFACE_COMMAND = ("/usr/sbin/iw", "dev", "wlan0", "info")
REG_COMMAND = ("/usr/sbin/iw", "reg", "get")
GUARD_CHECKS = ("prepared_profile", "exact_payload_pin", "firstboot_success",
                "app_stopped_and_masked", "helper_stopped_and_masked")
CHECKS = GUARD_CHECKS + ("wlan0_driver_and_wiphy_verified", "firmware_response_valid",
                       "firmware_country_matches", "kernel_global_country_matches",
                       "kernel_2_4ghz_limits_observed", "firmware_tuple_qualified")
LIMITATIONS = (
    "The firmware country/ccode/revision tuple is not qualified; this output never authorizes activation.",
    "PHY 98/99 labels do not prove the firmware country, nor invalidate it by themselves.",
    "Kernel channel flags and advertised power are observations, not measured RF or regulatory certification.",
    "iw 6.9 text does not expose every per-channel bandwidth restriction; no country rule equivalence is inferred.",
    "GET success with wlan0 down and Wi-Fi disabled has not been established on the physical Pi.",
    "Source references and local unsigned pin declarations do not attest the installed binary or firmware.",
    "Fixture observations are not live evidence; service/sysfs snapshots do not lock concurrent operator changes.",
    "No scan, association, setter, rfkill change, service start or application import is performed.",
)


class ObservationError(ValueError):
    pass


class SafeParser(argparse.ArgumentParser):
    def error(self, _message):
        raise ObservationError("invalid_arguments")


def parse_country(raw):
    """Strict inner BRCMF NLA stream; never treat iw recvbin as a bare struct."""
    if type(raw) is not bytes or not raw or len(raw) > MAX_OUTPUT:
        raise ObservationError("firmware_response_invalid")
    attrs, offset = {}, 0
    while offset < len(raw):
        if len(raw) - offset < 4:
            raise ObservationError("firmware_response_invalid")
        length, kind = struct.unpack_from("<HH", raw, offset)
        aligned = (length + 3) & ~3
        if (length < 4 or kind not in {1, 2} or kind in attrs
                or offset + aligned > len(raw) or any(raw[offset + length:offset + aligned])):
            raise ObservationError("firmware_response_invalid")
        attrs[kind] = raw[offset + 4:offset + length]
        offset += aligned
    if set(attrs) != {1, 2} or len(attrs[1]) != 2 or len(attrs[2]) != 20 or struct.unpack("<H", attrs[1])[0] != 20:
        raise ObservationError("firmware_response_invalid")
    abbreviation, revision, ccode = struct.unpack("<4si4s", attrs[2][:12])
    def code(value):
        # Codes such as 00/X2/Q2 can be observed, but never accepted as ISO
        # proof or mapped to FR without a separately qualified tuple.
        if not re.fullmatch(rb"[A-Z0-9]{2}\x00\x00", value):
            raise ObservationError("firmware_response_invalid")
        return value[:2].decode("ascii")
    if not -1 <= revision <= 65535:
        raise ObservationError("firmware_response_invalid")
    return {"country_abbrev": code(abbreviation), "ccode": code(ccode), "revision": revision}


def text(raw):
    if type(raw) is not bytes or not raw or len(raw) > MAX_OUTPUT:
        raise ObservationError("kernel_observation_invalid")
    try:
        return raw.decode("ascii")
    except UnicodeError:
        raise ObservationError("kernel_observation_invalid") from None


def parse_interface(raw, index):
    value = text(raw)
    names = re.findall(r"^Interface ([^\n]+)$", value, re.MULTILINE)
    indices = re.findall(r"^[ \t]*wiphy ([0-9]+)$", value, re.MULTILINE)
    if names != ["wlan0"] or indices != [str(index)]:
        raise ObservationError("wlan0_mapping_unverified")


def parse_regulatory(raw, index):
    current, sections = None, {}
    for line in text(raw).splitlines():
        stripped = line.strip()
        if stripped == "global":
            current = "global"
        elif stripped.startswith("phy#"):
            matched = re.fullmatch(r"phy#(0|[1-9][0-9]{0,2})(?: \((custom|self-managed)\))?", stripped)
            if matched is None or int(matched[1]) > 255:
                raise ObservationError("kernel_observation_invalid")
            current = int(matched[1])
        else:
            if stripped.startswith("country "):
                matched = re.fullmatch(r"country ([A-Z0-9]{2}):[ A-Z0-9-]*", stripped)
                if matched is None or current is None or "country" in sections[current]:
                    raise ObservationError("kernel_observation_invalid")
                sections[current]["country"] = matched[1]
            continue
        if current in sections:
            raise ObservationError("kernel_observation_invalid")
        sections[current] = {"custom": "(custom)" in stripped,
                             "self_managed": "(self-managed)" in stripped}
    if "country" not in sections.get("global", {}) or "country" not in sections.get(index, {}):
        raise ObservationError("kernel_observation_invalid")
    return {"global_country": sections["global"]["country"], "phy_country_label": sections[index]["country"],
            "phy_custom": sections[index]["custom"], "phy_self_managed": sections[index]["self_managed"]}


def frequency_mhz(token):
    # iw 6.9-1 info.c:409-415 prints FREQ.OFFSET when the optional kHz
    # attribute exists, even for zero. Accept only exact whole-MHz forms;
    # interpreting this printed pair as a decimal float would be incorrect.
    matched = re.fullmatch(r"(0|[1-9][0-9]{0,9})(?:\.0)?", token) if type(token) is str else None
    if matched is None or int(matched[1]) > 0xffffffff:
        raise ObservationError("kernel_observation_invalid")
    return int(matched[1])


def parse_channels(raw, index):
    """Export only 2.4 GHz frequency/power/known flags, never MACs or raw text."""
    value = text(raw)
    if re.findall(r"^Wiphy ([^\n]+)$", value, re.MULTILINE) != ["phy" + str(index)]:
        raise ObservationError("kernel_observation_invalid")
    channels = {}
    known_flags = {"no IR", "passive scan", "no ibss", "radar detection"}
    for line in value.splitlines():
        # Other iw lists include prose such as "* short GI for 40 MHz".
        # Numeric-looking MHz entries, or MHz followed by a channel bracket,
        # remain frequency candidates so malformed values cannot disappear.
        if (re.match(r"[ \t]*\* ", line) is None
                or not (re.match(r"[ \t]*\* [ \t]*[0-9+.-]", line) and "MHz" in line
                        or re.search(r"MHz[ \t]*\[", line))):
            continue
        prefix = re.match(r"[ \t]*\* (.*) MHz(?:[ \t]|$)", line)
        if prefix is None:
            raise ObservationError("kernel_observation_invalid")
        frequency = frequency_mhz(prefix[1])
        if not 2400 <= frequency <= 2500:
            continue
        matched = re.fullmatch(r"[ \t]*\* ((?:0|[1-9][0-9]{0,9})(?:\.0)?) MHz \[([0-9]+)\] \((disabled|[0-9]{1,2}\.[0-9] dBm)\)(?: \(([^()]*)\))?", line)
        if matched is None or frequency in channels:
            raise ObservationError("kernel_observation_invalid")
        channel = int(matched[2])
        expected = 2484 if channel == 14 else 2407 + channel * 5
        if not 1 <= channel <= 14 or frequency != expected:
            raise ObservationError("kernel_observation_invalid")
        disabled = matched[3] == "disabled"
        flags = matched[4].split(", ") if matched[4] else []
        if len(set(flags)) != len(flags) or not set(flags) <= known_flags or disabled and flags:
            raise ObservationError("kernel_observation_invalid")
        power = None if disabled else int(matched[3].split(".", 1)[0]) * 100 + int(matched[3].split(".", 1)[1][0]) * 10
        if power is not None and not 0 <= power <= 4000:
            raise ObservationError("kernel_observation_invalid")
        channels[frequency] = {"frequency_mhz": frequency, "channel": channel, "disabled": disabled,
                               "max_tx_power_mbm": power, "flags": sorted(flags)}
    if not channels or not any(not value["disabled"] for value in channels.values()):
        raise ObservationError("kernel_observation_invalid")
    return [channels[key] for key in sorted(channels)]


def bounded_command(argv, *, data=None, timeout=COMMAND_TIMEOUT, limit=MAX_OUTPUT):
    """Bounded bytes, discarded stderr, fixed environment; no shell."""
    process = None
    selector = selectors.DefaultSelector()
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd="/", close_fds=True,
                                   env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"})
        if data is not None:
            # Production supplies exactly 40 bytes, below any pipe capacity.
            if type(data) is not bytes or len(data) > len(GET_PAYLOAD):
                return None
            process.stdin.write(data)
            process.stdin.close()
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline, output = time.monotonic() + timeout, bytearray()
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            for key, _events in selector.select(remaining):
                chunk = os.read(key.fd, min(4096, limit + 1 - len(output)))
                if not chunk:
                    selector.unregister(key.fileobj)
                else:
                    output.extend(chunk)
                    if len(output) > limit:
                        return None
        remaining = deadline - time.monotonic()
        return bytes(output) if remaining > 0 and process.wait(timeout=remaining) == 0 else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    finally:
        selector.close()
        if process is not None:
            if process.poll() is None:
                process.kill()
                try:
                    process.wait(timeout=0.1)
                except subprocess.TimeoutExpired:
                    pass
            for stream in (process.stdin, process.stdout):
                if stream is not None:
                    stream.close()


class SysfsMapping:
    """Follow only kernel links under /sys to fixed wlan0/SDIO brcmfmac/PHY."""
    def sample(self):
        root = os.open("/sys", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            def safe(info):
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                    raise ObservationError("wlan0_mapping_unverified")
            safe(os.fstat(root))
            def directory(relative):
                fd = os.dup(root)
                try:
                    for part in relative.split("/") if relative else ():
                        if part in {"", ".", ".."}:
                            raise ObservationError("wlan0_mapping_unverified")
                        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        os.close(fd)
                        fd = child
                        safe(os.fstat(fd))
                    return fd
                except BaseException:
                    os.close(fd)
                    raise
            def link(relative):
                parent, name = relative.rsplit("/", 1)
                fd = directory(parent)
                try:
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if not stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
                        raise ObservationError("wlan0_mapping_unverified")
                    target = os.readlink(name, dir_fd=fd)
                    if not target or len(target) > 1024:
                        raise ObservationError("wlan0_mapping_unverified")
                    resolved = posixpath.normpath(target if target.startswith("/") else "/sys/" + parent + "/" + target)
                    after = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    stamp = lambda value: (value.st_dev, value.st_ino, value.st_mtime_ns, value.st_ctime_ns)
                    if not resolved.startswith("/sys/") or stamp(info) != stamp(after) or target != os.readlink(name, dir_fd=fd):
                        raise ObservationError("wlan0_mapping_unverified")
                    return resolved[5:]
                finally:
                    os.close(fd)
            net = link("class/net/wlan0")
            if not net.startswith("devices/") or not net.endswith("/net/wlan0"):
                raise ObservationError("wlan0_mapping_unverified")
            device = link(net + "/device")
            if net != device + "/net/wlan0" or link(device + "/driver") != "bus/sdio/drivers/brcmfmac":
                raise ObservationError("wlan0_mapping_unverified")
            phy = link(net + "/phy80211")
            matched = re.fullmatch(re.escape(device) + r"/ieee80211/phy(0|[1-9][0-9]{0,2})", phy)
            if matched is None or int(matched[1]) > 255 or link("class/ieee80211/phy" + matched[1]) != phy:
                raise ObservationError("wlan0_mapping_unverified")
            fd = directory(phy)
            index_fd = None
            try:
                index_fd = os.open("index", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                info = os.fstat(index_fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                    raise ObservationError("wlan0_mapping_unverified")
                index = os.read(index_fd, 33)
                if index not in {matched[1].encode(), (matched[1] + "\n").encode()}:
                    raise ObservationError("wlan0_mapping_unverified")
            finally:
                if index_fd is not None:
                    os.close(index_fd)
                os.close(fd)
            if link("class/net/wlan0") != net or link(device + "/driver") != "bus/sdio/drivers/brcmfmac":
                raise ObservationError("wlan0_mapping_unverified")
            return int(matched[1])
        finally:
            os.close(root)


def load_helpers():
    """Load only the installed root-owned stdlib preflight, never app/venv."""
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    file_fd = None
    try:
        for part in HELPER_PATH.strip("/").split("/")[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ObservationError("helpers_unavailable")
        name = HELPER_PATH.rsplit("/", 1)[1]
        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        before = os.fstat(file_fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                or stat.S_IMODE(before.st_mode) != 0o555 or before.st_nlink != 1 or before.st_size > 65536):
            raise ObservationError("helpers_unavailable")
        raw = bytearray()
        while len(raw) <= 65536:
            chunk = os.read(file_fd, min(4096, 65537 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after, current = os.fstat(file_fd), os.stat(name, dir_fd=fd, follow_symlinks=False)
        stamp = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if len(raw) > 65536 or stamp(before) != stamp(after) or stamp(after) != stamp(current):
            raise ObservationError("helpers_unavailable")
        namespace = {"__name__": "inkyos_radio_preflight_helpers", "__file__": HELPER_PATH}
        exec(compile(bytes(raw), HELPER_PATH, "exec"), namespace)
        return namespace
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(fd)


class PreparedGuard:
    def __init__(self, *, helpers=None, store=None, command=None, monotonic=time.monotonic):
        self.helpers, self.store, self.command, self.monotonic = helpers, store, command, monotonic
        self.native_live = helpers is None and store is None and command is None and monotonic is time.monotonic

    def collect(self):
        facts, store = {key: False for key in GUARD_CHECKS}, None
        try:
            helpers = self.helpers if self.helpers is not None else load_helpers()
            store = self.store if self.store is not None else helpers["ReadStore"]("/")
            marker = helpers["_json"](store.read(helpers["MARKER"]))
            facts["prepared_profile"] = (type(marker) is dict and type(marker.get("schema_version")) is int
                and marker["schema_version"] == 1 and marker.get("kind") == "test-lan-prepared"
                and marker.get("state") == "prepared-inactive" and marker.get("application_runtime") == "masked"
                and marker.get("activation_authorized") is False and marker.get("ready_for_activation") is False
                and marker.get("factory_authority") is False)
            if not facts["prepared_profile"]:
                return facts
            source, digest = marker.get("source_commit"), marker.get("manifest_sha256")
            if type(source) is not str or type(digest) is not str or helpers["REVIEWED_APPLICATIONS"].get(source) != digest:
                return facts
            manifest = store.read(helpers["MANIFEST"])
            declaration = store.read(helpers["SOURCE_FILE"], limit=256, app_owned=True)
            facts["exact_payload_pin"] = hashlib.sha256(manifest).hexdigest() == digest and declaration in {source.encode(), (source + "\n").encode()}
            if not facts["exact_payload_pin"]:
                return facts
            command = self.command if self.command is not None else helpers["bounded_command"]
            deadline = self.monotonic() + GUARD_BUDGET
            wanted = {
                "firstboot": ("firstboot_success", {"ActiveState": "active", "SubState": "exited", "LoadState": "loaded", "Result": "success", "ExecMainStatus": "0"}),
                "app": ("app_stopped_and_masked", {"ActiveState": "inactive", "SubState": "dead", "LoadState": "masked", "UnitFileState": "masked"}),
                "helper": ("helper_stopped_and_masked", {"ActiveState": "inactive", "SubState": "dead", "LoadState": "masked", "UnitFileState": "masked"}),
            }
            for key, (check, expected) in wanted.items():
                remaining = deadline - self.monotonic()
                if remaining <= 0:
                    break
                raw = command(helpers["COMMANDS"][key], timeout=min(COMMAND_TIMEOUT, remaining), limit=MAX_OUTPUT)
                if type(raw) is str and len(raw) <= MAX_OUTPUT:
                    facts[check] = helpers["_properties"](raw, set(expected)) == expected
            return facts
        except Exception:
            return facts
        finally:
            if self.store is None and store is not None:
                store.close()


class ProductionAdapter:
    def __init__(self, *, command=None, mapping=None):
        self.command = bounded_command if command is None else command
        self.mapping = SysfsMapping() if mapping is None else mapping
        self.native_live = command is None and mapping is None

    def sample(self):
        if self.native_live and (not sys.platform.startswith("linux") or os.geteuid() != 0 or sys.byteorder != "little"):
            raise ObservationError("linux_root_required")
        index = self.mapping.sample()
        if type(index) is not int or not 0 <= index <= 255:
            raise ObservationError("wlan0_mapping_unverified")
        def query(argv, data=None):
            raw = self.command(argv, data=data, timeout=COMMAND_TIMEOUT, limit=MAX_OUTPUT)
            if type(raw) is not bytes or not raw or len(raw) > MAX_OUTPUT:
                raise ObservationError("observation_unavailable")
            return raw
        parse_interface(query(INTERFACE_COMMAND), index)
        firmware = query(GET_COMMAND, GET_PAYLOAD)
        regulatory = query(REG_COMMAND)
        channels = query(("/usr/sbin/iw", "phy", "phy" + str(index), "info"))
        if self.mapping.sample() != index:
            raise ObservationError("wlan0_mapping_unverified")
        return {"wiphy_index": index, "firmware": firmware, "regulatory": regulatory, "channels": channels}


def observe(adapter=None, guard=None, *, live=False, country=None):
    facts = {key: False for key in CHECKS}
    output = {"schema_version": 1, "kind": "test-radio-observation", "scope": "read-only-unqualified-radio-observations",
              "live_selected": live is True, "observation_source": "inactive", "live_evidence": False,
              "observations_complete": False, "firmware_tuple_qualified": False, "checks": {},
              "firmware": None, "kernel": None, "channels_2_4ghz": None,
              "passed": False, "status": "BLOCKED", "activation_authorized": False,
              "hardware_qualified": False, "release_qualified": False, "error": None,
              "source_reference": {"raspberrypi_linux_commit": KERNEL_SOURCE, "iw_source_version": "6.9-1"},
              "limitations": list(LIMITATIONS)}
    valid_country = type(country) is str and re.fullmatch(r"[A-Z]{2}", country) is not None
    if live is True and not valid_country:
        output["error"] = "explicit_country_required"
    elif live is True:
        native = (type(adapter) is ProductionAdapter and adapter.native_live
                  and type(guard) is PreparedGuard and guard.native_live
                  and sys.platform.startswith("linux") and os.geteuid() == 0)
        output["observation_source"] = "live-system" if native else "fixture"
        try:
            observed = guard.collect() if guard is not None else {}
            if type(observed) is dict:
                for key in GUARD_CHECKS:
                    facts[key] = observed.get(key) is True
            if all(facts[key] for key in GUARD_CHECKS) and adapter is not None:
                sample = adapter.sample()
                index = sample["wiphy_index"]
                if type(index) is not int or not 0 <= index <= 255:
                    raise ObservationError("wlan0_mapping_unverified")
                facts["wlan0_driver_and_wiphy_verified"] = True
                output["firmware"] = parse_country(sample["firmware"])
                facts["firmware_response_valid"] = True
                facts["firmware_country_matches"] = output["firmware"]["country_abbrev"] == country
                output["kernel"] = parse_regulatory(sample["regulatory"], index)
                facts["kernel_global_country_matches"] = output["kernel"]["global_country"] == country
                output["channels_2_4ghz"] = parse_channels(sample["channels"], index)
                facts["kernel_2_4ghz_limits_observed"] = True
                output["observations_complete"], output["live_evidence"] = True, native
        except ObservationError as error:
            allowed = {"firmware_response_invalid", "kernel_observation_invalid", "wlan0_mapping_unverified", "linux_root_required"}
            output["error"] = str(error) if str(error) in allowed else "observation_unavailable"
        except Exception:
            output["error"] = "observation_unavailable"
    for key, passed in facts.items():
        output["checks"][key] = {"passed": passed, "status": "PASS" if passed else "BLOCKED"}
    # No path, including native successful observations, can qualify a tuple.
    return output


def main(argv=None):
    parser = SafeParser(prog="observe-test-radio.py", description=__doc__, allow_abbrev=False)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--country")
    try:
        args = parser.parse_args(argv)
        valid_country = type(args.country) is str and re.fullmatch(r"[A-Z]{2}", args.country) is not None
        if args.country is not None and not valid_country or args.live and not valid_country:
            raise ObservationError("invalid_arguments")
        if args.live and sys.platform.startswith("linux") and os.geteuid() == 0:
            output = observe(ProductionAdapter(), PreparedGuard(), live=True, country=args.country)
        else:
            output = observe(live=args.live, country=args.country)
            if args.live:
                output["error"] = "linux_root_required"
        code = 1
    except ObservationError:
        output = observe()
        output["error"] = "invalid_arguments"
        code = 2
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    sys.exit(main())
