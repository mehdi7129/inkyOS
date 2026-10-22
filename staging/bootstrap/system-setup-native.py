"""Native effects for the pinned factory setup service. No application imports.

The strict GET/parsing algorithms below are reviewed copies of the old read-only
observer; no TEST authority, receipt, capsule or module is loaded at runtime.
"""

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import posixpath
import re
import selectors
import shlex
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import types

MAX_OUTPUT = 16384
GET_COMMAND = (
    "/usr/sbin/iw",
    "dev",
    "wlan0",
    "vendor",
    "recvbin",
    "0x001018",
    "0x1",
    "-",
)
GET_PAYLOAD = struct.pack("<IiIII", 262, 20, 20, 0, 0) + b"country\0" + bytes(12)
NM = "org.freedesktop.NetworkManager"
NMPATH = "/org/freedesktop/NetworkManager"


class ObservationError(ValueError):
    def __init__(self, reason="unavailable"):
        self.reason = reason
        super().__init__(reason)


def require(value, reason="unavailable"):
    if not value:
        raise ObservationError(reason)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def canonical(value):
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


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
        if (
            length < 4
            or kind not in {1, 2}
            or kind in attrs
            or offset + aligned > len(raw)
            or any(raw[offset + length : offset + aligned])
        ):
            raise ObservationError("firmware_response_invalid")
        attrs[kind] = raw[offset + 4 : offset + length]
        offset += aligned
    if (
        set(attrs) != {1, 2}
        or len(attrs[1]) != 2
        or len(attrs[2]) != 20
        or struct.unpack("<H", attrs[1])[0] != 20
    ):
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
    return {
        "country_abbrev": code(abbreviation),
        "ccode": code(ccode),
        "revision": revision,
    }


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
            matched = re.fullmatch(
                r"phy#(0|[1-9][0-9]{0,2})(?: \((custom|self-managed)\))?", stripped
            )
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
        sections[current] = {
            "custom": "(custom)" in stripped,
            "self_managed": "(self-managed)" in stripped,
        }
    if "country" not in sections.get("global", {}) or "country" not in sections.get(
        index, {}
    ):
        raise ObservationError("kernel_observation_invalid")
    return {
        "global_country": sections["global"]["country"],
        "phy_country_label": sections[index]["country"],
        "phy_custom": sections[index]["custom"],
        "phy_self_managed": sections[index]["self_managed"],
    }


def frequency_mhz(token):
    # iw 6.9-1 info.c:409-415 prints FREQ.OFFSET when the optional kHz
    # attribute exists, even for zero. Accept only exact whole-MHz forms;
    # interpreting this printed pair as a decimal float would be incorrect.
    matched = (
        re.fullmatch(r"(0|[1-9][0-9]{0,9})(?:\.0)?", token)
        if type(token) is str
        else None
    )
    if matched is None or int(matched[1]) > 0xFFFFFFFF:
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
        if re.match(r"[ \t]*\* ", line) is None or not (
            re.match(r"[ \t]*\* [ \t]*[0-9+.-]", line)
            and "MHz" in line
            or re.search(r"MHz[ \t]*\[", line)
        ):
            continue
        prefix = re.match(r"[ \t]*\* (.*) MHz(?:[ \t]|$)", line)
        if prefix is None:
            raise ObservationError("kernel_observation_invalid")
        frequency = frequency_mhz(prefix[1])
        if not 2400 <= frequency <= 2500:
            continue
        matched = re.fullmatch(
            r"[ \t]*\* ((?:0|[1-9][0-9]{0,9})(?:\.0)?) MHz \[([0-9]+)\] \((disabled|[0-9]{1,2}\.[0-9] dBm)\)(?: \(([^()]*)\))?",
            line,
        )
        if matched is None or frequency in channels:
            raise ObservationError("kernel_observation_invalid")
        channel = int(matched[2])
        expected = 2484 if channel == 14 else 2407 + channel * 5
        if not 1 <= channel <= 14 or frequency != expected:
            raise ObservationError("kernel_observation_invalid")
        disabled = matched[3] == "disabled"
        flags = matched[4].split(", ") if matched[4] else []
        if (
            len(set(flags)) != len(flags)
            or not set(flags) <= known_flags
            or disabled
            and flags
        ):
            raise ObservationError("kernel_observation_invalid")
        power = (
            None
            if disabled
            else int(matched[3].split(".", 1)[0]) * 100
            + int(matched[3].split(".", 1)[1][0]) * 10
        )
        if power is not None and not 0 <= power <= 4000:
            raise ObservationError("kernel_observation_invalid")
        channels[frequency] = {
            "frequency_mhz": frequency,
            "channel": channel,
            "disabled": disabled,
            "max_tx_power_mbm": power,
            "flags": sorted(flags),
        }
    if not channels or not any(not value["disabled"] for value in channels.values()):
        raise ObservationError("kernel_observation_invalid")
    return [channels[key] for key in sorted(channels)]


class SysfsMapping:
    """Follow only kernel links under /sys to fixed wlan0/SDIO brcmfmac/PHY."""

    def sample(self):
        root = os.open("/sys", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:

            def safe(info):
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != 0
                    or info.st_mode & 0o022
                ):
                    raise ObservationError("wlan0_mapping_unverified")

            safe(os.fstat(root))

            def directory(relative):
                fd = os.dup(root)
                try:
                    for part in relative.split("/") if relative else ():
                        if part in {"", ".", ".."}:
                            raise ObservationError("wlan0_mapping_unverified")
                        child = os.open(
                            part,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd,
                        )
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
                    resolved = posixpath.normpath(
                        target
                        if target.startswith("/")
                        else "/sys/" + parent + "/" + target
                    )
                    after = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    stamp = lambda value: (
                        value.st_dev,
                        value.st_ino,
                        value.st_mtime_ns,
                        value.st_ctime_ns,
                    )
                    if (
                        not resolved.startswith("/sys/")
                        or stamp(info) != stamp(after)
                        or target != os.readlink(name, dir_fd=fd)
                    ):
                        raise ObservationError("wlan0_mapping_unverified")
                    return resolved[5:]
                finally:
                    os.close(fd)

            net = link("class/net/wlan0")
            if not net.startswith("devices/") or not net.endswith("/net/wlan0"):
                raise ObservationError("wlan0_mapping_unverified")
            device = link(net + "/device")
            if (
                net != device + "/net/wlan0"
                or link(device + "/driver") != "bus/sdio/drivers/brcmfmac"
            ):
                raise ObservationError("wlan0_mapping_unverified")
            phy = link(net + "/phy80211")
            matched = re.fullmatch(
                re.escape(device) + r"/ieee80211/phy(0|[1-9][0-9]{0,2})", phy
            )
            if (
                matched is None
                or int(matched[1]) > 255
                or link("class/ieee80211/phy" + matched[1]) != phy
            ):
                raise ObservationError("wlan0_mapping_unverified")
            fd = directory(phy)
            index_fd = None
            try:
                index_fd = os.open(
                    "index", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd
                )
                info = os.fstat(index_fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != 0
                    or info.st_mode & 0o022
                ):
                    raise ObservationError("wlan0_mapping_unverified")
                index = os.read(index_fd, 33)
                if index not in {matched[1].encode(), (matched[1] + "\n").encode()}:
                    raise ObservationError("wlan0_mapping_unverified")
            finally:
                if index_fd is not None:
                    os.close(index_fd)
                os.close(fd)
            if (
                link("class/net/wlan0") != net
                or link(device + "/driver") != "bus/sdio/drivers/brcmfmac"
            ):
                raise ObservationError("wlan0_mapping_unverified")
            return int(matched[1])
        finally:
            os.close(root)


class Commands:
    """Fixed pinned executables only; every started child is reaped, without PID fallback."""

    def __init__(self):
        self.lock = threading.RLock()

    def run(self, argv, *, data=None, limit=262144):
        require(
            argv[0]
            in {
                "/usr/bin/busctl",
                "/usr/sbin/iw",
                "/usr/bin/nmcli",
                "/usr/bin/systemctl",
            }
        )
        with self.lock:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                cwd="/",
                env={
                    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG": "C",
                    "LC_ALL": "C",
                },
            )
            pidfd = None
            failure = None
            output, errors = bytearray(), bytearray()
            try:
                pidfd = os.pidfd_open(process.pid, 0)
                if data is not None:
                    require(type(data) is bytes and len(data) <= 40)
                    process.stdin.write(data)
                    process.stdin.close()
                deadline = time.monotonic() + 5
                with selectors.DefaultSelector() as selector:
                    for stream, sink in (
                        (process.stdout, output),
                        (process.stderr, errors),
                    ):
                        os.set_blocking(stream.fileno(), False)
                        selector.register(stream, selectors.EVENT_READ, sink)
                    while selector.get_map():
                        require(time.monotonic() < deadline)
                        for key, _ in selector.select(
                            max(0, deadline - time.monotonic())
                        ):
                            part = os.read(key.fd, 8192)
                            if not part:
                                selector.unregister(key.fileobj)
                            else:
                                key.data.extend(part)
                            require(len(output) + len(errors) <= limit)
                    require(
                        process.wait(timeout=max(0, deadline - time.monotonic())) == 0
                        and not errors
                    )
            except BaseException as error:
                failure = error
            finally:
                if process.poll() is None and pidfd is not None:
                    try:
                        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                # No timeout frees ownership. A stuck kernel child holds the service/SH.
                while process.poll() is None:
                    try:
                        process.wait(timeout=0.1)
                    except subprocess.TimeoutExpired:
                        continue
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
                if pidfd is not None:
                    os.close(pidfd)
            if failure is not None:
                raise failure
            return bytes(output)

    def bus(self, destination, path, interface, method, signature="", *arguments):
        argv = (
            "/usr/bin/busctl",
            "--system",
            "--auto-start=no",
            "--allow-interactive-authorization=no",
            "--timeout=5s",
            "call",
            destination,
            path,
            interface,
            method,
        )
        if signature:
            argv += (signature, *arguments)
        return self.run(argv)

    def prop(self, destination, path, interface, name, kind):
        raw = self.run(
            (
                "/usr/bin/busctl",
                "--system",
                "--auto-start=no",
                "--allow-interactive-authorization=no",
                "--timeout=5s",
                "get-property",
                destination,
                path,
                interface,
                name,
            )
        )
        tokens = shlex.split(raw.decode("ascii"))
        require(len(tokens) == 2 and tokens[0] == kind)
        if kind == "b":
            require(tokens[1] in {"true", "false"})
            return tokens[1] == "true"
        if kind in {"u", "i"}:
            require(re.fullmatch(r"0|-?[1-9][0-9]*", tokens[1]))
            return int(tokens[1])
        require(kind in {"s", "o"})
        return tokens[1]

    def owner(self, name):
        raw = self.bus(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "GetNameOwner",
            "s",
            name,
        )
        tokens = shlex.split(raw.decode("ascii"))
        require(
            len(tokens) == 2
            and tokens[0] == "s"
            and re.fullmatch(r":[0-9]+\.[0-9]+", tokens[1])
        )
        return tokens[1]


class Native:
    def __init__(self, runtime, contract):
        require(
            sys.platform == "linux"
            and os.geteuid() == 0
            and sys.byteorder == "little"
            and platform.machine() == "aarch64"
            and contract._root == Path("/")
        )
        require(
            Path("/proc/device-tree/model").read_bytes().rstrip(b"\0\n")
            == b"Raspberry Pi Zero 2 W Rev 1.0"
        )
        self.runtime, self.contract = runtime, contract
        self.command, self.mapping = Commands(), SysfsMapping()
        self.schema = None

    @staticmethod
    def boottime():
        return time.clock_gettime_ns(time.CLOCK_BOOTTIME)

    def consumed(self, workflow):
        # Trusted OS receipt implementation, never Studio or a main boolean.
        relative = self.runtime.RECEIPT
        _, _, support, records = self.runtime.inventories(self.contract)
        require(relative in support["paths"])
        with self.contract.tree() as tree:
            self.runtime.check_path(tree, relative, records)
            raw = tree.read(relative, 0o555, 262144)
        module = types.ModuleType("inkyos_setup_receipt")
        module.__file__ = "/" + relative
        exec(compile(raw, module.__file__, "exec"), module.__dict__)
        record = module.inspect("/var/lib/inkyos/initialization")
        require(
            record["status"] == "consumed"
            and record["intent"] == workflow["initialization_intent"]
            and record["receipt"]["digest"] == workflow["initialization_receipt_digest"]
        )

    def rfkill(self, blocked=None):
        index = self.mapping.sample()
        entries = []
        for entry in Path("/sys/class/rfkill").iterdir():
            if (entry / "type").read_text().strip() != "wlan":
                continue
            require(re.fullmatch(r"rfkill(?:0|[1-9][0-9]*)", entry.name))
            require((entry / "name").read_text().strip() == "phy" + str(index))
            entries.append((int(entry.name[6:]), entry))
        require(len(entries) == 1)
        number, entry = entries[0]
        if blocked is not None:
            fd = os.open("/dev/rfkill", os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                require(stat.S_ISCHR(os.fstat(fd).st_mode))
                require(
                    os.write(fd, struct.pack("IBBBB", number, 1, 2, int(blocked), 0))
                    == 8
                )
            finally:
                os.close(fd)

        def flag(name):
            value = (entry / name).read_bytes()
            require(value in {b"0\n", b"1\n"})
            return value == b"1\n"

        soft, hard = flag("soft"), flag("hard")
        require(self.mapping.sample() == index)
        return index, soft, hard

    def wireless(self):
        return self.command.prop(NM, NMPATH, NM, "WirelessEnabled", "b")

    def set_wireless(self, enabled):
        require(type(enabled) is bool)
        require(
            self.command.bus(
                NM,
                NMPATH,
                "org.freedesktop.DBus.Properties",
                "Set",
                "ssv",
                NM,
                "WirelessEnabled",
                "b",
                "true" if enabled else "false",
            )
            == b""
        )

    def close_wlan(self):
        self.set_wireless(False)
        self.rfkill(True)
        index, soft, _ = self.rfkill()
        require(not self.wireless() and soft, "cleanup_unconfirmed")
        return index

    def gate_receipt(self, context):
        """Historical same-boot close receipt; does not assert the live radio is closed.

        Only the explicitly owned AP branch may use this without gate()'s
        current RF checks. The AP adapter supplies independent live readbacks.
        """
        path = "run/inkyos-wlan-gate/closed.json"
        with self.contract.tree() as tree:
            raw = tree.read(path, 0o644, 4096)
        value = json.loads(raw)
        require(
            canonical(value) == raw
            and value.get("boot_id") == context["boot_id"]
            and value.get("candidate_sha256") == context["candidate_sha256"]
            and value.get("restore_policy") == "systemd-rfkill-masked"
        )
        require(
            value.get("record_sha256")
            == digest(
                {key: item for key, item in value.items() if key != "record_sha256"}
            )
        )
        return value

    def gate(self, context):
        value = self.gate_receipt(context)
        _, soft, _ = self.rfkill()
        require(soft and not self.wireless())
        return value

    def clock(self, seconds, policy):
        target = policy.utc_nanoseconds(seconds)
        e0 = self.boottime()
        time.clock_settime_ns(time.CLOCK_REALTIME, target)
        e1 = self.boottime()
        r0 = self.boottime()
        realtime = time.clock_gettime_ns(time.CLOCK_REALTIME)
        r1 = self.boottime()
        require(
            r1 - r0 < 2_000_000_000
            and policy.readback_within_tolerance(
                seconds, realtime, e0=e0, e1=e1, r0=r0, r1=r1
            )
        )
        lower, upper = policy.readback_error_interval(
            seconds, realtime, e0=e0, e1=e1, r0=r0, r1=r1
        )
        return {
            "utc_seconds": seconds,
            "effect_start_boottime_ns": e0,
            "effect_end_boottime_ns": e1,
            "read_start_boottime_ns": r0,
            "read_end_boottime_ns": r1,
            "realtime_ns": realtime,
            "error_lower_ns": lower,
            "error_upper_ns": upper,
            "time_policy_sha256": "68bde4a4ff166b4b2f945bc8dbf8664750cee4f43e3315d8b3e624075a5c7148",
        }

    def observe_country(self, requested):
        index = self.mapping.sample()
        parse_interface(
            self.command.run(("/usr/sbin/iw", "dev", "wlan0", "info")), index
        )
        firmware = parse_country(self.command.run(GET_COMMAND, data=GET_PAYLOAD))
        regulatory = parse_regulatory(
            self.command.run(("/usr/sbin/iw", "reg", "get")), index
        )
        channels = parse_channels(
            self.command.run(("/usr/sbin/iw", "phy", "phy" + str(index), "info")), index
        )
        require(self.mapping.sample() == index)
        require(
            firmware["country_abbrev"]
            == firmware["ccode"]
            == regulatory["global_country"]
            == requested
            and regulatory["phy_country_label"] in {requested, "98", "99"}
            and not regulatory["phy_self_managed"]
            and len(channels) == 14,
            "country_unconfirmed",
        )
        return {
            "requested_country": requested,
            "firmware_country": firmware["country_abbrev"],
            "firmware_ccode": firmware["ccode"],
            "firmware_revision": firmware["revision"],
            "global_country": regulatory["global_country"],
            "phy_label": regulatory["phy_country_label"],
            "wiphy_index": index,
            "interface": "wlan0",
            "channel_evidence_sha256": digest(channels),
            "observed_boottime_ns": self.boottime(),
        }

    def country(self, requested, check):
        require(type(requested) is str and re.fullmatch(r"[A-Z]{2}", requested))
        check()
        _, soft, _ = self.rfkill()
        require(soft and not self.wireless())
        start = self.boottime()
        check()
        require(self.command.run(("/usr/sbin/iw", "reg", "set", requested)) == b"")
        while self.boottime() - start < 25_000_000_000:
            check()
            try:
                return self.observe_country(requested)
            except ObservationError:
                time.sleep(0.1)
        raise ObservationError("country_unconfirmed")

    def observe_live(self, country, radio):
        # Read-only facts from this boot, never invoke a setter or reopen RF.
        current = self.observe_country(country["requested_country"])
        index, soft, hard = self.rfkill()
        owner = self.command.owner(NM)
        require(
            self.wireless()
            and not soft
            and not hard
            and index
            == current["wiphy_index"]
            == country["wiphy_index"]
            == radio["wiphy_index"]
            and owner == radio["nm_unique_owner"]
        )
        return current, {
            "wireless_enabled": True,
            "wlan_soft_blocked": False,
            "wlan_hard_blocked": False,
            "wiphy_index": index,
            "interface": "wlan0",
            "nm_unique_owner": owner,
            "observed_boottime_ns": self.boottime(),
        }

    def closed(self, context):
        self.gate(context)
        return True

    def inventory(self, proof, *, ap_uuid=None):
        # ap_uuid is supplied only after NativeAP verifies its exact volatile
        # owned profile, active connection and current device/country evidence.
        if ap_uuid is not None:
            require(
                type(ap_uuid) is str
                and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", ap_uuid),
                "network_unconfirmed",
            )
        try:
            observation = self.network_latest(proof)
            if ap_uuid is None:
                self.check_network(observation, ready=False)
            else:
                # Only this inventory call follows NativeAP's exact current
                # AP attestation. AP activity does not mean station readiness.
                self._check_network(
                    observation, ready=False, verified_ap_uuid=ap_uuid
                )
            allowed = {observation["profile_uuid"]}
        except ObservationError as error:
            require(error.reason == "not_found", "network_unconfirmed")
            allowed = set()
        if ap_uuid is not None:
            require(ap_uuid not in allowed, "network_unconfirmed")
            allowed.add(ap_uuid)
        raw = self.command.run(
            (
                "/usr/bin/nmcli",
                "--escape",
                "yes",
                "--get-values",
                "UUID,TYPE",
                "connection",
                "show",
            )
        )
        lines = raw.decode("ascii").splitlines()
        require(
            len(lines) <= 64 and len(lines) == len(set(lines)), "network_unconfirmed"
        )
        wireless = set()
        for line in lines:
            cells = line.split(":")
            require(
                len(cells) == 2
                and re.fullmatch(
                    r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", cells[0]
                )
            )
            if cells[1] == "802-11-wireless":
                wireless.add(cells[0])
            else:
                require(
                    cells[1]
                    in {"802-3-ethernet", "loopback", "bridge", "tun", "wireguard"}
                )
        require(wireless == allowed, "network_unconfirmed")
        return allowed

    def enable_wlan(self, country, check):
        index = country["wiphy_index"]
        check()
        require(
            self.observe_country(country["requested_country"])["wiphy_index"] == index
        )
        check()
        self.rfkill(False)
        check()
        self.set_wireless(True)
        start = self.boottime()
        while self.boottime() - start < 5_000_000_000:
            check()
            observed, soft, hard = self.rfkill()
            if self.wireless() and not soft and not hard and observed == index:
                return {
                    "wireless_enabled": True,
                    "wlan_soft_blocked": False,
                    "wlan_hard_blocked": False,
                    "wiphy_index": index,
                    "interface": "wlan0",
                    "nm_unique_owner": self.command.owner(NM),
                    "observed_boottime_ns": self.boottime(),
                }
            time.sleep(0.1)
        raise ObservationError("network_unconfirmed")

    def helper(self, request, proof):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect("/run/inky-network/control.sock")
            with proof.network_guard(connection):
                proof.check()
                connection.sendall(canonical(request))
                stream = connection.makefile("rb")
                try:
                    raw = stream.readline(16385)
                finally:
                    stream.close()
                require(len(raw) <= 16384 and raw.endswith(b"\n"))
                value = json.loads(raw, object_pairs_hook=unique)
                require(type(value) is dict and type(value.get("ok")) is bool)
                if value["ok"] is False:
                    require(
                        set(value) == {"ok", "error"}
                        and value["error"]
                        in {
                            "not_found",
                            "busy",
                            "not_ready",
                            "permission_denied",
                            "invalid_request",
                        }
                    )
                    raise ObservationError(value["error"])
                require(set(value) == {"ok", "result"})
                observation = value["result"]
                require(
                    observation["observation_sha256"]
                    == digest(
                        {
                            key: item
                            for key, item in observation.items()
                            if key != "observation_sha256"
                        }
                    )
                )
                proof.check()
                return observation

    def network_exact(self, identifier, owner, proof):
        return self.helper(
            {"op": "inspect_committed", "id": identifier, "owner_id": owner}, proof
        )

    def network_latest(self, proof):
        return self.helper({"op": "inspect_latest_committed"}, proof)

    def check_network(self, observation, *, ready):
        # Public station observations remain strict, including readonly status.
        return self._check_network(observation, ready=ready)

    def _check_network(self, observation, *, ready, verified_ap_uuid=None):
        # Independent current NM evidence. A helper-owned JSON file is insufficient.
        # The private AP exception is only used by inventory after NativeAP has
        # attested that exact owned live AP. It can never authorize LAN readiness.
        if verified_ap_uuid is not None:
            require(
                ready is False
                and type(verified_ap_uuid) is str
                and re.fullmatch(
                    r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
                    verified_ap_uuid,
                )
                and verified_ap_uuid != observation["profile_uuid"],
                "network_unconfirmed",
            )
        require(
            observation["boot_id"]
            == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            and observation["nm_unique_owner"] == self.command.owner(NM)
        )
        identifier = observation["profile_uuid"]
        raw = self.command.bus(
            NM,
            NMPATH + "/Settings",
            NM + ".Settings",
            "GetConnectionByUuid",
            "s",
            identifier,
        )
        tokens = shlex.split(raw.decode("ascii"))
        require(
            len(tokens) == 2
            and tokens[0] == "o"
            and re.fullmatch(re.escape(NMPATH) + r"/Settings/[0-9]+", tokens[1])
        )
        require(
            self.command.prop(
                NM, tokens[1], NM + ".Settings.Connection", "Unsaved", "b"
            )
            is False
        )
        raw = self.command.run(
            (
                "/usr/bin/nmcli",
                "--escape",
                "yes",
                "--get-values",
                "connection.uuid,connection.type,connection.interface-name",
                "connection",
                "show",
                "uuid",
                identifier,
            )
        )
        require(
            raw.decode("ascii").splitlines() == [identifier, "802-11-wireless", "wlan0"]
        )
        raw = self.command.run(
            (
                "/usr/bin/nmcli",
                "--escape",
                "yes",
                "--get-values",
                "GENERAL.CON-UUID,IP4.ADDRESS",
                "device",
                "show",
                "wlan0",
            )
        )
        lines = raw.decode("ascii").splitlines()
        require(lines)
        active = None if lines[0] == "--" else lines[0]
        ipv4 = []
        for item in lines[1:]:
            if item == "--":
                continue
            address = str(ipaddress.IPv4Interface(item).ip)
            require(address not in ipv4)
            ipv4.append(address)
        require(
            active == observation["active_profile_uuid"]
            and sorted(ipv4) == sorted(observation["ipv4"])
            and observation["nm_unique_owner"] == self.command.owner(NM)
        )
        if ready:
            require(active == identifier and ipv4, "network_unconfirmed")
        else:
            allowed = {None, identifier}
            if verified_ap_uuid is not None:
                allowed.add(verified_ap_uuid)
            require(active in allowed, "network_unconfirmed")

    def origin(self):
        try:
            path = "var/lib/inkyos/system.json"
            with self.contract.tree() as tree:
                raw = tree.read(path, 0o600, 4096)
            state = json.loads(raw, object_pairs_hook=unique)
            require(type(state) is dict and set(state) == {"version", "hostname"})
            hostname = state["hostname"]
            require(
                state["version"] == 1 and re.fullmatch(r"inky-[0-9a-f]{32}", hostname)
            )
            with self.contract.tree() as tree:
                require(
                    tree.read("etc/hostname", 0o644, 256)
                    == (hostname + "\n").encode("ascii")
                )
            require(os.uname().nodename == hostname)
            owner = self.command.owner("org.freedesktop.Avahi")

            def avahi(method):
                return shlex.split(
                    self.command.bus(
                        "org.freedesktop.Avahi",
                        "/",
                        "org.freedesktop.Avahi.Server",
                        method,
                    ).decode("ascii")
                )

            require(
                avahi("GetState") == ["i", "2"]
                and avahi("GetHostNameFqdn") == ["s", hostname + ".local"]
            )
            raw = self.command.bus(NM, NMPATH, NM, "GetDeviceByIpIface", "s", "wlan0")
            tokens = shlex.split(raw.decode("ascii"))
            require(len(tokens) == 2 and tokens[0] == "o")
            require(
                self.command.prop(NM, tokens[1], NM + ".Device", "State", "u") == 100
                and self.command.owner("org.freedesktop.Avahi") == owner
            )
            return "https://" + hostname + ".local:8443"
        except Exception:
            return None
