#!/usr/bin/python3 -I
"""Targeted TEST LAN EEPROM observation; inactive unless --live is selected.

No driver/application imports, scans, SPI, refresh or EEPROM programming.
The fixed pointer-position transaction and 29-byte read reproduce Inky 2.3.0
read_eeprom. This tool does not activate services or qualify hardware.
"""

import sys
sys.dont_write_bytecode = True

import argparse
import ctypes
import fcntl
import hashlib
import json
import os
import select
import signal
import stat
import struct
import time


HELPER_PATH = "/usr/local/lib/inkyos/test-lan-preflight.py"
DEVICE_PATH = "/dev/i2c-1"
I2C_SLAVE = 0x0703
I2C_SMBUS = 0x0720
I2C_BLOCK = 8
ADDRESS = 0x50
SAMPLE_BYTES = 29
BUS_TIMEOUT = 2.0
GUARD_BUDGET = 6.0
CHECKS = ("prepared_profile", "exact_payload_pin", "firstboot_success",
          "app_stopped_and_masked", "helper_stopped_and_masked")
CATALOGUE = {
    (800, 480, 5, 20): ("AC073TC1A", "7colour", "inky.inky_ac073tc1a.Inky"),
    (1600, 1200, 6, 21): ("EL133UF1", "spectra6", "inky.inky_el133uf1.Inky"),
    (800, 480, 6, 22): ("E673", "spectra6", "inky.inky_e673.Inky"),
    (600, 400, 6, 25): ("E640", "spectra6", "inky.inky_e640.Inky"),
}
LIMITATIONS = (
    "EEPROM contents are unsigned declarations, not proof of the connected panel or driver operation.",
    "The payload pin verifies declarations and the manifest, not every installed application file.",
    "The fixed I2C write positions the read pointer; EEPROM data bytes are not programmed.",
    "Timeout bounds the caller; uninterruptible kernel I/O may leave a child transaction pending.",
    "PCB revision and the EEPROM timestamp are ignored and never exported.",
    "No scan, driver import, SPI, display refresh, service activation or qualification is performed.",
    "Fixture observations are not live hardware evidence; this output never authorizes activation.",
    "Service checks are observations without a lock against concurrent operator changes.",
)


class ObservationError(ValueError):
    pass


class SafeParser(argparse.ArgumentParser):
    def error(self, _message):
        raise ObservationError("invalid_arguments")


def parse_eeprom(raw):
    """Decode only reviewed fields; the 22p timestamp is discarded verbatim."""
    if type(raw) is not bytes or len(raw) != SAMPLE_BYTES:
        raise ObservationError("eeprom_invalid")
    width, height, color, _pcb, variant, _timestamp = struct.unpack("<HHBBB22p", raw)
    mapped = CATALOGUE.get((width, height, color, variant))
    if mapped is None:
        raise ObservationError("eeprom_unreviewed")
    reference, color_name, driver = mapped
    return {"display_variant": variant, "panel_reference": reference,
            "width": width, "height": height, "color_code": color,
            "color": color_name, "driver_class": driver}


# ABI pinned to Raspberry Pi Linux cff533aec2fa601846766b32ff57204e0a61bed7:
# include/uapi/linux/i2c-dev.h (request) and i2c.h (union and constants).
# Inky v2.3.0/inky/eeprom.py defines the exact write/read sequence and format;
# v2.3.0/inky/auto.py defines the four declared driver classes (never imported).
class SMBusData(ctypes.Union):
    _fields_ = [("byte", ctypes.c_uint8), ("word", ctypes.c_uint16),
                ("block", ctypes.c_uint8 * 34)]


class SMBusRequest(ctypes.Structure):
    _fields_ = [("read_write", ctypes.c_uint8), ("command", ctypes.c_uint8),
                ("size", ctypes.c_uint32), ("data", ctypes.POINTER(SMBusData))]


def abi_supported():
    pointer = ctypes.sizeof(ctypes.c_void_p)
    return (pointer in {4, 8} and ctypes.sizeof(SMBusData) == 34
            and SMBusRequest.read_write.offset == 0 and SMBusRequest.command.offset == 1
            and SMBusRequest.size.offset == 4 and SMBusRequest.data.offset == 8
            and ctypes.sizeof(SMBusRequest) == (16 if pointer == 8 else 12))


class LinuxI2C:
    """Fixed-device stdlib ioctl equivalent, injectable only through Python API."""
    def __init__(self, *, opener=os.open, metadata=os.fstat, ioctl=fcntl.ioctl, closer=os.close):
        self.opener, self.metadata, self.ioctl, self.closer = opener, metadata, ioctl, closer

    def sample(self):
        if not abi_supported():
            raise ObservationError("abi_unverified")
        fd = self.opener(DEVICE_PATH, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            info = self.metadata(fd)
            if (not stat.S_ISCHR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o007
                    or os.major(info.st_rdev) != 89 or os.minor(info.st_rdev) != 1):
                raise ObservationError("device_unverified")
            # No I2C_SLAVE_FORCE, retries, timeout ioctl, scan or other address.
            self.ioctl(fd, I2C_SLAVE, ADDRESS)
            data = SMBusData()
            request = SMBusRequest(0, 0, I2C_BLOCK, ctypes.pointer(data))
            data.block[0], data.block[1] = 1, 0
            self.ioctl(fd, I2C_SMBUS, request)
            data = SMBusData()
            request = SMBusRequest(1, 0, I2C_BLOCK, ctypes.pointer(data))
            data.block[0] = SAMPLE_BYTES
            self.ioctl(fd, I2C_SMBUS, request)
            if data.block[0] != SAMPLE_BYTES:
                raise ObservationError("eeprom_invalid")
            return bytes(data.block[1:SAMPLE_BYTES + 1])
        finally:
            self.closer(fd)


def _reap(pid, deadline):
    while True:
        try:
            found, _status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return True
        if found == pid:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.005)


def bounded_sample(reader, *, timeout=BUS_TIMEOUT):
    """A child owns the bus FD; parent never blocks indefinitely on ioctl/close."""
    read_fd, write_fd = os.pipe()
    pid = None
    deadline = time.monotonic() + min(BUS_TIMEOUT, max(0.01, timeout))
    try:
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            try:
                raw = reader()
                payload = b"S" + raw if type(raw) is bytes and len(raw) == SAMPLE_BYTES else b"E"
                os.write(write_fd, payload)
            except BaseException:
                try:
                    os.write(write_fd, b"E")
                except OSError:
                    pass
            finally:
                os.close(write_fd)
                os._exit(0)
        os.close(write_fd)
        write_fd = None
        ready, _write, _error = select.select([read_fd], [], [], max(0, deadline - time.monotonic()))
        payload = os.read(read_fd, SAMPLE_BYTES + 2) if ready else b""
        exited = _reap(pid, deadline)
        if not exited:
            raise ObservationError("eeprom_timeout")
        pid = None
        if payload[:1] != b"S" or len(payload) != SAMPLE_BYTES + 1:
            raise ObservationError("eeprom_unavailable")
        return payload[1:]
    finally:
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)
        if pid is not None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            # Kernel D-state I/O may remain pending. Never waitpid without
            # WNOHANG or claim the kernel transaction was cancelled.
            _reap(pid, time.monotonic() + 0.25)


def load_helpers():
    """Execute only the fixed installed, root-owned public preflight helper."""
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
        file_fd = os.open(HELPER_PATH.rsplit("/", 1)[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        before = os.fstat(file_fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022
                or before.st_nlink != 1 or before.st_size > 65536):
            raise ObservationError("helpers_unavailable")
        raw = bytearray()
        while len(raw) <= 65536:
            chunk = os.read(file_fd, min(4096, 65537 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(file_fd)
        stamp = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        current = os.stat(HELPER_PATH.rsplit("/", 1)[1], dir_fd=fd, follow_symlinks=False)
        if len(raw) > 65536 or stamp(before) != stamp(after) or stamp(after) != stamp(current):
            raise ObservationError("helpers_unavailable")
        namespace = {"__name__": "inkyos_observer_preflight_helpers", "__file__": HELPER_PATH}
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
        facts = {key: False for key in CHECKS}
        store = None
        own_store = self.store is None
        try:
            helpers = self.helpers if self.helpers is not None else load_helpers()
            store = self.store or helpers["ReadStore"]("/")
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
            facts["exact_payload_pin"] = (hashlib.sha256(manifest).hexdigest() == digest
                and declaration in {source.encode(), (source + "\n").encode()})
            if not facts["exact_payload_pin"]:
                return facts
            command = self.command or helpers["bounded_command"]
            deadline = self.monotonic() + GUARD_BUDGET
            expected = {
                "firstboot": ("firstboot_success", {"ActiveState": "active", "SubState": "exited", "LoadState": "loaded", "Result": "success", "ExecMainStatus": "0"}),
                "app": ("app_stopped_and_masked", {"ActiveState": "inactive", "SubState": "dead", "LoadState": "masked", "UnitFileState": "masked"}),
                "helper": ("helper_stopped_and_masked", {"ActiveState": "inactive", "SubState": "dead", "LoadState": "masked", "UnitFileState": "masked"}),
            }
            for key, (check, wanted) in expected.items():
                remaining = deadline - self.monotonic()
                if remaining <= 0:
                    break
                raw = command(helpers["COMMANDS"][key], timeout=min(2.0, remaining), limit=16384)
                if type(raw) is str and len(raw) <= 16384:
                    facts[check] = helpers["_properties"](raw, set(wanted)) == wanted
            return facts
        except Exception:
            return facts
        finally:
            if own_store and store is not None:
                store.close()


class ProductionAdapter:
    def sample(self):
        return bounded_sample(LinuxI2C().sample)


def observe(adapter=None, guard=None, *, live=False):
    facts = {key: False for key in CHECKS}
    output = {"schema_version": 1, "kind": "test-panel-observation", "scope": "eeprom_declaration_only",
              "live_selected": live is True, "observation_source": "inactive", "live_evidence": False,
              "checks": {}, "panel": None, "passed": False, "status": "BLOCKED",
              "activation_authorized": False, "hardware_qualified": False, "release_qualified": False,
              "error": None, "limitations": list(LIMITATIONS)}
    if live is True:
        native = type(adapter) is ProductionAdapter and type(guard) is PreparedGuard and guard.native_live
        output["observation_source"] = "live-system" if native else "fixture"
        try:
            observed = guard.collect() if guard is not None else {}
            if type(observed) is dict:
                facts = {key: observed.get(key) is True for key in CHECKS}
            if all(facts.values()) and adapter is not None:
                output["panel"] = parse_eeprom(adapter.sample())
                output["passed"], output["status"] = True, "PASS"
                output["live_evidence"] = native
        except ObservationError as error:
            allowed = {"eeprom_invalid", "eeprom_unreviewed", "eeprom_timeout", "eeprom_unavailable"}
            output["error"] = str(error) if str(error) in allowed else "observation_unavailable"
        except Exception:
            output["error"] = "observation_unavailable"
    for key, passed in facts.items():
        output["checks"][key] = {"passed": passed, "status": "PASS" if passed else "BLOCKED"}
    return output


def main(argv=None):
    parser = SafeParser(prog="observe-test-panel.py", description=__doc__, allow_abbrev=False)
    parser.add_argument("--live", action="store_true")
    try:
        args = parser.parse_args(argv)
        if args.live and sys.platform.startswith("linux") and os.geteuid() == 0:
            output = observe(ProductionAdapter(), PreparedGuard(), live=True)
        else:
            output = observe(live=args.live)
            if args.live:
                output["error"] = "linux_root_required"
        code = 0 if output["passed"] else 1
    except ObservationError:
        output = observe()
        output["error"] = "invalid_arguments"
        code = 2
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    sys.exit(main())
