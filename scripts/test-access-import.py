#!/usr/bin/python3 -I
"""Consume one signed TEST capsule into a private durable cache, without network.

The FAT files are data only and remain untouched. A fully committed cache can
be reused; partial state is preserved and requires explicit review. Nothing
here starts NetworkManager, SSH, the application, or a display driver.
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


BASE = "/usr/local/lib/inkyos/"
LEGACY = BASE + "test-enrollment-firstboot.py"
LEGACY_SHA256 = "081bac2c04d4e72a6e74a365664b72941fa4d1e84d1ccc32cf0dc25d9e8a337a"
MANIFEST = "/usr/local/share/inkyos/test-access-manifest.json"
PROFILE = "/etc/inkyos-test-enrollment/profile.json"
ENROLLED = "/var/lib/inkyos-test-enrollment/state.json"
HOST_PUBLIC = "/etc/inkyos-test-enrollment/ssh_host_ed25519_key.pub"
SYSTEM = "/var/lib/inkyos/system.json"
CACHE = "/var/lib/inkyos-test-access"
STATE = "state.json"
CAPSULE = "capsule.json"
SIGNATURE = "capsule.sig"
NETWORK = "network.nmconnection"
UUID = "ea14df0f-8d69-4f38-8716-16576575e39f"
MANIFEST_FIELDS = {"schema_version", "kind", "application_source_commit",
                   "application_manifest_sha256", "parent_image_sha256", "files"}
STATIC_PATHS = frozenset({
    *("usr/local/lib/inkyos/" + name + ".py" for name in (
        "test-enrollment-firstboot", "test-access-policy", "test-access-enrollment",
        "test-access-contract", "test-access-import", "test-access-connect", "test-access-boot",
        "test-access-network", "test-access-wifi-gate", "wifi-boot-gate", "test-lan-preflight",
        "observe-test-panel", "observe-test-radio")),
    "usr/local/lib/inkyos-test-ssh/dispatch.py", "usr/local/lib/inkyos-test-ssh/runner",
    "usr/lib/systemd/system/inkyos-test-access.service", "usr/lib/systemd/system/inkyos-test-ssh.service",
    "etc/systemd/system/NetworkManager.service.d/10-inkyos-test-wifi.conf",
    "etc/NetworkManager/conf.d/10-inkyos-test-loopback.conf",
    "etc/inkyos-test-ssh/sshd_config", "etc/sudoers.d/inkyos-test-ssh",
})
STATE_FIELDS = {"schema_version", "kind", "state", "profile_sha256", "host_public_key_sha256",
                "access_runtime_manifest_sha256", "capsule_sha256", "signature_sha256", "network_sha256"}
ERRORS = {"target_unverified", "sources_invalid", "enrollment_invalid", "operation_busy",
          "capsule_absent", "capsule_invalid", "signature_invalid", "cache_invalid", "review_required",
          "state_changed", "import_failed", "invalid_arguments"}


class ImportError(ValueError):
    pass


def require(value, code="cache_invalid"):
    if value is not True:
        raise ImportError(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load_legacy():
    """Bootstrap the existing audited safe reader before reading any manifest."""
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fd = None
    try:
        for part in LEGACY.strip("/").split("/")[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
            info = os.fstat(directory)
            require(info.st_uid == 0 and not info.st_mode & 0o022, "sources_invalid")
        fd = os.open(LEGACY.rsplit("/", 1)[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0
                and stat.S_IMODE(info.st_mode) == 0o555 and info.st_size <= 65536, "sources_invalid")
        raw = os.read(fd, 65537)
        require(len(raw) == info.st_size and digest(raw) == LEGACY_SHA256, "sources_invalid")
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)
    namespace = {"__name__": "inkyos_access_legacy", "__file__": LEGACY}
    exec(compile(raw, LEGACY, "exec"), namespace)
    return namespace


def network_profile(wifi):
    """PRIVATE bytes. Decimal SSID bytes and derived hex PSK avoid INI escaping."""
    require(type(wifi) is dict and set(wifi) == {"security", "band", "ssid_hex", "psk"}, "capsule_invalid")
    require(wifi["security"] == "wpa2-personal" and wifi["band"] == "2.4GHz", "capsule_invalid")
    require(type(wifi["ssid_hex"]) is str and re.fullmatch(r"(?:[0-9a-f]{2}){1,32}", wifi["ssid_hex"]) is not None,
            "capsule_invalid")
    ssid = bytes.fromhex(wifi["ssid_hex"])
    psk = wifi["psk"]
    require(type(psk) is str and (re.fullmatch(r"[\x20-\x7e]{8,63}", psk) is not None
            or re.fullmatch(r"[0-9a-f]{64}", psk) is not None), "capsule_invalid")
    if len(psk) != 64:
        psk = hashlib.pbkdf2_hmac("sha1", psk.encode("ascii"), ssid, 4096, 32).hex()
    return (f"[connection]\nid=inkyos-test-access\nuuid={UUID}\ntype=wifi\n"
            "interface-name=wlan0\nautoconnect=false\n\n[wifi]\nmode=infrastructure\nband=bg\nssid="
            + ";".join(str(byte) for byte in ssid) + ";\n\n[wifi-security]\nkey-mgmt=wpa-psk\nproto=rsn;\npsk="
            + psk + "\n\n[ipv4]\nmethod=auto\n\n[ipv6]\nmethod=auto\n").encode("ascii")


def state_record(expected, raw, signature, network, phase):
    return {"schema_version": 1, "kind": "test-access-import-state", "state": phase,
            **{key: expected[key] for key in ("profile_sha256", "host_public_key_sha256", "access_runtime_manifest_sha256")},
            "capsule_sha256": digest(raw), "signature_sha256": digest(signature), "network_sha256": digest(network)}


def valid_state(value, expected):
    return (type(value) is dict and set(value) == STATE_FIELDS and type(value["schema_version"]) is int
            and value["schema_version"] == 1 and value["kind"] == "test-access-import-state"
            and type(value["state"]) is str and value["state"] in {"importing", "imported", "review-required"}
            and all(type(value[key]) is str and re.fullmatch(r"[0-9a-f]{64}", value[key]) is not None
                    for key in STATE_FIELDS if key.endswith("_sha256"))
            and all(value[key] == expected[key] for key in
                    ("profile_sha256", "host_public_key_sha256", "access_runtime_manifest_sha256")))


class NativeAdapter:
    def __init__(self):
        self.lib = self.files = self.directory = None
        self.snapshot = {}
        self.state_stamp = None

    def target(self):
        if not (sys.platform.startswith("linux") and platform.machine() == "aarch64"
                and sys.byteorder == "little" and os.getuid() == os.geteuid() == 0):
            return False
        self.lib = load_legacy()
        self.files = self.lib["Files"]()
        return self.files.read(self.lib["MODEL_PATH"], limit=128) == self.lib["PI_MODEL"]

    def read_trusted(self, path, mode, *, private=False, limit=65536):
        raw = self.files.read(path, mode=mode, private=private, limit=limit)
        self.snapshot[path] = (raw, mode, private, limit)
        return raw

    def bind(self):
        raw = self.read_trusted(MANIFEST, 0o644)
        manifest = self.lib["strict_json"](raw)
        require(type(manifest) is dict and set(manifest) == MANIFEST_FIELDS
                and type(manifest["schema_version"]) is int and manifest["schema_version"] == 1
                and manifest["kind"] == "test-access-runtime" and type(manifest["files"]) is dict
                and 5 <= len(manifest["files"]) <= 40 and raw == canonical(manifest), "sources_invalid")
        sources = {}
        for relative, item in manifest["files"].items():
            require(type(relative) is str and relative in STATIC_PATHS
                    and type(item) is dict and set(item) == {"sha256", "mode"}
                    and item["mode"] in {"0555", "0644", "0440"}
                    and type(item["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None,
                    "sources_invalid")
            data = self.read_trusted("/" + relative, int(item["mode"], 8))
            require(digest(data) == item["sha256"], "sources_invalid")
            sources["/" + relative] = data
        require(LEGACY in sources and digest(sources[LEGACY]) == LEGACY_SHA256
                and BASE + "test-access-import.py" in sources, "sources_invalid")
        modules = {}
        for name in ("policy", "contract"):
            path = BASE + f"test-access-{name}.py"
            require(path in sources, "sources_invalid")
            ns = {"__name__": "inkyos_access_" + name, "__file__": path}
            exec(compile(sources[path], path, "exec"), ns)
            modules[name] = ns
        self.policy, self.contract = modules["policy"], modules["contract"]
        require((manifest["application_source_commit"], manifest["application_manifest_sha256"], manifest["parent_image_sha256"])
                == (self.policy["SOURCE"], self.policy["MANIFEST_HASH"], self.policy["PARENT_IMAGE_SHA256"]), "sources_invalid")
        profile_raw = self.read_trusted(PROFILE, 0o600, private=True, limit=4096)
        profile = self.policy["strict_json"](profile_raw)
        enrolled = self.read_trusted(ENROLLED, 0o600, private=True, limit=4096)
        require(self.policy["validate_profile"](profile) and profile_raw == self.policy["canonical"](profile)
                and profile["access_runtime_manifest_sha256"] == digest(raw)
                and self.policy["validate_enrolled_state"](enrolled, profile_raw), "enrollment_invalid")
        public_raw = self.read_trusted(HOST_PUBLIC, 0o644, private=True, limit=256)
        match = re.fullmatch(rb"(ssh-ed25519 [A-Za-z0-9+/]{68}) inkyos-test-host\n", public_raw)
        require(match is not None, "enrollment_invalid")
        wire = self.lib["public_key"](match[1].decode("ascii"))
        require(wire is not None, "enrollment_invalid")
        system = self.lib["strict_json"](self.read_trusted(SYSTEM, 0o600, private=True, limit=4096))
        require(type(system) is dict and set(system) == {"version", "hostname"}
                and type(system["version"]) is int and system["version"] == 1
                and type(system["hostname"]) is str and re.fullmatch(r"inky-[0-9a-f]{32}", system["hostname"]) is not None,
                "enrollment_invalid")
        self.operator = profile["operator_public_key"]
        self.expected = {"profile_sha256": digest(profile_raw), "challenge": profile["challenge"],
            "host_public_key_sha256": digest(wire), "application_source_commit": profile["application_source_commit"],
            "application_manifest_sha256": profile["application_manifest_sha256"],
            "access_runtime_manifest_sha256": digest(raw)}
        return dict(self.expected)

    def acquire(self):
        self.directory = self.files.directory(CACHE, private=True)
        try:
            fcntl.flock(self.directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ImportError("operation_busy") from None

    def names(self):
        with os.scandir(self.directory) as entries:
            return {entry.name for entry in entries}

    def read_cache(self, name):
        return self.files.read(CACHE + "/" + name, mode=0o600, private=True, limit=4096)

    def state(self):
        names = self.names()
        if not names:
            return None
        require(names == {STATE, CAPSULE, SIGNATURE, NETWORK}, "review_required")
        raw = self.read_cache(STATE)
        value = self.lib["strict_json"](raw)
        require(raw == canonical(value), "cache_invalid")
        return value

    def capsule(self, *, cached):
        if cached:
            return self.read_cache(CAPSULE), self.read_cache(SIGNATURE)
        directory = self.files.directory("/boot/firmware", fat=True)
        try:
            pid = os.getpid()
            require(self.lib["mount_is_fat"](self.files.read(f"/proc/{pid}/mountinfo", limit=1024**2),
                self.files.read(f"/proc/{pid}/fdinfo/{directory}"), os.fstat(directory).st_dev), "capsule_invalid")
            output = []
            for name, limit in (("INKYACC.JSN", 4096), ("INKYACC.SIG", 2048)):
                try:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                except FileNotFoundError:
                    raise ImportError("capsule_absent") from None
                try:
                    before = os.fstat(fd)
                    self.lib["_metadata"](before, fat=True)
                    require(0 < before.st_size <= limit, "capsule_invalid")
                    raw = os.read(fd, limit + 1)
                    require(len(raw) == before.st_size and self.lib["_stamp"](before) == self.lib["_stamp"](os.fstat(fd))
                            == self.lib["_stamp"](os.stat(name, dir_fd=directory, follow_symlinks=False)), "capsule_invalid")
                    output.append(raw)
                finally:
                    os.close(fd)
            return tuple(output)
        finally:
            os.close(directory)

    def authenticate(self, raw, signature):
        result = self.contract["verify_capsule"](raw, signature, expected=self.expected, operator_public_key=self.operator)
        require(result.get("passed") is True and result.get("operator_data_authenticated") is True, "signature_invalid")
        return self.contract["parse_capsule"](raw, expected=self.expected)

    def unchanged(self):
        return all(data == self.files.read(path, mode=mode, private=private, limit=limit)
                   for path, (data, mode, private, limit) in self.snapshot.items())

    def write_state(self, value):
        self.lib["write_atomic"](self.directory, STATE, canonical(value), replace_stamp=self.state_stamp,
            published=lambda stamp: setattr(self, "state_stamp", stamp))

    def write_cache(self, name, raw):
        self.lib["write_atomic"](self.directory, name, raw)

    def close(self):
        if self.directory is not None:
            os.close(self.directory)
        if self.files is not None:
            self.files.close()


def import_access(adapter):
    result = {"schema_version": 1, "kind": "test-access-import-result", "passed": False,
        "imported": False, "reused_committed_cache": False, "state": "blocked", "error": None,
        "live_evidence": False, "connection_authorized": False, "application_activation_authorized": False,
        "hardware_qualified": False, "release_qualified": False}
    try:
        require(adapter.target() is True, "target_unverified")
        expected = adapter.bind()
        adapter.acquire()
        previous = adapter.state()
        if previous is not None:
            require(valid_state(previous, expected), "cache_invalid")
            require(previous["state"] == "imported", "review_required")
        raw, signature = adapter.capsule(cached=previous is not None)
        value = adapter.authenticate(raw, signature)
        network = network_profile(value["wifi"])
        final = state_record(expected, raw, signature, network, "imported")
        require(adapter.unchanged() is True, "state_changed")
        if previous is None:
            adapter.write_state({**final, "state": "importing"})
            for name, content in ((CAPSULE, raw), (SIGNATURE, signature), (NETWORK, network)):
                adapter.write_cache(name, content)
            require(adapter.unchanged() is True, "state_changed")
            adapter.write_state(final)
        else:
            require(previous == final and adapter.read_cache(NETWORK) == network, "cache_invalid")
        require(adapter.state() == final and adapter.read_cache(CAPSULE) == raw
                and adapter.read_cache(SIGNATURE) == signature and adapter.read_cache(NETWORK) == network
                and adapter.unchanged() is True, "state_changed")
        result.update(passed=True, imported=True, state="imported", reused_committed_cache=previous is not None,
                      live_evidence=type(adapter) is NativeAdapter)
    except (KeyboardInterrupt, SystemExit):
        result.update(error="review_required", state="review-required")
    except Exception as error:
        result["error"] = str(error) if type(error) is ImportError and str(error) in ERRORS else "import_failed"
        if result["error"] in {"review_required", "cache_invalid", "state_changed", "import_failed"}:
            result["state"] = "review-required"
    finally:
        try:
            adapter.close()
        except Exception:
            result.update(passed=False, imported=False, state="review-required", error="import_failed")
    return result


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args:
        result = {"schema_version": 1, "kind": "test-access-import-result", "passed": False, "error": "invalid_arguments"}
    else:
        result = import_access(NativeAdapter())
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
