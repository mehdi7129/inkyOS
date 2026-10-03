#!/usr/bin/python3 -I
"""Private TEST capsule contract; no installer, live CLI or connection grant.

The caller supplies independently verified EXT4 bindings and the operator's
already enrolled raw Ed25519 public key. Neither is taken from the capsule.
parse_capsule returns PRIVATE data: never log it. verify_capsule returns only
a closed receipt. Its success authenticates bytes, not a physical device.
Replay consumption remains the future importer's responsibility. No timestamp
is an authority and no allowed_signers validity window or certificate is used.
SSHSIG provides no confidentiality; the FAT capsule contains a plaintext PSK.

Reviewed OpenSSH 10.0p1 interface and format:
https://github.com/openssh/openssh-portable/blob/V_10_0_P1/ssh-keygen.1
https://github.com/openssh/openssh-portable/blob/V_10_0_P1/PROTOCOL.sshsig
"""
import sys
sys.dont_write_bytecode = True

import base64
import json
import os
import re
import selectors
import stat
import struct
import subprocess
import tempfile
import time


NAMESPACE = "inkyos-test-access-v1"
PRINCIPAL = "inkyos-test-operator"
MAX_CAPSULE = 4096
MAX_SIGNATURE = 2048
VERIFY_TIMEOUT = 3.0
MAX_OUTPUT = 1024
EXPECTED_FIELDS = frozenset({"profile_sha256", "challenge", "host_public_key_sha256",
    "application_source_commit", "application_manifest_sha256", "access_runtime_manifest_sha256"})
FIELDS = (EXPECTED_FIELDS - {"challenge"}) | {"nonce", "schema_version", "kind", "purpose", "country", "wifi"}
ERRORS = frozenset({"bindings_invalid", "capsule_invalid", "public_key_invalid", "signature_invalid",
    "verifier_unavailable", "verification_timeout", "verification_output_excessive", "verification_failed",
    "interrupted"})


class ContractError(ValueError):
    """Closed error codes only; no untrusted values in diagnostics."""


def require(value, error="capsule_invalid"):
    if not value:
        raise ContractError(error)


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("utf-8")


def parse_capsule(raw, *, expected):
    """Validate canonical bytes and all trusted bindings; returns PRIVATE data."""
    require(type(expected) is dict and set(expected) == EXPECTED_FIELDS, "bindings_invalid")
    for key, value in expected.items():
        length = 40 if key == "application_source_commit" else 64
        require(type(value) is str and re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is not None,
                "bindings_invalid")
    require(expected["challenge"] != "0" * 64, "bindings_invalid")
    require(type(raw) is bytes and 0 < len(raw) <= MAX_CAPSULE)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    def invalid(_):
        raise ContractError("capsule_invalid")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_float=invalid, parse_constant=invalid)
        require(type(value) is dict and set(value) == FIELDS and raw == canonical(value))
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise ContractError("capsule_invalid") from None
    require(type(value["schema_version"]) is int and value["schema_version"] == 1
            and value["kind"] == "test-access-capsule" and value["purpose"] == "operator-ssh-only"
            and value["country"] == "FR")
    for key in EXPECTED_FIELDS:
        actual = value["nonce" if key == "challenge" else key]
        require(type(actual) is str and actual == expected[key], "bindings_invalid")
    wifi = value["wifi"]
    require(type(wifi) is dict and set(wifi) == {"security", "band", "ssid_hex", "psk"}
            and wifi["security"] == "wpa2-personal" and wifi["band"] == "2.4GHz")
    require(type(wifi["ssid_hex"]) is str and re.fullmatch(r"(?:[0-9a-f]{2}){1,32}", wifi["ssid_hex"]) is not None)
    psk = wifi["psk"]
    require(type(psk) is str and (re.fullmatch(r"[\x20-\x7e]{8,63}", psk) is not None
                                 or re.fullmatch(r"[0-9a-f]{64}", psk) is not None))
    return value


def _public_key(value):
    require(type(value) is str and re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]{68}", value) is not None,
            "public_key_invalid")
    try:
        wire = base64.b64decode(value.split(" ")[1], validate=True)
    except ValueError:
        raise ContractError("public_key_invalid") from None
    require(len(wire) == 51 and wire[:19] == struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32)
            and base64.b64encode(wire).decode("ascii") == value.split(" ")[1], "public_key_invalid")
    return value


def _bounded_verify(argv, raw):
    """Small stdin fits a pipe; merged diagnostics are bounded and discarded."""
    process = None
    selector = selectors.DefaultSelector()
    try:
        deadline = time.monotonic() + VERIFY_TIMEOUT
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd="/", close_fds=True, env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
        process.stdin.write(raw)
        process.stdin.close()
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        count = 0
        while selector.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, "verification_timeout")
            for key, _events in selector.select(remaining):
                block = os.read(key.fd, min(1024, MAX_OUTPUT + 1 - count))
                if not block:
                    selector.unregister(key.fileobj)
                else:
                    count += len(block)
                    require(count <= MAX_OUTPUT, "verification_output_excessive")
        remaining = deadline - time.monotonic()
        require(remaining > 0, "verification_timeout")
        require(process.wait(timeout=remaining) == 0, "signature_invalid")
    except subprocess.TimeoutExpired:
        raise ContractError("verification_timeout") from None
    except OSError:
        raise ContractError("verifier_unavailable") from None
    finally:
        selector.close()
        if process is not None:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                pass
            for stream in (process.stdin, process.stdout):
                if stream is not None:
                    stream.close()


def _verify(raw, signature, public_key):
    # Do not honor TMPDIR or caller paths. The fixed system temporary parent
    # must be root-owned; sticky mode protects our private child if writable.
    require(sys.platform in {"darwin", "linux"}, "verifier_unavailable")
    parent = "/private/tmp" if sys.platform == "darwin" else "/tmp"
    info = os.lstat(parent)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
            and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX), "verifier_unavailable")
    with tempfile.TemporaryDirectory(prefix="inkyos-access-verify.", dir=parent) as directory:
        info = os.lstat(directory)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o700, "verification_failed")
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            allowed = (PRINCIPAL + ' namespaces="' + NAMESPACE + '" ' + public_key + "\n").encode("ascii")
            for name, data in (("allowed_signers", allowed), ("capsule.sig", signature)):
                file_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                try:
                    os.fchmod(file_fd, 0o600)
                    with os.fdopen(file_fd, "wb", closefd=False) as stream:
                        stream.write(data)
                        stream.flush()
                    os.fsync(file_fd)
                finally:
                    os.close(file_fd)
            # Message bytes stay in memory and go to stdin; no PSK temp file.
            _bounded_verify(("/usr/bin/ssh-keygen", "-q", "-Y", "verify", "-f", directory + "/allowed_signers",
                "-I", PRINCIPAL, "-n", NAMESPACE, "-s", directory + "/capsule.sig"), raw)
        finally:
            os.close(fd)


def verify_capsule(raw, signature, *, expected, operator_public_key):
    """Authenticate private bytes. This receipt is never a connection permit."""
    result = {"schema_version": 1, "kind": "test-access-capsule-verification", "passed": False,
        "operator_data_authenticated": False, "physical_identity_verified": False,
        "connection_authorized": False, "application_activation_authorized": False,
        "factory_authority": False, "hardware_qualified": False, "release_qualified": False,
        "replay_protection_enforced": False, "error": None}
    try:
        parse_capsule(raw, expected=expected)
        public_key = _public_key(operator_public_key)
        require(type(signature) is bytes and 0 < len(signature) <= MAX_SIGNATURE, "signature_invalid")
        _verify(raw, signature, public_key)
        result.update(passed=True, operator_data_authenticated=True)
    except (KeyboardInterrupt, SystemExit):
        result["error"] = "interrupted"
    except Exception as error:
        result["error"] = str(error) if type(error) is ContractError and str(error) in ERRORS else "verification_failed"
    return result


if __name__ == "__main__":
    raise SystemExit("Inactive library; no provisioning or verification CLI.")
