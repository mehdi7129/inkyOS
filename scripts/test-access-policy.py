#!/usr/bin/python3 -I
"""Pure, closed policy for the new private TEST enrollment profile.

This profile permits enrollment and a stop only. A later authenticated capsule
and fresh runtime guards are required for operator access; no image release or
physical qualification is implied. Legacy v1 profiles are intentionally absent.
"""
import base64
import hashlib
import json
import re
import struct


SOURCE = "c31b13afdc957425571810c46230eaaf52fa5d14"
MANIFEST_HASH = "c4183e7304e3ff979450977b36e4a007b30016de68bb23ef121c7ca733cd26a1"
PARENT_IMAGE_SHA256 = "0854663168acf7986d26a473e9116dddeb7d6fbef8226f5d1d96cf190f77e286"
FALSE_FIELDS = ("network_profile_present", "ssh_access_enabled",
                "application_activation_authorized", "hardware_qualified", "release_qualified")
PROFILE_FIELDS = {"schema_version", "kind", "purpose", "state", "application_source_commit",
                  "application_manifest_sha256", "parent_image_sha256", "operator_public_key",
                  "challenge", "country_requested", "access_runtime_manifest_sha256", *FALSE_FIELDS}
STATE_FIELDS = {"schema_version", "kind", "state", "profile_sha256", "application_activation_authorized"}


class PolicyError(ValueError):
    pass


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise PolicyError("invalid_input")
            result[key] = value
        return result
    def invalid(_value):
        raise PolicyError("invalid_input")
    try:
        if type(raw) is not bytes:
            raise PolicyError("invalid_input")
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=invalid, parse_float=invalid)
    except (ValueError, UnicodeError, RecursionError, AttributeError):
        raise PolicyError("invalid_input") from None


def public_key(value):
    """Return the 51-byte canonical SSH Ed25519 wire key, never a file hash."""
    if type(value) is not str or not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]{68}", value):
        return None
    try:
        wire = base64.b64decode(value.split(" ")[1], validate=True)
    except (ValueError, base64.binascii.Error):
        return None
    if (len(wire) != 51 or wire[:19] != struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32)
            or base64.b64encode(wire).decode("ascii") != value.split(" ")[1]):
        return None
    return wire


def _digest(value):
    return (type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None
            and value != "0" * 64)


def validate_profile(data):
    return (type(data) is dict and set(data) == PROFILE_FIELDS
            and type(data["schema_version"]) is int and data["schema_version"] == 2
            and all(type(data[key]) is str for key in ("kind", "purpose", "state", "application_source_commit",
                    "application_manifest_sha256", "parent_image_sha256", "country_requested"))
            and data["kind"] == "test-lan-enrollment" and data["purpose"] == "test-enroll-and-stop"
            and data["state"] == "enrollment-pending"
            and data["application_source_commit"] == SOURCE and data["application_manifest_sha256"] == MANIFEST_HASH
            and data["parent_image_sha256"] == PARENT_IMAGE_SHA256 and data["country_requested"] == "FR"
            and public_key(data["operator_public_key"]) is not None
            and _digest(data["challenge"]) and _digest(data["access_runtime_manifest_sha256"])
            and all(data[name] is False for name in FALSE_FIELDS))


def validate_enrolled_state(raw, profile_raw):
    """Validate the immutable legacy-shaped state bound to a canonical v2 profile."""
    try:
        if (type(raw) is not bytes or not 0 < len(raw) <= 4096
                or type(profile_raw) is not bytes or not 0 < len(profile_raw) <= 4096):
            return False
        profile, state = strict_json(profile_raw), strict_json(raw)
        return (validate_profile(profile) and profile_raw == canonical(profile)
                and type(state) is dict and set(state) == STATE_FIELDS and raw == canonical(state)
                and type(state["schema_version"]) is int and state["schema_version"] == 1
                and type(state["kind"]) is str and state["kind"] == "test-lan-enrollment-state"
                and type(state["state"]) is str and state["state"] == "enrolled"
                and type(state["profile_sha256"]) is str
                and state["profile_sha256"] == hashlib.sha256(profile_raw).hexdigest()
                and state["application_activation_authorized"] is False)
    except (ValueError, UnicodeError, RecursionError, TypeError):
        return False
