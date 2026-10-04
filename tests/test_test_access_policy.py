"""Pure v2 profile/state policy. Public keys are synthetic wire fixtures."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("access_policy_tests", ROOT / "scripts/test-access-policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


def public_key(byte=b"o"):
    return "ssh-ed25519 " + base64.b64encode(
        struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + byte * 32).decode("ascii")


def profile():
    return {"schema_version": 2, "kind": "test-lan-enrollment", "purpose": "test-enroll-and-stop",
            "state": "enrollment-pending", "application_source_commit": policy.SOURCE,
            "application_manifest_sha256": policy.MANIFEST_HASH, "parent_image_sha256": policy.PARENT_IMAGE_SHA256,
            "operator_public_key": public_key(), "challenge": "a" * 64, "country_requested": "FR",
            "access_runtime_manifest_sha256": "b" * 64, **{key: False for key in policy.FALSE_FIELDS}}


def state(profile_raw):
    return {"schema_version": 1, "kind": "test-lan-enrollment-state", "state": "enrolled",
            "profile_sha256": hashlib.sha256(profile_raw).hexdigest(), "application_activation_authorized": False}


class ProfileTests(unittest.TestCase):
    def test_exact_pins_new_schema_and_pure_calls(self):
        self.assertEqual(policy.SOURCE, "c31b13afdc957425571810c46230eaaf52fa5d14")
        self.assertEqual(policy.MANIFEST_HASH, "c4183e7304e3ff979450977b36e4a007b30016de68bb23ef121c7ca733cd26a1")
        self.assertEqual(policy.PARENT_IMAGE_SHA256, "0854663168acf7986d26a473e9116dddeb7d6fbef8226f5d1d96cf190f77e286")
        with mock.patch("builtins.open", side_effect=AssertionError("Pure policy")):
            self.assertTrue(policy.validate_profile(profile()))
        self.assertEqual(set(profile()), policy.PROFILE_FIELDS)
        self.assertEqual(len(policy.PROFILE_FIELDS), 16)

    def test_old_and_crossed_tuples_cannot_be_migrated_implicitly(self):
        old = ("758a2bf7ed099aad41ef35316e53228e797b0b2b",
               "0d587792433d924ad1c4e71af19c2a46279f573791cb690571fa1019e7703551",
               "4cd9d6fa8183dfb8a7a04c350ab3d3366900264fab2fa0dff90192a7e4cc9a04")
        for field, value in zip(("application_source_commit", "application_manifest_sha256", "parent_image_sha256"), old):
            self.assertFalse(policy.validate_profile(dict(profile(), **{field: value})))
        self.assertFalse(policy.validate_profile(dict(profile(), schema_version=1)))

    def test_types_closed_fields_flags_and_intended_purpose(self):
        changes = [{"schema_version": True}, {"kind": "factory"}, {"purpose": "operator-ssh-only"},
                   {"state": "enrolled"}, {"country_requested": "US"}, {"private": "data"}]
        changes += [{name: bad} for name in policy.FALSE_FIELDS for bad in (True, 0, "false", None)]
        for change in changes:
            with self.subTest(change=change):
                self.assertFalse(policy.validate_profile(dict(profile(), **change)))
        for missing in policy.PROFILE_FIELDS:
            value = profile()
            del value[missing]
            self.assertFalse(policy.validate_profile(value))
        for value in (None, [], True, "x", 2):
            self.assertFalse(policy.validate_profile(value))

    def test_challenge_and_manifest_digest_nonzero_exact_lowercase(self):
        for field in ("challenge", "access_runtime_manifest_sha256"):
            for bad in (None, True, 3, "0" * 64, "A" * 64, "a" * 63, "a" * 65, "g" * 64):
                self.assertFalse(policy.validate_profile(dict(profile(), **{field: bad})))

    def test_public_wire_distinguishes_wire_hash_from_public_file_hash(self):
        value = public_key()
        wire = policy.public_key(value)
        self.assertEqual(len(wire), 51)
        self.assertNotEqual(hashlib.sha256(wire).hexdigest(), hashlib.sha256((value + " fixture\n").encode()).hexdigest())
        for bad in (value + " fixture", value + "\n", " " + value, value + "=", True,
                    "ssh-ed25519 " + base64.b64encode(bytes(51)).decode(), "ssh-rsa " + value.split()[1]):
            self.assertIsNone(policy.public_key(bad))
            self.assertFalse(policy.validate_profile(dict(profile(), operator_public_key=bad)))

    def test_strict_json_rejects_duplicate_nonfinite_floats_and_private_errors(self):
        for raw in (b'{"a":1,"a":1}', b'{"a":{"b":1,"b":2}}', b'{"a":NaN}', b'{"a":Infinity}',
                    b'{"a":1.0}', b'{"a":1e2}', b"\xff", b"PRIVATE_INVALID", "{}", bytearray(b"{}")):
            with self.assertRaisesRegex(policy.PolicyError, "^invalid_input$"):
                policy.strict_json(raw)
        self.assertEqual(policy.strict_json(policy.canonical(profile())), profile())


class StateTests(unittest.TestCase):
    def test_state_keeps_schema_one_bound_to_exact_new_profile(self):
        raw = policy.canonical(profile())
        self.assertTrue(policy.validate_enrolled_state(policy.canonical(state(raw)), raw))

    def test_noncanonical_inputs_are_rejected(self):
        raw = policy.canonical(profile())
        self.assertFalse(policy.validate_enrolled_state(json.dumps(state(raw)).encode(), raw))
        noncanonical = json.dumps(profile()).encode()
        self.assertFalse(policy.validate_enrolled_state(policy.canonical(state(noncanonical)), noncanonical))

    def test_pending_partial_review_or_foreign_state_never_authorizes_access(self):
        raw = policy.canonical(profile())
        changes = [{"state": "pending"}, {"state": "review-required"}, {"schema_version": 2},
                   {"schema_version": True}, {"kind": "test-access-state"}, {"profile_sha256": "0" * 64},
                   {"application_activation_authorized": 0}, {"application_activation_authorized": True},
                   {"extra": False}]
        for change in changes:
            self.assertFalse(policy.validate_enrolled_state(policy.canonical(dict(state(raw), **change)), raw))

    def test_state_never_confers_permissions_from_a_changed_profile(self):
        raw = policy.canonical(profile())
        for change in ({"challenge": "b" * 64}, {"access_runtime_manifest_sha256": "c" * 64},
                       {"ssh_access_enabled": True}, {"schema_version": 1}):
            changed = policy.canonical(dict(profile(), **change))
            self.assertFalse(policy.validate_enrolled_state(policy.canonical(state(raw)), changed))

    def test_malformed_oversized_and_nonbytes_inputs_return_false(self):
        raw = policy.canonical(profile())
        valid_state = policy.canonical(state(raw))
        for bad in (None, True, [], b"", b"x" * 4097, b'{"a":NaN}', b"\xff", bytearray(raw)):
            self.assertFalse(policy.validate_enrolled_state(bad, raw))
            self.assertFalse(policy.validate_enrolled_state(valid_state, bad))


if __name__ == "__main__":
    unittest.main()
