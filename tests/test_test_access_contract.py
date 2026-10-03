"""Closed capsule parsing and real SSHSIG with disposable Ed25519 keys only."""
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("test_capsule_contract", ROOT / "scripts/test-access-contract.py")
contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract)


def expected():
    return {"profile_sha256": "1" * 64, "challenge": "2" * 64, "host_public_key_sha256": "3" * 64,
        "application_source_commit": "4" * 40, "application_manifest_sha256": "5" * 64,
        "access_runtime_manifest_sha256": "6" * 64}


def capsule():
    context = expected()
    return {"schema_version": 1, "kind": "test-access-capsule", "purpose": "operator-ssh-only",
        "nonce": context.pop("challenge"), **context, "country": "FR",
        "wifi": {"security": "wpa2-personal", "band": "2.4GHz", "ssid_hex": "54455354", "psk": "fixture-ONLY-secret"}}


class ParseTests(unittest.TestCase):
    def parse(self, value):
        return contract.parse_capsule(contract.canonical(value), expected=expected())

    def test_canonical_format_and_private_return(self):
        value = capsule()
        self.assertEqual(contract.canonical(value), (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode())
        self.assertEqual(self.parse(value), value)

    def test_all_bindings_must_match_and_trusted_context_is_closed(self):
        for key in expected():
            value = capsule()
            value["nonce" if key == "challenge" else key] = "7" * len(expected()[key])
            with self.subTest(key=key), self.assertRaisesRegex(contract.ContractError, "^bindings_invalid$"):
                self.parse(value)
        for context in (None, [], {}, {**expected(), "extra": "SECRET"},
                        {**expected(), "challenge": "0" * 64}, {**expected(), "challenge": True},
                        {**expected(), "application_source_commit": "F" * 40}):
            with self.assertRaisesRegex(contract.ContractError, "^bindings_invalid$"):
                contract.parse_capsule(contract.canonical(capsule()), expected=context)

    def test_unknown_missing_fields_and_scalar_types_rejected(self):
        for key in capsule():
            value = capsule()
            value.pop(key)
            with self.subTest(key=key), self.assertRaises(contract.ContractError):
                self.parse(value)
        for key, bad in (("schema_version", True), ("schema_version", 1.0), ("schema_version", "1"),
                         ("kind", "OTHER"), ("purpose", "factory"), ("country", "US"),
                         ("country", True), ("wifi", []), ("nonce", None), ("extra", "SECRET")):
            with self.subTest(key=key, bad=bad), self.assertRaises(contract.ContractError):
                self.parse({**capsule(), key: bad})

    def test_wifi_types_and_security_are_closed(self):
        for change in ({"extra": "SECRET"}, {"security": "wpa3-personal"}, {"security": True},
                       {"band": "5GHz"}, {"ssid_hex": ""}, {"ssid_hex": "1"}, {"ssid_hex": "AA"},
                       {"ssid_hex": "00" * 33}, {"ssid_hex": True}, {"psk": "short"},
                       {"psk": "x" * 64}, {"psk": "x" * 65}, {"psk": "bad\nsecret"},
                       {"psk": "nonasciié"}, {"psk": "x" * 7 + "\x7f"}, {"psk": True}):
            value = capsule()
            value["wifi"].update(change)
            with self.subTest(change=change), self.assertRaises(contract.ContractError):
                self.parse(value)
        value = capsule()
        value["wifi"].pop("band")
        with self.assertRaises(contract.ContractError):
            self.parse(value)

    def test_valid_psk_and_ssid_boundaries(self):
        for psk in ("12345678", "x" * 63, "0123456789abcdef" * 4, ' spaces;\\" literal '):
            for ssid in ("00", "ff" * 32):
                value = capsule()
                value["wifi"].update(psk=psk, ssid_hex=ssid)
                self.assertEqual(self.parse(value), value)

    def test_noncanonical_duplicates_floats_constants_encoding_and_size(self):
        raw = contract.canonical(capsule())
        bad_values = (raw.rstrip(), b" " + raw, json.dumps(capsule()).encode(),
            raw.replace(b'"country": "FR",', b'"country": "FR", "country": "FR",'),
            raw.replace(b'"schema_version": 1', b'"schema_version": 1.0'),
            raw.replace(b'"schema_version": 1', b'"schema_version": NaN'),
            raw.replace(b'"schema_version": 1', b'"schema_version": Infinity'),
            raw.replace(b'"FR"', b'"\\u0046R"'), b'"\xff"', b"", b"[" * 4096,
            raw + b" " * 4096, raw.decode(), bytearray(raw), None)
        for bad in bad_values:
            with self.subTest(kind=type(bad).__name__), self.assertRaisesRegex(contract.ContractError, "^capsule_invalid$"):
                contract.parse_capsule(bad, expected=expected())


class SignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix="inkyos-capsule-test.")
        cls.keys = []
        for name in ("operator", "other"):
            key = Path(cls.work.name) / name
            result = subprocess.run(("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(key)),
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            if result.returncode:
                raise RuntimeError("Disposable key generation failed")
            cls.keys.append(key)
        cls.public = cls.keys[0].with_suffix(".pub").read_text().strip()

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def sign(self, raw, *, namespace=contract.NAMESPACE, key=None):
        result = subprocess.run(("/usr/bin/ssh-keygen", "-q", "-Y", "sign", "-f", str(key or self.keys[0]), "-n", namespace),
                                input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 0, "Disposable signature failed")
        self.assertLessEqual(len(result.stdout), contract.MAX_SIGNATURE)
        return result.stdout

    def verify(self, raw=None, signature=None, **kwargs):
        raw = contract.canonical(capsule()) if raw is None else raw
        signature = self.sign(raw) if signature is None else signature
        return contract.verify_capsule(raw, signature,
            expected=kwargs.pop("expected", expected()), operator_public_key=kwargs.pop("operator_public_key", self.public), **kwargs)

    def test_real_signature_authenticates_data_only_and_no_replay_claim(self):
        raw = contract.canonical(capsule())
        signature = self.sign(raw)
        result = self.verify(raw, signature)
        self.assertTrue(result["passed"])
        self.assertTrue(result["operator_data_authenticated"])
        self.assertIsNone(result["error"])
        self.assertEqual(self.verify(raw, signature), result)  # Future importer consumes the nonce.
        for name in ("physical_identity_verified", "connection_authorized", "application_activation_authorized",
                     "factory_authority", "hardware_qualified", "release_qualified", "replay_protection_enforced"):
            self.assertIs(result[name], False)
        self.assertNotIn(capsule()["wifi"]["psk"], json.dumps(result))
        self.assertNotIn(self.public, json.dumps(result))

    def test_tampered_psk_wrong_key_wrong_namespace_and_truncated_signature(self):
        raw = contract.canonical(capsule())
        changed = capsule()
        changed["wifi"]["psk"] = "different-secret"
        cases = ((contract.canonical(changed), self.sign(raw)),
                 (raw, self.sign(raw, key=self.keys[1])),
                 (raw, self.sign(raw, namespace="other-namespace")), (raw, self.sign(raw)[:40]),
                 (raw, b"private-error-secret"))
        for data, signature in cases:
            result = self.verify(data, signature)
            self.assertFalse(result["passed"])
            self.assertEqual(result["error"], "signature_invalid")

    def test_signature_cannot_override_bindings_or_noncanonical_bytes(self):
        for key in expected():
            value = capsule()
            value["nonce" if key == "challenge" else key] = "7" * len(expected()[key])
            raw = contract.canonical(value)
            self.assertEqual(self.verify(raw, self.sign(raw))["error"], "bindings_invalid")
        raw = json.dumps(capsule()).encode()
        self.assertEqual(self.verify(raw, self.sign(raw))["error"], "capsule_invalid")

    def test_trusted_public_key_is_raw_ed25519_without_options_or_comments(self):
        for bad in (None, True, self.public + " private-comment", 'cert-authority ' + self.public,
                    "ssh-ed25519 " + "A" * 68, self.public + "\n", self.public.replace("ssh-ed25519", "ssh-rsa")):
            self.assertEqual(self.verify(operator_public_key=bad)["error"], "public_key_invalid")
        other_public = self.keys[1].with_suffix(".pub").read_text().strip()
        self.assertEqual(self.verify(operator_public_key=other_public)["error"], "signature_invalid")

    def test_signature_boundaries_fail_before_native_verifier(self):
        raw = contract.canonical(capsule())
        for bad in (b"", b"x" * 2049, "SECRET", None, bytearray(b"SECRET")):
            with patch.object(contract, "_verify") as native:
                result = contract.verify_capsule(raw, bad, expected=expected(), operator_public_key=self.public)
                self.assertEqual(result["error"], "signature_invalid")
                native.assert_not_called()

    def test_private_temp_modes_fixed_command_stdin_and_cleanup(self):
        raw = contract.canonical(capsule())
        signature = self.sign(raw)
        directories = []
        def inspect(argv, message):
            self.assertEqual(message, raw)
            self.assertEqual(argv[:4], ("/usr/bin/ssh-keygen", "-q", "-Y", "verify"))
            self.assertEqual(argv[6:10], ("-I", contract.PRINCIPAL, "-n", contract.NAMESPACE))
            path = Path(argv[5]).parent
            directories.append(path)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            self.assertEqual(path.stat().st_uid, os.geteuid())
            self.assertEqual({p.name for p in path.iterdir()}, {"allowed_signers", "capsule.sig"})
            for entry in path.iterdir():
                self.assertEqual(stat.S_IMODE(entry.stat().st_mode), 0o600)
            allowed = (contract.PRINCIPAL + ' namespaces="' + contract.NAMESPACE + '" ' + self.public + "\n").encode()
            self.assertEqual((path / "allowed_signers").read_bytes(), allowed)
            self.assertEqual((path / "capsule.sig").read_bytes(), signature)
            raise OSError("PRIVATE-DIAGNOSTIC")
        out, err = io.StringIO(), io.StringIO()
        with patch.object(contract, "_bounded_verify", side_effect=inspect), redirect_stdout(out), redirect_stderr(err):
            result = self.verify(raw, signature)
        self.assertEqual(result["error"], "verification_failed")
        self.assertTrue(directories)
        self.assertTrue(all(not path.exists() for path in directories))
        self.assertEqual(out.getvalue() + err.getvalue(), "")
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_real_verifier_wrong_principal_refuses(self):
        raw = contract.canonical(capsule())
        signature = self.sign(raw)
        native = contract._bounded_verify
        def different_principal(argv, message):
            changed = list(argv)
            changed[7] = "different-principal"
            return native(changed, message)
        with patch.object(contract, "_bounded_verify", side_effect=different_principal):
            self.assertEqual(self.verify(raw, signature)["error"], "signature_invalid")

    def test_interruptions_and_internal_errors_are_closed(self):
        for error, code in ((KeyboardInterrupt(), "interrupted"), (SystemExit("SECRET"), "interrupted"),
                            (RuntimeError("SECRET"), "verification_failed"),
                            (contract.ContractError("SECRET"), "verification_failed")):
            with patch.object(contract, "_verify", side_effect=error):
                result = self.verify()
            self.assertEqual(result["error"], code)
            self.assertNotIn("SECRET", json.dumps(result))


class ProcessBoundsTests(unittest.TestCase):
    def test_real_timeout_kills_child_and_discards_its_output(self):
        with patch.object(contract, "VERIFY_TIMEOUT", 0.1):
            with self.assertRaisesRegex(contract.ContractError, "^verification_timeout$"):
                contract._bounded_verify((sys.executable, "-c", "import time; time.sleep(10)"), b"fixture")

    def test_real_excessive_stderr_is_bounded_not_returned(self):
        with self.assertRaisesRegex(contract.ContractError, "^verification_output_excessive$"):
            contract._bounded_verify((sys.executable, "-c", "import os; os.write(2, b'PRIVATE' * 1000)"), b"fixture")

    def test_unavailable_program_error_is_closed(self):
        with self.assertRaisesRegex(contract.ContractError, "^verifier_unavailable$"):
            contract._bounded_verify(("/inkyos-nonexistent-test-program",), b"fixture")


if __name__ == "__main__":
    unittest.main()
