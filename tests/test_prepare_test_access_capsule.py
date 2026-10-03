"""Local preparation with real disposable signatures; no Wi-Fi or SD access."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / 'scripts/prepare-test-access-capsule.py'
SPEC = importlib.util.spec_from_file_location('prepare_test_access_capsule', SOURCE)
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)


@unittest.skipUnless(Path('/usr/bin/ssh-keygen').is_file() and os.geteuid() != 0,
                     'Requires an unprivileged local OpenSSH signing client')
class PreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        cls.key_root = Path(cls.keys.name).resolve()
        for name in ('operator', 'other'):
            subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', '',
                            '-f', str(cls.key_root / name)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.key = self.root / 'operator'
        shutil.copyfile(self.key_root / 'operator', self.key)
        self.key.chmod(0o600)
        self.context = {'schema_version': 1, 'kind': 'verified-test-access-context',
            'operator_public_key': (self.key_root / 'operator.pub').read_text().strip(),
            'bindings': {'profile_sha256': 'a' * 64, 'challenge': 'b' * 64,
                'host_public_key_sha256': 'c' * 64, 'application_source_commit': 'd' * 40,
                'application_manifest_sha256': 'e' * 64, 'access_runtime_manifest_sha256': 'f' * 64}}
        self.network = {'ssid': 'Synthetic test network', 'psk': 'fixture password only'}
        self.context_path = self.write('context.json', self.context)
        self.network_path = self.write('network.json', self.network)
        self.output = self.root / 'prepared'

    def write(self, name, value):
        path = self.root / name
        path.write_bytes(prepare.contract.canonical(value))
        path.chmod(0o600)
        return path

    def run_prepare(self):
        return prepare.prepare(self.context_path, self.network_path, self.key, self.output)

    def assert_private_result(self, result):
        output = json.dumps(result)
        for value in (self.network['ssid'], self.network['psk'], str(self.root),
                      self.context['operator_public_key']):
            self.assertNotIn(value, output)
        for field in ('context_provenance_verified', 'copied_to_sd', 'connection_authorized',
                      'application_activation_authorized', 'hardware_qualified', 'release_qualified'):
            self.assertIs(result[field], False)

    def test_prepares_real_verified_private_capsule_and_preserves_inputs(self):
        before = {path: path.read_bytes() for path in (self.context_path, self.network_path, self.key)}
        result = self.run_prepare()
        self.assertTrue(result['prepared'], result)
        self.assertTrue(result['operator_signature_verified'])
        self.assert_private_result(result)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertEqual({p.name for p in self.output.iterdir()},
                         {'INKYACC.JSN', 'INKYACC.SIG', 'INKYACC.JSN.sig', 'signature-verification.json'})
        for path in self.output.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        raw = (self.output / 'INKYACC.JSN').read_bytes()
        value = prepare.contract.parse_capsule(raw, expected=self.context['bindings'])
        self.assertEqual(bytes.fromhex(value['wifi']['ssid_hex']).decode(), self.network['ssid'])
        self.assertEqual(value['wifi']['psk'], self.network['psk'])
        verification = json.loads((self.output / 'signature-verification.json').read_bytes())
        self.assertTrue(verification['operator_data_authenticated'])
        self.assertIs(verification['connection_authorized'], False)
        self.assertNotIn('prepared', verification)
        for path, old in before.items():
            self.assertEqual(path.read_bytes(), old)

    def test_existing_output_refused_without_overwriting_anything(self):
        self.output.mkdir(mode=0o700)
        marker = self.output / 'marker'
        marker.write_text('keep')
        result = self.run_prepare()
        self.assertFalse(result['prepared'])
        self.assertEqual({p.name for p in self.output.iterdir()}, {'marker'})
        self.assertEqual(marker.read_text(), 'keep')

    def test_wrong_signing_key_never_becomes_prepared(self):
        shutil.copyfile(self.key_root / 'other', self.key)
        result = self.run_prepare()
        self.assertFalse(result['prepared'])
        self.assertEqual(result['error'], 'signature_verification_refused')
        self.assertFalse((self.output / 'signature-verification.json').exists())
        self.assert_private_result(result)

    def test_private_input_permissions_and_links_are_enforced(self):
        for target in (self.context_path, self.network_path, self.key):
            with self.subTest(target=target.name):
                target.chmod(0o644)
                result = self.run_prepare()
                self.assertFalse(result['prepared'])
                self.assertFalse(self.output.exists())
                target.chmod(0o600)
        alias = self.root / 'network-alias.json'
        alias.symlink_to(self.network_path.name)
        self.network_path = alias
        self.assertFalse(self.run_prepare()['prepared'])
        self.assertFalse(self.output.exists())

    def test_symlink_parent_and_nonprivate_output_parent_refused(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        self.output = alias / 'prepared'
        self.assertFalse(self.run_prepare()['prepared'])
        self.assertFalse((self.root / 'prepared').exists())
        public = self.root / 'public'
        public.mkdir(mode=0o755)
        self.output = public / 'prepared'
        self.assertFalse(self.run_prepare()['prepared'])
        self.assertFalse(self.output.exists())

    def test_malformed_or_extended_private_inputs_rejected_before_signing(self):
        for network in ({'ssid': 'x', 'psk': 'short'}, {'ssid': 'x' * 33, 'psk': 'fixture only'},
                        {'ssid': 'x', 'psk': 'fixture only', 'command': 'ignored'}):
            with self.subTest(network=network):
                self.write('network.json', network)
                with patch.object(prepare.subprocess, 'run', side_effect=AssertionError('must not sign')):
                    self.assertFalse(self.run_prepare()['prepared'])
                self.assertFalse(self.output.exists())
        self.network_path.write_bytes(b'{"ssid":"x","ssid":"y","psk":"fixture only"}')
        self.assertFalse(self.run_prepare()['prepared'])

    def test_signer_failure_has_closed_error_and_retains_private_evidence(self):
        with patch.object(prepare.subprocess, 'run',
                          side_effect=RuntimeError('synthetic secret should not appear')):
            result = self.run_prepare()
        self.assertFalse(result['prepared'])
        self.assertEqual(result['error'], 'operator_signature_refused')
        self.assertNotIn('synthetic secret', json.dumps(result))
        self.assert_private_result(result)
        self.assertTrue((self.output / 'INKYACC.JSN').exists())
        self.assertFalse((self.output / 'signature-verification.json').exists())

    def test_final_sync_failure_cannot_leave_a_prepared_true_receipt(self):
        native = prepare.os.fsync
        def sync(fd):
            if (self.output / 'signature-verification.json').exists():
                raise OSError('synthetic final sync failure')
            return native(fd)
        with patch.object(prepare.os, 'fsync', side_effect=sync):
            result = self.run_prepare()
        self.assertFalse(result['prepared'])
        self.assertEqual(result['error'], 'private_evidence_refused')
        verification = json.loads((self.output / 'signature-verification.json').read_bytes())
        self.assertTrue(verification['operator_data_authenticated'])
        self.assertNotIn('prepared', verification)
        self.assertIs(verification['connection_authorized'], False)

    def test_key_metadata_change_during_signing_is_refused(self):
        native = prepare.subprocess.run
        def changed(*args, **kwargs):
            value = native(*args, **kwargs)
            self.key.chmod(0o400)
            return value
        with patch.object(prepare.subprocess, 'run', side_effect=changed):
            result = self.run_prepare()
        self.assertFalse(result['prepared'])
        self.assertEqual(result['error'], 'operator_signature_refused')

    def test_cli_reports_no_secrets_and_creates_only_local_data(self):
        result = subprocess.run([sys.executable, str(SOURCE), '--context', str(self.context_path),
            '--network', str(self.network_path), '--operator-key', str(self.key), '--output', str(self.output)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b'')
        self.assert_private_result(json.loads(result.stdout))

    def test_cli_rejects_arguments_without_echoing_values(self):
        result = subprocess.run([sys.executable, str(SOURCE), '--psk', 'synthetic-do-not-print'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 64)
        self.assertNotIn(b'synthetic-do-not-print', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
