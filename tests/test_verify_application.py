import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/verify-application.py'
spec = importlib.util.spec_from_file_location('verify_application', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ApplicationInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.assets = self.root / 'assets'
        self.assets.mkdir()
        self.manifest = self.root / 'manifest.json'
        self.data = {'schema_version': 1, 'application_version': '0.5.0-rc.2',
                     'source_commit': 'a' * 40, 'assets': [],
                     'compatibility': {**module.TARGET, **{key: 'git:' + 'a' * 40 for key in module.CONTRACTS}},
                     'qualification': {'evidence': []}}
        for role, suffix in module.ROLES.items():
            name = role + suffix
            # Opaque bytes intentionally: this gate does NOT inspect archives.
            content = ('fixture for ' + role).encode()
            (self.assets / name).write_bytes(content)
            self.data['assets'].append({'role': role, 'filename': name,
                                       'size_bytes': len(content),
                                       'sha256': hashlib.sha256(content).hexdigest()})

    def save(self, data=None):
        self.manifest.write_text(json.dumps(self.data if data is None else data))
        return hashlib.sha256(self.manifest.read_bytes()).hexdigest()

    def verify(self):
        return module.verify(self.manifest, self.save(), self.assets)

    def test_exact_inputs_pass_without_granting_qualification(self):
        result = self.verify()
        self.assertTrue(result['passed'])
        self.assertFalse(result['integration_enabled'])
        self.assertFalse(result['evidence_content_verified'])
        self.assertEqual(result['missing_evidence_categories'], ['hardware', 'software'])
        self.assertEqual(len(list(self.assets.iterdir())), 3)

    def test_reviewed_pin_is_required_before_json_is_trusted(self):
        self.save()
        with self.assertRaises(module.ManifestError):
            module.verify(self.manifest, '0' * 64, self.assets)

    def test_corrupt_or_missing_asset_fails_and_stays_untouched(self):
        path = self.assets / self.data['assets'][0]['filename']
        path.write_bytes(b'X' * path.stat().st_size)
        with self.assertRaises(module.ManifestError):
            self.verify()
        self.assertTrue(path.read_bytes().startswith(b'X'))
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.verify()

    def test_roles_extensions_paths_and_sizes_are_strict(self):
        mutations = [('filename', '../escape.tar.gz'), ('filename', '/absolute.tar.gz'),
                     ('filename', 'wheelhouse.tar.gz\n'), ('filename', 'app.zip'),
                     ('role', 'wheelhouse'), ('size_bytes', True),
                     ('size_bytes', module.MAX_ASSET + 1), ('sha256', 'latest')]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                altered = copy.deepcopy(self.data)
                altered['assets'][0][key] = value
                with self.assertRaises(module.ManifestError):
                    module.validate_manifest(altered)

    def test_incompatible_python_architecture_and_contracts_fail(self):
        for key, value in (('architecture', 'amd64'), ('python_minor', '3.11'),
                           ('debian_release', 'bookworm'), ('ble_contract', 'pending')):
            with self.subTest(key=key):
                altered = copy.deepcopy(self.data)
                altered['compatibility'][key] = value
                with self.assertRaises(module.ManifestError):
                    module.validate_manifest(altered)

    def test_source_version_and_unknown_fields_fail(self):
        for key, value in (('schema_version', True), ('source_commit', 'a' * 7),
                           ('application_version', 'latest'), ('extra', 'unreviewed')):
            with self.subTest(key=key):
                altered = copy.deepcopy(self.data)
                altered[key] = value
                with self.assertRaises(module.ManifestError):
                    module.validate_manifest(altered)

    def test_duplicate_json_key_is_rejected(self):
        self.save()
        self.manifest.write_text(self.manifest.read_text().replace('"schema_version": 1',
                                 '"schema_version": 2, "schema_version": 1'))
        digest = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        with self.assertRaises(module.ManifestError):
            module.verify(self.manifest, digest, self.assets)

    def test_symlink_and_fifo_inputs_are_not_followed(self):
        path = self.assets / self.data['assets'][0]['filename']
        outside = self.root / 'outside'
        outside.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(outside)
        with self.assertRaises(OSError):
            self.verify()
        path.unlink()
        os.mkfifo(path)
        with self.assertRaises(module.ManifestError):
            self.verify()
        self.assertEqual(outside.read_bytes(), b'fixture for application')

    def test_evidence_is_only_declared_and_urls_cannot_hold_credentials(self):
        record = {'kind': 'hardware', 'name': 'Fixture evidence',
                  'url': 'https://example.invalid/review/report.json', 'sha256': 'b' * 64}
        self.data['qualification']['evidence'] = [record]
        result = self.verify()
        self.assertEqual(result['evidence_counts']['hardware'], 1)
        self.assertFalse(result['evidence_content_verified'])
        for url in ('http://example.invalid/file', 'https://user:password@example.invalid/file',
                    'https://example.invalid/file?token=private'):
            record['url'] = url
            with self.assertRaises(module.ManifestError):
                self.verify()

    def test_cli_refuses_overwrite_and_output_in_bundle(self):
        pin = self.save()
        base = [sys.executable, str(SCRIPT), '--manifest', str(self.manifest),
                '--sha256', pin, '--assets-dir', str(self.assets)]
        output = self.root / 'result.json'
        first = subprocess.run(base + ['--output', str(output)], capture_output=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        before = output.read_bytes()
        self.assertNotEqual(subprocess.run(base + ['--output', str(output)], capture_output=True).returncode, 0)
        self.assertEqual(output.read_bytes(), before)
        nested = self.assets / 'report.json'
        self.assertNotEqual(subprocess.run(base + ['--output', str(nested)], capture_output=True).returncode, 0)
        self.assertFalse(nested.exists())


if __name__ == '__main__':
    unittest.main()
