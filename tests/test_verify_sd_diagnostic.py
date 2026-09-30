"""Derived exports are synthetic fixtures; no image mounts or disk access occur."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/verify-sd-diagnostic.py'
SPEC = importlib.util.spec_from_file_location('verify_sd_diagnostic', SCRIPT)
diagnostic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostic)
IMAGE = b'synthetic SD diagnostic image; never mounted\n'


def encoded(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def record(raw=b'fixture'):
    return {'type': 'file', 'mode': '0644', 'uid': 0, 'gid': 0,
            'size_bytes': len(raw), 'sha256': digest(raw),
            'xattrs': {'status': 'inspected', 'entries': {}}}


def archive_bytes(blobs, recipe, *, extra=None, omit=None):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        items = {'recipe/' + name: data for name, data in blobs.items()}
        items['recipe/recipe-inputs.json'] = encoded(recipe)
        if extra is not None:
            items.update(extra)
        for name, raw in sorted(items.items()):
            if name == omit:
                continue
            info = tarfile.TarInfo(name); info.size = len(raw); info.mode = 0o444
            archive.addfile(info, io.BytesIO(raw))
    return buffer.getvalue()


def fixture(directory):
    source = {'source_commit': 'a' * 40, 'application_version': '0.5.0-rc.2'}
    source_raw = encoded(source)
    app = {**source, 'manifest_sha256': digest(source_raw), 'startup': 'masked-pending-firstboot-contract',
           'release_qualified': False}
    parent = {'schema_version': 1, 'kind': 'application-prototype', 'hardware_qualified': False,
              'application': app, 'image': {'filename': 'parent.img', 'size_bytes': len(IMAGE), 'sha256': '1' * 64},
              'recipe': {'schema_version': 1, 'source_commit': 'b' * 40, 'worktree_dirty': False,
                         'files': {'application-manifest.json': digest(source_raw)}},
              'reports': {name: '2' * 64 for name in diagnostic.artifacts.REQUIRED_REPORTS
                          | diagnostic.artifacts.APPLICATION_REPORTS}}
    parent_raw = encoded(parent)
    blobs = {name: (name + ' fixture source\n').encode() for name in diagnostic.DIAGNOSTIC_SOURCES}
    blobs.update({'application-manifest.json': source_raw, 'parent-manifest.json': parent_raw})
    recipe = {'schema_version': 1, 'source_commit': 'c' * 40, 'worktree_dirty': True,
              'files': {name: digest(raw) for name, raw in blobs.items()}}
    metadata = {'type': 'directory', 'mode': '0755', 'uid': 0, 'gid': 0,
                'xattrs': {'status': 'inspected', 'entries': {}}}
    filesystem = {'schema_version': 2, 'scope': 'content-and-metadata-without-timestamps',
                  'rootfs': {'.': copy.deepcopy(metadata)}, 'bootfs': {'.': copy.deepcopy(metadata)}}
    protected_lines = []
    for name in sorted(diagnostic.PROTECTED_FILES):
        section, _separator, relative = name.partition('/')
        raw = (name + ' unchanged\n').encode()
        filesystem[section + 'fs'][relative] = record(raw)
        protected_lines.append(digest(raw) + '  ' + name + '\n')
    for name, relative in diagnostic.DIAGNOSTIC_PAYLOADS.items():
        filesystem['rootfs'][relative] = record(blobs[name])
        if name.endswith('.py'):
            filesystem['rootfs'][relative]['mode'] = '0555'
    for unit in diagnostic.DIAGNOSTIC_MASKS:
        filesystem['rootfs']['etc/systemd/system/' + unit] = {
            **copy.deepcopy(metadata), 'type': 'symlink', 'mode': '0777', 'target': '/dev/null'}
    filesystem['rootfs']['etc/systemd/system/timers.target.wants/inkyos-sd-diagnostic.timer'] = {
        **copy.deepcopy(metadata), 'type': 'symlink', 'mode': '0777',
        'target': '/etc/systemd/system/inkyos-sd-diagnostic.timer'}
    config_raw = b'parent config\n\n[all]\nbootloader_update=0\ndtoverlay=disable-wifi\n'
    filesystem['bootfs']['config.txt'] = record(config_raw)
    parent_filesystem = copy.deepcopy(filesystem)
    parent_filesystem['bootfs']['config.txt'] = record(b'parent config\n')
    for relative in diagnostic.DIAGNOSTIC_PAYLOADS.values():
        del parent_filesystem['rootfs'][relative]
    parent_filesystem_raw = encoded(parent_filesystem)
    parent['reports']['filesystem-manifest.json'] = digest(parent_filesystem_raw)
    parent_raw = encoded(parent)
    blobs['parent-manifest.json'] = parent_raw
    recipe['files']['parent-manifest.json'] = digest(parent_raw)
    checks = diagnostic.artifacts.REQUIRED_STATIC_CHECKS | {'BOOT_NO_COUNTRY'}
    static = {'schema_version': 1, 'scope': 'offline-system-prototype-contract', 'passed': True,
              'failed_checks': [], 'checks': [{'id': name, 'passed': True} for name in sorted(checks)]}
    app_static = {'schema_version': 1, 'scope': 'offline-application-prototype-contract', 'passed': True,
                  'failed_checks': [], 'checks': [{'id': name, 'passed': True}
                                                  for name in sorted(diagnostic.artifacts.APPLICATION_CHECKS)],
                  **{key: app[key] for key in ('source_commit', 'application_version', 'manifest_sha256')}}
    configuration = {'schema_version': 1, 'scope': 'offline-sd-diagnostic-configuration', 'passed': True,
                     'parent_image_sha256': parent['image']['sha256'], 'application_started': False,
                     'hardware_qualified': False,
                     'recipe_source_commit': recipe['source_commit'],
                     'recipe_worktree_dirty': recipe['worktree_dirty'],
                     'recipe_inputs_sha256': digest(encoded(recipe)),
                     'source_file_sha256': {name: digest(blobs[name]) for name in diagnostic.DIAGNOSTIC_SOURCES},
                     'checks': {name: True for name in diagnostic.DIAGNOSTIC_CHECKS},
                     'boot_config_delta': {'parent_sha256': digest(b'parent config\n'),
                                           'configured_sha256': digest(config_raw),
                                           'append': '\n\n[all]\nbootloader_update=0\ndtoverlay=disable-wifi\n'}}
    image = {'filename': 'diagnostic.img', 'size_bytes': len(IMAGE), 'sha256': digest(IMAGE)}
    reports = {
        'parent-manifest.json': parent_raw,
        'parent-filesystem-manifest.json': parent_filesystem_raw,
        'parent-integrity.json': encoded({'scope': 'local-export-integrity', 'passed': True,
                                         'image_sha256_verified': True, 'authenticity_verified': False,
                                         'hardware_qualified': False}),
        'recipe.tar': archive_bytes(blobs, recipe),
        'diagnostic-configuration.json': encoded(configuration),
        'qualification-static.json': encoded(static),
        'qualification-application.json': encoded(app_static),
        'application-manifest.json': source_raw,
        'filesystem-manifest.json': encoded(filesystem),
        'image-inspection.json': encoded({'image': image}),
        'systemd-verify.txt': b'fixture syntax pass\n',
        'boot-preserved.sha256': ''.join(protected_lines).encode(),
        'fsck-ext4.txt': b'fixture pass\n', 'fsck-fat.txt': b'fixture pass\n',
    }
    manifest = {'schema_version': 1, 'kind': 'sd-diagnostic', 'hardware_qualified': False,
                'release_qualified': False, 'no_active_application': True, 'application': app,
                'parent': {'kind': parent['kind'], 'image_sha256': parent['image']['sha256'],
                           'size_bytes': parent['image']['size_bytes'], 'manifest_sha256': digest(parent_raw)},
                'image': image, 'recipe': recipe,
                'reports': {name: digest(raw) for name, raw in reports.items()}}
    for name, raw in reports.items():
        (directory / name).write_bytes(raw)
    (directory / image['filename']).write_bytes(IMAGE)
    (directory / 'manifest.json').write_bytes(encoded(manifest))
    (directory / 'recipe-inputs.json').write_bytes(encoded(recipe))
    return manifest, blobs


def rehash_report(directory, name, raw):
    raw = encoded(raw) if isinstance(raw, dict) else raw
    (directory / name).write_bytes(raw)
    manifest = json.loads((directory / 'manifest.json').read_text())
    manifest['reports'][name] = digest(raw)
    (directory / 'manifest.json').write_bytes(encoded(manifest))


class DiagnosticExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.manifest, self.blobs = fixture(self.directory)

    def tearDown(self):
        self.temp.cleanup()

    def test_complete_export_is_inert_and_explicitly_unqualified(self):
        report = diagnostic.load_export(self.directory)['report']
        self.assertTrue(report['passed'])
        self.assertTrue(report['image_sha256_verified'])
        self.assertTrue(report['recipe_source_hashes_verified'])
        self.assertFalse(report['authenticity_verified'])
        self.assertFalse(report['hardware_qualified'])
        self.assertTrue(any('No boot' in value for value in report['limits']))

    def test_reject_image_and_report_tampering(self):
        for name in ('diagnostic.img', 'systemd-verify.txt'):
            with self.subTest(name=name):
                raw = (self.directory / name).read_bytes()
                (self.directory / name).write_bytes(raw[:-1] + b'x')
                with self.assertRaises(diagnostic.ArtifactError):
                    diagnostic.load_export(self.directory)
                (self.directory / name).write_bytes(raw)

    def test_reject_report_symlink(self):
        path = self.directory / 'systemd-verify.txt'
        path.unlink(); path.symlink_to('fsck-fat.txt')
        with self.assertRaises(OSError):
            diagnostic.load_export(self.directory)

    def test_reject_source_tampering_even_with_rehashed_archive(self):
        blobs = dict(self.blobs)
        blobs['diagnostic/sd-diagnostic.py'] = b'changed source'
        rehash_report(self.directory, 'recipe.tar', archive_bytes(blobs, self.manifest['recipe']))
        with self.assertRaisesRegex(diagnostic.ArtifactError, 'source-file'):
            diagnostic.load_export(self.directory)

    def test_reject_recipe_extra_and_missing_members(self):
        for extra, omit in (({'recipe/unreviewed.py': b'bad'}, None),
                            (None, 'recipe/diagnostic/sd-diagnostic.py')):
            with self.subTest(extra=extra, omit=omit):
                rehash_report(self.directory, 'recipe.tar', archive_bytes(self.blobs, self.manifest['recipe'],
                                                                          extra=extra, omit=omit))
                with self.assertRaises(diagnostic.ArtifactError):
                    diagnostic.load_export(self.directory)

    def test_reject_parent_and_active_or_qualified_claims(self):
        for key, value in (('hardware_qualified', True), ('release_qualified', True),
                           ('no_active_application', False), ('kind', 'application-prototype')):
            bad = copy.deepcopy(self.manifest); bad[key] = value
            with self.subTest(key=key), self.assertRaises(diagnostic.ArtifactError):
                diagnostic.validate_manifest(bad)
        self.manifest['parent']['image_sha256'] = '9' * 64
        (self.directory / 'manifest.json').write_bytes(encoded(self.manifest))
        with self.assertRaisesRegex(diagnostic.ArtifactError, 'Parent manifest'):
            diagnostic.load_export(self.directory)

    def test_reject_inconsistent_configuration_checks(self):
        configuration = json.loads((self.directory / 'diagnostic-configuration.json').read_text())
        configuration['checks']['wifi_disabled_diagnostic_only'] = False
        rehash_report(self.directory, 'diagnostic-configuration.json', configuration)
        with self.assertRaisesRegex(diagnostic.ArtifactError, 'configuration PASS'):
            diagnostic.load_export(self.directory)

    def test_reject_static_failed_or_missing_core_check(self):
        static = json.loads((self.directory / 'qualification-static.json').read_text())
        static['checks'] = [check for check in static['checks'] if check['id'] != 'BOOT_NO_COUNTRY']
        rehash_report(self.directory, 'qualification-static.json', static)
        with self.assertRaisesRegex(diagnostic.ArtifactError, 'system static gate'):
            diagnostic.load_export(self.directory)

    def test_reject_mask_loss_and_protected_content_delta(self):
        initial = json.loads((self.directory / 'filesystem-manifest.json').read_text())
        for target in ('mask', 'boot'):
            filesystem = copy.deepcopy(initial)
            if target == 'mask':
                filesystem['rootfs']['etc/systemd/system/inky-studio.service']['target'] = '/usr/lib/active'
            else:
                filesystem['bootfs']['kernel8.img']['sha256'] = '8' * 64
            with self.subTest(target=target):
                rehash_report(self.directory, 'filesystem-manifest.json', filesystem)
                with self.assertRaises(diagnostic.ArtifactError):
                    diagnostic.load_export(self.directory)

    def test_reject_duplicate_json_and_traversal_names(self):
        with self.assertRaises(diagnostic.ArtifactError):
            diagnostic.artifacts.parse_json(b'{"kind":1,"kind":2}')
        self.manifest['reports']['../outside'] = '4' * 64
        with self.assertRaises(diagnostic.ArtifactError):
            diagnostic.validate_manifest(self.manifest)

    def test_reject_parent_inventory_tampering_and_provenance_mismatch(self):
        original = (self.directory / 'parent-filesystem-manifest.json').read_bytes()
        rehash_report(self.directory, 'parent-filesystem-manifest.json', original + b' ')
        with self.assertRaisesRegex(diagnostic.ArtifactError, 'original parent manifest'):
            diagnostic.load_export(self.directory)
        rehash_report(self.directory, 'parent-filesystem-manifest.json', original)
        config = json.loads((self.directory / 'diagnostic-configuration.json').read_text())
        config['recipe_worktree_dirty'] = False
        rehash_report(self.directory, 'diagnostic-configuration.json', config)
        with self.assertRaisesRegex(diagnostic.ArtifactError, 'provenance'):
            diagnostic.load_export(self.directory)

    def test_reject_payload_modes_timer_and_firmware_masks(self):
        initial = json.loads((self.directory / 'filesystem-manifest.json').read_text())
        for target in ('payload', 'timer', 'firmware'):
            filesystem = copy.deepcopy(initial)
            if target == 'payload':
                filesystem['rootfs']['usr/local/lib/inkyos/sd-diagnostic.py']['mode'] = '0777'
            elif target == 'timer':
                del filesystem['rootfs']['etc/systemd/system/timers.target.wants/inkyos-sd-diagnostic.timer']
            else:
                filesystem['rootfs']['etc/systemd/system/rpi-eeprom-update.service']['target'] = '/active'
            with self.subTest(target=target):
                rehash_report(self.directory, 'filesystem-manifest.json', filesystem)
                with self.assertRaises(diagnostic.ArtifactError):
                    diagnostic.load_export(self.directory)

    def test_existing_prototype_verifier_rejects_diagnostic_kind(self):
        with self.assertRaises(diagnostic.ArtifactError):
            diagnostic.artifacts.validate_build(self.manifest)

    def test_cli_output_is_external_and_never_overwritten(self):
        inside = subprocess.run([sys.executable, str(SCRIPT), str(self.directory), '--output',
                                 str(self.directory / 'new.json')], capture_output=True)
        self.assertEqual(inside.returncode, 2)
        self.assertFalse((self.directory / 'new.json').exists())
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'integrity.json'
            command = [sys.executable, str(SCRIPT), str(self.directory), '--output', str(output)]
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            raw = output.read_bytes()
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 2)
            self.assertEqual(output.read_bytes(), raw)


if __name__ == '__main__':
    unittest.main()
