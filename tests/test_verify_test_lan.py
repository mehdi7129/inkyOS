"""Synthetic export consistency tests only; never mount or activate an image."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/verify-test-lan.py'
SPEC = importlib.util.spec_from_file_location('verify_test_lan', SCRIPT)
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)
IMAGE = b'synthetic prepared test LAN image; no executable filesystem\n'


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def directory(uid=0, gid=0):
    return {'type': 'directory', 'mode': '0755', 'uid': uid, 'gid': gid,
            'xattrs': {'status': 'inspected', 'entries': {}}}


def record(raw=b'fixture', mode='0644'):
    return {'type': 'file', 'mode': mode, 'uid': 0, 'gid': 0, 'size_bytes': len(raw),
            'sha256': digest(raw), 'xattrs': {'status': 'inspected', 'entries': {}}}


def mask():
    return {'type': 'symlink', 'mode': '0777', 'uid': 0, 'gid': 0, 'target': '/dev/null',
            'xattrs': {'status': 'inspected', 'entries': {}}}


def put(tree, name, value):
    for parent in reversed(PurePosixPath(name).parents):
        tree.setdefault(str(parent), directory())
    tree[name] = value


def archive_bytes(blobs, recipe, *, extra=None, omit=None):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        values = {'recipe/' + name: data for name, data in blobs.items()}
        values['recipe/recipe-inputs.json'] = encoded(recipe)
        if extra:
            values.update(extra)
        for name, raw in sorted(values.items()):
            if name == omit:
                continue
            info = tarfile.TarInfo(name); info.mode = 0o444; info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return buffer.getvalue()


def fixture(path, manifest_name='application-manifest-758a2bf7.json'):
    source_raw = (Path(__file__).with_name('fixtures') / manifest_name).read_bytes()
    source = json.loads(source_raw)
    assert digest(source_raw) == verify.overlay.REVIEWED_APPLICATIONS[source['source_commit']]
    app = {'source_commit': source['source_commit'], 'application_version': source['application_version'],
           'manifest_sha256': digest(source_raw), 'startup': 'masked-pending-firstboot-contract', 'release_qualified': False}
    filesystem = {'schema_version': 2, 'scope': 'content-and-metadata-without-timestamps',
                  'rootfs': {'.': directory()}, 'bootfs': {'.': directory()}}
    root, boot = filesystem['rootfs'], filesystem['bootfs']
    protected = {}
    for name in sorted(verify.PROTECTED_FILES):
        section, _, relative = name.partition('/')
        raw = (name + ' unmodified\n').encode()
        put(filesystem[section + 'fs'], relative, record(raw))
        protected[name] = digest(raw)
    config_raw = b'[all]\ninclude inkyos.txt\n'
    put(boot, 'config.txt', record(config_raw))
    for name, (pin, mode) in verify.overlay.STATIC_PARENT_FILES.items():
        item = record(mode=format(mode, '04o')); item['sha256'] = pin
        put(root, name, item)
    for name, raw in (
        ('etc/machine-id', b'uninitialized\n'),
        ('home/inky/inky-studio/server/SOURCE_COMMIT', (source['source_commit'] + '\n').encode()),
        ('var/lib/NetworkManager/NetworkManager.state', b'[main]\nWirelessEnabled=false\n'),
    ):
        put(root, name, record(raw))
    put(root, 'var/lib/inky-studio', directory(1000, 1000))
    put(root, 'var/lib/inky-studio/photos', directory(1000, 1000))
    for unit in ('inky-studio.service', 'inky-network.service', 'ssh.service', 'ssh.socket', 'sshswitch.service'):
        put(root, 'etc/systemd/system/' + unit, mask())
    # A masked vendor timer can legitimately retain its inherited wants link.
    link = mask(); link['target'] = '/usr/lib/systemd/system/apt-daily.timer'
    put(root, 'etc/systemd/system/timers.target.wants/apt-daily.timer', link)
    parent_filesystem = copy.deepcopy(filesystem)
    parent_filesystem_raw = encoded(parent_filesystem)
    sources = set(verify.overlay.SOURCES) | verify.INHERITED_RECIPE_FILES
    blobs = {name: (name + ' synthetic recipe source\n').encode() for name in sources}
    blobs['application-manifest.json'] = source_raw
    parent = {
        'schema_version': 1, 'kind': 'application-prototype', 'hardware_qualified': False,
        'application': app, 'image': {'filename': 'parent.img', 'size_bytes': len(IMAGE), 'sha256': '1' * 64},
        'recipe': {'schema_version': 1, 'source_commit': 'a' * 40, 'worktree_dirty': False,
                   'files': {name: digest(blobs[name]) for name in verify.INHERITED_RECIPE_FILES | {'application-manifest.json'}}},
        'reports': {name: '2' * 64 for name in verify.artifacts.REQUIRED_REPORTS | verify.artifacts.APPLICATION_REPORTS},
    }
    parent['reports']['filesystem-manifest.json'] = digest(parent_filesystem_raw)
    parent_raw = encoded(parent); blobs['parent-manifest.json'] = parent_raw
    recipe = {'schema_version': 1, 'source_commit': 'b' * 40, 'worktree_dirty': True,
              'files': {name: digest(raw) for name, raw in blobs.items()}}
    configured_boot = config_raw.decode().rstrip() + verify.overlay.BOOT_APPEND
    hashes = {name: digest(blobs[name]) for name in verify.overlay.SOURCES}
    metadata = verify.overlay.expected_metadata(parent['image']['sha256'], hashes, recipe,
                                                digest(encoded(recipe)), config_raw.decode(), protected, application=app)
    for name, (relative, mode) in verify.overlay.PAYLOADS.items():
        put(root, relative, record(blobs[name], format(mode, '04o')))
    put(root, verify.METADATA_PATH, record(encoded(metadata)))
    for unit in verify.overlay.MASKS:
        put(root, 'etc/systemd/system/' + unit, mask())
    boot['config.txt'] = record(configured_boot.encode())
    config = {
        'schema_version': 1, 'kind': 'test-lan-prepared', 'scope': 'offline-test-lan-prepared-configuration',
        'passed': True, 'application_started': False, 'hardware_qualified': False,
        'release_qualified': False, 'ready_for_activation': False,
        'parent_image_sha256': parent['image']['sha256'], 'source_file_sha256': hashes,
        'recipe_source_commit': recipe['source_commit'], 'recipe_worktree_dirty': recipe['worktree_dirty'],
        'recipe_inputs_sha256': digest(encoded(recipe)), 'boot_config_delta': metadata['boot_config_delta'],
        'checks': {name: True for name in verify.overlay.CHECKS}, 'metadata_path': verify.METADATA_PATH,
        'marker_sha256': digest(encoded(metadata)), 'removed_pending_boot_artifacts': [],
        'protected_boot_grow_sha256': protected,
    }
    image = {'filename': 'prepared.img', 'size_bytes': len(IMAGE), 'sha256': digest(IMAGE)}
    static = {'schema_version': 1, 'scope': 'offline-system-prototype-contract', 'passed': True,
              'failed_checks': [], 'checks': [{'id': name, 'passed': True} for name in
                                               sorted(verify.artifacts.REQUIRED_STATIC_CHECKS | {'BOOT_NO_COUNTRY'})]}
    app_static = {'schema_version': 1, 'scope': 'offline-application-prototype-contract', 'passed': True,
                  'failed_checks': [], 'checks': [{'id': name, 'passed': True} for name in
                                                 sorted(verify.artifacts.APPLICATION_CHECKS)],
                  **{key: app[key] for key in ('source_commit', 'application_version', 'manifest_sha256')}}
    reports = {
        'parent-manifest.json': parent_raw, 'parent-filesystem-manifest.json': parent_filesystem_raw,
        'parent-integrity.json': encoded({'scope': 'local-export-integrity', 'passed': True,
                                         'image_sha256_verified': True, 'authenticity_verified': False,
                                         'hardware_qualified': False}),
        'recipe.tar': archive_bytes(blobs, recipe), 'test-lan-configuration.json': encoded(config),
        'qualification-static.json': encoded(static), 'qualification-application.json': encoded(app_static),
        'application-manifest.json': source_raw, 'filesystem-manifest.json': encoded(filesystem),
        'image-inspection.json': encoded({'image': image}), 'systemd-verify.txt': b'fixture syntax check\n',
        'boot-preserved.sha256': ''.join(value + '  ' + name + '\n' for name, value in sorted(protected.items())).encode(),
        'fsck-ext4.txt': b'fixture ext4 check\n', 'fsck-fat.txt': b'fixture FAT check\n',
    }
    manifest = {
        'schema_version': 1, 'kind': 'test-lan-prepared', 'hardware_qualified': False, 'release_qualified': False,
        'no_active_application': True, 'ready_for_activation': False, 'application': app,
        'parent': {'kind': parent['kind'], 'image_sha256': parent['image']['sha256'],
                   'size_bytes': len(IMAGE), 'manifest_sha256': digest(parent_raw)},
        'image': image, 'recipe': recipe, 'reports': {name: digest(raw) for name, raw in reports.items()},
    }
    for name, raw in reports.items():
        (path / name).write_bytes(raw)
    (path / 'manifest.json').write_bytes(encoded(manifest))
    (path / 'recipe-inputs.json').write_bytes(encoded(recipe))
    (path / image['filename']).write_bytes(IMAGE)
    return manifest, blobs


def rehash_report(path, name, value):
    raw = encoded(value) if isinstance(value, dict) else value
    (path / name).write_bytes(raw)
    manifest = json.loads((path / 'manifest.json').read_text())
    manifest['reports'][name] = digest(raw)
    (path / 'manifest.json').write_bytes(encoded(manifest))


class TestLanExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)
        self.manifest, self.blobs = fixture(self.path)

    def tearDown(self):
        self.temp.cleanup()

    def read(self, name):
        return json.loads((self.path / name).read_text())

    def test_complete_export_is_inactive_unqualified_and_full_image_hashed(self):
        report = verify.load_export(self.path)['report']
        self.assertTrue(report['passed'])
        self.assertTrue(report['image_sha256_verified'])
        self.assertTrue(report['filesystem_delta_allowlist_verified'])
        self.assertEqual(report['protected_boot_grow_files_verified'], 10)
        self.assertTrue(report['no_active_application'])
        for field in ('ready_for_activation', 'authenticity_verified', 'hardware_qualified', 'release_qualified'):
            self.assertIs(report[field], False)

    def test_original_export_uses_original_marker_and_pin(self):
        manifest, _ = fixture(self.path, 'application-manifest-6a697d1.json')
        result = verify.load_export(self.path)
        self.assertTrue(result['report']['passed'])
        self.assertEqual(result['manifest']['application'], manifest['application'])
        self.assertNotEqual(manifest['application']['source_commit'], verify.overlay.SOURCE_COMMIT)

    def test_crossed_reviewed_pairs_and_unknown_manifest_are_refused(self):
        for source, pin in verify.overlay.REVIEWED_APPLICATIONS.items():
            for other in (*verify.overlay.REVIEWED_APPLICATIONS.values(), 'f' * 64):
                if other == pin:
                    continue
                bad = copy.deepcopy(self.manifest)
                bad['application'].update(source_commit=source, manifest_sha256=other)
                bad['recipe']['files']['application-manifest.json'] = other
                with self.subTest(source=source, digest=other), self.assertRaises(verify.ArtifactError):
                    verify.validate_manifest(bad)

    def test_skipping_image_hash_explicitly_limits_receipt(self):
        report = verify.load_export(self.path, verify_images=False)['report']
        self.assertFalse(report['image_sha256_verified'])
        self.assertTrue(any('not hashed' in line for line in report['limits']))

    def test_missing_required_report(self):
        for name in verify.REQUIRED_REPORTS:
            bad = copy.deepcopy(self.manifest); del bad['reports'][name]
            with self.subTest(name=name), self.assertRaises(verify.ArtifactError):
                verify.validate_manifest(bad)

    def test_wrong_pins_and_activation_claims(self):
        for field, value in (('kind', 'application-prototype'), ('ready_for_activation', True),
                             ('no_active_application', False), ('hardware_qualified', True), ('release_qualified', True)):
            bad = copy.deepcopy(self.manifest); bad[field] = value
            with self.subTest(field=field), self.assertRaises(verify.ArtifactError):
                verify.validate_manifest(bad)
        for field in ('source_commit', 'manifest_sha256', 'application_version', 'startup'):
            bad = copy.deepcopy(self.manifest); bad['application'][field] = 'different'
            with self.subTest(field=field), self.assertRaises(verify.ArtifactError):
                verify.validate_manifest(bad)

    def test_image_bytes_size_and_report_tampering(self):
        for name in ('prepared.img', 'systemd-verify.txt'):
            raw = (self.path / name).read_bytes()
            for replacement in (raw[:-1] + b'X', raw + b'X'):
                with self.subTest(name=name, size=len(replacement)):
                    (self.path / name).write_bytes(replacement)
                    with self.assertRaises(verify.ArtifactError):
                        verify.load_export(self.path)
            (self.path / name).write_bytes(raw)

    def test_symlink_report_refused(self):
        path = self.path / 'systemd-verify.txt'; path.unlink(); path.symlink_to('fsck-fat.txt')
        with self.assertRaises(OSError):
            verify.load_export(self.path)

    def test_recipe_payload_changed_despite_rehashed_archive(self):
        blobs = dict(self.blobs); blobs['scripts/test-lan-preflight.py'] += b'changed\n'
        rehash_report(self.path, 'recipe.tar', archive_bytes(blobs, self.manifest['recipe']))
        with self.assertRaisesRegex(verify.ArtifactError, 'source-file'):
            verify.load_export(self.path)

    def test_changed_parent_audit_input_requires_a_new_parent(self):
        for name in verify.INHERITED_RECIPE_FILES:
            manifest, blobs = fixture(self.path)
            blobs[name] += b'changed audit source\n'
            manifest['recipe']['files'][name] = digest(blobs[name])
            (self.path / 'manifest.json').write_bytes(encoded(manifest))
            (self.path / 'recipe-inputs.json').write_bytes(encoded(manifest['recipe']))
            rehash_report(self.path, 'recipe.tar', archive_bytes(blobs, manifest['recipe']))
            with self.subTest(name=name), self.assertRaisesRegex(verify.ArtifactError, 'Inherited base/package/application audit source changed'):
                verify.load_export(self.path)

    def test_recipe_missing_or_extra_member(self):
        for extra, omit in (({'recipe/extra': b'not declared'}, None),
                            (None, 'recipe/scripts/test-lan-preflight.py')):
            with self.subTest(extra=extra, omit=omit):
                rehash_report(self.path, 'recipe.tar', archive_bytes(self.blobs, self.manifest['recipe'], extra=extra, omit=omit))
                with self.assertRaises(verify.ArtifactError):
                    verify.load_export(self.path)

    def test_parent_image_and_inventory_pins(self):
        for field in ('image_sha256', 'manifest_sha256'):
            bad = copy.deepcopy(self.manifest); bad['parent'][field] = '9' * 64
            (self.path / 'manifest.json').write_bytes(encoded(bad))
            with self.subTest(field=field), self.assertRaises(verify.ArtifactError):
                verify.load_export(self.path)
        (self.path / 'manifest.json').write_bytes(encoded(self.manifest))
        rehash_report(self.path, 'parent-filesystem-manifest.json', (self.path / 'parent-filesystem-manifest.json').read_bytes() + b' ')
        with self.assertRaisesRegex(verify.ArtifactError, 'original parent manifest'):
            verify.load_export(self.path)

    def test_configuration_missing_check_wrong_scope_or_provenance(self):
        original = self.read('test-lan-configuration.json')
        changes = [('kind', 'sd-diagnostic'), ('scope', 'offline-sd-diagnostic-configuration'), ('ready_for_activation', True),
                   ('recipe_worktree_dirty', False), ('marker_sha256', '7' * 64),
                   ('removed_pending_boot_artifacts', ['pieeprom.upd'])]
        for field, value in changes:
            bad = copy.deepcopy(original); bad[field] = value
            with self.subTest(field=field):
                rehash_report(self.path, 'test-lan-configuration.json', bad)
                with self.assertRaises(verify.ArtifactError):
                    verify.load_export(self.path)
        bad = copy.deepcopy(original); bad['checks'].pop(next(iter(bad['checks'])))
        rehash_report(self.path, 'test-lan-configuration.json', bad)
        with self.assertRaisesRegex(verify.ArtifactError, 'Configuration PASS'):
            verify.load_export(self.path)

    def test_missing_or_unmasked_application_ssh_and_update(self):
        original = self.read('filesystem-manifest.json')
        for unit in ('inky-studio.service', 'ssh.socket', 'rpi-eeprom-update.service'):
            for missing in (False, True):
                bad = copy.deepcopy(original); path = 'etc/systemd/system/' + unit
                if missing:
                    del bad['rootfs'][path]
                else:
                    bad['rootfs'][path]['target'] = '/active'
                with self.subTest(unit=unit, missing=missing):
                    rehash_report(self.path, 'filesystem-manifest.json', bad)
                    with self.assertRaises(verify.ArtifactError):
                        verify.load_export(self.path)

    def test_payload_marker_modes_ownership_and_hashes(self):
        original = self.read('filesystem-manifest.json')
        paths = [path for path, _mode in verify.overlay.PAYLOADS.values()] + [verify.METADATA_PATH]
        for path in paths:
            for field, value in (('mode', '0777'), ('uid', 1000), ('gid', 1000), ('sha256', '8' * 64)):
                bad = copy.deepcopy(original); bad['rootfs'][path][field] = value
                with self.subTest(path=path, field=field):
                    rehash_report(self.path, 'filesystem-manifest.json', bad)
                    with self.assertRaises(verify.ArtifactError):
                        verify.load_export(self.path)

    def test_forbidden_additions_removals_metadata_and_xattrs(self):
        original = self.read('filesystem-manifest.json')
        for mutation in ('new_file', 'deleted_parent', 'parent_mode', 'parent_xattr', 'boot_extra', 'boot_removed'):
            bad = copy.deepcopy(original)
            if mutation == 'new_file':
                bad['rootfs']['etc/arbitrary'] = record()
            elif mutation == 'deleted_parent':
                del bad['rootfs']['etc/systemd/system/timers.target.wants/apt-daily.timer']
            elif mutation == 'parent_mode':
                bad['rootfs']['usr']['mode'] = '0777'
            elif mutation == 'parent_xattr':
                bad['rootfs']['usr']['xattrs']['entries']['user.synthetic'] = {'sha256': '4' * 64, 'size_bytes': 3}
            elif mutation == 'boot_extra':
                bad['bootfs']['extra.txt'] = record()
            else:
                del bad['bootfs']['kernel8.img']
            with self.subTest(mutation=mutation):
                rehash_report(self.path, 'filesystem-manifest.json', bad)
                with self.assertRaises(verify.ArtifactError):
                    verify.load_export(self.path)

    def test_generated_state_diagnostics_and_activation_hooks_refused(self):
        original = self.read('filesystem-manifest.json')
        for path in ('var/lib/inky-studio/credentials.json', 'var/lib/inky-studio/photos/test.png',
                     'var/lib/inky-network/journal.json', 'etc/NetworkManager/system-connections/test.nmconnection',
                     'etc/systemd/system/inkyos-sd-diagnostic.timer', 'etc/systemd/system/inkyos-test-lan.service',
                     'etc/systemd/system/multi-user.target.wants/inky-studio.service'):
            bad = copy.deepcopy(original); bad['rootfs'][path] = record()
            with self.subTest(path=path):
                rehash_report(self.path, 'filesystem-manifest.json', bad)
                with self.assertRaises(verify.ArtifactError):
                    verify.load_export(self.path)

    def test_protected_file_payload_and_static_gate_mismatch(self):
        filesystem = self.read('filesystem-manifest.json')
        filesystem['bootfs']['kernel8.img']['sha256'] = '9' * 64
        rehash_report(self.path, 'filesystem-manifest.json', filesystem)
        with self.assertRaisesRegex(verify.ArtifactError, 'Protected'):
            verify.load_export(self.path)
        fixture(self.path)
        gate = self.read('qualification-static.json')
        gate['checks'] = [row for row in gate['checks'] if row['id'] != 'BOOT_NO_COUNTRY']
        rehash_report(self.path, 'qualification-static.json', gate)
        with self.assertRaisesRegex(verify.ArtifactError, 'static gate'):
            verify.load_export(self.path)

    def test_report_parser_rejects_duplicate_json_and_traversal(self):
        with self.assertRaises(verify.ArtifactError):
            verify.artifacts.parse_json(b'{"passed":true,"passed":false}')
        self.manifest['reports']['../outside'] = '3' * 64
        with self.assertRaises(verify.ArtifactError):
            verify.validate_manifest(self.manifest)

    def test_cli_creates_only_new_external_receipt(self):
        command = [sys.executable, '-B', str(SCRIPT), str(self.path), '--output']
        inside = self.path / 'integrity.json'
        self.assertEqual(subprocess.run(command + [str(inside)], capture_output=True).returncode, 2)
        self.assertFalse(inside.exists())
        with tempfile.TemporaryDirectory() as temporary:
            outside = Path(temporary) / 'integrity.json'
            result = subprocess.run(command + [str(outside)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            raw = outside.read_bytes()
            self.assertEqual(subprocess.run(command + [str(outside)], capture_output=True).returncode, 2)
            self.assertEqual(outside.read_bytes(), raw)


if __name__ == '__main__':
    unittest.main()
