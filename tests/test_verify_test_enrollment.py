"""Synthetic private export evidence; no real image, key, SD or hardware."""
import copy
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import tarfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value
verify = load(ROOT / 'scripts/verify-test-enrollment.py', 'verify_enrollment_fixtures')
seed = load(ROOT / 'tests/test_verify_test_lan.py', 'enrollment_export_seed')
profile_fixture = load(ROOT / 'tests/test_test_enrollment_rootfs.py', 'enrollment_profile_fixture')
encoded, digest, put = seed.encoded, seed.digest, seed.put


def archive_bytes(blobs, recipe, **kwargs):
    # Preserve the PRIVATE input mode in the tar header; all keys are fixtures.
    buffer = io.BytesIO()
    raw = seed.archive_bytes(blobs, recipe, **kwargs)
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as original, tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for member in original:
            if member.name == 'recipe/private-profile.json': member.mode = 0o600
            archive.addfile(member, original.extractfile(member))
    return buffer.getvalue()


def fixture(path):
    with tempfile.TemporaryDirectory() as temp:
        parent_path = Path(temp)
        parent, parent_blobs = seed.fixture(parent_path)
        parent_filesystem = json.loads((parent_path / 'filesystem-manifest.json').read_bytes())
        oldroot = parent_filesystem['rootfs']
        oldroot['usr/local/lib/inkyos']['mode'] = '0700'
        for name in verify.overlay.PRESERVED_FILES:
            if name not in oldroot:
                put(oldroot, name, seed.record((name + ' generic unmodified fixture\n').encode()))
        parent_filesystem_raw = encoded(parent_filesystem)
        parent['image']['sha256'] = verify.overlay.PARENT_IMAGE_SHA256
        parent['reports']['filesystem-manifest.json'] = digest(parent_filesystem_raw)
        parent_raw = encoded(parent)
        blobs = dict(parent_blobs)
        blobs['parent-manifest.json'] = parent_raw
        for name in verify.overlay.SOURCES:
            if name not in verify.INHERITED_RECIPE_FILES:
                blobs[name] = (ROOT / name).read_bytes()
        for name in verify.overlay.RECIPE_FILES - {verify.overlay.PRIVATE_PROFILE}:
            blobs.setdefault(name, (name + ' synthetic unused audit source\n').encode())
        raw_profile = encoded(profile_fixture.profile())
        blobs[verify.overlay.PRIVATE_PROFILE] = raw_profile
        recipe = {'schema_version': 1, 'source_commit': 'd' * 40, 'worktree_dirty': True,
                  'files': {name: digest(raw) for name, raw in blobs.items()}}
        filesystem = copy.deepcopy(parent_filesystem)
        root = filesystem['rootfs']
        for name, (relative, mode) in verify.overlay.PAYLOADS.items():
            put(root, relative, seed.record(blobs[name], format(mode, '04o')))
        put(root, verify.overlay.PROFILE_PATH, seed.record(raw_profile, '0600'))
        for name in (verify.overlay.PROFILE_DIRECTORY, verify.overlay.STATE_DIRECTORY):
            value = seed.directory(); value['mode'] = '0700'; put(root, name, value)
        link = seed.mask(); link['target'] = verify.overlay.UNIT_TARGET
        put(root, verify.overlay.ENABLE_PATH, link)
        protected = {}
        for name in verify.PROTECTED_FILES:
            section, _, relative = name.partition('/')
            protected[name] = filesystem[section + 'fs'][relative]['sha256']
        boot_snapshot = {}
        for name, record in filesystem['bootfs'].items():
            if name != '.':
                boot_snapshot[name] = {key: record[key] for key in ('type', 'uid', 'gid')}
                boot_snapshot[name]['mode'] = int(record['mode'], 8)
                if record['type'] == 'file': boot_snapshot[name]['sha256'] = record['sha256']
        configuration = {
            'schema_version': 1, 'kind': 'test-lan-enrollment', 'scope': 'offline-test-enrollment-configuration',
            'passed': True, 'private_artifact': True, 'bootstrap_action': 'enroll-and-stop',
            'application_started': False, 'no_active_application': True, 'ready_for_activation': False,
            'hardware_qualified': False, 'release_qualified': False, 'removed_rootfs_paths': [], 'removed_bootfs_paths': [],
            'checks': {name: True for name in verify.overlay.CHECKS}, 'parent_image_sha256': verify.overlay.PARENT_IMAGE_SHA256,
            'profile_sha256': digest(raw_profile), 'source_file_sha256': {name: digest(blobs[name]) for name in verify.overlay.SOURCES},
            'recipe_source_commit': recipe['source_commit'], 'recipe_worktree_dirty': recipe['worktree_dirty'],
            'recipe_inputs_sha256': digest(encoded(recipe)),
            'preserved_parent_file_sha256': {name: oldroot[name]['sha256'] for name in verify.overlay.PRESERVED_FILES},
            'protected_boot_grow_sha256': protected,
            'bootfs_snapshot_sha256': digest(json.dumps(boot_snapshot, sort_keys=True, separators=(',', ':')).encode()),
        }
        qualification_prepared = {
            'schema_version': 1, 'scope': 'offline-inherited-prepared-constraints', 'kind': 'test-lan-enrollment',
            'passed': True, 'enrollment_hook_exception_explicit': True,
            'inherited_prepared_marker_sha256': oldroot[verify.lan.METADATA_PATH]['sha256'],
            'application_started': False, 'no_active_application': True, 'ready_for_activation': False,
            'hardware_qualified': False, 'release_qualified': False,
            'checks': {name: True for name in verify.PREPARED_CHECKS},
        }
        reports = {name: (parent_path / name).read_bytes() for name in verify.REQUIRED_REPORTS
                   if (parent_path / name).exists()}
        image = {'filename': 'inkyos-test-enrollment.img', 'size_bytes': len(seed.IMAGE), 'sha256': digest(seed.IMAGE)}
        reports.update({
            'parent-manifest.json': parent_raw, 'parent-filesystem-manifest.json': parent_filesystem_raw,
            'parent-integrity.json': encoded({'scope': 'local-test-lan-prepared-export-integrity',
                'passed': True, 'image_sha256_verified': True, 'no_active_application': True,
                'authenticity_verified': False, 'hardware_qualified': False, 'release_qualified': False, 'ready_for_activation': False}),
            'recipe.tar': archive_bytes(blobs, recipe), 'test-enrollment-configuration.json': encoded(configuration),
            'qualification-prepared.json': encoded(qualification_prepared), 'filesystem-manifest.json': encoded(filesystem),
            'image-inspection.json': encoded({'image': {'sha256': image['sha256'], 'size_bytes': image['size_bytes']}}),
            'build.log': b'Synthetic private enrollment build; no execution.\n',
        })
        manifest = {'schema_version': 1, 'kind': 'test-lan-enrollment', 'private_artifact': True,
            'bootstrap_action': 'enroll-and-stop', 'no_active_application': True, 'ready_for_activation': False,
            'hardware_qualified': False, 'release_qualified': False, 'application': parent['application'],
            'parent': {'kind': 'test-lan-prepared', 'image_sha256': verify.overlay.PARENT_IMAGE_SHA256,
                       'size_bytes': image['size_bytes'], 'manifest_sha256': digest(parent_raw)},
            'personalization': {'profile_sha256': digest(raw_profile), 'network_profile_present': False, 'country_requested': 'FR'},
            'image': image, 'recipe': recipe, 'reports': {name: digest(raw) for name, raw in reports.items()}}
        for name, raw in reports.items(): (path / name).write_bytes(raw)
        (path / 'manifest.json').write_bytes(encoded(manifest))
        (path / 'recipe-inputs.json').write_bytes(encoded(recipe))
        (path / image['filename']).write_bytes(seed.IMAGE)
        return manifest, blobs


def rehash(path, name, value):
    raw = encoded(value) if type(value) is dict else value
    (path / name).write_bytes(raw)
    manifest = json.loads((path / 'manifest.json').read_bytes())
    manifest['reports'][name] = digest(raw)
    (path / 'manifest.json').write_bytes(encoded(manifest))


class EnrollmentExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.manifest, self.blobs = fixture(self.path)
    def read(self, name):
        return json.loads((self.path / name).read_bytes())
    def test_complete_private_export_has_only_enrollment_boot_authority_and_no_qualification(self):
        result = verify.load_export(self.path)
        report = result['report']
        self.assertTrue(report['passed'])
        self.assertTrue(report['private_artifact'])
        self.assertTrue(report['image_sha256_verified'])
        self.assertTrue(report['filesystem_delta_allowlist_verified'])
        self.assertEqual(report['protected_boot_grow_files_verified'], 10)
        self.assertEqual(report['inherited_prepared_constraints_verified'], 16)
        for name in ('ready_for_activation', 'hardware_qualified', 'release_qualified', 'authenticity_verified'):
            self.assertFalse(report[name])
        self.assertNotIn(profile_fixture.profile()['operator_public_key'], encoded(report).decode())
        self.assertNotIn(profile_fixture.profile()['challenge'], encoded(report).decode())
    def test_manifest_requires_private_flag_exact_parent_and_final_pin_without_wifi_or_activation(self):
        for field, changed in (('kind', 'test-lan-prepared'), ('private_artifact', False), ('bootstrap_action', 'activate'),
                               ('no_active_application', False), ('ready_for_activation', True), ('hardware_qualified', True), ('release_qualified', True)):
            value = copy.deepcopy(self.manifest); value[field] = changed
            with self.subTest(field=field), self.assertRaises(verify.ArtifactError): verify.validate_manifest(value)
        for field, changed in (('kind', 'application-prototype'), ('image_sha256', 'a' * 64)):
            value = copy.deepcopy(self.manifest); value['parent'][field] = changed
            with self.assertRaises(verify.ArtifactError): verify.validate_manifest(value)
        value = copy.deepcopy(self.manifest); value['personalization']['network_profile_present'] = True
        with self.assertRaises(verify.ArtifactError): verify.validate_manifest(value)
        value = copy.deepcopy(self.manifest); value['application']['source_commit'] = 'f' * 40
        with self.assertRaises(verify.ArtifactError): verify.validate_manifest(value)
    def test_report_list_is_exact_and_configuration_fields_and_checks_are_closed(self):
        for name in verify.REQUIRED_REPORTS:
            value = copy.deepcopy(self.manifest); del value['reports'][name]
            with self.assertRaises(verify.ArtifactError): verify.validate_manifest(value)
        for change in ('missing', 'extra', 'false'):
            value = self.read('test-enrollment-configuration.json')
            if change == 'missing': value['checks'].pop(next(iter(value['checks'])))
            if change == 'extra': value['extra'] = 'PRIVATE'
            if change == 'false': value['checks'][next(iter(value['checks']))] = False
            rehash(self.path, 'test-enrollment-configuration.json', value)
            with self.assertRaises(verify.ArtifactError): verify.load_export(self.path)
            fixture(self.path)
        value = copy.deepcopy(self.manifest)
        value['recipe']['files']['client_ed25519'] = 'a' * 64
        with self.assertRaises(verify.ArtifactError): verify.validate_manifest(value)
        value = copy.deepcopy(self.manifest); value['operator_identity'] = 'PRIVATE'
        with self.assertRaises(verify.ArtifactError): verify.validate_manifest(value)
    def test_prepared_constraints_require_16_checks_and_explicit_hook_exception(self):
        for mode in ('extra_hook_claim', 'exception_false', 'marker_changed'):
            value = self.read('qualification-prepared.json')
            if mode == 'extra_hook_claim': value['checks']['no_diagnostic_or_test_runtime_hooks'] = True
            if mode == 'exception_false': value['enrollment_hook_exception_explicit'] = False
            if mode == 'marker_changed': value['inherited_prepared_marker_sha256'] = 'a' * 64
            rehash(self.path, 'qualification-prepared.json', value)
            with self.assertRaises(verify.ArtifactError): verify.load_export(self.path)
            fixture(self.path)
    def test_parent_entry_changes_removals_boot_changes_and_arbitrary_additions_are_refused(self):
        cases = [('rootfs', 'etc/passwd', seed.record(b'changed')),
                 ('rootfs', 'usr/local/lib/inkyos', seed.directory()),
                 ('rootfs', 'etc/inkyos-test-lan.json', None),
                 ('bootfs', 'config.txt', seed.record(b'changed')),
                 ('rootfs', 'etc/systemd/system/inkyos-test-other.service', seed.record()),
                 ('rootfs', 'etc/NetworkManager/system-connections/private.nmconnection', seed.record()),
                 ('rootfs', verify.overlay.STATE_DIRECTORY + '/state.json', seed.record()),
                 ('rootfs', 'etc/ssh/ssh_host_ed25519_key', seed.record())]
        for section, path, changed in cases:
            value = self.read('filesystem-manifest.json')
            if changed is None: value[section].pop(path)
            else: put(value[section], path, changed)
            rehash(self.path, 'filesystem-manifest.json', value)
            with self.subTest(path=path), self.assertRaises(verify.ArtifactError): verify.load_export(self.path)
            fixture(self.path)
    def test_private_modes_extra_profile_payload_hash_and_enable_link_target_are_bound(self):
        for path, field, changed in ((verify.overlay.PROFILE_PATH, 'mode', '0644'),
                                     (verify.overlay.STATE_DIRECTORY, 'mode', '0755'),
                                     (verify.overlay.ENABLE_PATH, 'target', '/usr/lib/systemd/system/ssh.service'),
                                     (verify.overlay.PAYLOADS['scripts/observe-test-radio.py'][0], 'sha256', 'a' * 64)):
            value = self.read('filesystem-manifest.json'); value['rootfs'][path][field] = changed
            rehash(self.path, 'filesystem-manifest.json', value)
            with self.assertRaises(verify.ArtifactError): verify.load_export(self.path)
            fixture(self.path)
    def test_recipe_unknown_symlink_member_tampering_and_profile_not_canonical_are_refused(self):
        for extra, omit in (({'recipe/extra': b'unknown'}, None), (None, 'recipe/private-profile.json')):
            rehash(self.path, 'recipe.tar', archive_bytes(self.blobs, self.manifest['recipe'], extra=extra, omit=omit))
            with self.assertRaises(verify.ArtifactError): verify.load_export(self.path)
            fixture(self.path)
        blobs = dict(self.blobs); blobs['scripts/observe-test-radio.py'] += b'changed'
        rehash(self.path, 'recipe.tar', archive_bytes(blobs, self.manifest['recipe']))
        with self.assertRaises(verify.ArtifactError): verify.load_export(self.path)
        for raw in (json.dumps(profile_fixture.profile()).encode(), encoded(profile_fixture.profile()) + b'\n'):
            with self.assertRaises(verify.ArtifactError):
                verify.private_profile({verify.overlay.PRIVATE_PROFILE: raw}, {}, b'', b'')
        fixture(self.path)
        rehash(self.path, 'recipe.tar', seed.archive_bytes(self.blobs, self.manifest['recipe']))
        with self.assertRaisesRegex(verify.ArtifactError, 'archive metadata'): verify.load_export(self.path)
    def test_public_reports_cannot_contain_operator_key_nonce_or_fingerprint(self):
        wire = base64.b64decode(profile_fixture.profile()['operator_public_key'].split(' ')[1])
        fingerprint = b'SHA256:' + base64.b64encode(hashlib.sha256(wire).digest()).rstrip(b'=')
        for token in (profile_fixture.profile()['operator_public_key'].encode(), profile_fixture.profile()['challenge'].encode(), fingerprint):
            rehash(self.path, 'build.log', b'PRIVATE_LEAK ' + token)
            with self.assertRaisesRegex(verify.ArtifactError, 'leaked'): verify.load_export(self.path)
            fixture(self.path)
    def test_image_tampering_and_symlink_evidence_are_refused(self):
        path = self.path / 'inkyos-test-enrollment.img'; raw = path.read_bytes(); path.write_bytes(raw[:-1] + b'x')
        with self.assertRaises(verify.ArtifactError): verify.load_export(self.path)
        path.write_bytes(raw)
        report = self.path / 'build.log'; report.unlink(); report.symlink_to('fsck-fat.txt')
        with self.assertRaises(OSError): verify.load_export(self.path)
    def test_unhashed_image_limitation_is_explicit_and_receipt_contains_no_profile(self):
        report = verify.load_export(self.path, verify_images=False)['report']
        self.assertFalse(report['image_sha256_verified'])
        self.assertTrue(any('not hashed' in value for value in report['limits']))
        self.assertNotIn('operator_public_key', report)


if __name__ == '__main__':
    unittest.main()
