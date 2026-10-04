"""Synthetic c31 export consistency; no image mount, key generation or service.

Inventories and the tiny image are fixtures, not hardware/authenticity evidence.
The real public recipe sources are hashed, never executed as target programs.
"""
import base64
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verify = load('access_export_verifier_fixture', 'scripts/verify-test-access.py')
seed = load('access_export_parent_fixture', 'tests/test_verify_test_lan.py')
profile_seed = load('access_export_profile_fixture', 'tests/test_test_access_policy.py')
encoded, digest, put = seed.encoded, seed.digest, seed.put


def archive_bytes(blobs, recipe, *, private_mode=0o600, extra=None):
    result = io.BytesIO()
    original = seed.archive_bytes(blobs, recipe, extra=extra)
    with tarfile.open(fileobj=io.BytesIO(original), mode='r:') as source, \
            tarfile.open(fileobj=result, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for member in source:
            if member.name == 'recipe/' + verify.overlay.PRIVATE_PROFILE:
                member.mode = private_mode
            archive.addfile(member, source.extractfile(member))
    return result.getvalue()


def fixture(path):
    """Use the reviewed c31 parent fixture and independently compose its delta."""
    overlay = verify.overlay
    with tempfile.TemporaryDirectory() as temp:
        parent_path = Path(temp)
        parent, parent_blobs = seed.fixture(parent_path, 'application-manifest-c31b13af.json')
        old = json.loads((parent_path / 'filesystem-manifest.json').read_bytes())
        oldroot = old['rootfs']
        oldroot['usr/local/lib/inkyos']['mode'] = '0700'
        for name in overlay.PRESERVED_FILES:
            if name not in oldroot:
                put(oldroot, name, seed.record((name + ' unchanged fixture\n').encode()))
        # Account bytes are intentionally synthetic, never host account files.
        accounts = {
            'etc/passwd': (b'root:x:0:0:root:/root:/bin/sh\n', '0644', 0),
            'etc/group': (b'root:x:0:\n', '0644', 0),
            'etc/shadow': (b'root:*:0:0:99999:7:::\n', '0640', 42),
            'etc/gshadow': (b'root:*::\n', '0640', 42),
        }
        for name, (raw, mode, gid) in accounts.items():
            row = seed.record(raw, mode); row['gid'] = gid
            put(oldroot, name, row)
        blobs = {name: (ROOT / name).read_bytes() for name in verify.builder.RECIPE_FILES}
        blobs['application-manifest.json'] = parent_blobs['application-manifest.json']
        # The prepared preflight is inherited byte-for-byte, including its pin.
        preflight = 'scripts/test-lan-preflight.py'
        put(oldroot, overlay.PAYLOADS[preflight][0], seed.record(blobs[preflight], '0555'))
        for name in verify.INHERITED_RECIPE_FILES:
            parent['recipe']['files'][name] = digest(blobs[name])
        parent['image']['sha256'] = overlay.PARENT_IMAGE_SHA256
        parent['reports']['filesystem-manifest.json'] = digest(encoded(old))
        parent_raw = encoded(parent)
        blobs['parent-manifest.json'] = parent_raw
        runtime_raw = encoded(overlay._manifest(blobs))
        value = profile_seed.profile()
        value['access_runtime_manifest_sha256'] = digest(runtime_raw)
        profile_raw = encoded(value)
        blobs[overlay.PRIVATE_PROFILE] = profile_raw
        blobs[overlay.PRIVATE_MANIFEST] = runtime_raw
        recipe = {'schema_version': 1, 'source_commit': 'd' * 40, 'worktree_dirty': True,
                  'files': {name: digest(raw) for name, raw in blobs.items()}}
        filesystem = copy.deepcopy(old)
        root = filesystem['rootfs']
        for name, (target, mode) in overlay.PAYLOADS.items():
            put(root, target, seed.record(blobs[name], format(mode, '04o')))
        put(root, overlay.PROFILE_PATH, seed.record(profile_raw, '0600'))
        put(root, overlay.MANIFEST_PATH, seed.record(runtime_raw, '0644'))
        put(root, overlay.AUTHORIZED_KEYS, seed.record(('restrict ' + value['operator_public_key'] + '\n').encode()))
        for name, mode in ((overlay.PROFILE_DIRECTORY, '0700'), (overlay.STATE_DIRECTORY, '0700'),
                           (overlay.CACHE_DIRECTORY, '0700'), (overlay.SSH_DIRECTORY, '0755'),
                           (overlay.SSH_PUBLIC_DIRECTORY, '0755')):
            row = seed.directory(); row['mode'] = mode; put(root, name, row)
        link = seed.mask(); link['target'] = overlay.UNIT_TARGET
        put(root, overlay.ENABLE_PATH, link)
        for name, suffix in overlay.ACCOUNT_APPEND.items():
            raw, mode, gid = accounts[name]
            row = seed.record(raw + suffix, mode); row['gid'] = gid
            root[name] = row
        protected = {}
        for name in verify.PROTECTED_FILES:
            section, _, relative = name.partition('/')
            protected[name] = old[section + 'fs'][relative]['sha256']
        boot_snapshot = {}
        for name, row in old['bootfs'].items():
            if name == '.':
                continue
            boot_snapshot[name] = {key: row[key] for key in ('type', 'uid', 'gid')}
            boot_snapshot[name]['mode'] = int(row['mode'], 8)
            if row['type'] == 'file':
                boot_snapshot[name]['sha256'] = row['sha256']
        configuration = {
            'schema_version': 1, 'kind': 'test-lan-access', 'scope': 'offline-test-access-configuration',
            'passed': True, 'private_artifact': True, 'bootstrap_action': 'enrollment-then-signed-access',
            'application_started': False, 'ssh_started': False, 'network_connected': False,
            'no_active_application': True, 'ready_for_activation': False,
            'hardware_qualified': False, 'release_qualified': False, 'removed_rootfs_paths': [], 'removed_bootfs_paths': [],
            'checks': {name: True for name in overlay.CHECKS}, 'parent_image_sha256': overlay.PARENT_IMAGE_SHA256,
            'profile_sha256': digest(profile_raw), 'access_runtime_manifest_sha256': digest(runtime_raw),
            'source_file_sha256': {name: digest(blobs[name]) for name in overlay.SOURCES},
            'recipe_source_commit': recipe['source_commit'], 'recipe_worktree_dirty': recipe['worktree_dirty'],
            'recipe_inputs_sha256': digest(encoded(recipe)),
            'preserved_parent_file_sha256': {name: oldroot[name]['sha256'] for name in overlay.PRESERVED_FILES},
            'protected_boot_grow_sha256': protected, 'bootfs_snapshot_sha256': digest(encoded(boot_snapshot)),
            'account_file_sha256': {name: {'before': oldroot[name]['sha256'], 'after': root[name]['sha256']}
                                    for name in accounts},
            'account_parent_metadata': {name: {'mode': int(oldroot[name]['mode'], 8),
                                             'uid': oldroot[name]['uid'], 'gid': oldroot[name]['gid']}
                                        for name in accounts},
        }
        prepared = {'schema_version': 1, 'scope': 'pristine-parent-before-access-configuration',
            'kind': 'test-lan-prepared', 'passed': True, 'marker_sha256': oldroot[verify.lan.METADATA_PATH]['sha256'],
            'application_started': False, 'ready_for_activation': False, 'hardware_qualified': False,
            'release_qualified': False, 'checks': {name: True for name in verify.PREPARED_CHECKS}}
        image = {'filename': 'inkyos-test-access.img', 'size_bytes': len(seed.IMAGE), 'sha256': digest(seed.IMAGE)}
        reports = {name: (parent_path / name).read_bytes() for name in verify.REQUIRED_REPORTS
                   if (parent_path / name).exists()}
        reports.update({
            'parent-manifest.json': parent_raw, 'parent-filesystem-manifest.json': encoded(old),
            'parent-integrity.json': encoded({'scope': 'local-test-lan-prepared-export-integrity',
                'passed': True, 'image_sha256_verified': True, 'no_active_application': True,
                'authenticity_verified': False, 'hardware_qualified': False, 'release_qualified': False,
                'ready_for_activation': False}),
            'recipe.tar': archive_bytes(blobs, recipe), 'test-access-configuration.json': encoded(configuration),
            'qualification-prepared.json': encoded(prepared), 'filesystem-manifest.json': encoded(filesystem),
            'image-inspection.json': encoded({'image': image}),
            'build.log': b'Synthetic access export; no target execution.\n',
            'sudoers-verify.txt': b'Synthetic sudoers syntax evidence, not execution.\n',
        })
        manifest = {'schema_version': 1, 'kind': 'test-lan-access', 'private_artifact': True,
            'bootstrap_action': 'enrollment-then-signed-access', 'no_active_application': True,
            'ready_for_activation': False, 'hardware_qualified': False, 'release_qualified': False,
            'application': parent['application'],
            'parent': {'kind': 'test-lan-prepared', 'image_sha256': overlay.PARENT_IMAGE_SHA256,
                       'size_bytes': image['size_bytes'], 'manifest_sha256': digest(parent_raw)},
            'personalization': {'profile_sha256': digest(profile_raw), 'network_profile_present': False,
                                'country_requested': 'FR'},
            'image': image, 'recipe': recipe, 'reports': {name: digest(raw) for name, raw in reports.items()}}
        for name, raw in reports.items():
            (path / name).write_bytes(raw)
        (path / 'manifest.json').write_bytes(encoded(manifest))
        (path / 'recipe-inputs.json').write_bytes(encoded(recipe))
        (path / image['filename']).write_bytes(seed.IMAGE)
        return manifest, blobs


class AccessExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.manifest, self.blobs = fixture(self.path)
        self.assertTrue(verify.load_export(self.path)['report']['passed'])

    def read(self, name):
        return json.loads((self.path / name).read_bytes())

    def rewrite_report(self, name, value):
        seed.rehash_report(self.path, name, value)

    def assert_report_rejected(self, name, value):
        original = (self.path / name).read_bytes()
        try:
            self.rewrite_report(name, value)
            with self.assertRaises(verify.ArtifactError):
                verify.load_export(self.path)
        finally:
            self.rewrite_report(name, original)

    def test_complete_c31_export_preserves_inactive_scope_and_lists_limits(self):
        result = verify.load_export(self.path)
        report = result['report']
        for key in ('passed', 'private_artifact', 'image_sha256_verified', 'filesystem_delta_allowlist_verified'):
            self.assertIs(report[key], True)
        for key in ('ready_for_activation', 'hardware_qualified', 'release_qualified', 'authenticity_verified'):
            self.assertIs(report[key], False)
        self.assertEqual(report['pristine_parent_constraints_verified_before_changes'], 17)
        self.assertEqual(report['protected_boot_grow_files_verified'], 10)
        self.assertEqual(len(verify.overlay.PAYLOADS), 21)
        self.assertEqual(set(verify.builder.REPORTS), verify.REQUIRED_REPORTS)
        self.assertTrue(any('not regenerated from image bytes' in item for item in report['limits']))
        self.assertTrue(any('Account append content' in item for item in report['limits']))
        self.assertNotIn(profile_seed.profile()['operator_public_key'], encoded(report).decode())
        self.assertNotIn(profile_seed.profile()['challenge'], encoded(report).decode())

    def test_manifest_rejects_scope_escalation_crossed_parent_and_unknown_recipe(self):
        for field, value in (('private_artifact', False), ('bootstrap_action', 'activate'),
                             ('no_active_application', False), ('ready_for_activation', True),
                             ('hardware_qualified', True), ('release_qualified', True), ('schema_version', True)):
            bad = copy.deepcopy(self.manifest); bad[field] = value
            with self.subTest(field=field), self.assertRaises(verify.ArtifactError):
                verify.validate_manifest(bad)
        for section, field, value in (('parent', 'image_sha256', 'f' * 64),
                                      ('application', 'source_commit', 'f' * 40),
                                      ('personalization', 'network_profile_present', True)):
            bad = copy.deepcopy(self.manifest); bad[section][field] = value
            with self.assertRaises(verify.ArtifactError): verify.validate_manifest(bad)
        for name in ('client_ed25519', 'private-extra.json'):
            bad = copy.deepcopy(self.manifest); bad['recipe']['files'][name] = 'e' * 64
            with self.assertRaises(verify.ArtifactError): verify.validate_manifest(bad)

    def test_configuration_and_prepared_evidence_require_all_closed_checks(self):
        for name in ('test-access-configuration.json', 'qualification-prepared.json'):
            for mutation in ('missing', 'false', 'scope'):
                bad = self.read(name)
                if mutation == 'missing': bad['checks'].pop(next(iter(bad['checks'])))
                elif mutation == 'false': bad['checks'][next(iter(bad['checks']))] = False
                else: bad['scope'] = 'offline-inherited-prepared-constraints'
                with self.subTest(name=name, mutation=mutation): self.assert_report_rejected(name, bad)

    def test_parent_entry_mutation_removal_and_boot_change_are_refused(self):
        for section, name, field in (('rootfs', 'usr/local/lib/inkyos', 'mode'),
                                     ('rootfs', 'etc/machine-id', 'sha256'),
                                     ('bootfs', 'config.txt', 'sha256'),
                                     ('rootfs', verify.lan.METADATA_PATH, None)):
            bad = self.read('filesystem-manifest.json')
            if field is None: del bad[section][name]
            else: bad[section][name][field] = '0755' if field == 'mode' else 'e' * 64
            with self.subTest(name=name): self.assert_report_rejected('filesystem-manifest.json', bad)

    def test_no_precreated_key_cache_identity_network_profile_or_extra_hook(self):
        for name in ('etc/ssh/ssh_host_ed25519_key',
                     verify.overlay.PROFILE_DIRECTORY + '/ssh_host_ed25519_key',
                     verify.overlay.PROFILE_DIRECTORY + '/ssh_host_ed25519_key.pub',
                     verify.overlay.STATE_DIRECTORY + '/state.json',
                     verify.overlay.CACHE_DIRECTORY + '/capsule.json',
                     'var/lib/inkyos/system.json', 'run/NetworkManager/system-connections/secret.nmconnection',
                     'etc/systemd/system/multi-user.target.wants/inkyos-test-ssh.service',
                     'usr/lib/systemd/system/inkyos-test-other.service'):
            bad = self.read('filesystem-manifest.json'); put(bad['rootfs'], name, seed.record())
            with self.subTest(name=name): self.assert_report_rejected('filesystem-manifest.json', bad)

    def test_private_directory_payload_authorized_keys_and_single_hook_are_bound(self):
        for name, field, value in ((verify.overlay.PROFILE_PATH, 'mode', '0644'),
                                  (verify.overlay.CACHE_DIRECTORY, 'mode', '0755'),
                                  (verify.overlay.AUTHORIZED_KEYS, 'sha256', 'e' * 64),
                                  (verify.overlay.ENABLE_PATH, 'target', '/usr/lib/systemd/system/ssh.service'),
                                  (verify.overlay.PAYLOADS['scripts/test-access-connect.py'][0], 'sha256', 'e' * 64)):
            bad = self.read('filesystem-manifest.json'); bad['rootfs'][name][field] = value
            with self.subTest(name=name): self.assert_report_rejected('filesystem-manifest.json', bad)

    def test_runtime_manifest_and_profile_must_share_exact_payload_binding(self):
        old = self.read('parent-filesystem-manifest.json')
        current = self.read('filesystem-manifest.json')
        config = self.read('test-access-configuration.json')
        for mutation in ('runtime_entry', 'profile_binding', 'runtime_noncanonical', 'config_binding'):
            blobs = dict(self.blobs); configuration = copy.deepcopy(config)
            if mutation == 'profile_binding':
                value = json.loads(blobs[verify.overlay.PRIVATE_PROFILE]); value['access_runtime_manifest_sha256'] = 'e' * 64
                blobs[verify.overlay.PRIVATE_PROFILE] = encoded(value)
            elif mutation == 'runtime_entry':
                value = json.loads(blobs[verify.overlay.PRIVATE_MANIFEST]); value['files'].pop(next(iter(value['files'])))
                blobs[verify.overlay.PRIVATE_MANIFEST] = encoded(value)
            elif mutation == 'runtime_noncanonical': blobs[verify.overlay.PRIVATE_MANIFEST] += b'\n'
            else: configuration['access_runtime_manifest_sha256'] = 'e' * 64
            with self.subTest(mutation=mutation), self.assertRaises(verify.ArtifactError):
                verify.validate_inventory(old, current, configuration, blobs)

    def test_account_append_size_hash_metadata_and_parent_metadata_are_bound(self):
        for name in verify.overlay.ACCOUNT_APPEND:
            for field, value in (('size_bytes', 123456), ('sha256', 'e' * 64), ('mode', '0666'), ('uid', 1001), ('gid', 1001)):
                bad = self.read('filesystem-manifest.json'); bad['rootfs'][name][field] = value
                with self.subTest(name=name, field=field): self.assert_report_rejected('filesystem-manifest.json', bad)
            for field in ('mode', 'uid', 'gid'):
                bad = self.read('test-access-configuration.json')
                bad['account_parent_metadata'][name][field] += 1
                with self.subTest(name=name, field=field): self.assert_report_rejected('test-access-configuration.json', bad)
        for field in ('account_file_sha256', 'account_parent_metadata'):
            bad = self.read('test-access-configuration.json'); bad[field] = {}
            self.assert_report_rejected('test-access-configuration.json', bad)

    def test_private_archive_mode_extra_member_and_source_tampering_are_refused(self):
        recipe = self.manifest['recipe']
        for raw in (archive_bytes(self.blobs, recipe, private_mode=0o444),
                    archive_bytes(self.blobs, recipe, extra={'recipe/client_ed25519': b'SYNTHETIC SECRET'})):
            self.assert_report_rejected('recipe.tar', raw)
        blobs = dict(self.blobs); blobs['scripts/test-access-boot.py'] += b'# changed\n'
        self.assert_report_rejected('recipe.tar', archive_bytes(blobs, recipe))

    def test_public_evidence_rejects_key_nonce_wire_and_fingerprint(self):
        value = profile_seed.profile()
        wire = base64.b64decode(value['operator_public_key'].split()[1])
        fingerprint = b'SHA256:' + base64.b64encode(hashlib.sha256(wire).digest()).rstrip(b'=')
        for token in (value['operator_public_key'].encode(), value['operator_public_key'].split()[1].encode(),
                      value['challenge'].encode(), fingerprint):
            self.assert_report_rejected('build.log', b'fixture leak ' + token)

    def test_profile_policy_refuses_legacy_noncanonical_or_activated_profile(self):
        raw = self.blobs[verify.overlay.PRIVATE_PROFILE]
        cases = [json.dumps(json.loads(raw)).encode(), raw + b'\n']
        for field, value in (('schema_version', 1), ('ssh_access_enabled', True),
                             ('application_activation_authorized', True)):
            bad = json.loads(raw); bad[field] = value; cases.append(encoded(bad))
        for bad in cases:
            with self.assertRaises(verify.ArtifactError):
                verify.private_profile({verify.overlay.PRIVATE_PROFILE: bad}, {}, b'', b'')

    def test_image_bytes_and_evidence_symlinks_are_checked_without_mounting(self):
        image = self.path / self.manifest['image']['filename']
        image.write_bytes(seed.IMAGE[:-1] + b'x')
        with self.assertRaises(verify.ArtifactError): verify.load_export(self.path)
        report = verify.load_export(self.path, verify_images=False)['report']
        self.assertIs(report['image_sha256_verified'], False)
        self.assertTrue(any('not hashed' in item for item in report['limits']))
        image.write_bytes(seed.IMAGE)
        report_path = self.path / 'build.log'; report_path.unlink(); report_path.symlink_to('fsck-fat.txt')
        with self.assertRaises(OSError): verify.load_export(self.path)

    def test_builder_reuses_only_explicit_public_file_and_never_derives_private_path(self):
        public = self.path / 'operator.pub'
        public.write_text(profile_seed.public_key() + '\n'); public.chmod(0o600)
        read_public = verify.builder.read_operator_public_key
        with mock.patch.object(verify.builder, 'invoke', side_effect=AssertionError('No key generation or VM')), \
                mock.patch.object(verify.builder, 'read_operator_public_key', wraps=read_public) as reader:
            result = verify.builder.select_operator_public_key(self.path, public)
        self.assertEqual(result, profile_seed.public_key())
        reader.assert_called_once_with(public)
        self.assertFalse((self.path / 'operator').exists())


if __name__ == '__main__':
    unittest.main()
