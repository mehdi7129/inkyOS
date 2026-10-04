"""Synthetic rootfs only; missing future payloads are inert fixture text.

These checks exercise offline composition and refusal, not service semantics,
systemd, PAM, a real image, boot, network, enrollment or physical qualification.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import unittest
from unittest import mock

from test_test_access_policy import profile

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


overlay = module('access_rootfs_configuration_fixture', ROOT / 'scripts/configure-test-access-rootfs.py')
seed_module = module('access_prepared_seed_fixture', ROOT / 'tests/test_test_lan_rootfs.py')


class ConfigureAccessTests(unittest.TestCase):
    def setUp(self):
        self.seed = seed_module.TestLanRootfsTests()
        self.seed.setUp()
        self.addCleanup(self.seed.doCleanups)
        self.seed.select_candidate()
        self.seed.write(self.seed.source, 'scripts/test-lan-preflight.py', (ROOT / 'scripts/test-lan-preflight.py').read_text())
        self.seed.refresh_inputs()
        self.seed.configure()
        self.root, self.boot = self.seed.root, self.seed.boot
        (self.root / 'usr/local/lib/inkyos').chmod(0o700)
        pinned = mock.patch.dict(overlay.prepared.DRAIN_STATIC_PARENT_FILES, seed_module.overlay.DRAIN_STATIC_PARENT_FILES)
        pinned.start()
        self.addCleanup(pinned.stop)
        for name, content, mode in (
            ('etc/passwd', 'root:x:0:0:root:/root:/usr/sbin/nologin\ninky:x:1000:1000:Inky:/home/inky:/usr/sbin/nologin\n'
                           'inky-network:x:993:993:Network:/nonexistent:/usr/sbin/nologin\n', 0o644),
            ('etc/group', 'root:x:0:\ninky:x:1000:\ninky-network:x:993:\n', 0o644),
            ('etc/shadow', 'root:*:0:0:99999:7:::\ninky:!:0:0:99999:7:::\ninky-network:!:0:0:99999:7:::\n', 0o640),
            ('etc/gshadow', 'root:*::\ninky:!::\ninky-network:!::\n', 0o640),
        ):
            self.seed.write(self.root, name, content, mode)
        self.source = self.seed.base / 'private-access-recipe'
        self.source.mkdir(mode=0o700)
        self.source.chmod(0o700)
        for name in overlay.SOURCES:
            target = self.source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if name == 'application-manifest.json':
                shutil.copyfile(self.root / 'usr/local/share/inkyos/inky-studio-manifest-v1.json', target)
            elif (ROOT / name).is_file():
                shutil.copyfile(ROOT / name, target)
            else:
                target.write_bytes(b'# SYNTHETIC INERT FUTURE PAYLOAD; MUST NEVER BE EXECUTED\n')
            target.chmod(0o644)
        self.seed.write(self.source, 'parent-manifest.json', '{"kind":"synthetic-parent-audit-input"}\n')
        self.value = profile()
        self.profile_path = self.source / overlay.PRIVATE_PROFILE
        self.refresh_private_recipe()
        self.kwargs = dict(_owner_uid=os.getuid(), _owner_gid=os.getgid(), _app_uid=os.getuid(), _app_gid=os.getgid())

    def refresh_private_recipe(self):
        manifest = overlay.build_manifest(self.source)
        raw = overlay.policy.canonical(manifest)
        self.seed.write(self.source, overlay.PRIVATE_MANIFEST, raw.decode())
        self.value['access_runtime_manifest_sha256'] = hashlib.sha256(raw).hexdigest()
        self.profile_path.write_bytes(overlay.policy.canonical(self.value))
        self.profile_path.chmod(0o600)
        self.refresh_inputs()

    def refresh_inputs(self):
        files = {name: hashlib.sha256((self.source / name).read_bytes()).hexdigest() for name in overlay.RECIPE_FILES}
        self.seed.write(self.source, 'recipe-inputs.json', overlay.policy.canonical(
            {'schema_version': 1, 'source_commit': 'b' * 40, 'worktree_dirty': True, 'files': files}).decode())

    def configure(self):
        return overlay.configure(self.root, self.boot, self.source, self.profile_path, overlay.PARENT_IMAGE_SHA256, **self.kwargs)

    def verify(self, metadata):
        return overlay.verification(self.root, self.boot, metadata, **self.kwargs)

    def pristine(self):
        for path in (overlay.PROFILE_DIRECTORY, overlay.STATE_DIRECTORY, overlay.CACHE_DIRECTORY,
                     overlay.SSH_DIRECTORY, overlay.SSH_PUBLIC_DIRECTORY, overlay.MANIFEST_PATH, overlay.ENABLE_PATH):
            self.assertFalse((self.root / path).exists() or (self.root / path).is_symlink(), path)
        for name in overlay.ACCOUNT_APPEND:
            self.assertNotIn(b'inky-test:', (self.root / name).read_bytes())

    def test_manifest_is_pure_static_exact_and_does_not_read_profile_or_identity(self):
        read = overlay.read_bytes
        calls = []
        def track(tree, name, **options):
            calls.append(name)
            return read(tree, name, **options)
        with mock.patch.object(overlay, 'read_bytes', side_effect=track), \
                mock.patch('subprocess.Popen', side_effect=AssertionError('No commands')):
            manifest = overlay.build_manifest(self.source)
        self.assertEqual(set(manifest), runtime_fields := {'schema_version', 'kind', 'application_source_commit',
            'application_manifest_sha256', 'parent_image_sha256', 'files'})
        self.assertEqual(len(runtime_fields), 6)
        self.assertEqual(set(manifest['files']), overlay.runtime.STATIC_PATHS)
        self.assertEqual(set(calls), set(overlay.PAYLOADS))
        self.assertTrue(all(value['mode'] in {'0555', '0644', '0440'} for value in manifest['files'].values()))
        self.assertNotIn(self.value['operator_public_key'], json.dumps(manifest))
        self.assertNotIn(self.value['challenge'], json.dumps(manifest))

    def test_configure_exact_delta_and_eighteen_closed_checks(self):
        before = {name: (self.root / name).read_bytes() for name in overlay.PRESERVED_FILES | set(overlay.ACCOUNT_APPEND)}
        boot_before = overlay.boot_snapshot(overlay.prepared.safe_tree(self.boot))
        with mock.patch('subprocess.Popen', side_effect=AssertionError('No target commands')):
            metadata = self.configure()
            result = self.verify(metadata)
        self.assertTrue(result['passed'])
        self.assertEqual(set(result['checks']), overlay.CHECKS)
        self.assertEqual(len(result['checks']), 18)
        self.assertEqual(result['kind'], 'test-lan-access')
        self.assertEqual(result['bootstrap_action'], 'enrollment-then-signed-access')
        self.assertIs(result['no_active_application'], True)
        self.assertTrue(all(value is True for value in result['checks'].values()))
        self.assertEqual(overlay.boot_snapshot(overlay.prepared.safe_tree(self.boot)), boot_before)
        for name in overlay.PRESERVED_FILES:
            self.assertEqual((self.root / name).read_bytes(), before[name], name)
        for name, line in overlay.ACCOUNT_APPEND.items():
            self.assertEqual((self.root / name).read_bytes(), before[name] + line)
            self.assertEqual(metadata['account_file_sha256'][name],
                {'before': hashlib.sha256(before[name]).hexdigest(), 'after': hashlib.sha256(before[name] + line).hexdigest()})
        for name in (overlay.PROFILE_DIRECTORY, overlay.STATE_DIRECTORY, overlay.CACHE_DIRECTORY):
            self.assertEqual(stat.S_IMODE((self.root / name).stat().st_mode), 0o700)
        self.assertEqual(list((self.root / overlay.STATE_DIRECTORY).iterdir()), [])
        self.assertEqual(list((self.root / overlay.CACHE_DIRECTORY).iterdir()), [])
        self.assertEqual((self.root / overlay.AUTHORIZED_KEYS).read_text(), 'restrict ' + self.value['operator_public_key'] + '\n')
        self.assertEqual(stat.S_IMODE((self.root / overlay.AUTHORIZED_KEYS).stat().st_mode), 0o644)
        self.assertEqual(os.readlink(self.root / overlay.ENABLE_PATH), overlay.UNIT_TARGET)
        for unit in ('inkyos-test-activate.service', 'inkyos-test-drain.service'):
            self.assertFalse((self.root / 'etc/systemd/system/multi-user.target.wants' / unit).exists())
        for unit in ('inky-studio.service', 'inky-network.service'):
            self.assertFalse((self.root / 'etc/systemd/system' / (unit + '.d') / '10-inkyos-test-access.conf').exists())
            self.assertEqual(os.readlink(self.root / 'etc/systemd/system' / unit), '/dev/null')
        self.assertEqual(stat.S_IMODE((self.root / 'usr/local/lib/inkyos').stat().st_mode), 0o700)
        for key in ('application_started', 'ssh_started', 'network_connected', 'ready_for_activation',
                    'hardware_qualified', 'release_qualified'):
            self.assertIs(result[key], False)
        self.assertNotIn(self.value['operator_public_key'], json.dumps(result))
        self.assertNotIn(self.value['challenge'], json.dumps(result))

    def test_portable_proof_survives_same_bytes_new_inode_and_new_mtime(self):
        metadata = self.configure()
        paths = [*overlay.PRESERVED_FILES, *overlay.ACCOUNT_APPEND, overlay.PROFILE_PATH, overlay.MANIFEST_PATH]
        for name in paths:
            path = self.root / name
            raw, info = path.read_bytes(), path.stat()
            path.unlink()
            path.write_bytes(raw)
            path.chmod(stat.S_IMODE(info.st_mode))
            if os.geteuid() == 0:
                os.chown(path, info.st_uid, info.st_gid)
        self.assertTrue(self.verify(metadata)['passed'])

    def test_only_current_parent_tuple_and_never_booted_image_are_admitted_before_writes(self):
        with self.assertRaises(ValueError):
            overlay.configure(self.root, self.boot, self.source, self.profile_path, 'a' * 64, **self.kwargs)
        self.pristine()
        marker = self.root / overlay.prepared.MARKER_PATH
        old = marker.read_bytes()
        for field, value in (('source_commit', overlay.prepared.SOURCE_COMMIT),
                             ('manifest_sha256', overlay.prepared.MANIFEST_SHA256), ('release_qualified', True)):
            changed = json.loads(old)
            changed[field] = value
            marker.write_bytes(overlay.policy.canonical(changed))
            with self.assertRaises(ValueError):
                self.configure()
            self.pristine()
        marker.write_bytes(old)
        self.seed.write(self.root, 'etc/machine-id', 'a' * 32 + '\n')
        with self.assertRaises(ValueError):
            self.configure()
        self.pristine()

    def test_old_or_duplicate_access_hook_refused_before_writes(self):
        for path in ('etc/systemd/system/inkyos-test-enrollment.service',
                     'usr/lib/systemd/system/inkyos-test-other.service',
                     'etc/systemd/system/multi-user.target.wants/inkyos-test-ssh.service'):
            item = self.seed.write(self.root, path, 'SYNTHETIC OLD HOOK\n')
            with self.assertRaises(ValueError):
                self.configure()
            self.pristine()
            item.unlink()

    def test_used_uid_gid_operator_name_membership_or_malformed_accounts_refused(self):
        changes = [
            ('etc/passwd', 'other:x:1001:1000::/nonexistent:/bin/sh\n'),
            ('etc/passwd', 'other:x:1002:1001::/nonexistent:/bin/sh\n'),
            ('etc/group', 'other:x:1001:\n'),
            ('etc/passwd', 'inky-test:x:1100:1100::/nonexistent:/bin/sh\n'),
            ('etc/group', 'other:x:1100:inky-test\n'),
            ('etc/gshadow', 'other:!:inky-test:\n'),
            ('etc/shadow', 'other:UNLOCKED:0:0:99999:7:::\n'),
            ('etc/passwd', 'MALFORMED\n'),
        ]
        for name, extra in changes:
            path = self.root / name
            original = path.read_bytes()
            path.write_bytes(original + extra.encode())
            with self.assertRaises(ValueError):
                self.configure()
            self.assertFalse((self.root / overlay.PROFILE_DIRECTORY).exists())
            self.assertEqual(path.read_bytes(), original + extra.encode())
            path.write_bytes(original)
            self.pristine()

    def test_network_host_key_capsule_identity_or_runtime_state_refused_without_private_reads(self):
        cases = [(self.root, 'etc/ssh/ssh_host_ed25519_key'),
                 (self.root, 'var/lib/inkyos/system.json'),
                 (self.root, 'etc/NetworkManager/system-connections/private.nmconnection'),
                 (self.root, overlay.CACHE_DIRECTORY + '/state.json'),
                 (self.boot, 'InKyAcC.JsN'), (self.boot, '.INKYACC.SIG.tmp'),
                 (self.boot, 'inkyos-test-enrollment.json')]
        for tree, relative in cases:
            path = self.seed.write(tree, relative, 'SYNTHETIC PRIVATE ARTIFACT\n')
            read = overlay.read_bytes
            def guarded(t, name, **options):
                self.assertNotEqual(t.root / name, path)
                return read(t, name, **options)
            with mock.patch.object(overlay, 'read_bytes', side_effect=guarded):
                with self.assertRaises(ValueError):
                    self.configure()
            self.assertFalse((self.root / overlay.PROFILE_DIRECTORY).exists())
            path.unlink()
            if relative.startswith(overlay.CACHE_DIRECTORY + '/'):
                path.parent.rmdir()

    def test_app_helper_vendor_ssh_updates_and_enabled_wifi_refused_before_writes(self):
        for unit in overlay.MASKS:
            path = self.root / 'etc/systemd/system' / unit
            path.unlink()
            path.symlink_to('/usr/lib/systemd/system/' + unit)
            with self.assertRaises(ValueError):
                self.configure()
            self.pristine()
            path.unlink()
            path.symlink_to('/dev/null')
        self.seed.write(self.root, 'var/lib/NetworkManager/NetworkManager.state', '[main]\nWirelessEnabled=true\n')
        with self.assertRaises(ValueError):
            self.configure()
        self.pristine()

    def test_invalid_profile_path_modes_schema_and_binding_are_refused(self):
        with mock.patch.object(overlay, 'read_profile', side_effect=AssertionError('Arbitrary profile read')):
            with self.assertRaises(ValueError):
                overlay.configure(self.root, self.boot, self.source, '/etc/shadow', overlay.PARENT_IMAGE_SHA256, **self.kwargs)
        for mode in (0o644, 0o666):
            self.profile_path.chmod(mode)
            with self.assertRaises(ValueError):
                self.configure()
            self.pristine()
        self.profile_path.chmod(0o600)
        for change in ({'schema_version': 1}, {'challenge': '0' * 64}, {'ssh_access_enabled': True},
                       {'access_runtime_manifest_sha256': 'a' * 64}, {'country_requested': 'US'}):
            self.profile_path.write_bytes(overlay.policy.canonical(dict(self.value, **change)))
            self.refresh_inputs()
            with self.assertRaises(ValueError):
                self.configure()
            self.pristine()

    def test_manifest_extra_identity_noncanonical_or_forged_hash_refused_before_writes(self):
        path = self.source / overlay.PRIVATE_MANIFEST
        original = path.read_bytes()
        altered = json.loads(original)
        altered['files'][overlay.PROFILE_PATH] = {'sha256': 'a' * 64, 'mode': '0600'}
        for raw in (overlay.policy.canonical(altered), json.dumps(json.loads(original)).encode(), b'{"kind":"untrusted"}\n'):
            path.write_bytes(raw)
            self.refresh_inputs()
            with self.assertRaises(ValueError):
                self.configure()
            self.pristine()

    def test_inherited_preflight_and_generic_parent_bytes_are_not_replaced(self):
        name = next(iter(overlay.INHERITED_PAYLOADS))
        path = self.root / name
        original = path.read_bytes()
        path.chmod(0o755)
        path.write_bytes(original + b'\n# CHANGED\n')
        path.chmod(0o555)
        with self.assertRaises(ValueError):
            self.configure()
        self.pristine()
        self.assertEqual(path.read_bytes(), original + b'\n# CHANGED\n')

    def test_recipe_tampering_missing_inputs_and_source_links_refused_before_profile_read(self):
        recipe = self.source / 'recipe-inputs.json'
        original = recipe.read_bytes()
        value = json.loads(original)
        value['files']['scripts/observe-test-radio.py'] = '0' * 64
        recipe.write_bytes(overlay.policy.canonical(value))
        with mock.patch.object(overlay, 'read_profile', side_effect=AssertionError('Premature profile read')):
            with self.assertRaises(ValueError):
                self.configure()
        self.pristine()
        recipe.write_bytes(original)
        path = self.source / 'overlay-test-access/sshd_config'
        contents = path.read_bytes()
        outside = self.seed.base / 'outside-synthetic'
        outside.write_bytes(contents)
        for kind in ('symlink', 'hardlink'):
            path.unlink()
            if kind == 'symlink':
                path.symlink_to(outside)
            else:
                os.link(outside, path)
            with self.assertRaises((ValueError, OSError)):
                self.configure()
            self.pristine()

    def test_second_configuration_refuses_existing_child_and_preserves_first_result(self):
        metadata = self.configure()
        before = {name: (self.root / name).read_bytes() for name in overlay.ACCOUNT_APPEND}
        with self.assertRaises(ValueError):
            self.configure()
        self.assertEqual(before, {name: (self.root / name).read_bytes() for name in overlay.ACCOUNT_APPEND})
        self.assertTrue(self.verify(metadata)['passed'])

    def test_verification_detects_account_profile_authorization_or_enabled_ssh_mutation(self):
        metadata = self.configure()
        cases = [(overlay.AUTHORIZED_KEYS, b'command="/bin/sh" ssh-ed25519 SYNTHETIC\n'),
                 ('etc/shadow', (self.root / 'etc/shadow').read_bytes().replace(b'inky-test:!::0:::::', b'inky-test:!:0:0:::::')),
                 (overlay.PROFILE_PATH, overlay.policy.canonical(dict(self.value, challenge='d' * 64)))]
        for relative, changed in cases:
            path = self.root / relative
            original = path.read_bytes()
            path.write_bytes(changed)
            with self.assertRaises(ValueError):
                self.verify(metadata)
            path.write_bytes(original)
        path = self.root / 'etc/systemd/system/multi-user.target.wants/inkyos-test-ssh.service'
        path.symlink_to('/usr/lib/systemd/system/inkyos-test-ssh.service')
        with self.assertRaises(ValueError):
            self.verify(metadata)

    def test_grow_and_boot_bytes_preserved_and_later_change_detected(self):
        metadata = self.configure()
        path = self.boot / 'cmdline.txt'
        path.write_text('console=tty1 rootwait\n')
        with self.assertRaises(ValueError):
            self.verify(metadata)


if __name__ == '__main__':
    unittest.main()
