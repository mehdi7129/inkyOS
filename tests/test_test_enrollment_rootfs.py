"""Private enrollment fixtures only; no keys, images, services or hardware."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value
overlay = load(ROOT / 'scripts/configure-test-enrollment-rootfs.py', 'enrollment_rootfs_fixture')
seed_module = load(ROOT / 'tests/test_test_lan_rootfs.py', 'enrollment_prepared_seed')


def profile():
    # Synthetic public-key WIRE bytes only; no private key exists or is made.
    wire = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + bytes(range(1, 33))
    return {'schema_version': 1, 'kind': 'test-lan-enrollment', 'purpose': 'test-enroll-and-stop',
            'state': 'enrollment-pending', 'application_source_commit': overlay.SOURCE_COMMIT,
            'application_manifest_sha256': overlay.MANIFEST_SHA256,
            'parent_image_sha256': overlay.PARENT_IMAGE_SHA256,
            'operator_public_key': 'ssh-ed25519 ' + base64.b64encode(wire).decode(), 'challenge': 'c1' * 32,
            'country_requested': 'FR', 'network_profile_present': False, 'ssh_access_enabled': False,
            'application_activation_authorized': False, 'hardware_qualified': False, 'release_qualified': False}


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


class EnrollmentRootfsTests(unittest.TestCase):
    def setUp(self):
        self.seed = seed_module.TestLanRootfsTests()
        self.seed.setUp()
        self.addCleanup(self.seed.doCleanups)
        self.root, self.boot = self.seed.root, self.seed.boot
        self.seed.configure()
        runtime_dir = self.root / 'usr/local/lib/inkyos'
        runtime_dir.chmod(0o700)
        for relative in ('etc/group', 'etc/gshadow'):
            self.seed.write(self.root, relative, 'LOCKED_GENERIC_ACCOUNT_FIXTURE\n')
        patcher = mock.patch.dict(overlay.prepared.STATIC_PARENT_FILES, seed_module.overlay.STATIC_PARENT_FILES)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.source = self.seed.base / 'enrollment-recipe'
        self.source.mkdir(mode=0o700)
        for name in overlay.RECIPE_FILES - {overlay.PRIVATE_PROFILE}:
            target = self.source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if name == 'application-manifest.json':
                shutil.copyfile(self.root / 'usr/local/share/inkyos/inky-studio-manifest-v1.json', target)
            elif (ROOT / name).is_file():
                shutil.copyfile(ROOT / name, target)
            else:
                target.write_bytes(b'Synthetic unused audit input\n')
        self.profile_path = self.source / overlay.PRIVATE_PROFILE
        self.profile_path.write_bytes(canonical(profile()))
        self.profile_path.chmod(0o600)
        self.refresh_inputs()
    def refresh_inputs(self):
        files = {name: hashlib.sha256((self.source / name).read_bytes()).hexdigest()
                 for name in overlay.RECIPE_FILES}
        (self.source / 'recipe-inputs.json').write_bytes(canonical({'schema_version': 1,
            'source_commit': 'b' * 40, 'worktree_dirty': True, 'files': files}))
    def configure(self):
        return overlay.configure(self.root, self.boot, self.source, self.profile_path, overlay.PARENT_IMAGE_SHA256,
                                 _owner_uid=os.getuid(), _owner_gid=os.getgid(), _app_uid=os.getuid(), _app_gid=os.getgid())
    def verify(self, metadata):
        return overlay.verification(self.root, self.boot, metadata, _owner_uid=os.getuid(), _owner_gid=os.getgid(),
                                    _app_uid=os.getuid(), _app_gid=os.getgid())
    def assert_pristine(self):
        self.assertFalse((self.root / overlay.PROFILE_DIRECTORY).exists())
        self.assertFalse((self.root / overlay.STATE_DIRECTORY).exists())
        self.assertFalse((self.root / overlay.ENABLE_PATH).exists())
    def test_exact_private_delta_preserves_boot_parent_private_directory_and_inactive_application(self):
        before = {name: (self.root / name).read_bytes() for name in overlay.PRESERVED_FILES}
        boot_before = overlay.boot_snapshot(overlay.prepared.safe_tree(self.boot))
        with mock.patch('subprocess.Popen', side_effect=AssertionError('No commands allowed')):
            metadata = self.configure()
            report = self.verify(metadata)
        self.assertEqual(set(report['checks']), overlay.CHECKS)
        self.assertEqual(len(report['checks']), 16)
        self.assertTrue(all(value is True for value in report['checks'].values()))
        self.assertEqual(overlay.boot_snapshot(overlay.prepared.safe_tree(self.boot)), boot_before)
        for name, raw in before.items():
            self.assertEqual((self.root / name).read_bytes(), raw, name)
        self.assertEqual(stat.S_IMODE((self.root / 'usr/local/lib/inkyos').stat().st_mode), 0o700)
        self.assertEqual((self.root / overlay.PROFILE_PATH).read_bytes(), self.profile_path.read_bytes())
        self.assertEqual(stat.S_IMODE((self.root / overlay.PROFILE_PATH).stat().st_mode), 0o600)
        for name in (overlay.PROFILE_DIRECTORY, overlay.STATE_DIRECTORY):
            self.assertEqual(stat.S_IMODE((self.root / name).stat().st_mode), 0o700)
        self.assertEqual(list((self.root / overlay.STATE_DIRECTORY).iterdir()), [])
        self.assertEqual(os.readlink(self.root / overlay.ENABLE_PATH), overlay.UNIT_TARGET)
        for name, (path, mode) in overlay.PAYLOADS.items():
            self.assertEqual((self.root / path).read_bytes(), (self.source / name).read_bytes())
            self.assertEqual(stat.S_IMODE((self.root / path).stat().st_mode), mode)
        self.assertTrue(report['private_artifact'])
        self.assertTrue(report['no_active_application'])
        self.assertEqual(report['bootstrap_action'], 'enroll-and-stop')
        for name in ('ready_for_activation', 'application_started', 'hardware_qualified', 'release_qualified'):
            self.assertFalse(report[name])
        encoded = json.dumps(report)
        self.assertNotIn(profile()['operator_public_key'], encoded)
        self.assertNotIn(profile()['challenge'], encoded)
        self.assertNotIn('SHA256:', encoded)
    def test_missing_or_crossed_parent_pin_booted_image_and_unknown_marker_refused_before_writes(self):
        with self.assertRaises(ValueError):
            overlay.configure(self.root, self.boot, self.source, self.profile_path, 'a' * 64)
        self.assert_pristine()
        path = self.root / 'etc/machine-id'
        raw = path.read_bytes(); path.write_bytes(b'0' * 32 + b'\n')
        with self.assertRaises(ValueError): self.configure()
        self.assert_pristine(); path.write_bytes(raw)
        marker = self.root / overlay.prepared.MARKER_PATH
        raw = marker.read_bytes()
        value = json.loads(raw); value['source_commit'] = 'f' * 40
        marker.write_bytes(canonical(value))
        with self.assertRaises(ValueError): self.configure()
        self.assert_pristine(); marker.write_bytes(raw)
        unknown = self.seed.write(self.root, 'etc/inkyos-unknown.json', 'FIXTURE\n')
        with self.assertRaises(ValueError): self.configure()
        self.assert_pristine(); unknown.unlink()
        release = self.root / 'etc/inkyos-release.json'
        raw = release.read_bytes(); release.write_bytes(b'[]\n')
        with self.assertRaises(ValueError): self.configure()
        self.assert_pristine(); release.write_bytes(raw)
    def test_arbitrary_profile_path_is_rejected_without_opening_it(self):
        with mock.patch.object(overlay, 'read_profile', side_effect=AssertionError('No arbitrary private reads')):
            for name in ('/etc/shadow', str(self.source / 'other.json')):
                with self.assertRaises(ValueError):
                    overlay.configure(self.root, self.boot, self.source, name, overlay.PARENT_IMAGE_SHA256)
        self.assert_pristine()
    def test_invalid_recipe_sources_are_rejected_before_private_profile_read(self):
        path = self.source / 'recipe-inputs.json'
        value = json.loads(path.read_bytes()); value['files']['scripts/observe-test-radio.py'] = '0' * 64
        path.write_bytes(canonical(value))
        with mock.patch.object(overlay, 'read_profile', side_effect=AssertionError('No premature private reads')):
            with self.assertRaises(ValueError): self.configure()
        self.assert_pristine()
    def test_profile_modes_links_size_duplicate_fields_and_schema_are_refused(self):
        raw = self.profile_path.read_bytes()
        for mode in (0o644, 0o666):
            self.profile_path.chmod(mode)
            with self.assertRaises(ValueError): self.configure()
            self.assert_pristine()
        self.profile_path.chmod(0o600)
        bad_values = [dict(profile(), challenge='0' * 64), dict(profile(), country_requested='US'),
                      dict(profile(), ssh_access_enabled=True), dict(profile(), extra='PRIVATE'),
                      dict(profile(), operator_public_key=profile()['operator_public_key'] + ' comment')]
        for value in bad_values:
            self.profile_path.write_bytes(canonical(value)); self.refresh_inputs()
            with self.assertRaises(ValueError): self.configure()
            self.assert_pristine()
        for value in (b'x' * 4097, b'{"schema_version":1,"schema_version":1}',
                      json.dumps(profile()).encode(), canonical(profile()) + b'\n', canonical(profile()).rstrip(b'\n')):
            self.profile_path.write_bytes(value); self.refresh_inputs()
            with self.assertRaises(ValueError): self.configure()
            self.assert_pristine()
        self.profile_path.write_bytes(raw); self.refresh_inputs()
        sentinel = self.seed.base / 'synthetic-profile'; sentinel.write_bytes(raw); sentinel.chmod(0o600)
        for kind in ('symlink', 'hardlink'):
            self.profile_path.unlink()
            if kind == 'symlink': self.profile_path.symlink_to(sentinel)
            else: os.link(sentinel, self.profile_path)
            with self.assertRaises((ValueError, OSError)): self.configure()
            self.assert_pristine()
            self.assertEqual(sentinel.read_bytes(), raw)
    def test_existing_state_runtime_hostkey_fat_report_network_or_unknown_hook_refused(self):
        cases = [(self.root, overlay.STATE_DIRECTORY + '/state.json'),
                 (self.root, 'etc/ssh/ssh_host_ed25519_key'),
                 (self.boot, 'inkyos-test-enrollment.json'),
                 (self.root, 'etc/NetworkManager/system-connections/private.nmconnection'),
                 (self.root, 'etc/systemd/system/inkyos-test-other.service')]
        for tree, name in cases:
            path = self.seed.write(tree, name, 'PRIVATE_FIXTURE\n')
            with self.assertRaises(ValueError): self.configure()
            self.assertFalse((self.root / overlay.PROFILE_DIRECTORY).exists())
            path.unlink()
            if name.startswith(overlay.STATE_DIRECTORY + '/'):
                path.parent.rmdir()
    def test_app_ssh_update_unmasking_and_writable_private_parent_refused(self):
        for unit in overlay.MASKS:
            path = self.root / 'etc/systemd/system' / unit
            path.unlink(); path.symlink_to('/usr/lib/systemd/system/' + unit)
            with self.assertRaises(ValueError): self.configure()
            self.assert_pristine()
            path.unlink(); path.symlink_to('/dev/null')
        (self.root / 'usr/local/lib/inkyos').chmod(0o755)
        with self.assertRaises(ValueError): self.configure()
        self.assert_pristine()
    def test_second_configuration_and_postconfiguration_mutations_fail(self):
        metadata = self.configure()
        with self.assertRaises(ValueError): self.configure()
        for path, value in ((self.root / overlay.STATE_DIRECTORY / 'state.json', b'PRIVATE'),
                            (self.root / overlay.PROFILE_DIRECTORY / 'extra', b'PRIVATE'),
                            (self.boot / 'extra-report.json', b'PRIVATE')):
            path.write_bytes(value)
            with self.assertRaises(ValueError): self.verify(metadata)
            path.unlink()
        path = self.root / overlay.PAYLOADS['scripts/observe-test-radio.py'][0]
        path.chmod(0o755)
        with self.assertRaises(ValueError): self.verify(metadata)


if __name__ == '__main__':
    unittest.main()
