"""Prepared TEST LAN overlay fixtures; no image, service, radio or disk access."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch


REPOSITORY = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('configure_test_lan_rootfs', REPOSITORY / 'scripts/configure-test-lan-rootfs.py')
overlay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(overlay)


class TestLanRootfsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root, self.boot, self.source = (self.base / name for name in ('root', 'boot', 'source'))
        for path in (self.root, self.boot, self.source):
            path.mkdir()
        self.parent_hash = 'a' * 64
        manifest = (REPOSITORY / 'tests/fixtures/application-manifest-758a2bf7.json').read_text()
        digest = hashlib.sha256(manifest.encode()).hexdigest()
        self.release = json.dumps({'kind': 'application-prototype', 'status': 'not-hardware-qualified',
            'application': {'source_commit': overlay.SOURCE_COMMIT, 'manifest_sha256': digest,
                            'application_version': '0.5.0-rc.2',
                            'startup': 'masked-pending-firstboot-contract', 'release_qualified': False}}) + '\n'
        for relative, content in {
            'etc/machine-id': 'uninitialized\n', 'etc/inkyos-release.json': self.release,
            'etc/shadow': 'root:*:0:0:99999:7:::\ninky:!:0:0:99999:7:::\ninky-network:!:0:0:99999:7:::\n',
            'etc/passwd': 'UNCHANGED_ACCOUNT_DATABASE\n',
            'home/inky/inky-studio/server/SOURCE_COMMIT': overlay.SOURCE_COMMIT + '\n',
            'var/lib/NetworkManager/NetworkManager.state': '[main]\nWirelessEnabled=false\n',
        }.items():
            self.write(self.root, relative, content)
        # mkdir(parents=True) applies the host umask to implicit parents. Model
        # both app directories explicitly, including Linux's usual umask 0002.
        for name in ('etc/ssh', 'etc/NetworkManager/system-connections',
                     'var/lib/inky-studio', 'var/lib/inky-studio/photos'):
            directory = self.root / name
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o755)
        for name in ('inky-studio.service', 'inky-network.service', 'ssh.service', 'ssh.socket', 'sshswitch.service'):
            path = self.root / 'etc/systemd/system' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to('/dev/null')
        static_fixture = {}
        for name, (_pin, mode) in overlay.STATIC_PARENT_FILES.items():
            content = '# inert declarative configuration fixture ' + name + '\n'
            self.write(self.root, name, content, mode)
            static_fixture[name] = (hashlib.sha256(content.encode()).hexdigest(), mode)
        parent_config = patch.dict(overlay.STATIC_PARENT_FILES, static_fixture)
        parent_config.start()
        self.addCleanup(parent_config.stop)
        for name in overlay.PROTECTED_FILES:
            tree, relative = name.split('/', 1)
            self.write(self.root if tree == 'root' else self.boot, relative, 'PRESERVED_' + name + '\n')
        self.cmdline = 'console=tty1 rootwait resize\n'
        self.config = '# exact parent fixture\nauto_initramfs=1\n[all]\ninclude inkyos.txt\n'
        self.write(self.boot, 'cmdline.txt', self.cmdline)
        self.write(self.boot, 'config.txt', self.config)
        self.write(self.boot, 'inkyos.txt', overlay.EXPECTED_INKYOS_CONFIG)
        for name in overlay.SOURCES:
            if name == 'scripts/test-lan-preflight.py':
                self.write(self.source, name, 'raise AssertionError("PREFLIGHT_NOT_EXECUTED_BY_PREPARATION")\n')
            elif name == 'application-manifest.json':
                self.write(self.source, name, manifest)
            else:
                path = self.source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(REPOSITORY / name, path)
        self.refresh_inputs()

    def write(self, tree, relative, content, mode=0o644):
        path = tree / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(mode)
        return path

    def refresh_inputs(self):
        self.write(self.source, 'recipe-inputs.json', json.dumps({'schema_version': 1, 'source_commit': 'b' * 40,
            'worktree_dirty': False, 'files': {name: hashlib.sha256((self.source / name).read_bytes()).hexdigest()
                                             for name in overlay.SOURCES}}))

    def configure(self):
        return overlay.configure(self.root, self.boot, self.source, self.parent_hash,
            _owner_uid=os.getuid(), _owner_gid=os.getgid(), _app_uid=os.getuid(), _app_gid=os.getgid())

    def verify(self, metadata):
        return overlay.verification(self.root, self.boot, metadata, _owner_uid=os.getuid(), _owner_gid=os.getgid(),
                                    _app_uid=os.getuid(), _app_gid=os.getgid())

    def assert_unprepared(self):
        self.assertFalse((self.root / overlay.MARKER_PATH).exists())
        self.assertFalse((self.root / 'usr/local/lib/inkyos/test-lan-preflight.py').exists())
        self.assertEqual((self.boot / 'config.txt').read_text(), self.config)

    def test_static_preparation_keeps_app_inactive_and_has_no_automatic_hook(self):
        before = {name: (self.root / name).read_bytes() for name in
                  ('etc/machine-id', 'etc/shadow', 'etc/passwd', 'etc/inkyos-release.json',
                   'home/inky/inky-studio/server/SOURCE_COMMIT', 'var/lib/NetworkManager/NetworkManager.state')}
        protected = overlay.protected_hashes(overlay.safe_tree(self.root), overlay.safe_tree(self.boot))
        metadata = self.configure()
        for name, original in before.items():
            self.assertEqual((self.root / name).read_bytes(), original, name)
        self.assertEqual(metadata['protected_boot_grow_sha256'], protected)
        self.assertEqual(overlay.protected_hashes(overlay.safe_tree(self.root), overlay.safe_tree(self.boot)), protected)
        self.assertEqual((self.boot / 'config.txt').read_text(), self.config.rstrip() + overlay.BOOT_APPEND)
        self.assertNotIn('disable-wifi', (self.boot / 'config.txt').read_text())
        self.assertFalse((self.root / 'etc/systemd/system/inkyos-test-lan.service').exists())
        self.assertFalse((self.root / 'etc/systemd/system/inkyos-test-lan.timer').exists())
        self.assertFalse((self.boot / 'inkyos-diagnostics').exists())
        self.assertEqual(list((self.root / 'var/lib/inky-studio/photos').iterdir()), [])
        for unit in overlay.MASKS:
            self.assertEqual(os.readlink(self.root / 'etc/systemd/system' / unit), '/dev/null')

    def test_marker_and_manual_payload_are_pinned_readonly_and_explicitly_unqualified(self):
        self.write(self.source, 'scripts/unreviewed-payload.py', 'DO_NOT_IMPORT\n')
        metadata = self.configure()
        self.assertEqual(metadata, json.loads((self.root / overlay.MARKER_PATH).read_text()))
        self.assertEqual(metadata['kind'], 'test-lan-prepared')
        self.assertEqual(metadata['state'], 'prepared-inactive')
        self.assertEqual(metadata['source_commit'], overlay.SOURCE_COMMIT)
        self.assertEqual(metadata['manifest_sha256'], overlay.MANIFEST_SHA256)
        self.assertEqual(metadata['parent_image_sha256'], self.parent_hash)
        for name in ('ready_for_activation', 'activation_authorized', 'factory_authority', 'hardware_qualified',
                     'release_qualified', 'auto_poweroff', 'privileges_added', 'first_boot_without_lan'):
            self.assertIs(metadata[name], False, name)
        for name, (relative, mode) in overlay.PAYLOADS.items():
            target = self.root / relative
            self.assertEqual(target.read_bytes(), (self.source / name).read_bytes())
            self.assertEqual(target.stat().st_mode & 0o777, mode)
            self.assertEqual(target.stat().st_uid, os.getuid())
        self.assertEqual((self.root / overlay.MARKER_PATH).stat().st_mode & 0o777, 0o644)
        self.assertEqual(set(metadata['source_file_sha256']), overlay.SOURCES)
        self.assertFalse((self.root / 'usr/local/lib/inkyos/unreviewed-payload.py').exists())

    def test_original_parent_selects_original_marker_and_manifest(self):
        raw = (REPOSITORY / 'tests/fixtures/application-manifest-6a697d1.json').read_text()
        source = json.loads(raw)['source_commit']
        digest = hashlib.sha256(raw.encode()).hexdigest()
        release = json.loads(self.release)
        release['application'].update(source_commit=source, manifest_sha256=digest)
        self.write(self.root, 'etc/inkyos-release.json', json.dumps(release))
        self.write(self.root, 'home/inky/inky-studio/server/SOURCE_COMMIT', source + '\n')
        self.write(self.source, 'application-manifest.json', raw)
        self.refresh_inputs()
        metadata = self.configure()
        self.assertEqual(metadata['source_commit'], source)
        self.assertEqual(metadata['manifest_sha256'], digest)
        self.assertEqual((self.root / overlay.PAYLOADS['application-manifest.json'][0]).read_text(), raw)
        self.assertTrue(self.verify(metadata)['passed'])

    def test_allowlist_matches_application_gate_and_refuses_crossed_pairs(self):
        spec = importlib.util.spec_from_file_location('application_config_pins', REPOSITORY / 'scripts/configure-application-rootfs.py')
        app_config = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(app_config)
        self.assertEqual(overlay.REVIEWED_APPLICATIONS, app_config.REVIEWED_APPLICATIONS)
        self.assertEqual(len(overlay.REVIEWED_APPLICATIONS), 2)
        for source, pin in overlay.REVIEWED_APPLICATIONS.items():
            for other in (*overlay.REVIEWED_APPLICATIONS.values(), 'f' * 64):
                changed = json.loads(self.release)
                changed['application'].update(source_commit=source, manifest_sha256=other)
                if other == pin:
                    self.assertTrue(overlay.reviewed_application(changed['application']))
                    continue
                self.write(self.root, 'etc/inkyos-release.json', json.dumps(changed))
                self.write(self.root, 'home/inky/inky-studio/server/SOURCE_COMMIT', source + '\n')
                with self.subTest(source=source, digest=other), self.assertRaisesRegex(ValueError, 'Exact inactive parent'):
                    self.configure()
                self.assert_unprepared()

    def test_verification_has_exact_checks_and_does_not_authorize_activation(self):
        metadata = self.configure()
        report = self.verify(metadata)
        self.assertEqual(report['scope'], 'offline-test-lan-prepared-configuration')
        self.assertEqual(set(report['checks']), overlay.CHECKS)
        self.assertTrue(all(value is True for value in report['checks'].values()))
        for name in ('ready_for_activation', 'application_started', 'hardware_qualified', 'release_qualified'):
            self.assertIs(report[name], False)
        self.assertEqual(report['removed_pending_boot_artifacts'], [])
        self.assertEqual(report['marker_sha256'], hashlib.sha256((self.root / overlay.MARKER_PATH).read_bytes()).hexdigest())
        self.write(self.boot, 'cmdline.txt', self.cmdline + 'changed\n')
        with self.assertRaises(ValueError):
            self.verify(metadata)

    def test_booted_image_and_wrong_commit_manifest_kind_or_state_are_refused(self):
        original = (self.root / 'etc/machine-id').read_bytes()
        self.write(self.root, 'etc/machine-id', '0' * 32 + '\n')
        with self.assertRaises(ValueError):
            self.configure()
        self.assert_unprepared()
        (self.root / 'etc/machine-id').write_bytes(original)
        release = json.loads(self.release)
        for key, value in (('source_commit', 'c' * 40), ('manifest_sha256', 'c' * 64), ('startup', 'active'), ('release_qualified', True)):
            changed = json.loads(self.release)
            changed['application'][key] = value
            self.write(self.root, 'etc/inkyos-release.json', json.dumps(changed))
            with self.assertRaises(ValueError):
                self.configure()
            self.assert_unprepared()
        release['kind'] = 'sd-diagnostic'
        self.write(self.root, 'etc/inkyos-release.json', json.dumps(release))
        with self.assertRaises(ValueError):
            self.configure()
        self.assert_unprepared()

    def test_modified_parent_units_helper_privileges_and_overrides_are_refused(self):
        path = self.root / 'usr/local/lib/inky-studio/network-helper.py'
        before = path.read_bytes()
        path.chmod(0o755)
        path.write_text('UNREVIEWED_HELPER\n')
        with self.assertRaises(ValueError):
            self.configure()
        self.assert_unprepared()
        path.write_bytes(before)
        path.chmod(0o555)
        extra = self.write(self.root, 'etc/systemd/system/inky-network.service.d/99-extra.conf', '[Service]\nAmbientCapabilities=CAP_SYS_TIME\n')
        with self.assertRaises(ValueError):
            self.configure()
        self.assert_unprepared()
        self.assertEqual(extra.read_text(), '[Service]\nAmbientCapabilities=CAP_SYS_TIME\n')

    def test_app_helper_and_ssh_unmasking_are_refused(self):
        for unit in ('inky-studio.service', 'inky-network.service', 'ssh.service', 'ssh.socket', 'sshswitch.service'):
            path = self.root / 'etc/systemd/system' / unit
            path.unlink()
            path.symlink_to('/usr/lib/systemd/system/' + unit)
            with self.assertRaises(ValueError):
                self.configure()
            self.assert_unprepared()
            path.unlink()
            path.symlink_to('/dev/null')

    def test_diagnostic_unknown_variant_marker_and_repeat_preparation_are_refused(self):
        for tree, relative in ((self.root, 'etc/inkyos-diagnostic.json'), (self.root, 'etc/inkyos-unknown.json'),
                               (self.root, 'etc/systemd/system/inkyos-sd-diagnostic.timer'),
                               (self.boot, 'INKYOS-DIAGNOSTIC.txt'), (self.boot, 'INKYOS-UNKNOWN.txt')):
            path = self.write(tree, relative, 'PREVIOUS_VARIANT\n')
            with self.assertRaises(ValueError):
                self.configure()
            self.assert_unprepared()
            path.unlink()
        self.configure()
        original = (self.root / overlay.MARKER_PATH).read_bytes()
        with self.assertRaises(ValueError):
            self.configure()
        self.assertEqual((self.root / overlay.MARKER_PATH).read_bytes(), original)

    def test_disabled_wifi_overlay_conflicting_firmware_and_pending_updates_are_refused(self):
        for line in ('dtoverlay=disable-wifi\n', 'dtoverlay=disable-bt\n', 'bootloader_update=1\n'):
            self.write(self.boot, 'config.txt', self.config + line)
            with self.assertRaises(ValueError):
                self.configure()
            self.assertFalse((self.root / overlay.MARKER_PATH).exists())
        self.write(self.boot, 'config.txt', self.config)
        for name in ('recovery.bin', 'RECOVERY.003', 'pieeprom.upd', 'vl805.sig'):
            pending = self.write(self.boot, name, 'FIRMWARE_SENTINEL\n')
            with self.assertRaises(ValueError):
                self.configure()
            self.assert_unprepared()
            self.assertEqual(pending.read_text(), 'FIRMWARE_SENTINEL\n')
            pending.unlink()

    def test_credentials_country_identity_unlocked_account_and_live_wifi_are_refused(self):
        for tree, relative in ((self.root, 'etc/ssh/ssh_host_ed25519_key'),
                               (self.root, 'etc/NetworkManager/system-connections/home.nmconnection'),
                               (self.root, 'var/lib/inkyos/system.json'),
                               (self.root, 'etc/default/crda'), (self.root, 'var/lib/inky-studio/photos/private.jpg'),
                               (self.boot, 'userconf.txt')):
            path = self.write(tree, relative, 'PRIVATE_SENTINEL\n')
            with self.assertRaises(ValueError):
                self.configure()
            self.assert_unprepared()
            path.unlink()
        original = (self.root / 'var/lib/NetworkManager/NetworkManager.state').read_bytes()
        self.write(self.root, 'var/lib/NetworkManager/NetworkManager.state', '[main]\nWirelessEnabled=true\n')
        with self.assertRaises(ValueError):
            self.configure()
        self.assert_unprepared()
        (self.root / 'var/lib/NetworkManager/NetworkManager.state').write_bytes(original)
        self.write(self.root, 'etc/shadow', 'root:password:0:0:99999:7:::\n')
        with self.assertRaises(ValueError):
            self.configure()
        self.assert_unprepared()

    def test_data_owner_or_mode_mismatch_refused_before_payload_install(self):
        directory = self.root / 'var/lib/inky-studio/photos'
        directory.chmod(0o777)
        with self.assertRaises(ValueError):
            self.configure()
        self.assert_unprepared()
        directory.chmod(0o755)
        with self.assertRaises(ValueError):
            overlay.configure(self.root, self.boot, self.source, self.parent_hash,
                _owner_uid=os.getuid(), _owner_gid=os.getgid(), _app_uid=os.getuid() + 1, _app_gid=os.getgid())
        self.assert_unprepared()

    def test_source_links_target_links_and_overlapping_roots_refused(self):
        sentinel = self.write(self.base, 'outside-source', 'OUTSIDE_SENTINEL\n')
        path = self.source / 'scripts/test-lan-preflight.py'
        for kind in ('symlink', 'hardlink'):
            path.unlink()
            if kind == 'symlink':
                path.symlink_to(sentinel)
            else:
                os.link(sentinel, path)
            with self.assertRaises(ValueError):
                self.configure()
            self.assert_unprepared()
        path.unlink()
        path.write_text('raise AssertionError("not executed")\n')
        self.refresh_inputs()
        target = self.root / 'usr/local/lib/inkyos/test-lan-preflight.py'
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(sentinel)
        with self.assertRaises(ValueError):
            self.configure()
        self.assertEqual(sentinel.read_text(), 'OUTSIDE_SENTINEL\n')
        alias = self.base / 'alias'
        alias.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(ValueError):
            overlay.configure(alias / 'root', self.boot, self.source, self.parent_hash)
        with self.assertRaises(ValueError):
            overlay.configure(self.root, self.root, self.source, self.parent_hash)

    def test_changed_manifest_pin_or_recipe_provenance_refused(self):
        manifest = self.source / 'application-manifest.json'
        original = manifest.read_bytes()
        manifest.write_text('CHANGED_MANIFEST\n')
        self.refresh_inputs()
        with self.assertRaises(ValueError):
            self.configure()
        self.assert_unprepared()
        manifest.write_bytes(original)
        self.refresh_inputs()
        inputs = self.source / 'recipe-inputs.json'
        data = json.loads(inputs.read_text())
        for changed in ({**data, 'source_commit': 'untrusted'}, {**data, 'worktree_dirty': 'false'}, {**data, 'files': {}}):
            inputs.write_text(json.dumps(changed))
            with self.assertRaises(ValueError):
                self.configure()
            self.assert_unprepared()

    def test_target_parent_symlink_and_existing_payload_hardlink_are_refused(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (self.root / 'usr/local/share').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.configure()
        self.assert_unprepared()
        self.assertEqual(list(outside.iterdir()), [])
        (self.root / 'usr/local/share').unlink()
        sentinel = self.write(self.base, 'outside-payload', 'OUTSIDE_SENTINEL\n')
        target = self.root / 'usr/local/lib/inkyos/test-lan-preflight.py'
        target.parent.mkdir(parents=True, exist_ok=True)
        os.link(sentinel, target)
        with self.assertRaises(ValueError):
            self.configure()
        self.assertEqual(sentinel.read_text(), 'OUTSIDE_SENTINEL\n')

    def test_altered_marker_or_readonly_payload_modes_fail_verification(self):
        metadata = self.configure()
        target = self.root / 'usr/local/lib/inkyos/test-lan-preflight.py'
        target.chmod(0o755)
        with self.assertRaises(ValueError):
            self.verify(metadata)
        target.chmod(0o555)
        marker = self.root / overlay.MARKER_PATH
        marker.chmod(0o666)
        with self.assertRaises(ValueError):
            self.verify(metadata)


if __name__ == '__main__':
    unittest.main()
