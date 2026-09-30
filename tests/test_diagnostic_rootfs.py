"""Diagnostic image overlay fixtures; no disk, mount, service or Pi access."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('configure_diagnostic_rootfs',
                                             REPOSITORY / 'scripts/configure-diagnostic-rootfs.py')
overlay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(overlay)


class DiagnosticRootfsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root, self.boot, self.source = (self.base / name for name in ('root', 'boot', 'source'))
        for path in (self.root, self.boot, self.source):
            path.mkdir()
        for relative, content in {
            'etc/machine-id': 'uninitialized\n',
            'etc/inkyos-release.json': json.dumps({'kind': 'application-prototype',
                'application': {'startup': 'masked-pending-firstboot-contract', 'release_qualified': False}}),
            'etc/shadow': 'root:*:0:0:99999:7:::\ninky:!:0:0:99999:7:::\ninky-network:!:0:0:99999:7:::\n',
            'etc/passwd': 'ACCOUNT_DATABASE_SENTINEL\n',
            'usr/local/lib/inkyos/firstboot.py': 'PRISTINE_FIRSTBOOT_SENTINEL\n',
            'var/lib/NetworkManager/NetworkManager.state': '[main]\nWirelessEnabled=false\n',
        }.items():
            self.write(self.root, relative, content)
        for relative in ('etc/ssh', 'etc/NetworkManager/system-connections', 'etc/wpa_supplicant',
                         'var/lib/inky-studio/photos'):
            (self.root / relative).mkdir(parents=True, exist_ok=True)
        for unit in ('inky-studio.service', 'inky-network.service', 'ssh.service', 'ssh.socket', 'sshswitch.service'):
            target = self.root / 'etc/systemd/system' / unit
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to('/dev/null')
        self.cmdline = 'console=tty1 rootwait resize\n'
        self.config = '# parent fixture\nauto_initramfs=1\n[all]\ninclude inkyos.txt\n'
        self.write(self.boot, 'cmdline.txt', self.cmdline)
        self.write(self.boot, 'config.txt', self.config)
        self.write(self.boot, 'inkyos.txt', overlay.EXPECTED_INKYOS_CONFIG)
        for name in overlay.SOURCE_FILES:
            if name == 'diagnostic/sd-diagnostic.py':
                self.write(self.source, name, '# fixture exporter; never executed\n')
            else:
                destination = self.source / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(REPOSITORY / name, destination)
        self.write(self.source, 'recipe-inputs.json', json.dumps({'schema_version': 1,
            'source_commit': 'b' * 40, 'worktree_dirty': False,
            'files': {name: hashlib.sha256((self.source / name).read_bytes()).hexdigest()
                      for name in overlay.SOURCE_FILES}}))
        self.parent_hash = 'a' * 64

    def write(self, tree, relative, content):
        path = tree / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def configure(self):
        return overlay.configure(self.root, self.boot, self.source, self.parent_hash)

    def assert_not_installed(self):
        self.assertFalse((self.root / 'usr/local/lib/inkyos/sd-diagnostic.py').exists())
        self.assertEqual((self.boot / 'config.txt').read_text(), self.config)

    def test_inert_application_and_original_firstboot_state_remain_unchanged(self):
        preserved = {name: (self.root / name).read_bytes() for name in
                     ('etc/machine-id', 'etc/shadow', 'etc/passwd', 'etc/inkyos-release.json',
                      'usr/local/lib/inkyos/firstboot.py', 'var/lib/NetworkManager/NetworkManager.state')}
        self.configure()
        for name, before in preserved.items():
            self.assertEqual((self.root / name).read_bytes(), before, name)
        self.assertEqual((self.boot / 'cmdline.txt').read_text(), self.cmdline)
        self.assertEqual((self.boot / 'inkyos.txt').read_text(), overlay.EXPECTED_INKYOS_CONFIG)
        self.assertEqual(list((self.root / 'var/lib/inky-studio/photos').iterdir()), [])
        self.assertFalse((self.boot / 'inkyos-diagnostics').exists())
        for name in ('var/lib/inkyos/system.json', 'var/lib/inky-network', 'var/lib/systemd/random-seed'):
            self.assertFalse((self.root / name).exists(), name)

    def test_metadata_names_parent_and_only_explicit_source_files(self):
        self.write(self.source, 'diagnostic/unreviewed.txt', 'DO_NOT_IMPORT\n')
        result = self.configure()
        self.assertEqual(result, json.loads((self.root / 'etc/inkyos-diagnostic.json').read_text()))
        self.assertEqual(result['parent_image_sha256'], self.parent_hash)
        self.assertEqual(result['kind'], 'sd-boot-diagnostic')
        self.assertEqual(result['status'], 'not-qualified')
        self.assertFalse(result['release_qualified'])
        self.assertTrue(result['auto_poweroff'])
        self.assertFalse(result['automatic_reboot'])
        expected = {name: hashlib.sha256((self.source / name).read_bytes()).hexdigest() for name in overlay.SOURCE_FILES}
        self.assertEqual(result['source_file_sha256'], expected)
        self.assertEqual(result['recipe_source_commit'], 'b' * 40)
        self.assertFalse(result['recipe_worktree_dirty'])
        self.assertEqual(result['recipe_inputs_sha256'], hashlib.sha256((self.source / 'recipe-inputs.json').read_bytes()).hexdigest())
        self.assertEqual(result['boot_config_delta']['parent_sha256'], hashlib.sha256(self.config.encode()).hexdigest())
        for source_name, (relative, mode) in overlay.COPY_FILES.items():
            target = self.root / relative
            self.assertEqual(target.read_bytes(), (self.source / source_name).read_bytes())
            self.assertEqual(target.stat().st_mode & 0o777, mode)
        self.assertFalse((self.root / 'usr/local/lib/inkyos/unreviewed.txt').exists())
        self.assertIn('NOT A RELEASE', (self.boot / 'INKYOS-DIAGNOSTIC.txt').read_text())
        self.assertIn(overlay.REPORT_TEMPLATE, (self.boot / 'INKYOS-DIAGNOSTIC.txt').read_text())

    def test_one_timer_orders_after_services_without_requiring_success(self):
        self.configure()
        service = (self.root / 'etc/systemd/system' / overlay.SERVICE).read_text()
        timer = (self.root / 'etc/systemd/system' / overlay.TIMER).read_text()
        self.assertIn('RequiresMountsFor=/boot/firmware\n', service)
        self.assertNotIn('Requires=', service)
        self.assertNotIn('Wants=', service)
        for name in ('local-fs.target', 'inkyos-firstboot.service', 'rpi-resize.service',
                     'systemd-growfs-root.service', 'NetworkManager.service', 'avahi-daemon.service', 'bluetooth.service'):
            self.assertIn(name, service)
        self.assertIn('TimeoutStartSec=45s\n', service)
        self.assertIn('ExecStartPost=/usr/bin/systemctl --no-block poweroff\n', service)
        self.assertIn('OnBootSec=45s\n', timer)
        self.assertNotIn('OnUnitActiveSec=', timer)
        self.assertNotIn('reboot', service)
        self.assertNotIn('Restart=', service)
        link = self.root / 'etc/systemd/system/timers.target.wants' / overlay.TIMER
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), '/etc/systemd/system/' + overlay.TIMER)

    def test_updates_masked_wifi_disabled_and_bluetooth_preserved(self):
        self.configure()
        for unit in overlay.MASKED_UNITS:
            target = self.root / 'etc/systemd/system' / unit
            self.assertEqual(os.readlink(target), '/dev/null')
        self.assertEqual((self.boot / 'config.txt').read_text(), self.config.rstrip() + overlay.BOOT_CONFIG_APPEND)
        self.assertNotIn('disable-bt', (self.boot / 'config.txt').read_text())
        self.assertFalse((self.root / 'etc/systemd/system/bluetooth.service').is_symlink())
        self.assertFalse((self.root / 'etc/systemd/system/rpi-resize.service').is_symlink())

    def test_report_is_expurgated_boolean_checks_with_traceable_inputs(self):
        result = self.configure()
        report = overlay.verification(self.root, self.boot, result)
        self.assertTrue(all(value is True for value in report['checks'].values()))
        self.assertEqual(report['parent_image_sha256'], self.parent_hash)
        self.assertEqual(report['source_file_sha256'], result['source_file_sha256'])
        self.assertFalse(report['release_qualified'])
        target = self.root / 'usr/local/lib/inkyos/sd-diagnostic.py'
        target.chmod(0o755)
        target.write_text('CHANGED\n')
        with self.assertRaises(ValueError):
            overlay.verification(self.root, self.boot, result)

    def test_pending_firmware_files_and_symlinks_rejected_before_any_write(self):
        for name in ('recovery.bin', 'recovery.000', 'RECOVERY.003', 'pieeprom.bin', 'pieeprom.upd',
                     'pieeprom.sig', 'pieeprom-2026.bin', 'VL805.bin', 'vl805.sig'):
            with self.subTest(name=name):
                path = self.write(self.boot, name, 'FIRMWARE_SENTINEL\n')
                with self.assertRaises(ValueError):
                    self.configure()
                self.assert_not_installed()
                path.unlink()
        path = self.boot / 'recovery.bin'
        path.symlink_to(self.base / 'nonexistent')
        with self.assertRaises(ValueError):
            self.configure()
        self.assert_not_installed()

    def test_conflicting_bootloader_setting_and_unknown_parent_overlay_rejected(self):
        for line in ('bootloader_update=1\n', 'bootloader_update = 2 # update\n', 'BOOTLOADER_UPDATE=1\n'):
            self.write(self.boot, 'config.txt', self.config + line)
            with self.assertRaises(ValueError):
                self.configure()
            self.assertFalse((self.root / 'usr/local/lib/inkyos/sd-diagnostic.py').exists())
        self.write(self.boot, 'config.txt', self.config)
        self.write(self.boot, 'inkyos.txt', '[all]\ndtoverlay=disable-bt\n')
        with self.assertRaises(ValueError):
            self.configure()
        self.assert_not_installed()

    def test_booted_image_active_app_unlocked_account_and_content_rejected(self):
        cases = (
            ('etc/machine-id', '0' * 32 + '\n'),
            ('etc/inkyos-release.json', json.dumps({'kind': 'application-prototype',
                'application': {'startup': 'active', 'release_qualified': False}})),
            ('etc/shadow', 'root:*:0:0:99999:7:::\ninky:password:0:0:99999:7:::\ninky-network:!:0:0:99999:7:::\n'),
        )
        for relative, content in cases:
            path = self.root / relative
            before = path.read_bytes()
            path.write_text(content)
            with self.assertRaises(ValueError):
                self.configure()
            self.assert_not_installed()
            path.write_bytes(before)
        photo = self.write(self.root, 'var/lib/inky-studio/photos/example.jpg', 'CONTENT_SENTINEL\n')
        with self.assertRaises(ValueError):
            self.configure()
        self.assert_not_installed()
        self.assertEqual(photo.read_text(), 'CONTENT_SENTINEL\n')

    def test_boot_credentials_network_credentials_ssh_keys_and_runtime_state_rejected(self):
        for tree, relative in ((self.boot, 'userconf.txt'), (self.boot, 'network-config'),
                               (self.root, 'etc/ssh/ssh_host_ed25519_key'),
                               (self.root, 'etc/NetworkManager/system-connections/home.nmconnection'),
                               (self.root, 'etc/wpa_supplicant/wpa_supplicant.conf'),
                               (self.root, 'etc/wpa_supplicant/functions.sh'),
                               (self.root, 'var/lib/inkyos/system.json')):
            with self.subTest(relative=relative):
                path = self.write(tree, relative, 'PRIVATE_SENTINEL\n')
                with self.assertRaises(ValueError):
                    self.configure()
                self.assert_not_installed()
                path.unlink()

    def test_preexisting_report_and_repeat_configuration_rejected(self):
        (self.boot / 'inkyos-diagnostics').mkdir()
        with self.assertRaises(ValueError):
            self.configure()
        self.assert_not_installed()
        (self.boot / 'inkyos-diagnostics').rmdir()
        self.configure()
        original = (self.root / 'etc/inkyos-diagnostic.json').read_bytes()
        with self.assertRaises(ValueError):
            self.configure()
        self.assertEqual((self.root / 'etc/inkyos-diagnostic.json').read_bytes(), original)

    def test_missing_pin_overlap_and_changed_executing_source_rejected(self):
        for digest in ('', 'A' * 64, 'a' * 63, None):
            with self.assertRaises(ValueError):
                overlay.configure(self.root, self.boot, self.source, digest)
            self.assert_not_installed()
        with self.assertRaises(ValueError):
            overlay.configure(self.root, self.root, self.source, self.parent_hash)
        path = self.source / 'scripts/configure-diagnostic-rootfs.py'
        path.write_text(path.read_text() + '# unreviewed change\n')
        with self.assertRaises(ValueError):
            self.configure()
        self.assert_not_installed()

    def test_source_and_destination_links_cannot_escape_build_tree(self):
        sentinel = self.write(self.base, 'outside-payload', 'OUTSIDE_SENTINEL\n')
        source = self.source / 'diagnostic/sd-diagnostic.py'
        for kind in ('symlink', 'hardlink'):
            source.unlink()
            if kind == 'symlink':
                source.symlink_to(sentinel)
            else:
                os.link(sentinel, source)
            with self.assertRaises(ValueError):
                self.configure()
            self.assert_not_installed()
            self.assertEqual(sentinel.read_text(), 'OUTSIDE_SENTINEL\n')
        source.unlink()
        source.write_text('# fixture exporter\n')
        target = self.root / 'usr/local/lib/inkyos/sd-diagnostic.py'
        target.symlink_to(sentinel)
        with self.assertRaises(ValueError):
            self.configure()
        self.assertEqual(sentinel.read_text(), 'OUTSIDE_SENTINEL\n')

    def test_tree_ancestor_and_target_parent_symlinks_rejected(self):
        alias = self.base / 'alias'
        alias.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(ValueError):
            overlay.configure(alias / 'root', self.boot, self.source, self.parent_hash)
        directory = self.root / 'usr/local/lib/inkyos'
        saved = self.base / 'saved-lib'
        directory.rename(saved)
        directory.symlink_to(saved, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.configure()
        self.assertFalse((saved / 'sd-diagnostic.py').exists())

    def test_reviewed_vendor_wireless_scripts_are_preserved_without_profiles(self):
        from unittest.mock import patch
        script = '# fixture package integration script\n'
        with patch.dict(overlay.WPA_VENDOR_SCRIPTS, {'functions.sh': hashlib.sha256(script.encode()).hexdigest()}):
            path = self.write(self.root, 'etc/wpa_supplicant/functions.sh', script)
            self.configure()
            self.assertEqual(path.read_text(), script)

    def test_recipe_provenance_missing_or_hash_mismatch_rejected(self):
        path = self.source / 'recipe-inputs.json'
        data = json.loads(path.read_text())
        for changed in ({**data, 'source_commit': 'untrusted'}, {**data, 'worktree_dirty': 'false'},
                        {**data, 'files': {}}, {**data, 'schema_version': 2}):
            path.write_text(json.dumps(changed))
            with self.assertRaises(ValueError):
                self.configure()
            self.assert_not_installed()


if __name__ == '__main__':
    unittest.main()
