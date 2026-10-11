"""Synthetic offline factory layout tests; no app, service, VM, image or SD runs.

Explicit ownership seams use the fixture owner's IDs on the host filesystem.
Linux root tests use real app UID/GID 1000. Non-Linux tests substitute the xattr
query explicitly; they do not establish native ownership, ACL or hardware proof.
"""
import builtins
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


configure = module('configure_factory_rootfs_fixture', 'configure-factory-rootfs.py')
verify = module('verify_factory_rootfs_fixture', 'verify-factory-rootfs.py')


class FactoryRootfsTests(unittest.TestCase):
    def setUp(self):
        if sys.platform != 'linux':
            xattrs = patch.object(os, 'listxattr', create=True, return_value=[])
            xattrs.start(); self.addCleanup(xattrs.stop)
        temporary = tempfile.TemporaryDirectory(prefix='inkyos-factory-layout-',
                                                dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / 'root'; self.root.mkdir(mode=0o700)
        self.source = self.base / 'source'; self.source.mkdir(mode=0o700)
        app_uid, app_gid = (1000, 1000) if sys.platform == 'linux' and os.geteuid() == 0 else (os.geteuid(), os.getegid())
        self.owner = {'_owner_uid': os.geteuid(), '_owner_gid': os.getegid(),
                      '_app_uid': app_uid, '_app_gid': app_gid}
        for name in ('etc/ssh', 'etc/systemd/system', 'usr/local/lib', 'var/lib/NetworkManager'):
            self.directory(name)
        self.write('etc/machine-id', b'uninitialized\n')
        self.write('etc/passwd', b'root:x:0:0:root:/root:/bin/bash\n'
                   b'inky:x:1000:1000::/home/inky:/usr/sbin/nologin\n')
        self.write(verify.WIFI, b'[main]\nWirelessEnabled=false\n', 0o600)
        scripts = self.source / 'scripts'; scripts.mkdir(mode=0o700)
        for name in verify.MODULE_PINS:
            target = scripts / name
            target.write_bytes((ROOT / 'scripts' / name).read_bytes())
            target.chmod(0o644)

    def directory(self, relative, mode=0o755):
        path = self.root / relative
        missing = []
        current = path
        while current != self.root and not current.exists():
            missing.append(current); current = current.parent
        for entry in reversed(missing):
            entry.mkdir(mode=0o755); entry.chmod(0o755)
        path.chmod(mode)
        return path

    def write(self, relative, raw, mode=0o644):
        path = self.root / relative
        if not path.parent.exists():
            self.directory(str(path.parent.relative_to(self.root)))
        path.write_bytes(raw); path.chmod(mode)
        return path

    def snapshot(self, root=None):
        root = self.root if root is None else root
        result = {}
        for path in (root, *sorted(root.rglob('*'))):
            info = path.lstat()
            kind = ('directory' if stat.S_ISDIR(info.st_mode) else 'symlink' if stat.S_ISLNK(info.st_mode)
                    else 'file' if stat.S_ISREG(info.st_mode) else 'special')
            value = (kind, stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid, info.st_nlink)
            if kind == 'file':
                value += (path.read_bytes(),)
            elif kind == 'symlink':
                value += (os.readlink(path),)
            result[str(path.relative_to(root))] = value
        return result

    def prepare(self):
        return configure.configure(self.root, self.source, **self.owner)

    def data_directory(self):
        path = self.directory(verify.DATA, 0o700)
        if sys.platform == 'linux' and os.geteuid() == 0:
            os.chown(path, self.owner['_app_uid'], self.owner['_app_gid'])
        return path

    def check(self):
        return verify.verify(self.root, **self.owner)

    def assert_refused_without_mutation(self):
        before, source = self.snapshot(), self.snapshot(self.source)
        with self.assertRaises((ValueError, OSError)):
            self.prepare()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.snapshot(self.source), source)

    def assert_verification_refuses(self):
        report = self.check()
        self.assertFalse(report['passed'])
        self.assertTrue(report['failed_checks'])
        self.assertTrue(all(type(value) is bool for value in report['checks'].values()))

    def test_passive_layout_has_exact_pending_permission_and_empty_private_data(self):
        before_sources = self.snapshot(self.source)
        report = self.prepare()
        self.assertTrue(report['passed'], report.get('failed_checks'))
        self.assertEqual(report['scope'], 'offline-factory-layout')
        for flag in ('image_code_executed', 'services_enabled', 'secret_values_included',
                     'exporter_support_verified', 'full_image_verified', 'writer_barrier_qualified',
                     'runtime_qualified', 'hardware_qualified'):
            self.assertIs(report[flag], False)
        self.assertEqual(self.snapshot(self.source), before_sources)
        data = self.root / verify.DATA
        self.assertEqual(list(data.iterdir()), [])
        self.assertEqual(stat.S_IMODE(data.stat().st_mode), 0o700)
        self.assertEqual((data.stat().st_uid, data.stat().st_gid),
                         (self.owner['_app_uid'], self.owner['_app_gid']))
        marker = self.root / verify.MARKER
        self.assertEqual(json.loads(marker.read_bytes()),
                         {'version': 1, 'app_uid': 1000, 'data_dir': '/var/lib/inky-studio'})
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o644)
        permission = self.root / verify.PERMISSION
        self.assertEqual(stat.S_IMODE(permission.stat().st_mode), 0o700)
        self.assertEqual({path.name for path in permission.iterdir()}, {'lock', 'pending.json'})
        self.assertEqual((permission / 'lock').read_bytes(), b'')
        self.assertEqual(json.loads((permission / 'pending.json').read_bytes()),
                         {'version': 1, 'operation': 'create-initialization-authority'})
        for path in (permission / 'lock', permission / 'pending.json'):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual((path.stat().st_uid, path.stat().st_gid),
                             (self.owner['_owner_uid'], self.owner['_owner_gid']))
        self.assertFalse((self.root / 'var/lib/inkyos/initialization').exists())
        for unit in verify.MASKS:
            self.assertEqual(os.readlink(self.root / 'etc/systemd/system' / unit), '/dev/null')

    def test_four_modules_are_exact_pinned_bytes_and_never_executed(self):
        self.assertEqual(set(verify.MODULE_PINS), {'factory-authority.py',
            'factory-credentials-publisher.py', 'initialization-receipt.py', 'initialization-server.py'})
        with patch.object(builtins, 'exec', side_effect=AssertionError('Installed source must never execute')):
            self.prepare()
        for name, digest in verify.MODULE_PINS.items():
            path = self.root / verify.MODULE_DIR / name
            raw = path.read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
            self.assertEqual(raw, (self.source / 'scripts' / name).read_bytes())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o555)
            self.assertEqual((path.stat().st_uid, path.stat().st_gid),
                             (self.owner['_owner_uid'], self.owner['_owner_gid']))

    def test_absent_and_already_empty_private_data_are_allowed(self):
        self.data_directory()
        self.assertTrue(self.prepare()['passed'])

    def test_nonempty_data_and_old_public_data_layout_are_refused(self):
        for content in ('credentials.json', 'photos'):
            with self.subTest(content=content):
                data = self.data_directory()
                path = data / content
                if content == 'photos':
                    path.mkdir()
                else:
                    path.write_bytes(b'INERT STATE SENTINEL\n')
                self.assert_refused_without_mutation()
                path.rmdir() if path.is_dir() else path.unlink()
        (self.root / verify.DATA).chmod(0o755)
        self.assert_refused_without_mutation()

    def test_source_pin_mismatch_refuses_before_any_layout_mutation(self):
        for name in verify.MODULE_PINS:
            path = self.source / 'scripts' / name
            original = path.read_bytes()
            with self.subTest(module=name):
                path.write_bytes(b'raise AssertionError("UNPINNED SOURCE EXECUTED")\n')
                self.assert_refused_without_mutation()
            path.write_bytes(original)

    def test_source_symlink_and_hardlink_are_refused_before_any_layout_mutation(self):
        name = next(iter(verify.MODULE_PINS)); path = self.source / 'scripts' / name
        original = path.read_bytes()
        outside = self.base / 'inert-source'; outside.write_bytes(original)
        path.unlink(); path.symlink_to(outside)
        self.assert_refused_without_mutation()
        path.unlink(); os.link(outside, path)
        self.assert_refused_without_mutation()

    def test_existing_masks_are_preserved_and_second_prepare_refuses_without_mutation(self):
        for unit in verify.MASKS:
            (self.root / 'etc/systemd/system' / unit).symlink_to('/dev/null')
        self.assertTrue(self.prepare()['passed'])
        self.assert_refused_without_mutation()

    def test_radio_open_and_initialized_machine_are_refused_without_mutation(self):
        mutations = [('etc/machine-id', b'a' * 32 + b'\n'),
                     (verify.WIFI, b'[main]\nWirelessEnabled=true\n')]
        for relative, content in mutations:
            with self.subTest(relative=relative):
                path = self.root / relative; original = path.read_bytes()
                path.write_bytes(content)
                self.assert_refused_without_mutation()
                path.write_bytes(original)

    def test_readonly_uninitialized_machine_id_is_preserved(self):
        path = self.root / 'etc/machine-id'
        path.chmod(0o444)
        before = verify.stamp(path.lstat())
        raw = path.read_bytes()
        self.assertEqual(raw, b'uninitialized\n')
        self.assertTrue(self.prepare()['passed'])
        self.assertTrue(self.check()['passed'])
        self.assertEqual(verify.stamp(path.lstat()), before)
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(os.listxattr(path), [])

    def test_machine_id_modes_other_than_0444_and_0644_are_refused(self):
        path = self.root / 'etc/machine-id'
        for mode in (0o400, 0o440, 0o555, 0o600, 0o640, 0o646, 0o664, 0o666, 0o755, 0o444 | stat.S_ISUID):
            with self.subTest(mode=oct(mode)):
                path.chmod(mode)
                self.assert_refused_without_mutation()
                self.assertEqual(stat.S_IMODE(path.lstat().st_mode), mode)

    def test_actual_machine_identity_is_refused_in_both_permitted_modes(self):
        path = self.root / 'etc/machine-id'
        path.write_bytes(b'a' * 32 + b'\n')
        for mode in (0o444, 0o644):
            with self.subTest(mode=oct(mode)):
                path.chmod(mode)
                self.assert_refused_without_mutation()

    def test_machine_id_mode_change_before_open_or_during_read_refuses_before_layout_mutation(self):
        path = self.root / 'etc/machine-id'
        original_read = os.read
        original_bytes = configure.verification.LayoutTree.bytes
        for boundary, start, finish in (('before_open', 0o444, 0o644), ('during_read', 0o444, 0o644),
                                        ('before_open', 0o644, 0o444), ('during_read', 0o644, 0o444)):
            with self.subTest(boundary=boundary, start=oct(start), finish=oct(finish)):
                path.chmod(start)
                before = self.snapshot()
                pin = path.lstat()
                changed = []

                def bytes_with_mode_change(tree, name, **options):
                    if boundary == 'before_open' and name == 'etc/machine-id' and not changed:
                        path.chmod(finish)
                        changed.append(True)
                    return original_bytes(tree, name, **options)

                def read_with_mode_change(fd, count):
                    opened = os.fstat(fd)
                    if boundary == 'during_read' and (opened.st_dev, opened.st_ino) == (pin.st_dev, pin.st_ino) and not changed:
                        path.chmod(finish)
                        changed.append(True)
                    return original_read(fd, count)

                with patch.object(configure.verification.LayoutTree, 'bytes', new=bytes_with_mode_change), \
                        patch.object(os, 'read', side_effect=read_with_mode_change), self.assertRaises(ValueError):
                    self.prepare()
                self.assertEqual(changed, [True])
                after = self.snapshot()
                self.assertEqual({name for name in before if before[name] != after[name]}, {'etc/machine-id'})
                self.assertFalse((self.root / verify.PERMISSION).exists())

    def test_host_identity_is_refused_without_mutation(self):
        path = self.write('etc/ssh/ssh_host_ed25519_key', b'INERT IDENTITY SENTINEL\n', 0o600)
        self.assert_refused_without_mutation()
        path.unlink()

    def test_unsafe_existing_service_unmasking_is_refused_without_mutation(self):
        for unit in verify.MASKS:
            with self.subTest(unit=unit):
                path = self.write('etc/systemd/system/' + unit, b'[Service]\nExecStart=/inert\n')
                self.assert_refused_without_mutation()
                path.unlink()

    def test_enablement_links_and_dropins_are_refused_before_mutation(self):
        for unit in verify.MASKS:
            with self.subTest(unit=unit, entry='enablement'):
                parent = self.directory('etc/systemd/system/multi-user.target.wants')
                link = parent / unit; link.symlink_to('/usr/lib/systemd/system/' + unit)
                self.assert_refused_without_mutation()
                link.unlink(); parent.rmdir()
            with self.subTest(unit=unit, entry='dropin'):
                path = self.write('etc/systemd/system/' + unit + '.d/override.conf', b'[Service]\nEnvironment=INERT=1\n')
                self.assert_refused_without_mutation()
                path.unlink(); path.parent.rmdir()

    def test_wrong_mask_target_is_refused_without_mutation(self):
        unit = verify.MASKS[0]
        path = self.root / 'etc/systemd/system' / unit
        path.symlink_to('/usr/lib/systemd/system/' + unit)
        self.assert_refused_without_mutation()

    def test_rootfs_ancestor_symlink_cannot_redirect_writes_outside_fixture(self):
        parent = self.root / 'usr/local'
        outside = self.base / 'outside'
        parent.rename(outside); parent.symlink_to(outside, target_is_directory=True)
        before = self.snapshot(outside)
        self.assert_refused_without_mutation()
        self.assertEqual(self.snapshot(outside), before)

    def test_source_ancestor_symlink_is_refused(self):
        parent = self.source / 'scripts'
        outside = self.base / 'outside-sources'
        parent.rename(outside); parent.symlink_to(outside, target_is_directory=True)
        self.assert_refused_without_mutation()

    def test_hardlinked_system_input_is_refused_without_mutation(self):
        path = self.root / 'etc/machine-id'
        os.link(path, self.base / 'inert-machine-id-link')
        self.assert_refused_without_mutation()

    def test_verifier_refuses_installed_module_byte_and_mode_changes(self):
        self.prepare()
        for name in verify.MODULE_PINS:
            path = self.root / verify.MODULE_DIR / name
            original = path.read_bytes()
            with self.subTest(module=name, mutation='mode'):
                path.chmod(0o755)
                self.assert_verification_refuses()
                path.chmod(0o555)
            with self.subTest(module=name, mutation='bytes'):
                path.chmod(0o644); path.write_bytes(b'INERT TAMPERED SOURCE\n'); path.chmod(0o555)
                self.assert_verification_refuses()
                path.chmod(0o644); path.write_bytes(original); path.chmod(0o555)
        self.assertTrue(self.check()['passed'])

    def test_verifier_refuses_credentials_consumed_permission_and_authority(self):
        self.prepare()
        credentials = self.root / verify.DATA / 'credentials.json'
        credentials.write_bytes(b'INERT STATE SENTINEL\n'); credentials.chmod(0o600)
        if sys.platform == 'linux' and os.geteuid() == 0:
            os.chown(credentials, 1000, 1000)
        self.assert_verification_refuses(); credentials.unlink()
        pending = self.root / verify.PERMISSION / 'pending.json'
        consumed = pending.with_name('consumed.json')
        pending.rename(consumed)
        self.assert_verification_refuses(); consumed.rename(pending)
        authority = self.directory('var/lib/inkyos/initialization', 0o700)
        self.assert_verification_refuses(); authority.rmdir()
        self.assertTrue(self.check()['passed'])

    def test_verifier_requires_empty_lock_and_exact_marker_and_permission_schema(self):
        self.prepare()
        mutations = [(verify.PERMISSION + '/lock', b'INERT LOCK CONTENT\n'),
                     (verify.PERMISSION + '/pending.json', b'{"version":true,"operation":"create-initialization-authority"}\n'),
                     (verify.MARKER, b'{"version":1,"app_uid":1000,"data_dir":"/other"}\n'),
                     (verify.MARKER, b'{"version":1,"version":1,"app_uid":1000,"data_dir":"/var/lib/inky-studio"}\n')]
        for relative, raw in mutations:
            with self.subTest(path=relative, value=raw):
                path = self.root / relative; original = path.read_bytes()
                path.write_bytes(raw)
                self.assert_verification_refuses()
                path.write_bytes(original)
        self.assertTrue(self.check()['passed'])

    def test_verifier_refuses_hardlinked_or_symlinked_installed_module(self):
        self.prepare()
        path = self.root / verify.MODULE_DIR / next(iter(verify.MODULE_PINS))
        outside = self.base / 'outside-installed-module'
        os.link(path, outside)
        self.assert_verification_refuses()
        path.unlink(); path.symlink_to(outside)
        self.assert_verification_refuses()

    def test_verifier_remains_readonly_when_layout_is_incomplete(self):
        before = self.snapshot()
        self.assert_verification_refuses()
        self.assertEqual(self.snapshot(), before)

    def test_owner_uid_and_gid_must_both_match_before_mutation(self):
        for field in ('_owner_uid', '_owner_gid'):
            with self.subTest(field=field):
                before = self.snapshot()
                options = {**self.owner, field: self.owner[field] + 10000}
                with self.assertRaises((ValueError, OSError)):
                    configure.configure(self.root, self.source, **options)
                self.assertEqual(self.snapshot(), before)

    def test_existing_data_uid_and_gid_must_both_match_before_mutation(self):
        self.data_directory()
        for field in ('_app_uid', '_app_gid'):
            with self.subTest(field=field):
                before = self.snapshot()
                options = {**self.owner, field: self.owner[field] + 10000}
                with self.assertRaises((ValueError, OSError)):
                    configure.configure(self.root, self.source, **options)
                self.assertEqual(self.snapshot(), before)

    def test_verifier_checks_both_owner_and_app_uid_gid(self):
        self.prepare()
        for field in self.owner:
            with self.subTest(field=field):
                report = verify.verify(self.root, **{**self.owner, field: self.owner[field] + 10000})
                self.assertFalse(report['passed'])
                self.assertTrue(report['failed_checks'])

    def test_dirty_authority_permission_identity_profiles_and_legacy_data_are_refused(self):
        paths = ('var/lib/inkyos/system.json', 'var/lib/inkyos/initialization/state.json',
                 'var/lib/inkyos/factory-permission/consumed.json',
                 'var/lib/systemd/random-seed',
                 'var/lib/inkyos-test-enrollment/inert-state.json',
                 'var/lib/inkyos-test-access/inert-state.json',
                 'etc/NetworkManager/system-connections/inert.nmconnection',
                 'etc/inkyos-test-access.json',
                 'home/inky/inky-studio/server/data/credentials.json',
                 'home/inky/.ssh/authorized_keys', 'root/.ssh/authorized_keys')
        for relative in paths:
            with self.subTest(path=relative):
                existing = set(self.root.rglob('*'))
                self.write(relative, b'PRIVATE INERT STATE SENTINEL\n', 0o600)
                self.assert_refused_without_mutation()
                self.assertNotIn('PRIVATE INERT STATE SENTINEL', json.dumps(self.check()))
                for path in sorted(set(self.root.rglob('*')) - existing,
                                   key=lambda path: len(path.parts), reverse=True):
                    path.rmdir() if path.is_dir() and not path.is_symlink() else path.unlink()

    def test_known_country_configuration_is_refused_without_mutation(self):
        cases = [('etc/modprobe.d/inert-regdom.conf', b'options cfg80211 ieee80211_regdom=FR\n'),
                 ('etc/NetworkManager/conf.d/inert-country.conf', b'[device]\nregulatory-domain=FR\n')]
        for relative, raw in cases:
            with self.subTest(path=relative):
                path = self.write(relative, raw)
                self.assert_refused_without_mutation()
                path.unlink(); path.parent.rmdir()

    def test_country_words_in_comments_do_not_open_the_radio(self):
        self.write('etc/modprobe.d/inert-comment.conf', b'# ieee80211_regdom=FR\n')
        self.write('etc/NetworkManager/conf.d/inert-comment.conf', b'[device]\n# country=FR\n')
        self.assertTrue(self.prepare()['passed'])
        self.assertEqual((self.root / verify.WIFI).read_bytes(), b'[main]\nWirelessEnabled=false\n')

    def test_unsafe_parent_modes_are_refused_without_chmod_repair(self):
        for relative in ('etc', 'usr/local/lib', 'var/lib'):
            with self.subTest(parent=relative):
                path = self.root / relative; mode = stat.S_IMODE(path.stat().st_mode)
                path.chmod(0o777)
                self.assert_refused_without_mutation()
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o777)
                path.chmod(mode)

    def test_late_io_failure_leaves_partial_layout_and_retry_refuses_it(self):
        before = self.snapshot()
        original = configure.create_file
        writes = []
        def fail_after_first(tree, path, raw, mode):
            writes.append(path)
            if len(writes) == 2:
                raise OSError('inert late write failure')
            return original(tree, path, raw, mode)
        with patch.object(configure, 'create_file', side_effect=fail_after_first), self.assertRaises(OSError):
            self.prepare()
        self.assertEqual(len(writes), 2)
        self.assertTrue((self.root / writes[0]).is_file())
        self.assertNotEqual(self.snapshot(), before)
        self.assert_verification_refuses()
        self.assert_refused_without_mutation()

    def test_fifo_system_input_is_refused_before_opening_the_file(self):
        path = self.root / 'etc/machine-id'
        path.unlink(); os.mkfifo(path, 0o600)
        original = os.open
        forbidden_opens = []
        def guarded_open(name, flags, *args, **kwargs):
            if str(name) in {'machine-id', str(path)} and not flags & os.O_DIRECTORY:
                forbidden_opens.append(str(name))
                raise AssertionError('A special input must be refused before its open')
            return original(name, flags, *args, **kwargs)
        with patch.object(os, 'open', side_effect=guarded_open):
            self.assert_refused_without_mutation()
            self.assert_verification_refuses()
        self.assertEqual(forbidden_opens, [])

    def test_unavailable_xattr_api_refuses_closed_without_mutation(self):
        before = self.snapshot()
        with patch.object(os, 'listxattr', create=True, new=None):
            with self.assertRaises((ValueError, OSError, TypeError)):
                self.prepare()
            self.assert_verification_refuses()
        self.assertEqual(self.snapshot(), before)


if __name__ == '__main__':
    unittest.main()
