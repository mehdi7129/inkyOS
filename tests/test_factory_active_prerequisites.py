"""Offline account fixtures; no target process, network or factory activation.

Owner/platform seams are limited to synthetic temporary non-/ roots. Linux
inspects real xattrs. Darwin substitutes only that Linux metadata observation.
The production CLI has no fixture flags and refuses the host root independently.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'active_prerequisites_fixture', ROOT / 'scripts/configure-factory-active-prerequisites.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)
PRODUCTION_ENVIRONMENT = prepare._production_environment
LOCK_PROBE = '''import errno,fcntl,os,sys
fd=os.open(sys.argv[1],os.O_RDWR)
try:
    fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
except OSError as error:
    if error.errno not in (errno.EACCES,errno.EAGAIN): raise
    print('blocked')
else:
    print('acquired')
finally:
    os.close(fd)
'''


class FactoryActivePrerequisitesTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='inkyos-prerequisites-',
                                                dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.base.chmod(0o700)
        self.root = self.base / 'root'
        for path in ('', 'etc', 'var', 'var/lib'):
            directory = self.root / path
            directory.mkdir(exist_ok=True)
            directory.chmod(0o755)
        self.write('passwd', 'root:x:0:0:root:/root:/bin/bash\n'
                   'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n'
                   'inky:x:1000:1000::/home/inky:/usr/sbin/nologin\n')
        self.write('group', 'root:x:0:\nshadow:x:42:\nnogroup:x:65534:\ninky:x:1000:\n'
                   'spi:x:997:inky\ni2c:x:998:inky\ngpio:x:996:inky\n')
        self.write('shadow', 'root:*:0:0:99999:7:::\n'
                   'nobody:*:0:0:99999:7:::\ninky:!:20000:0:99999:7:::\n', 0o600)
        self.write('gshadow', 'root:*::\nshadow:*::\nnogroup:*::\ninky:!::\n'
                   'spi:!::inky\ni2c:!::inky\ngpio:!::inky\n', 0o600)
        self.write('nsswitch.conf', 'passwd: files systemd\ngroup: files systemd\n'
                   'shadow: files systemd\ngshadow: files systemd\nhosts: files mdns4_minimal dns\n')
        self.write('machine-id', 'uninitialized\n')
        self.write('subuid', '')
        self.write('subgid', '')
        self.patches = [
            patch.object(prepare, '_production_environment', self.fixture_environment),
            patch.object(prepare.safety, '_owner_ids', self.fixture_owner),
            patch.object(prepare, '_parent_ids', self.fixture_parents),
        ]
        if not sys.platform.startswith('linux'):
            self.patches.extend([
                patch.object(prepare, '_xattrs', self.fixture_xattrs),
                patch.object(prepare.safety, '_xattrs', self.fixture_xattrs),
            ])
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def fixture_environment(self, rootfs):
        prepare.require(rootfs == self.root and rootfs != Path('/'), 'fixture_root_refused')
        return self.base, self.base

    def fixture_owner(self, rootfs):
        prepare.require(rootfs == self.root and rootfs != Path('/'), 'fixture_root_refused')
        return os.geteuid(), os.getegid()

    def fixture_parents(self, rootfs, *unused):
        prepare.require(rootfs == self.root and rootfs != Path('/'), 'fixture_root_refused')
        return {name: (os.geteuid(), os.getegid()) for name in prepare.PARENTS}

    def fixture_xattrs(self, rootfs, *args, **kwargs):
        prepare.require(rootfs == self.root and rootfs != Path('/'), 'fixture_root_refused')
        return {'status': 'inspected', 'entries': {}}

    def write(self, name, content, mode=0o644):
        path = self.root / 'etc' / name
        path.write_text(content)
        path.chmod(mode)

    def snapshot(self):
        result = {}
        for path in (self.root, *sorted(self.root.rglob('*'))):
            info = path.lstat()
            record = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                      info.st_nlink)
            if stat.S_ISREG(info.st_mode):
                record += (path.read_bytes(),)
            elif stat.S_ISLNK(info.st_mode):
                record += (os.readlink(path),)
            result[str(path.relative_to(self.root))] = record
        return result

    def run_prepare(self, **changes):
        values = dict(rootfs=self.root, helper_uid=991, provisioning_gid=992)
        values.update(changes)
        return prepare.configure(**values)

    def refused_without_mutation(self, **changes):
        before = self.snapshot()
        with self.assertRaises((prepare.Refused, OSError, ValueError)):
            self.run_prepare(**changes)
        self.assertEqual(self.snapshot(), before)

    def change(self, name, old, new):
        path = self.root / 'etc' / name
        self.write(name, path.read_text().replace(old, new), stat.S_IMODE(path.stat().st_mode))

    def test_prepares_exact_accounts_and_empty_parents_without_target_execution(self):
        originals = {name: (self.root / 'etc' / name).read_bytes() for name in prepare.DATABASES}
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('target executed')), \
                patch.object(os, 'system', side_effect=AssertionError('shell executed')):
            receipt = self.run_prepare()
        self.assertTrue(receipt['passed'])
        self.assertTrue(receipt['accounts_and_parents_prepared'])
        self.assertEqual(receipt['operation'], 'configure')
        for flag in ('image_code_executed', 'factory_authority_created', 'services_enabled',
                     'runtime_qualified', 'hardware_qualified', 'wifi_credentials_written'):
            self.assertIs(receipt[flag], False)
        raw = {name: (self.root / 'etc' / name).read_bytes() for name in prepare.DATABASES}
        prepare._accounts(raw, 991, 992, configured=True)
        for name in prepare.DATABASES:
            self.assertTrue(raw[name].startswith(originals[name]))
            self.assertEqual(len(raw[name].splitlines()), len(originals[name].splitlines()) + 1)
            self.assertFalse((self.root / 'etc' / prepare.TEMPORARY[name]).exists())
        for name in prepare.PARENTS:
            path = self.root / 'var/lib' / name
            self.assertEqual(list(path.iterdir()), [])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        self.assertEqual(set((self.root / 'var/lib').iterdir()),
                         {self.root / 'var/lib' / name for name in prepare.PARENTS})
        self.refused_without_mutation()

    def test_check_only_completes_preflight_without_creating_anything(self):
        before = self.snapshot()
        receipt = self.run_prepare(check_only=True)
        self.assertEqual(receipt['operation'], 'check')
        self.assertFalse(receipt['accounts_and_parents_prepared'])
        self.assertEqual(self.snapshot(), before)

    def test_reserved_ids_are_required_exact_system_integers(self):
        for field in ('helper_uid', 'provisioning_gid'):
            for value in (0, -1, 1000, True, '991'):
                with self.subTest(field=field, value=value):
                    self.refused_without_mutation(**{field: value})

    def test_id_collisions_and_duplicate_ids_are_refused(self):
        self.refused_without_mutation(helper_uid=1000)
        self.refused_without_mutation(provisioning_gid=997)
        self.change('passwd', 'nobody:x:65534:', 'nobody:x:991:')
        self.refused_without_mutation()
        self.change('passwd', 'nobody:x:991:', 'nobody:x:1000:')
        self.refused_without_mutation()
        self.change('passwd', 'nobody:x:1000:', 'nobody:x:65534:')
        self.change('group', 'shadow:x:42:', 'shadow:x:997:')
        self.refused_without_mutation()

    def test_reserved_names_in_any_database_are_not_adopted(self):
        for name, content in {
            'passwd': 'inky-network:x:991:0::/nonexistent:/usr/sbin/nologin\n',
            'shadow': 'inky-network:!:0:0:99999:7:::\n',
            'group': 'inky-provisioning:x:992:inky\n',
            'gshadow': 'inky-provisioning:!::inky\n',
        }.items():
            path = self.root / 'etc' / name
            original = path.read_text()
            self.write(name, original + content, stat.S_IMODE(path.stat().st_mode))
            self.refused_without_mutation()
            self.write(name, original, 0o600 if name in ('shadow', 'gshadow') else 0o644)

    def test_app_requires_locked_nologin_identity_and_exact_hardware_memberships(self):
        for name, old, new in (
            ('passwd', '/usr/sbin/nologin', '/bin/bash'),
            ('passwd', '1000:1000', '1000:0'),
            ('group', 'spi:x:997:inky', 'spi:x:997:'),
            ('gshadow', 'spi:!::inky', 'spi:!::'),
            ('shadow', 'inky:!:', 'inky::'),
            ('shadow', 'inky:!:', 'inky:!$6$lockedhash:'),
        ):
            with self.subTest(name=name, replacement=new):
                original = (self.root / 'etc' / name).read_text()
                self.change(name, old, new)
                self.refused_without_mutation()
                self.write(name, original, 0o600 if name in ('shadow', 'gshadow') else 0o644)
        self.change('group', 'root:x:0:', 'root:x:0:inky')
        self.change('gshadow', 'root:*::', 'root:*::inky')
        self.refused_without_mutation()

    def test_gshadow_privilege_and_membership_disagreement_are_refused(self):
        self.change('gshadow', 'spi:!::inky', 'spi:!:inky:inky')
        self.refused_without_mutation()
        self.change('gshadow', 'spi:!:inky:inky', 'spi:!::inky,inky')
        self.refused_without_mutation()
        self.change('gshadow', 'spi:!::inky,inky', 'spi:!::ghost')
        self.refused_without_mutation()

    def test_malformed_duplicate_and_nis_records_are_refused(self):
        original = (self.root / 'etc/passwd').read_text()
        for bad in (original + original, original + '+::::::\n', original.replace('1000:1000', '01000:1000'),
                    original.rstrip('\n'), original.replace('root:x:', 'root::'),
                    original.replace('root:x:0:0', 'root:x:0:42:extra')):
            self.write('passwd', bad)
            self.refused_without_mutation()
        self.write('passwd', original)

    def test_external_nss_missing_entries_and_duplicate_sources_are_refused(self):
        original = (self.root / 'etc/nsswitch.conf').read_text()
        for bad in (original.replace('passwd: files systemd', 'passwd: compat'),
                    original.replace('group: files systemd', 'group: files ldap'),
                    original.replace('shadow: files systemd', 'shadow: systemd files'),
                    original.replace('gshadow: files systemd\n', ''),
                    original + 'passwd: files\n'):
            self.write('nsswitch.conf', bad)
            self.refused_without_mutation()
        self.write('nsswitch.conf', original)

    def test_existing_data_helper_locks_backups_and_staging_files_are_never_adopted(self):
        for name in prepare.PARENTS:
            path = self.root / 'var/lib' / name
            path.mkdir(mode=0o700)
            self.refused_without_mutation()
            path.rmdir()
        for name in (*prepare.LOCKS, *prepare.BACKUPS, *prepare.TEMPORARY.values()):
            path = self.root / 'etc' / name
            path.write_text('inert existing state\n')
            self.refused_without_mutation()
            path.unlink()

    def test_preexisting_dangling_links_are_refused(self):
        for path in (self.root / 'var/lib/inky-studio', self.root / 'var/lib/inky-network',
                     self.root / 'etc/.pwd.lock'):
            path.symlink_to('does-not-exist')
            self.refused_without_mutation()
            path.unlink()

    def test_benign_password_lock_is_unchanged_and_held_through_readback(self):
        self.write(prepare.PASSWORD_LOCK, '', 0o600)
        path = self.root / 'etc' / prepare.PASSWORD_LOCK
        before = prepare._signature(path.stat())
        original = prepare._verify
        observations = []

        def verify_locked(*args):
            probe = subprocess.run([sys.executable, '-I', '-c', LOCK_PROBE, str(path)],
                                   text=True, capture_output=True, check=True, timeout=5)
            observations.append(probe.stdout.strip())
            result = original(*args)
            probe = subprocess.run([sys.executable, '-I', '-c', LOCK_PROBE, str(path)],
                                   text=True, capture_output=True, check=True, timeout=5)
            observations.append(probe.stdout.strip())
            return result

        with patch.object(prepare, '_verify', verify_locked):
            self.run_prepare()
        self.assertEqual(observations, ['blocked', 'blocked'])
        self.assertEqual(prepare._signature(path.stat()), before)
        self.assertEqual(path.read_bytes(), b'')
        probe = subprocess.run([sys.executable, '-I', '-c', LOCK_PROBE, str(path)],
                               text=True, capture_output=True, check=True, timeout=5)
        self.assertEqual(probe.stdout.strip(), 'acquired')

    def test_check_only_never_creates_or_changes_password_lock(self):
        self.assertFalse((self.root / 'etc' / prepare.PASSWORD_LOCK).exists())
        self.run_prepare(check_only=True)
        self.assertFalse((self.root / 'etc' / prepare.PASSWORD_LOCK).exists())
        self.write(prepare.PASSWORD_LOCK, '', 0o600)
        before = self.snapshot()
        self.run_prepare(check_only=True)
        self.assertEqual(self.snapshot(), before)

    def test_password_lock_bad_size_mode_hardlink_or_kind_is_refused(self):
        path = self.root / 'etc' / prepare.PASSWORD_LOCK
        for content, mode in (('corrupt', 0o600), ('', 0o644), ('', 0o400), ('', 0o1600)):
            with self.subTest(content=content, mode=mode):
                self.write(prepare.PASSWORD_LOCK, content, mode)
                self.refused_without_mutation()
                path.unlink()
        self.write(prepare.PASSWORD_LOCK, '', 0o600)
        link = self.base / 'lock-hardlink'
        os.link(path, link)
        self.refused_without_mutation()
        link.unlink(); path.unlink()
        path.mkdir(mode=0o700)
        self.refused_without_mutation()
        path.rmdir()
        os.mkfifo(path, 0o600)
        self.refused_without_mutation()
        path.unlink()

    def test_password_lock_xattr_corruption_is_refused(self):
        self.write(prepare.PASSWORD_LOCK, '', 0o600)
        lock_inode = (self.root / 'etc' / prepare.PASSWORD_LOCK).stat().st_ino
        original = prepare._xattrs

        def corrupted(rootfs, target):
            if isinstance(target, int) and os.fstat(target).st_ino == lock_inode:
                return {'status': 'inspected', 'entries': {'user.corrupt': 'inert'}}
            return original(rootfs, target)

        with patch.object(prepare, '_xattrs', corrupted):
            self.refused_without_mutation()

    def test_password_lock_contended_by_separate_process_refuses_before_write(self):
        self.write(prepare.PASSWORD_LOCK, '', 0o600)
        path = self.root / 'etc' / prepare.PASSWORD_LOCK
        code = ('import fcntl,os,sys\n'
                'fd=os.open(sys.argv[1],os.O_RDWR)\n'
                'fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\n'
                'print("held",flush=True)\n'
                'sys.stdin.read(1)\n')
        child = subprocess.Popen([sys.executable, '-I', '-c', code, str(path)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), 'held')
            self.refused_without_mutation()
            self.refused_without_mutation(check_only=True)
        finally:
            child.communicate('x', timeout=5)
        self.assertEqual(child.returncode, 0)

    def test_account_links_hardlinks_modes_and_parent_modes_are_refused(self):
        passwd = self.root / 'etc/passwd'
        saved = self.base / 'saved-passwd'
        passwd.rename(saved)
        passwd.symlink_to(saved)
        self.refused_without_mutation()
        passwd.unlink(); os.link(saved, passwd)
        self.refused_without_mutation()
        passwd.unlink(); saved.rename(passwd)
        for mode in (0o666, 0o600, 0o4644):
            passwd.chmod(mode)
            self.refused_without_mutation()
        passwd.chmod(0o644)
        (self.root / 'var/lib').chmod(0o777)
        self.refused_without_mutation()

    def test_parent_symlink_is_refused_without_modifying_external_tree(self):
        lib = self.root / 'var/lib'
        lib.rmdir()
        external = self.base / 'outside'
        external.mkdir(mode=0o755)
        lib.symlink_to(external)
        self.refused_without_mutation()
        self.assertEqual(list(external.iterdir()), [])

    def test_root_and_private_workspace_guards_cannot_target_host(self):
        self.refused_without_mutation(rootfs=Path('/'))
        with self.assertRaises(prepare.Refused):
            PRODUCTION_ENVIRONMENT(self.root)
        for path in (self.root, self.base):
            mode = stat.S_IMODE(path.stat().st_mode)
            path.chmod(0o777)
            self.refused_without_mutation()
            path.chmod(mode)

    def test_booted_image_and_subordinate_app_ids_are_refused(self):
        self.write('machine-id', 'b' * 32 + '\n')
        self.refused_without_mutation()
        self.write('machine-id', 'uninitialized\n')
        self.write('subuid', 'inky:100000:65536\n')
        self.refused_without_mutation()

    def test_mutation_failure_keeps_exclusive_staging_and_refuses_retry(self):
        original = prepare._write_file
        count = 0

        def interrupt(*args):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError('simulated write failure')
            return original(*args)

        with patch.object(prepare, '_write_file', interrupt):
            with self.assertRaises(OSError):
                self.run_prepare()
        self.assertTrue((self.root / 'etc' / prepare.TEMPORARY['passwd']).exists())
        self.assertFalse((self.root / 'var/lib/inky-studio').exists())
        self.refused_without_mutation()

    def test_cli_receipt_never_serializes_passwords_or_internal_errors(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = prepare.main(['--rootfs', str(self.root), '--helper-uid', '991',
                                 '--provisioning-gid', '992', '--check-only'])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(output.getvalue())['passed'])
        self.change('shadow', 'inky:!:', 'inky:PRIVATE_PASSWORD_SENTINEL:')
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = prepare.main(['--rootfs', str(self.root), '--helper-uid', '991',
                                 '--provisioning-gid', '992'])
        self.assertEqual(code, 1)
        self.assertNotIn('PRIVATE_PASSWORD_SENTINEL', output.getvalue())
        self.assertNotIn(str(self.root), output.getvalue())

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux xattrs required')
    def test_native_account_and_parent_xattrs_are_refused(self):
        self.write(prepare.PASSWORD_LOCK, '', 0o600)
        for path in (self.root / 'etc/passwd', self.root / 'var/lib',
                     self.root / 'etc' / prepare.PASSWORD_LOCK):
            os.setxattr(path, 'user.fixture', b'inert')
            try:
                self.refused_without_mutation()
            finally:
                os.removexattr(path, 'user.fixture')

    @unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0,
                         'Linux root ownership required')
    def test_native_exact_ids_and_debian_shadow_metadata(self):
        self.write(prepare.PASSWORD_LOCK, '', 0o600)
        lock = self.root / 'etc' / prepare.PASSWORD_LOCK
        os.chown(lock, 0, 42)
        self.refused_without_mutation()
        os.chown(lock, 0, 0)
        for name in ('shadow', 'gshadow'):
            path = self.root / 'etc' / name
            os.chown(path, 0, 42)
            path.chmod(0o640)
        with patch.object(prepare, '_parent_ids',
                          lambda rootfs, app, helper, group: {
                              'inky-studio': (1000, 1000), 'inky-network': (helper, group)}):
            self.run_prepare()
        for name, ids in {'inky-studio': (1000, 1000), 'inky-network': (991, 992)}.items():
            info = (self.root / 'var/lib' / name).stat()
            self.assertEqual((info.st_uid, info.st_gid), ids)
        for name in ('shadow', 'gshadow'):
            info = (self.root / 'etc' / name).stat()
            self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (0, 42, 0o640))


if __name__ == '__main__':
    unittest.main()
