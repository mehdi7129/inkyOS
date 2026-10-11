"""Inert writer-parent provisioning and inode binding, without services or media.

The existing synthetic Contract supplies a public boot context. macOS uses the
same explicit FD-xattr fixture as the runtime tests; only physical parent owners
are substituted by identities(). NSS validation has separate, explicit mocks.
No helper, initialization receipt operation, image, VM or network connection is executed.
"""
import builtins
import copy
from contextlib import ExitStack, contextmanager
import grp
import json
import os
from pathlib import Path
import pwd
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_factory_runtime_contract import BOOT_ID, ContractFixture, encoded, load_module, runtime


parents = load_module('writer_parents_test', 'staging/bootstrap/writer-parents.py')
OTHER_BOOT = '87654321-4321-4321-4321-cba987654321'


class WriterParentsFixture(ContractFixture):
    def setUp(self):
        super().setUp()
        self.value = self.contract()
        runtime.prepare_boot_context(self.value)
        self.persistent = self.mkdir(parents.PERSISTENT, 0o700)
        self.real_identities = parents.identities
        seam = patch.object(parents, 'identities', return_value=(os.geteuid(), os.getegid()))
        seam.start()
        self.addCleanup(seam.stop)

    def assert_parents_refused(self, operation, *, unchanged=True):
        before = self.snapshot() if unchanged else None
        with self.assertRaises(parents.Refused) as caught:
            operation()
        self.assertEqual(caught.exception.reason, 'writer_parents_refused')
        if unchanged:
            self.assertEqual(self.snapshot(), before)

    def prepared(self):
        self.assertEqual(parents.prepare(self.value), {'status': 'writer_parents_prepared'})
        self.assertEqual(parents.verify(self.value), {'status': 'writer_parents_verified'})

    def receipt(self):
        return json.loads((self.root / parents.RECEIPT).read_bytes())

    @contextmanager
    def nss(self, *, user_changes=None, group_changes=None, reverse_user_changes=None,
            reverse_group_changes=None):
        helper = self.manifest['helper_uid']
        provisioning = self.manifest['provisioning_gid']
        users = {
            'inky': pwd.struct_passwd(('inky', 'x', 1000, 1000, '', '/inert', '/inert')),
            'inky-network': pwd.struct_passwd(('inky-network', 'x', helper, provisioning,
                                             '', '/inert', '/inert')),
        }
        groups = {
            'inky': grp.struct_group(('inky', 'x', 1000, [])),
            'inky-provisioning': grp.struct_group(('inky-provisioning', 'x', provisioning, [])),
        }
        by_uid = {row.pw_uid: row for row in users.values()}
        by_gid = {row.gr_gid: row for row in groups.values()}
        users.update(user_changes or {})
        groups.update(group_changes or {})
        by_uid.update(reverse_user_changes or {})
        by_gid.update(reverse_group_changes or {})
        with ExitStack() as stack:
            stack.enter_context(patch.object(parents.pwd, 'getpwnam', side_effect=users.__getitem__))
            stack.enter_context(patch.object(parents.pwd, 'getpwuid', side_effect=by_uid.__getitem__))
            stack.enter_context(patch.object(parents.grp, 'getgrnam', side_effect=groups.__getitem__))
            stack.enter_context(patch.object(parents.grp, 'getgrgid', side_effect=by_gid.__getitem__))
            yield


class WriterParentsTests(WriterParentsFixture):
    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                         'Real numerical helper ownership requires Linux root; no NSS qualification')
    def test_real_root_creates_distinct_numerical_parent_owners(self):
        helper = self.manifest['helper_uid']
        provisioning = self.manifest['provisioning_gid']
        os.chown(self.persistent, helper, provisioning)
        with patch.object(parents, 'identities', return_value=(helper, provisioning)):
            self.prepared()
        for relative, expected in {
                parents.RUNTIME_IPC: (0, provisioning, 0o750),
                parents.RUNTIME_HELPER: (helper, provisioning, 0o750),
                parents.PERSISTENT: (helper, provisioning, 0o700),
                parents.RECEIPT_DIR: (0, 0, 0o755),
                parents.RECEIPT: (0, 0, 0o644)}.items():
            with self.subTest(path=relative):
                info = (self.root / relative).lstat()
                self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), expected)

    def test_preflight_needs_no_context_and_makes_no_mutation(self):
        (self.root / parents.CONTEXT).unlink()
        (self.root / runtime.CONTEXT_DIR).rmdir()
        before = self.snapshot()
        parents.preflight(self.value)
        self.assertEqual(self.snapshot(), before)
        for relative in (parents.RECEIPT_DIR, parents.RUNTIME_IPC, parents.RUNTIME_HELPER,
                         parents.ADMISSION, runtime.CONTEXT_DIR):
            self.assertFalse((self.root / relative).exists())

    def test_preflight_refuses_bad_persistent_metadata_or_nss_without_mutation(self):
        (self.root / parents.CONTEXT).unlink()
        (self.root / runtime.CONTEXT_DIR).rmdir()
        self.persistent.chmod(0o750)
        self.assert_parents_refused(lambda: parents.preflight(self.value))
        self.persistent.chmod(0o700)
        with patch.object(parents, 'identities', self.real_identities), \
                patch.object(parents.pwd, 'getpwnam', side_effect=KeyError('INERT_MISSING_ACCOUNT')):
            self.assert_parents_refused(lambda: parents.preflight(self.value))

    def test_prepare_creates_only_fixed_runtime_parents_and_public_receipt(self):
        persistent_before = self.persistent.stat()
        self.prepared()
        expected = {
            parents.RUNTIME_IPC: (os.geteuid(), os.getegid(), 0o750),
            parents.RUNTIME_HELPER: (os.geteuid(), os.getegid(), 0o750),
            parents.PERSISTENT: (os.geteuid(), os.getegid(), 0o700),
            parents.RECEIPT_DIR: (os.geteuid(), os.getegid(), 0o755),
        }
        for relative, metadata in expected.items():
            with self.subTest(path=relative):
                info = (self.root / relative).lstat()
                self.assertTrue(stat.S_ISDIR(info.st_mode))
                self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), metadata)
        receipt_path = self.root / parents.RECEIPT
        info = receipt_path.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)),
                         (os.geteuid(), os.getegid(), 0o644))
        self.assertEqual(set((self.root / parents.RECEIPT_DIR).iterdir()), {receipt_path})
        self.assertFalse((self.root / parents.ADMISSION).exists())
        self.assertEqual((self.persistent.stat().st_dev, self.persistent.stat().st_ino),
                         (persistent_before.st_dev, persistent_before.st_ino))
        receipt = self.receipt()
        self.assertEqual(set(receipt), {'version', 'boot_id', 'candidate_sha256', 'parents'})
        self.assertEqual((receipt['version'], receipt['boot_id'], receipt['candidate_sha256']),
                         (1, BOOT_ID, self.value.candidate_sha256))
        self.assertEqual(set(receipt['parents']),
                         {parents.RUNTIME_IPC, parents.RUNTIME_HELPER, parents.PERSISTENT})
        for relative, record in receipt['parents'].items():
            observed = (self.root / relative).lstat()
            self.assertEqual(record, {'dev': observed.st_dev, 'ino': observed.st_ino,
                                      'uid': observed.st_uid, 'gid': observed.st_gid,
                                      'mode': f'{stat.S_IMODE(observed.st_mode):04o}'})
        self.assertEqual(receipt_path.read_bytes(), encoded(receipt))

    def test_prepare_cannot_be_retried_or_repair_a_complete_operation(self):
        self.prepared()
        self.assert_parents_refused(lambda: parents.prepare(self.value))

    def test_verify_is_read_only_and_does_not_replace_receipt(self):
        self.prepared()
        before = self.snapshot()
        self.assertEqual(parents.verify(self.value), {'status': 'writer_parents_verified'})
        self.assertEqual(self.snapshot(), before)

    def test_verify_allows_legitimate_children_and_directory_timestamp_nlink_changes(self):
        self.prepared()
        for relative in (parents.RUNTIME_IPC, parents.RUNTIME_HELPER, parents.PERSISTENT):
            self.mkdir(relative + '/inert-child', 0o700)
            self.write(relative + '/inert-child/inert-state', b'INERT_LOCAL_STATE', 0o600)
        before = self.snapshot()
        self.assertEqual(parents.verify(self.value), {'status': 'writer_parents_verified'})
        self.assertEqual(self.snapshot(), before)

    def test_nonempty_persistent_parent_is_never_traversed_read_or_repaired(self):
        private_file = self.write(parents.PERSISTENT + '/private-sentinel',
                                  b'INERT_PRIVATE_SENTINEL_NOT_A_KEY', 0o600)
        self.symlink(parents.PERSISTENT + '/untrusted-child', '/INERT_OUTSIDE')
        private_inode = (self.persistent.stat().st_dev, self.persistent.stat().st_ino)
        sentinel_inode = (private_file.stat().st_dev, private_file.stat().st_ino)
        before = self.snapshot()
        originals = {name: getattr(os, name) for name in
                     ('open', 'read', 'listdir', 'scandir', 'fchmod', 'fchown')}
        original_open = builtins.open

        def inode(fd):
            value = os.fstat(fd)
            return value.st_dev, value.st_ino

        def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
            if dir_fd is not None:
                self.assertNotEqual(inode(dir_fd), private_inode,
                                    'Provisioner must not open a helper-private child')
            if not isinstance(path, int):
                target = Path(path)
                self.assertFalse(target.is_absolute() and self.persistent in target.parents)
            return originals['open'](path, flags, mode, dir_fd=dir_fd)

        def guarded_read(fd, count):
            self.assertNotEqual(inode(fd), sentinel_inode, 'Provisioner must not read private data')
            return originals['read'](fd, count)

        def guarded_listing(name):
            def call(path='.'):
                if isinstance(path, int):
                    self.assertNotEqual(inode(path), private_inode,
                                        'Provisioner must not enumerate persistent contents')
                else:
                    self.assertNotEqual(Path(path), self.persistent)
                return originals[name](path)
            return call

        def guarded_metadata(name):
            def call(fd, *args):
                self.assertNotEqual(inode(fd), private_inode,
                                    'Existing persistent parent must not be chmod/chown repaired')
                return originals[name](fd, *args)
            return call

        def guarded_builtin_open(file, *args, **kwargs):
            if not isinstance(file, int):
                target = Path(file)
                self.assertFalse(target.is_absolute() and self.persistent in target.parents)
            return original_open(file, *args, **kwargs)

        with ExitStack() as stack:
            stack.enter_context(patch.object(os, 'open', side_effect=guarded_open))
            stack.enter_context(patch.object(os, 'read', side_effect=guarded_read))
            for name in ('listdir', 'scandir'):
                stack.enter_context(patch.object(os, name, side_effect=guarded_listing(name)))
            for name in ('fchmod', 'fchown'):
                stack.enter_context(patch.object(os, name, side_effect=guarded_metadata(name)))
            stack.enter_context(patch.object(builtins, 'open', side_effect=guarded_builtin_open))
            self.prepared()
            self.assertEqual(parents.verify(self.value), {'status': 'writer_parents_verified'})
        after = self.snapshot()
        for relative in (parents.PERSISTENT, parents.PERSISTENT + '/private-sentinel',
                         parents.PERSISTENT + '/untrusted-child'):
            self.assertEqual(after[relative], before[relative])
        self.assertEqual(set(self.receipt()['parents'][parents.PERSISTENT]),
                         {'dev', 'ino', 'uid', 'gid', 'mode'})

    def test_missing_persistent_parent_is_not_created(self):
        self.persistent.rmdir()
        self.assert_parents_refused(lambda: parents.prepare(self.value))
        self.assertFalse(self.persistent.exists())
        self.assertFalse((self.root / parents.RECEIPT_DIR).exists())

    def test_prepare_refuses_preexisting_runtime_objects_without_adoption(self):
        for relative in (parents.RUNTIME_IPC, parents.RUNTIME_HELPER):
            for kind in ('directory', 'file', 'symlink'):
                with self.subTest(path=relative, kind=kind):
                    path = (self.mkdir(relative, 0o750) if kind == 'directory'
                            else self.write(relative, b'INERT_RESERVED_OBJECT') if kind == 'file'
                            else self.symlink(relative, '/INERT_DANGLING'))
                    try:
                        self.assert_parents_refused(lambda: parents.prepare(self.value))
                        self.assertFalse((self.root / parents.RECEIPT_DIR).exists())
                    finally:
                        if kind == 'directory': path.rmdir()
                        else: path.unlink()

    def test_prepare_refuses_preexisting_admission(self):
        path = self.mkdir(parents.ADMISSION)
        self.write(parents.ADMISSION + '/inert-existing-lock', b'INERT')
        self.assert_parents_refused(lambda: parents.prepare(self.value))
        self.assertTrue(path.is_dir())
        self.assertFalse((self.root / parents.RECEIPT_DIR).exists())

    def test_verify_accepts_admission_created_after_parent_provisioning(self):
        self.prepared()
        self.mkdir(parents.ADMISSION)
        before = self.snapshot()
        self.assertEqual(parents.verify(self.value), {'status': 'writer_parents_verified'})
        self.assertEqual(self.snapshot(), before)

    def test_partial_receipt_directory_is_never_resumed(self):
        self.mkdir(parents.RECEIPT_DIR)
        self.assert_parents_refused(lambda: parents.prepare(self.value))
        self.assert_parents_refused(lambda: parents.verify(self.value))

    def test_io_failure_after_latch_keeps_partial_state_and_blocks_retry(self):
        real_mkdir = os.mkdir
        calls = []

        def fail_helper(path, mode=0o777, *, dir_fd=None):
            calls.append(str(path))
            if str(path) == Path(parents.RUNTIME_HELPER).name:
                raise OSError('INERT_MKDIR_FAILURE')
            return real_mkdir(path, mode, dir_fd=dir_fd)

        with patch.object(parents.os, 'mkdir', side_effect=fail_helper):
            self.assert_parents_refused(lambda: parents.prepare(self.value), unchanged=False)
        self.assertEqual(calls[:2], [Path(parents.RECEIPT_DIR).name,
                                    Path(parents.RUNTIME_IPC).name])
        self.assertTrue((self.root / parents.RECEIPT_DIR).is_dir())
        self.assertTrue((self.root / parents.RUNTIME_IPC).is_dir())
        self.assertFalse((self.root / parents.RUNTIME_HELPER).exists())
        self.assertFalse((self.root / parents.RECEIPT).exists())
        self.assert_parents_refused(lambda: parents.prepare(self.value))
        self.assert_parents_refused(lambda: parents.verify(self.value))

    def test_parent_inode_replacement_is_refused_even_with_correct_metadata(self):
        self.prepared()
        for relative, mode in ((parents.RUNTIME_IPC, 0o750), (parents.RUNTIME_HELPER, 0o750),
                               (parents.PERSISTENT, 0o700)):
            with self.subTest(path=relative):
                path = self.root / relative
                old = path.with_name(path.name + '.inert-retained')
                path.rename(old)
                self.mkdir(relative, mode)
                try:
                    self.assert_parents_refused(lambda: parents.verify(self.value))
                finally:
                    path.rmdir()
                    old.rename(path)
        self.assertEqual(parents.verify(self.value), {'status': 'writer_parents_verified'})

    def test_parent_absence_after_prepare_is_refused_without_recreation(self):
        self.prepared()
        for relative in (parents.RUNTIME_IPC, parents.RUNTIME_HELPER, parents.PERSISTENT):
            with self.subTest(path=relative):
                path = self.root / relative
                old = path.with_name(path.name + '.inert-retained')
                path.rename(old)
                try:
                    self.assert_parents_refused(lambda: parents.verify(self.value))
                    self.assertFalse(path.exists())
                finally:
                    old.rename(path)

    def test_parent_symlink_after_prepare_is_refused_without_following(self):
        self.prepared()
        for relative in (parents.RUNTIME_IPC, parents.RUNTIME_HELPER, parents.PERSISTENT):
            with self.subTest(path=relative):
                path = self.root / relative
                old = path.with_name(path.name + '.inert-retained')
                path.rename(old)
                self.symlink(relative, str(old))
                try:
                    self.assert_parents_refused(lambda: parents.verify(self.value))
                finally:
                    path.unlink()
                    old.rename(path)

    def test_wrong_persistent_mode_is_refused_without_chmod_repair(self):
        self.persistent.chmod(0o750)
        self.assert_parents_refused(lambda: parents.prepare(self.value))
        self.assertEqual(stat.S_IMODE(self.persistent.stat().st_mode), 0o750)

    def test_wrong_parent_modes_after_prepare_are_refused_without_repair(self):
        self.prepared()
        for relative, correct in ((parents.RUNTIME_IPC, 0o750), (parents.RUNTIME_HELPER, 0o750),
                                  (parents.PERSISTENT, 0o700)):
            with self.subTest(path=relative):
                path = self.root / relative
                path.chmod(0o777)
                try:
                    self.assert_parents_refused(lambda: parents.verify(self.value))
                finally:
                    path.chmod(correct)

    def test_wrong_parent_owner_is_refused(self):
        self.prepared()
        real_stat = os.stat
        for relative in (parents.RUNTIME_IPC, parents.RUNTIME_HELPER, parents.PERSISTENT):
            with self.subTest(path=relative):
                selected = (self.root / relative).lstat()

                def wrong_owner(path, *args, **kwargs):
                    info = real_stat(path, *args, **kwargs)
                    if (info.st_dev, info.st_ino) == (selected.st_dev, selected.st_ino):
                        values = {key: getattr(info, key) for key in dir(info) if key.startswith('st_')}
                        values['st_uid'] += 1
                        return SimpleNamespace(**values)
                    return info

                with patch.object(parents.os, 'stat', side_effect=wrong_owner):
                    self.assert_parents_refused(lambda: parents.verify(self.value))

    def test_parent_xattrs_are_refused(self):
        self.prepared()
        real_listxattr = os.listxattr
        for relative in (parents.RUNTIME_IPC, parents.RUNTIME_HELPER, parents.PERSISTENT):
            with self.subTest(path=relative):
                selected = (self.root / relative).lstat()

                def unexpected_attribute(path, *args, **kwargs):
                    if isinstance(path, int):
                        info = os.fstat(path)
                        if (info.st_dev, info.st_ino) == (selected.st_dev, selected.st_ino):
                            return ['user.inert-unapproved']
                    return real_listxattr(path, *args, **kwargs)

                with patch.object(parents.os, 'listxattr', side_effect=unexpected_attribute):
                    self.assert_parents_refused(lambda: parents.verify(self.value))

    def test_receipt_absence_extra_file_modes_and_bytes_are_refused(self):
        self.prepared()
        receipt_path = self.root / parents.RECEIPT
        original = receipt_path.read_bytes()
        receipt_path.unlink()
        self.assert_parents_refused(lambda: parents.verify(self.value))
        self.write(parents.RECEIPT, original)
        extra = self.write(parents.RECEIPT_DIR + '/unapproved', b'INERT')
        self.assert_parents_refused(lambda: parents.verify(self.value))
        extra.unlink()
        receipt_path.chmod(0o600)
        self.assert_parents_refused(lambda: parents.verify(self.value))
        receipt_path.chmod(0o644)
        self.write(parents.RECEIPT, original + b'\n')
        self.assert_parents_refused(lambda: parents.verify(self.value))

    def test_receipt_binding_tampering_is_refused(self):
        self.prepared()
        original = self.receipt()
        for key, wrong in (('version', 2), ('boot_id', OTHER_BOOT), ('candidate_sha256', '0' * 64)):
            with self.subTest(field=key):
                value = copy.deepcopy(original)
                value[key] = wrong
                self.write(parents.RECEIPT, encoded(value))
                self.assert_parents_refused(lambda: parents.verify(self.value))
        self.write(parents.RECEIPT, encoded(original))

    def test_changed_boot_is_refused_for_prepare_and_verify(self):
        self.assert_parents_refused(lambda: parents.prepare(self.contract(boot=OTHER_BOOT)))
        self.prepared()
        self.assert_parents_refused(lambda: parents.verify(self.contract(boot=OTHER_BOOT)))

    def test_changed_candidate_is_refused_for_prepare_and_verify(self):
        self.prepared()
        self.manifest['studio_commit'] = '1' * 40
        self.write_manifest()
        changed = self.contract()
        self.assertNotEqual(changed.candidate_sha256, self.value.candidate_sha256)
        self.assert_parents_refused(lambda: parents.verify(changed))
        self.assert_parents_refused(lambda: parents.prepare(changed))
        self.assert_parents_refused(lambda: parents.verify(self.value))

    def test_changed_or_absent_context_is_refused(self):
        self.prepared()
        context_path = self.root / parents.CONTEXT
        original = context_path.read_bytes()
        self.write(parents.CONTEXT, original + b'\n')
        self.assert_parents_refused(lambda: parents.verify(self.value))
        context_path.unlink()
        self.assert_parents_refused(lambda: parents.verify(self.value))

    def test_wrong_caller_identity_is_refused_before_mutation(self):
        with patch.object(parents.os, 'geteuid', return_value=os.geteuid() + 1):
            self.assert_parents_refused(lambda: parents.prepare(self.value))

    def test_real_root_cannot_use_synthetic_owner_seam(self):
        value = copy.copy(self.value)
        value._root = Path('/')
        value._uid = value._gid = 1
        self.assert_parents_refused(lambda: parents.prepare(value))

    def test_nss_exact_forward_reverse_identity_is_accepted(self):
        with self.nss():
            self.assertEqual(self.real_identities(self.value),
                             (self.manifest['helper_uid'], self.manifest['provisioning_gid']))

    def test_nss_wrong_identity_or_reverse_alias_is_refused_before_mutation(self):
        helper = self.manifest['helper_uid']
        provisioning = self.manifest['provisioning_gid']
        cases = (
            {'user_changes': {'inky': pwd.struct_passwd(('inky', 'x', 1001, 1000, '', '/', '/inert'))}},
            {'user_changes': {'inky-network': pwd.struct_passwd(
                ('inky-network', 'x', helper + 1, provisioning, '', '/', '/inert'))}},
            {'group_changes': {'inky-provisioning': grp.struct_group(
                ('inky-provisioning', 'x', provisioning + 1, []))}},
            {'reverse_user_changes': {helper: pwd.struct_passwd(
                ('inert-alias', 'x', helper, provisioning, '', '/', '/inert'))}},
            {'reverse_group_changes': {provisioning: grp.struct_group(
                ('inert-alias', 'x', provisioning, []))}},
        )
        for index, values in enumerate(cases):
            with self.subTest(case=index), self.nss(**values), \
                    patch.object(parents, 'identities', self.real_identities):
                self.assert_parents_refused(lambda: parents.prepare(self.value))

    def test_nss_missing_account_is_wrapped_as_fixed_refusal(self):
        with patch.object(parents, 'identities', self.real_identities), \
                patch.object(parents.pwd, 'getpwnam', side_effect=KeyError('INERT_MISSING_ACCOUNT')):
            self.assert_parents_refused(lambda: parents.prepare(self.value))
