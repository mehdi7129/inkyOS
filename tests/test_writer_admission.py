"""Synthetic admission protocol tests; no service, app, VM, image or SD runs.

Non-Linux hosts use explicit owner and xattr seams. Linux root runs additionally
exercise a real numeric UID/GID 1000 writer. All process coordination uses pipes
with bounded deadlines; no timing sleeps establish ordering.
"""
import errno
import fcntl
import importlib.util
import multiprocessing
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'writer_admission_fixture', ROOT / 'staging/bootstrap/writer-admission.py')
admission = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(admission)
CONTEXT = multiprocessing.get_context('fork')
DEADLINE = 8


def receive(pipe):
    if not pipe.poll(DEADLINE):
        raise AssertionError('Child process did not reach the expected pipe stage')
    return pipe.recv()


def child_raw_lock(root, pipe, operation):
    try:
        fd = os.open(root / admission.DIRECTORY / 'lock', os.O_RDONLY)
        try:
            fcntl.flock(fd, operation | fcntl.LOCK_NB)
            pipe.send(('locked', os.getpid()))
            if receive(pipe) != 'release':
                raise AssertionError('Unexpected release command')
        finally:
            os.close(fd)
        pipe.send(('released',))
    except BaseException as error:
        pipe.send(('error', type(error).__name__, str(error)))
    finally:
        pipe.close()


def child_writer(root, owner, pipe, drop_identity=False):
    try:
        if drop_identity:
            os.setgroups([])
            os.setgid(1000)
            os.setuid(1000)
        with admission.writer(root, **owner) as lease:
            pipe.send(('writer', os.geteuid(), os.getegid(), os.getgroups(),
                       os.get_inheritable(lease.fileno())))
            if receive(pipe) != 'release':
                raise AssertionError('Unexpected release command')
        pipe.send(('released',))
    except BaseException as error:
        pipe.send(('error', type(error).__name__, getattr(error, 'reason', str(error))))
    finally:
        pipe.close()


def child_factory_crash(root, owner, pipe):
    try:
        with admission.factory(root, **owner):
            pipe.send(('attempted',))
            if receive(pipe) != 'crash':
                raise AssertionError('Unexpected crash command')
            os._exit(73)
    except BaseException as error:
        pipe.send(('error', type(error).__name__, getattr(error, 'reason', str(error))))
    finally:
        pipe.close()


def child_factory_crash_before_attempted(root, owner, pipe):
    original_create = admission.create

    def stop_before_attempted(parent, name, raw, uid, gid):
        if name == 'attempted':
            pipe.send(('before_attempted',))
            if receive(pipe) != 'crash':
                raise AssertionError('Unexpected crash command')
            os._exit(74)
        return original_create(parent, name, raw, uid, gid)

    try:
        with patch.object(admission, 'create', side_effect=stop_before_attempted):
            with admission.factory(root, **owner):
                raise AssertionError('Factory yielded before the injected crash')
    except BaseException as error:
        pipe.send(('error', type(error).__name__, getattr(error, 'reason', str(error))))
    finally:
        pipe.close()


def child_inherited_lease(lease, pipe):
    try:
        try:
            lease.publish_ready()
        except admission.Refused as error:
            pipe.send(('inherited', error.reason))
        else:
            pipe.send(('error', 'Inherited lease published Ready'))
        if receive(pipe) != 'release':
            raise AssertionError('Unexpected release command')
        lease.close()
        pipe.send(('released',))
    except BaseException as error:
        pipe.send(('error', type(error).__name__, str(error)))
    finally:
        pipe.close()


def child_unprivileged_creation(root, owner, pipe):
    try:
        os.setgroups([])
        os.setgid(1000)
        os.setuid(1000)
        directory = root / admission.DIRECTORY
        fd = os.open(directory / 'lock', os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            denied = []
            for name in ('attempted', 'Ready'):
                try:
                    new_fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
                except PermissionError:
                    denied.append(name)
                else:
                    os.close(new_fd)
                    raise AssertionError('Numeric UID 1000 created factory state')
            for operation in ('prepare', 'factory'):
                try:
                    if operation == 'prepare':
                        admission.prepare(root, **owner)
                    else:
                        with admission.factory(root, **owner):
                            raise AssertionError('Numeric UID 1000 entered factory')
                except admission.Refused as error:
                    if error.reason != 'not_owner':
                        raise
            pipe.send(('denied', os.geteuid(), os.getegid(), os.getgroups(), denied))
            if receive(pipe) != 'release':
                raise AssertionError('Unexpected release command')
        finally:
            os.close(fd)
        pipe.send(('released',))
    except BaseException as error:
        pipe.send(('error', type(error).__name__, getattr(error, 'reason', str(error))))
    finally:
        pipe.close()


class WriterAdmissionTests(unittest.TestCase):
    def setUp(self):
        if sys.platform != 'linux':
            seam = patch.object(os, 'listxattr', create=True, return_value=[])
            seam.start()
            self.addCleanup(seam.stop)
        temporary = tempfile.TemporaryDirectory(
            prefix='inkyos-admission-', dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.owner = {'_owner_uid': os.geteuid(), '_owner_gid': os.getegid()}
        self.root = self.make_root('root')
        self.serial = 0

    def make_root(self, name):
        root = self.base / name
        root.mkdir(mode=0o700)
        (root / 'run').mkdir(mode=0o755)
        (root / 'run').chmod(0o755)
        return root

    def fresh(self):
        self.serial += 1
        return self.make_root(f'case-{self.serial}')

    def prepare(self, root=None):
        root = self.root if root is None else root
        admission.prepare(root, **self.owner)
        return root / admission.DIRECTORY

    def ready(self, root=None):
        root = self.root if root is None else root
        directory = self.prepare(root)
        with admission.factory(root, **self.owner) as lease:
            lease.publish_ready()
        return directory

    def snapshot(self, root=None):
        root = self.root if root is None else root
        result = {}
        for path in (root, *sorted(root.rglob('*'))):
            info = path.lstat()
            kind = ('directory' if stat.S_ISDIR(info.st_mode) else
                    'symlink' if stat.S_ISLNK(info.st_mode) else
                    'file' if stat.S_ISREG(info.st_mode) else 'special')
            record = (kind, stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid,
                      info.st_nlink, info.st_dev, info.st_ino)
            if kind == 'file':
                record += (path.read_bytes(),)
            elif kind == 'symlink':
                record += (os.readlink(path),)
            result[str(path.relative_to(root))] = record
        return result

    def assert_refused(self, reason, operation, *, root=None, owner=None):
        root = self.root if root is None else root
        owner = self.owner if owner is None else owner
        before = self.snapshot(root)
        with self.assertRaises(admission.Refused) as caught:
            if operation == 'prepare':
                admission.prepare(root, **owner)
            else:
                with getattr(admission, operation)(root, **owner):
                    self.fail('Refused operation yielded a lease')
        self.assertEqual(caught.exception.reason, reason)
        self.assertEqual(self.snapshot(root), before)

    def spawn(self, function, *arguments):
        parent_pipe, child_pipe = CONTEXT.Pipe()
        process = CONTEXT.Process(target=function, args=(*arguments, child_pipe))
        process.start()
        child_pipe.close()

        def cleanup():
            parent_pipe.close()
            if process.is_alive():
                process.kill()
            process.join(DEADLINE)
            if process.is_alive():
                raise AssertionError('Child process remained alive after cleanup')
            process.close()

        self.addCleanup(cleanup)
        return process, parent_pipe

    def finish(self, process, pipe, expected_exit=0):
        process.join(DEADLINE)
        self.assertFalse(process.is_alive(), 'Child process did not exit by the deadline')
        self.assertEqual(process.exitcode, expected_exit)

    def assert_fd_closed(self, fd):
        with self.assertRaises(OSError) as caught:
            os.fstat(fd)
        self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_prepare_creates_only_empty_public_readable_lock(self):
        directory = self.prepare()
        self.assertEqual(admission.DIRECTORY, 'run/inkyos-admission')
        self.assertEqual({path.name for path in directory.iterdir()}, {'lock'})
        self.assertEqual((directory / 'lock').read_bytes(), b'')
        for path, mode in ((directory, 0o755), (directory / 'lock', 0o644)):
            info = path.lstat()
            self.assertEqual(stat.S_IMODE(info.st_mode), mode)
            self.assertEqual((info.st_uid, info.st_gid),
                             (self.owner['_owner_uid'], self.owner['_owner_gid']))
        self.assert_refused('invalid_state', 'prepare')

    def test_prepare_requires_existing_safe_run_without_mutation(self):
        for defect in ('absent', 'symlink', 'writable'):
            with self.subTest(defect=defect):
                root = self.fresh()
                run = root / 'run'
                if defect == 'absent':
                    run.rmdir()
                elif defect == 'symlink':
                    run.rmdir()
                    run.symlink_to(self.root / 'run', target_is_directory=True)
                else:
                    run.chmod(0o777)
                self.assert_refused('invalid_state', 'prepare', root=root)

    def test_attempted_is_created_before_yield_and_ready_only_by_explicit_publish(self):
        directory = self.prepare()
        self.assertEqual(admission.ATTEMPTED, b'{"schema_version":1,"state":"attempted"}\n')
        self.assertEqual(admission.READY, b'{"schema_version":1,"state":"factory-complete"}\n')
        with admission.factory(self.root, **self.owner) as lease:
            self.assertEqual((directory / 'attempted').read_bytes(), admission.ATTEMPTED)
            self.assertFalse((directory / 'Ready').exists())
            self.assertFalse(os.get_inheritable(lease.fileno()))
            lease.publish_ready()
            self.assertEqual((directory / 'Ready').read_bytes(), admission.READY)
            self.assert_refused('busy', 'writer')
        self.assertEqual({path.name for path in directory.iterdir()}, {'lock', 'attempted', 'Ready'})
        for name in ('attempted', 'Ready'):
            info = (directory / name).stat()
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o644)
            self.assertEqual(info.st_nlink, 1)
        with admission.writer(self.root, **self.owner) as lease:
            self.assertFalse(os.get_inheritable(lease.fileno()))

    def test_writer_requires_ready_and_never_creates_any_state(self):
        self.assert_refused('invalid_state', 'writer')
        self.prepare()
        self.assert_refused('not_ready', 'writer')
        with admission.factory(self.root, **self.owner):
            pass
        self.assert_refused('not_ready', 'writer')

    def test_factory_exception_leaves_sticky_attempted_and_blocks_retry(self):
        directory = self.prepare()
        with self.assertRaisesRegex(RuntimeError, 'inert failure'):
            with admission.factory(self.root, **self.owner):
                raise RuntimeError('inert failure')
        self.assertEqual((directory / 'attempted').read_bytes(), admission.ATTEMPTED)
        self.assertFalse((directory / 'Ready').exists())
        self.assert_refused('recovery_required', 'factory')
        self.assert_refused('not_ready', 'writer')

    def test_failed_attempted_write_leaves_invalid_state_without_retry_or_repair(self):
        directory = self.prepare()
        with patch.object(os, 'write', side_effect=OSError('Inert attempted write failure')):
            with self.assertRaises(admission.Refused) as caught:
                with admission.factory(self.root, **self.owner):
                    self.fail('Incomplete attempted marker admitted factory')
        self.assertEqual(caught.exception.reason, 'invalid_state')
        self.assertTrue((directory / 'attempted').exists())
        self.assertFalse((directory / 'Ready').exists())
        self.assert_refused('invalid_state', 'factory')
        self.assert_refused('invalid_state', 'writer')

    def test_factory_crash_leaves_sticky_attempted_without_ready(self):
        directory = self.prepare()
        process, pipe = self.spawn(child_factory_crash, self.root, self.owner)
        self.assertEqual(receive(pipe), ('attempted',))
        self.assert_refused('busy', 'factory')
        pipe.send('crash')
        self.finish(process, pipe, expected_exit=73)
        self.assertEqual((directory / 'attempted').read_bytes(), admission.ATTEMPTED)
        self.assertFalse((directory / 'Ready').exists())
        self.assert_refused('recovery_required', 'factory')
        self.assert_refused('not_ready', 'writer')

    def test_factory_crash_before_attempted_releases_lock_without_spending_attempt(self):
        directory = self.prepare()
        before = self.snapshot()
        process, pipe = self.spawn(child_factory_crash_before_attempted, self.root, self.owner)
        self.assertEqual(receive(pipe), ('before_attempted',))
        self.assert_refused('busy', 'factory')
        self.assert_refused('busy', 'writer')
        self.assertEqual(self.snapshot(), before)
        pipe.send('crash')
        self.finish(process, pipe, expected_exit=74)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((directory / 'attempted').exists())
        with admission.factory(self.root, **self.owner):
            self.assertEqual((directory / 'attempted').read_bytes(), admission.ATTEMPTED)
            self.assertFalse((directory / 'Ready').exists())

    def test_completed_factory_refuses_second_run_without_mutation(self):
        self.ready()
        self.assert_refused('already_ready', 'factory')

    def test_publication_error_after_create_does_not_revoke_visible_ready(self):
        directory = self.prepare()
        original_create = admission.create

        def create_then_error(parent, name, raw, uid, gid):
            original_create(parent, name, raw, uid, gid)
            if name == 'Ready':
                raise OSError('Inert injected error after completed Ready creation')

        with admission.factory(self.root, **self.owner) as lease:
            with patch.object(admission, 'create', side_effect=create_then_error):
                with self.assertRaises(admission.Refused) as caught:
                    lease.publish_ready()
            self.assertEqual(caught.exception.reason, 'publication_uncertain')
            self.assertEqual((directory / 'Ready').read_bytes(), admission.READY)
            self.assert_refused('busy', 'writer')
        with admission.writer(self.root, **self.owner):
            pass
        self.assert_refused('already_ready', 'factory')

    def test_partial_ready_write_is_uncertain_and_cannot_admit_writer(self):
        directory = self.prepare()
        with admission.factory(self.root, **self.owner) as lease:
            with patch.object(os, 'write', side_effect=OSError('Inert Ready write failure')):
                with self.assertRaises(admission.Refused) as caught:
                    lease.publish_ready()
            self.assertEqual(caught.exception.reason, 'publication_uncertain')
        self.assertTrue((directory / 'Ready').exists())
        self.assertNotEqual((directory / 'Ready').read_bytes(), admission.READY)
        self.assert_refused('invalid_state', 'writer')
        self.assert_refused('invalid_state', 'factory')

    def test_exclusive_lock_blocks_factory_and_writer_without_signals_or_mutation(self):
        self.prepare()
        # Signature order keeps the pipe last for the common spawn helper.
        def child(root, operation, pipe):
            child_raw_lock(root, pipe, operation)
        process, pipe = self.spawn(child, self.root, fcntl.LOCK_EX)
        self.assertEqual(receive(pipe)[0], 'locked')
        with patch.object(os, 'kill', side_effect=AssertionError('Admission must not signal another process')):
            self.assert_refused('busy', 'factory')
            self.assert_refused('busy', 'writer')
        pipe.send('release')
        self.assertEqual(receive(pipe), ('released',))
        self.finish(process, pipe)
        self.assertFalse((self.root / admission.DIRECTORY / 'attempted').exists())

    def test_two_process_writers_hold_shared_lock_and_factory_is_busy(self):
        self.ready()
        process, pipe = self.spawn(child_writer, self.root, self.owner)
        self.assertEqual(receive(pipe)[0], 'writer')
        with admission.writer(self.root, **self.owner):
            self.assert_refused('busy', 'factory')
        pipe.send('release')
        self.assertEqual(receive(pipe), ('released',))
        self.finish(process, pipe)
        self.assert_refused('already_ready', 'factory')

    def test_dup_retains_factory_lock_until_last_descriptor_closes(self):
        self.prepare()
        with admission.factory(self.root, **self.owner) as lease:
            duplicate = os.dup(lease.fileno())
            try:
                lease.close()
                lease.close()
                self.assert_refused('busy', 'factory')
            finally:
                os.close(duplicate)
            self.assert_refused('recovery_required', 'factory')

    def test_fork_retains_lock_after_parent_close_and_inherited_publish_is_refused(self):
        directory = self.prepare()
        with admission.factory(self.root, **self.owner) as lease:
            process, pipe = self.spawn(child_inherited_lease, lease)
            self.assertEqual(receive(pipe), ('inherited', 'not_owner'))
            lease.close()
            self.assert_refused('busy', 'factory')
            self.assertFalse((directory / 'Ready').exists())
            pipe.send('release')
            self.assertEqual(receive(pipe), ('released',))
            self.finish(process, pipe)
            self.assert_refused('recovery_required', 'factory')

    def test_factory_and_writer_contexts_close_fd_and_close_is_idempotent(self):
        self.prepare()
        with admission.factory(self.root, **self.owner) as lease:
            factory_fd = lease.fileno()
            lease.publish_ready()
        self.assert_fd_closed(factory_fd)
        lease.close()
        with admission.writer(self.root, **self.owner) as lease:
            writer_fd = lease.fileno()
        self.assert_fd_closed(writer_fd)
        lease.close()

    def test_closed_factory_lease_cannot_publish(self):
        directory = self.prepare()
        with admission.factory(self.root, **self.owner) as lease:
            lease.close()
            before = self.snapshot()
            with self.assertRaises(admission.Refused) as caught:
                lease.publish_ready()
            self.assertEqual(caught.exception.reason, 'invalid_state')
            self.assertEqual(self.snapshot(), before)
        self.assertFalse((directory / 'Ready').exists())

    def test_prepare_and_factory_require_owner_identity_including_group(self):
        for key in ('_owner_uid', '_owner_gid'):
            wrong = {**self.owner, key: self.owner[key] + 10001}
            with self.subTest(key=key):
                self.assert_refused('not_owner', 'prepare', owner=wrong)
        self.prepare()
        for key in ('_owner_uid', '_owner_gid'):
            wrong = {**self.owner, key: self.owner[key] + 10001}
            with self.subTest(key=key):
                self.assert_refused('not_owner', 'factory', owner=wrong)

    def test_publish_rechecks_owner_uid_and_gid(self):
        directory = self.prepare()
        with admission.factory(self.root, **self.owner) as lease:
            for function, wrong in (('geteuid', os.geteuid() + 10001),
                                    ('getegid', os.getegid() + 10001)):
                with self.subTest(function=function):
                    before = self.snapshot()
                    with patch.object(os, function, return_value=wrong):
                        with self.assertRaises(admission.Refused) as caught:
                            lease.publish_ready()
                    self.assertEqual(caught.exception.reason, 'not_owner')
                    self.assertEqual(self.snapshot(), before)
        self.assertFalse((directory / 'Ready').exists())

    def test_extra_entries_and_wrong_directory_modes_fail_closed(self):
        for defect in ('extra', 'writable', 'private', 'symlink'):
            with self.subTest(defect=defect):
                root = self.fresh()
                directory = self.ready(root)
                if defect == 'extra':
                    (directory / 'unexpected').write_bytes(b'inert\n')
                elif defect == 'symlink':
                    moved = directory.with_name('moved-admission')
                    directory.rename(moved)
                    directory.symlink_to(moved, target_is_directory=True)
                else:
                    directory.chmod(0o777 if defect == 'writable' else 0o700)
                self.assert_refused('invalid_state', 'writer', root=root)
                self.assert_refused('invalid_state', 'factory', root=root)

    def test_lock_and_markers_reject_symlink_hardlink_fifo_modes_and_oversize(self):
        for name in ('lock', 'attempted', 'Ready'):
            for defect in ('symlink', 'hardlink', 'fifo', 'writable', 'private', 'oversize'):
                with self.subTest(name=name, defect=defect):
                    root = self.fresh()
                    directory = self.ready(root)
                    path = directory / name
                    if defect in ('symlink', 'hardlink'):
                        outside = self.base / f'outside-{self.serial}'
                        path.rename(outside)
                        path.symlink_to(outside) if defect == 'symlink' else os.link(outside, path)
                    elif defect == 'fifo':
                        path.unlink()
                        os.mkfifo(path, 0o644)
                    elif defect in ('writable', 'private'):
                        path.chmod(0o666 if defect == 'writable' else 0o600)
                    else:
                        path.write_bytes(b'x' * 65536)
                    self.assert_refused('invalid_state', 'writer', root=root)
                    self.assert_refused('invalid_state', 'factory', root=root)

    def test_malformed_or_inexact_markers_are_not_authority(self):
        for name in ('attempted', 'Ready'):
            for content in (b'', b'{}\n', b'{"schema_version":true}\n',
                            b'{"schema_version":1,"state":"factory-complete","extra":0}\n'):
                with self.subTest(name=name, content=content):
                    root = self.fresh()
                    path = self.ready(root) / name
                    path.write_bytes(content)
                    self.assert_refused('invalid_state', 'writer', root=root)
                    self.assert_refused('invalid_state', 'factory', root=root)

    def test_ready_without_attempted_is_invalid_not_success(self):
        directory = self.ready()
        (directory / 'attempted').unlink()
        self.assert_refused('invalid_state', 'writer')
        self.assert_refused('invalid_state', 'factory')

    def test_replaced_lock_during_lease_blocks_ready_publication(self):
        directory = self.prepare()
        with admission.factory(self.root, **self.owner) as lease:
            (directory / 'lock').rename(self.base / 'original-lock')
            (directory / 'lock').touch(mode=0o644)
            before = self.snapshot()
            with self.assertRaises(admission.Refused) as caught:
                lease.publish_ready()
            self.assertEqual(caught.exception.reason, 'invalid_state')
            self.assertEqual(self.snapshot(), before)
        self.assertFalse((directory / 'Ready').exists())

    def test_replacement_after_flock_is_detected_before_factory_attempted(self):
        directory = self.prepare()
        real_flock = fcntl.flock
        replaced = False

        def replace_after_lock(fd, operation):
            nonlocal replaced
            result = real_flock(fd, operation)
            if not replaced and operation & fcntl.LOCK_EX:
                replaced = True
                (directory / 'lock').rename(self.base / 'original-lock')
                (directory / 'lock').touch(mode=0o644)
            return result

        with patch.object(fcntl, 'flock', side_effect=replace_after_lock):
            with self.assertRaises(admission.Refused) as caught:
                with admission.factory(self.root, **self.owner):
                    self.fail('Replaced lock admitted factory')
        self.assertEqual(caught.exception.reason, 'invalid_state')
        self.assertFalse((directory / 'attempted').exists())

    def test_replacement_after_shared_flock_is_detected_before_writer_yield(self):
        directory = self.ready()
        real_flock = fcntl.flock
        replaced = False

        def replace_after_lock(fd, operation):
            nonlocal replaced
            result = real_flock(fd, operation)
            if not replaced and operation & fcntl.LOCK_SH:
                replaced = True
                (directory / 'lock').rename(self.base / 'original-lock')
                (directory / 'lock').touch(mode=0o644)
            return result

        with patch.object(fcntl, 'flock', side_effect=replace_after_lock):
            with self.assertRaises(admission.Refused) as caught:
                with admission.writer(self.root, **self.owner):
                    self.fail('Replaced lock admitted writer')
        self.assertEqual(caught.exception.reason, 'invalid_state')

    def test_missing_or_unreadable_xattr_support_fails_closed(self):
        saved = os.listxattr
        del os.listxattr
        try:
            self.assert_refused('invalid_state', 'prepare')
        finally:
            os.listxattr = saved
        for error in (OSError('inert xattr query failure'), TypeError('unsupported fd')):
            with self.subTest(error=type(error).__name__):
                with patch.object(os, 'listxattr', side_effect=error):
                    self.assert_refused('invalid_state', 'prepare')
        with patch.object(os, 'listxattr', return_value=['user.inert-fixture']):
            self.assert_refused('invalid_state', 'prepare')

    def test_repeated_refusals_do_not_leak_file_descriptors(self):
        directory = self.prepare()
        fd_directory = '/proc/self/fd' if sys.platform == 'linux' else '/dev/fd'
        baseline = len(os.listdir(fd_directory))
        for _ in range(64):
            self.assert_refused('not_ready', 'writer')
        with admission.factory(self.root, **self.owner):
            pass
        (directory / 'attempted').chmod(0o666)
        for _ in range(64):
            self.assert_refused('invalid_state', 'factory')
            self.assert_refused('invalid_state', 'writer')
        self.assertLessEqual(len(os.listdir(fd_directory)), baseline + 1)

    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                         'Real numeric identity qualification requires Linux root')
    def test_linux_numeric_uid_gid_1000_writer_uses_root_owned_read_only_lock(self):
        self.base.chmod(0o755)
        self.root.chmod(0o755)
        self.ready()

        def child(root, owner, pipe):
            child_writer(root, owner, pipe, drop_identity=True)

        process, pipe = self.spawn(child, self.root, self.owner)
        self.assertEqual(receive(pipe), ('writer', 1000, 1000, [], False))
        self.assert_refused('busy', 'factory')
        pipe.send('release')
        self.assertEqual(receive(pipe), ('released',))
        self.finish(process, pipe)

    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                         'Real numeric identity qualification requires Linux root')
    def test_linux_uid_gid_1000_can_lock_shared_but_cannot_create_factory_state(self):
        self.base.chmod(0o755)
        self.root.chmod(0o755)
        directory = self.prepare()
        process, pipe = self.spawn(child_unprivileged_creation, self.root, self.owner)
        self.assertEqual(receive(pipe), ('denied', 1000, 1000, [], ['attempted', 'Ready']))
        self.assert_refused('busy', 'factory')
        self.assertEqual({path.name for path in directory.iterdir()}, {'lock'})
        pipe.send('release')
        self.assertEqual(receive(pipe), ('released',))
        self.finish(process, pipe)

    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                         'Foreign file ownership fixtures require Linux root')
    def test_linux_foreign_uid_and_gid_on_each_state_object_are_refused(self):
        for name in ('', 'lock', 'attempted', 'Ready'):
            for uid, gid in ((1000, 0), (0, 1000)):
                with self.subTest(name=name, uid=uid, gid=gid):
                    root = self.fresh()
                    directory = self.ready(root)
                    path = directory / name if name else directory
                    os.chown(path, uid, gid)
                    self.assert_refused('invalid_state', 'writer', root=root)
                    self.assert_refused('invalid_state', 'factory', root=root)


if __name__ == '__main__':
    unittest.main()
