"""Shared guard tests with the actual contract, role verifier and admission code.

Payload fixtures are inert. Ownership/identity and mountinfo seams are explicit;
the files, pins, context, descriptors, flock locks and fork inheritance are real.
Only the existing ContractFixture supplies data; no FakeRuntime is used.
"""
import copy
import errno
import fcntl
import multiprocessing
import os
from pathlib import Path
import stat
import unittest
from unittest.mock import patch

from test_factory_runtime_contract import ContractFixture, runtime


PROCESSES = multiprocessing.get_context('fork')
DEADLINE = 8


def receive(pipe):
    if not pipe.poll(DEADLINE):
        raise AssertionError('Inert child missed its pipe checkpoint')
    return pipe.recv()


def close_if_open(fd):
    try:
        os.close(fd)
    except OSError as error:
        if error.errno != errno.EBADF:
            raise


def retained_lease(fd, pipe):
    try:
        info = os.fstat(fd)
        pipe.send(('retained', info.st_dev, info.st_ino, os.get_inheritable(fd)))
        if receive(pipe) != 'release':
            raise AssertionError('Unexpected lease release command')
    except BaseException as error:
        pipe.send(('error', type(error).__name__, str(error)))
    finally:
        pipe.close()


class CallerFailure(RuntimeError):
    pass


class RuntimeWriterGuardTests(ContractFixture):
    def setUp(self):
        super().setUp()
        self.value = self.full_candidate()
        self.value, self.admission = self.ready(self.value)
        self.lock_path = self.root / 'run/inkyos-admission/lock'

    def guard(self, role='main', *, environment=None, **overrides):
        options = {'_contract': self.value, '_identity': self.identity(role),
                   '_environ': {} if environment is None else environment}
        options.update(overrides)
        return runtime.writer_guard(role, **options)

    def environment(self, fd, role='main'):
        return {'INKYOS_WRITER_LEASE_FD': str(fd), 'INKYOS_WRITER_ROLE': role,
                'INKYOS_WRITER_CONTEXT_SHA256': self.value.context_sha256}

    def assert_busy(self, path=None, operation=fcntl.LOCK_EX):
        fd = os.open(self.lock_path if path is None else path, os.O_RDONLY)
        try:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(fd, operation | fcntl.LOCK_NB)
        finally:
            os.close(fd)

    def assert_unlocked(self, path=None):
        fd = os.open(self.lock_path if path is None else path, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)

    def assert_closed(self, fd):
        with self.assertRaises(OSError) as caught:
            os.fstat(fd)
        self.assertEqual(caught.exception.errno, errno.EBADF)

    def refused(self, role='main', *, environment=None, unchanged=True, **overrides):
        before = self.snapshot() if unchanged else None
        env_before = None if environment is None else dict(environment)
        with self.assertRaises(runtime.Refused) as caught:
            with self.guard(role, environment=environment, **overrides):
                self.fail('Refused guard yielded a lease')
        self.assertEqual(caught.exception.reason, 'writer_admission_refused')
        if unchanged:
            self.assertEqual(self.snapshot(), before)
        if environment is not None:
            self.assertEqual(environment, env_before)

    def spawn(self, fd):
        parent, child = PROCESSES.Pipe()
        process = PROCESSES.Process(target=retained_lease, args=(fd, child))
        process.start()
        child.close()

        def cleanup():
            parent.close()
            if process.is_alive():
                process.kill()
            process.join(DEADLINE)
            if process.is_alive():
                raise AssertionError('Inert child exceeded its cleanup deadline')
            process.close()

        self.addCleanup(cleanup)
        return process, parent

    def release(self, process, pipe):
        pipe.send('release')
        process.join(DEADLINE)
        self.assertFalse(process.is_alive(), 'Inert child exceeded its exit deadline')
        self.assertEqual(process.exitcode, 0)

    def test_every_role_takes_real_readonly_shared_lease_without_inherited_environment(self):
        before = self.snapshot()
        for role in ('main', 'helper', 'ipc'):
            with self.subTest(role=role):
                environment = {'PATH': '/untrusted', 'OTHER': 'untouched'}
                with self.guard(role, environment=environment) as lease:
                    fd = lease.fileno()
                    self.assertFalse(os.get_inheritable(fd))
                    self.assertEqual(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
                    self.assert_busy()
                    with self.assertRaises(self.admission.Refused) as blocked:
                        with self.admission.factory(self.root, **self.owner):
                            self.fail('Factory entered while guard held SH')
                    self.assertEqual(blocked.exception.reason, 'busy')
                self.assert_closed(fd)
                self.assert_unlocked()
                self.assertEqual(environment, {'PATH': '/untrusted', 'OTHER': 'untouched'})
        self.assertEqual(self.snapshot(), before)

    def test_shared_admission_precedes_actual_context_and_role_verification(self):
        events = []
        real_import = runtime.import_admission
        real_context = runtime.context_sha256
        real_role = runtime.verify_role

        def imported(contract):
            self.assert_unlocked()
            events.append('import')
            return real_import(contract)

        def context(contract):
            self.assert_busy()
            events.append('context')
            return real_context(contract)

        def role(contract, role, **kwargs):
            self.assert_busy()
            events.append('role')
            return real_role(contract, role, **kwargs)

        with patch.object(runtime, 'import_admission', side_effect=imported), \
                patch.object(runtime, 'context_sha256', side_effect=context), \
                patch.object(runtime, 'verify_role', side_effect=role):
            with self.guard():
                events.append('yield')
        self.assertEqual(events[0], 'import')
        self.assertLess(events.index('context'), events.index('role'))
        self.assertEqual(events[-1], 'yield')
        self.assertGreaterEqual(events.count('context'), 2)

    def test_every_role_retires_inherited_fd_after_its_own_independent_sh(self):
        for role in ('main', 'helper', 'ipc'):
            with self.subTest(role=role):
                with self.admission.writer(self.root, **self.owner) as original:
                    inherited = os.dup(original.fileno())
                    environment = self.environment(inherited, role)
                    environment['OTHER'] = 'preserved'
                    with self.guard(role, environment=environment) as fresh:
                        self.assertNotEqual(fresh.fileno(), original.fileno())
                        self.assert_closed(inherited)
                        os.fstat(original.fileno())
                        self.assert_busy()
                    self.assertEqual(environment, {'OTHER': 'preserved'})
                    self.assert_busy()
                self.assert_unlocked()

    def test_retiring_fd_never_unlocks_another_duplicate_of_its_open_file_description(self):
        with self.admission.writer(self.root, **self.owner) as original:
            inherited = os.dup(original.fileno())
            retained = os.dup(inherited)
            self.addCleanup(close_if_open, retained)
            with self.guard(environment=self.environment(inherited)):
                self.assert_closed(inherited)
        self.assert_busy()
        os.close(retained)
        self.assert_unlocked()

    def test_fork_keeps_shared_lease_after_parent_guard_closes(self):
        with self.guard() as lease:
            fd = lease.fileno()
            info = os.fstat(fd)
            process, pipe = self.spawn(fd)
            self.assertEqual(receive(pipe), ('retained', info.st_dev, info.st_ino, False))
        self.assert_closed(fd)
        self.assert_busy()
        self.release(process, pipe)
        self.assert_unlocked()

    def test_exclusive_inherited_lease_is_not_converted_or_retired(self):
        for filename in ('attempted', 'Ready'):
            (self.root / 'run/inkyos-admission' / filename).unlink()
        with self.admission.factory(self.root, **self.owner) as exclusive:
            environment = self.environment(exclusive.fileno())
            with patch.object(runtime, 'context_sha256') as context, \
                    patch.object(runtime, 'verify_role') as role:
                self.refused(environment=environment)
                context.assert_not_called()
                role.assert_not_called()
            self.assert_busy(operation=fcntl.LOCK_SH)
            os.fstat(exclusive.fileno())
            exclusive.publish_ready()

    def test_missing_ready_closes_fresh_descriptor_before_context_or_role(self):
        (self.root / 'run/inkyos-admission/Ready').unlink()
        actual_flock = fcntl.flock
        with patch.object(fcntl, 'flock', wraps=actual_flock) as flock, \
                patch.object(runtime, 'context_sha256') as context, \
                patch.object(runtime, 'verify_role') as role:
            self.refused()
            context.assert_not_called()
            role.assert_not_called()
        descriptors = [call.args[0] for call in flock.call_args_list
                       if call.args[1] == fcntl.LOCK_SH | fcntl.LOCK_NB]
        self.assertEqual(len(descriptors), 1)
        self.assert_closed(descriptors[0])
        self.assert_unlocked()

    def test_payload_identity_context_and_candidate_failures_before_yield(self):
        for role, relative in (
            ('main', runtime.APP + '/server/.venv/lib/python3.13/site-packages/inky_web/main.py'),
            ('helper', runtime.HELPER), ('ipc', runtime.IPC),
        ):
            with self.subTest(role=role):
                path = self.root / relative
                original, mode = path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
                self.write(relative, original + b'TAMPERED', mode)
                self.refused(role)
                self.assert_unlocked()
                self.write(relative, original, mode)
                identity = self.identity(role)
                identity['groups'].append(777)
                self.refused(role, _identity=identity)
                self.assert_unlocked()
        context = self.root / runtime.CONTEXT
        raw = context.read_bytes()
        self.write(runtime.CONTEXT, raw + b' ')
        self.refused()
        self.assert_unlocked()
        self.write(runtime.CONTEXT, raw)
        self.manifest['studio_commit'] = 'b' * 40
        self.write_manifest()
        self.refused()
        self.assert_unlocked()

    def test_admission_module_pin_failure_precedes_any_lock(self):
        self.write(runtime.MODULE_DIR + '/writer-admission.py',
                   b'raise AssertionError("altered admission must not execute")\n', 0o555)
        with patch.object(fcntl, 'flock', wraps=fcntl.flock) as flock:
            self.refused()
            flock.assert_not_called()

    def test_context_change_during_actual_role_verification_prevents_yield_and_retirement(self):
        inherited = os.open(self.lock_path, os.O_RDONLY)
        self.addCleanup(close_if_open, inherited)
        environment = self.environment(inherited)
        real_role = runtime.verify_role

        def changed_context(contract, role, **kwargs):
            real_role(contract, role, **kwargs)
            path = self.root / runtime.CONTEXT
            path.write_bytes(path.read_bytes().replace(b'12345678', b'22345678', 1))

        with patch.object(runtime, 'verify_role', side_effect=changed_context):
            self.refused(environment=environment, unchanged=False)
        os.fstat(inherited)
        self.assert_unlocked()

    def test_replaced_lock_path_refuses_and_closes_the_original_shared_lease(self):
        original_path = self.base / 'replaced-admission-lock'
        real_role = runtime.verify_role

        def replaced(contract, role, **kwargs):
            real_role(contract, role, **kwargs)
            self.lock_path.rename(original_path)
            self.lock_path.write_bytes(b'')
            self.lock_path.chmod(0o644)

        with patch.object(runtime, 'verify_role', side_effect=replaced):
            self.refused(unchanged=False)
        self.assert_unlocked(original_path)
        self.assert_unlocked()

    def test_closed_environment_triplet_invalid_descriptors_and_identity_are_not_retired(self):
        readonly = os.open(self.lock_path, os.O_RDONLY)
        writable = os.open(self.lock_path, os.O_RDWR)
        other_path = self.write('other-file', b'')
        other = os.open(other_path, os.O_RDONLY)
        for fd in (readonly, writable, other):
            self.addCleanup(close_if_open, fd)
        cases = [self.environment(999999), self.environment(writable), self.environment(other),
                 {'INKYOS_WRITER_UNKNOWN': 'refused'},
                 dict(self.environment(readonly), INKYOS_WRITER_UNKNOWN='refused')]
        complete = self.environment(readonly)
        for key in complete:
            incomplete = dict(complete)
            del incomplete[key]
            cases.append(incomplete)
        for key, value in (('INKYOS_WRITER_ROLE', 'ipc'),
                           ('INKYOS_WRITER_CONTEXT_SHA256', '0' * 64),
                           ('INKYOS_WRITER_LEASE_FD', '0'), ('INKYOS_WRITER_LEASE_FD', '2'),
                           ('INKYOS_WRITER_LEASE_FD', '03'), ('INKYOS_WRITER_LEASE_FD', True)):
            wrong = dict(complete)
            wrong[key] = value
            cases.append(wrong)
        for environment in cases:
            with self.subTest(environment=environment):
                self.refused(environment=environment)
                for fd in (readonly, writable, other):
                    os.fstat(fd)
                self.assert_unlocked()

    def test_refused_identity_keeps_valid_inherited_fd_and_environment(self):
        inherited = os.open(self.lock_path, os.O_RDONLY)
        self.addCleanup(close_if_open, inherited)
        environment = self.environment(inherited)
        identity = self.identity('main')
        identity['uids'] = [0, 0, 0]
        self.refused(environment=environment, _identity=identity)
        os.fstat(inherited)
        self.assert_unlocked()

    def test_caller_exception_propagates_and_closes_only_fresh_lease(self):
        with self.admission.writer(self.root, **self.owner) as external:
            with self.assertRaisesRegex(CallerFailure, '^caller-owned error$'):
                with self.guard() as lease:
                    fd = lease.fileno()
                    raise CallerFailure('caller-owned error')
            self.assert_closed(fd)
            os.fstat(external.fileno())
            self.assert_busy()
        self.assert_unlocked()

    def test_setup_baseexceptions_propagate_close_fresh_sh_and_preserve_inherited_fd(self):
        inherited = os.open(self.lock_path, os.O_RDONLY)
        self.addCleanup(close_if_open, inherited)
        for stage in ('context_sha256', 'verify_role'):
            original = getattr(runtime, stage)
            for interruption in (KeyboardInterrupt(), SystemExit(37)):
                with self.subTest(stage=stage, interruption=type(interruption).__name__):
                    environment = self.environment(inherited)
                    expected_environment = dict(environment)
                    real_flock = fcntl.flock

                    def interrupted(*args, **kwargs):
                        original(*args, **kwargs)
                        self.assert_busy()
                        raise interruption

                    with patch.object(runtime, stage, side_effect=interrupted), \
                            patch.object(fcntl, 'flock', wraps=real_flock) as flock:
                        with self.assertRaises(type(interruption)) as caught:
                            with self.guard(environment=environment):
                                self.fail('Interrupted setup yielded')
                        self.assertIs(caught.exception, interruption)
                    descriptors = [call.args[0] for call in flock.call_args_list
                                   if call.args[1] == fcntl.LOCK_SH | fcntl.LOCK_NB]
                    self.assertEqual(len(descriptors), 1)
                    self.assert_closed(descriptors[0])
                    os.fstat(inherited)
                    self.assertEqual(environment, expected_environment)
                    self.assert_unlocked()

    def test_failed_retirement_does_not_remove_environment_or_leak_fresh_sh(self):
        inherited = os.open(self.lock_path, os.O_RDONLY)
        self.addCleanup(close_if_open, inherited)
        environment = self.environment(inherited)
        real_close = os.close

        def failed_close(fd):
            if fd == inherited:
                raise OSError(errno.EIO, 'inert retirement failure')
            return real_close(fd)

        with patch.object(runtime.os, 'close', side_effect=failed_close):
            self.refused(environment=environment)
        os.fstat(inherited)
        self.assert_unlocked()

    def test_inherited_fd_replaced_at_final_context_check_is_not_retired(self):
        other_path = self.write('replacement-file', b'')
        original_context = runtime.context_sha256
        for replacement_path, flags in ((self.lock_path, os.O_RDWR), (other_path, os.O_RDONLY)):
            with self.subTest(path=replacement_path.name, flags=flags):
                inherited = os.open(self.lock_path, os.O_RDONLY)
                replacement = os.open(replacement_path, flags)
                self.addCleanup(close_if_open, inherited)
                self.addCleanup(close_if_open, replacement)
                environment = self.environment(inherited)
                calls = 0

                def replaced_context(contract):
                    nonlocal calls
                    calls += 1
                    digest = original_context(contract)
                    if calls == 3:
                        os.dup2(replacement, inherited)
                    return digest

                with patch.object(runtime, 'context_sha256', side_effect=replaced_context):
                    self.refused(environment=environment)
                self.assertEqual(calls, 3)
                actual, expected = os.fstat(inherited), os.fstat(replacement)
                self.assertEqual((actual.st_dev, actual.st_ino), (expected.st_dev, expected.st_ino))
                self.assertEqual(fcntl.fcntl(inherited, fcntl.F_GETFL) & os.O_ACCMODE, flags)
                self.assert_unlocked()

    def test_root_aliases_noncanonical_and_relative_contract_roots_are_refused(self):
        alias = self.base / 'root-alias'
        alias.symlink_to(self.root, target_is_directory=True)
        for root in (Path('/'), Path('//'), Path('/usr/..'), Path('relative'), alias,
                     self.root / '..' / 'root'):
            with self.subTest(root=root):
                contract = copy.copy(self.value)
                contract._root = root
                with patch.object(runtime, 'import_admission') as imported:
                    self.refused(_contract=contract)
                    imported.assert_not_called()

    def test_production_overrides_and_unknown_roles_have_closed_refusal(self):
        with patch.object(runtime, 'load_contract') as loaded:
            for override in ({'_identity': self.identity('main')}, {'_environ': {}}):
                with self.subTest(override=tuple(override)):
                    with self.assertRaises(runtime.Refused) as caught:
                        with runtime.writer_guard('main', **override):
                            self.fail('Production override yielded')
                    self.assertEqual(caught.exception.reason, 'writer_admission_refused')
            loaded.assert_not_called()
        for role in ('factory', '', True, []):
            with self.subTest(role=role):
                with self.assertRaises(runtime.Refused) as caught:
                    with runtime.writer_guard(role, _contract=self.value,
                            _identity=self.identity('main'), _environ={}):
                        self.fail('Unsupported role yielded')
                self.assertEqual(caught.exception.reason, 'writer_admission_refused')


if __name__ == '__main__':
    unittest.main()
