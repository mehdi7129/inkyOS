"""Standalone launcher protocol tests; only an inert Python child is executed."""
import copy
import errno
import fcntl
import grp
import multiprocessing
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from test_factory_runtime_contract import ContractFixture, load_module, runtime


launcher = load_module('writer_launcher_test', 'scripts/writer-launcher.py')
PROCESSES = multiprocessing.get_context('fork')
DEADLINE = 8
ARGV = {
    'main': ['/usr/lib/inky-studio/server/.venv/bin/python', '-I', '-B', '/usr/lib/inkyos/factory-main.py'],
    'helper': ['/usr/bin/python3', '-I', '-B', '/usr/local/lib/inky-studio/network-helper.py'],
    'ipc': ['/usr/bin/python3', '-I', '-B', '/usr/local/lib/inkyos/initialization-server.py'],
}


class CapturedExec(BaseException):
    pass


def receive(pipe):
    if not pipe.poll(DEADLINE):
        raise AssertionError('Child did not reach the expected pipe stage')
    return pipe.recv()


def child_real_exec(contract, identity, pipe):
    """A real exec proves the live SH lease descriptor survives replacement."""
    try:
        launcher.runtime = runtime
        os.set_inheritable(pipe.fileno(), True)
        script = '\n'.join((
            'import os',
            'from multiprocessing.connection import Connection',
            f'pipe = Connection({pipe.fileno()})',
            'fd = int(os.environ["INKYOS_WRITER_LEASE_FD"])',
            'info = os.fstat(fd)',
            'pipe.send(("exec", os.get_inheritable(fd), info.st_dev, info.st_ino, dict(os.environ)))',
            f'assert pipe.poll({DEADLINE}), "release deadline exceeded"',
            'assert pipe.recv() == "release"',
            'pipe.send(("released",))',
        ))

        def inert_exec(path, argv, environ):
            if argv != ARGV['main'] or path != argv[0]:
                raise AssertionError('Launcher changed the fixed argv')
            os.execve(sys.executable, [sys.executable, '-I', '-B', '-c', script], environ)

        launcher.launch('main', _contract=contract, _identity=identity,
                        _environ={}, _execve=inert_exec)
        raise AssertionError('Real exec returned')
    except BaseException as error:
        pipe.send(('error', type(error).__name__, getattr(error, 'reason', str(error))))
    finally:
        pipe.close()


def child_numeric_main(contract, named, pipe):
    """Linux root only: actual UID/GID 1000, explicit synthetic NSS fixture."""
    try:
        launcher.runtime = runtime
        groups = [grp.struct_group((name, 'x', gid, [])) for name, gid in named.items()]
        os.setgroups(list(named.values()))
        os.setresgid(1000, 1000, 1000)
        os.setresuid(1000, 1000, 1000)

        def get_name(name):
            return next(group for group in groups if group.gr_name == name)

        def get_gid(gid):
            return next(group for group in groups if group.gr_gid == gid)

        def inspect_exec(path, argv, environ):
            fd = int(environ['INKYOS_WRITER_LEASE_FD'])
            pipe.send(('numeric', os.getresuid(), os.getresgid(), sorted(os.getgroups()),
                       os.get_inheritable(fd),
                       os.access(contract._root / 'etc/private-runtime-support', os.R_OK)))
            if receive(pipe) != 'release':
                raise AssertionError('Unexpected release command')
            raise CapturedExec()

        with patch.object(runtime.grp, 'getgrall', return_value=groups), \
                patch.object(runtime.grp, 'getgrnam', side_effect=get_name), \
                patch.object(runtime.grp, 'getgrgid', side_effect=get_gid):
            try:
                launcher.launch('main', _contract=contract, _identity=None,
                                _environ={}, _execve=inspect_exec)
            except CapturedExec:
                pass
        pipe.send(('released',))
    except BaseException as error:
        pipe.send(('error', type(error).__name__, getattr(error, 'reason', str(error))))
    finally:
        pipe.close()


class LauncherTests(ContractFixture):
    def setUp(self):
        super().setUp()
        seam = patch.object(launcher, 'runtime', runtime)
        seam.start()
        self.addCleanup(seam.stop)
        self.contract_value = self.full_candidate()
        self.contract_value, self.admission = self.ready(self.contract_value)

    def invoke(self, role='main', **kwargs):
        options = {'_contract': self.contract_value, '_identity': self.identity(role),
                   '_environ': {}, '_execve': self.capture_exec}
        options.update(kwargs)
        return launcher.launch(role, **options)

    def capture_exec(self, path, argv, environ):
        self.captured = (path, argv, environ)
        fd = int(environ['INKYOS_WRITER_LEASE_FD'])
        self.assertTrue(os.get_inheritable(fd))
        info = os.fstat(fd)
        lock = (self.root / 'run/inkyos-admission/lock').stat()
        self.assertEqual((info.st_dev, info.st_ino), (lock.st_dev, lock.st_ino))
        with self.assertRaises(self.admission.Refused) as caught:
            with self.admission.factory(self.root, **self.owner):
                self.fail('Factory acquired EX while exec held writer SH')
        self.assertEqual(caught.exception.reason, 'busy')
        raise CapturedExec()

    def assert_launcher_refused(self, reason, callback):
        before = self.snapshot()
        with self.assertRaises(launcher.Refused) as caught:
            callback()
        self.assertEqual(caught.exception.reason, reason)
        self.assertEqual(self.snapshot(), before)

    def spawn(self, function, *arguments):
        parent, child = PROCESSES.Pipe()
        process = PROCESSES.Process(target=function, args=(*arguments, child))
        process.start()
        child.close()

        def cleanup():
            parent.close()
            if process.is_alive():
                process.kill()
            process.join(DEADLINE)
            if process.is_alive():
                raise AssertionError('Child remained alive after cleanup deadline')
            process.close()

        self.addCleanup(cleanup)
        return process, parent

    def finish(self, process):
        process.join(DEADLINE)
        self.assertFalse(process.is_alive(), 'Child exceeded exit deadline')
        self.assertEqual(process.exitcode, 0)

    def test_fixed_argv_closed_environment_and_live_lease_for_every_role(self):
        hostile = {'PATH': '/hostile', 'PYTHONPATH': '/untrusted', 'LD_PRELOAD': '/bad.so',
                   'HOME': '/private-home', 'SECRET_PASSWORD': 'never inherit me',
                   'INKYOS_WRITER_LEASE_FD': '99999', 'INKYOS_WRITER_ROLE': 'ipc',
                   'INKYOS_WRITER_CONTEXT_SHA256': '0' * 64,
                   'NOTIFY_SOCKET': '/run/inert-notify'}
        for role in ('main', 'helper', 'ipc'):
            with self.subTest(role=role):
                with self.assertRaises(CapturedExec):
                    self.invoke(role, _environ=hostile)
                path, argv, environ = self.captured
                self.assertEqual((path, argv), (ARGV[role][0], ARGV[role]))
                expected = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
                            'INKYOS_WRITER_ROLE': role,
                            'INKYOS_WRITER_CONTEXT_SHA256': self.contract_value.context_sha256,
                            'INKYOS_WRITER_LEASE_FD': environ['INKYOS_WRITER_LEASE_FD']}
                if role in ('main', 'helper'):
                    expected.update(INKY_STUDIO_FACTORY_REQUIRED='1',
                                    INKY_STUDIO_DATA_DIR='/var/lib/inky-studio')
                if role == 'main':
                    expected.update(INKY_STUDIO_DISPLAY_MODE='hardware', INKY_STUDIO_BLUETOOTH='1')
                if role == 'ipc':
                    expected['NOTIFY_SOCKET'] = '/run/inert-notify'
                self.assertEqual(environ, expected)
                with self.assertRaises(OSError) as caught:
                    os.fstat(int(environ['INKYOS_WRITER_LEASE_FD']))
                self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_notify_socket_is_ipc_only_and_validated(self):
        for value in ('/run/notify', '@abstract-notify'):
            with self.subTest(value=value):
                with self.assertRaises(CapturedExec):
                    self.invoke('ipc', _environ={'NOTIFY_SOCKET': value})
                self.assertEqual(self.captured[2]['NOTIFY_SOCKET'], value)
        for value in ('', '@', 'relative', '/bad\npath', '/bad\x00path', '/' + 'x' * 107):
            with self.subTest(value=value):
                with patch.object(self, 'capture_exec') as execute:
                    self.assert_launcher_refused('invalid_environment',
                        lambda: self.invoke('ipc', _environ={'NOTIFY_SOCKET': value}))
                    execute.assert_not_called()
        with self.assertRaises(CapturedExec):
            self.invoke('main', _environ={'NOTIFY_SOCKET': '\x00'})
        self.assertNotIn('NOTIFY_SOCKET', self.captured[2])

    def test_launcher_requires_ready_before_role_verification_or_exec(self):
        (self.root / 'run/inkyos-admission/Ready').unlink()
        with patch.object(runtime, 'verify_role') as checked, \
                patch.object(self, 'capture_exec') as execute:
            self.assert_launcher_refused('not_ready', self.invoke)
            checked.assert_not_called()
            execute.assert_not_called()

    def test_inherited_ex_descriptor_is_never_converted_to_writer_sh(self):
        for name in ('Ready', 'attempted'):
            (self.root / 'run/inkyos-admission' / name).unlink()
        with self.admission.factory(self.root, **self.owner) as factory:
            fd = factory.fileno()
            with patch.object(self, 'capture_exec') as execute:
                self.assert_launcher_refused('busy', lambda: self.invoke(
                    _environ={'INKYOS_WRITER_LEASE_FD': str(fd)}))
                execute.assert_not_called()
            separate = os.open(self.root / 'run/inkyos-admission/lock', os.O_RDONLY)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(separate, fcntl.LOCK_SH | fcntl.LOCK_NB)
            finally:
                os.close(separate)
            factory.publish_ready()

    def test_context_is_rechecked_after_role_and_before_exec(self):
        original = runtime.verify_role
        context = self.root / runtime.CONTEXT

        def swap_context(contract, role, **kwargs):
            original(contract, role, **kwargs)
            context.write_bytes(context.read_bytes().replace(b'12345678', b'22345678', 1))

        with patch.object(runtime, 'verify_role', side_effect=swap_context), \
                patch.object(self, 'capture_exec') as execute:
            with self.assertRaises(launcher.Refused) as caught:
                self.invoke()
            self.assertEqual(caught.exception.reason, 'invalid_context')
            execute.assert_not_called()

    def test_wrong_identity_refused_before_exec(self):
        identity = copy.deepcopy(self.identity('main'))
        identity['groups'].append(0)
        with patch.object(self, 'capture_exec') as execute:
            self.assert_launcher_refused('wrong_identity', lambda: self.invoke(_identity=identity))
            execute.assert_not_called()

    def test_exec_error_releases_writer_lease(self):
        def fail_exec(*_):
            raise OSError(errno.ENOENT, 'inert injected exec failure')

        self.assert_launcher_refused('exec_failed', lambda: self.invoke(_execve=fail_exec))
        with self.assertRaises(self.admission.Refused) as caught:
            with self.admission.factory(self.root, **self.owner):
                self.fail('Ready factory was rerun')
        self.assertEqual(caught.exception.reason, 'already_ready')

    def test_returning_exec_seam_is_refused_and_fd_is_closed(self):
        captured = []

        def returns(path, argv, environ):
            fd = int(environ['INKYOS_WRITER_LEASE_FD'])
            self.assertTrue(os.get_inheritable(fd))
            captured.append(fd)

        self.assert_launcher_refused('exec_returned', lambda: self.invoke(_execve=returns))
        self.assertEqual(len(captured), 1)
        with self.assertRaises(OSError) as caught:
            os.fstat(captured[0])
        self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_production_root_forbids_all_test_overrides(self):
        with patch.object(launcher, 'installed_runtime') as installed:
            for options in ({'_identity': self.identity('main')}, {'_environ': {}},
                            {'_execve': self.capture_exec}):
                with self.subTest(options=tuple(options)):
                    self.assert_launcher_refused('invalid_override',
                        lambda: launcher.launch('main', **options))
            production = copy.copy(self.contract_value)
            production._root = Path('/')
            self.assert_launcher_refused('invalid_override',
                lambda: launcher.launch('main', _contract=production))
            installed.assert_not_called()

    def test_uninstalled_launcher_refuses_without_loading_from_repository(self):
        with patch.object(launcher, 'bootstrap_read') as read:
            self.assert_launcher_refused('not_installed', lambda: launcher.launch('main'))
            read.assert_not_called()

    def test_unsupported_role_refuses_before_read_or_execution(self):
        with patch.object(runtime, 'import_admission') as imported:
            self.assert_launcher_refused('unsupported_role',
                lambda: launcher.launch('factory', _contract=self.contract_value))
            imported.assert_not_called()

    def test_real_exec_keeps_shared_lock_until_inert_child_exits(self):
        process, pipe = self.spawn(child_real_exec, self.contract_value, self.identity('main'))
        result = receive(pipe)
        self.assertEqual(result[:2], ('exec', True), result)
        lock = (self.root / 'run/inkyos-admission/lock').stat()
        self.assertEqual(result[2:4], (lock.st_dev, lock.st_ino))
        self.assertEqual(result[4]['INKYOS_WRITER_ROLE'], 'main')
        self.assertNotIn('SECRET_PASSWORD', result[4])
        with self.assertRaises(self.admission.Refused) as caught:
            with self.admission.factory(self.root, **self.owner):
                self.fail('Factory acquired EX while inert exec child held SH')
        self.assertEqual(caught.exception.reason, 'busy')
        pipe.send('release')
        self.assertEqual(receive(pipe), ('released',))
        self.finish(process)
        with self.assertRaises(self.admission.Refused) as caught:
            with self.admission.factory(self.root, **self.owner):
                self.fail('Completed factory was rerun')
        self.assertEqual(caught.exception.reason, 'already_ready')

    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                         'requires Linux root for real numeric UID/GID 1000')
    def test_real_numeric_main_reads_public_role_without_private_support(self):
        self.base.chmod(0o755)
        process, pipe = self.spawn(child_numeric_main, self.contract_value,
                                   self.identity('main')['named_groups'])
        result = receive(pipe)
        self.assertEqual(result, ('numeric', (1000, 1000, 1000), (1000, 1000, 1000),
                                  [101, 102, 103, 992], True, False))
        with self.assertRaises(self.admission.Refused) as caught:
            with self.admission.factory(self.root, **self.owner):
                self.fail('Numeric main released its live SH lease')
        self.assertEqual(caught.exception.reason, 'busy')
        pipe.send('release')
        self.assertEqual(receive(pipe), ('released',))
        self.finish(process)


if __name__ == '__main__':
    unittest.main()
