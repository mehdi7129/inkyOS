"""Real cooperative flock tests with explicitly simulated contract validation.

FakeRuntime does not qualify installed files, identities or boot state. The
admission module, lease descriptors, fork inheritance and process waits are real.
All children are inert and coordinated by pipes with an external test deadline.
"""
import contextlib
import errno
import fcntl
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import signal
import socket
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


server = load('initialization_writer_guard_test', 'scripts/initialization-server.py')
admission = load('initialization_writer_admission_test', 'staging/bootstrap/writer-admission.py')
shared = load('initialization_writer_shared_test', 'scripts/factory-runtime-contract.py')
PROCESSES = multiprocessing.get_context('fork')
DEADLINE = 8
DIGEST = 'a' * 64
REQUEST = {'v': 1, 'id': '11111111-1111-4111-8111-111111111111', 'op': 'initialization.inspect'}


class FakeRuntime:
    """Explicit fixture: only admission uses production verification here."""
    def __init__(self):
        self.events = []

    def import_admission(self, contract):
        self.events.append('import-admission')
        return admission

    def context_sha256(self, contract):
        self.events.append('context')
        return DIGEST

    def verify_role(self, contract, role, *, _identity=None):
        if role != 'ipc':
            raise AssertionError('Wrong fixture role')
        self.events.append('verify-ipc-fixture')

    @contextlib.contextmanager
    def writer_guard(self, role, *, _contract=None, _environ=None):
        # Exercise the common guard and real admission. Only contract/context/
        # role validation stays explicitly simulated in these lifecycle tests.
        with patch.object(shared, 'import_admission', side_effect=self.import_admission), \
                patch.object(shared, 'context_sha256', side_effect=self.context_sha256), \
                patch.object(shared, 'verify_role', side_effect=self.verify_role):
            with shared.writer_guard(role, _contract=_contract, _environ=_environ) as lease:
                yield lease


def receive(pipe):
    if not pipe.poll(DEADLINE):
        raise AssertionError('Child did not reach its pipe checkpoint')
    return pipe.recv()


def close_if_open(fd):
    try:
        os.close(fd)
    except OSError as error:
        if error.errno != errno.EBADF:
            raise


def lock_server(root):
    fd = os.open(root / 'server.lock', os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd


def process_retained_descriptor(fd, pipe):
    try:
        os.fstat(fd)
        pipe.send(('inherited-fd',))
        if receive(pipe) != 'release':
            raise AssertionError('Unexpected release command')
    except BaseException as error:
        pipe.send(('error', type(error).__name__, str(error)))
    finally:
        pipe.close()


def process_ambiguous_drain(contract, already_uncertain, pipe):
    """Wait observations are synthetic; both retained flock leases are real."""
    server_fd = None
    try:
        with server.writer_guard(_runtime=FakeRuntime(), _contract=contract, _environ={}):
            server_fd = lock_server(contract._root)
            worker = server.Worker(object())
            worker.pid = 123456789
            worker.uncertain = already_uncertain
            kills = []
            observations = 0
            blocking_observations = 0

            def observed(pid, flags):
                nonlocal observations, blocking_observations
                if flags == os.WNOHANG:
                    observations += 1
                    if not already_uncertain and observations == 1:
                        return 0, 0
                    raise ChildProcessError(errno.ECHILD, 'synthetic ambiguous observation')
                blocking_observations += 1
                if blocking_observations == 1:
                    return pid + 1, 0  # A different PID is not our child reaped.
                if blocking_observations == 2:
                    return pid, 0x7f  # A stopped child is not terminal.
                pipe.send(('ambiguous', len(kills), worker.pid, flags))
                if receive(pipe) != 'terminal':
                    raise AssertionError('Unexpected terminal observation command')
                return pid, 0

            with patch.object(server.os, 'kill', side_effect=lambda *args: kills.append(args)), \
                    patch.object(server.os, 'waitpid', side_effect=observed):
                worker.stop()
                worker.drain()
            close_if_open(server_fd)
            server_fd = None
        pipe.send(('drained', len(kills), worker.pid))
    except BaseException as error:
        pipe.send(('error', type(error).__name__, str(error)))
    finally:
        if server_fd is not None:
            close_if_open(server_fd)
        pipe.close()


def process_delayed_reap(contract, pipe):
    """A real child stays alive while the test suppresses the first kill request."""
    server_fd = None
    child_pid = None
    try:
        with server.writer_guard(_runtime=FakeRuntime(), _contract=contract, _environ={}):
            server_fd = lock_server(contract._root)
            child_pid = os.fork()
            if child_pid == 0:
                try:
                    pipe.send(('child-running', os.getpid()))
                    if receive(pipe) != 'exit-child':
                        os._exit(2)
                    os._exit(0)
                except BaseException:
                    os._exit(2)
            worker = server.Worker(object())
            worker.pid = child_pid
            calls = []

            def record_kill(pid, signum):
                calls.append((pid, signum))
                pipe.send(('kill-requested', pid, signum))

            with patch.object(server.os, 'kill', side_effect=record_kill):
                worker.drain()
            child_pid = None
            close_if_open(server_fd)
            server_fd = None
        pipe.send(('drained', len(calls), worker.pid))
    except BaseException as error:
        pipe.send(('error', type(error).__name__, str(error)))
    finally:
        if child_pid is not None:
            try:
                os.kill(child_pid, signal.SIGKILL)
                os.waitpid(child_pid, 0)
            except OSError:
                pass
        if server_fd is not None:
            close_if_open(server_fd)
        pipe.close()


def process_parent_with_worker(contract, pipe):
    """Parent will be killed; its real Worker child retains both inherited locks."""
    try:
        with server.writer_guard(_runtime=FakeRuntime(), _contract=contract, _environ={}):
            server_fd = lock_server(contract._root)
            directory = os.open(contract._root, os.O_RDONLY | os.O_DIRECTORY)
            listener_read, listener_write = os.pipe()
            connection, peer = socket.socketpair()

            def inspect(_):
                pipe.send(('worker-running', os.getpid()))
                if receive(pipe) != 'exit-child':
                    os._exit(2)
                # The parent has died. Avoid a response to its now-closed pipe.
                os._exit(0)

            receipt = types.SimpleNamespace(inspect=inspect, IntentConflict=RuntimeError)
            worker = server.Worker(receipt, close_fds=(listener_read, directory))
            worker.run(connection, REQUEST, time.monotonic() + DEADLINE)
            worker.drain()
            for fd in (server_fd, directory, listener_read, listener_write):
                close_if_open(fd)
            connection.close()
            peer.close()
    except BaseException as error:
        pipe.send(('error', type(error).__name__, str(error)))
    finally:
        pipe.close()


class GuardFixture(unittest.TestCase):
    def setUp(self):
        if sys.platform != 'linux':
            seam = patch.object(os, 'listxattr', create=True, return_value=[])
            seam.start()
            self.addCleanup(seam.stop)
        temporary = tempfile.TemporaryDirectory(
            prefix='inkyos-ipc-writer-', dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o755)
        (self.root / 'run').mkdir(mode=0o755)
        (self.root / 'run').chmod(0o755)
        (self.root / 'server.lock').write_bytes(b'')
        (self.root / 'server.lock').chmod(0o600)
        self.owner = {'_owner_uid': os.geteuid(), '_owner_gid': os.getegid()}
        self.contract = shared.Contract({}, 'fixture-only', self.root, os.geteuid(), os.getegid(), None, None)
        self.runtime = FakeRuntime()
        admission.prepare(self.root, **self.owner)
        with admission.factory(self.root, **self.owner) as lease:
            lease.publish_ready()

    def guard(self, environment=None, **overrides):
        options = {'_runtime': self.runtime, '_contract': self.contract,
                   '_environ': {} if environment is None else environment}
        options.update(overrides)
        return server.writer_guard(**options)

    def environment(self, fd):
        return {'INKYOS_WRITER_LEASE_FD': str(fd), 'INKYOS_WRITER_ROLE': 'ipc',
                'INKYOS_WRITER_CONTEXT_SHA256': DIGEST}

    def assert_busy(self, path=None):
        path = self.root / admission.DIRECTORY / 'lock' if path is None else path
        fd = os.open(path, os.O_RDONLY)
        try:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)

    def assert_unlocked(self, path=None):
        path = self.root / admission.DIRECTORY / 'lock' if path is None else path
        fd = os.open(path, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)

    def refused(self, environment=None, **overrides):
        with self.assertRaisesRegex(server.WriterRefused, '^writer_admission_refused$'):
            with self.guard(environment, **overrides):
                self.fail('Refused guard yielded a lease')

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
                raise AssertionError('Inert process exceeded cleanup deadline')
            process.close()

        self.addCleanup(cleanup)
        return process, parent

    def finish(self, process, code=0):
        process.join(DEADLINE)
        self.assertFalse(process.is_alive(), 'Inert process exceeded test deadline')
        self.assertEqual(process.exitcode, code)


class WriterGuardTests(GuardFixture):
    def test_fresh_shared_lease_is_taken_without_inherited_environment(self):
        with self.guard() as lease:
            self.assert_busy()
            self.assertFalse(os.get_inheritable(lease.fileno()))
            self.assertIn('verify-ipc-fixture', self.runtime.events)
        self.assert_unlocked()

    def test_valid_inherited_fd_is_retired_after_independent_sh_without_unlocking_dup(self):
        with admission.writer(self.root, **self.owner) as original:
            inherited = os.dup(original.fileno())
            retained = os.dup(inherited)
            self.addCleanup(close_if_open, retained)
            environment = self.environment(inherited)
            environment['UNRELATED'] = 'preserved'
            real_flock = fcntl.flock
            with patch.object(server.fcntl, 'flock', wraps=real_flock) as called:
                with self.guard(environment) as fresh:
                    self.assertNotEqual(fresh.fileno(), original.fileno())
                    with self.assertRaises(OSError) as caught:
                        os.fstat(inherited)
                    self.assertEqual(caught.exception.errno, errno.EBADF)
                    self.assertEqual(environment, {'UNRELATED': 'preserved'})
                self.assertFalse(any(call.args[1] & fcntl.LOCK_UN for call in called.call_args_list))
        self.assert_busy()  # retained duplicate still shares the inherited OFD.
        os.close(retained)
        self.assert_unlocked()

    def test_invalid_triplets_refuse_without_retiring_any_descriptor(self):
        lock = self.root / admission.DIRECTORY / 'lock'
        readonly = os.open(lock, os.O_RDONLY)
        writable = os.open(lock, os.O_RDWR)
        different = os.open(self.root / 'server.lock', os.O_RDONLY)
        self.addCleanup(close_if_open, readonly)
        self.addCleanup(close_if_open, writable)
        self.addCleanup(close_if_open, different)
        cases = [self.environment(999999), self.environment(writable), self.environment(different)]
        cases.append(dict(self.environment(readonly), INKYOS_WRITER_UNKNOWN='refused'))
        cases.append({'INKYOS_WRITER_UNKNOWN': 'refused'})
        for key in shared.WRITER_ENV:
            partial = self.environment(readonly)
            del partial[key]
            cases.append(partial)
        for key, value in (('INKYOS_WRITER_ROLE', 'main'),
                           ('INKYOS_WRITER_CONTEXT_SHA256', 'b' * 64),
                           ('INKYOS_WRITER_LEASE_FD', '0'),
                           ('INKYOS_WRITER_LEASE_FD', '01'),
                           ('INKYOS_WRITER_LEASE_FD', True)):
            bad = self.environment(readonly)
            bad[key] = value
            cases.append(bad)
        for environment in cases:
            with self.subTest(environment=environment):
                before = dict(environment)
                self.refused(environment)
                self.assertEqual(environment, before)
                for fd in (readonly, writable, different):
                    os.fstat(fd)
                self.assert_unlocked()

    def test_retiring_inherited_descriptor_does_not_unlock_its_forked_copy(self):
        with admission.writer(self.root, **self.owner) as original:
            inherited = os.dup(original.fileno())
            process, pipe = self.spawn(process_retained_descriptor, inherited)
            self.assertEqual(receive(pipe), ('inherited-fd',))
            with self.guard(self.environment(inherited)):
                self.assert_busy()
        self.assert_busy()
        pipe.send('release')
        self.finish(process)
        self.assert_unlocked()

    def test_exclusive_inherited_fd_is_never_downgraded(self):
        for name in ('Ready', 'attempted'):
            (self.root / admission.DIRECTORY / name).unlink()
        with admission.factory(self.root, **self.owner) as exclusive:
            environment = self.environment(exclusive.fileno())
            self.refused(environment)
            self.assertEqual(environment, self.environment(exclusive.fileno()))
            fd = os.open(self.root / admission.DIRECTORY / 'lock', os.O_RDONLY)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            finally:
                os.close(fd)
            exclusive.publish_ready()

    def test_missing_ready_and_context_swap_refuse_and_release_fresh_lease(self):
        (self.root / admission.DIRECTORY / 'Ready').unlink()
        self.refused()
        self.assert_unlocked()
        (self.root / admission.DIRECTORY / 'Ready').write_bytes(admission.READY)
        (self.root / admission.DIRECTORY / 'Ready').chmod(0o644)
        with patch.object(self.runtime, 'context_sha256', side_effect=[DIGEST, 'b' * 64]):
            self.refused()
        self.assert_unlocked()

    def test_real_root_and_production_overrides_are_forbidden(self):
        with patch.object(server, 'load_runtime') as loaded:
            for root in (Path('/'), Path('//'), Path('/usr/..')):
                self.refused(_contract=types.SimpleNamespace(_root=root, _uid=0, _gid=0))
            with self.assertRaises(server.WriterRefused):
                with server.writer_guard(_runtime=self.runtime):
                    self.fail('Production override accepted')
            loaded.assert_not_called()

    def test_main_without_installed_guard_refuses_before_receipt_listener_or_notify(self):
        with patch.object(server.sys, 'platform', 'linux'), patch.object(server.os, 'geteuid', return_value=0), \
                patch.object(server, 'load_receipt') as receipt, patch.object(server, 'listen') as listen, \
                patch.object(server, 'notify_ready') as notify:
            self.assertEqual(server.main([]), 78)
            receipt.assert_not_called()
            listen.assert_not_called()
            notify.assert_not_called()


class DrainTests(GuardFixture):
    def test_ambiguous_reap_retains_both_locks_and_never_repeats_kill(self):
        for already_uncertain in (False, True):
            with self.subTest(already_uncertain=already_uncertain):
                process, pipe = self.spawn(process_ambiguous_drain, self.contract, already_uncertain)
                expected_kills = 0 if already_uncertain else 1
                self.assertEqual(receive(pipe), ('ambiguous', expected_kills, 123456789, 0))
                self.assert_busy()
                self.assert_busy(self.root / 'server.lock')
                pipe.send('terminal')
                self.assertEqual(receive(pipe), ('drained', expected_kills, None))
                self.finish(process)
                self.assert_unlocked()
                self.assert_unlocked(self.root / 'server.lock')

    def test_real_waitpid_holds_locks_until_delayed_child_is_reaped(self):
        process, pipe = self.spawn(process_delayed_reap, self.contract)
        messages = [receive(pipe), receive(pipe)]
        self.assertEqual({item[0] for item in messages}, {'child-running', 'kill-requested'}, messages)
        child = next(item[1] for item in messages if item[0] == 'child-running')
        self.assertIn(('kill-requested', child, signal.SIGKILL), messages)
        self.assert_busy()
        self.assert_busy(self.root / 'server.lock')
        pipe.send('exit-child')
        self.assertEqual(receive(pipe), ('drained', 1, None))
        self.finish(process)
        self.assert_unlocked()
        self.assert_unlocked(self.root / 'server.lock')

    def test_worker_child_keeps_both_locks_after_parent_death(self):
        process, pipe = self.spawn(process_parent_with_worker, self.contract)
        started = receive(pipe)
        self.assertEqual(started[0], 'worker-running', started)
        process.kill()
        # The forked worker also inherits multiprocessing's sentinel writer.
        # Poll the owned parent's waitpid status, not that still-live sentinel.
        deadline = time.monotonic() + DEADLINE
        while process.exitcode is None:
            if time.monotonic() >= deadline:
                self.fail('Killed inert parent was not observed terminating')
            time.sleep(0.01)
        self.assertEqual(process.exitcode, -signal.SIGKILL)
        self.assert_busy()
        self.assert_busy(self.root / 'server.lock')
        pipe.send('exit-child')
        deadline = time.monotonic() + DEADLINE
        while True:
            try:
                self.assert_unlocked()
                self.assert_unlocked(self.root / 'server.lock')
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    self.fail('Orphan inert worker did not release its inherited locks')
                time.sleep(0.01)
        self.finish(process, -signal.SIGKILL)

    def test_main_drains_before_lock_release_even_if_listener_close_fails(self):
        real_guard = server.writer_guard
        events = []
        listener_fd, pipe_write = os.pipe()
        self.addCleanup(close_if_open, pipe_write)
        self.addCleanup(close_if_open, listener_fd)
        lock = lock_server(self.root)
        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(close_if_open, lock)
        self.addCleanup(close_if_open, directory)

        class Listener:
            def fileno(self):
                return listener_fd

            def close(self):
                events.append('listener-close')
                os.close(listener_fd)
                raise OSError('synthetic listener cleanup failure')

        fixture = self

        class Worker:
            def __init__(self, receipt, close_fds=(), *, stopping=None):
                fixture.assertEqual(close_fds, (listener_fd, directory))
                fixture.assertNotIn(lock, close_fds)

            def reap(self):
                raise OSError('synthetic request pipe cleanup failure')

            def drain(self):
                events.append('drain')
                fixture.assert_busy()
                fixture.assert_busy(fixture.root / 'server.lock')
                os.fstat(lock)
                os.fstat(directory)

        with patch.object(server.sys, 'platform', 'linux'), patch.object(server.os, 'geteuid', return_value=0), \
                patch.object(server, 'writer_guard', side_effect=lambda: real_guard(
                    _runtime=self.runtime, _contract=self.contract, _environ={})), \
                patch.object(server, 'load_receipt', return_value=object()), \
                patch.object(server, 'listen', return_value=(Listener(), lock, directory)), \
                patch.object(server, 'Worker', Worker), patch.object(server, 'notify_ready'):
            self.assertEqual(server.main([]), 1)
        self.assertEqual(events, ['listener-close', 'drain'])
        self.assert_unlocked()
        self.assert_unlocked(self.root / 'server.lock')


class StopFlagTests(unittest.TestCase):
    def test_requested_flag_prevents_pipe_fork_and_invoke(self):
        stopping = server.StopFlag()
        stopping.request(signal.SIGTERM, None)
        self.assertTrue(stopping())
        worker = server.Worker(object(), stopping=stopping)
        with patch.object(server.os, 'pipe') as pipes, patch.object(server.os, 'fork') as fork, \
                patch.object(server, 'invoke') as invoke:
            result = worker.run(Mock(), REQUEST, time.monotonic() + 1)
            self.assertEqual(result['error'], 'unavailable')
            pipes.assert_not_called()
            fork.assert_not_called()
            invoke.assert_not_called()

    def test_flag_between_pipe_and_fork_closes_pipe_without_fork(self):
        stopping = server.StopFlag()
        worker = server.Worker(object(), stopping=stopping)
        real_pipe = os.pipe
        descriptors = []

        def interrupted_pipe():
            descriptors.extend(real_pipe())
            stopping.request()
            return tuple(descriptors)

        with patch.object(server.os, 'pipe', side_effect=interrupted_pipe), \
                patch.object(server.os, 'fork') as fork:
            self.assertEqual(worker.run(Mock(), REQUEST, time.monotonic() + 1)['error'], 'unavailable')
            fork.assert_not_called()
        for fd in descriptors:
            with self.assertRaises(OSError) as caught:
                os.fstat(fd)
            self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_child_checks_stopping_before_receipt_invocation(self):
        original_pid = os.getpid()
        worker = server.Worker(object(), stopping=lambda: os.getpid() != original_pid)
        marker_read, marker_write = os.pipe()
        self.addCleanup(close_if_open, marker_read)
        self.addCleanup(close_if_open, marker_write)
        os.set_blocking(marker_read, False)
        connection, client = socket.socketpair()
        self.addCleanup(connection.close)
        self.addCleanup(client.close)

        def invoked(*_):
            os.write(marker_write, b'UNEXPECTED_INVOKE')
            return {'ok': True}

        with patch.object(server, 'invoke', side_effect=invoked):
            result = worker.run(connection, REQUEST, time.monotonic() + 1)
        worker.drain()
        self.assertEqual(result['error'], 'unavailable')
        with self.assertRaises(BlockingIOError):
            os.read(marker_read, 128)

    def test_signal_after_request_read_refuses_without_worker_run(self):
        stopping = server.StopFlag()
        worker = Mock(stopping=stopping)
        connection, client = socket.socketpair()
        self.addCleanup(client.close)

        def read(*_):
            stopping.request(signal.SIGINT, None)
            return REQUEST

        with patch.object(server, 'read_request', side_effect=read):
            server.handle_connection(connection, worker, _peer_uid=lambda _: 1000)
        client.settimeout(1)
        raw = client.recv(2048)
        self.assertEqual(json.loads(raw)['error'], 'unavailable')
        worker.run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
