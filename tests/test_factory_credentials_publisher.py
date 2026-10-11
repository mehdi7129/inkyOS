"""Synthetic roots and inert producers only; never the Studio serializer."""
import contextlib
import importlib.util
import io
import json
import multiprocessing
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch


SOURCE = Path(__file__).parents[1] / 'scripts/factory-credentials-publisher.py'
SPEC = importlib.util.spec_from_file_location('factory_publisher_fixture', SOURCE)
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)
CANARY = 'PRIVATE_OUTPUT_MUST_NOT_ESCAPE'
RAW = b'opaque bytes, deliberately not JSON\n'


class InertProducer:
    """Verify production spawn arguments, then substitute trusted fixture code."""
    def __init__(self, code, cwd):
        self.code, self.cwd = code, cwd
        self.calls, self.processes = [], []

    def __call__(self, argv, **options):
        self.calls.append((argv, options.copy()))
        assert argv == publisher.ARGV
        assert options['user'] == options['group'] == 1000
        assert options['extra_groups'] == []
        assert options['cwd'] == publisher.CWD and options['env'] == publisher.ENV
        assert options['shell'] is False and options['close_fds'] is True
        assert options['start_new_session'] is True and options['umask'] == 0o077
        assert options['stdin'] == subprocess.DEVNULL
        assert options['stdout'] == subprocess.PIPE and options['stderr'] == subprocess.DEVNULL
        assert options['text'] is False and options['bufsize'] == 0
        assert 'preexec_fn' not in options and 'pass_fds' not in options
        for name in ('user', 'group', 'extra_groups'):
            del options[name]
        options['cwd'] = str(self.cwd)
        process = subprocess.Popen([sys.executable, '-I', '-B', '-c', self.code], **options)
        self.processes.append(process)
        return process


def crash_publish(options, stage, cwd):
    def checkpoint(current):
        if current == stage:
            os._exit(71)
    producer = InertProducer('import os; os.write(1, ' + repr(RAW) + ')', cwd)
    publisher.publish(**options, _spawn=producer, _checkpoint=checkpoint)
    os._exit(0)


class PublisherTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='.inkyos-publisher-', dir=Path.home().resolve())
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / 'root'
        self.root.mkdir(mode=0o700)
        for name in ('var', 'var/lib', 'var/lib/inky-studio'):
            (self.root / name).mkdir(mode=0o700)
        self.data = self.root / publisher.DATA
        self.target = self.data / publisher.NAME
        self.options = {'_root': self.root, '_app_uid': os.geteuid(), '_app_gid': os.getegid()}

    def producer(self, raw=RAW, exit_code=0, extra=''):
        code = 'import os; os.write(1, ' + repr(raw) + '); '
        if extra:
            code += extra + '; '
        return InertProducer(code + 'os._exit(' + str(exit_code) + ')', self.base)

    def publish(self, producer=None, **options):
        return publisher.publish(**{**self.options, '_spawn': producer or self.producer(), **options})

    def assert_refused(self, code, producer=None, **options):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with self.assertRaises(publisher.PublisherError) as raised:
                self.publish(producer, **options)
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(str(raised.exception), code)
        self.assertNotIn(CANARY, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertEqual((out.getvalue(), err.getvalue()), ('', ''))
        return raised.exception

    def test_exact_opaque_bytes_private_metadata_and_order(self):
        producer = self.producer()
        stages = []
        original = publisher.os.fsync
        def fsync(fd):
            stages.append('fsync_directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'fsync_file')
            return original(fd)
        def checkpoint(stage):
            stages.append(stage)
            if stage == 'producer_finished':
                self.assertFalse(self.target.exists())
                self.assertEqual(producer.processes[0].returncode, 0)
                self.assertTrue(producer.processes[0].stdout.closed)
        with patch.object(publisher.os, 'fsync', fsync):
            self.assertEqual(self.publish(producer, _checkpoint=checkpoint), {'status': 'published'})
        self.assertEqual(stages, ['data_checked', 'producer_finished', 'file_created', 'file_written',
                                 'fsync_file', 'file_synced', 'fsync_directory', 'directory_synced', 'published'])
        self.assertEqual(self.target.read_bytes(), RAW)
        info = self.target.lstat()
        self.assertEqual((stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid, info.st_nlink),
                         (0o600, os.geteuid(), os.getegid(), 1))
        self.assertEqual(len(producer.calls), 1)

    def test_exact_arguments_and_environment_exclude_inherited_values(self):
        producer = self.producer()
        with patch.dict(os.environ, {'PYTHONPATH': CANARY, 'LD_PRELOAD': CANARY,
                                     'INKY_STUDIO_PASSWORD': CANARY}):
            self.publish(producer)
        argv, options = producer.calls[0]
        self.assertEqual(argv, ('/usr/lib/inkyos/factory-exporter/venv/bin/python', '-I', '-B', '-m',
                               'inky_web.provisioning.factory_credentials', '--emit-v2'))
        lock = json.loads((SOURCE.parents[1] / 'config/factory-exporter.lock.json').read_bytes())
        self.assertEqual(lock['contract'], 'factory-exporter-v2')
        self.assertEqual(argv, tuple(lock['argv']))
        self.assertEqual(options['cwd'], '/')
        self.assertFalse(any(CANARY in value for value in options['env'].values()))

    def test_transport_limit_includes_lf(self):
        raw = b'x' * 8191 + b'\n'
        self.publish(self.producer(raw))
        self.assertEqual(self.target.read_bytes(), raw)

    def test_overflow_refused_without_publication(self):
        self.assert_refused('producer_output_invalid', self.producer(b'x' * 8192 + b'\n'))
        self.assertFalse(self.target.exists())

    def test_ascii_single_lf_and_nonempty_framing(self):
        for raw in (b'', b'\n', b'opaque', b'a\nb\n', b'a\n\n', b'\xff\n'):
            with self.subTest(raw=raw):
                self.assert_refused('producer_output_invalid', self.producer(raw))
                self.assertFalse(self.target.exists())

    def test_nonzero_codes_and_signals_never_publish(self):
        for code in (64, 70, 1, 99):
            with self.subTest(code=code):
                self.assert_refused('producer_failed', self.producer(RAW, code))
        producer = InertProducer('import os, signal; os.kill(os.getpid(), signal.SIGKILL)', self.base)
        self.assert_refused('producer_failed', producer)
        self.assertFalse(self.target.exists())

    def test_stderr_and_spawn_exception_canaries_not_reflected(self):
        producer = InertProducer('import os; os.write(2, ' + repr(CANARY.encode()) + '); os._exit(70)', self.base)
        self.assert_refused('producer_failed', producer)
        self.assert_refused('producer_failed', Mock(side_effect=OSError(CANARY)))

    def test_complete_line_waits_for_eof_and_exit(self):
        producer = InertProducer('import os,time; os.write(1, ' + repr(RAW)
                                 + '); os.close(1); time.sleep(0.15)', self.base)
        start = time.monotonic()
        self.publish(producer, _timeout=2)
        self.assertGreaterEqual(time.monotonic() - start, 0.15)

    def test_partial_output_stall_is_killed_reaped_and_never_published(self):
        producer = InertProducer('import os,time; os.write(1,b"partial"); time.sleep(10)', self.base)
        start = time.monotonic()
        self.assert_refused('producer_timeout', producer, _timeout=0.4)
        self.assertLess(time.monotonic() - start, 2)
        self.assertIsNotNone(producer.processes[0].returncode)
        self.assertTrue(producer.processes[0].stdout.closed)
        self.assertFalse(self.target.exists())

    @unittest.skipUnless(hasattr(os, 'fork'), 'requires POSIX fork')
    def test_descendant_holding_stdout_does_not_turn_leader_exit_into_success(self):
        # Deliberately violates the pure serializer contract. The inert child
        # exits by itself shortly afterwards; this test claims no confinement.
        code = 'import os,time\nif os.fork()==0:\n time.sleep(0.7)\nelse:\n os.write(1,' + repr(RAW) + ')\n os._exit(0)\n'
        producer = InertProducer(code, self.base)
        self.assert_refused('producer_timeout', producer, _timeout=0.4)
        self.assertFalse(self.target.exists())

    def test_unreaped_child_is_explicit_failure(self):
        producer = self.producer(b'bad')
        with patch.object(publisher, '_stop', return_value=False):
            self.assert_refused('producer_unreaped', producer)
        self.assertFalse(self.target.exists())

    def test_existing_data_never_runs_producer_or_replaces(self):
        for name in (publisher.NAME, 'other-data'):
            path = self.data / name
            path.write_bytes(b'keep')
            before = path.stat()
            producer = Mock(side_effect=AssertionError('must not spawn'))
            self.assert_refused('data_unavailable', producer)
            producer.assert_not_called()
            self.assertEqual(path.read_bytes(), b'keep')
            self.assertEqual(path.stat().st_ino, before.st_ino)
            path.unlink()

    def test_missing_directory_never_created(self):
        self.data.rmdir()
        producer = Mock(side_effect=AssertionError('must not spawn'))
        self.assert_refused('data_unavailable', producer)
        producer.assert_not_called()
        self.assertFalse(self.data.exists())

    def test_symlink_directory_and_writable_parent_refused(self):
        moved = self.data.with_name('held-data')
        self.data.rename(moved)
        self.data.symlink_to(moved)
        self.assert_refused('data_unavailable')
        self.data.unlink(); moved.rename(self.data)
        self.data.parent.chmod(0o777)
        self.assert_refused('data_unavailable')

    def test_wrong_directory_mode_or_owner_refused(self):
        self.data.chmod(0o750)
        self.assert_refused('data_unavailable')
        self.data.chmod(0o700)
        self.assert_refused('data_unavailable', _app_uid=os.geteuid() + 1)

    def test_directory_swap_after_producer_refused(self):
        moved = self.data.with_name('held-data')
        def checkpoint(stage):
            if stage == 'producer_finished':
                self.data.rename(moved)
                self.data.mkdir(mode=0o700)
        self.assert_refused('data_unavailable', _checkpoint=checkpoint)
        self.assertEqual(list(self.data.iterdir()), [])
        self.assertEqual(list(moved.iterdir()), [])

    def test_exclusive_create_blocks_late_symlink_without_touching_target(self):
        outside = self.base / 'keep'; outside.write_bytes(b'keep')
        original = publisher.os.open
        def late_entry(path, flags, *args, **kwargs):
            if path == publisher.NAME and flags & os.O_CREAT:
                self.target.symlink_to(outside)
            return original(path, flags, *args, **kwargs)
        with patch.object(publisher.os, 'open', late_entry):
            self.assert_refused('publication_failed')
        self.assertEqual(outside.read_bytes(), b'keep')
        self.assertTrue(self.target.is_symlink())

    def test_short_writes_are_completed_without_byte_changes(self):
        original = publisher.os.write
        with patch.object(publisher.os, 'write', lambda fd, raw: original(fd, raw[:3])):
            self.publish()
        self.assertEqual(self.target.read_bytes(), RAW)

    def test_zero_write_and_each_fsync_failure_preserve_file(self):
        with patch.object(publisher.os, 'write', return_value=0):
            self.assert_refused('publication_failed')
        self.assertEqual(self.target.read_bytes(), b'')
        self.target.unlink()  # Fixture reset only; publisher never removes it.
        original = publisher.os.fsync
        for fail_at in (1, 2):
            calls = []
            def fsync(fd):
                calls.append(fd)
                if len(calls) == fail_at:
                    raise OSError(CANARY)
                return original(fd)
            with patch.object(publisher.os, 'fsync', fsync):
                self.assert_refused('publication_failed')
            self.assertEqual(self.target.read_bytes(), RAW)
            self.target.unlink()

    def test_readback_tamper_inode_replacement_and_hardlink_refused(self):
        for action in ('tamper', 'replace', 'hardlink'):
            def checkpoint(stage):
                if stage == 'directory_synced':
                    if action == 'tamper': self.target.write_bytes(b'x' * (len(RAW) - 1) + b'\n')
                    elif action == 'replace':
                        self.target.rename(self.data / 'held')
                        self.target.write_bytes(RAW); self.target.chmod(0o600)
                    else: os.link(self.target, self.data / 'held')
            with self.subTest(action=action):
                self.assert_refused('publication_failed', _checkpoint=checkpoint)
                self.assertTrue(self.target.exists())
                for path in self.data.iterdir(): path.unlink()

    @unittest.skipUnless('fork' in multiprocessing.get_all_start_methods(), 'requires POSIX fork')
    def test_crash_preserves_partial_or_complete_file_and_never_replaces(self):
        for stage in ('file_created', 'file_written', 'file_synced', 'directory_synced', 'published'):
            with self.subTest(stage=stage):
                process = multiprocessing.get_context('fork').Process(
                    target=crash_publish, args=(self.options, stage, self.base))
                process.start(); process.join(5)
                if process.is_alive():
                    process.kill(); process.join(2); self.fail('fixture worker did not stop')
                self.assertEqual(process.exitcode, 71)
                self.assertEqual(self.target.read_bytes(), b'' if stage == 'file_created' else RAW)
                producer = Mock(side_effect=AssertionError('no replacement'))
                self.assert_refused('data_unavailable', producer)
                producer.assert_not_called()
                self.target.unlink()

    def test_production_rejects_fixture_injection_before_io(self):
        with patch.object(publisher.os, 'geteuid', return_value=0), \
                patch.object(publisher.sys, 'platform', 'linux'), \
                patch.object(publisher, '_open_data', side_effect=AssertionError('no IO')):
            for options in ({'_timeout': 1}, {'_spawn': Mock()}, {'_checkpoint': Mock()}, {'_app_uid': 0}):
                with self.subTest(options=tuple(options)):
                    with self.assertRaisesRegex(publisher.PublisherError, '^configuration_invalid$'):
                        publisher.publish(**options)
            with self.assertRaisesRegex(publisher.PublisherError, '^configuration_invalid$'):
                publisher.publish(_root='//', _spawn=Mock())

    def test_invalid_arguments_fail_without_io(self):
        for options in ({'_timeout': True}, {'_timeout': float('nan')}, {'_timeout': 31},
                        {'_timeout': 0}, {'_app_uid': True}, {'_root': 'relative'},
                        {'_root': '/tmp/../not-a-fixture'}):
            with self.subTest(options=tuple(options)):
                self.assert_refused('configuration_invalid', **options)

    def test_signal_failure_still_observes_reaped_child_but_not_live_child(self):
        with patch.object(publisher.os, 'killpg', side_effect=PermissionError('inert')):
            for exit_code, expected in ((0, True), (-9, True), (None, False)):
                child = Mock(pid=123, poll=Mock(return_value=exit_code))
                self.assertIs(publisher._stop(child, time.monotonic()), expected)
                self.assertEqual(child.poll.call_count, 2 if exit_code is None else 1)

    def test_reaped_child_never_signals_a_reusable_process_group_number(self):
        for code in (0, 64, -9):
            child = Mock(pid=123, poll=Mock(return_value=code))
            with patch.object(publisher.os, 'killpg') as kill:
                self.assertIs(publisher._stop(child, time.monotonic() + 1), True)
                kill.assert_not_called()

    def test_import_has_no_execution_or_cli(self):
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('import spawned')):
            scope = {'__name__': '__main__'}
            exec(compile(SOURCE.read_bytes(), str(SOURCE), 'exec'), scope)
        self.assertNotIn('main', scope)
        self.assertEqual(list(self.data.iterdir()), [])


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                     'real uid/group drop needs root Linux; inert producer only')
class NativePrivilegeDropTests(unittest.TestCase):
    setUp = PublisherTests.setUp
    publish = PublisherTests.publish

    def test_inert_interpreter_observes_dropped_real_effective_saved_ids(self):
        os.chown(self.data, 1000, 1000)
        def spawn(argv, **options):
            self.assertEqual(argv, publisher.ARGV)
            options['cwd'] = '/'
            code = ('import json,os; print(json.dumps({"uid":os.getresuid(),'
                    '"gid":os.getresgid(),"groups":os.getgroups()}))')
            return subprocess.Popen([sys.executable, '-I', '-B', '-c', code], **options)
        self.assertEqual(self.publish(spawn, _app_uid=1000, _app_gid=1000), {'status': 'published'})
        observed = json.loads(self.target.read_bytes())
        self.assertEqual(observed, {'uid': [1000]*3, 'gid': [1000]*3, 'groups': []})
        self.assertEqual((self.target.stat().st_uid, self.target.stat().st_gid), (1000, 1000))


if __name__ == '__main__':
    unittest.main()
