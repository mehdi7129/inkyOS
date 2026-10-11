"""Synthetic roots only; no service, image, radio or production permission."""
import contextlib
import hashlib
import importlib.util
import io
import json
import multiprocessing
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


factory = load('factory_authority', ROOT / 'scripts/factory-authority.py')
receipt = load('factory_test_receipt', ROOT / 'scripts/initialization-receipt.py')
ENV = {'INKY_STUDIO_FACTORY_REQUIRED': '1', 'INKY_STUDIO_DATA_DIR': '/var/lib/inky-studio'}


def crash_worker(options, stage):
    def checkpoint(current):
        if stage == current:
            os._exit(71)
    factory.initialize(**options, _checkpoint=checkpoint)
    os._exit(0)


def partial_create_worker(options, point):
    original_mkdir = factory.os.mkdir
    original_fsync = factory.os.fsync
    creating = False
    def mkdir(name, *args, **kwargs):
        nonlocal creating
        value = original_mkdir(name, *args, **kwargs)
        if name == 'initialization':
            creating = True
            if point == 'mkdir':
                os._exit(72)
        return value
    def fsync(fd):
        value = original_fsync(fd)
        if creating and point == 'fsync':
            os._exit(73)
        return value
    with patch.object(factory.os, 'mkdir', mkdir), patch.object(factory.os, 'fsync', fsync):
        factory.initialize(**options)
    os._exit(0)


def locked_worker(options, pipe):
    def checkpoint(stage):
        if stage == 'validated':
            pipe.send('locked')
            if not pipe.poll(5) or pipe.recv() != 'continue':
                raise RuntimeError('fixture release missing')
    try:
        pipe.send(factory.initialize(**options, _checkpoint=checkpoint))
    finally:
        pipe.close()


class FactoryAuthorityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='.inkyos-factory-test-', dir=Path.home().resolve())
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.owner = {'_owner_uid': os.geteuid(), '_owner_gid': os.getegid()}
        self.root = self.make_root('root')

    def make_root(self, name):
        root = self.base / name; root.mkdir(mode=0o700)
        for directory in ('etc', 'etc/inky-studio', 'usr', 'usr/local', 'usr/local/lib',
                          'usr/local/lib/inkyos', 'var', 'var/lib', 'var/lib/inkyos'):
            (root / directory).mkdir(mode=0o700)
        self.write(root / factory.MARKER, factory.MARKER_VALUE, 0o644)
        source = root / factory.SOURCE
        source.write_bytes((ROOT / 'scripts/initialization-receipt.py').read_bytes()); source.chmod(0o555)
        permission = root / factory.PERMISSION; permission.mkdir(mode=0o700)
        self.write(permission / 'pending.json', factory.PERMISSION_VALUE, 0o600)
        (permission / 'lock').touch(mode=0o600)
        return root

    def write(self, path, value, mode=0o600):
        path.write_text(json.dumps(value) + '\n'); path.chmod(mode)

    def options(self, root=None):
        return {'_root': root or self.root, **self.owner, '_environ': dict(ENV)}

    def initialize(self, **extra):
        return factory.initialize(**{**self.options(), **extra})

    def snapshot(self, root=None):
        root = root or self.root
        return {str(p.relative_to(root)): (stat.S_IMODE(p.lstat().st_mode), p.read_bytes())
                for p in root.rglob('*') if p.is_file() and not p.is_symlink()}

    def assert_error(self, code, **options):
        with self.assertRaises(factory.FactoryError) as result:
            self.initialize(**options)
        self.assertEqual(result.exception.code, code)

    def test_create_once_and_restart_inspects_same_authority(self):
        self.assertEqual(self.initialize(), {'status': 'created', 'authority_status': 'authorized'})
        state = self.root / factory.AUTHORITY
        original = (state / 'state.json').read_bytes()
        before = self.snapshot()
        self.assertEqual(self.initialize(), {'status': 'existing', 'authority_status': 'authorized'})
        self.assertEqual(self.snapshot(), before)
        self.assertEqual((state / 'state.json').read_bytes(), original)
        self.assertEqual(set(p.name for p in (self.root / factory.PERMISSION).iterdir()), {'lock', 'consumed.json'})
        self.assertFalse((self.root / 'var/lib/inky-studio').exists())

    def test_consumed_receipt_remains_consumed_without_app_data(self):
        self.initialize(); state = self.root / factory.AUTHORITY
        result = receipt.begin(state, '12345678-1234-4234-8234-123456789abc', **self.owner)
        before = self.snapshot()
        self.assertEqual(self.initialize(), {'status': 'existing', 'authority_status': 'consumed'})
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(receipt.inspect(state, **self.owner)['receipt'], result['receipt'])

    def test_env_absent_or_inexact_refuses_before_mutation(self):
        before = self.snapshot()
        for env in ({}, {**ENV, 'INKY_STUDIO_FACTORY_REQUIRED': True},
                    {**ENV, 'INKY_STUDIO_FACTORY_REQUIRED': '0'},
                    {**ENV, 'INKY_STUDIO_DATA_DIR': '/tmp/other'}):
            with self.subTest(env=env):
                self.assert_error('configuration_invalid', _environ=env)
                self.assertEqual(self.snapshot(), before)

    def test_marker_closed_schema_exact_types_and_duplicate_rejected(self):
        path = self.root / factory.MARKER
        bad = [[], {}, {**factory.MARKER_VALUE, 'version': True},
               {**factory.MARKER_VALUE, 'app_uid': 1000.0}, {**factory.MARKER_VALUE, 'extra': 1},
               {**factory.MARKER_VALUE, 'data_dir': '/other'}, {**factory.MARKER_VALUE, 'app_uid': 0}]
        for value in bad:
            self.write(path, value, 0o644)
            before = self.snapshot(); self.assert_error('configuration_invalid'); self.assertEqual(self.snapshot(), before)
        path.write_bytes(b'{"version":1,"version":1,"app_uid":1000,"data_dir":"/var/lib/inky-studio"}\n')
        self.assert_error('configuration_invalid')

    def test_missing_marker_and_bad_source_never_consume(self):
        source = self.root / factory.SOURCE
        source.chmod(0o755)
        self.assert_error('configuration_invalid')
        source.chmod(0o555)
        with patch.object(factory, 'RECEIPT_SHA256', '0' * 64):
            self.assert_error('configuration_invalid')
        original = source.read_bytes()
        source.chmod(0o755)
        source.write_bytes(b'raise RuntimeError("unpinned source executed")\n'); source.chmod(0o555)
        self.assert_error('configuration_invalid')
        source.chmod(0o755); source.write_bytes(original); source.chmod(0o555)
        (self.root / factory.MARKER).unlink()
        self.assert_error('configuration_invalid')
        self.assertTrue((self.root / factory.PERMISSION / 'pending.json').exists())

    def test_permission_and_lock_never_created_implicitly(self):
        permission = self.root / factory.PERMISSION
        (permission / 'pending.json').unlink(); (permission / 'lock').unlink(); permission.rmdir()
        before = self.snapshot(); self.assert_error('permission_unavailable'); self.assertEqual(self.snapshot(), before)
        permission.mkdir(mode=0o700)
        self.write(permission / 'pending.json', factory.PERMISSION_VALUE)
        before = self.snapshot(); self.assert_error('permission_unavailable'); self.assertEqual(self.snapshot(), before)

    def test_ambiguous_permission_sets_never_create_authority(self):
        permission = self.root / factory.PERMISSION
        for name in ('consumed.json', '.write.pending', 'unexpected'):
            self.write(permission / name, factory.PERMISSION_VALUE)
            before = self.snapshot(); self.assert_error('recovery_required'); self.assertEqual(self.snapshot(), before)
            (permission / name).unlink()
        (permission / 'pending.json').unlink()
        self.assert_error('recovery_required')
        self.assertFalse((self.root / factory.AUTHORITY).exists())

    def test_permission_closed_schema_and_mode(self):
        path = self.root / factory.PERMISSION / 'pending.json'
        for value in ({}, {'version': True, 'operation': 'create-initialization-authority'},
                      {**factory.PERMISSION_VALUE, 'other': True},
                      {'version': 1, 'operation': 'reset'}):
            self.write(path, value)
            self.assert_error('recovery_required')
        self.write(path, factory.PERMISSION_VALUE, 0o644)
        self.assert_error('recovery_required')

    def test_preexisting_authority_even_dangling_link_refuses_pending(self):
        authority = self.root / factory.AUTHORITY
        authority.symlink_to(self.root / 'absent')
        self.assert_error('recovery_required'); authority.unlink()
        authority.mkdir(mode=0o700)
        self.assert_error('recovery_required'); authority.rmdir()
        receipt.create_authorization(authority, **self.owner)
        before = self.snapshot(); self.assert_error('recovery_required'); self.assertEqual(self.snapshot(), before)
        self.assertTrue((self.root / factory.PERMISSION / 'pending.json').exists())

    def test_consumed_with_missing_partial_or_corrupt_authority_never_recreates(self):
        permission = self.root / factory.PERMISSION
        (permission / 'pending.json').rename(permission / 'consumed.json')
        self.assert_error('recovery_required')
        authority = self.root / factory.AUTHORITY; authority.mkdir(mode=0o700)
        self.assert_error('recovery_required'); authority.rmdir()
        receipt.create_authorization(authority, **self.owner)
        (authority / 'state.json').write_text('broken')
        before = self.snapshot(); self.assert_error('recovery_required'); self.assertEqual(self.snapshot(), before)

    def test_symlinks_hardlinks_special_files_and_writable_parents_refused(self):
        permission = self.root / factory.PERMISSION
        path = permission / 'pending.json'; raw = path.read_bytes(); path.unlink()
        outside = self.root / 'outside'; outside.write_bytes(raw); outside.chmod(0o600)
        path.symlink_to(outside)
        self.assert_error('recovery_required'); path.unlink()
        os.link(outside, path)
        self.assert_error('recovery_required'); path.unlink()
        os.mkfifo(path, 0o600)
        self.assert_error('recovery_required'); path.unlink()
        self.write(path, factory.PERMISSION_VALUE)
        permission.chmod(0o750)
        self.assert_error('recovery_required'); permission.chmod(0o700)
        (self.root / 'var/lib').chmod(0o777)
        self.assert_error('recovery_required')
        self.assertFalse((self.root / factory.AUTHORITY).exists())

    def test_lock_replacement_after_acquisition_is_refused(self):
        def checkpoint(stage):
            if stage == 'validated':
                lock = self.root / factory.PERMISSION / 'lock'
                lock.rename(lock.with_name('old-lock'))
                lock.touch(mode=0o600)
        self.assert_error('recovery_required', _checkpoint=checkpoint)
        self.assertFalse((self.root / factory.AUTHORITY).exists())

    def test_marker_source_and_lock_links_refused(self):
        for relative, code in ((factory.MARKER, 'configuration_invalid'),
                               (factory.SOURCE, 'configuration_invalid'),
                               (factory.PERMISSION / 'lock', 'recovery_required')):
            with self.subTest(relative=relative):
                root = self.make_root('link-' + relative.name)
                path = root / relative; outside = root / 'held-original'
                path.rename(outside); path.symlink_to(outside)
                self.assert_error(code, _root=root)
                path.unlink(); os.link(outside, path)
                self.assert_error(code, _root=root)
                self.assertTrue((root / factory.PERMISSION / 'pending.json').exists())

    def test_unexpected_owner_or_group_refused(self):
        inode = (self.root / factory.PERMISSION / 'pending.json').stat().st_ino
        original = factory.os.fstat
        for index in (4, 5):
            def changed(fd):
                result = original(fd)
                if result.st_ino == inode:
                    fields = list(result); fields[index] += 1
                    return os.stat_result(fields)
                return result
            with self.subTest(index=index), patch.object(factory.os, 'fstat', changed):
                self.assert_error('recovery_required')
        self.assertFalse((self.root / factory.AUTHORITY).exists())

    def test_marker_changed_after_validation_is_refused_before_consumption(self):
        def checkpoint(stage):
            if stage == 'validated':
                path = self.root / factory.MARKER
                replacement = path.with_name('replacement.json')
                self.write(replacement, factory.MARKER_VALUE, 0o644)
                replacement.replace(path)
        self.assert_error('recovery_required', _checkpoint=checkpoint)
        self.assertTrue((self.root / factory.PERMISSION / 'pending.json').exists())

    def test_fsync_failure_after_rename_never_calls_create(self):
        original_mkdir = factory.os.mkdir
        creates = []
        def mkdir(name, *args, **kwargs):
            if name == 'initialization': creates.append(name)
            return original_mkdir(name, *args, **kwargs)
        with patch.object(factory.os, 'fsync', side_effect=OSError('synthetic fsync failure')), \
                patch.object(factory.os, 'mkdir', mkdir):
            self.assert_error('recovery_required')
        self.assertEqual(creates, [])
        self.assertTrue((self.root / factory.PERMISSION / 'consumed.json').exists())
        self.assert_error('recovery_required')
        self.assertFalse((self.root / factory.AUTHORITY).exists())

    def test_create_occurs_after_successful_permission_fsync(self):
        original_mkdir = factory.os.mkdir; original_fsync = factory.os.fsync
        events = []
        def fsync(fd):
            result = original_fsync(fd)
            if os.fstat(fd).st_ino == (self.root / factory.PERMISSION).stat().st_ino:
                events.append('permission_fsynced')
            return result
        def mkdir(name, *args, **kwargs):
            if name == 'initialization':
                self.assertEqual(events, ['permission_fsynced'])
                events.append('create')
            return original_mkdir(name, *args, **kwargs)
        with patch.object(factory.os, 'fsync', fsync), patch.object(factory.os, 'mkdir', mkdir):
            self.assertEqual(self.initialize()['status'], 'created')
        self.assertEqual(events[:2], ['permission_fsynced', 'create'])

    @unittest.skipUnless(hasattr(os, 'fork'), 'process interruption requires fork')
    def test_process_interruptions_and_restart(self):
        ctx = multiprocessing.get_context('fork')
        for stage in ('validated', 'permission_renamed', 'permission_synced',
                      'before_authority_create', 'authority_created'):
            with self.subTest(stage=stage):
                root = self.make_root(stage)
                child = ctx.Process(target=crash_worker, args=(self.options(root), stage))
                child.start(); child.join(5)
                if child.is_alive(): child.kill(); child.join(); self.fail('fixture timeout')
                self.assertEqual(child.exitcode, 71)
                if stage == 'validated':
                    self.assertEqual(self.initialize(_root=root)['status'], 'created')
                elif stage == 'authority_created':
                    before = self.snapshot(root)
                    self.assertEqual(self.initialize(_root=root)['status'], 'existing')
                    self.assertEqual(self.snapshot(root), before)
                else:
                    self.assert_error('recovery_required', _root=root)
                    self.assertFalse((root / factory.AUTHORITY).exists())

    @unittest.skipUnless(hasattr(os, 'fork'), 'process interruption requires fork')
    def test_interrupted_receipt_create_preserves_partial_state_and_refuses_retry(self):
        ctx = multiprocessing.get_context('fork')
        for point, exit_code in (('mkdir', 72), ('fsync', 73)):
            with self.subTest(point=point):
                root = self.make_root(point)
                child = ctx.Process(target=partial_create_worker, args=(self.options(root), point))
                child.start(); child.join(5)
                if child.is_alive(): child.kill(); child.join(); self.fail('fixture timeout')
                self.assertEqual(child.exitcode, exit_code)
                self.assertTrue((root / factory.AUTHORITY).is_dir())
                before = self.snapshot(root)
                self.assert_error('recovery_required', _root=root)
                self.assertEqual(self.snapshot(root), before)

    @unittest.skipUnless(hasattr(os, 'fork'), 'process concurrency requires fork')
    def test_concurrent_hook_is_busy_then_only_inspects(self):
        ctx = multiprocessing.get_context('fork'); parent, child_pipe = ctx.Pipe()
        child = ctx.Process(target=locked_worker, args=(self.options(), child_pipe)); child.start(); child_pipe.close()
        try:
            self.assertTrue(parent.poll(5)); self.assertEqual(parent.recv(), 'locked')
            self.assert_error('busy')
            parent.send('continue')
            self.assertTrue(parent.poll(5)); self.assertEqual(parent.recv()['status'], 'created')
            child.join(5); self.assertEqual(child.exitcode, 0)
            self.assertEqual(self.initialize()['status'], 'existing')
        finally:
            parent.close()
            if child.is_alive(): child.kill()
            child.join(5)

    def test_source_pin_and_hook_stays_uninstalled(self):
        self.assertEqual(hashlib.sha256((ROOT / 'scripts/initialization-receipt.py').read_bytes()).hexdigest(), factory.RECEIPT_SHA256)
        for relative in ('scripts/build-prototype.sh', 'scripts/build-image-linux.sh',
                         'scripts/configure-rootfs.py', 'scripts/configure-application-rootfs.py'):
            self.assertNotIn('factory-authority', (ROOT / relative).read_text())

    def test_cli_invalid_arguments_never_initialize_and_errors_are_closed(self):
        with patch.object(factory, 'initialize') as invoke, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(factory.main(['--reset']), 1)
            invoke.assert_not_called()
        self.assertEqual(json.loads(output.getvalue()), {'status': 'refused', 'error': 'configuration_invalid'})
        with patch.object(factory.sys, 'platform', 'linux'), patch.object(factory.os, 'geteuid', return_value=0), \
                patch.object(factory, 'initialize', side_effect=factory.FactoryError('recovery_required')), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(factory.main([]), 1)
        self.assertEqual(json.loads(output.getvalue()), {'status': 'refused', 'error': 'recovery_required'})


if __name__ == '__main__':
    unittest.main()
