"""Inert unit fixtures for the installed exporter probe.

No systemd unit, target interpreter, chroot, image or real credential is used.
These checks cover orchestration contracts, not native or hardware qualification.
"""
import copy
import configparser
import contextlib
import ast
import builtins
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import types
import unittest
from unittest.mock import Mock, call, patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'staging/bootstrap/probe-factory-installed-linux.py'
UNIT = 'inkyos-factory-probe-installed-01234567-fresh.service'
spec = importlib.util.spec_from_file_location('factory_installed_probe_fixture', SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def encoded(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


class InertLauncherExit(BaseException):
    pass


class ValidationLauncherFixture:
    """Execute only launcher control flow; every OS operation is an inert fake."""
    def __init__(self, failure=None):
        self.failure = failure
        self.uid = self.gid = (0, 0, 0)
        self.groups = [0, 27]
        self.events = []
        self.exec_calls = []
        self.os = types.SimpleNamespace(
            O_RDONLY=os.O_RDONLY, getresuid=lambda: self.uid, getresgid=lambda: self.gid,
            getgroups=lambda: self.groups, setgroups=self.setgroups,
            setresgid=self.setresgid, setresuid=self.setresuid,
            open=self.open, read=self.read, close=lambda fd: self.events.append(('close', fd)),
            execve=self.execve, _exit=self.exit)

    def setgroups(self, groups):
        self.events.append(('setgroups', groups))
        self.groups = [27] if self.failure == 'groups' else list(groups)

    def setresgid(self, *gid):
        self.events.append(('setresgid', gid))
        self.gid = (1000, 1000, 0) if self.failure == 'gid' else gid

    def setresuid(self, *uid):
        self.events.append(('setresuid', uid))
        if self.failure == 'setuid':
            raise OSError('inert drop failure')
        self.uid = (1000, 1000, 0) if self.failure == 'uid' else uid

    def open(self, path, flags):
        self.events.append(('open', path, flags))
        if path != '/proc/self/status' or flags != os.O_RDONLY:
            raise AssertionError('Unexpected fake launcher read')
        return 123

    def read(self, fd, limit):
        values = {name: '00000000' for name in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb')}
        values['NoNewPrivs'] = '1'
        if self.failure in values:
            values[self.failure] = '0' if self.failure == 'NoNewPrivs' else '00000001'
        return ''.join(name + ':\t' + value + '\n' for name, value in values.items()).encode()

    def execve(self, target, argv, environ):
        self.events.append(('execve', target))
        self.exec_calls.append((target, argv, environ, self.uid, self.gid, self.groups))

    def exit(self, code):
        raise InertLauncherExit(code)

    def run(self):
        command = probe.validation_command()
        def importer(name, *args, **kwargs):
            self.events.append(('import', name))
            if name != 'os':
                raise AssertionError('No app or other module may be imported by the root launcher')
            return self.os
        safe_builtins = {**vars(builtins), '__import__': importer}
        exec(compile(command[-1], '<inert-validation-launcher>', 'exec'), {'__builtins__': safe_builtins})


class ObserverFixture:
    """Run the observer with no real filesystem, process or target module access."""
    MASK = '/usr/lib/modules'

    def __init__(self):
        self.imports = []
        self.opened = []
        self.fds = {}
        self.next_fd = 10
        self.output = {}
        self.fail_receipt = False
        self.mask_options = {'ro', 'nosuid', 'nodev', 'noexec'}
        self.extra_mounts = []
        self.mask_count = 1
        self.text_overrides = {}
        self.flag_overrides = {}
        self.argv_override = None
        self.pin_override = None
        self.entries = {self.MASK: []}
        self.mask_flags = 1 | 2 | 4 | 8
        self.attributes = {}
        self.infos = {}
        self.root_info = self.info(stat.S_IFDIR | 0o755, dev=31, ino=2)
        self.infos['/'] = self.root_info
        self.infos['/dev'] = self.info(stat.S_IFDIR | 0o755, dev=40)
        self.infos[self.MASK] = self.info(stat.S_IFDIR, dev=42)
        binds = ['/var/lib/inkyos', '/var/lib/inky-studio', '/etc/inky-studio', '/usr/local/lib/inkyos']
        for index, path in enumerate(binds):
            self.infos[path] = self.info(stat.S_IFDIR | 0o700, dev=41, ino=100 + index)
        helper = b'def inventory(path):\n return {"inert_fixture_path": str(path)}\n'
        self.expected = {
            'unit': UNIT, 'host_net': 'net:[host]', 'host_dev': 39,
            'root_identity': [31, 2],
            'bind_identities': {path: [self.infos[path].st_dev, self.infos[path].st_ino] for path in binds},
            'inventory_sha256': hashlib.sha256(helper).hexdigest(),
            'local_tree': {'inert_fixture_path': '/usr/local/lib'},
            'bundle_tree': {'inert_fixture_path': '/usr/lib/inkyos/factory-exporter'},
        }
        self.files = {'/etc/inky-studio/manifest-rootfs.py': helper}
        self.output_path = '/var/lib/inkyos/observations/' + UNIT + '.json'
        fixture = self

        class FakePath:
            def __init__(self, value):
                self.path = PurePosixPath(str(value))

            def __str__(self):
                return str(self.path)

            def __fspath__(self):
                return str(self.path)

            def __truediv__(self, value):
                return FakePath(self.path / value)

            def read_text(self):
                return fixture.read_text(str(self))

            def glob(self, pattern):
                if str(self) != '/dev' or pattern != 'spidev*':
                    raise AssertionError('Unexpected observer glob')
                return []

            def iterdir(self):
                return iter(FakePath(self.path / name) for name in fixture.entries.get(str(self), []))

            def stat(self, **kwargs):
                return fixture.stat(str(self), **kwargs)

            def lstat(self):
                return fixture.stat(str(self))

        self.Path = FakePath
        self.os = types.SimpleNamespace(
            O_RDONLY=os.O_RDONLY, O_WRONLY=os.O_WRONLY, O_NONBLOCK=os.O_NONBLOCK,
            O_NOFOLLOW=os.O_NOFOLLOW, O_CREAT=os.O_CREAT, O_EXCL=os.O_EXCL,
            ST_RDONLY=1, ST_NOSUID=2, ST_NODEV=4, ST_NOEXEC=8,
            getresuid=lambda: (0, 0, 0), getresgid=lambda: (0, 0, 0),
            open=self.open, close=lambda fd: None, fstat=lambda fd: self.stat(self.fds[fd][0]),
            stat=self.stat, lstat=self.stat, statvfs=self.statvfs,
            read=self.read, write=self.write, fsync=lambda fd: None,
            readlink=lambda path: 'net:[private]', _exit=self.exit,
            listdir=lambda path: list(self.entries.get(str(path), [])),
            listxattr=lambda path, **kwargs: self.attributes.get(str(path), []))

    @staticmethod
    def info(mode, *, dev=31, ino=10, uid=0, gid=0, size=0):
        return types.SimpleNamespace(st_dev=dev, st_ino=ino, st_mode=mode,
            st_uid=uid, st_gid=gid, st_nlink=1, st_size=size, st_mtime_ns=1, st_ctime_ns=1)

    def stat(self, path, **kwargs):
        path = str(path)
        if path in self.files:
            return self.info(stat.S_IFREG | 0o444, size=len(self.files[path]))
        return self.infos.get(path, self.root_info)

    def statvfs(self, path):
        path = str(path)
        flags = self.mask_flags if path == self.MASK else (0 if path in {'/var/lib/inkyos', '/var/lib/inky-studio'} else 1)
        return types.SimpleNamespace(f_flag=self.flag_overrides.get(path, flags))

    def read_text(self, path):
        if path in self.text_overrides:
            return self.text_overrides[path]
        if path == '/proc/self/status':
            return 'CapEff:\t000000e3\nCapPrm:\t000000e3\nCapBnd:\t000000e3\nCapInh:\t0\nCapAmb:\t0\nNoNewPrivs:\t1\n'
        if path == '/proc/self/mountinfo':
            rows = ['20 1 7:2 / / ro,nosuid,nodev - ext4 /dev/loop7p2 ro',
                    '21 20 0:41 /marker /etc/inky-studio ro,nosuid,nodev - ext4 /dev/loop7p2 ro',
                    '22 20 0:41 /modules /usr/local/lib/inkyos ro,nosuid,nodev - ext4 /dev/loop7p2 ro']
            rows += [f'23 20 0:42 /inaccessible/dir {self.MASK} {",".join(sorted(self.mask_options))} - tmpfs tmpfs rw'] * self.mask_count
            rows += [f'24 20 0:43 / {path} ro,nosuid,nodev - tmpfs tmpfs rw' for path in self.extra_mounts]
            return '\n'.join(rows) + '\n'
        if path == '/proc/self/cgroup':
            return '0::/system.slice/' + UNIT + '\n'
        if path.endswith('/pids.max'):
            return '2\n'
        if path.endswith('/cgroup.events'):
            return 'populated 1\n'
        raise AssertionError('Unexpected observer text read: ' + path)

    def open(self, path, flags, mode=None):
        path = str(path)
        self.opened.append((path, flags, mode))
        if flags & os.O_WRONLY:
            if path != self.output_path or self.fail_receipt or path in self.output:
                raise OSError('inert receipt unavailable')
            if flags != os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW or mode != 0o600:
                raise AssertionError('Unexpected receipt flags or mode')
            self.output[path] = b''
        elif path not in self.files:
            raise AssertionError('Unexpected observer file read: ' + path)
        fd = self.next_fd; self.next_fd += 1
        self.fds[fd] = (path, flags)
        return fd

    def read(self, fd, limit):
        return self.files[self.fds[fd][0]][:limit]

    def write(self, fd, raw):
        self.output[self.fds[fd][0]] += raw
        return len(raw)

    def exit(self, code):
        raise InertLauncherExit(code)

    def run(self, source=None):
        self.files['/etc/inky-studio/bench-expected.json'] = encoded(self.expected)
        pin = hashlib.sha256(self.files['/etc/inky-studio/bench-expected.json']).hexdigest()
        modules = {'hashlib': hashlib, 'json': json, 'os': self.os, 're': re, 'stat': stat,
                   'sys': types.SimpleNamespace(argv=self.argv_override or ['observer.py', UNIT, self.pin_override or pin]),
                   'types': types, 'pathlib': types.SimpleNamespace(Path=self.Path)}
        def importer(name, *args, **kwargs):
            self.imports.append(name)
            if name not in modules:
                raise AssertionError('Unapproved observer import')
            return modules[name]
        code = probe.OBSERVER if source is None else source
        try:
            exec(compile(code, '<inert-observer>', 'exec'),
                 {'__builtins__': {**vars(builtins), '__import__': importer}})
        except InertLauncherExit as stopped:
            return stopped.args[0]
        return 0


class InstalledObserverExecutionTests(unittest.TestCase):
    def failure_receipt(self, phase):
        return {'schema_version': 1, 'scope': 'exec-start-pre-only',
                'control_group': '/system.slice/' + UNIT, 'checks_passed': False,
                'failure_phase': phase}

    def assert_refused(self, fixture, phase):
        self.assertEqual(fixture.run(), 64 + probe.PRE_PHASES.index(phase))
        value = json.loads(fixture.output[fixture.output_path])
        self.assertEqual(value, self.failure_receipt(phase))
        self.assertLessEqual(len(fixture.output[fixture.output_path]), 512)
        return value

    def test_legacy_mount_predicate_rejects_expected_kernel_modules_mask(self):
        # Exact former predicate, executed against the same inert mount table.
        legacy = b'''import os
from pathlib import Path
def require(value):
 if not value: raise ValueError('pre_guard')
try:
 for line in Path('/proc/self/mountinfo').read_text().splitlines():
  target=line.split()[4]
  if target in ('/usr','/etc','/lib') or target.startswith(('/usr/','/etc/','/lib/')):
   require(target in ('/etc/inky-studio','/usr/local/lib/inkyos'))
except BaseException:os._exit(1)
'''
        fixture = ObserverFixture()
        self.assertEqual(fixture.run(legacy), 1)
        self.assertEqual(fixture.output, {})
        fixture = ObserverFixture(); fixture.mask_count = 0
        self.assertEqual(fixture.run(legacy), 0)

    def test_observer_accepts_only_exact_inaccessible_modules_mask(self):
        fixture = ObserverFixture()
        self.assertEqual(fixture.run(), 0)
        self.assertEqual(json.loads(fixture.output[fixture.output_path]), {
            'schema_version': 1, 'scope': 'exec-start-pre-only',
            'control_group': '/system.slice/' + UNIT, 'checks_passed': True})
        self.assertEqual(set(fixture.imports), {'hashlib', 'json', 'os', 're', 'stat', 'sys', 'types', 'pathlib'})
        self.assertEqual([path for path, flags, _ in fixture.opened if flags & os.O_WRONLY],
                         [fixture.output_path])
        # The empty inaccessible directory does not require nosuid/nodev.
        fixture = ObserverFixture(); fixture.mask_options = {'ro', 'noexec'}
        self.assertEqual(fixture.run(), 0)

    def test_modules_mask_rejects_metadata_mount_flag_and_content_mutations(self):
        mutations = [
            ('writable', lambda f: f.mask_options.discard('ro')),
            ('executable', lambda f: f.mask_options.discard('noexec')),
            ('statvfs writable', lambda f: setattr(f, 'mask_flags', f.mask_flags & ~1)),
            ('base filesystem', lambda f: setattr(f.infos[f.MASK], 'st_dev', f.root_info.st_dev)),
            ('base permissions', lambda f: setattr(f.infos[f.MASK], 'st_mode', stat.S_IFDIR | 0o755)),
            ('owner', lambda f: setattr(f.infos[f.MASK], 'st_uid', 1000)),
            ('group', lambda f: setattr(f.infos[f.MASK], 'st_gid', 1000)),
            ('symlink', lambda f: setattr(f.infos[f.MASK], 'st_mode', stat.S_IFLNK)),
            ('file', lambda f: setattr(f.infos[f.MASK], 'st_mode', stat.S_IFREG)),
            ('content', lambda f: f.entries[f.MASK].append('untrusted.ko')),
            ('missing mount', lambda f: setattr(f, 'mask_count', 0)),
            ('duplicate mount', lambda f: setattr(f, 'mask_count', 2)),
        ]
        for label, mutate in mutations:
            with self.subTest(mutation=label):
                fixture = ObserverFixture(); mutate(fixture)
                self.assert_refused(fixture, 'critical_mounts')

    def test_unrelated_critical_mounts_are_still_refused(self):
        for path in ('/usr', '/etc', '/lib', '/usr/lib', '/usr/lib/modules/extra',
                     '/usr/lib/python3.13', '/usr/lib/aarch64-linux-gnu',
                     '/etc/ld.so.cache', '/lib/modules', '/usr/local/lib/other'):
            with self.subTest(path=path):
                fixture = ObserverFixture(); fixture.extra_mounts.append(path)
                self.assert_refused(fixture, 'critical_mounts')

    def test_missing_or_duplicate_explicit_readonly_bind_is_refused(self):
        for target in ('/etc/inky-studio', '/usr/local/lib/inkyos'):
            for operation in ('missing', 'duplicate'):
                with self.subTest(target=target, operation=operation):
                    fixture = ObserverFixture()
                    rows = fixture.read_text('/proc/self/mountinfo').splitlines()
                    matching = next(row for row in rows if row.split()[4] == target)
                    rows = [row for row in rows if row != matching] if operation == 'missing' else rows + [matching]
                    fixture.text_overrides['/proc/self/mountinfo'] = '\n'.join(rows)
                    self.assert_refused(fixture, 'critical_mounts')

    def test_failures_emit_only_the_closed_phase_and_fixed_exit_code(self):
        mutations = {
            'manifest': lambda f: setattr(f, 'pin_override', '0' * 64),
            'identity': lambda f: setattr(f.os, 'getresuid', lambda: (1000, 1000, 1000)),
            'capabilities': lambda f: f.text_overrides.update({'/proc/self/status': 'PRIVATE INERT ERROR\n'}),
            'isolation': lambda f: f.expected.update(host_net='net:[private]'),
            'binds': lambda f: f.expected.update(root_identity=[999, 999]),
            'mount_flags': lambda f: f.flag_overrides.update({'/': 0}),
            'critical_mounts': lambda f: f.extra_mounts.append('/usr/forbidden'),
            'inventory_helper': lambda f: f.expected.update(inventory_sha256='0' * 64),
            'local_inventory': lambda f: f.expected.update(local_tree={}),
            'bundle_inventory': lambda f: f.expected.update(bundle_tree={}),
            'cgroup': lambda f: f.text_overrides.update({'/proc/self/cgroup': '0::/other\n'}),
        }
        self.assertEqual(set(mutations) | {'arguments', 'receipt'}, set(probe.PRE_PHASES))
        for phase, mutate in mutations.items():
            with self.subTest(phase=phase):
                fixture = ObserverFixture(); mutate(fixture)
                value = self.assert_refused(fixture, phase)
                self.assertNotIn('PRIVATE INERT ERROR', json.dumps(value))

    def test_invalid_arguments_fail_without_a_receipt_path(self):
        for argv in (['observer.py'], ['observer.py', '../../escape', '0' * 64]):
            with self.subTest(argv=argv):
                fixture = ObserverFixture(); fixture.argv_override = argv
                self.assertEqual(fixture.run(), 64 + probe.PRE_PHASES.index('arguments'))
                self.assertEqual(fixture.output, {})

    def test_receipt_failure_keeps_fixed_phase_exit_without_other_writes(self):
        fixture = ObserverFixture(); fixture.fail_receipt = True
        self.assertEqual(fixture.run(), 64 + probe.PRE_PHASES.index('receipt'))
        self.assertEqual(fixture.output, {})
        self.assertEqual([path for path, flags, _ in fixture.opened if flags & os.O_WRONLY],
                         [fixture.output_path, fixture.output_path])
        fixture = ObserverFixture(); fixture.fail_receipt = True; fixture.mask_count = 0
        self.assertEqual(fixture.run(), 64 + probe.PRE_PHASES.index('critical_mounts'))
        self.assertEqual(fixture.output, {})


class InstalledProbeContractTests(unittest.TestCase):
    def support_fixture(self):
        directory = {'type': 'directory', 'uid': 0, 'gid': 0, 'mode': '0755',
                     'xattrs': {'status': 'inspected', 'entries': {}}}
        original = {'type': 'file', 'uid': 0, 'gid': 0, 'mode': '0644',
                    'xattrs': {'status': 'inspected', 'entries': {}},
                    'size_bytes': 7, 'sha256': hashlib.sha256(b'inert\n\n').hexdigest()}
        support = {'trees': {'usr/local/lib': {
            '.': copy.deepcopy(directory), 'inkyos': copy.deepcopy(directory),
            'inkyos/original.py': original}}}
        support['trees']['usr/local/lib']['inkyos']['mode'] = '0700'
        additions = {name: b'# inert source; never imported\n' + name.encode()
                     for name in ('factory-authority.py', 'factory-credentials-publisher.py',
                                  'initialization-receipt.py', 'factory-installed-observer.py')}
        return support, additions

    def test_local_tree_preserves_every_original_record_and_pins_additions(self):
        support, additions = self.support_fixture()
        before = copy.deepcopy(support)
        expected = probe.expected_local_tree(support, additions)
        original = support['trees']['usr/local/lib']
        self.assertEqual(support, before)
        self.assertEqual(set(expected), set(original) | {'inkyos/' + name for name in additions})
        for name, record in original.items():
            self.assertEqual(expected[name], record)
        for name, raw in additions.items():
            self.assertEqual(expected['inkyos/' + name], {
                'type': 'file', 'mode': '0555', 'uid': 0, 'gid': 0,
                'xattrs': {'status': 'inspected', 'entries': {}},
                'size_bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})

    def test_local_tree_refuses_collision_without_mutating_support(self):
        support, additions = self.support_fixture()
        support['trees']['usr/local/lib']['inkyos/factory-authority.py'] = copy.deepcopy(
            support['trees']['usr/local/lib']['inkyos/original.py'])
        before = copy.deepcopy(support)
        with self.assertRaises(ValueError):
            probe.expected_local_tree(support, additions)
        self.assertEqual(support, before)

    def test_local_tree_refuses_unsafe_addition_names(self):
        support, additions = self.support_fixture()
        for name in ('../escape.py', '/absolute.py', 'subdir/file.py', '.', '..', '',
                     'bad\x00.py', 'bad\n.py'):
            with self.subTest(name=repr(name)):
                invalid = dict(additions)
                invalid[name] = b'# inert'
                with self.assertRaises(ValueError):
                    probe.expected_local_tree(support, invalid)

    def unit_properties(self):
        config = configparser.ConfigParser(interpolation=None)
        config.optionxform = str
        config.read(ROOT / 'staging/bootstrap/inkyos-factory-fixture.service')
        base = dict(config['Service'])
        paths = [Path('/var/lib/inkyos-build/factory-installed.A1/root')]
        paths += [Path('/var/lib/inkyos-build/inert') / name
                  for name in ('state', 'data', 'marker', 'modules')]
        result = probe.unit_properties(base, *paths,
            UNIT, 'a' * 64,
            Path('/var/lib/inkyos-build/inert/hook-output.json'))
        return base, paths, result

    def test_unit_keeps_sandbox_and_direct_hook_contract(self):
        base, paths, props = self.unit_properties()
        self.assertEqual(props['RootDirectory'], str(paths[0]))
        self.assertEqual(props['MountAPIVFS'], 'yes')
        self.assertEqual(props['BindLogSockets'], 'no')
        self.assertEqual(props['TasksMax'], '2')
        self.assertEqual(props['NoNewPrivileges'], 'yes')
        self.assertEqual(props['KillMode'], 'control-group')
        self.assertEqual(props['CapabilityBoundingSet'].split(), [
            'CAP_CHOWN', 'CAP_DAC_OVERRIDE', 'CAP_KILL', 'CAP_SETGID', 'CAP_SETUID'])
        self.assertEqual(props['AmbientCapabilities'], '')
        self.assertEqual(props['TimeoutStartSec'], '40s')
        self.assertNotIn('User', props)
        self.assertEqual(base['ExecStart'], '/usr/bin/false')
        for key in ('PrivateDevices', 'PrivateNetwork', 'PrivateTmp',
                    'ProtectControlGroups', 'ProtectKernelModules'):
            self.assertEqual(props[key], 'yes')
        self.assertEqual(props['ProtectSystem'], 'strict')
        self.assertNotIn('ExecStart', props)

    def test_unit_exposes_only_four_explicit_bind_destinations(self):
        _, _, props = self.unit_properties()
        writable = props['BindPaths'].split()
        readonly = props['BindReadOnlyPaths'].split()
        self.assertEqual(len(writable), 2)
        self.assertEqual(len(readonly), 2)
        self.assertEqual({item.split(':')[1] for item in writable},
                         {'/var/lib/inkyos', '/var/lib/inky-studio'})
        self.assertEqual({item.split(':')[1] for item in readonly},
                         {'/etc/inky-studio', '/usr/local/lib/inkyos'})
        self.assertEqual(props['StandardError'], 'null')

    def test_hook_results_accept_only_expected_case(self):
        values = {
            'fresh': {'status': 'created', 'authority_status': 'authorized'},
            'restart': {'status': 'existing', 'authority_status': 'authorized'},
            'consumed_no_authority': {'status': 'refused', 'error': 'recovery_required'},
            'no_permission': {'status': 'refused', 'error': 'permission_unavailable'},
        }
        for case, result in values.items():
            with self.subTest(case=case):
                probe.validate_hook_output(encoded(result), case)
                for other_case, other_result in values.items():
                    if other_case != case:
                        with self.assertRaises((ValueError, KeyError)):
                            probe.validate_hook_output(encoded(other_result), case)

    def test_hook_results_reject_duplicate_keys_extra_fields_and_non_json(self):
        invalid = [
            b'{"status":"created","status":"created","authority_status":"authorized"}',
            encoded({'status': 'created', 'authority_status': 'authorized', 'secret': 'inert'}),
            encoded({'status': True, 'authority_status': 'authorized'}),
            encoded({'status': 'created', 'authority_status': 'authorized'}) + b'{}',
            b'not-json', b'[]', b'null', b'', b'\xff',
        ]
        for raw in invalid:
            with self.subTest(raw=raw):
                with self.assertRaises((ValueError, TypeError, UnicodeError)):
                    probe.validate_hook_output(raw, 'fresh')

    def test_hook_argv_is_direct_system_python_without_injection(self):
        self.assertEqual(probe.hook_command(), [
            '/usr/bin/python3.13', '-I', '-B', '-S',
            '/usr/local/lib/inkyos/factory-authority.py'])

    def test_studio_validation_result_has_exact_closed_boolean_schema(self):
        self.assertEqual(probe.validate_studio_output(encoded(probe.STUDIO_RESULT)), probe.STUDIO_RESULT)
        for key in probe.STUDIO_RESULT:
            changed = {**probe.STUDIO_RESULT, key: 1 if key != 'status' else 'FAIL'}
            with self.subTest(key=key), self.assertRaises(ValueError):
                probe.validate_studio_output(encoded(changed))
        for raw in (encoded({**probe.STUDIO_RESULT, 'credential': 'INERT'}),
                    encoded(probe.STUDIO_RESULT) + b'\n', b'{}\n', b' ' * 513 + b'\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                probe.validate_studio_output(raw)

    def test_validation_launcher_drops_numeric_identity_before_target_exec(self):
        self.assertEqual(probe.validation_command()[:5], ['/usr/bin/python3.13', '-I', '-B', '-S', '-c'])
        fixture = ValidationLauncherFixture(); fixture.run()
        self.assertEqual(len(fixture.exec_calls), 1)
        target, argv, env, uid, gid, groups = fixture.exec_calls[0]
        self.assertEqual(argv, [target, '-I', '-B', '-c', probe.VALIDATE])
        self.assertEqual(target, '/usr/lib/inkyos/factory-exporter/venv/bin/python')
        self.assertEqual((uid, gid, groups), ((1000, 1000, 1000), (1000, 1000, 1000), []))
        self.assertEqual(env, {'HOME': '/home/inky', 'PATH': '/usr/bin:/bin',
                               'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'})
        self.assertEqual(fixture.events[:4], [('import', 'os'), ('setgroups', []),
                                            ('setresgid', (1000, 1000, 1000)),
                                            ('setresuid', (1000, 1000, 1000))])

    def test_validation_launcher_refuses_residual_privileges_before_target_exec(self):
        for failure in ('setuid', 'uid', 'gid', 'groups', 'CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'NoNewPrivs'):
            with self.subTest(failure=failure):
                fixture = ValidationLauncherFixture(failure)
                with self.assertRaises(InertLauncherExit) as stopped:
                    fixture.run()
                self.assertEqual(stopped.exception.args, (1,))
                self.assertEqual(fixture.exec_calls, [])

    def test_stop_all_attempts_every_cleanup_after_failure(self):
        service = Mock()
        service.stop_unit.side_effect = [RuntimeError('inert'), None, OSError('inert')]
        attempted = [('one.service', Path('/inert/one')),
                     ('two.service', Path('/inert/two')),
                     ('three.service', Path('/inert/three'))]
        self.assertFalse(probe.stop_all(service, attempted))
        self.assertEqual(service.stop_unit.call_args_list,
                         [call(*item) for item in attempted])

    def test_stop_all_accepts_successful_cleanup(self):
        service = Mock()
        self.assertTrue(probe.stop_all(service, [('one.service', Path('/inert/one'))]))
        service.stop_unit.assert_called_once_with('one.service', Path('/inert/one'))

    def test_pre_receipt_is_bound_to_exact_unit_and_scope(self):
        value = {'schema_version': 1, 'scope': 'exec-start-pre-only',
                 'control_group': '/system.slice/' + UNIT, 'checks_passed': True}
        self.assertEqual(probe.validate_pre_receipt(encoded(value), UNIT),
                         '/system.slice/' + UNIT)
        mutations = [
            {'schema_version': True}, {'checks_passed': 1}, {'checks_passed': False},
            {'scope': 'exec-start'}, {'control_group': '/system.slice/other.service'},
            {'control_group': '/system.slice/../other.service'}, {'extra': 'inert'},
        ]
        for extra in mutations:
            with self.subTest(extra=extra):
                with self.assertRaises(ValueError):
                    probe.validate_pre_receipt(encoded({**value, **extra}), UNIT)
        with self.assertRaises(ValueError):
            probe.validate_pre_receipt(encoded(value), UNIT.replace('fresh', 'restart'))

    def test_pre_failure_receipt_accepts_only_enumerated_closed_phase(self):
        base = {'schema_version': 1, 'scope': 'exec-start-pre-only',
                'control_group': '/system.slice/' + UNIT, 'checks_passed': False}
        for phase in probe.PRE_PHASES:
            with self.subTest(phase=phase), self.assertRaises(probe.PreRefusal) as refused:
                probe.validate_pre_receipt(encoded({**base, 'failure_phase': phase}), UNIT)
            self.assertEqual(refused.exception.phase, phase)
            self.assertEqual(str(refused.exception), 'installed_pre_refused')
        valid = {**base, 'failure_phase': 'critical_mounts'}
        mutations = [{'schema_version': True}, {'checks_passed': 0}, {'checks_passed': True},
                     {'scope': 'exec-start'}, {'control_group': '/system.slice/other.service'},
                     {'failure_phase': 'unknown'}, {'failure_phase': '../outside'},
                     {'failure_phase': 'critical_mounts\n'}, {'failure_phase': True},
                     {'failure_phase': ['critical_mounts']}, {'exception': 'PRIVATE INERT ERROR'}]
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaises(ValueError) as refused:
                probe.validate_pre_receipt(encoded({**valid, **changed}), UNIT)
            self.assertNotIsInstance(refused.exception, probe.PreRefusal)
        duplicate = encoded(valid).replace(b'"checks_passed": false', b'"checks_passed": false, "checks_passed": false')
        with self.assertRaises(ValueError) as refused:
            probe.validate_pre_receipt(duplicate, UNIT)
        self.assertNotIsInstance(refused.exception, probe.PreRefusal)

    def test_closed_json_bounds_ascii_duplicates_and_constants(self):
        for raw in (b'{"same":1,"same":1}', b'{"x":NaN}', b'{"x":Infinity}',
                    b'\xff', b'', b' ' * 513):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    probe.closed_json(raw, 512)

    def test_unit_rejects_unsafe_paths_names_or_unpinned_manifest(self):
        base, paths, _ = self.unit_properties()
        output = Path('/var/lib/inkyos-build/inert/hook.stdout')
        for unit, pin, bad_path in (
                ('other.service', 'a' * 64, paths[0]),
                (UNIT, 'A' * 64, paths[0]),
                (UNIT, 'a' * 64, Path('/var/lib/../escape')),
                (UNIT, 'a' * 64, Path('/var/lib/space here')),
                (UNIT, 'a' * 64, Path('/var/lib/colon:inject'))):
            with self.subTest(unit=unit, pin=pin, path=bad_path):
                with self.assertRaises(ValueError):
                    probe.unit_properties(base, bad_path, *paths[1:], unit, pin, output)

    def test_wait_unit_accepts_terminal_result_after_more_than_old_twelve_seconds(self):
        service = Mock(PROPERTIES=('ActiveState', 'SubState'))
        service.command.side_effect = [b'ActiveState=activating\nSubState=start\n',
                                       b'ActiveState=active\nSubState=exited\n']
        with patch.object(probe.time, 'monotonic', side_effect=[0, 1, 21, 22]), \
                patch.object(probe.time, 'sleep') as sleep:
            result = probe.wait_unit(service, UNIT)
        self.assertEqual(result['SubState'], 'exited')
        self.assertEqual(service.command.call_count, 2)
        self.assertEqual(service.command.call_args.kwargs['timeout'], 5)
        sleep.assert_called_once()

    def test_wait_unit_deadline_limits_each_command_and_refuses_overrun(self):
        service = Mock(PROPERTIES=('ActiveState', 'SubState'))
        service.command.return_value = b'ActiveState=activating\nSubState=start\n'
        with patch.object(probe.time, 'monotonic', side_effect=[0, 49, 50, 51]), \
                patch.object(probe.time, 'sleep'):
            with self.assertRaises(ValueError):
                probe.wait_unit(service, UNIT)
        self.assertEqual(service.command.call_count, 1)
        self.assertEqual(service.command.call_args.kwargs['timeout'], 1)

    def test_wait_unit_preserves_empty_cgroup_terminal_failure(self):
        service = Mock(PROPERTIES=('ActiveState', 'SubState', 'ControlGroup'))
        service.command.return_value = b'ActiveState=failed\nSubState=failed\nControlGroup=\n'
        self.assertEqual(probe.wait_unit(service, UNIT)['ControlGroup'], '')


class InstalledProbeGuardTests(unittest.TestCase):
    ROOTFS = Path('/var/lib/inkyos-build/factory-installed.A1/root')
    IMAGE_SHA = hashlib.sha256(b'inert image fixture').hexdigest()

    def test_source_pins_match_repository_bytes(self):
        for relative, digest in probe.SOURCE_PINS.items():
            with self.subTest(source=relative):
                self.assertEqual(hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(), digest)

    def test_source_pin_failure_precedes_any_dependency_execution(self):
        with patch.object(probe, 'guard_path'), \
                patch.object(probe, 'regular', return_value=b'raise AssertionError("must not execute")\n'), \
                patch.object(probe.importlib.util, 'spec_from_file_location') as spec, \
                self.assertRaises(ValueError):
            probe.load_dependencies()
        spec.assert_not_called()

    @contextlib.contextmanager
    def regular_fixture(self, **changed):
        raw = b'inert'
        values = dict(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_nlink=1,
                      st_size=len(raw), st_dev=1, st_ino=2, st_mtime_ns=3, st_ctime_ns=4,
                      st_atime_ns=5)
        before = types.SimpleNamespace(**values)
        after = types.SimpleNamespace(**{**values, **changed})
        path = Mock()
        path.lstat.return_value = after
        with patch.object(probe.os, 'open', return_value=123) as opened, \
                patch.object(probe.os, 'fstat', side_effect=[before, after]), \
                patch.object(probe.os, 'read', return_value=raw), \
                patch.object(probe.os, 'close') as closed:
            yield path, raw, opened, closed

    def test_regular_ignores_access_time_but_preserves_stable_identity(self):
        with self.regular_fixture(st_atime_ns=12345) as (path, raw, opened, closed):
            self.assertEqual(probe.regular(path, 512, mode=0o600), raw)
        self.assertEqual(opened.call_args.args[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        closed.assert_called_once_with(123)

    def test_regular_rejects_metadata_or_content_changes_during_read(self):
        for changed in ({'st_ino': 3}, {'st_mode': stat.S_IFREG | 0o644},
                        {'st_nlink': 2}, {'st_size': 9}, {'st_mtime_ns': 8}, {'st_ctime_ns': 9}):
            with self.subTest(changed=changed), self.regular_fixture(**changed) as (path, _, _, closed):
                with self.assertRaises(ValueError):
                    probe.regular(path, 512, mode=0o600)
            closed.assert_called_once_with(123)

    def test_exclusive_write_restores_exact_mode_after_creation_umask(self):
        service = Mock()
        path = Mock()
        with patch.object(probe.os, 'chmod') as chmod:
            probe.write_exact(service, path, b'inert', 0o555)
        service.write_new.assert_called_once_with(path, b'inert', 0o555)
        chmod.assert_called_once_with(path, 0o555, follow_symlinks=False)

    @contextlib.contextmanager
    def rootfs_fixture(self, *, options='ro,nosuid,nodev', filesystem='ext4',
                       source='/dev/loop7p2', global_namespace=True,
                       block_readonly='1', backing=None, image_digest=None,
                       duplicate_mount=False, parent_mode=0o700, nonempty=False):
        rootfs = self.ROOTFS
        line = f'30 20 7:2 / {rootfs} {options} - {filesystem} {source} ro\n'
        texts = {'/proc/self/mountinfo': line * (2 if duplicate_mount else 1),
                 '/sys/block/loop7/ro': block_readonly,
                 '/sys/block/loop7/loop/backing_file': backing or str(rootfs.parent / 'image.img')}
        parent_info = types.SimpleNamespace(st_mode=stat.S_IFDIR | parent_mode)
        image_info = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600,
            st_dev=1, st_ino=2, st_uid=0, st_gid=0, st_nlink=1, st_size=19,
            st_mtime_ns=1, st_ctime_ns=1)
        verifier = Mock()
        verifier.single_record.side_effect = [{'type': 'directory', 'mode': '0755'},
                                              {'type': 'directory', 'mode': '0700'}]
        with contextlib.ExitStack() as stack:
            guard = stack.enter_context(patch.object(probe, 'guard_path'))
            stack.enter_context(patch.object(Path, 'stat', autospec=True,
                side_effect=lambda path, **_: parent_info if path == rootfs.parent else image_info))
            stack.enter_context(patch.object(Path, 'read_text', autospec=True,
                side_effect=lambda path, **_: texts[str(path)]))
            stack.enter_context(patch.object(Path, 'open', autospec=True,
                side_effect=lambda *args, **_: io.BytesIO(b'inert image fixture')))
            stack.enter_context(patch.object(Path, 'iterdir', autospec=True,
                side_effect=lambda _: iter([Path('/inert')] if nonempty else [])))
            stack.enter_context(patch.object(probe.os, 'readlink',
                side_effect=lambda path: 'mnt:[1]' if global_namespace or path.endswith('self/ns/mnt') else 'mnt:[2]'))
            stack.enter_context(patch.object(probe.hashlib, 'file_digest', create=True,
                return_value=types.SimpleNamespace(hexdigest=lambda: image_digest or self.IMAGE_SHA)))
            yield verifier, guard

    def test_rootfs_requires_exact_readonly_global_loop_mount_and_empty_mountpoints(self):
        with self.rootfs_fixture() as (verifier, guard):
            probe.guard_rootfs(self.ROOTFS, self.IMAGE_SHA, verifier)
        self.assertEqual(guard.call_args_list, [call(self.ROOTFS),
                                               call(self.ROOTFS.parent / 'image.img')])
        self.assertEqual(verifier.secure_record.call_count, 2)
        self.assertEqual(verifier.single_record.call_args_list,
                         [call(self.ROOTFS / 'etc/inky-studio'),
                          call(self.ROOTFS / 'var/lib/inkyos')])

    def test_rootfs_refuses_mount_and_image_identity_failures(self):
        for changes in ({'options': 'rw,nosuid,nodev'}, {'options': 'ro,nodev'},
                        {'options': 'ro,nosuid,nodev,noexec'}, {'filesystem': 'xfs'},
                        {'source': '/dev/sda2'}, {'source': '/dev/loop7p1'},
                        {'global_namespace': False}, {'block_readonly': '0'},
                        {'backing': '/other/image.img'}, {'image_digest': '0' * 64},
                        {'duplicate_mount': True}, {'parent_mode': 0o755},
                        {'nonempty': True}):
            with self.subTest(changes=changes), self.rootfs_fixture(**changes) as (verifier, _):
                with self.assertRaises(ValueError):
                    probe.guard_rootfs(self.ROOTFS, self.IMAGE_SHA, verifier)

    def test_rootfs_refuses_path_or_digest_before_filesystem_access(self):
        with patch.object(probe, 'guard_path') as guard:
            for path, digest in ((Path('/tmp/root'), self.IMAGE_SHA),
                                 (self.ROOTFS, 'not-a-pin'),
                                 (Path('/var/lib/inkyos-build/factory-installed.A1/../root'), self.IMAGE_SHA)):
                with self.subTest(path=path, digest=digest), self.assertRaises(ValueError):
                    probe.guard_rootfs(path, digest, Mock())
        guard.assert_not_called()

    def test_guard_path_checks_every_ancestor_and_rejects_unsafe_metadata(self):
        target = Path('/var/lib/inkyos-build/inert/source.py')
        ancestors = list(reversed((target, *target.parents)))
        good = types.SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o755, st_nlink=1)
        file_info = types.SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o644, st_nlink=1)
        with patch.object(Path, 'lstat', autospec=True,
                side_effect=lambda path: file_info if path == target else good) as lstat, \
                patch.object(probe.os, 'listxattr', create=True, return_value=[]) as attrs:
            probe.guard_path(target)
        self.assertEqual(lstat.call_args_list, [call(path) for path in ancestors])
        self.assertEqual(attrs.call_args_list,
                         [call(path, follow_symlinks=False) for path in ancestors])
        for replacement, xattrs in (
                (types.SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o777, st_nlink=1), []),
                (types.SimpleNamespace(st_uid=1000, st_gid=0, st_mode=stat.S_IFDIR | 0o755, st_nlink=1), []),
                (types.SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFLNK | 0o777, st_nlink=1), []),
                (good, ['system.posix_acl_access'])):
            with self.subTest(replacement=replacement, attrs=xattrs), \
                    patch.object(Path, 'lstat', return_value=replacement), \
                    patch.object(probe.os, 'listxattr', create=True, return_value=xattrs), \
                    self.assertRaises(ValueError):
                probe.guard_path(target)


class InstalledProbePreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='inkyos-installed-inert-')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.service = Mock()
        def write_new(path, raw, mode=0o600):
            with path.open('xb') as stream:
                stream.write(raw)
            path.chmod(mode)
        self.service.write_new.side_effect = write_new
        self.chown = patch.object(probe.os, 'chown')
        self.chown.start(); self.addCleanup(self.chown.stop)

    def test_fresh_fixture_has_explicit_pending_permission_and_empty_data(self):
        case = probe.prepare_case(self.work, 'fresh', self.service)
        permission = case / 'state/factory-permission'
        self.assertEqual({path.name for path in permission.iterdir()}, {'lock', 'pending.json'})
        self.assertEqual(json.loads((permission / 'pending.json').read_bytes()),
                         {'version': 1, 'operation': 'create-initialization-authority'})
        self.assertEqual((permission / 'lock').read_bytes(), b'')
        self.assertEqual(list((case / 'data').iterdir()), [])
        self.assertFalse((case / 'state/initialization').exists())

    def test_missing_permission_fixture_really_has_no_permission_directory(self):
        case = probe.prepare_case(self.work, 'no_permission', self.service)
        self.assertFalse((case / 'state/factory-permission').exists())
        self.assertFalse((case / 'state/initialization').exists())
        self.assertEqual(list((case / 'data').iterdir()), [])

    def test_consumed_without_authority_copies_only_opaque_fixture_bytes(self):
        fresh = self.work / 'fresh'
        raw = b'INERT TEST BYTES; NOT A CREDENTIAL\n'
        with patch.object(probe, 'regular', return_value=raw) as read:
            case = probe.prepare_case(self.work, 'consumed_no_authority', self.service, fresh)
        read.assert_called_once_with(fresh / 'data/credentials.json', 8192, uid=1000, mode=0o600)
        self.assertEqual((case / 'data/credentials.json').read_bytes(), raw)
        self.assertEqual({path.name for path in (case / 'state/factory-permission').iterdir()},
                         {'lock', 'consumed.json'})
        self.assertFalse((case / 'state/initialization').exists())

    def test_restart_cannot_accidentally_prepare_a_new_fixture(self):
        with patch.object(probe, 'new_directory') as mkdir, self.assertRaises(ValueError):
            probe.prepare_case(self.work, 'restart', self.service)
        mkdir.assert_not_called()


class InstalledProbeOrchestrationTests(unittest.TestCase):
    @contextlib.contextmanager
    def orchestration(self):
        """All process, target filesystem and OS identity APIs are replaced."""
        args = types.SimpleNamespace(
            installed_composition=True,
            fixture_token='01234567',
            rootfs=Path('/var/lib/inkyos-build/factory-installed.A1/root'),
            prepared_image_sha256='a' * 64,
            sources_dir=Path('/var/lib/inkyos-build/inert-input/sources'),
            wheels_dir=Path('/var/lib/inkyos-build/inert-input/wheels'),
            support_manifest=Path('/var/lib/inkyos-build/inert-input/support.json'))
        support = {'python_version': '3.13.5', 'trees': {'usr/local/lib': {
            '.': {'type': 'directory', 'uid': 0, 'gid': 0, 'mode': '0755', 'xattrs': probe.EMPTY_XATTRS},
            'inkyos': {'type': 'directory', 'uid': 0, 'gid': 0, 'mode': '0700', 'xattrs': probe.EMPTY_XATTRS}}}}
        material = {'scripts/' + name: b'# inert OS module; never executed\n' for name in probe.MODULES}
        material['scripts/manifest-rootfs.py'] = b'# inert inventory; never executed\n'
        material['staging/bootstrap/inkyos-factory-fixture.service'] = (
            ROOT / 'staging/bootstrap/inkyos-factory-fixture.service').read_bytes()
        additions = {name: material['scripts/' + name] for name in probe.MODULES}
        additions[probe.OBSERVER_NAME] = probe.OBSERVER
        tree = probe.expected_local_tree(support, additions)
        modules = {'.': tree['inkyos'], **{key[len('inkyos/'):]: value
                   for key, value in tree.items() if key.startswith('inkyos/')}}
        service = Mock()
        service.CAPS = dict.fromkeys(('CAP_CHOWN', 'CAP_DAC_OVERRIDE', 'CAP_KILL', 'CAP_SETGID', 'CAP_SETUID'))
        service.trusted_builder.return_value = 123
        service.group_path.side_effect = lambda value: Path('/sys/fs/cgroup') / value.lstrip('/')
        service.command.return_value = b'not-found\n'
        verifier = Mock()
        verifier.load_lock.return_value = {'support_manifest_sha256': 'b' * 64}
        material['config/factory-exporter.lock.json'] = encoded(verifier.load_lock.return_value)
        verifier.load_support.return_value = (support, {})
        verifier.expected_bundle.return_value = {'inert': 'bundle'}
        verifier.inventory_module.inventory.return_value = modules
        baseline = {'bundle_manifest_sha256': 'c' * 64, 'support_manifest_sha256': 'b' * 64}
        events = []
        verifier.verify.side_effect = lambda *args: events.append('verify') or baseline
        identity = types.SimpleNamespace(st_dev=1, st_ino=2)
        def read(path, maximum=1024 * 1024, **options):
            if path.name == 'credentials.json':
                return b'INERT TEST BYTES; NOT A CREDENTIAL\n'
            if path.parent.name == 'observations':
                return encoded({'schema_version': 1, 'scope': 'exec-start-pre-only',
                                'control_group': '/system.slice/' + path.stem, 'checks_passed': True})
            case = path.name.removeprefix('hook-').removesuffix('.stdout')
            return encoded(probe.STUDIO_RESULT if case == 'validate' else probe.HOOK_RESULTS[case])
        def observed(service, unit):
            success = unit.endswith(('-fresh.service', '-restart.service', '-validate.service'))
            return {'ControlGroup': '', 'ExecMainCode': '1', 'ExecMainStatus': '0' if success else '1',
                    'Result': 'success' if success else 'exit-code',
                    'TasksMax': '2', 'EffectiveTasksMax': '2', 'Type': 'oneshot',
                    'KillMode': 'control-group', 'Delegate': 'no', 'NoNewPrivileges': 'yes',
                    'PrivateDevices': 'yes', 'PrivateNetwork': 'yes', 'ProtectSystem': 'strict',
                    'ProtectHome': 'read-only', 'ProtectControlGroups': 'yes'}
        def entries(path):
            if path.name == 'data':
                return iter([path / 'credentials.json'])
            if path.name == 'factory-permission':
                return iter([path / 'lock', path / 'consumed.json'])
            raise AssertionError('Unexpected fixture tree read')
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(probe.sys, 'platform', 'linux'))
            stack.enter_context(patch.object(probe.sys, 'flags', types.SimpleNamespace(isolated=True, no_site=True)))
            stack.enter_context(patch.object(probe.sys, 'dont_write_bytecode', True))
            stack.enter_context(patch.object(probe.platform, 'machine', return_value='aarch64'))
            stack.enter_context(patch.object(probe.os, 'geteuid', return_value=0))
            stack.enter_context(patch.object(probe.os, 'close'))
            stack.enter_context(patch.object(probe.os, 'readlink', return_value='net:[fixture]'))
            stack.enter_context(patch.object(probe.os, 'stat', return_value=identity))
            stack.enter_context(patch.object(Path, 'stat', return_value=identity))
            stack.enter_context(patch.object(Path, 'is_file', return_value=True))
            stack.enter_context(patch.object(Path, 'iterdir', autospec=True, side_effect=entries))
            dependencies = stack.enter_context(patch.object(probe, 'load_dependencies', return_value=(service, verifier, material)))
            guard_rootfs = stack.enter_context(patch.object(probe, 'guard_rootfs'))
            stack.enter_context(patch.object(probe, 'guard_path'))
            mkdir = stack.enter_context(patch.object(probe, 'new_directory', side_effect=lambda *args: events.append('mkdir')))
            stack.enter_context(patch.object(probe, 'write_exact',
                side_effect=lambda service, path, raw, mode=0o600: service.write_new(path, raw, mode)))
            authority = stack.enter_context(patch.object(probe, 'inspect_authority'))
            prepare = stack.enter_context(patch.object(probe, 'prepare_case',
                side_effect=lambda work, case, service, fresh=None: work / case))
            stack.enter_context(patch.object(probe, 'private_snapshot', return_value={'inert': 'unchanged'}))
            stack.enter_context(patch.object(probe, 'regular', side_effect=read))
            wait = stack.enter_context(patch.object(probe, 'wait_unit', side_effect=observed))
            yield types.SimpleNamespace(args=args, service=service, verifier=verifier, events=events,
                                        guard_rootfs=guard_rootfs, mkdir=mkdir, prepare=prepare, wait=wait,
                                        dependencies=dependencies, authority=authority, observed=observed)

    def test_rootfs_and_bundle_refusals_precede_every_fixture_write(self):
        for failure in ('rootfs', 'bundle'):
            with self.subTest(failure=failure), self.orchestration() as fixture:
                target = fixture.guard_rootfs if failure == 'rootfs' else fixture.verifier.verify
                target.side_effect = ValueError('inert validation failure')
                report = probe.run(fixture.args)
                self.assertEqual(report['status'], 'FAIL')
                fixture.mkdir.assert_not_called()
                fixture.prepare.assert_not_called()
                fixture.service.write_new.assert_not_called()
                fixture.service.command.assert_not_called()

    def test_failure_after_start_attempt_still_stops_that_unit(self):
        with self.orchestration() as fixture:
            fixture.service.command.side_effect = [b'not-found\n', RuntimeError('PRIVATE INERT DIAGNOSTIC')]
            report = probe.run(fixture.args)
            self.assertEqual(report['status'], 'FAIL')
            self.assertTrue(report['all_units_stopped'])
            fixture.service.stop_unit.assert_called_once_with(
                UNIT, Path('/sys/fs/cgroup/system.slice') / UNIT)
            self.assertNotIn('PRIVATE INERT DIAGNOSTIC', json.dumps(report))

    def test_interruption_during_wait_still_stops_that_unit(self):
        with self.orchestration() as fixture:
            fixture.wait.side_effect = KeyboardInterrupt()
            report = probe.run(fixture.args)
            self.assertEqual(report['status'], 'FAIL')
            self.assertTrue(report['all_units_stopped'])
            fixture.service.stop_unit.assert_called_once_with(
                UNIT, Path('/sys/fs/cgroup/system.slice') / UNIT)

    def test_full_orchestration_restarts_same_fixture_and_reports_no_credentials(self):
        with self.orchestration() as fixture:
            report = probe.run(fixture.args)
            self.assertEqual(report['status'], 'PASS')
            self.assertEqual([item['case'] for item in report['cases']], list(probe.CASES))
            self.assertEqual([item.args[1] for item in fixture.prepare.call_args_list],
                             ['fresh', 'consumed_no_authority', 'no_permission'])
            starts = [item.args[0] for item in fixture.service.command.call_args_list
                      if item.args[0][0] == '/usr/bin/systemd-run']
            self.assertEqual(len(starts), 5)
            fresh_bind = next(value for value in starts[0] if value.startswith('--property=BindPaths='))
            self.assertIn(fresh_bind, starts[1])
            self.assertIn(fresh_bind, starts[2])
            self.assertNotEqual(starts[0][3], starts[2][3])
            self.assertIn('--unit=' + UNIT.replace('fresh', 'validate'), starts[1])
            self.assertEqual(starts[1][-6:], probe.validation_command())
            self.assertEqual(report['completed_case_count'], 4)
            self.assertEqual(report['studio_validation'], probe.STUDIO_RESULT)
            fixture.authority.assert_called_once()
            calls = fixture.service.method_calls
            stopped = calls.index(call.stop_unit(UNIT, Path('/sys/fs/cgroup/system.slice') / UNIT))
            validation_started = calls.index(call.command(starts[1]))
            self.assertLess(stopped, validation_started)
            self.assertEqual(fixture.verifier.verify.call_count, 2)
            self.assertEqual(fixture.events[0], 'verify')
            self.assertEqual(fixture.events[-1], 'verify')
            self.assertEqual(fixture.service.stop_unit.call_count, 10)
            self.assertTrue(report['all_units_stopped'])
            self.assertNotIn('INERT TEST BYTES', json.dumps(report))
            for flag in ('pre_observation_is_start_observation', 'credential_bytes_exported',
                         'writer_barrier_qualified', 'application_candidate_complete',
                         'image_recipe_activated', 'hardware_qualified'):
                self.assertIs(report[flag], False)

    def test_cleanup_failure_prevents_pass_and_does_not_skip_other_units(self):
        with self.orchestration() as fixture:
            # Five ordinary stops succeed; one of five final stops fails.
            fixture.service.stop_unit.side_effect = [None] * 5 + [OSError('inert'), None, None, None, None]
            report = probe.run(fixture.args)
            self.assertEqual(report['status'], 'FAIL')
            self.assertFalse(report['all_units_stopped'])
            self.assertEqual(fixture.service.stop_unit.call_count, 10)

    def test_invalid_fixture_tokens_fail_before_loading_dependencies(self):
        for token in ('', '0123456', '012345678', 'ABCDEF01', 'other/01', '../abcde', 'a' * 8 + '\n'):
            with self.subTest(token=repr(token)), self.orchestration() as fixture:
                fixture.args.fixture_token = token
                report = probe.run(fixture.args)
                self.assertEqual(report['status'], 'FAIL')
                fixture.dependencies.assert_not_called()
                fixture.mkdir.assert_not_called()

    def test_validation_failure_cannot_report_four_completed_cases(self):
        with self.orchestration() as fixture:
            def wait(service, unit):
                if unit.endswith('-validate.service'):
                    raise RuntimeError('inert validation failure')
                return fixture.observed(service, unit)
            fixture.wait.side_effect = wait
            report = probe.run(fixture.args)
            self.assertEqual(report['status'], 'FAIL')
            self.assertEqual(report['phase'], 'validate')
            self.assertEqual(report['completed_case_count'], 0)
            self.assertIsNone(report['studio_validation'])
            self.assertTrue(report['all_units_stopped'])
            self.assertEqual(fixture.service.stop_unit.call_count, 3)

    def test_observed_sandbox_regression_refuses_success_and_runs_cleanup(self):
        changes = {'Type': 'simple', 'KillMode': 'process', 'Delegate': 'yes',
                   'NoNewPrivileges': 'no', 'PrivateDevices': 'no', 'PrivateNetwork': 'no',
                   'ProtectSystem': 'no', 'ProtectHome': 'no', 'ProtectControlGroups': 'no',
                   'TasksMax': '3', 'EffectiveTasksMax': '3'}
        for key, value in changes.items():
            with self.subTest(key=key), self.orchestration() as fixture:
                fixture.wait.side_effect = lambda service, unit: {**fixture.observed(service, unit), key: value}
                report = probe.run(fixture.args)
                self.assertEqual(report['status'], 'FAIL')
                self.assertEqual(report['completed_case_count'], 0)
                self.assertTrue(report['all_units_stopped'])
                fixture.service.stop_unit.assert_called_once()

    def test_closed_pre_failure_is_reported_and_unit_is_stopped_before_any_hook_result(self):
        with self.orchestration() as fixture:
            regular = probe.regular
            read_paths = []
            def read(path, *args, **kwargs):
                read_paths.append(path)
                if path.parent.name == 'observations':
                    return encoded({'schema_version': 1, 'scope': 'exec-start-pre-only',
                                    'control_group': '/system.slice/' + UNIT,
                                    'checks_passed': False, 'failure_phase': 'critical_mounts'})
                return regular(path, *args, **kwargs)
            # The failed Pre has no hook exit fields; its receipt is read first.
            fixture.wait.side_effect = lambda *args: {'ControlGroup': ''}
            with patch.object(probe, 'regular', side_effect=read):
                report = probe.run(fixture.args)
            self.assertEqual(report['status'], 'FAIL')
            self.assertEqual(report['pre_failure_phase'], 'critical_mounts')
            self.assertEqual(report['completed_case_count'], 0)
            self.assertIsNone(report['studio_validation'])
            self.assertTrue(report['all_units_stopped'])
            self.assertTrue(report['target_execution_attempted'])
            fixture.authority.assert_not_called()
            fixture.service.stop_unit.assert_called_once_with(UNIT, Path('/sys/fs/cgroup/system.slice') / UNIT)
            self.assertEqual(len(read_paths), 1)
            self.assertEqual(read_paths[0].parent.name, 'observations')

    def test_missing_pre_receipt_preserves_failure_without_inventing_phase(self):
        with self.orchestration() as fixture, patch.object(probe, 'regular', side_effect=FileNotFoundError('PRIVATE INERT ERROR')):
            report = probe.run(fixture.args)
            self.assertEqual(report['status'], 'FAIL')
            self.assertIsNone(report['pre_failure_phase'])
            self.assertTrue(report['all_units_stopped'])
            self.assertNotIn('PRIVATE INERT ERROR', json.dumps(report))
            fixture.service.stop_unit.assert_called_once()

    def test_observer_imports_only_stdlib_and_cannot_spawn_an_application(self):
        tree = ast.parse(probe.OBSERVER.decode('ascii'))
        imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                   for alias in node.names}
        imports |= {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        self.assertEqual(imports, {'hashlib', 'json', 'os', 're', 'stat', 'sys', 'types', 'pathlib'})
        calls = {node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute)}
        self.assertFalse(calls & {'Popen', 'system', 'fork', 'posix_spawn', 'execve', 'spawn'})


if __name__ == '__main__':
    unittest.main()
