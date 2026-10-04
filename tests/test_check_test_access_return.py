"""Inert v2 return orchestration: fake commands and synthetic private output."""
import base64
import contextlib
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/check-test-access-return-linux.sh'


def driver():
    source = SCRIPT.read_text().split("<<'PY_ACCESS_RETURN'\n", 1)[1].rsplit('\nPY_ACCESS_RETURN', 1)[0]
    namespace = {'__name__': 'inert_access_return_runner'}
    exec(compile(source, str(SCRIPT), 'exec'), namespace)
    return namespace


def historical():
    path = ROOT / 'scripts/check-test-enrollment-return-linux.sh'
    source = path.read_text().split("<<'PY_RETURN'\n", 1)[1].rsplit('\nPY_RETURN', 1)[0]
    namespace = {'__name__': 'inert_historical_primitives'}
    exec(compile(source, str(path), 'exec'), namespace)
    return namespace


def controller():
    path = ROOT / 'scripts/verify-test-access-return.py'
    spec = importlib.util.spec_from_file_location('access_return_wrapper_controller', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def outcome(module, code):
    result = module.summary(native=True)
    result.update(status=('PASS', 'FAIL', 'INVALID')[code], passed=code == 0,
        native_readonly_evidence=code != 2, error=(None, 'return_incomplete', 'invalid_input')[code],
        context_written=code == 0, private_output_files_written=2 if code == 0 else 0)
    result['checks'] = {name: code == 0 or code == 1 and index < 4 for index, name in enumerate(module.CHECKS)}
    return result


def context_fixture(module):
    policy = module.policy
    key = 'ssh-ed25519 ' + base64.b64encode(struct.pack('>I', 11) + b'ssh-ed25519'
                                           + struct.pack('>I', 32) + b'h' * 32).decode()
    manifest = b'fixture-manifest\n'
    profile = {'schema_version': 2, 'kind': 'test-lan-enrollment', 'purpose': 'test-enroll-and-stop',
        'state': 'enrollment-pending', 'application_source_commit': policy.SOURCE,
        'application_manifest_sha256': policy.MANIFEST_HASH, 'parent_image_sha256': policy.PARENT_IMAGE_SHA256,
        'operator_public_key': key, 'challenge': 'a' * 64, 'country_requested': 'FR',
        'access_runtime_manifest_sha256': module.digest(manifest), **dict.fromkeys(policy.FALSE_FIELDS, False)}
    raw = policy.canonical(profile)
    expected = {'profile_bytes': raw, 'profile_sha256': module.digest(raw), 'manifest_bytes': manifest}
    value = module._context(profile, expected['profile_sha256'], module.digest(policy.public_key(key)), module.digest(manifest))
    return expected, {'context.json': policy.canonical(value),
                      'known_hosts': ('[inky-' + '1' * 32 + '.local]:2222 ' + key + '\n').encode()}


class WrapperTests(unittest.TestCase):
    def test_help_and_argument_failures_never_enter_native_path(self):
        done = subprocess.run(['/bin/bash', str(SCRIPT), '--help'], capture_output=True, timeout=3)
        self.assertEqual(done.returncode, 0)
        self.assertIn(b'READ ONLY', done.stdout)
        self.assertIn(b'EXPECTED_SIZE EXPECTED_SHA256', done.stdout)
        self.assertIn(b'16 files', done.stdout)
        done = subprocess.run(['/bin/bash', str(SCRIPT)], capture_output=True, timeout=3)
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, b'')

    def test_dependency_closure_and_two_reviewed_entry_pins(self):
        runner = driver()
        self.assertEqual(len(runner['SOURCES']), 16)
        self.assertEqual(len(runner['EXPORT']), 20)
        self.assertEqual(len(runner['INPUT_FILES']), 38)
        for name, pin in ((runner['PRIMITIVES'], runner['PRIMITIVES_SHA256']),
                          (runner['CONTROLLER'], runner['CONTROLLER_SHA256'])):
            self.assertEqual(hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest(), pin)
        self.assertEqual(runner['OUTPUT_FILES'], {'context.json', 'known_hosts'})
        self.assertFalse(any('private_key' in name or 'profile.json' in name for name in runner['INPUT_FILES']))
        self.assertEqual(runner['REPORTS'], controller().export_contract.REQUIRED_REPORTS)

    def test_result_contract_accepts_all_native_codes_and_context_write_failure(self):
        runner, module, lib = driver(), controller(), historical()
        for code in (0, 1, 2):
            value = outcome(module, code)
            self.assertEqual(runner['validate_result'](code, json.dumps(value).encode(), module, lib['parse']), value)
        value = outcome(module, 0)
        value.update(status='INVALID', passed=False, error='readonly_cleanup_failed', context_written=False)
        self.assertEqual(runner['validate_result'](2, json.dumps(value).encode(), module, lib['parse']), value)

    def test_result_rejects_arbitrary_fields_privileges_and_fixture_pass(self):
        runner, module, lib = driver(), controller(), historical()
        original = outcome(module, 0)
        cases = [{'secret': 'PRIVATE'}, {'schema_version': True}, {'observation_source': 'fixture'},
                 {'error': 'PRIVATE'}, {'context_written': False}, {'private_output_files_written': 1},
                 {'private_output_files_written': True}, {'native_readonly_evidence': 1}]
        cases += [{name: True} for name in runner['FALSE_FIELDS']]
        cases += [{name: 0} for name in runner['FALSE_FIELDS']]
        checks = dict(original['checks']); checks[next(iter(checks))] = 1
        cases.append({'checks': checks})
        for change in cases:
            with self.subTest(change=change), self.assertRaises(ValueError):
                runner['validate_result'](0, json.dumps({**original, **change}).encode(), module, lib['parse'])
        for raw in (b'PRIVATE', b'x' * 65537, b'{"schema_version":1,' + json.dumps(original).encode()[1:]):
            with self.assertRaises(ValueError): runner['validate_result'](0, raw, module, lib['parse'])

    def test_sudo_account_is_bound_to_name_uid_and_primary_gid(self):
        runner = driver()
        row = SimpleNamespace(pw_name='builder', pw_uid=1200, pw_gid=1200)
        valid = {'SUDO_USER': 'builder', 'SUDO_UID': '1200', 'SUDO_GID': '1200'}
        with patch.object(runner['pwd'], 'getpwnam', return_value=row), \
             patch.object(runner['pwd'], 'getpwuid', return_value=row):
            self.assertEqual(runner['account'](valid), (1200, 1200))
            for change in ({'SUDO_USER': 'root'}, {'SUDO_UID': '0'}, {'SUDO_UID': '01200'},
                           {'SUDO_UID': '1201'}, {'SUDO_GID': '0'}, {'SUDO_GID': '1201'}, {'SUDO_USER': '../x'}):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    runner['account']({**valid, **change})

    def test_context_pair_must_bind_expected_profile_and_host_wire_key(self):
        runner, module = driver(), controller()
        expected, raws = context_fixture(module)
        self.assertTrue(runner['validate_context'](raws, module, expected))
        for name, raw in [('known_hosts', raws['known_hosts'].replace(b':2222', b':22')),
                          ('known_hosts', raws['known_hosts'] + b'PRIVATE\n'),
                          ('context.json', module.policy.canonical({**json.loads(raws['context.json']), 'PRIVATE': 'x'}))]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                runner['validate_context']({**raws, name: raw}, module, expected)
        value = json.loads(raws['context.json']); value['bindings']['host_public_key_sha256'] = 'f' * 64
        with self.assertRaises(ValueError):
            runner['validate_context']({**raws, 'context.json': module.policy.canonical(value)}, module, expected)

    def test_invalid_inputs_refuse_before_loading_sources_or_devices(self):
        runner = driver()
        runner['primitives'] = lambda _: self.fail('must refuse before filesystem access')
        for returned, expected, path in ((0, 512, '/var/lib/inkyos-build/access-return.12345678'),
                                        (1024, 513, '/var/lib/inkyos-build/access-return.12345678'),
                                        (512, 1024, '/var/lib/inkyos-build/access-return.12345678'),
                                        (1024, 512, '/tmp/fixture'),
                                        (33 * 1024**3, 512, '/var/lib/inkyos-build/access-return.12345678')):
            with self.subTest(returned=returned, expected=expected, path=path), self.assertRaises(ValueError):
                runner['main'](Path(path), 'a' * 64, returned, 'b' * 64, expected, 'c' * 64)


class SyntheticOutputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name)
        self.parent.chmod(0o755)
        self.runner, self.lib = driver(), historical()
        self.lib['ancestors'] = lambda path: self.assertEqual(path, self.parent)
        self.real_fstat = os.fstat
        def fixture_root_stat(fd):
            info = self.real_fstat(fd)
            return SimpleNamespace(**{name: getattr(info, name) for name in dir(info) if name.startswith('st_')},
                                   )
        self.fake_stat = fixture_root_stat
        self.raws = {'context.json': b'fixture-context\n', 'known_hosts': b'fixture-host\n'}

    @contextlib.contextmanager
    def ownership_seam(self):
        # No chown is performed by tests; metadata is projected solely for the
        # root writer seam, while bytes/no-follow/modes/links stay real.
        owner = (os.getuid(), os.getgid())
        changed = set()
        def fstat(fd):
            value = self.fake_stat(fd)
            if value.st_ino not in changed: value.st_uid = value.st_gid = 0
            return value
        def chown(fd, uid, gid):
            self.assertEqual((uid, gid), owner)
            changed.add(self.real_fstat(fd).st_ino)
        with patch.object(os, 'fstat', side_effect=fstat), patch.object(os, 'fchown', side_effect=chown):
            yield owner

    def test_export_has_exact_two_files_private_modes_and_no_overwrite(self):
        destination = self.parent / 'access-context.12345678'
        with self.ownership_seam() as owner:
            self.runner['export_context'](destination, self.raws, owner, self.lib)
            self.assertEqual({p.name for p in destination.iterdir()}, set(self.raws))
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            for name, raw in self.raws.items():
                self.assertEqual((destination / name).read_bytes(), raw)
                self.assertEqual((destination / name).stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                self.runner['export_context'](destination, self.raws, owner, self.lib)

    def test_export_refuses_unsafe_parent_and_existing_symlink(self):
        destination = self.parent / 'access-context.12345678'
        self.parent.chmod(0o777)
        with self.ownership_seam() as owner, self.assertRaises(ValueError):
            self.runner['export_context'](destination, self.raws, owner, self.lib)
        self.assertFalse(destination.exists())
        self.parent.chmod(0o755)
        destination.symlink_to(self.parent / 'never-open')
        with self.ownership_seam() as owner, self.assertRaises(FileExistsError):
            self.runner['export_context'](destination, self.raws, owner, self.lib)

    def test_corruption_before_reread_never_hands_directory_to_user(self):
        destination = self.parent / 'access-context.12345678'
        real_open = os.open
        corrupted = False
        def changed(path, flags, *args, **kwargs):
            nonlocal corrupted
            if path == 'context.json' and flags & os.O_NONBLOCK and not corrupted:
                (destination / 'context.json').write_bytes(b'corrupted\n')
                corrupted = True
            return real_open(path, flags, *args, **kwargs)
        with self.ownership_seam() as owner, patch.object(os, 'open', side_effect=changed), self.assertRaises(ValueError):
            self.runner['export_context'](destination, self.raws, owner, self.lib)
        self.assertTrue(corrupted)


class OrchestrationTests(unittest.TestCase):
    def simulate(self, *, controller_code=0, cleanup_failure=False, mutate_source=False):
        runner, lib, module = driver(), historical(), controller()
        expected, context = context_fixture(module)
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary) / 'access-return.12345678'
            work.mkdir(mode=0o700)
            (work / 'sources').mkdir(mode=0o700); (work / 'expected').mkdir(mode=0o700)
            image_raw, returned_raw = b'e' * 512, b'r' * 1024
            blobs = {runner['RUNNER']: SCRIPT.read_bytes(), 'returned.img': returned_raw}
            blobs.update({'sources/' + name: (ROOT / 'scripts' / name).read_bytes() for name in runner['SOURCES']})
            blobs.update({'expected/' + name: b'fixture-data\n' for name in runner['EXPORT']})
            blobs['expected/' + runner['IMAGE']] = image_raw
            blobs['expected/manifest.json'] = json.dumps({'image': {'filename': runner['IMAGE'],
                'size_bytes': 512, 'sha256': hashlib.sha256(image_raw).hexdigest()}}).encode()
            seals = {name: hashlib.sha256(raw).hexdigest() for name, raw in blobs.items()}
            inputs = json.dumps({'schema_version': 1, 'files': seals}).encode()
            for name, raw in {**blobs, 'inputs.json': inputs}.items():
                path = work / name; path.write_bytes(raw)
                path.chmod(0o600 if name.startswith('expected/') or name == 'returned.img' else 0o444)
            def read_file(path, mode, *, image_size=None):
                if str(path) == '/var/lib/inkyos-build/owner': return b'inkyos-builder-v1\n', '', None
                info = path.lstat()
                self.assertEqual(stat.S_IMODE(info.st_mode), mode)
                raw = path.read_bytes()
                if image_size is not None: self.assertEqual(len(raw), image_size)
                return None if image_size is not None else raw, hashlib.sha256(raw).hexdigest(), lib['stamp'](info)
            lib.update(read_file=read_file, ancestors=lambda path: None, directory=lambda path: None)
            calls, mounted, loops, exports = [], set(), [], []
            def command(*args, **kwargs):
                calls.append(args)
                raw, code = b'', 0
                if args[:2] == ('losetup', '--read-only'):
                    loops.append('/dev/loop7'); raw = b'/dev/loop7\n'
                elif args[:2] == ('losetup', '--list'): raw = ('\n'.join(loops) + '\n').encode()
                elif args[:2] == ('losetup', '-d'): loops.remove(args[2])
                elif args[0] == 'lsblk': raw = b'loop\npart\npart\n'
                elif args[0] == 'blkid': raw = b'vfat\n' if args[-1].endswith('p1') else b'ext4\n'
                elif args[0] == 'mount': mounted.add(args[-1])
                elif args[0] == 'findmnt': code = 0 if args[-1] in mounted else 1
                elif args[0] == 'umount':
                    if cleanup_failure: raise TimeoutError('PRIVATE')
                    mounted.remove(args[1])
                elif args[:2] == ('/usr/bin/python3', '-I'):
                    code = controller_code
                    raw = json.dumps(outcome(module, code)).encode()
                    if code == 0:
                        target = work / 'private-context'; target.mkdir(mode=0o700)
                        for name, content in context.items():
                            (target / name).write_bytes(content); (target / name).chmod(0o600)
                    if mutate_source:
                        target = work / 'sources' / runner['CONTROLLER']
                        target.chmod(0o600); target.write_bytes(b'changed source\n')
                else: self.fail('unexpected command ' + repr(args))
                return subprocess.CompletedProcess(args, code, raw)
            lib['command'] = command
            runner['primitives'] = lambda path: lib
            runner['account'] = lambda environ: (os.getuid(), os.getgid())
            runner['load_controller'] = lambda path: module
            def export(destination, raws, owner, observed_lib):
                self.assertEqual(mounted, set()); self.assertEqual(loops, [])
                self.assertEqual(raws, context)
                exports.append(destination.name)
            runner['export_context'] = export
            original_match, original_text, original_exists = runner['re'].fullmatch, Path.read_text, Path.exists
            def match(pattern, value, *args, **kwargs):
                if type(pattern) is str and pattern.startswith('/var/lib/inkyos-build/access-return') and value == str(work): return object()
                return original_match(pattern, value, *args, **kwargs)
            def text(path, *args, **kwargs):
                if str(path) == '/proc/net/dev': return 'header\nheader\n lo: 0\n'
                if str(path) == '/sys/class/block/loop7/ro': return '1\n'
                return original_text(path, *args, **kwargs)
            with patch.object(runner['re'], 'fullmatch', side_effect=match), \
                 patch.object(module, 'ReadTree', return_value=SimpleNamespace(close=lambda: None)), \
                 patch.object(module, 'expected_export', return_value=expected), \
                 patch.object(Path, 'read_text', text), \
                 patch.object(Path, 'exists', lambda path: True if str(path) in {'/dev/loop7p1', '/dev/loop7p2'} else original_exists(path)), \
                 patch.object(os, 'readlink', side_effect=lambda path: 'own' if '/self/' in path else 'init'), \
                 patch.object(runner['signal'], 'signal'), patch('builtins.print') as output:
                status = runner['main'](work, hashlib.sha256(inputs).hexdigest(), 1024,
                    hashlib.sha256(returned_raw).hexdigest(), 512, hashlib.sha256(image_raw).hexdigest())
            report = json.loads((work / 'report.json').read_bytes())
            self.assertFalse(report['hardware_qualified'])
            self.assertFalse(report['connection_authorized'])
            self.assertNotIn('PRIVATE', repr(output.call_args))
            return status, report, calls, exports

    def test_native_pass_exports_only_after_both_readonly_mounts_and_loop_cleanup(self):
        status, report, calls, exports = self.simulate()
        self.assertEqual(status, 0)
        self.assertTrue(report['private_context_exported'])
        self.assertEqual(exports, ['access-context.12345678'])
        mounts = [call for call in calls if call[0] == 'mount']
        self.assertEqual([call[4] for call in mounts], ['ro,noload,noatime,nosuid,nodev,noexec', 'ro,noatime,nosuid,nodev,noexec'])
        self.assertTrue(any(call[:2] == ('losetup', '--read-only') for call in calls))

    def test_native_failure_never_exports_context_but_cleans_up(self):
        status, report, calls, exports = self.simulate(controller_code=1)
        self.assertEqual(status, 1)
        self.assertEqual(exports, [])
        self.assertTrue(report['checks']['mounts_removed'])
        self.assertTrue(report['checks']['loop_detached'])

    def test_cleanup_or_post_comparison_source_change_prevents_export(self):
        for changes in ({'cleanup_failure': True}, {'mutate_source': True}):
            with self.subTest(changes=changes):
                status, report, calls, exports = self.simulate(**changes)
                self.assertEqual(status, 2)
                self.assertEqual(exports, [])
                self.assertFalse(report['private_context_exported'])
                if changes.get('cleanup_failure'):
                    self.assertFalse(any(call[:2] == ('losetup', '-d') for call in calls))


if __name__ == '__main__':
    unittest.main()
