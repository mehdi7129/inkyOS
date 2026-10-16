"""Offline support proposals: real bytes/maps, no target execution or ABI claim."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_factory_exporter_rootfs import wheel_bytes


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('system_support_plan_test', ROOT / 'scripts/plan-factory-system-support.py')
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)
runtime = planner.runtime
sha = planner.exporter.sha


def elf(marker=b'', *, needed=(), rpath=None, runpath=None, interpreter=None, soname=None):
    """Section-free, structurally real ELF64 AArch64 with PT_DYNAMIC strings."""
    strings = bytearray(b'\0')
    entries = []
    for tag, value in [(1, name) for name in needed] + [(tag, value) for tag, value in
                       ((15, rpath), (29, runpath), (14, soname)) if value is not None]:
        entries.append((tag, len(strings))); strings.extend(value.encode() + b'\0')
    phnum = 3 if interpreter else 2
    dynamic_offset = 64 + phnum * 56
    string_offset = dynamic_offset + (len(entries) + 3) * 16
    address = 0x10000
    dynamic = [(5, address + string_offset), (10, len(strings)), *entries, (0, 0)]
    interp_offset = string_offset + len(strings)
    interp_raw = (interpreter.encode() + b'\0') if interpreter else b''
    size = interp_offset + len(interp_raw) + len(marker)
    header = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01' + b'\0' * 9,
                         3, 183, 1, 0, 64, 0, 0, 64, 56, phnum, 64, 0, 0)
    load = struct.pack('<IIQQQQQQ', 1, 5, 0, address, address, size, size, 0x1000)
    dyn = struct.pack('<IIQQQQQQ', 2, 4, dynamic_offset, address + dynamic_offset,
                      address + dynamic_offset, len(dynamic) * 16, len(dynamic) * 16, 8)
    interp = struct.pack('<IIQQQQQQ', 3, 4, interp_offset, address + interp_offset,
                         address + interp_offset, len(interp_raw), len(interp_raw), 1) if interpreter else b''
    return header + load + dyn + interp + b''.join(struct.pack('<QQ', *row) for row in dynamic) + strings + interp_raw + marker


def observation(**fields):
    return {**dict(needed=[], rpath=None, runpath=None, soname=None, interpreter=None), **fields}


def cache(rows=()):
    strings = bytearray()
    entries = []
    start = 48 + len(rows) * 24
    for name, path, flags, hwcap in rows:
        key = start + len(strings); strings.extend(name.encode() + b'\0')
        value = start + len(strings); strings.extend(path.encode() + b'\0')
        entries.append(struct.pack('<iIIIQ', flags, key, value, 0, hwcap))
    return b'glibc-ld.so.cache1.1' + struct.pack('<II', len(rows), len(strings)) + b'\x02\0\0\0' + b'\0' * 16 + b''.join(entries) + strings


READELF = '''ELF Header:
  Class:                             ELF64
  Data:                              2's complement, little endian
  Machine:                           AArch64
Program Headers:
  INTERP         0x000040 0x0000000000010040 0x0000000000010040 0x00001b 0x00001b R   0x1
      [Requesting program interpreter: /lib/ld-linux-aarch64.so.1]
Dynamic section at offset 0x80 contains 5 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x000000000000000f (RPATH)              Library rpath: [$ORIGIN/../libs]
 0x000000000000000e (SONAME)             Library soname: [fixture.so]
 0x0000000000000000 (NULL)               0x0
'''


class ParsingTests(unittest.TestCase):
    def test_readelf_fields_from_gnu_output(self):
        result = planner.parse_readelf(elf(), READELF)
        self.assertEqual(result['needed'], ['libc.so.6'])
        self.assertEqual(result['rpath'], '$ORIGIN/../libs')
        self.assertEqual(result['soname'], 'fixture.so')
        self.assertEqual(result['interpreter'], '/lib/ld-linux-aarch64.so.1')

    def test_malformed_or_wrong_architecture_refused(self):
        for raw in (b'bad', elf()[:63], elf()[:18] + b'\x3e\0' + elf()[20:]):
            with self.subTest(raw=raw[:20]), self.assertRaises(planner.Refused):
                planner.parse_readelf(raw, READELF)

    def test_unknown_dangerous_dynamic_features_refused(self):
        for tag, value in (('AUDIT', 'Library audit: [evil.so]'), ('FLAGS_1', 'Flags: NODEFLIB')):
            with self.subTest(tag=tag), self.assertRaises(planner.Refused):
                planner.parse_readelf(elf(), READELF + ' 0x00000001 (' + tag + ') ' + value + '\n')

    def test_duplicate_needed_and_broken_output_refused(self):
        for text in (READELF.replace('Machine:', 'Other:').replace('AArch64', 'x86-64'),
                     READELF + ' 0x00000001 (NEEDED) Shared library: [libc.so.6]\n',
                     READELF.replace('Shared library: [libc.so.6]', 'opaque format')):
            with self.subTest(text=text[-100:]), self.assertRaises(planner.Refused):
                planner.parse_readelf(elf(), text)

    def test_cache_1_1_retains_all_hardware_and_abi_candidates(self):
        result = planner.parse_cache(cache([('libc.so.6', '/lib/libc.so.6', 0xa03, 0),
                                            ('libc.so.6', '/lib/glibc-hwcaps/fast/libc.so.6', 0xa03, 7)]))
        self.assertEqual(len(result['libc.so.6']), 2)
        self.assertEqual(result['libc.so.6'][1]['hwcap'], 7)

    def test_cache_malformed_offsets_and_unsupported_format_refused(self):
        good = cache([('x.so', '/lib/x.so', 0xa03, 0)])
        bad = bytearray(good); struct.pack_into('<I', bad, 52, 1)
        for raw in (b'ld.so-1.7.0', good[:-1], bytes(bad), good[:28] + b'\x01' + good[29:]):
            with self.subTest(raw=raw[:30]), self.assertRaises(planner.Refused):
                planner.parse_cache(raw)

    def test_cache_escape_refused(self):
        with self.assertRaises(planner.Refused):
            planner.parse_cache(cache([('x.so', '/../outside.so', 0xa03, 0)]))

    @unittest.skipUnless(sys.platform.startswith('linux') and Path('/usr/bin/readelf').exists(), 'native Linux readelf only')
    def test_real_builder_readelf_on_inert_arm64_elf(self):
        path = Path('/usr/bin/readelf').resolve()
        tool = planner.Readelf(path, sha(path.read_bytes()))
        result = tool(elf(needed=['libc.so.6'], rpath='$ORIGIN/../libs',
                          interpreter='/lib/ld-linux-aarch64.so.1'))
        self.assertEqual(result['needed'], ['libc.so.6'])
        self.assertEqual(result['rpath'], '$ORIGIN/../libs')


class ClosureTests(unittest.TestCase):
    def setUp(self):
        self.records = {}
        self.raw = {}
        self.observations = {}
        self.loader = {'interpreter': '/lib/ld-linux-aarch64.so.1', 'default_search_paths': ['lib']}
        self.dir('.')
        self.dir('lib')
        self.dir('app')
        self.dir('app/libs')

    def dir(self, path):
        self.records[path] = {'type': 'directory'}

    def file(self, path, **fields):
        self.records[path] = {'type': 'file'}
        self.raw[path] = path.encode()
        self.observations[self.raw[path]] = observation(**fields)

    def run_closure(self, roots=('app/a.so',)):
        closure = planner.Closure(self.records, {'lib', 'app'}, ['etc/ld.so.cache'], self.loader,
                                  self.raw.__getitem__, self.observations.__getitem__)
        return closure.run(roots)

    def test_transitive_rpath_reaches_grandchild(self):
        self.file('app/a.so', needed=['b.so'], rpath='$ORIGIN/libs')
        self.file('app/libs/b.so', needed=['c.so'])
        self.file('app/libs/c.so')
        result = self.run_closure()
        self.assertTrue(result['complete_without_conflicts'])
        self.assertEqual(result['files'], ['app/a.so', 'app/libs/b.so', 'app/libs/c.so'])

    def test_runpath_is_direct_only(self):
        self.file('app/a.so', needed=['b.so'], runpath='$ORIGIN/libs')
        self.file('app/libs/b.so', needed=['c.so'])
        self.file('app/libs/c.so')
        result = self.run_closure()
        self.assertFalse(result['complete_without_conflicts'])
        self.assertIn('unresolved', [problem['kind'] for problem in result['problems']])

    def test_all_candidates_and_soname_collisions_are_exposed(self):
        self.file('app/a.so', needed=['b.so'], runpath='$ORIGIN/libs')
        self.file('app/libs/b.so', soname='b.so')
        self.file('lib/b.so', soname='b.so')
        result = self.run_closure()
        self.assertIn('multiple_candidates', [problem['kind'] for problem in result['problems']])
        self.assertIn('soname_collision', [problem['kind'] for problem in result['problems']])
        self.assertEqual(len(result['files']), 3)

    def test_absolute_symlink_uses_sysroot_map(self):
        self.file('app/a.so', needed=['b.so'])
        self.file('lib/actual.so')
        self.records['lib/b.so'] = {'type': 'symlink', 'target': '/lib/actual.so'}
        self.assertTrue(self.run_closure()['complete_without_conflicts'])

    def test_symlink_escape_or_loop_never_reads_host(self):
        for target in ('../../outside.so', 'b.so'):
            with self.subTest(target=target):
                self.file('app/a.so', needed=['b.so'])
                self.records['lib/b.so'] = {'type': 'symlink', 'target': target}
                result = self.run_closure()
                self.assertFalse(result['complete_without_conflicts'])
                self.assertEqual(result['files'], ['app/a.so'])

    def test_unsupported_tokens_and_relative_search_refuse_positive_result(self):
        for value in ('$LIB', '$PLATFORM', 'relative', ':$ORIGIN', '$ORIGIN/../../..'):
            with self.subTest(value=value):
                self.file('app/a.so', needed=['b.so'], rpath=value)
                self.assertFalse(self.run_closure()['complete_without_conflicts'])

    def test_cache_entries_are_transitive(self):
        self.dir('etc')
        self.records['etc/ld.so.cache'] = {'type': 'file'}
        self.raw['etc/ld.so.cache'] = cache([('b.so', '/lib/b.so', 0xa03, 0)])
        self.file('app/a.so', needed=['b.so'])
        self.file('lib/b.so', needed=['c.so'])
        self.file('lib/c.so')
        self.assertTrue(self.run_closure()['complete_without_conflicts'])

    def test_missing_root_is_reported(self):
        result = self.run_closure()
        self.assertFalse(result['complete_without_conflicts'])
        self.assertEqual(result['problems'][0]['path'], 'app/a.so')


class PlanTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='support-plan-', dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / 'root'; self.root.mkdir(mode=0o755)
        self.root.chmod(0o755)
        self.owner = os.geteuid(), os.getegid()
        # Fixture host xattrs are normalized explicitly; production never does this.
        attributes = patch.object(planner.inventory, '_xattrs', return_value=planner.exporter.EMPTY_XATTRS)
        attributes.start(); self.addCleanup(attributes.stop)
        self.data = {}
        for path in runtime.SUPPORT_TREES:
            self.mkdir(path)
        required = {runtime.HELPER, *runtime.HOOKS, *runtime.SUPERVISOR_FILES, *runtime.WRITER_FILES}
        required |= {runtime.MODULE_DIR + '/' + name for name in runtime.MODULES}
        for path in required:
            self.write(path, b'raise AssertionError("TARGET_MUST_NOT_RUN")\n', 0o555)
        self.write('usr/bin/python3.13', elf(b'python'), 0o755)
        self.write('usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1', elf(b'loader'), 0o755)
        self.link('lib', 'usr/lib')
        self.link('usr/lib/ld-linux-aarch64.so.1', 'aarch64-linux-gnu/ld-linux-aarch64.so.1')
        self.link('usr/bin/python3', 'python3.13')
        self.write('etc/ld.so.cache', cache())
        self.write('etc/ld.so.conf', b'include /etc/ld.so.conf.d/*.conf\n')
        self.write(runtime.APP + '/app.so', elf(b'app'))
        app = {'schema_version': 1, 'kind': 'factory-studio-bundle-manifest', 'studio_commit': 'a' * 40,
               'records': planner.inventory.inventory(self.root / runtime.APP)}
        self.app_path, self.app_pin = self.input('app.json', app)
        self.write(runtime.APP + '/manifest.json', self.app_path.read_bytes())
        source = self.base / 'sources'; source.mkdir()
        (source / 'native.so').write_bytes(elf(b'virtual-exporter'))
        wheels = self.base / 'wheels'; wheels.mkdir()
        wheel_raw, _ = wheel_bytes(); (wheels / 'fixture-1.0-py3-none-any.whl').write_bytes(wheel_raw)
        lock = json.loads((ROOT / 'config/factory-exporter.lock.json').read_bytes())
        lock['source_sha256'] = {'native.so': sha((source / 'native.so').read_bytes())}
        lock['wheel_sha256'] = {'fixture-1.0-py3-none-any.whl': sha(wheel_raw)}
        self.lock_path, self.lock_pin = self.input('exporter-lock.json', lock)
        provenance = {key: lock[key] for key in planner.PROVENANCE}
        provenance['python_version'] = '3.13.5'
        self.provenance_path, self.provenance_pin = self.input('provenance.json', provenance)
        self.policy = {'schema_version': 1, 'kind': 'factory-system-support-policy',
                       'trees': sorted(runtime.SUPPORT_TREES),
                       'paths': sorted({path for path in required if not any(
                           path.startswith(tree + '/') for tree in runtime.SUPPORT_TREES)} |
                           {'lib', 'usr/bin/python3', 'usr/bin/python3.13',
                            'usr/lib/ld-linux-aarch64.so.1', 'etc/ld.so.cache', 'etc/ld.so.conf'}),
                       'absent': sorted(runtime.ABSENCE_GUARDS | runtime.TEST_ABSENT | runtime.UNIT_ABSENT),
                       'elf_roots': ['usr/bin/python3.13'],
                       'loader': {'interpreter': '/lib/ld-linux-aarch64.so.1',
                                  'default_search_paths': ['lib/aarch64-linux-gnu',
                                                           'usr/lib/aarch64-linux-gnu', 'lib', 'usr/lib']}}
        self.policy_path, self.policy_pin = self.input('policy.json', self.policy)
        self.args = dict(policy=self.policy_path, policy_sha256=self.policy_pin,
                         provenance=self.provenance_path, provenance_sha256=self.provenance_pin,
                         app_manifest=self.app_path, app_manifest_sha256=self.app_pin,
                         exporter_lock=self.lock_path, exporter_lock_sha256=self.lock_pin,
                         sources_dir=source, wheels_dir=wheels, readelf=Path('/usr/bin/readelf'),
                         readelf_sha256='a' * 64, _owner=self.owner,
                         _inspect=lambda raw: planner.parse_readelf(raw, READELF.replace(
                             ' 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]\n', '').replace(
                             ' 0x000000000000000f (RPATH)              Library rpath: [$ORIGIN/../libs]\n', '').replace(
                             ' 0x000000000000000e (SONAME)             Library soname: [fixture.so]\n', '').replace(
                             '      [Requesting program interpreter: /lib/ld-linux-aarch64.so.1]\n', '')))

    def mkdir(self, path):
        current = self.root
        for part in Path(path).parts:
            current /= part
            current.mkdir(exist_ok=True, mode=0o755); current.chmod(0o755)

    def write(self, path, raw, mode=0o644):
        target = self.root / path
        self.mkdir(str(Path(path).parent))
        target.write_bytes(raw); target.chmod(mode)

    def link(self, path, target):
        self.mkdir(str(Path(path).parent)); (self.root / path).symlink_to(target)
        if hasattr(os, 'lchmod'):
            os.lchmod(self.root / path, 0o777)

    def input(self, name, value):
        raw = planner.canonical(value); path = self.base / name; path.write_bytes(raw)
        return path, sha(raw)

    def snapshot(self):
        return planner.inventory.inventory(self.root)

    def plan(self, **overrides):
        return planner.plan(self.root, **{**self.args, **overrides})

    def test_proposal_has_no_review_and_does_not_require_installed_exporter(self):
        before = self.snapshot()
        result = self.plan()
        self.assertTrue(result['elf_observations']['complete_without_conflicts'])
        self.assertNotIn('elf_closure_review', result['support_candidate'])
        self.assertFalse((self.root / planner.exporter.DESTINATION).exists())
        self.assertTrue(any('/factory-exporter/' in name for name in result['elf_observations']['files']))
        self.assertFalse(result['abi_qualified'])
        self.assertEqual(self.snapshot(), before)

    def test_wrong_explicit_pins_refuse_without_mutation(self):
        before = self.snapshot()
        for field in ('policy_sha256', 'provenance_sha256', 'app_manifest_sha256', 'exporter_lock_sha256'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.plan(**{field: '0' * 64})
        self.assertEqual(self.snapshot(), before)

    def test_app_bytes_must_match_manifest(self):
        self.write(runtime.APP + '/app.so', elf(b'changed'))
        with self.assertRaisesRegex(planner.Refused, 'app_inventory_mismatch'):
            self.plan()

    def test_unsafe_ownership_mode_or_hardlink_refused(self):
        target = self.root / 'usr/bin/python3.13'; target.chmod(0o777)
        with self.assertRaises(ValueError):
            self.plan()
        target.chmod(0o755)
        os.link(target, self.root / 'usr/bin/copied-python')
        with self.assertRaises(ValueError):
            self.plan()

    def test_test_profile_and_incomplete_tree_policy_refused(self):
        for value in (dict(self.policy, trees=[tree for tree in self.policy['trees'] if 'dist-packages' not in tree]),
                      dict(self.policy, absent=[])):
            path, digest = self.input('bad-policy.json', value)
            with self.assertRaises(planner.Refused):
                self.plan(policy=path, policy_sha256=digest)

    def test_present_guard_and_symlink_input_refused(self):
        self.write('etc/ld.so.preload', b'/outside.so\n')
        with self.assertRaises(planner.Refused):
            self.plan()
        linked = self.base / 'linked-policy.json'; linked.symlink_to(self.policy_path)
        with self.assertRaises(ValueError):
            self.plan(policy=linked)

    def test_tree_path_overlap_and_bundle_collision_refused(self):
        value = copy.deepcopy(self.policy)
        value['paths'].append('usr/lib/python3.13')
        path, digest = self.input('bad-policy.json', value)
        with self.assertRaisesRegex(planner.Refused, 'overlapping_paths'):
            self.plan(policy=path, policy_sha256=digest)
        value = copy.deepcopy(self.policy); value['paths'].append(runtime.APP)
        path, digest = self.input('bad-policy.json', value)
        with self.assertRaisesRegex(planner.Refused, 'bundle_support_collision'):
            self.plan(policy=path, policy_sha256=digest)

    def test_rootfs_host_root_and_symlink_parent_refused(self):
        with self.assertRaises(planner.Refused):
            planner.plan(Path('/'), **self.args)
        alias = self.base / 'root-alias'; alias.symlink_to(self.root)
        with self.assertRaises(ValueError):
            planner.plan(alias, **self.args)

    def test_drift_during_elf_inspection_is_detected(self):
        done = False
        def inspect(raw):
            nonlocal done
            if not done:
                self.write('etc/ld.so.conf', b'changed while planning\n'); done = True
            return observation()
        with self.assertRaisesRegex(planner.Refused, 'input_changed'):
            self.plan(_inspect=inspect)


if __name__ == '__main__':
    unittest.main()
