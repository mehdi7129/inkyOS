"""Offline materialization fixtures; payloads fail if executed.

Synthetic workspace/owner seams are explicit and refuse host '/'. Linux uses
actual xattrs; macOS substitutes only the Linux empty-xattrs observation. Neither
fixture mode nor any target override is exposed by the production CLI.
"""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


installer = module('studio_bundle_install_test', ROOT / 'scripts/install-factory-studio-bundle-rootfs.py')
fixtures = module('studio_bundle_install_wheel_fixtures', ROOT / 'tests/test_factory_studio_bundle_plan.py')


class FactoryStudioBundleInstallTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='inkyos-studio-install-',
                                                dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.base.chmod(0o700)
        self.rootfs = self.base / 'root'
        self.rootfs.mkdir(mode=0o755)
        self.sources = self.base / 'sources'
        self.wheels = self.base / 'wheels'
        self.sources.mkdir(); self.wheels.mkdir()
        self.input_file = self.base / 'inputs.json'
        self.receipt = self.base / 'receipt.json'
        self.bundle = self.rootfs / 'usr/lib/inky-studio'
        self.source_payload = {'scripts/inky-network-helper.py': b'raise AssertionError("not executed")\n',
                               'client/dist/index.html': b'<title>Inert fixture</title>\n'}
        for name, raw in self.source_payload.items():
            self.write(self.sources / name, raw)
        self.app_raw, self.app_payload = fixtures.synthetic_wheel(fixtures.APP_WHEEL, {
            'inky_web/__init__.py': b'raise AssertionError("not imported")\n',
            'inky_web/main.py': b'raise AssertionError("not executed")\n'})
        self.dep_raw, self.dep_payload = fixtures.synthetic_wheel(fixtures.DEP_WHEEL, {
            'fixture_dep/__init__.py': b'raise AssertionError("not imported")\n'})
        self.write(self.wheels / fixtures.APP_WHEEL, self.app_raw)
        self.write(self.wheels / fixtures.DEP_WHEEL, self.dep_raw)
        self.inputs = {'schema_version': 1, 'kind': 'factory-studio-bundle-inputs',
            'studio_commit': 'a' * 40, 'python_version': '3.13.5', 'app_wheel': fixtures.APP_WHEEL,
            'source_sha256': {name: fixtures.sha(raw) for name, raw in self.source_payload.items()},
            'wheel_sha256': {fixtures.APP_WHEEL: fixtures.sha(self.app_raw),
                             fixtures.DEP_WHEEL: fixtures.sha(self.dep_raw)}}
        self.write_inputs()
        self.env_patch = patch.object(installer, '_production_environment', self.fixture_environment)
        self.env_patch.start(); self.addCleanup(self.env_patch.stop)
        self.owner_patch = patch.object(installer, '_owner_ids', self.fixture_owners)
        self.owner_patch.start(); self.addCleanup(self.owner_patch.stop)
        if not sys.platform.startswith('linux'):
            self.xattrs_patch = patch.object(installer, '_xattrs', self.fixture_xattrs)
            self.xattrs_patch.start(); self.addCleanup(self.xattrs_patch.stop)
            self.symlink_patch = patch.object(installer, '_write_symlink', self.fixture_symlink)
            self.symlink_patch.start(); self.addCleanup(self.symlink_patch.stop)

    def fixture_environment(self, rootfs):
        installer.require(rootfs != Path('/') and rootfs.parent == self.base,
                          'fixture_root_refused')
        return self.base, self.base

    @staticmethod
    def fixture_owners(rootfs):
        installer.require(rootfs != Path('/'), 'fixture_root_refused')
        return os.geteuid(), os.getegid()

    @staticmethod
    def fixture_xattrs(rootfs, target, *, nofollow=False):
        installer.require(rootfs != Path('/'), 'fixture_root_refused')
        return {'status': 'inspected', 'entries': {}}

    def fixture_symlink(self, rootfs, parent, name, target):
        # Darwin creates 0755 symlinks; this synthetic scaffold uses lchmod to
        # reproduce Linux 0777 metadata, never normalize production inventory.
        installer.require(rootfs == self.rootfs and rootfs != Path('/'), 'fixture_root_refused')
        path = self.bundle / 'server/.venv' / (name if name == 'lib64' else 'bin/' + name)
        installer.require(path.parent.stat().st_ino == os.fstat(parent).st_ino,
                          'fixture_parent_refused')
        os.symlink(target, name, dir_fd=parent)
        os.lchmod(path, 0o777)
        os.chown(path, os.geteuid(), os.getegid(), follow_symlinks=False)
        os.fsync(parent)

    def write(self, path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        for parent in (path.parent, *path.parent.parents):
            if parent == self.base:
                break
            parent.chmod(0o755)
        path.write_bytes(raw); path.chmod(0o644)

    def write_inputs(self):
        raw = fixtures.canonical(self.inputs)
        self.write(self.input_file, raw)
        self.input_sha = fixtures.sha(raw)

    def args(self, **changes):
        values = dict(rootfs=self.rootfs, input_manifest=self.input_file,
                      input_sha256=self.input_sha, sources_dir=self.sources, wheels_dir=self.wheels)
        values.update(changes)
        return values

    def install(self, **changes):
        receipt = changes.pop('receipt_output', self.receipt)
        return installer.install_bundle(**self.args(**changes), receipt_output=receipt)

    def verify(self, **changes):
        return installer.verify_bundle(**self.args(**changes))

    def snapshot(self):
        result = {}
        for path in (self.base, *sorted(self.base.rglob('*'))):
            info = path.lstat()
            record = (info.st_mode, info.st_uid, info.st_gid, info.st_nlink, info.st_ino)
            if stat.S_ISREG(info.st_mode):
                record += (path.read_bytes(),)
            elif stat.S_ISLNK(info.st_mode):
                record += (os.readlink(path),)
            result[str(path.relative_to(self.base))] = record
        return result

    def refused_without_write(self, callback):
        before = self.snapshot()
        with self.assertRaises(installer.Refused) as caught:
            callback()
        self.assertRegex(caught.exception.reason, '^[a-z_]{1,64}$')
        self.assertEqual(self.snapshot(), before)
        return caught.exception.reason

    def test_exact_tree_metadata_manifest_receipt_and_verification(self):
        expected_raw, plan_receipt = installer.planner.plan(
            self.input_file, self.input_sha, self.sources, self.wheels)
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('child executed')), \
                patch.object(os, 'system', side_effect=AssertionError('shell executed')):
            receipt = self.install()
        expected = json.loads(expected_raw)['records']
        self.assertEqual((self.bundle / 'manifest.json').read_bytes(), expected_raw)
        self.assertEqual(set(str(path.relative_to(self.bundle)) for path in self.bundle.rglob('*')) | {'.'},
                         set(expected) | {'manifest.json'})
        payload = {**self.source_payload, **{fixtures.SITE + '/' + path: raw for path, raw
                   in {**self.app_payload, **self.dep_payload}.items()}}
        payload['server/.venv/pyvenv.cfg'] = (
            b'home = /usr/bin\ninclude-system-site-packages = false\nversion = 3.13.5\n'
            b'executable = /usr/bin/python3.13\n')
        for name, record in expected.items():
            path = self.bundle if name == '.' else self.bundle / name
            info = path.lstat()
            self.assertEqual((info.st_uid, info.st_gid), (os.geteuid(), os.getegid()))
            self.assertEqual(format(stat.S_IMODE(info.st_mode), '04o'), record['mode'], name)
            if record['type'] == 'file':
                self.assertEqual(path.read_bytes(), payload[name])
            elif record['type'] == 'symlink':
                self.assertEqual(os.readlink(path), record['target'])
        self.assertEqual(receipt['scope'], 'offline-factory-studio-bundle-install')
        self.assertEqual(receipt['operation'], 'install')
        self.assertTrue(receipt['bundle_verified'])
        for flag in ('support_verified', 'image_code_executed', 'application_code_executed',
                     'runtime_qualified', 'hardware_qualified'):
            self.assertIs(receipt[flag], False)
        self.assertEqual(receipt['bundle_manifest_sha256'], plan_receipt['bundle_manifest_sha256'])
        self.assertEqual(self.receipt.read_bytes(), fixtures.canonical(receipt))
        self.assertEqual(stat.S_IMODE(self.receipt.stat().st_mode), 0o600)
        before = self.snapshot()
        verified = self.verify()
        self.assertEqual(verified, dict(receipt, operation='verify'))
        self.assertEqual(self.snapshot(), before)

    def test_existing_safe_usr_lib_metadata_is_unchanged(self):
        (self.rootfs / 'usr/lib').mkdir(parents=True, mode=0o700)
        (self.rootfs / 'usr').chmod(0o711)
        before = [(path.lstat().st_mode, path.lstat().st_ino) for path in
                  (self.rootfs / 'usr', self.rootfs / 'usr/lib')]
        self.install()
        self.assertEqual([(path.lstat().st_mode, path.lstat().st_ino) for path in
                          (self.rootfs / 'usr', self.rootfs / 'usr/lib')], before)

    def test_invalid_pin_refuses_before_creating_generic_directories(self):
        self.refused_without_write(lambda: self.install(input_sha256='b' * 64))
        self.assertFalse((self.rootfs / 'usr').exists())

    def test_payload_hash_mismatch_refuses_before_write(self):
        self.write(self.sources / 'client/dist/index.html', b'changed')
        self.refused_without_write(self.install)

    def test_invalid_manifest_refuses_before_write(self):
        self.inputs['unknown'] = 'closed'
        self.write_inputs()
        self.refused_without_write(self.install)

    def test_extra_input_refuses_before_write(self):
        self.write(self.wheels / 'unexpected', b'x')
        self.refused_without_write(self.install)

    def input_with_wheel_member(self, name):
        raw, _ = fixtures.synthetic_wheel(fixtures.DEP_WHEEL, {name: b'inert payload'})
        self.write(self.wheels / fixtures.DEP_WHEEL, raw)
        self.inputs['wheel_sha256'][fixtures.DEP_WHEEL] = fixtures.sha(raw)
        self.write_inputs()
        manifest, _ = installer.planner.plan(self.input_file, self.input_sha, self.sources, self.wheels)
        final_name = fixtures.SITE + '/' + name
        self.assertIn(final_name, json.loads(manifest)['records'])
        return final_name

    def unmaterializable_without_write(self):
        reason = self.refused_without_write(self.install)
        self.assertEqual(reason, 'unmaterializable_path')
        self.assertFalse((self.rootfs / 'usr').exists())
        self.assertFalse(self.bundle.exists())
        self.assertFalse(self.receipt.exists())

    def test_planner_valid_wheel_depth_with_prefix_refuses_before_write(self):
        name = '/'.join(['d'] * 60 + ['file.py'])
        self.assertLessEqual(len(name.split('/')), 64)
        final_name = self.input_with_wheel_member(name)
        self.assertGreater(len(final_name.split('/')), 64)
        self.unmaterializable_without_write()

    def test_planner_valid_wheel_path_bytes_with_prefix_refuses_before_write(self):
        name = '/'.join(['a' * 240] * 16 + ['b' * 230])
        self.assertLessEqual(len(name.encode('utf-8')), 4096)
        final_name = self.input_with_wheel_member(name)
        self.assertGreater(len(final_name.encode('utf-8')), 4096)
        self.unmaterializable_without_write()

    def test_planner_valid_component_over_filesystem_name_max_refuses_before_write(self):
        name_max = os.pathconf(self.rootfs, 'PC_NAME_MAX')
        self.assertLess(name_max, 4096)
        self.input_with_wheel_member('a' * (name_max + 1))
        self.unmaterializable_without_write()

    def test_name_max_counts_encoded_component_bytes_before_write(self):
        name_max = os.pathconf(self.rootfs, 'PC_NAME_MAX')
        self.assertLess(name_max, 4095)
        name = '\N{LATIN SMALL LETTER E WITH ACUTE}' * (name_max // 2 + 1)
        self.assertLessEqual(len(name), name_max)
        self.assertGreater(len(os.fsencode(name)), name_max)
        self.input_with_wheel_member(name)
        self.unmaterializable_without_write()

    def test_indeterminate_name_max_refuses_before_write(self):
        with patch.object(os, 'fpathconf', return_value=-1):
            self.assertEqual(self.refused_without_write(self.install), 'unsupported_name_limit')
        self.assertFalse((self.rootfs / 'usr').exists())

    def test_manifest_name_is_preflighted_before_any_creation(self):
        # Some payload names are also longer; the complete preflight must always
        # include our own generated filename rather than validate ZIP paths only.
        environment = installer.Environment(self.rootfs, self.input_file, self.sources,
                                            self.wheels, self.receipt, installing=True)
        try:
            with patch.object(os, 'fpathconf', return_value=len('manifest.json') - 1):
                self.assertEqual(self.refused_without_write(
                    lambda: installer._preflight_paths(environment, {'.': {}})),
                    'unmaterializable_path')
        finally:
            environment.close()

    def test_partial_second_pass_payload_alteration_refuses_before_write(self):
        original = installer._relative_file
        def corrupted(rootfs, directory, name, limit):
            raw = original(rootfs, directory, name, limit)
            return raw + b'x' if name == 'client/dist/index.html' else raw
        with patch.object(installer, '_relative_file', corrupted):
            self.refused_without_write(self.install)

    def test_expected_record_tampering_does_not_promote_observed_bytes(self):
        original = installer._expected
        def altered(*args):
            manifest, records, receipt = original(*args)
            records['client/dist/index.html']['sha256'] = 'b' * 64
            return manifest, records, receipt
        with patch.object(installer, '_expected', altered):
            self.refused_without_write(self.install)

    def test_existing_destination_directory_refuses_before_write(self):
        self.bundle.mkdir(parents=True)
        self.refused_without_write(self.install)

    def test_existing_destination_file_refuses_before_write(self):
        self.write(self.bundle, b'preserve')
        self.refused_without_write(self.install)

    def test_existing_receipt_refuses_before_write(self):
        self.write(self.receipt, b'preserve')
        self.refused_without_write(self.install)

    def test_receipt_symlink_refuses_before_write(self):
        self.receipt.symlink_to(self.input_file)
        self.refused_without_write(self.install)

    def test_source_symlink_refuses_before_write(self):
        path = self.sources / 'client/dist/index.html'
        path.unlink(); path.symlink_to(self.input_file)
        self.refused_without_write(self.install)

    def test_input_parent_symlink_refuses_before_write(self):
        linked = self.base / 'linked'; linked.symlink_to(self.sources)
        self.refused_without_write(lambda: self.install(sources_dir=linked))

    def test_destination_parent_symlink_refuses_before_write(self):
        (self.rootfs / 'usr').symlink_to(self.sources)
        self.refused_without_write(self.install)

    def test_existing_parent_file_refuses_before_write(self):
        self.write(self.rootfs / 'usr', b'preserve')
        self.refused_without_write(self.install)

    def test_untrusted_parent_mode_refuses_before_write(self):
        (self.rootfs / 'usr').mkdir(); (self.rootfs / 'usr').chmod(0o777)
        self.refused_without_write(self.install)

    def test_untrusted_owner_refuses_before_write(self):
        with patch.object(installer, '_owner_ids', return_value=(os.geteuid() + 1, os.getegid())):
            self.refused_without_write(self.install)

    def test_untrusted_input_file_mode_refuses_before_write(self):
        (self.sources / 'client/dist/index.html').chmod(0o666)
        self.refused_without_write(self.install)

    def test_private_workspace_mode_required(self):
        self.base.chmod(0o755)
        self.refused_without_write(self.install)

    def test_receipt_rootfs_overlap_refuses_before_write(self):
        self.refused_without_write(lambda: self.install(receipt_output=self.rootfs / 'receipt.json'))

    def test_receipt_input_overlap_refuses_before_write(self):
        self.refused_without_write(lambda: self.install(receipt_output=self.sources / 'receipt.json'))

    def test_input_rootfs_overlap_refuses_before_write(self):
        self.refused_without_write(lambda: self.install(sources_dir=self.rootfs))

    def test_host_root_refused_even_with_fixture_environment(self):
        self.refused_without_write(lambda: self.install(rootfs=Path('/')))

    def test_noncanonical_relative_path_refuses_before_write(self):
        self.refused_without_write(lambda: self.install(rootfs=Path('relative')))

    def test_traversal_path_refuses_before_write(self):
        self.refused_without_write(lambda: self.install(rootfs=self.rootfs / '..' / 'root'))

    def test_input_hardlink_refuses_before_write(self):
        os.link(self.sources / 'client/dist/index.html', self.base / 'extra-link')
        self.refused_without_write(self.install)

    def test_preexisting_xattrs_refused_before_write(self):
        original = installer._xattrs
        def attrs(rootfs, target, **kwargs):
            result = original(rootfs, target, **kwargs)
            if isinstance(target, int) and os.fstat(target).st_ino == self.rootfs.stat().st_ino:
                return {'status': 'inspected', 'entries': {'fixture.attr': {'size_bytes': 1,
                                                                         'sha256': 'a' * 64}}}
            return result
        with patch.object(installer, '_xattrs', attrs):
            self.refused_without_write(self.install)

    def test_input_xattrs_refused_before_write(self):
        original = installer._xattrs
        inode = (self.sources / 'client/dist/index.html').stat().st_ino
        def attrs(rootfs, target, **kwargs):
            if isinstance(target, int) and os.fstat(target).st_ino == inode:
                return {'status': 'unsupported', 'reason': 'filesystem'}
            return original(rootfs, target, **kwargs)
        with patch.object(installer, '_xattrs', attrs):
            self.refused_without_write(self.install)

    def test_io_partial_tree_is_retained_and_cannot_be_resumed(self):
        original = installer._write_file
        calls = 0
        def failed(*args):
            nonlocal calls
            calls += 1
            original(*args)
            if calls == 1:
                raise OSError('injected after first payload creation')
        with patch.object(installer, '_write_file', failed):
            with self.assertRaises(installer.Refused):
                self.install()
        self.assertTrue(self.bundle.is_dir())
        self.assertFalse((self.bundle / 'manifest.json').exists())
        self.assertFalse(self.receipt.exists())
        self.refused_without_write(self.install)

    def test_wrong_materialized_bytes_refuses_before_manifest_and_receipt(self):
        original = installer._write_file
        def corrupted(rootfs, parent, name, raw, mode):
            original(rootfs, parent, name, raw + b'x' if name == 'index.html' else raw, mode)
        with patch.object(installer, '_write_file', corrupted):
            with self.assertRaises(installer.Refused):
                self.install()
        self.assertFalse((self.bundle / 'manifest.json').exists())
        self.assertFalse(self.receipt.exists())

    def test_changed_input_after_materialization_refuses_before_manifest(self):
        original = installer._inventory
        def changed(rootfs, bundle):
            result = original(rootfs, bundle)
            self.write(self.sources / 'client/dist/index.html', b'changed after payload')
            return result
        with patch.object(installer, '_inventory', changed):
            with self.assertRaises(installer.Refused):
                self.install()
        self.assertFalse((self.bundle / 'manifest.json').exists())
        self.assertFalse(self.receipt.exists())

    def test_unexpected_materialized_entry_refuses_before_manifest(self):
        original = installer._inventory
        def added(rootfs, bundle):
            self.write(self.bundle / 'unexpected', b'x')
            return original(rootfs, bundle)
        with patch.object(installer, '_inventory', added):
            with self.assertRaises(installer.Refused):
                self.install()
        self.assertFalse((self.bundle / 'manifest.json').exists())
        self.assertFalse(self.receipt.exists())

    def test_destination_parent_replacement_refuses_publication(self):
        original = installer._write_file
        changed = False
        def replacement(*args):
            nonlocal changed
            original(*args)
            if not changed:
                changed = True
                (self.rootfs / 'usr/lib').rename(self.rootfs / 'usr/previous-lib')
                (self.rootfs / 'usr/lib').mkdir()
        with patch.object(installer, '_write_file', replacement):
            with self.assertRaises(installer.Refused):
                self.install()
        self.assertTrue((self.rootfs / 'usr/previous-lib/inky-studio').exists())
        self.assertFalse((self.rootfs / 'usr/previous-lib/inky-studio/manifest.json').exists())
        self.assertFalse(self.receipt.exists())

    def test_receipt_parent_replacement_refuses_before_first_creation(self):
        output = self.base / 'outputs'; output.mkdir()
        self.receipt = output / 'receipt.json'
        original = installer._payload
        def replacement(*args):
            payload = original(*args)
            output.rename(self.base / 'previous-outputs')
            output.mkdir()
            return payload
        with patch.object(installer, '_payload', replacement):
            with self.assertRaises(installer.Refused):
                self.install()
        self.assertFalse((self.rootfs / 'usr').exists())
        self.assertFalse(self.receipt.exists())

    def test_manifest_io_failure_retains_partial_and_no_receipt(self):
        original = installer._write_file
        def failed(rootfs, parent, name, raw, mode):
            if name == 'manifest.json':
                original(rootfs, parent, name, raw[:10], mode)
                raise OSError('injected manifest failure')
            original(rootfs, parent, name, raw, mode)
        with patch.object(installer, '_write_file', failed):
            with self.assertRaises(installer.Refused):
                self.install()
        self.assertEqual((self.bundle / 'manifest.json').read_bytes(),
                         fixtures.canonical(json.loads(installer.planner.plan(
                             self.input_file, self.input_sha, self.sources, self.wheels)[0]))[:10])
        self.assertFalse(self.receipt.exists())
        self.refused_without_write(self.install)

    def test_receipt_io_failure_retains_partial_and_cannot_resume(self):
        original = installer._write_file
        def failed(rootfs, parent, name, raw, mode):
            if name == self.receipt.name:
                original(rootfs, parent, name, raw[:10], mode)
                raise OSError('injected receipt failure')
            original(rootfs, parent, name, raw, mode)
        with patch.object(installer, '_write_file', failed):
            with self.assertRaises(installer.Refused):
                self.install()
        self.assertTrue((self.bundle / 'manifest.json').exists())
        self.assertEqual(len(self.receipt.read_bytes()), 10)
        self.refused_without_write(self.install)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'actual Linux xattrs require Linux')
    def test_actual_linux_input_xattr_refuses_before_write(self):
        os.setxattr(self.sources / 'client/dist/index.html', 'user.fixture', b'x')
        self.refused_without_write(self.install)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'actual Linux xattrs require Linux')
    def test_actual_linux_bundle_xattr_refuses_verification_without_repair(self):
        self.install()
        os.setxattr(self.bundle / 'client/dist/index.html', 'user.fixture', b'x')
        self.refused_without_write(self.verify)

    def test_metadata_mismatch_refuses_verification_without_repair(self):
        self.install()
        (self.bundle / 'client/dist/index.html').chmod(0o600)
        self.refused_without_write(self.verify)

    def test_payload_mismatch_refuses_verification_without_repair(self):
        self.install()
        self.write(self.bundle / 'client/dist/index.html', b'altered')
        self.refused_without_write(self.verify)

    def test_manifest_mismatch_refuses_verification_without_repair(self):
        self.install()
        self.write(self.bundle / 'manifest.json', b'{}\n')
        self.refused_without_write(self.verify)

    def test_extra_empty_directory_refuses_verification_without_repair(self):
        self.install()
        (self.bundle / 'extra').mkdir()
        self.refused_without_write(self.verify)

    def test_symlink_target_mismatch_refuses_verification_without_repair(self):
        self.install()
        path = self.bundle / 'server/.venv/bin/python'
        path.unlink(); path.symlink_to('/usr/bin/python3.13')
        self.refused_without_write(self.verify)

    def test_bundle_hardlink_refuses_verification_without_repair(self):
        self.install()
        os.link(self.bundle / 'client/dist/index.html', self.base / 'extra-link')
        self.refused_without_write(self.verify)

    def test_bundle_fifo_refuses_verification_without_opening_it(self):
        self.install()
        os.mkfifo(self.bundle / 'unexpected')
        self.refused_without_write(self.verify)

    def test_missing_bundle_refuses_verification_without_write(self):
        self.refused_without_write(self.verify)

    def test_cli_production_guard_has_no_fixture_flag(self):
        command = [sys.executable, str(ROOT / 'scripts/install-factory-studio-bundle-rootfs.py'),
                   '--rootfs', str(self.rootfs), '--input-manifest', str(self.input_file),
                   '--input-sha256', self.input_sha, '--sources-dir', str(self.sources),
                   '--wheels-dir', str(self.wheels), '--receipt', str(self.receipt)]
        before = self.snapshot()
        result = subprocess.run(command, capture_output=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b'factory_studio_install_refused:', result.stderr)
        self.assertEqual(self.snapshot(), before)


if __name__ == '__main__':
    unittest.main()
