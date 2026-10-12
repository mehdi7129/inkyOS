"""Inert offline fixtures. These tests do not qualify an installed runtime.

Production requires root/Linux, actual inode pinning and empty Linux xattrs.
Fixture seams alter only workspace/owner checks and Darwin's xattr observation;
they are not production arguments and always refuse the host root.
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


installer = module('writer_files_fixture', ROOT / 'scripts/install-factory-writer-rootfs.py')
verification, guards = installer.verification, installer.guards
PRODUCTION_ENVIRONMENT = verification._production_environment


class WriterFilesTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='inkyos-writer-files-',
                                                dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.base.chmod(0o700)
        self.rootfs, self.sources = self.base / 'root', self.base / 'sources'
        self.rootfs.mkdir(mode=0o755); self.sources.mkdir(mode=0o755)
        self.inputs_path, self.bundle_manifest = self.base / 'inputs.json', self.base / 'bundle.json'
        self.receipt = self.base / 'receipt.json'
        self.payload = {name: ('raise AssertionError("never executed: ' + name + '")\n').encode()
                        for name in verification.SOURCE_MAP}
        for name, raw in self.payload.items():
            self.write(self.sources / name, raw)
        self.helper = b'raise AssertionError("helper never executed")\n'
        self.bundle = {'schema_version': 1, 'kind': 'factory-studio-bundle-manifest',
                       'studio_commit': verification.STUDIO_COMMIT,
                       'records': {verification.HELPER_SOURCE:
                                   guards.planner.exporter.file_record(self.helper)}}
        self.write_bundle()
        self.write(self.rootfs / verification.BUNDLE / verification.HELPER_SOURCE, self.helper)
        self.inputs = {'schema_version': 1, 'kind': 'factory-writer-file-inputs',
                       'os_commit': 'a' * 40, 'studio_commit': verification.STUDIO_COMMIT,
                       'os_source_sha256': {name: verification.sha(raw) for name, raw in self.payload.items()},
                       'studio_bundle_manifest_sha256': verification.sha(verification.canonical(self.bundle)),
                       'helper_source_sha256': verification.sha(self.helper)}
        self.write_inputs()
        self.environment_patch = patch.object(verification, '_production_environment', self.fixture_environment)
        self.environment_patch.start(); self.addCleanup(self.environment_patch.stop)
        self.owner_patch = patch.object(guards, '_owner_ids', self.fixture_owners)
        self.owner_patch.start(); self.addCleanup(self.owner_patch.stop)
        if not sys.platform.startswith('linux'):
            self.xattrs_patch = patch.object(guards, '_xattrs', self.fixture_xattrs)
            self.xattrs_patch.start(); self.addCleanup(self.xattrs_patch.stop)

    def fixture_environment(self, rootfs):
        verification.require(rootfs != Path('/') and rootfs == self.rootfs, 'fixture_root_refused')
        return self.base, self.base

    @staticmethod
    def fixture_owners(rootfs):
        verification.require(rootfs != Path('/'), 'fixture_root_refused')
        return os.geteuid(), os.getegid()

    @staticmethod
    def fixture_xattrs(rootfs, target, *, nofollow=False):
        verification.require(rootfs != Path('/'), 'fixture_root_refused')
        return guards.EMPTY_XATTRS

    def write(self, path, raw, mode=0o644):
        path.parent.mkdir(parents=True, exist_ok=True)
        for parent in (path.parent, *path.parent.parents):
            if parent == self.base:
                break
            parent.chmod(0o755)
        path.write_bytes(raw); path.chmod(mode)

    def write_bundle(self):
        raw = verification.canonical(self.bundle)
        self.write(self.bundle_manifest, raw)
        self.write(self.rootfs / verification.BUNDLE / 'manifest.json', raw)

    def write_inputs(self):
        raw = verification.canonical(self.inputs)
        self.write(self.inputs_path, raw)
        self.input_sha = verification.sha(raw)

    def args(self, **changes):
        values = dict(rootfs=self.rootfs, input_manifest=self.inputs_path, input_sha256=self.input_sha,
                      sources_dir=self.sources, bundle_manifest=self.bundle_manifest)
        values.update(changes)
        return values

    def install(self, **changes):
        receipt = changes.pop('receipt_output', self.receipt)
        return installer.install_writer(**self.args(**changes), receipt_output=receipt)

    def verify(self, **changes):
        return verification.verify_writer(**self.args(**changes))

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
        with self.assertRaises(verification.Refused) as caught:
            callback()
        self.assertRegex(caught.exception.reason, r'^[a-z_]{1,64}$')
        self.assertEqual(self.snapshot(), before)
        return caught.exception.reason

    def test_exact_bytes_metadata_receipt_and_read_only_verification(self):
        self.write(self.rootfs / 'etc/os-release', b'NAME="Inert base OS"\n')
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('child executed')), \
                patch.object(os, 'system', side_effect=AssertionError('shell executed')):
            result = self.install()
        expected = {verification.SOURCE_MAP[name][0]: (raw, verification.SOURCE_MAP[name][1])
                    for name, raw in self.payload.items()}
        expected[verification.HELPER] = self.helper, '0555'
        self.assertEqual(len(expected), 17)
        self.assertEqual(set(result['records']), set(expected))
        for name, (raw, mode) in expected.items():
            path = self.rootfs / name
            info = path.lstat()
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(stat.S_IMODE(info.st_mode), int(mode, 8))
            self.assertEqual((info.st_uid, info.st_gid, info.st_nlink),
                             (os.geteuid(), os.getegid(), 1))
        self.assertEqual(result['os_commit_evidence'], 'caller-declared-correlation-only')
        self.assertTrue(result['files_verified'])
        for flag in ('studio_bundle_qualified', 'services_enabled', 'service_actions_issued',
                     'image_code_executed', 'application_code_executed', 'support_verified',
                     'authority_provisioned', 'runtime_qualified', 'image_qualified', 'hardware_qualified'):
            self.assertIs(result[flag], False)
        self.assertEqual(self.receipt.read_bytes(), verification.canonical(result))
        self.assertEqual(stat.S_IMODE(self.receipt.stat().st_mode), 0o600)
        before = self.snapshot()
        self.assertEqual(self.verify(), dict(result, operation='verify'))
        self.assertEqual(self.snapshot(), before)
        self.assertEqual((self.rootfs / 'etc/os-release').read_bytes(), b'NAME="Inert base OS"\n')

    def test_closed_mapping_matches_existing_unit_influence_contract(self):
        runtime = module('writer_files_unit_contract_fixture', ROOT / 'scripts/factory-runtime-contract.py')
        self.assertEqual(verification.UNIT_ABSENT, runtime.UNIT_ABSENT)
        self.assertEqual(verification.TEST_ABSENT, runtime.TEST_ABSENT)
        self.assertEqual(verification.UNITS, set(runtime.UNIT_TEMPLATES))
        self.assertEqual(len(verification.SOURCE_MAP), 16)

    def test_existing_trusted_parent_permissions_are_preserved(self):
        directory = self.rootfs / 'usr/local/lib'
        directory.mkdir(parents=True)
        directory.chmod(0o711)
        before = directory.stat()
        self.install()
        after = directory.stat()
        self.assertEqual((after.st_mode, after.st_uid, after.st_gid, after.st_ino),
                         (before.st_mode, before.st_uid, before.st_gid, before.st_ino))

    def test_input_pin_missing_changed_or_extra_source_pins_refuse_before_write(self):
        for variant in ('missing', 'changed', 'extra'):
            original = dict(self.inputs['os_source_sha256'])
            first = sorted(original)[0]
            if variant == 'missing':
                del self.inputs['os_source_sha256'][first]
            elif variant == 'changed':
                self.inputs['os_source_sha256'][first] = '0' * 64
            else:
                self.inputs['os_source_sha256']['scripts/extra.py'] = '0' * 64
            self.write_inputs()
            with self.subTest(variant=variant):
                self.refused_without_write(self.install)
            self.inputs['os_source_sha256'] = original
        self.write_inputs()
        self.refused_without_write(lambda: self.install(input_sha256='0' * 64))

    def test_unknown_fields_duplicate_json_boolean_schema_and_studio_commit_refuse(self):
        for field, content in (('extra', True), ('schema_version', True), ('studio_commit', 'b' * 40)):
            previous = dict(self.inputs)
            self.inputs[field] = content; self.write_inputs()
            with self.subTest(field=field):
                self.refused_without_write(self.install)
            self.inputs = previous
        self.write_inputs()
        raw = self.inputs_path.read_bytes().rstrip()[:-1] + b',"schema_version":1}\n'
        self.inputs_path.write_bytes(raw)
        self.refused_without_write(lambda: self.install(input_sha256=verification.sha(raw)))

    def test_source_bytes_missing_extra_file_and_empty_directory_refuse(self):
        path = self.sources / sorted(self.payload)[0]
        raw = path.read_bytes()
        path.write_bytes(b'changed')
        self.refused_without_write(self.install)
        path.unlink()
        self.refused_without_write(self.install)
        self.write(path, raw)
        extra = self.sources / 'extra.py'; self.write(extra, b'never run')
        self.refused_without_write(self.install); extra.unlink()
        extra.mkdir()
        self.refused_without_write(self.install)

    def test_helper_bytes_record_bundle_copy_and_external_pin_refuse(self):
        path = self.rootfs / verification.BUNDLE / verification.HELPER_SOURCE
        path.write_bytes(b'changed')
        self.refused_without_write(self.install); path.write_bytes(self.helper)
        self.bundle['records'][verification.HELPER_SOURCE]['sha256'] = '0' * 64
        self.write_bundle()
        self.inputs['studio_bundle_manifest_sha256'] = verification.sha(verification.canonical(self.bundle))
        self.write_inputs()
        self.refused_without_write(self.install)

    def test_installed_bundle_manifest_mismatch_refuses(self):
        self.write(self.rootfs / verification.BUNDLE / 'manifest.json', b'{}\n')
        self.refused_without_write(self.install)

    def test_source_symlink_and_hardlink_refuse(self):
        path = self.sources / sorted(self.payload)[0]
        raw = path.read_bytes()
        path.unlink(); path.symlink_to(self.inputs_path)
        self.refused_without_write(self.install); path.unlink(); self.write(path, raw)
        second = self.base / 'linked'; os.link(path, second)
        self.refused_without_write(self.install)

    def test_source_mode_owner_and_xattrs_refuse(self):
        path = self.sources / sorted(self.payload)[0]
        path.chmod(0o666)
        self.refused_without_write(self.install); path.chmod(0o644)
        with patch.object(guards, '_owner_ids', return_value=(os.geteuid() + 1, os.getegid())):
            self.refused_without_write(self.install)
        original = guards._xattrs

        def nonempty(root, target, **kwargs):
            info = os.fstat(target) if isinstance(target, int) else os.stat(target)
            if info.st_ino == path.stat().st_ino:
                return {'status': 'inspected', 'entries': {'user.fixture': 'inert'}}
            return original(root, target, **kwargs)
        with patch.object(guards, '_xattrs', nonempty):
            self.refused_without_write(self.install)

    def test_existing_destination_masks_aliases_enable_links_and_influence_directories_refuse(self):
        cases = (
            ('usr/lib/inkyos/factory-main.py', 'file'),
            ('etc/systemd/system/inky-studio.service', 'mask'),
            ('usr/lib/systemd/system/alias.service', 'alias'),
            ('etc/systemd/system/multi-user.target.wants/inky-studio.service', 'enable'),
            ('usr/lib/systemd/system/service.d', 'directory'),
        )
        for name, kind in cases:
            path = self.rootfs / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if kind == 'file':
                self.write(path, b'occupied')
            elif kind == 'directory':
                path.mkdir()
            else:
                path.symlink_to('/dev/null' if kind == 'mask' else
                                '/usr/lib/systemd/system/inky-studio.service')
            with self.subTest(kind=kind):
                self.refused_without_write(self.install)
            if kind == 'directory': path.rmdir()
            else: path.unlink()

    def test_factory_or_test_state_presence_refuses_without_reading_contents(self):
        for name in ('etc/inky-studio/factory-v1.json', 'var/lib/inkyos/initialization',
                     'etc/inkyos-test-enrollment', 'run/inkyos-admission'):
            path = self.rootfs / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.mkdir()
            with self.subTest(name=name):
                self.refused_without_write(self.install)
            path.rmdir()

    def test_unrelated_extension_directory_link_refuses_without_traversal(self):
        path = self.rootfs / 'usr/lib/systemd/system/other.service.wants'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(self.sources, target_is_directory=True)
        self.refused_without_write(self.install)

    def test_split_lib_refuses_and_exact_usr_merge_alias_is_preserved(self):
        path = self.rootfs / 'lib'
        path.mkdir()
        self.refused_without_write(self.install); path.rmdir()
        path.symlink_to('other')
        self.refused_without_write(self.install); path.unlink()
        path.symlink_to('usr/lib')
        before = path.lstat()
        self.install()
        self.assertEqual(os.readlink(path), 'usr/lib')
        self.assertEqual(path.lstat().st_ino, before.st_ino)

    def test_parent_symlink_workspace_permissions_overlap_and_host_root_refuse(self):
        path = self.rootfs / 'usr/local'
        path.symlink_to(self.sources, target_is_directory=True)
        self.refused_without_write(self.install); path.unlink()
        self.base.chmod(0o755)
        self.refused_without_write(self.install); self.base.chmod(0o700)
        self.refused_without_write(lambda: self.install(receipt_output=self.inputs_path))
        self.refused_without_write(lambda: self.install(receipt_output=self.rootfs / 'receipt'))
        self.refused_without_write(lambda: self.install(rootfs=Path('/')))

    def test_receipt_exists_and_verify_missing_files_refuse_without_write(self):
        self.write(self.receipt, b'previous receipt')
        self.refused_without_write(self.install)
        self.refused_without_write(self.verify)

    def test_source_replacement_after_first_read_refuses_before_write(self):
        original = verification._load_payload
        calls = 0
        path = self.sources / sorted(self.payload)[0]

        def replace(environment, digest):
            nonlocal calls
            value = original(environment, digest)
            calls += 1
            if calls == 1:
                path.write_bytes(b'replaced')
            return value
        with patch.object(verification, '_load_payload', replace):
            with self.assertRaises(verification.Refused): self.install()
        self.assertFalse((self.rootfs / 'usr/lib/inkyos').exists())
        self.assertFalse(self.receipt.exists())

    def test_held_parent_replacement_refuses_before_first_write(self):
        original = verification._preflight
        old = self.rootfs / 'usr'
        moved = self.rootfs / 'usr-old'
        calls = 0

        def replace(environment, payload, *, installing):
            nonlocal calls
            original(environment, payload, installing=installing)
            calls += 1
            if calls == 2:
                old.rename(moved); old.mkdir()
        with patch.object(verification, '_preflight', replace):
            with self.assertRaises(verification.Refused): self.install()
        self.assertFalse((old / 'lib/inkyos').exists())
        self.assertFalse((moved / 'lib/inkyos').exists())
        self.assertFalse(self.receipt.exists())

    def test_partial_write_is_retained_without_success_receipt_or_retry(self):
        original = guards._write_file
        calls = 0

        def fail(rootfs, fd, name, raw, mode):
            nonlocal calls
            calls += 1
            if calls == 2:
                original(rootfs, fd, name, raw[:4], mode)
                raise OSError('inert injected write failure')
            return original(rootfs, fd, name, raw, mode)
        with patch.object(guards, '_write_file', fail):
            with self.assertRaises(verification.Refused): self.install()
        present = [self.rootfs / name for name in sorted(
            destination for destination, _ in verification.SOURCE_MAP.values())]
        self.assertTrue(present[0].exists())
        self.assertEqual(present[1].read_bytes(), next(
            raw[:4] for name, raw in self.payload.items()
            if verification.SOURCE_MAP[name][0] == str(present[1].relative_to(self.rootfs))))
        self.assertFalse(self.receipt.exists())
        self.refused_without_write(self.install)

    def test_verify_rejects_changed_bytes_mode_links_and_new_unit_influence(self):
        self.install()
        path = self.rootfs / verification.HELPER
        path.chmod(0o644); path.write_bytes(b'changed'); path.chmod(0o555)
        self.refused_without_write(self.verify)
        path.chmod(0o644); path.write_bytes(self.helper); path.chmod(0o555)
        path.chmod(0o755)
        self.refused_without_write(self.verify); path.chmod(0o555)
        alias = self.rootfs / 'usr/lib/systemd/system/new-alias.service'
        alias.symlink_to('inky-studio.service')
        self.refused_without_write(self.verify)

    def test_verify_rejects_destination_symlink_hardlink_and_xattrs(self):
        self.install()
        path = self.rootfs / verification.HELPER
        linked = self.base / 'linked-helper'; os.link(path, linked)
        self.refused_without_write(self.verify); linked.unlink()
        path.unlink(); path.symlink_to(self.rootfs / verification.BUNDLE / verification.HELPER_SOURCE)
        self.refused_without_write(self.verify); path.unlink(); self.write(path, self.helper, 0o555)
        original = guards._xattrs

        def nonempty(root, target, **kwargs):
            info = os.fstat(target) if isinstance(target, int) else os.stat(target)
            if info.st_ino == path.stat().st_ino:
                return {'status': 'inspected', 'entries': {'user.fixture': 'inert'}}
            return original(root, target, **kwargs)
        with patch.object(guards, '_xattrs', nonempty):
            self.refused_without_write(self.verify)

    def test_helper_source_mode_and_boolean_record_metadata_refuse(self):
        path = self.rootfs / verification.BUNDLE / verification.HELPER_SOURCE
        path.chmod(0o555)
        self.refused_without_write(self.install); path.chmod(0o644)
        self.bundle['records'][verification.HELPER_SOURCE]['uid'] = False
        self.write_bundle()
        self.inputs['studio_bundle_manifest_sha256'] = verification.sha(verification.canonical(self.bundle))
        self.write_inputs()
        self.refused_without_write(self.install)

    def test_production_boundary_exposes_no_fixture_override(self):
        with self.assertRaises(verification.Refused): PRODUCTION_ENVIRONMENT(Path('/'))
        with self.assertRaises(verification.Refused): PRODUCTION_ENVIRONMENT(self.rootfs)
        with self.assertRaises(verification.Refused):
            PRODUCTION_ENVIRONMENT(Path('/var/lib/inkyos-build/factory-studio.token/root'))
        with patch.object(sys, 'argv', ['verify-factory-writer-rootfs.py', '--owner-uid', '0']):
            with self.assertRaises(SystemExit), patch.object(sys, 'stderr'):
                verification.main()


if __name__ == '__main__':
    unittest.main()
