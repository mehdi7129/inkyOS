"""Inert exporter fixtures: no target Python, app, ELF or installer is executed.

Local bundle checks explicitly normalize UID/GID and the host xattr capability;
they are not native Linux ownership or runtime qualification.
"""
import base64
import contextlib
import copy
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
import warnings
from unittest.mock import Mock, call, patch
import zipfile


ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


verify = module('factory_exporter_verifier_fixture', 'verify-factory-exporter-rootfs.py')
installer = module('factory_exporter_installer_fixture', 'install-factory-exporter-rootfs.py')
WHEEL_NAME = 'fixture-1.0-py3-none-any.whl'
INERT = b'raise AssertionError("FIXTURE_MUST_NEVER_BE_IMPORTED")\n'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def archive(entries, modes=None):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as wheel:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            for path, content in entries:
                info = zipfile.ZipInfo(path)
                info.create_system = 3
                info.external_attr = (modes or {}).get(path, stat.S_IFREG | 0o644) << 16
                wheel.writestr(info, content)
    return output.getvalue()


def wheel_bytes(files=None, *, filename=WHEEL_NAME, tags=None, modes=None):
    stem = filename[:-4].split('-')
    metadata = '-'.join(stem[:2]) + '.dist-info'
    files = dict({'fixture/__init__.py': INERT} if files is None else files)
    files[metadata + '/WHEEL'] = (
        'Wheel-Version: 1.0\nRoot-Is-Purelib: true\n' +
        ''.join('Tag: ' + tag + '\n' for tag in (tags or ['-'.join(stem[-3:])]))).encode()
    files[metadata + '/METADATA'] = b'Metadata-Version: 2.1\nName: fixture\nVersion: 1.0\n'
    record = metadata + '/RECORD'
    rows = io.StringIO(newline='')
    writer = csv.writer(rows, lineterminator='\n')
    for path, content in files.items():
        encoded = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b'=').decode()
        writer.writerow((path, 'sha256=' + encoded, len(content)))
    writer.writerow((record, '', ''))
    files[record] = rows.getvalue().encode()
    return archive(files.items(), modes), files


class ExporterFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        # macOS /var is a symlink; fixture inputs deliberately use canonical paths.
        self.base = Path(temporary.name).resolve()
        self.root = self.base / 'root'
        self.sources = self.base / 'sources'
        self.wheels = self.base / 'wheels'
        for path in (self.root, self.sources, self.wheels):
            path.mkdir(mode=0o755)
            path.chmod(0o755)
        self.raw_wheel, self.wheel_files = wheel_bytes()
        self.source_files = {
            'inky_web/__init__.py': INERT,
            'inky_web/provisioning/__init__.py': INERT,
            'inky_web/provisioning/factory_credentials.py': INERT,
            'inky_web/auth.py': INERT,
        }
        self.lock = {
            'source_sha256': {p: digest(raw) for p, raw in self.source_files.items()},
            'wheel_sha256': {WHEEL_NAME: digest(self.raw_wheel)},
            'support_manifest_sha256': None,
            'base_image_sha256': '1' * 64,
            'base_lock_sha256': '2' * 64,
            'system_packages_lock_sha256': '3' * 64,
        }
        self.write(self.wheels / WHEEL_NAME, self.raw_wheel)
        for path, raw in self.source_files.items():
            self.write(self.sources / path, raw)

    def write(self, path, raw, mode=0o644):
        missing = []
        parent = path.parent
        while not parent.exists():
            missing.append(parent)
            parent = parent.parent
        for directory in reversed(missing):
            directory.mkdir(mode=0o755)
            directory.chmod(0o755)
        path.write_bytes(raw)
        path.chmod(mode)
        return path

    def build_inert_bundle(self):
        payload = dict(self.wheel_files, **self.source_files)
        self.support_digest = '5' * 64
        expected = verify.expected_bundle(payload, '3.13.5', self.support_digest)
        self.manifest_raw = verify.bundle_manifest(expected, self.support_digest)
        self.production_expected = copy.deepcopy(expected)
        bundle = self.root / verify.DESTINATION
        self.write(bundle / 'venv/pyvenv.cfg', verify.configuration('3.13.5'))
        # The installed manifest is computed with production identity and xattrs
        # before the fixture adapts comparison metadata to the host filesystem.
        self.write(bundle / 'manifest.json', self.manifest_raw)
        for path, raw in payload.items():
            self.write(bundle / verify.SITE / path, raw)
        for path, record in sorted(expected.items(), key=lambda item: item[0].count('/')):
            target = bundle / path
            if record['type'] == 'directory':
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(0o755)
            elif record['type'] == 'symlink':
                target.symlink_to(record['target'])
                if sys.platform == 'darwin':
                    # macOS applies umask to symlink modes; explicitly create
                    # the Linux 0777 fixture rather than accepting arbitrary modes.
                    target.lchmod(0o777)
        # Only host-specific identity/xattr capability is normalized. Expected
        # paths, bytes, modes and symlink targets remain independently derived.
        actual = verify.inventory_module.inventory(bundle)
        for path, record in expected.items():
            record['uid'], record['gid'] = os.getuid(), os.getgid()
            xattrs = actual[path]['xattrs']
            self.assertEqual(xattrs, verify.EMPTY_XATTRS if sys.platform.startswith('linux')
                             else {'status': 'unsupported', 'reason': 'platform'})
            record['xattrs'] = copy.deepcopy(xattrs)
        self.bundle = bundle
        self.expected = expected
        return expected

    def check_bundle(self):
        return verify.verify_bundle(self.root, self.expected,
                                    owner=(os.getuid(), os.getgid()), fixture=True)

    @contextlib.contextmanager
    def builder_identity(self):
        real_inventory = installer.verifier.inventory_module.inventory

        def fixture_inventory(path):
            records = real_inventory(path)
            # Only Linux identity/xattr capability is simulated. Real bytes,
            # entry sets, file kinds and modes drive the rejection under test.
            for record in records.values():
                record['uid'] = record['gid'] = 1000
                record['xattrs'] = copy.deepcopy(verify.EMPTY_XATTRS)
            return records

        with patch.object(installer.verifier.inventory_module, 'inventory', side_effect=fixture_inventory):
            yield

    def support_fixture(self):
        directory = {'type': 'directory', 'uid': 0, 'gid': 0, 'mode': '0755',
                     'xattrs': copy.deepcopy(verify.EMPTY_XATTRS)}
        paths = {path: copy.deepcopy(directory)
                 for path in ('.', 'usr', 'usr/bin', 'usr/lib', 'usr/local', 'etc')}
        # Deliberately non-ELF bytes: load_support validates a trusted inventory
        # contract, never loads the interpreter or claims to perform ELF review.
        paths['usr/bin/python3.13'] = verify.file_record(b'INERT_INTERPRETER', '0755')
        paths['usr/bin/setpriv'] = verify.file_record(b'INERT_SETPRIV', '0755')
        paths['usr/bin/env'] = verify.file_record(b'INERT_ENV', '0755')
        paths['usr/bin/python3'] = {'type': 'symlink', 'uid': 0, 'gid': 0, 'mode': '0777',
                                  'target': 'python3.13', 'xattrs': copy.deepcopy(verify.EMPTY_XATTRS)}
        paths['etc/ld.so.cache'] = verify.file_record(b'INERT_CACHE')
        paths['etc/ld.so.conf'] = verify.file_record(b'include /etc/ld.so.conf.d/*.conf\n')
        trees = {path: {'.': copy.deepcopy(directory)} for path in
                 ('usr/lib/python3.13', 'usr/lib/aarch64-linux-gnu',
                  'usr/local/lib', 'etc/ld.so.conf.d')}
        return dict(schema_version=1, kind='factory-exporter-system-support',
                    python_version='3.13.5', paths=paths, trees=trees,
                    absent=sorted(verify.ABSENCE_GUARDS),
                    elf_closure_review={'method': 'INERT_FIXTURE_NOT_A_NATIVE_REVIEW',
                                        'evidence_sha256': '4' * 64,
                                        'roots': ['usr/bin/python3.13', 'usr/bin/setpriv', 'usr/bin/env'],
                                        'files': ['usr/bin/python3.13', 'usr/bin/setpriv', 'usr/bin/env'],
                                        'search_paths': ['usr/lib/aarch64-linux-gnu']},
                    **{key: self.lock[key] for key in
                       ('base_image_sha256', 'base_lock_sha256', 'system_packages_lock_sha256')})

    def load_support_fixture(self, support):
        raw = json.dumps(support, sort_keys=True).encode()
        self.lock['support_manifest_sha256'] = digest(raw)
        path = self.write(self.base / 'support.json', raw)
        return verify.load_support(self.lock, path)


class WheelPayloadTests(ExporterFixture):
    def test_valid_wheel_preserves_record_and_every_payload_byte_without_import(self):
        self.assertEqual(verify.wheel_payload(self.raw_wheel, WHEEL_NAME), self.wheel_files)
        expected = dict(self.wheel_files, **self.source_files)
        self.assertEqual(verify.expected_payload(self.lock, self.sources, self.wheels), expected)
        self.assertEqual(len(self.lock['source_sha256']), 4)
        self.assertNotIn('fixture', sys.modules)

    def test_native_filename_compressed_tags_accepts_expanded_wheel_tags(self):
        filename = 'fixture-1.0-cp313-cp313-manylinux_2_17_aarch64.manylinux2014_aarch64.whl'
        raw, files = wheel_bytes(filename=filename, tags=[
            'cp313-cp313-manylinux_2_17_aarch64', 'cp313-cp313-manylinux2014_aarch64'])
        self.assertEqual(verify.wheel_payload(raw, filename), files)

    def test_record_tamper_missing_duplicate_and_unrecorded_members_are_refused(self):
        record = 'fixture-1.0.dist-info/RECORD'
        cases = []
        tampered = dict(self.wheel_files); tampered['fixture/__init__.py'] = b'changed\n'
        cases.append(list(tampered.items()))
        missing = dict(self.wheel_files); missing.pop('fixture/__init__.py')
        cases.append(list(missing.items()))
        duplicate = dict(self.wheel_files)
        duplicate[record] += duplicate[record].splitlines(keepends=True)[0]
        cases.append(list(duplicate.items()))
        cases.append(list(self.wheel_files.items()) + [('unrecorded.py', INERT)])
        cases.append(list(self.wheel_files.items()) + [('fixture/__init__.py', INERT)])
        for entries in cases:
            with self.subTest(entries=[p for p, _ in entries]), self.assertRaises(ValueError):
                verify.wheel_payload(archive(entries), WHEEL_NAME)

    def test_unsafe_and_import_hook_paths_are_refused_even_with_valid_record(self):
        paths = ('../escape.py', '/absolute.py', 'a//b.py', 'a/./b.py', 'a\\b.py',
                 'fixture-1.0.data/scripts/tool', 'inject.pth', 'local.egg-link',
                 'sitecustomize.py', 'usercustomize/__init__.py', 'sitecustomize.cpython-313.so',
                 '__pycache__/fixture.cpython-313.pyc', 'fixture.pyc')
        for path in paths:
            raw, _ = wheel_bytes({path: INERT})
            with self.subTest(path=path), self.assertRaises(ValueError):
                verify.wheel_payload(raw, WHEEL_NAME)

    def test_zip_name_with_hidden_nul_suffix_is_refused(self):
        # zipfile truncates ZipInfo.filename at NUL while retaining orig_filename.
        # Build the malformed ZIP explicitly; ZipInfo's writer sanitizes NULs.
        prefix = 'fixture/__init__.py'
        entries = [(path + 'XXXXX' if path == prefix else path, raw)
                   for path, raw in self.wheel_files.items()]
        raw = archive(entries).replace((prefix + 'XXXXX').encode(), (prefix + '\0xxxx').encode())
        with self.assertRaises(ValueError):
            verify.wheel_payload(raw, WHEEL_NAME)

    def test_wheel_links_special_modes_and_file_directory_collisions_are_refused(self):
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o600, stat.S_IFREG | 0o4755):
            raw, _ = wheel_bytes(modes={'fixture/__init__.py': mode})
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                verify.wheel_payload(raw, WHEEL_NAME)
        raw, _ = wheel_bytes({'collision': b'file', 'collision/module.py': INERT})
        with self.assertRaisesRegex(ValueError, 'collision'):
            verify.wheel_payload(raw, WHEEL_NAME)

    def test_pinned_source_and_wheel_hashes_and_exact_wheelhouse_are_enforced(self):
        for path in (self.wheels / WHEEL_NAME, self.sources / 'inky_web/auth.py'):
            original = path.read_bytes()
            path.write_bytes(original + b'changed')
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'hash mismatch'):
                verify.expected_payload(self.lock, self.sources, self.wheels)
            path.write_bytes(original)
        self.write(self.wheels / 'extra.whl', b'not an accepted input')
        with self.assertRaisesRegex(ValueError, 'exactly'):
            verify.expected_payload(self.lock, self.sources, self.wheels)

    def test_source_and_cross_wheel_collisions_are_refused(self):
        for filename, files in (('other-1.0-py3-none-any.whl', {'fixture/__init__.py': INERT}),
                                ('other-2.0-py3-none-any.whl', {'inky_web/auth.py': INERT})):
            raw, _ = wheel_bytes(files, filename=filename)
            self.write(self.wheels / filename, raw)
            self.lock['wheel_sha256'][filename] = digest(raw)
            with self.subTest(filename=filename), self.assertRaisesRegex(ValueError, 'collision'):
                verify.expected_payload(self.lock, self.sources, self.wheels)
            (self.wheels / filename).unlink()
            del self.lock['wheel_sha256'][filename]

    def test_input_symlink_hardlink_and_fifo_are_refused_without_reading_them(self):
        path = self.sources / 'inky_web/auth.py'
        original = path.read_bytes()
        outside = self.write(self.base / 'outside.py', original)
        for kind in ('symlink', 'hardlink', 'fifo'):
            path.unlink()
            if kind == 'symlink':
                path.symlink_to(outside)
            elif kind == 'hardlink':
                os.link(outside, path)
            else:
                os.mkfifo(path)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                verify.expected_payload(self.lock, self.sources, self.wheels)
            path.unlink()
            self.write(path, original)


class BundleTests(ExporterFixture):
    def test_exact_bundle_is_checked_statically_with_explicit_fixture_identity(self):
        self.build_inert_bundle()
        self.assertEqual(self.check_bundle(), self.expected)
        self.assertFalse(any('pip' in p or 'setuptools' in p or p.endswith('.pyc') for p in self.expected))
        self.assertEqual(os.readlink(self.bundle / 'venv/bin/python3.13'), '/usr/bin/python3.13')

    def test_manifest_is_deterministic_and_excludes_only_its_own_record(self):
        payload = dict(self.wheel_files, **self.source_files)
        support_pin = '5' * 64
        expected = verify.expected_bundle(payload, '3.13.5', support_pin)
        raw = verify.bundle_manifest(expected, support_pin)
        reordered = verify.expected_bundle(dict(reversed(list(payload.items()))), '3.13.5', support_pin)
        self.assertEqual(verify.bundle_manifest(reordered, support_pin), raw)
        manifest = json.loads(raw)
        self.assertEqual(manifest['support_manifest_sha256'], support_pin)
        self.assertEqual(manifest['records'], {p: r for p, r in expected.items() if p != 'manifest.json'})
        self.assertIn('.', manifest['records'])
        self.assertIn('venv/pyvenv.cfg', manifest['records'])
        self.assertIn(verify.SITE + '/fixture-1.0.dist-info/RECORD', manifest['records'])
        self.assertEqual(expected['manifest.json'], verify.file_record(raw))
        expected['manifest.json'] = {'this_self_record': 'must_not_be_serialized'}
        self.assertEqual(verify.bundle_manifest(expected, support_pin), raw)

    def test_manifest_changes_with_pinned_payload_support_or_python_configuration(self):
        payload = dict(self.wheel_files, **self.source_files)
        baseline = verify.expected_bundle(payload, '3.13.5', '5' * 64)
        changed_payload = dict(payload)
        changed_payload['inky_web/auth.py'] += b'# changed pinned input\n'
        variants = (
            verify.expected_bundle(changed_payload, '3.13.5', '5' * 64),
            verify.expected_bundle(payload, '3.13.5', '6' * 64),
            verify.expected_bundle(payload, '3.13.6', '5' * 64),
        )
        for index, expected in enumerate(variants):
            with self.subTest(variant=index):
                self.assertNotEqual(expected['manifest.json']['sha256'], baseline['manifest.json']['sha256'])
        self.assertEqual({p: r for p, r in variants[1].items() if p != 'manifest.json'},
                         {p: r for p, r in baseline.items() if p != 'manifest.json'})

    def test_manifest_tamper_is_refused_without_rebuilding_expected_from_disk(self):
        self.build_inert_bundle()
        path = self.bundle / 'manifest.json'
        path.write_bytes(self.manifest_raw + b' ')
        with self.assertRaisesRegex(ValueError, 'exact source/wheel'):
            self.check_bundle()
        path.write_bytes(self.manifest_raw)
        self.assertEqual(self.check_bundle(), self.expected)
        path.unlink()
        with self.assertRaisesRegex(ValueError, 'exact source/wheel'):
            self.check_bundle()

    def test_file_tamper_missing_record_and_additional_importable_files_are_refused(self):
        self.build_inert_bundle()
        path = self.bundle / verify.SITE / 'fixture/__init__.py'
        raw = path.read_bytes()
        path.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'exact source/wheel'):
            self.check_bundle()
        path.write_bytes(raw)
        record = self.bundle / verify.SITE / 'fixture-1.0.dist-info/RECORD'
        raw_record = record.read_bytes(); record.unlink()
        with self.assertRaisesRegex(ValueError, 'exact source/wheel'):
            self.check_bundle()
        self.write(record, raw_record)
        for name in ('extra.py', 'inject.pth', 'local.egg-link', 'sitecustomize.py', 'pip/__init__.py'):
            extra = self.write(self.bundle / verify.SITE / name, INERT)
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check_bundle()
            extra.unlink()
            if name.startswith('pip/'):
                extra.parent.rmdir()

    def test_bundle_links_special_files_and_writable_parents_are_refused(self):
        self.build_inert_bundle()
        path = self.bundle / verify.SITE / 'fixture/__init__.py'
        raw = path.read_bytes()
        target = self.write(self.base / 'outside.py', raw)
        for kind in ('symlink', 'hardlink', 'fifo'):
            path.unlink()
            if kind == 'symlink':
                path.symlink_to(target)
            elif kind == 'hardlink':
                os.link(target, path)
            else:
                os.mkfifo(path)
            with self.subTest(kind=kind), self.assertRaises((ValueError, verify.inventory_module.ManifestError)):
                self.check_bundle()
            path.unlink(); self.write(path, raw)
        for parent in (self.root, self.root / 'usr', self.root / 'usr/lib', self.root / 'usr/lib/inkyos'):
            original = stat.S_IMODE(parent.stat().st_mode)
            parent.chmod(0o777)
            with self.subTest(parent=parent), self.assertRaisesRegex(ValueError, 'Writable'):
                self.check_bundle()
            parent.chmod(original)

    def test_single_record_refuses_special_or_multiple_link_files(self):
        path = self.write(self.base / 'plain', b'inert')
        record = verify.single_record(path)
        self.assertEqual(record['sha256'], digest(b'inert'))
        os.link(path, self.base / 'alias')
        with self.assertRaisesRegex(ValueError, 'hardlink'):
            verify.single_record(path)
        fifo = self.base / 'fifo'; os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, 'Special'):
            verify.single_record(fifo)


class SupportTests(ExporterFixture):
    def test_inert_support_contract_is_parsed_without_executing_interpreter(self):
        support = self.support_fixture()
        loaded, records = self.load_support_fixture(support)
        self.assertEqual(loaded, support)
        self.assertEqual(records['usr/bin/python3.13']['sha256'], digest(b'INERT_INTERPRETER'))

    def test_missing_pin_and_manifest_hash_tamper_are_refused(self):
        for pin in (None, '', 'not-a-hash', 'A' * 64, True):
            with self.subTest(pin=pin), self.assertRaisesRegex(ValueError, 'not pinned'):
                verify.require_support_pin({'support_manifest_sha256': pin})
        self.load_support_fixture(self.support_fixture())
        path = self.base / 'support.json'
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, 'pin mismatch'):
            verify.load_support(self.lock, path)

    def test_wrong_provenance_missing_inventory_and_unsafe_records_are_refused(self):
        cases = []
        support = self.support_fixture(); support['base_image_sha256'] = 'a' * 64; cases.append(support)
        support = self.support_fixture(); del support['trees']['usr/local/lib']; cases.append(support)
        support = self.support_fixture(); support['absent'].remove('etc/ld.so.preload'); cases.append(support)
        support = self.support_fixture(); support['paths']['usr/bin/python3']['target'] = '/outside/python'; cases.append(support)
        support = self.support_fixture(); support['paths']['usr/bin/python3']['target'] = 'python3'; cases.append(support)
        support = self.support_fixture(); support['paths']['usr/bin/python3.13']['mode'] = '0777'; cases.append(support)
        support = self.support_fixture(); support['paths']['usr']['uid'] = 1000; cases.append(support)
        support = self.support_fixture(); support['paths']['usr']['xattrs'] = {'status': 'unsupported', 'reason': 'platform'}; cases.append(support)
        support = self.support_fixture(); support['elf_closure_review']['evidence_sha256'] = ''; cases.append(support)
        support = self.support_fixture(); support['elf_closure_review']['roots'].remove('usr/bin/setpriv'); cases.append(support)
        for index, support in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(ValueError):
                self.load_support_fixture(support)

    def test_duplicate_json_keys_are_refused_even_with_matching_input_hash(self):
        raw = b'{"schema_version": 1, "schema_version": 1}'
        self.lock['support_manifest_sha256'] = digest(raw)
        path = self.write(self.base / 'duplicate.json', raw)
        with self.assertRaisesRegex(ValueError, 'Duplicate JSON'):
            verify.load_support(self.lock, path)

    def test_python_path_override_absence_cannot_be_omitted_or_declared_present(self):
        path = 'usr/bin/python3.13._pth'
        support = self.support_fixture()
        support['absent'].remove(path)
        with self.assertRaisesRegex(ValueError, 'absence guards'):
            self.load_support_fixture(support)
        support = self.support_fixture()
        support['paths'][path] = verify.file_record(b'/unreviewed/imports\n')
        with self.assertRaisesRegex(ValueError, 'Present and absent'):
            self.load_support_fixture(support)

    def test_absence_check_rejects_a_real_file_or_dangling_link_without_following_it(self):
        # Isolate the absence checker, without claiming this partial map is a
        # complete support manifest or invoking the public PASS/report path.
        path = self.root / 'usr/bin/python3.13._pth'
        self.write(path.parent / 'keep', b'inert')
        support = {'trees': {}, 'paths': {}, 'absent': ['usr/bin/python3.13._pth']}
        records = {'usr/bin': verify.single_record(path.parent)}
        verify.verify_support(self.root, support, records)
        path.write_bytes(b'/unreviewed/imports\n')
        with self.assertRaisesRegex(ValueError, 'Forbidden'):
            verify.verify_support(self.root, support, records)
        path.unlink()
        path.symlink_to(self.base / 'nonexistent')
        with self.assertRaisesRegex(ValueError, 'Forbidden'):
            verify.verify_support(self.root, support, records)
        path.unlink()
        (path.parent / 'keep').unlink(); path.parent.rmdir()
        path.parent.symlink_to(self.sources, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'Symlink'):
            verify.verify_support(self.root, support, records)

    def test_verifier_cli_with_null_pin_refuses_before_inspection_or_report_creation(self):
        output = self.base / 'report.json'
        args = ['--rootfs', str(self.root), '--sources-dir', str(self.sources),
                '--wheels-dir', str(self.wheels), '--support-manifest', str(self.base / 'missing.json'),
                '--output', str(output)]
        stdout = io.StringIO(); stderr = io.StringIO()
        before = list(self.root.rglob('*'))
        with patch.object(verify, 'load_lock', return_value=self.lock), \
                patch.object(verify, 'verify', side_effect=AssertionError('must stop before verification')) as check, \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(verify.main(args), 1)
        check.assert_not_called()
        self.assertNotIn('PASS', stdout.getvalue())
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.rglob('*')), before)


class InstallerTests(ExporterFixture):
    def test_run_step_waits_for_normal_supervisor_completion(self):
        process = Mock(pid=4321)
        process.wait.return_value = 0
        log = self.base / 'normal-step.log'
        with patch.object(installer.subprocess, 'Popen', return_value=process) as popen, \
                patch.object(installer.os, 'killpg') as killpg:
            installer.run_step(self.root, ['/INERT_COMMAND'], log, timeout=7)
        popen.assert_called_once()
        process.wait.assert_called_once_with(timeout=7)
        killpg.assert_not_called()
        self.assertEqual(log.read_bytes(), b'')

    def test_run_step_kills_then_waits_before_propagating_timeout_or_interruption(self):
        failures = (subprocess.TimeoutExpired(['/INERT_COMMAND'], 7), KeyboardInterrupt())
        for index, failure in enumerate(failures):
            events = []
            process = Mock(pid=4321)

            def wait(timeout=None):
                events.append(('wait', timeout))
                if len(events) == 1:
                    raise failure
                return -signal.SIGKILL

            process.wait.side_effect = wait
            with self.subTest(failure=type(failure).__name__), \
                    patch.object(installer.subprocess, 'Popen', return_value=process), \
                    patch.object(installer.os, 'killpg',
                                 side_effect=lambda pid, sig: events.append(('killpg', pid, sig))) as killpg:
                with self.assertRaises(type(failure)) as raised:
                    installer.run_step(self.root, ['/INERT_COMMAND'],
                                       self.base / ('failed-step-' + str(index) + '.log'), timeout=7)
                self.assertIs(raised.exception, failure)
            self.assertEqual(events, [('wait', 7), ('killpg', 4321, signal.SIGKILL), ('wait', None)])
            self.assertEqual(process.wait.call_args_list, [call(timeout=7), call()])
            killpg.assert_called_once_with(4321, signal.SIGKILL)

    def test_finish_refuses_child_created_manifest_without_overwriting_or_freezing(self):
        self.build_inert_bundle()
        manifest = self.bundle / 'manifest.json'
        child_content = b'CHILD_CREATED_MUST_NOT_BECOME_TRUST_INPUT\n'
        manifest.write_bytes(child_content)
        for name in ('activate', 'activate.csh', 'activate.fish', 'Activate.ps1'):
            self.write(self.bundle / 'venv/bin' / name, INERT)
        with self.builder_identity(), patch.object(installer.os, 'chown') as chown:
            with self.assertRaisesRegex(ValueError, 'before freeze'):
                installer.finish_tree(self.bundle, self.production_expected, self.manifest_raw, '3.13.5')
        chown.assert_not_called()
        self.assertEqual(manifest.read_bytes(), child_content)

    def test_finish_refuses_extra_pth_before_manifest_publication_or_freeze(self):
        self.build_inert_bundle()
        manifest = self.bundle / 'manifest.json'
        manifest.unlink()
        injected = self.write(self.bundle / verify.SITE / 'unreviewed.pth', b'import forbidden_hook\n')
        for name in ('activate', 'activate.csh', 'activate.fish', 'Activate.ps1'):
            self.write(self.bundle / 'venv/bin' / name, INERT)
        with self.builder_identity(), patch.object(installer.os, 'chown') as chown:
            with self.assertRaisesRegex(ValueError, 'before freeze'):
                installer.finish_tree(self.bundle, self.production_expected, self.manifest_raw, '3.13.5')
        chown.assert_not_called()
        self.assertFalse(manifest.exists())
        self.assertEqual(injected.read_bytes(), b'import forbidden_hook\n')

    def test_builder_steps_do_not_import_global_site_or_run_pip(self):
        steps = installer.install_steps()
        self.assertEqual([label for label, _ in steps], ['venv', 'payload'])
        for label, command in steps:
            with self.subTest(label=label):
                self.assertEqual(command[0], '/usr/bin/python3.13')
                self.assertIn('-I', command)
                self.assertIn('-B', command)
                self.assertIn('-S', command)
                self.assertFalse(any(part in {'pip', 'ensurepip', 'setup.py'} for part in command))
        self.assertIn('--without-pip', steps[0][1])
        self.assertIn('--without-scm-ignore-files', steps[0][1])
        self.assertNotIn('--system-site-packages', steps[0][1])

    def test_child_command_drops_identity_and_groups_before_target_python(self):
        command = ['/usr/bin/python3.13', '-I', '-B', '-S', '/inert.py']
        child = installer.child_command(self.root, command)
        self.assertEqual(child[-len(command):], command)
        boundary = child.index('/usr/bin/setpriv')
        self.assertLess(child.index('/usr/sbin/chroot'), boundary)
        self.assertIn(str(self.root), child[:boundary])
        for argument in ('--reuid=1000', '--regid=1000', '--clear-groups', '--no-new-privs',
                         '--inh-caps=-all', '--ambient-caps=-all', '--bounding-set=-all'):
            self.assertIn(argument, child[boundary:child.index('/usr/bin/env')])
        self.assertEqual(child[child.index('/usr/bin/env') + 1], '-i')
        self.assertIn('--kill-child=KILL', child)
        self.assertIn('--pid', child)
        self.assertIn('--fork', child)

    def test_guard_preserves_existing_destination_scratch_and_symlink_parent(self):
        self.write(self.root / 'usr/lib/keep', b'preserve')
        self.write(self.root / 'var/tmp/keep', b'preserve')
        installer.guard_destinations(self.root)
        self.assertFalse((self.root / 'usr/lib/inkyos').exists())
        destination = self.root / installer.DESTINATION.relative_to('/')
        self.write(destination / 'do-not-overwrite', b'existing exporter')
        with self.assertRaisesRegex(ValueError, 'already exists'):
            installer.guard_destinations(self.root)
        self.assertEqual((destination / 'do-not-overwrite').read_bytes(), b'existing exporter')
        (destination / 'do-not-overwrite').unlink(); destination.rmdir()
        scratch = self.root / installer.SCRATCH.relative_to('/')
        scratch.mkdir()
        with self.assertRaisesRegex(ValueError, 'already exists'):
            installer.guard_destinations(self.root)
        scratch.rmdir()
        destination.parent.rmdir()
        destination.parent.symlink_to(self.sources, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'Symlink'):
            installer.guard_destinations(self.root)
        with self.assertRaisesRegex(ValueError, 'Host root'):
            installer.guard_destinations(Path('/'))

    def test_installer_cli_null_support_pin_blocks_before_any_mutation_or_child(self):
        output = self.base / 'install-report.json'
        args = ['--rootfs', str(self.root), '--sources-dir', str(self.sources),
                '--wheels-dir', str(self.wheels), '--support-manifest', str(self.base / 'missing.json'),
                '--output', str(output)]
        stdout = io.StringIO(); stderr = io.StringIO()
        before = sorted(str(p.relative_to(self.base)) for p in self.base.rglob('*'))
        with patch.object(installer.verifier, 'load_lock', return_value=self.lock), \
                patch.object(installer.verifier, 'load_support') as support, \
                patch.object(installer, 'check_environment') as environment, \
                patch.object(installer, 'run_step') as child, \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(installer.main(args), 1)
        support.assert_not_called(); environment.assert_not_called(); child.assert_not_called()
        self.assertEqual(stdout.getvalue(), '')
        self.assertFalse(output.exists())
        self.assertFalse(output.with_name(output.name + '.logs').exists())
        self.assertEqual(sorted(str(p.relative_to(self.base)) for p in self.base.rglob('*')), before)


if __name__ == '__main__':
    unittest.main()
