"""Synthetic fixed-contract tests, independent of builders and other test suites.

No image, service, app or factory hook is executed. macOS explicitly simulates
the Linux FD xattr API; Linux exercises the real API and numeric metadata.
"""
import copy
from contextlib import contextmanager
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runtime = load_module('factory_runtime_test', 'scripts/factory-runtime-contract.py')
BOOT_ID = '12345678-1234-1234-1234-123456789abc'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


@contextmanager
def temporary_umask(value):
    previous = os.umask(value)
    try:
        yield
    finally:
        os.umask(previous)


class ContractFixture(unittest.TestCase):
    def setUp(self):
        if sys.platform != 'linux':
            seam = patch.object(os, 'listxattr', create=True, return_value=[])
            seam.start()
            self.addCleanup(seam.stop)
        temporary = tempfile.TemporaryDirectory(
            prefix='inkyos-runtime-', dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / 'root'
        self.root.mkdir(mode=0o755)
        self.root.chmod(0o755)
        self.owner = {'_owner_uid': os.geteuid(), '_owner_gid': os.getegid()}
        self.mkdir('run')
        admission_bytes = (ROOT / 'staging/bootstrap/writer-admission.py').read_bytes()
        self.assertEqual(digest(admission_bytes), runtime.ADMISSION_SHA256)
        self.write(runtime.MODULE_DIR + '/writer-admission.py', admission_bytes, 0o555)
        self.manifest = {
            'version': 1, 'studio_commit': 'a' * 40,
            'bundle_manifest_sha256': 'b' * 64,
            'exporter_manifest_sha256': 'c' * 64,
            'support_manifest_sha256': 'd' * 64,
            'helper_uid': 991, 'provisioning_gid': 992,
            'os_module_pins': {
                'writer-admission.py': runtime.ADMISSION_SHA256,
                'factory-runtime-contract.py': 'e' * 64,
                'writer-launcher.py': 'f' * 64,
            },
        }
        self.write_manifest()

    def parents(self, path):
        current = self.root
        for part in path.relative_to(self.root).parts:
            current /= part
            try:
                current.mkdir(mode=0o755)
            except FileExistsError:
                continue
            current.chmod(0o755)

    def mkdir(self, relative, mode=0o755):
        path = self.root / relative
        self.parents(path.parent)
        path.mkdir(exist_ok=True, mode=mode)
        path.chmod(mode)
        return path

    def write(self, relative, raw, mode=0o644):
        path = self.root / relative
        self.parents(path.parent)
        if path.exists():
            path.chmod(0o600)
        path.write_bytes(raw)
        path.chmod(mode)
        return path

    def write_manifest(self, raw=None):
        return self.write(runtime.MANIFEST, encoded(self.manifest) if raw is None else raw)

    def symlink(self, relative, target):
        path = self.root / relative
        self.parents(path.parent)
        path.symlink_to(target)
        if stat.S_IMODE(path.lstat().st_mode) != 0o777:
            os.chmod(path, 0o777, follow_symlinks=False)
        return path

    def record(self, path):
        info = path.lstat()
        value = {'uid': 0, 'gid': 0, 'mode': f'{stat.S_IMODE(info.st_mode):04o}',
                 'xattrs': {'status': 'inspected', 'entries': {}}}
        if stat.S_ISREG(info.st_mode):
            raw = path.read_bytes()
            value.update(type='file', size_bytes=len(raw), sha256=digest(raw))
        elif stat.S_ISDIR(info.st_mode):
            value.update(type='directory')
        elif stat.S_ISLNK(info.st_mode):
            value.update(type='symlink', target=os.readlink(path))
        else:
            raise AssertionError('Fixture cannot inventory special files')
        return value

    def inventory(self, relative, *, exclude=()):
        root = self.root / relative
        return {str(path.relative_to(root)): self.record(path)
                for path in (root, *sorted(root.rglob('*')))
                if str(path.relative_to(root)) not in exclude}

    def full_candidate(self):
        """Inert source bytes and explicit inventories; never a runnable image."""
        for filename in ('factory-runtime-contract.py', 'writer-launcher.py'):
            raw = (ROOT / 'scripts' / filename).read_bytes()
            self.write(runtime.MODULE_DIR + '/' + filename, raw, 0o555)
            self.manifest['os_module_pins'][filename] = digest(raw)
        helper = b'raise AssertionError("fixture helper must not execute")\n'
        self.write(runtime.HELPER, helper, 0o555)
        self.write(runtime.APP + '/' + runtime.HELPER_SOURCE, helper, 0o555)
        for path in runtime.HOOKS:
            self.write(path, b'raise AssertionError("fixture factory hook must not execute")\n', 0o555)
        for path, mode in (runtime.SUPERVISOR_FILES | runtime.SETUP_FILES).items():
            self.write(path, b'# inert supervisor\n', int(mode, 8))
        for unit in runtime.UNIT_TEMPLATES:
            self.write(runtime.UNIT_VENDOR_DIR + '/' + unit,
                       (ROOT / 'staging/bootstrap' / unit).read_bytes())
        for command in runtime.NATIVE_COMMANDS:
            self.write(command,b'INERT_NATIVE_NOT_EXECUTED',0o755)
        self.write('usr/bin/python3.13', b'INERT_INTERPRETER_NOT_EXECUTED', 0o755)
        self.symlink('usr/bin/python3', 'python3.13')
        self.write('etc/ld.so.conf', b'include /etc/ld.so.conf.d/*.conf\n')
        self.write('etc/ld.so.cache', b'INERT_LOADER_CACHE')
        for prefix in ('usr/lib/python3.13', 'usr/lib/aarch64-linux-gnu',
                       'usr/lib/python3/dist-packages', 'etc/ld.so.conf.d'):
            self.mkdir(prefix)
        self.write('usr/lib/python3.13/site.py', b'# inert site module\n')
        self.write('usr/lib/python3/dist-packages/dbus/__init__.py', b'# inert IPC support\n')
        self.write('etc/private-runtime-support', b'INERT_PRIVATE_SUPPORT', 0o600)
        config = (b'home = /usr/bin\ninclude-system-site-packages = false\n'
                  b'version = 3.13.5\nexecutable = /usr/bin/python3.13\n')
        self.write(runtime.APP + '/server/.venv/pyvenv.cfg', config)
        self.symlink(runtime.APP + '/server/.venv/bin/python', '/usr/bin/python3.13')
        self.write(runtime.APP + '/server/.venv/lib/python3.13/site-packages/inky_web/main.py',
                   b'raise AssertionError("fixture studio must not execute")\n')
        self.write(runtime.EXPORTER + '/venv/pyvenv.cfg', config)
        self.symlink(runtime.EXPORTER + '/venv/bin/python', '/usr/bin/python3.13')
        self.write(runtime.EXPORTER + '/venv/lib/python3.13/site-packages/inky_web/provisioning/factory_credentials.py',
                   b'raise AssertionError("fixture exporter must not execute")\n')
        trees = {prefix: self.inventory(prefix) for prefix in
                 ('usr/lib/python3.13', 'usr/lib/aarch64-linux-gnu', 'usr/local/lib',
                  'etc/ld.so.conf.d', 'usr/lib/python3/dist-packages')}
        paths = {'.', 'usr', 'usr/bin', 'usr/sbin', 'usr/lib', 'usr/local', 'etc', 'etc/inkyos',
                 'usr/bin/python3', 'usr/bin/python3.13', 'usr/lib/python3',
                 'etc/ld.so.conf', 'etc/ld.so.cache', 'etc/private-runtime-support',
                 runtime.MODULE_DIR, 'usr/lib/systemd', 'usr/lib/systemd/system'}
        paths.update(runtime.MODULE_DIR + '/' + item for item in runtime.MODULES)
        paths.update(runtime.SUPERVISOR_FILES)
        paths.update(runtime.SETUP_FILES)
        paths.update(runtime.NATIVE_COMMANDS)
        paths.update(runtime.WRITER_FILES)
        self.support = {
            'schema_version': 1, 'kind': 'factory-exporter-system-support',
            'python_version': '3.13.5', 'paths': {path: self.record(self.root / path) for path in paths},
            'trees': trees, 'absent': sorted(runtime.ABSENCE_GUARDS | runtime.TEST_ABSENT | runtime.UNIT_ABSENT),
            'elf_closure_review': {
                'method': 'INERT_FIXTURE_NOT_A_NATIVE_REVIEW', 'evidence_sha256': '4' * 64,
                'roots': sorted({'usr/bin/python3.13'} | runtime.NATIVE_COMMANDS),
                'files': sorted({'usr/bin/python3.13'} | runtime.NATIVE_COMMANDS),
                'search_paths': ['usr/lib/aarch64-linux-gnu'],
            },
            **{field: '1' * 64 for field in ('base_image_sha256', 'base_lock_sha256',
                'system_packages_lock_sha256', 'test_access_packages_lock_sha256')},
        }
        self.bundle = {'schema_version': 1, 'kind': 'factory-studio-bundle-manifest',
                       'studio_commit': self.manifest['studio_commit'],
                       'records': self.inventory(runtime.APP)}
        self.exporter = {'schema_version': 1, 'kind': 'factory-exporter-bundle-manifest',
                         'support_manifest_sha256': digest(encoded(self.support)),
                         'records': self.inventory(runtime.EXPORTER)}
        self.publish_candidate()
        return self.contract()

    def publish_candidate(self):
        support_raw = encoded(self.support)
        self.write(runtime.SUPPORT, support_raw)
        self.exporter['support_manifest_sha256'] = digest(support_raw)
        app_raw, exporter_raw = encoded(self.bundle), encoded(self.exporter)
        self.write(runtime.APP + '/manifest.json', app_raw)
        self.write(runtime.EXPORTER + '/manifest.json', exporter_raw)
        self.manifest.update(bundle_manifest_sha256=digest(app_raw),
                             exporter_manifest_sha256=digest(exporter_raw),
                             support_manifest_sha256=digest(support_raw))
        self.write_manifest()

    def identity(self, role):
        provisioning = self.manifest['provisioning_gid']
        uid, gid, groups = {
            'main': (1000, 1000, [101, 102, 103, provisioning]),
            'helper': (self.manifest['helper_uid'], provisioning, [provisioning]),
            'ipc': (0, provisioning, [0, provisioning]),
            'setup':(0,0,[0,provisioning]),
        }[role]
        return {'uids': [uid] * 3, 'gids': [gid] * 3, 'groups': groups,
                'named_groups': {'spi': 101, 'i2c': 102, 'gpio': 103,
                                 'inky-provisioning': provisioning}}

    def mountinfo(self, *, filesystem='tmpfs', options='rw,nosuid,nodev',
                  mount_root='/', device=None, mountpoint=None):
        info = (self.root / 'run').stat()
        device = device or f'{os.major(info.st_dev)}:{os.minor(info.st_dev)}'
        mountpoint = str(self.root / 'run') if mountpoint is None else mountpoint
        mountpoint = mountpoint.replace('\\', '\\134').replace(' ', '\\040')
        return f'71 29 {device} {mount_root} {mountpoint} {options} - {filesystem} tmpfs rw\n'

    def contract(self, *, boot=BOOT_ID, mounts=None):
        return runtime.load_contract(_root=self.root, **self.owner, _boot_id=boot,
                                     _mountinfo=self.mountinfo() if mounts is None else mounts)

    def ready(self, contract=None):
        contract = self.contract() if contract is None else contract
        runtime.prepare_boot_context(contract)
        admission = runtime.import_admission(contract)
        admission.prepare(self.root, **self.owner)
        with admission.factory(self.root, **self.owner) as lease:
            lease.publish_ready()
        return contract, admission

    def snapshot(self):
        result = {}
        for path in (self.root, *sorted(self.root.rglob('*'))):
            info = path.lstat()
            value = (info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
                     info.st_dev, info.st_ino)
            if stat.S_ISREG(info.st_mode):
                value += (path.read_bytes(),)
            elif stat.S_ISLNK(info.st_mode):
                value += (os.readlink(path),)
            result[str(path.relative_to(self.root))] = value
        return result

    def assert_refused(self, operation, reason=None, *, unchanged=True):
        before = self.snapshot() if unchanged else None
        with self.assertRaises(runtime.Refused) as caught:
            operation()
        self.assertIs(type(caught.exception.reason), str)
        if reason is not None:
            self.assertEqual(caught.exception.reason, reason)
        if unchanged:
            self.assertEqual(self.snapshot(), before)
        return caught.exception.reason


class ManifestTests(ContractFixture):
    def test_valid_fixed_manifest_uses_hash_of_exact_bytes(self):
        contract = self.contract()
        self.assertEqual(contract.manifest, self.manifest)
        self.assertEqual(contract.candidate_sha256,
                         digest((self.root / runtime.MANIFEST).read_bytes()))
        self.assertFalse((self.root / runtime.CONTEXT_DIR).exists())

    def test_schema_rejects_missing_extra_bool_and_unpinned_admission(self):
        original = copy.deepcopy(self.manifest)
        cases = []
        for key in original:
            value = copy.deepcopy(original)
            del value[key]
            cases.append(value)
        for key, wrong in [('version', True), ('helper_uid', True), ('provisioning_gid', True),
                           ('helper_uid', 1000), ('helper_uid', 0), ('studio_commit', 'A' * 40),
                           ('bundle_manifest_sha256', 'g' * 64), ('unknown', 'field')]:
            value = copy.deepcopy(original)
            value[key] = wrong
            cases.append(value)
        value = copy.deepcopy(original)
        value['os_module_pins']['writer-admission.py'] = '0' * 64
        cases.append(value)
        value = copy.deepcopy(original)
        value['os_module_pins']['../writer-admission.py'] = value['os_module_pins'].pop('writer-admission.py')
        cases.append(value)
        for index, value in enumerate(cases):
            with self.subTest(index=index):
                self.manifest = value
                self.write_manifest()
                self.assert_refused(self.contract, 'invalid_contract')

    def test_duplicate_json_keys_and_nonfinite_values_refused(self):
        raw = encoded(self.manifest)
        for bad in (b'{"version":1,' + raw[1:],
                    raw.replace(b'"helper_uid":991', b'"helper_uid":NaN'),
                    b'[]', b'\xff'):
            with self.subTest(raw=bad[:32]):
                self.write_manifest(bad)
                self.assert_refused(self.contract)

    def test_manifest_symlink_hardlink_and_unsafe_modes_refused(self):
        target = self.root / runtime.MANIFEST
        original = target.read_bytes()
        alias = self.base / 'manifest-alias'
        alias.write_bytes(original)
        for defect in ('symlink', 'hardlink', 'writable', 'setuid', 'wrong-mode'):
            with self.subTest(defect=defect):
                target.unlink()
                if defect == 'symlink':
                    target.symlink_to(alias)
                elif defect == 'hardlink':
                    os.link(alias, target)
                else:
                    target.write_bytes(original)
                    target.chmod({'writable': 0o666, 'setuid': 0o4644, 'wrong-mode': 0o600}[defect])
                self.assert_refused(self.contract, 'invalid_metadata')

    def test_wrong_owner_or_group_rejected_before_read(self):
        for owner in ({'_owner_uid': os.geteuid() + 1, '_owner_gid': os.getegid()},
                      {'_owner_uid': os.geteuid(), '_owner_gid': os.getegid() + 1}):
            with self.subTest(owner=owner):
                self.assert_refused(lambda: runtime.load_contract(_root=self.root, **owner),
                                    'invalid_metadata')

    def test_xattr_api_failure_and_unreviewed_xattrs_refused(self):
        for options in ({'return_value': ['user.unreviewed']},
                        {'side_effect': OSError('unsupported')}):
            with self.subTest(options=options):
                with patch.object(os, 'listxattr', **options):
                    self.assert_refused(self.contract)

    def test_seams_cannot_target_real_root(self):
        with patch.object(runtime, 'Tree') as opened:
            for options in ({'_owner_uid': 1000}, {'_owner_gid': 1000},
                            {'_boot_id': BOOT_ID}, {'_mountinfo': self.mountinfo()}):
                with self.subTest(options=options):
                    with self.assertRaises(runtime.Refused):
                        runtime.load_contract(_root=Path('/'), **options)
            opened.assert_not_called()


class ContextTests(ContractFixture):
    def test_context_is_public_exact_and_tied_to_boot_and_candidate(self):
        contract = self.contract()
        expected = {'version': 1, 'boot_id': BOOT_ID,
                    'candidate_sha256': contract.candidate_sha256}
        self.assertEqual(runtime.prepare_boot_context(contract), expected)
        raw = (self.root / runtime.CONTEXT).read_bytes()
        self.assertEqual(raw, encoded(expected))
        self.assertEqual(runtime.validate_context(contract), expected)
        self.assertEqual(contract.context_sha256, digest(raw))
        self.assertEqual(stat.S_IMODE((self.root / runtime.CONTEXT).stat().st_mode), 0o644)
        self.assert_refused(lambda: runtime.prepare_boot_context(contract), 'context_exists')

    def test_run_requires_matching_tmpfs_device_mount_root_and_rw(self):
        variants = [self.mountinfo(filesystem='ext4'), self.mountinfo(options='ro'),
                    self.mountinfo(mount_root='/bound-subtree'), self.mountinfo(device='0:999999'),
                    self.mountinfo(mountpoint=str(self.root / 'elsewhere')),
                    self.mountinfo() * 2, 'not mountinfo\n']
        for mounts in variants:
            with self.subTest(mounts=mounts):
                contract = self.contract(mounts=mounts)
                self.assert_refused(lambda: runtime.prepare_boot_context(contract), 'invalid_run')

    def test_boot_id_must_be_canonical_uuid(self):
        for boot in (True, '', BOOT_ID + '\n', BOOT_ID.upper(), '../boot'):
            with self.subTest(boot=boot):
                self.assert_refused(lambda: runtime.prepare_boot_context(self.contract(boot=boot)),
                                    'invalid_context')

    def test_run_parent_symlink_or_writable_directory_refused(self):
        run = self.root / 'run'
        run.chmod(0o777)
        self.assert_refused(lambda: runtime.prepare_boot_context(self.contract()), 'invalid_metadata')
        run.chmod(0o755)
        original = self.base / 'other-run'
        run.rename(original)
        run.symlink_to(original, target_is_directory=True)
        self.assert_refused(lambda: runtime.prepare_boot_context(self.contract()), 'invalid_context')

    def test_context_rejects_different_boot_and_changed_candidate(self):
        original = self.contract()
        runtime.prepare_boot_context(original)
        other_boot = self.contract(boot='22345678-1234-1234-1234-123456789abc')
        self.assert_refused(lambda: runtime.validate_context(other_boot), 'invalid_context')
        self.manifest['studio_commit'] = '0' * 40
        self.write_manifest()
        self.assert_refused(lambda: runtime.validate_context(original), 'pin_mismatch')
        self.assert_refused(lambda: runtime.validate_context(self.contract()), 'invalid_context')

    def test_existing_context_accepts_readonly_run_view(self):
        contract = self.contract()
        runtime.prepare_boot_context(contract)
        readonly = self.contract(mounts=self.mountinfo(options='ro,nosuid,nodev'))
        self.assertEqual(runtime.validate_context(readonly), runtime.validate_context(contract))
        self.assertEqual(readonly.context_sha256, contract.context_sha256)

    def test_partial_publication_is_left_closed_and_never_repaired(self):
        contract = self.contract()
        original = runtime.Tree.create

        def fail_after_creation(tree, path, raw, mode):
            original(tree, path, raw[:5], mode)
            raise OSError('injected I/O failure')

        with patch.object(runtime.Tree, 'create', new=fail_after_creation):
            self.assert_refused(lambda: runtime.prepare_boot_context(contract),
                                'invalid_context', unchanged=False)
        self.assertEqual((self.root / runtime.CONTEXT).read_bytes(), b'{"boo')
        self.assert_refused(lambda: runtime.validate_context(contract), 'invalid_context')
        self.assert_refused(lambda: runtime.prepare_boot_context(contract), 'context_exists')

    def test_preexisting_admission_or_context_is_never_adopted(self):
        for relative in (runtime.CONTEXT_DIR, 'run/inkyos-admission'):
            with self.subTest(relative=relative):
                directory = self.mkdir(relative)
                self.assert_refused(lambda: runtime.prepare_boot_context(self.contract()), 'context_exists')
                directory.rmdir()

    def test_context_extra_entry_hardlink_and_noncanonical_bytes_refused(self):
        contract = self.contract()
        runtime.prepare_boot_context(contract)
        target = self.root / runtime.CONTEXT
        raw = target.read_bytes()
        extra = self.write(runtime.CONTEXT_DIR + '/extra', b'')
        self.assert_refused(lambda: runtime.validate_context(contract), 'invalid_context')
        extra.unlink()
        alias = self.base / 'context-alias'
        os.link(target, alias)
        self.assert_refused(lambda: runtime.validate_context(contract), 'invalid_metadata')
        alias.unlink()
        target.write_bytes(raw + b' ')
        self.assert_refused(lambda: runtime.validate_context(contract), 'invalid_context')

    def test_import_uses_only_pinned_admission_source(self):
        contract = self.contract()
        imported = runtime.import_admission(contract)
        self.assertEqual(imported.READY, b'{"schema_version":1,"state":"factory-complete"}\n')
        target = self.root / runtime.MODULE_DIR / 'writer-admission.py'
        self.write(runtime.MODULE_DIR + '/writer-admission.py',
                   b'raise AssertionError("must never execute altered source")\n', 0o555)
        self.assert_refused(lambda: runtime.import_admission(contract), 'pin_mismatch')


class CandidateTests(ContractFixture):
    def writer_parents_source(self):
        path = runtime.WRITER_PARENTS
        self.write(path, (ROOT / 'staging/bootstrap/writer-parents.py').read_bytes(), 0o555)
        self.support['paths'][path] = self.record(self.root / path)
        self.publish_candidate()
        return self.contract()

    def test_import_writer_parents_uses_required_public_support_pin(self):
        self.full_candidate()
        contract = self.writer_parents_source()
        before = self.snapshot()
        module = runtime.import_writer_parents(contract)
        self.assertEqual(module.RECEIPT, 'run/inkyos-writer-parents/parents.json')
        self.assertTrue(callable(module.preflight) and callable(module.prepare) and callable(module.verify))
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(set(self.manifest['os_module_pins']), runtime.MODULES)

    def test_import_writer_parents_refuses_altered_bytes_before_execution(self):
        self.full_candidate()
        contract = self.writer_parents_source()
        self.write(runtime.WRITER_PARENTS, b'raise AssertionError("unpinned module executed")\n', 0o555)
        self.assert_refused(lambda: runtime.import_writer_parents(contract), 'pin_mismatch')

    def test_writer_parents_module_is_mandatory_in_support_paths(self):
        self.full_candidate()
        del self.support['paths'][runtime.WRITER_PARENTS]
        self.publish_candidate()
        contract = self.contract()
        self.assert_refused(lambda: runtime.verify_candidate(contract), 'invalid_candidate')
        self.assert_refused(lambda: runtime.import_writer_parents(contract), 'invalid_candidate')

    def test_import_writer_parents_refuses_symlink_and_writable_source(self):
        self.full_candidate()
        contract = self.writer_parents_source()
        path = self.root / runtime.WRITER_PARENTS
        path.chmod(0o755)
        self.assert_refused(lambda: runtime.import_writer_parents(contract), 'pin_mismatch')
        path.unlink()
        self.symlink(runtime.WRITER_PARENTS, '/outside-unpinned-source')
        self.assert_refused(lambda: runtime.import_writer_parents(contract), 'pin_mismatch')

    def test_private_umask_creates_public_fixture_without_opening_private_parents(self):
        with temporary_umask(0o077):
            fixture = ContractFixture()
            try:
                fixture.setUp()
                contract = fixture.full_candidate()
                runtime.verify_candidate(contract)
                for role in ('main', 'helper', 'ipc'):
                    runtime.verify_role(contract, role, _identity=fixture.identity(role))
                for directory in (fixture.root, *fixture.root.rglob('*')):
                    if directory.is_dir():
                        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755, str(directory))
                private = fixture.mkdir('private', 0o700)
                fixture.write('private/written/fixture', b'INERT')
                fixture.symlink('private/linked/fixture', '/inert-target')
                fixture.mkdir('private/directories/leaf')
                self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
                for relative in ('written', 'linked', 'directories', 'directories/leaf'):
                    self.assertEqual(stat.S_IMODE((private / relative).stat().st_mode), 0o755)
            finally:
                fixture.doCleanups()

    def test_complete_inert_candidate_and_all_public_roles_pass(self):
        contract = self.full_candidate()
        before = self.snapshot()
        runtime.verify_candidate(contract)
        for role in ('main', 'helper', 'ipc'):
            runtime.verify_role(contract, role, _identity=self.identity(role))
        self.assertEqual(self.snapshot(), before)

    def test_tampered_pinned_payload_rejected_without_mutation(self):
        contract = self.full_candidate()
        for relative in (runtime.APP + '/server/.venv/lib/python3.13/site-packages/inky_web/main.py',
                         runtime.EXPORTER + '/venv/lib/python3.13/site-packages/inky_web/provisioning/factory_credentials.py',
                         'etc/private-runtime-support', runtime.HELPER):
            with self.subTest(relative=relative):
                path = self.root / relative
                raw, mode = path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
                self.write(relative, raw + b'TAMPERED', mode)
                self.assert_refused(lambda: runtime.verify_candidate(contract), 'pin_mismatch')
                self.write(relative, raw, mode)

    def test_native_payload_requires_explicit_review_root(self):
        self.full_candidate()
        path = 'server/.venv/lib/python3.13/site-packages/native.so'
        self.write(runtime.APP + '/' + path, b'INERT_NATIVE_NOT_EXECUTED')
        self.bundle['records'] = self.inventory(runtime.APP, exclude={'manifest.json'})
        self.publish_candidate()
        self.assert_refused(lambda: runtime.verify_candidate(self.contract()), 'invalid_candidate')
        self.support['elf_closure_review']['roots'].append(runtime.APP + '/' + path)
        self.publish_candidate()
        runtime.verify_candidate(self.contract())

    def test_extra_entries_in_every_closed_tree_refused(self):
        contract = self.full_candidate()
        for prefix in (runtime.APP, runtime.EXPORTER, *sorted(runtime.SUPPORT_TREES)):
            with self.subTest(prefix=prefix):
                extra = self.write(prefix + '/unexpected-file', b'UNPINNED')
                self.assert_refused(lambda: runtime.verify_candidate(contract), 'pin_mismatch')
                extra.unlink()

    def test_record_schema_rejects_bool_traversal_and_uninspected_metadata(self):
        self.full_candidate()
        original = copy.deepcopy(self.bundle)
        entry = 'server/.venv/lib/python3.13/site-packages/inky_web/main.py'
        cases = []
        for field, value in [('uid', True), ('gid', 1000), ('size_bytes', True),
                             ('mode', '0666'), ('extra', 1),
                             ('xattrs', {'status': 'unsupported', 'reason': 'platform'})]:
            candidate = copy.deepcopy(original)
            candidate['records'][entry][field] = value
            cases.append(candidate)
        for bad_path in ('../escape', '/absolute', 'server/../escape', 'server//escape'):
            candidate = copy.deepcopy(original)
            candidate['records'][bad_path] = copy.deepcopy(candidate['records'][entry])
            cases.append(candidate)
        candidate = copy.deepcopy(original)
        candidate['records']['manifest.json'] = copy.deepcopy(candidate['records'][entry])
        cases.append(candidate)
        for malformed in (None, [], True):
            candidate = copy.deepcopy(original)
            candidate['records']['.'] = malformed
            cases.append(candidate)
        for index, candidate in enumerate(cases):
            with self.subTest(index=index):
                self.bundle = candidate
                self.publish_candidate()
                self.assert_refused(lambda: runtime.verify_candidate(self.contract()))

    def test_bundle_duplicate_fields_and_wrong_binding_refused(self):
        self.full_candidate()
        self.exporter['support_manifest_sha256'] = '9' * 64
        raw = encoded(self.exporter)
        self.write(runtime.EXPORTER + '/manifest.json', raw)
        self.manifest['exporter_manifest_sha256'] = digest(raw)
        self.write_manifest()
        self.assert_refused(lambda: runtime.verify_candidate(self.contract()), 'invalid_contract')
        raw = b'{"schema_version":1,' + encoded(self.bundle)[1:]
        self.write(runtime.APP + '/manifest.json', raw)
        self.manifest['bundle_manifest_sha256'] = digest(raw)
        self.write_manifest()
        self.assert_refused(lambda: runtime.verify_candidate(self.contract()), 'invalid_contract')

    def test_test_access_artifact_is_refused_even_when_other_pins_match(self):
        contract = self.full_candidate()
        artifact = self.write('etc/inkyos-test-enrollment', b'forbidden TEST state')
        self.assert_refused(lambda: runtime.verify_candidate(contract), 'invalid_candidate')
        artifact.unlink()
        runtime.verify_candidate(contract)

    def test_hardlink_and_symlink_escape_are_refused(self):
        contract = self.full_candidate()
        relative = runtime.APP + '/server/.venv/lib/python3.13/site-packages/inky_web/main.py'
        path = self.root / relative
        alias = self.base / 'aliased-main'
        os.link(path, alias)
        self.assert_refused(lambda: runtime.verify_candidate(contract), 'invalid_metadata')
        alias.unlink()
        python = self.root / runtime.APP / 'server/.venv/bin/python'
        python.unlink()
        self.symlink(runtime.APP + '/server/.venv/bin/python', '/outside/pinned/root')
        self.bundle['records']['server/.venv/bin/python']['target'] = '/outside/pinned/root'
        self.publish_candidate()
        self.assert_refused(lambda: runtime.verify_candidate(self.contract()), 'invalid_candidate')

    def test_private_support_error_is_fatal_to_full_scan_but_outside_main_role(self):
        contract = self.full_candidate()
        original = runtime.actual_record

        def deny_private(tree, path):
            if path == 'etc/private-runtime-support':
                raise PermissionError('synthetic unreadable private support')
            return original(tree, path)

        with patch.object(runtime, 'actual_record', side_effect=deny_private):
            self.assert_refused(lambda: runtime.verify_candidate(contract), 'invalid_candidate')
            runtime.verify_role(contract, 'main', _identity=self.identity('main'))

    def test_role_payload_permission_error_is_not_suppressed(self):
        contract = self.full_candidate()
        original = runtime.actual_record
        relative = runtime.APP + '/server/.venv/lib/python3.13/site-packages/inky_web/main.py'

        def deny_entry(tree, path):
            if path == relative:
                raise PermissionError('synthetic unreadable public entry')
            return original(tree, path)

        with patch.object(runtime, 'actual_record', side_effect=deny_entry):
            self.assert_refused(lambda: runtime.verify_role(contract, 'main', _identity=self.identity('main')),
                                'invalid_candidate')

    def test_each_role_checks_its_own_payload(self):
        contract = self.full_candidate()
        for relative, role, other in (
            (runtime.APP + '/server/.venv/lib/python3.13/site-packages/inky_web/main.py', 'main', 'helper'),
            (runtime.RECEIPT, 'ipc', 'helper'),
        ):
            with self.subTest(relative=relative):
                path = self.root / relative
                raw, mode = path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
                self.write(relative, raw + b'TAMPERED', mode)
                self.assert_refused(lambda: runtime.verify_role(contract, role, _identity=self.identity(role)),
                                    'pin_mismatch')
                runtime.verify_role(contract, other, _identity=self.identity(other))
                self.write(relative, raw, mode)

    def test_base_python_and_loader_mutations_refused_by_full_scan(self):
        contract = self.full_candidate()
        for relative in ('usr/lib/python3.13/site.py', 'etc/ld.so.conf'):
            path = self.root / relative
            raw = path.read_bytes()
            self.write(relative, raw + b'TAMPERED')
            with self.subTest(relative=relative):
                self.assert_refused(lambda: runtime.verify_candidate(contract), 'pin_mismatch')
            self.write(relative, raw)

    def test_identity_rejects_wrong_uid_gid_groups_and_nss_aliases(self):
        contract = self.full_candidate()
        for role in ('main', 'helper', 'ipc'):
            good = self.identity(role)
            cases = []
            for field in ('uids', 'gids'):
                wrong = copy.deepcopy(good)
                wrong[field][1] += 1
                cases.append(wrong)
            wrong = copy.deepcopy(good)
            wrong['groups'].append(777)
            cases.append(wrong)
            wrong = copy.deepcopy(good)
            wrong['named_groups']['gpio'] = wrong['named_groups']['spi']
            cases.append(wrong)
            wrong = copy.deepcopy(good)
            wrong['named_groups']['inky-provisioning'] = 993
            cases.append(wrong)
            wrong = copy.deepcopy(good)
            wrong['uids'] = [True] * 3
            cases.append(wrong)
            for index, wrong in enumerate(cases):
                with self.subTest(role=role, index=index):
                    self.assert_refused(lambda: runtime.verify_role(contract, role, _identity=wrong),
                                        'wrong_identity')

    def test_live_identity_snapshot_rejects_duplicate_nss_names(self):
        groups = [grp.struct_group((name, 'x', gid, []))
                  for name, gid in self.identity('main')['named_groups'].items()]
        groups.append(groups[0])
        with patch.object(runtime.grp, 'getgrall', return_value=groups):
            self.assert_refused(runtime.identity_snapshot, 'wrong_identity')

    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                         'requires Linux root to change actual numeric UID/GID')
    def test_actual_foreign_payload_owner_and_group_are_refused(self):
        contract = self.full_candidate()
        path = self.root / runtime.HELPER
        for uid, gid in ((1000, 0), (0, 1000)):
            with self.subTest(uid=uid, gid=gid):
                os.chown(path, uid, gid)
                self.assert_refused(lambda: runtime.verify_candidate(contract), 'invalid_metadata')
                os.chown(path, 0, 0)


class NameValidationTests(unittest.TestCase):
    @staticmethod
    def legacy_name(path, root=False):
        """The exact character predicate and path guards before the regex change."""
        runtime.require(type(path) is str and len(path) <= 4096 and
                        (root and path == '.' or path and not path.startswith('/')
                         and all(part not in ('', '.', '..') for part in path.split('/')))
                        and not any(ord(char) < 32 or ord(char) == 127 or char == '\\'
                                    for char in path))
        return path

    @staticmethod
    def outcome(function, path, root=False):
        try:
            return ('accepted', function(path, root=root))
        except runtime.Refused as error:
            return ('refused', error.reason)

    def test_every_unicode_codepoint_preserves_acceptance_and_return(self):
        # Include lone surrogates/noncharacters: the existing contract permits
        # them, as well as non-ASCII whitespace, when the path is canonical.
        for value in range(sys.maxunicode + 1):
            path = 'a' + chr(value) + 'z'
            old = self.outcome(self.legacy_name, path)
            new = self.outcome(runtime.name, path)
            if new != old:
                self.fail(f'Unicode U+{value:04X}: {old!r} != {new!r}')

    def test_path_type_root_canonical_and_length_edges_match_legacy(self):
        class StringSubclass(str):
            pass

        cases = [None, False, 0, [], {}, b'file', Path('file'), StringSubclass('file'),
                 '', '.', '..', '/', '/file', './file', '../file', 'file/',
                 'a//b', 'a/./b', 'a/../b', 'file/.', 'file/..', 'a\\b',
                 'a/.../b', '.hidden/file', 'a / b', 'cadre/été/照片',
                 '\x80\x85\xa0\u200b\u2028\u2029\ud800\udfff\U0010ffff',
                 'a' * 4095, 'a' * 4096, 'a' * 4097,
                 'é' * 4096, 'é' * 4097]
        for path in cases:
            for root in (False, True):
                with self.subTest(path=repr(path)[:80], root=root):
                    self.assertEqual(self.outcome(runtime.name, path, root),
                                     self.outcome(self.legacy_name, path, root))

    def test_forbidden_characters_at_all_positions_and_length_boundary(self):
        for character in [*(chr(value) for value in range(32)), '\x7f', '\\']:
            for path in (character + 'a', 'a' + character + 'b', 'a' + character,
                         'a' * 4095 + character):
                with self.subTest(path=repr(path)[:80]):
                    self.assertEqual(self.outcome(runtime.name, path),
                                     self.outcome(self.legacy_name, path))
                    self.assertEqual(self.outcome(runtime.name, path)[0], 'refused')


class InventoryClosureTests(ContractFixture):
    @staticmethod
    def legacy_schema(records):
        """Pre-optimization schema, retained as a transitive-closure oracle."""
        runtime.require(type(records) is dict and 0 < len(records) <= 100000
                        and type(records.get('.')) is dict
                        and records['.'].get('type') == 'directory')
        for path, record in records.items():
            runtime.name(path, root=True)
            runtime.record_schema(record)
            for parent in PurePosixPath(path).parents:
                runtime.require(str(parent) in records
                                and records[str(parent)]['type'] == 'directory')

    def outcome(self, records, *, legacy):
        before = copy.deepcopy(records)
        try:
            (self.legacy_schema if legacy else runtime.records_schema)(records)
            for path, record in records.items():
                if legacy or record['type'] == 'symlink':
                    runtime.resolve(path, records)
        except (ValueError, TypeError, KeyError):
            result = ('refused', None)
        else:
            result = ('accepted', records)
        self.assertEqual(records, before)
        return result

    def test_closed_map_matches_legacy_acceptance_and_return_in_both_orders(self):
        directory = {'type': 'directory', 'uid': 0, 'gid': 0, 'mode': '0755',
                     'xattrs': copy.deepcopy(runtime.EMPTY_XATTRS)}
        file = {**directory, 'type': 'file', 'mode': '0644', 'size_bytes': 1,
                'sha256': 'a' * 64}

        def link(target):
            return {**directory, 'type': 'symlink', 'mode': '0777', 'target': target}

        base = {'.': directory, 'a': directory, 'a/b': directory, 'a/b/file': file}
        cases = [('root-only', {'.': directory}, True), ('closed', base, True),
                 ('top-file', {'.': directory, 'file': file}, True)]
        for missing in ('.', 'a', 'a/b'):
            cases.append(('missing-' + missing,
                          {path: record for path, record in base.items() if path != missing}, False))
        for ancestor in ('a', 'a/b'):
            for record in (file, link('/a/b')):
                cases.append(('non-directory-' + ancestor, {**base, ancestor: record}, False))
        for path in ('', '/', './a', 'a/', 'a//b', 'a/./b', 'a/../b', '/a', 'a\\b'):
            cases.append(('noncanonical-' + path, {**base, path: file}, False))
        for target, accepted in (('/a/b/file', True), ('a/b/file', True),
                                 ('a/b/../b/file', True), ('/', True),
                                 ('missing', False), ('alias', False),
                                 ('../outside', False), ('a/b/file/child', False)):
            cases.append(('alias-' + target, {**base, 'alias': link(target)}, accepted))
        cases.append(('two-link-cycle', {**base, 'alias': link('other'),
                                        'other': link('alias')}, False))
        for field, value in (('uid', True), ('gid', 1), ('mode', '0666'),
                             ('size_bytes', True), ('sha256', 'not-a-hash'),
                             ('xattrs', {'status': 'uninspected', 'entries': {}})):
            cases.append(('metadata-' + field,
                          {**base, 'a/b/file': {**file, field: value}}, False))
        for label, records, accepted in cases:
            for reverse in (False, True):
                with self.subTest(case=label, reverse=reverse):
                    records = dict(reversed(list(records.items()))) if reverse else records
                    old = self.outcome(records, legacy=True)
                    new = self.outcome(records, legacy=False)
                    self.assertEqual(new, old)
                    self.assertEqual(new[0], 'accepted' if accepted else 'refused')

    def test_inventories_refuses_unused_dangling_and_cyclic_links_without_writes(self):
        self.full_candidate()
        path = 'usr/lib/unreferenced'
        directory = self.support['paths']['usr/lib']
        for target in ('missing', 'unreferenced', '../../../outside',
                       '../bin/python3.13/child'):
            with self.subTest(target=target):
                self.support['paths'][path] = {
                    **directory, 'type': 'symlink', 'mode': '0777', 'target': target}
                self.publish_candidate()
                self.assert_refused(lambda: runtime.inventories(self.contract()),
                                    'invalid_candidate')

    def test_inventories_retains_valid_absolute_relative_and_root_links(self):
        self.full_candidate()
        path = 'usr/lib/unreferenced'
        directory = self.support['paths']['usr/lib']
        for target, resolved in (('/usr/bin/python3.13', 'usr/bin/python3.13'),
                                 ('../bin/python3.13', 'usr/bin/python3.13'),
                                 ('../..', '.')):
            with self.subTest(target=target):
                self.support['paths'][path] = {
                    **directory, 'type': 'symlink', 'mode': '0777', 'target': target}
                self.publish_candidate()
                before = self.snapshot()
                app, exporter, support, records = runtime.inventories(self.contract())
                self.assertEqual((app, exporter, support),
                                 (self.bundle, self.exporter, self.support))
                self.assertEqual(runtime.resolve(path, records), resolved)
                self.assertEqual(self.outcome(records, legacy=False),
                                 self.outcome(records, legacy=True))
                self.assertEqual(self.snapshot(), before)


if __name__ == '__main__':
    unittest.main()
