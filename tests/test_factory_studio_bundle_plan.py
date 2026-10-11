"""Static planner tests using synthetic sources and independently built wheels.

The fixture payloads raise if executed. No app, pip, subprocess, rootfs, service,
image, VM or hardware is needed; the tests inspect planned bytes only.
"""
import base64
import copy
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'studio_bundle_planner_test', ROOT / 'scripts/plan-factory-studio-bundle.py')
planner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(planner)
APP_WHEEL = 'inky_studio-1.2.3-py3-none-any.whl'
DEP_WHEEL = 'fixture_dep-4.5.6-py3-none-any.whl'
SITE = 'server/.venv/lib/python3.13/site-packages'
EMPTY_XATTRS = {'status': 'inspected', 'entries': {}}
STUDIO_TAG_CASES = (
    'py3-none-any',
    'py2.py3-none-any',
    'cp313-cp313-manylinux_2_17_aarch64.manylinux2014_aarch64',
    'cp313-cp313-manylinux2014_aarch64.manylinux_2_17_aarch64',
    'cp313-cp313-manylinux2014_aarch64.manylinux_2_17_aarch64.manylinux_2_28_aarch64',
    'cp313-cp313-manylinux_2_27_aarch64.manylinux_2_28_aarch64',
    'cp313-cp313-linux_aarch64',
    'cp311-abi3-manylinux_2_34_aarch64',
    'cp310-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64',
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def inert_elf_header():
    """Only a synthetic ELF64 LE AArch64 ET_DYN header; no executable payload."""
    header = bytearray(64)
    header[:7] = b'\x7fELF\x02\x01\x01'
    header[16:18] = (3).to_bytes(2, 'little')
    header[18:20] = (183).to_bytes(2, 'little')
    header[20:24] = (1).to_bytes(4, 'little')
    header[52:54] = (64).to_bytes(2, 'little')
    return bytes(header)


def synthetic_wheel(filename, files, *, metadata=None, omit_metadata=False, record_transform=None,
                    special_modes=None, extra_members=(), wheel_tags=None):
    """Build ZIP and RECORD independently of the production wheel parser."""
    package, version, python, abi, platform = filename[:-4].split('-')
    dist = f'{package}-{version}.dist-info'
    payload = dict(files)
    tags = [f'{py}-{ab}-{pl}' for py in python.split('.') for ab in abi.split('.')
            for pl in platform.split('.')]
    if wheel_tags is not None:
        tags = wheel_tags
    payload[dist + '/WHEEL'] = ('Wheel-Version: 1.0\nGenerator: inert-fixture\n'
        + ''.join(f'Tag: {tag}\n' for tag in tags)).encode()
    if not omit_metadata:
        payload[dist + '/METADATA'] = (metadata if metadata is not None else
            f'Metadata-Version: 2.1\nName: {package}\nVersion: {version}\n'.encode())
    record = dist + '/RECORD'
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, lineterminator='\n')
    for name, raw in sorted(payload.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b'=').decode('ascii')
        writer.writerow((name, 'sha256=' + digest, str(len(raw))))
    writer.writerow((record, '', ''))
    record_bytes = stream.getvalue().encode()
    payload[record] = record_bytes if record_transform is None else record_transform(record_bytes)
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, raw in (*sorted(payload.items()), *extra_members):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (special_modes or {}).get(name, stat.S_IFREG | 0o644) << 16
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                archive.writestr(info, raw)
    return output.getvalue(), payload


class FactoryStudioBundlePlanTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(
            prefix='inkyos-studio-plan-', dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.sources = self.directory('sources')
        self.wheels = self.directory('wheels')
        self.outputs = self.directory('outputs')
        self.input_file = self.base / 'inputs.json'
        self.output = self.outputs / 'manifest.json'
        self.receipt_output = self.outputs / 'receipt.json'
        self.source_payload = {
            'scripts/inky-network-helper.py': b'raise AssertionError("planner must not execute helper")\n',
            'client/dist/index.html': b'<!doctype html><title>Inert fixture</title>\n',
            'client/dist/app.js': b'throw new Error("planner must not execute frontend");\n',
        }
        for name, raw in self.source_payload.items():
            self.write(self.sources / name, raw)
        self.app_files = {
            'inky_web/__init__.py': b'raise AssertionError("planner must not import app")\n',
            'inky_web/main.py': b'raise AssertionError("planner must not execute app")\n',
            'inky_web/provisioning/__init__.py': b'',
        }
        self.dep_files = {'fixture_dep/__init__.py': b'raise AssertionError("no dependency import")\n'}
        app_raw, self.app_payload = synthetic_wheel(APP_WHEEL, self.app_files)
        dep_raw, self.dep_payload = synthetic_wheel(DEP_WHEEL, self.dep_files)
        self.write(self.wheels / APP_WHEEL, app_raw)
        self.write(self.wheels / DEP_WHEEL, dep_raw)
        self.inputs = {
            'schema_version': 1, 'kind': 'factory-studio-bundle-inputs',
            'studio_commit': 'a' * 40, 'python_version': '3.13.5', 'app_wheel': APP_WHEEL,
            'source_sha256': {name: sha(raw) for name, raw in self.source_payload.items()},
            'wheel_sha256': {APP_WHEEL: sha(app_raw), DEP_WHEEL: sha(dep_raw)},
        }
        self.write_inputs()

    def directory(self, relative):
        path = self.base / relative
        path.mkdir(parents=True, exist_ok=True)
        for parent in (path, *path.parents):
            if parent == self.base:
                break
            parent.chmod(0o755)
        return path

    def write(self, path, raw, mode=0o644):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        for parent in (path.parent, *path.parent.parents):
            if parent == self.base:
                break
            parent.chmod(0o755)
        if path.exists():
            path.chmod(0o600)
        path.write_bytes(raw)
        path.chmod(mode)
        return path

    def write_inputs(self, raw=None):
        raw = canonical(self.inputs) if raw is None else raw
        self.write(self.input_file, raw)
        self.input_sha = sha(raw)

    def replace_wheel(self, filename, files, **kwargs):
        raw, payload = synthetic_wheel(filename, files, **kwargs)
        self.write(self.wheels / filename, raw)
        self.inputs['wheel_sha256'][filename] = sha(raw)
        self.write_inputs()
        return payload

    def plan(self, **changes):
        values = dict(input_manifest=self.input_file, input_sha256=self.input_sha,
                      sources_dir=self.sources, wheels_dir=self.wheels)
        values.update(changes)
        return planner.plan(**values)

    def publish(self, **changes):
        values = dict(input_manifest=self.input_file, input_sha256=self.input_sha,
                      sources_dir=self.sources, wheels_dir=self.wheels,
                      output=self.output, receipt_output=self.receipt_output)
        values.update(changes)
        return planner.publish_plan(**values)

    def snapshot(self):
        result = {}
        for path in (self.base, *sorted(self.base.rglob('*'))):
            info = path.lstat()
            record = (info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
                      info.st_ino, info.st_dev)
            if stat.S_ISREG(info.st_mode):
                record += (path.read_bytes(),)
            elif stat.S_ISLNK(info.st_mode):
                record += (os.readlink(path),)
            result[str(path.relative_to(self.base))] = record
        return result

    def refused(self, callback=None):
        before = self.snapshot()
        with self.assertRaises(planner.Refused) as caught:
            (self.plan if callback is None else callback)()
        self.assertRegex(caught.exception.reason, r'^[a-z_]{1,64}$')
        self.assertEqual(self.snapshot(), before)
        return caught.exception.reason

    def test_exact_deterministic_manifest_records_and_receipt(self):
        before = self.snapshot()
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('planner launched child')), \
                patch.object(os, 'system', side_effect=AssertionError('planner ran shell')):
            first, receipt = self.plan()
            second, receipt2 = self.plan()
        self.assertEqual((first, receipt), (second, receipt2))
        self.assertEqual(self.snapshot(), before)
        value = json.loads(first)
        self.assertEqual(first, canonical(value))
        self.assertEqual(set(value), {'schema_version', 'kind', 'studio_commit', 'records'})
        self.assertEqual(value['schema_version'], 1)
        self.assertEqual(value['kind'], 'factory-studio-bundle-manifest')
        self.assertEqual(value['studio_commit'], self.inputs['studio_commit'])
        records = value['records']
        payload = {**self.source_payload,
                   **{SITE + '/' + name: raw for name, raw in {**self.app_payload, **self.dep_payload}.items()}}
        payload['server/.venv/pyvenv.cfg'] = (
            b'home = /usr/bin\ninclude-system-site-packages = false\n'
            b'version = 3.13.5\nexecutable = /usr/bin/python3.13\n')
        links = {'server/.venv/bin/python': 'python3.13',
                 'server/.venv/bin/python3': 'python3.13',
                 'server/.venv/bin/python3.13': '/usr/bin/python3.13',
                 'server/.venv/lib64': 'lib'}
        directories = {'.', 'server/.venv/include/python3.13'}
        for path in (*payload, *links, 'server/.venv/include/python3.13'):
            directories.update(map(str, PurePosixPath(path).parents))
        self.assertEqual(set(records), set(payload) | set(links) | directories)
        self.assertNotIn('manifest.json', records)
        for name, raw in payload.items():
            mode = '0555' if name == 'scripts/inky-network-helper.py' else '0644'
            expected = {'type': 'file', 'uid': 0, 'gid': 0, 'mode': mode,
                        'xattrs': EMPTY_XATTRS, 'size_bytes': len(raw), 'sha256': sha(raw)}
            self.assertEqual(records[name], expected, name)
        for name, target in links.items():
            self.assertEqual(records[name], {'type': 'symlink', 'uid': 0, 'gid': 0,
                             'mode': '0777', 'target': target, 'xattrs': EMPTY_XATTRS})
        for name in directories:
            self.assertEqual(records[name], {'type': 'directory', 'uid': 0, 'gid': 0,
                             'mode': '0755', 'xattrs': EMPTY_XATTRS})
        self.assertEqual(receipt, {
            'schema_version': 1, 'scope': 'factory-studio-bundle-plan-only',
            'input_manifest_sha256': self.input_sha, 'bundle_manifest_sha256': sha(first),
            'studio_commit': self.inputs['studio_commit'], 'source_files': len(self.source_payload),
            'wheel_files': 2, 'payload_files': len(payload) - 1, 'bundle_entries': len(records),
            'record_metadata': 'expected-root-owned-no-xattrs', 'image_code_executed': False,
            'application_candidate_qualified': False,
        })

    def test_records_conform_to_fixed_runtime_schema_without_qualifying_candidate(self):
        spec = importlib.util.spec_from_file_location(
            'studio_plan_runtime_schema', ROOT / 'scripts/factory-runtime-contract.py')
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        manifest, _ = self.plan()
        runtime.records_schema(json.loads(manifest)['records'])

    def test_input_map_order_does_not_change_planned_bundle(self):
        first, _ = self.plan()
        self.inputs['source_sha256'] = dict(reversed(list(self.inputs['source_sha256'].items())))
        self.inputs['wheel_sha256'] = dict(reversed(list(self.inputs['wheel_sha256'].items())))
        self.write_inputs()
        second, _ = self.plan()
        self.assertEqual(first, second)

    def test_supported_native_wheel_tag_is_static_payload(self):
        filename = 'fixture_native-1.0-cp313-cp313-manylinux_2_17_aarch64.manylinux2014_aarch64.whl'
        header = inert_elf_header()
        payload = self.replace_wheel(filename, {'fixture_native/module.so': header})
        raw, _ = self.plan()
        records = json.loads(raw)['records']
        self.assertEqual(records[SITE + '/fixture_native/module.so']['sha256'], sha(header))
        self.assertTrue(all(SITE + '/' + name in records for name in payload))

    def test_all_nine_reviewed_studio_filename_tags_plan_exact_payload(self):
        wanted = {}
        for index, tag in enumerate(STUDIO_TAG_CASES):
            filename = f'fixture_tag_{index}-1.0-{tag}.whl'
            path = f'fixture_tag_{index}/' + ('__init__.py' if tag.endswith('-any') else 'module.so')
            content = b'raise AssertionError("never imported")\n' if tag.endswith('-any') else inert_elf_header()
            wanted.update(self.replace_wheel(filename, {path: content}))
        raw, receipt = self.plan()
        records = json.loads(raw)['records']
        for path, content in wanted.items():
            self.assertEqual(records[SITE + '/' + path]['sha256'], sha(content), path)
        self.assertEqual(receipt['wheel_files'], 11)
        self.assertFalse(receipt['application_candidate_qualified'])
        self.assertFalse(receipt['image_code_executed'])

    def test_unreviewed_abi_architecture_os_and_tag_combinations_refused_before_publish(self):
        for tag in ('cp313t-cp313t-linux_aarch64', 'cp313-cp313-linux_armv7l',
                    'cp313-cp313-macosx_11_0_arm64', 'cp313-cp313-musllinux_1_2_aarch64',
                    'cp313-cp313-manylinux_2_34_aarch64', 'cp312-cp312-linux_aarch64'):
            filename = f'foreign-1.0-{tag}.whl'
            self.replace_wheel(filename, {'foreign/module.so': inert_elf_header()})
            with self.subTest(tag=tag):
                self.refused(self.publish)
            (self.wheels / filename).unlink()
            del self.inputs['wheel_sha256'][filename]
            self.write_inputs()

    def test_expanded_wheel_tags_must_exactly_match_new_compressed_filename(self):
        filename = 'fixture_native-1.0-cp313-cp313-manylinux2014_aarch64.manylinux_2_17_aarch64.whl'
        valid = ['cp313-cp313-manylinux2014_aarch64', 'cp313-cp313-manylinux_2_17_aarch64']
        for tags in ([], valid[:1], valid + ['cp313-cp313-linux_aarch64'],
                     ['cp313-cp313-manylinux_2_28_aarch64']):
            self.replace_wheel(filename, {'fixture_native/module.so': inert_elf_header()}, wheel_tags=tags)
            with self.subTest(tags=tags):
                self.refused(self.publish)

    def test_new_native_tags_do_not_bypass_record_hash_validation(self):
        filename = 'fixture_native-1.0-cp313-cp313-linux_aarch64.whl'
        self.replace_wheel(filename, {'fixture_native/module.so': inert_elf_header()},
                           record_transform=lambda raw: raw.replace(b'sha256=', b'sha512=', 1))
        self.refused(self.publish)

    def test_shared_objects_require_complete_elf64_le_aarch64_headers(self):
        valid = inert_elf_header()
        variants = [b'INERT_NOT_AN_ELF', valid[:63], b'\x7fELF',
                    valid[:4] + b'\x01' + valid[5:],
                    valid[:5] + b'\x02' + valid[6:],
                    valid[:6] + b'\x00' + valid[7:],
                    valid[:18] + (62).to_bytes(2, 'little') + valid[20:],
                    valid[:20] + (0).to_bytes(4, 'little') + valid[24:],
                    valid[:52] + (63).to_bytes(2, 'little') + valid[54:],
                    valid[:16] + (2).to_bytes(2, 'little') + valid[18:]]
        filename = 'fixture_native-1.0-cp313-cp313-linux_aarch64.whl'
        for path in ('fixture_native/module.so', 'fixture_native.libs/libexample.so.1.2'):
            for header in variants:
                self.replace_wheel(filename, {path: header})
                with self.subTest(path=path, header=header):
                    self.refused(self.publish)

    def test_elf_magic_without_so_suffix_is_also_checked(self):
        filename = 'fixture_native-1.0-cp313-cp313-linux_aarch64.whl'
        valid = inert_elf_header()
        self.replace_wheel(filename, {'fixture_native/data': valid})
        raw, _ = self.plan()
        self.assertEqual(json.loads(raw)['records'][SITE + '/fixture_native/data']['sha256'], sha(valid))
        for header in (valid[:12], valid[:18] + (40).to_bytes(2, 'little') + valid[20:]):
            self.replace_wheel(filename, {'fixture_native/data': header})
            with self.subTest(header=header):
                self.refused(self.publish)

    def test_any_tag_refuses_shared_object_or_elf_magic_even_with_valid_record(self):
        for tag in ('py3-none-any', 'py2.py3-none-any'):
            filename = f'fixture_pure-1.0-{tag}.whl'
            for path in ('fixture_pure/module.so', 'fixture_pure.libs/libexample.so.1', 'fixture_pure/data'):
                self.replace_wheel(filename, {path: inert_elf_header()})
                with self.subTest(tag=tag, path=path):
                    self.refused(self.publish)
            (self.wheels / filename).unlink()
            del self.inputs['wheel_sha256'][filename]
            self.write_inputs()

    def test_schema_rejects_missing_unknown_bool_bad_hash_and_version(self):
        original = copy.deepcopy(self.inputs)
        variants = []
        for key in original:
            value = copy.deepcopy(original)
            del value[key]
            variants.append(value)
        for key, value in [('schema_version', True), ('kind', 'other-kind'),
                           ('studio_commit', 'A' * 40), ('python_version', '3.13.05'),
                           ('python_version', '3.12.5'), ('app_wheel', DEP_WHEEL),
                           ('source_sha256', []), ('unknown', 'field')]:
            variant = copy.deepcopy(original)
            variant[key] = value
            variants.append(variant)
        variant = copy.deepcopy(original)
        variant['source_sha256']['scripts/inky-network-helper.py'] = True
        variants.append(variant)
        for index, value in enumerate(variants):
            with self.subTest(index=index):
                self.inputs = value
                self.write_inputs()
                self.refused()

    def test_noncanonical_duplicate_and_nonfinite_json_refused(self):
        raw = canonical(self.inputs)
        variants = [json.dumps(self.inputs, indent=2).encode() + b'\n', raw.rstrip(b'\n'),
                    raw + b'\n', b'{"schema_version":1,' + raw[1:],
                    raw.replace(b'"schema_version":1', b'"schema_version":NaN'), b'\xff']
        for value in variants:
            with self.subTest(prefix=value[:40]):
                self.write_inputs(value)
                self.refused()

    def test_input_and_payload_pins_are_checked_before_any_output(self):
        self.refused(lambda: self.publish(input_sha256='0' * 64))
        for key, name in (('source_sha256', 'scripts/inky-network-helper.py'),
                          ('wheel_sha256', APP_WHEEL)):
            with self.subTest(key=key):
                original = self.inputs[key][name]
                self.inputs[key][name] = '0' * 64
                self.write_inputs()
                self.refused(self.publish)
                self.inputs[key][name] = original
                self.write_inputs()
        self.assertFalse(self.output.exists())
        self.assertFalse(self.receipt_output.exists())

    def test_exact_inventory_rejects_extra_files_and_empty_directories(self):
        for root, name, directory in ((self.sources, 'extra.txt', False),
                (self.sources, 'client/dist/unused', True), (self.wheels, 'extra.whl', False),
                (self.wheels, 'empty', True), (self.sources, '.DS_Store', False)):
            with self.subTest(root=root.name, name=name):
                path = root / name
                if directory:
                    path.mkdir(mode=0o755)
                    path.chmod(0o755)
                else:
                    self.write(path, b'UNPINNED')
                self.refused()
                path.rmdir() if directory else path.unlink()

    def test_missing_pinned_input_and_missing_mandatory_helper_refused(self):
        helper = self.sources / 'scripts/inky-network-helper.py'
        raw = helper.read_bytes()
        helper.unlink()
        self.refused()
        self.write(helper, raw)
        del self.inputs['source_sha256']['scripts/inky-network-helper.py']
        self.write_inputs()
        helper.unlink()
        (self.sources / 'scripts').rmdir()
        self.refused()

    def test_source_whitelist_reserved_paths_and_build_configuration_refused(self):
        for name in ('manifest.json', 'server/.venv/pyvenv.cfg', 'assets/image.png',
                     'scripts/other-helper.py', 'client/dist/pyproject.toml',
                     'client/dist/setup.py', 'client/dist/setup.cfg',
                     'client/dist/pip.conf', 'client/dist/direct_url.json',
                     'client/dist/.git/config', 'client/dist/.venv/pyvenv.cfg'):
            with self.subTest(name=name):
                path = self.write(self.sources / name, b'FORBIDDEN_CONFIG')
                self.inputs['source_sha256'][name] = sha(path.read_bytes())
                self.write_inputs()
                self.refused()
                del self.inputs['source_sha256'][name]
                path.unlink()
                parent = path.parent
                while parent not in (self.sources, self.sources / 'client/dist', self.sources / 'scripts'):
                    if any(parent.iterdir()):
                        break
                    parent.rmdir()
                    parent = parent.parent
                self.write_inputs()

    def test_traversal_absolute_and_nonflat_wheel_names_refused(self):
        original = copy.deepcopy(self.inputs)
        for key, path in (('source_sha256', '../outside'), ('source_sha256', '/absolute'),
                          ('source_sha256', 'client//dist/entry'),
                          ('source_sha256', 'client/dist/../entry'),
                          ('wheel_sha256', 'nested/' + APP_WHEEL),
                          ('wheel_sha256', '../' + APP_WHEEL)):
            with self.subTest(key=key, path=path):
                self.inputs = copy.deepcopy(original)
                self.inputs[key][path] = '1' * 64
                self.write_inputs()
                self.refused()

    def test_input_file_symlink_hardlink_and_fifo_are_refused(self):
        original = self.input_file.read_bytes()
        alias = self.write(self.base / 'input-alias', original)
        for kind in ('symlink', 'hardlink', 'fifo'):
            with self.subTest(kind=kind):
                self.input_file.unlink()
                if kind == 'symlink':
                    self.input_file.symlink_to(alias)
                elif kind == 'hardlink':
                    os.link(alias, self.input_file)
                else:
                    os.mkfifo(self.input_file)
                self.refused()

    def test_source_symlink_hardlink_fifo_and_symlink_parent_are_refused(self):
        helper = self.sources / 'scripts/inky-network-helper.py'
        raw = helper.read_bytes()
        alias = self.write(self.base / 'helper-alias', raw)
        for kind in ('symlink', 'hardlink', 'fifo'):
            with self.subTest(kind=kind):
                helper.unlink()
                if kind == 'symlink':
                    helper.symlink_to(alias)
                elif kind == 'hardlink':
                    os.link(alias, helper)
                else:
                    os.mkfifo(helper)
                self.refused()
        helper.unlink()
        self.write(helper, raw)
        (self.sources / 'scripts').rename(self.base / 'moved-scripts')
        (self.sources / 'scripts').symlink_to(self.base / 'moved-scripts', target_is_directory=True)
        self.refused()

    def test_wheel_file_symlink_hardlink_and_fifo_are_refused(self):
        path = self.wheels / APP_WHEEL
        alias = self.write(self.base / 'wheel-alias', path.read_bytes())
        for kind in ('symlink', 'hardlink', 'fifo'):
            with self.subTest(kind=kind):
                path.unlink()
                if kind == 'symlink':
                    path.symlink_to(alias)
                elif kind == 'hardlink':
                    os.link(alias, path)
                else:
                    os.mkfifo(path)
                self.refused()

    def test_wheel_record_missing_row_wrong_hash_size_duplicate_or_self_hash_refused(self):
        transformations = [lambda raw: b'\n'.join(raw.split(b'\n')[1:]),
                           lambda raw: raw.replace(b'sha256=', b'sha512=', 1),
                           lambda raw: raw.replace(b',,\n', b',sha256=bad,1\n'),
                           lambda raw: raw + raw.split(b'\n')[0] + b'\n']
        def wrong_size(raw):
            rows = list(csv.reader(io.StringIO(raw.decode())))
            rows[0][2] = str(int(rows[0][2]) + 1)
            stream = io.StringIO(newline='')
            csv.writer(stream, lineterminator='\n').writerows(rows)
            return stream.getvalue().encode()
        transformations.append(wrong_size)
        for index, transform in enumerate(transformations):
            with self.subTest(index=index):
                self.replace_wheel(APP_WHEEL, self.app_files, record_transform=transform)
                self.refused()

    def test_wheel_hooks_relocation_and_generated_payloads_refused(self):
        for path in ('bad.pth', 'bad.egg-link', 'sitecustomize.py', 'usercustomize.py',
                     'inky_studio-1.2.3.data/scripts/entry', 'inky_web/__pycache__/main.pyc',
                     'inky_web/generated.pyc', 'nested/sitecustomize.cpython-313.so'):
            with self.subTest(path=path):
                self.replace_wheel(APP_WHEEL, {**self.app_files, path: b'FORBIDDEN_IMPORT_HOOK'})
                self.refused()

    def test_wheel_traversal_duplicate_special_and_file_directory_collision_refused(self):
        for path in ('../outside', '/absolute', 'inky_web//bad', 'inky_web/../bad'):
            with self.subTest(path=path):
                self.replace_wheel(APP_WHEEL, {**self.app_files, path: b'UNSAFE_PATH'})
                self.refused()
        self.replace_wheel(APP_WHEEL, self.app_files,
                           extra_members=(('inky_web/main.py', b'DUPLICATE'),))
        self.refused()
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o644, stat.S_IFREG | 0o4644):
            with self.subTest(mode=mode):
                self.replace_wheel(APP_WHEEL, self.app_files,
                                   special_modes={'inky_web/main.py': mode})
                self.refused()
        self.replace_wheel(APP_WHEEL, {**self.app_files, 'inky_web/main.py/child': b'COLLISION'})
        self.refused()

    def test_dependencies_cannot_contribute_app_namespace_or_collide(self):
        for files in ({'inky_web/foreign.py': b'FOREIGN_APP_CODE'},
                      {'inky_web/__init__.py': self.app_files['inky_web/__init__.py']},
                      {'inky_web.py': b'FOREIGN_APP_MODULE'},
                      {'inky_web.cpython-313-aarch64-linux-gnu.so': b'FOREIGN_NATIVE_APP_MODULE'},
                      {'shared/module.py': b'SECOND_PROVIDER'}):
            with self.subTest(paths=tuple(files)):
                if 'shared/module.py' in files:
                    self.replace_wheel(APP_WHEEL, {**self.app_files, 'shared/module.py': b'FIRST_PROVIDER'})
                self.replace_wheel(DEP_WHEEL, files)
                self.refused()

    def test_cross_wheel_file_directory_collision_refused(self):
        self.replace_wheel(APP_WHEEL, {**self.app_files, 'shared': b'FILE'})
        self.replace_wheel(DEP_WHEEL, {'shared/child.py': b'CHILD'})
        self.refused()

    def test_app_entrypoints_and_metadata_are_required(self):
        for missing in ('inky_web/__init__.py', 'inky_web/main.py'):
            with self.subTest(missing=missing):
                files = dict(self.app_files)
                del files[missing]
                self.replace_wheel(APP_WHEEL, files)
                self.refused()
        self.replace_wheel(APP_WHEEL, self.app_files, omit_metadata=True)
        self.refused()
        for metadata in (b'', b'Name: inky_studio\nVersion: 1.2.3\n',
                         b'Metadata-Version: 2.1\nName: other\nVersion: 1.2.3\n',
                         b'Metadata-Version: 2.1\nName: inky_studio\nVersion: 9.9\n'):
            with self.subTest(metadata=metadata):
                self.replace_wheel(APP_WHEEL, self.app_files, metadata=metadata)
                self.refused()

    def test_unsupported_python_tag_and_unlisted_app_wheel_refused(self):
        filename = 'other-1.0-cp312-cp312-manylinux_2_17_aarch64.whl'
        self.replace_wheel(filename, {'other/__init__.py': b''})
        self.refused()
        (self.wheels / filename).unlink()
        del self.inputs['wheel_sha256'][filename]
        self.inputs['app_wheel'] = 'absent-1.0-py3-none-any.whl'
        self.write_inputs()
        self.refused()

    def test_publish_outputs_are_exact_and_exclusively_created(self):
        manifest, expected_receipt = self.plan()
        receipt = self.publish()
        self.assertEqual(receipt, expected_receipt)
        self.assertEqual(self.output.read_bytes(), manifest)
        self.assertEqual(self.receipt_output.read_bytes(), canonical(receipt))
        self.refused(self.publish)

    def test_existing_either_output_is_refused_before_creating_other(self):
        for target in (self.output, self.receipt_output):
            with self.subTest(target=target.name):
                self.write(target, b'PRESERVE_EXISTING_OUTPUT')
                self.refused(self.publish)
                target.unlink()
        self.assertFalse(self.output.exists())
        self.assertFalse(self.receipt_output.exists())

    def test_output_aliases_and_symlink_parent_are_refused(self):
        self.refused(lambda: self.publish(receipt_output=self.output))
        self.output.symlink_to(self.input_file)
        self.refused(self.publish)
        self.output.unlink()
        moved = self.base / 'real-outputs'
        self.outputs.rename(moved)
        self.outputs.symlink_to(moved, target_is_directory=True)
        self.refused(self.publish)

    def test_outputs_cannot_be_written_into_any_input_tree(self):
        for changes in ({'output': self.sources / 'client/dist/planned.json'},
                        {'receipt_output': self.wheels / 'receipt.json'},
                        {'output': self.input_file}):
            with self.subTest(changes=changes):
                self.refused(lambda: self.publish(**changes))
        self.assertFalse(self.output.exists())
        self.assertFalse(self.receipt_output.exists())

    def test_overlapping_input_roots_are_refused(self):
        self.refused(lambda: self.plan(wheels_dir=self.sources))
        self.refused(lambda: self.plan(wheels_dir=self.sources / 'client'))
        copied = self.write(self.sources / 'client/dist/inputs.json', self.input_file.read_bytes())
        self.refused(lambda: self.plan(input_manifest=copied))

    def test_bounded_payload_refusal_leaves_outputs_absent(self):
        with patch.object(planner, 'MAX_BYTES', 1):
            self.refused(self.publish)
        with patch.object(planner, 'MAX_FILES', 4):
            self.refused(self.publish)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.receipt_output.exists())

    def test_cli_refusal_has_code_one_and_creates_nothing(self):
        arguments = ['--input-manifest', str(self.input_file), '--input-sha256', '0' * 64,
                     '--sources-dir', str(self.sources), '--wheels-dir', str(self.wheels),
                     '--output', str(self.output), '--receipt', str(self.receipt_output)]
        before = self.snapshot()
        with patch('sys.stdout', new_callable=io.StringIO), \
                patch('sys.stderr', new_callable=io.StringIO):
            self.assertEqual(planner.main(arguments), 1)
        self.assertEqual(self.snapshot(), before)

    def test_umask_077_fixture_and_publication_remain_supported(self):
        previous = os.umask(0o077)
        try:
            self.publish()
        finally:
            os.umask(previous)
        self.assertEqual(json.loads(self.output.read_bytes())['kind'], 'factory-studio-bundle-manifest')


if __name__ == '__main__':
    unittest.main()
