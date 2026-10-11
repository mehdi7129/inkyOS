#!/usr/bin/env python3
"""Derive an expected Studio bundle from pinned bytes; never install or run it."""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile
import zlib

_spec = importlib.util.spec_from_file_location(
    '_studio_plan_exporter', Path(__file__).with_name('verify-factory-exporter-rootfs.py'))
exporter = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(exporter)

DESTINATION = '/usr/lib/inky-studio'
VENV = 'server/.venv'
SITE = VENV + '/lib/python3.13/site-packages'
HELPER = 'scripts/inky-network-helper.py'
INPUT_FIELDS = {'schema_version', 'kind', 'studio_commit', 'python_version',
                'app_wheel', 'source_sha256', 'wheel_sha256'}
HASH = re.compile(r'[0-9a-f]{64}\Z')
MAX_FILES = 20000
MAX_BYTES = 256 * 1024 * 1024
BUILD_NAMES = {'.git', '.hg', '.svn', '.env', '.venv', 'venv', 'pyvenv.cfg',
               'pip.conf', '.python-version', 'pyproject.toml', 'setup.py', 'setup.cfg',
               'direct_url.json'}
STUDIO_FILENAME_TAGS = frozenset({
    ('py3', 'none', 'any'),
    ('py2.py3', 'none', 'any'),
    ('cp313', 'cp313', 'manylinux_2_17_aarch64.manylinux2014_aarch64'),
    ('cp313', 'cp313', 'manylinux2014_aarch64.manylinux_2_17_aarch64'),
    ('cp313', 'cp313', 'manylinux2014_aarch64.manylinux_2_17_aarch64.manylinux_2_28_aarch64'),
    ('cp313', 'cp313', 'manylinux_2_27_aarch64.manylinux_2_28_aarch64'),
    ('cp313', 'cp313', 'linux_aarch64'),
    ('cp311', 'abi3', 'manylinux_2_34_aarch64'),
    ('cp310', 'abi3', 'manylinux_2_17_aarch64.manylinux2014_aarch64'),
})


class Refused(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def require(value, reason):
    if not value:
        raise Refused(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def safe_name(path):
    require(type(path) is str and len(path.encode('utf-8')) <= 4096
            and len(path.split('/')) <= 64 and '\x7f' not in path, 'invalid_path')
    exporter.name(path)
    exporter.import_name(path)
    parts = path.split('/')
    require(not any(part in BUILD_NAMES or part.startswith(('.env.', '__editable__'))
                    or part.endswith('.egg-info') for part in parts), 'unsupported_payload')
    return path


def load_inputs(path, digest):
    require(type(digest) is str and HASH.fullmatch(digest), 'invalid_pin')
    raw = exporter.ordinary(path, 1024 * 1024)
    require(exporter.sha(raw) == digest, 'pin_mismatch')
    value = exporter.strict_json(raw)
    require(type(value) is dict and set(value) == INPUT_FIELDS
            and raw == canonical(value), 'invalid_input_manifest')
    require(type(value['schema_version']) is int and value['schema_version'] == 1
            and value['kind'] == 'factory-studio-bundle-inputs'
            and type(value['studio_commit']) is str
            and re.fullmatch('[0-9a-f]{40}', value['studio_commit']), 'invalid_input_manifest')
    require(type(value['python_version']) is str
            and re.fullmatch(r'3\.13\.(0|[1-9][0-9]*)', value['python_version']), 'invalid_input_manifest')
    for field, limit in (('source_sha256', MAX_FILES), ('wheel_sha256', 128)):
        pins = value[field]
        require(type(pins) is dict and 0 < len(pins) <= limit, 'invalid_input_manifest')
        for name, pin in pins.items():
            safe_name(name)
            require(type(pin) is str and HASH.fullmatch(pin), 'invalid_pin')
            if field == 'source_sha256':
                require(name == HELPER or name.startswith('client/dist/'), 'unsupported_source')
            else:
                require('/' not in name and name.endswith('.whl'), 'invalid_wheel')
    require(HELPER in value['source_sha256'] and type(value['app_wheel']) is str
            and value['app_wheel'] in value['wheel_sha256'], 'missing_app_or_helper')
    return value


def exact_inputs(root, pins):
    """No links, special files, extra empty directories or unpinned inputs."""
    exporter.checked_path(root)
    require(root.is_dir(), 'invalid_input_tree')
    expected = {name: 'file' for name in pins}
    for name in pins:
        for parent in PurePosixPath(name).parents:
            if str(parent) != '.':
                require(expected.get(str(parent), 'directory') == 'directory', 'path_collision')
                expected[str(parent)] = 'directory'
    pending, actual = [root], {}
    while pending:
        directory = pending.pop()
        for child in directory.iterdir():
            relative = str(child.relative_to(root))
            require(relative in expected and len(actual) < MAX_FILES * 64, 'extra_input')
            info = child.lstat()
            require(not info.st_mode & 0o7000, 'invalid_input_tree')
            if stat.S_ISDIR(info.st_mode):
                require(expected[relative] == 'directory', 'invalid_input_tree')
                actual[relative] = 'directory'; pending.append(child)
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and expected[relative] == 'file', 'invalid_input_tree')
                actual[relative] = 'file'
    require(actual == expected, 'missing_input')


def app_metadata(payload, filename):
    distribution, version, *_ = filename[:-4].split('-')
    metadata = payload.get(distribution + '-' + version + '.dist-info/METADATA')
    require(metadata is not None, 'invalid_app_wheel')
    text = metadata.decode('utf-8')
    header = text.split('\n\n', 1)[0].splitlines()
    for label, expected in (('Name', distribution), ('Version', version)):
        values = [line[len(label) + 2:] for line in header if line.startswith(label + ': ')]
        require(len(values) == 1, 'invalid_app_wheel')
        if label == 'Name':
            normalize = lambda item: re.sub(r'[-_.]+', '_', item).lower()
            require(normalize(values[0]) == normalize(expected), 'invalid_app_wheel')
        else:
            require(values[0] == expected, 'invalid_app_wheel')
    versions = [line for line in header if line.startswith('Metadata-Version: ')]
    require(len(versions) == 1 and re.fullmatch(r'Metadata-Version: [12]\.[0-9]+', versions[0])
            and {'inky_web/__init__.py', 'inky_web/main.py'} <= set(payload), 'invalid_app_wheel')


def wheel_payload(raw, filename):
    """Studio's closed tags and inert native-header preflight, not a loader."""
    payload = exporter.wheel_payload(raw, filename, allowed_filename_tags=STUDIO_FILENAME_TAGS)
    pure_tag = filename[:-4].split('-')[-1] == 'any'
    for path, content in payload.items():
        shared_object = re.search(r'\.so(?:\.|$)', PurePosixPath(path).name) is not None
        if shared_object or content.startswith(b'\x7fELF'):
            require(not pure_tag, 'native_in_pure_wheel')
            require(len(content) >= 64 and content[:7] == b'\x7fELF\x02\x01\x01'
                    and int.from_bytes(content[18:20], 'little') == 183
                    and int.from_bytes(content[20:24], 'little') == 1
                    and int.from_bytes(content[52:54], 'little') == 64,
                    'invalid_native_header')
            require(not shared_object or int.from_bytes(content[16:18], 'little') == 3,
                    'invalid_shared_object')
    return payload


def derive(value, sources, wheels):
    exact_inputs(sources, value['source_sha256'])
    exact_inputs(wheels, value['wheel_sha256'])
    files, total, site_names = {}, 0, set()
    for filename, pin in value['wheel_sha256'].items():
        raw = exporter.ordinary(wheels / filename)
        require(exporter.sha(raw) == pin, 'pin_mismatch')
        payload = wheel_payload(raw, filename)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for member in archive.infolist():
                safe_name(member.filename[:-1] if member.is_dir() else member.filename)
        if filename == value['app_wheel']:
            app_metadata(payload, filename)
        else:
            require(not any(path == 'inky_web' or path.startswith(('inky_web/', 'inky_web.')) for path in payload),
                    'app_namespace_collision')
        for path, content in payload.items():
            safe_name(path)
            require(path not in site_names, 'wheel_collision')
            site_names.add(path)
            total += len(content)
            require(total <= MAX_BYTES and len(files) < MAX_FILES, 'payload_limit')
            files[SITE + '/' + path] = exporter.file_record(content)
    for path, pin in value['source_sha256'].items():
        raw = exporter.ordinary(sources / path)
        require(exporter.sha(raw) == pin, 'pin_mismatch')
        total += len(raw)
        require(total <= MAX_BYTES and len(files) < MAX_FILES, 'payload_limit')
        require(path not in files, 'path_collision')
        files[path] = exporter.file_record(raw, '0555' if path == HELPER else '0644')
    # Recheck the input inventories after bounded reads, before any publication.
    exact_inputs(sources, value['source_sha256'])
    exact_inputs(wheels, value['wheel_sha256'])
    directory = {'type': 'directory', 'uid': 0, 'gid': 0, 'mode': '0755', 'xattrs': exporter.EMPTY_XATTRS}
    records = {'.': directory.copy(), **files}
    records[VENV + '/pyvenv.cfg'] = exporter.file_record(exporter.configuration(value['python_version']))
    for path, target in {'bin/python': 'python3.13', 'bin/python3': 'python3.13',
                         'bin/python3.13': '/usr/bin/python3.13', 'lib64': 'lib'}.items():
        records[VENV + '/' + path] = {'type': 'symlink', 'uid': 0, 'gid': 0, 'mode': '0777',
                                     'target': target, 'xattrs': exporter.EMPTY_XATTRS}
    records[VENV + '/include/python3.13'] = directory.copy()
    for path in list(records):
        for parent in PurePosixPath(path).parents:
            parent = str(parent)
            require(parent not in records or records[parent]['type'] == 'directory', 'path_collision')
            records.setdefault(parent, directory.copy())
            require(len(records) <= 100000, 'payload_limit')
    return records, len(files)


def plan(input_manifest, input_sha256, sources_dir, wheels_dir):
    try:
        inputs = Path(input_manifest)
        sources, wheels = Path(sources_dir), Path(wheels_dir)
        require(not sources.is_relative_to(wheels) and not wheels.is_relative_to(sources)
                and not inputs.is_relative_to(sources) and not inputs.is_relative_to(wheels), 'input_overlap')
        value = load_inputs(inputs, input_sha256)
        records, count = derive(value, sources, wheels)
        manifest = canonical({'schema_version': 1, 'kind': 'factory-studio-bundle-manifest',
                              'studio_commit': value['studio_commit'], 'records': records})
        require(len(manifest) <= 32 * 1024 * 1024, 'payload_limit')
        receipt = {'schema_version': 1, 'scope': 'factory-studio-bundle-plan-only',
                   'input_manifest_sha256': input_sha256, 'bundle_manifest_sha256': exporter.sha(manifest),
                   'studio_commit': value['studio_commit'], 'source_files': len(value['source_sha256']),
                   'wheel_files': len(value['wheel_sha256']), 'payload_files': count,
                   'bundle_entries': len(records), 'record_metadata': 'expected-root-owned-no-xattrs',
                   'image_code_executed': False, 'application_candidate_qualified': False}
        return manifest, receipt
    except Refused:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError,
            NotImplementedError, zipfile.BadZipFile, zlib.error):
        raise Refused('invalid_inputs') from None


def publish_plan(input_manifest, input_sha256, sources_dir, wheels_dir, *, output, receipt_output):
    manifest, receipt = plan(input_manifest, input_sha256, sources_dir, wheels_dir)
    try:
        targets = (Path(output), Path(receipt_output))
        require(targets[0] != targets[1], 'output_overlap')
        for target in targets:
            exporter.checked_path(target, missing=True)
            require(not os.path.lexists(target) and target != Path(input_manifest)
                    and not any(target.is_relative_to(Path(root)) for root in (sources_dir, wheels_dir)),
                    'output_exists_or_overlaps')
        # No overwrite/repair on I/O failure: a partial output requires inspection.
        for target, raw in zip(targets, (manifest, canonical(receipt))):
            with target.open('xb') as stream:
                os.fchmod(stream.fileno(), 0o644)
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        return receipt
    except Refused:
        raise
    except (OSError, ValueError, TypeError):
        raise Refused('publication_failed') from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-sha256', required=True)
    for field in ('input-manifest', 'sources-dir', 'wheels-dir', 'output', 'receipt'):
        parser.add_argument('--' + field, type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        publish_plan(args.input_manifest, args.input_sha256, args.sources_dir, args.wheels_dir,
                     output=args.output, receipt_output=args.receipt)
    except Refused as error:
        print('factory_studio_plan_refused:' + error.reason, file=sys.stderr)
        return 1
    print('Expected bundle planned; no candidate built or qualified.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
