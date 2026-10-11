#!/usr/bin/env python3
"""Static staging exporter verification; never import or execute image code.

The expected payload comes from reviewed input bytes, never a post-build hash.
System-support is an independently reviewed, pinned trust input: its ELF review
must cover loader search, recursive dependencies and native wheel code. This is
not an ELF resolver. A missing support pin prevents a successful verification.
"""
import argparse
import base64
import csv
import hashlib
import importlib.util
import io
import itertools
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = 'usr/lib/inkyos/factory-exporter'
SITE = 'venv/lib/python3.13/site-packages'
LIMIT = 64 * 1024**2
HASH = re.compile(r'[0-9a-f]{64}')
EMPTY_XATTRS = {'status': 'inspected', 'entries': {}}
ABSENCE_GUARDS = {'usr/lib/python313.zip', 'etc/ld.so.preload',
                  'usr/bin/python3.13._pth', 'usr/bin/python3._pth',
                  'usr/bin/pybuilddir.txt', 'usr/bin/Modules',
                  'usr/pyvenv.cfg', 'usr/bin/pyvenv.cfg', 'usr/bin/lib', 'usr/lib/lib'}


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


inventory_module = module('_factory_inventory', 'manifest-rootfs.py')
application_installer = module('_factory_input_helpers', 'install-application-rootfs.py')
checked_path = application_installer.checked_path


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'Duplicate JSON key')
            result[key] = value
        return result
    def invalid(_):
        raise ValueError('Non-finite JSON number')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def name(value, *, root=False):
    require(isinstance(value, str) and value and '\\' not in value
            and not any(ord(c) < 32 for c in value), 'Unsafe relative path')
    require(value == '.' and root or
            not value.startswith('/') and all(p not in {'', '.', '..'} for p in value.split('/')),
            'Unsafe relative path')
    return value


def ordinary(path, limit=LIMIT):
    checked_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size <= limit, 'Bounded single-link regular input required')
        raw = stream.read(limit + 1)
        require(len(raw) == before.st_size and inventory_module._signature(before) ==
                inventory_module._signature(os.fstat(stream.fileno())) ==
                inventory_module._signature(path.lstat()), 'Input changed during read')
        return raw


def load_lock(path=ROOT / 'config/factory-exporter.lock.json', *, expected_sha256=None):
    require(expected_sha256 is None or
            isinstance(expected_sha256, str) and HASH.fullmatch(expected_sha256),
            'Invalid exporter lock pin')
    raw = ordinary(path)
    require(expected_sha256 is None or sha(raw) == expected_sha256, 'Exporter lock pin mismatch')
    lock = strict_json(raw)
    require(lock['schema_version'] == 1 and lock['contract'] == 'factory-exporter-v2'
            and lock['destination'] == '/' + DESTINATION,
            'Unsupported exporter lock')
    require(lock['argv'] == ['/' + DESTINATION + '/venv/bin/python', '-I', '-B', '-m',
                            'inky_web.provisioning.factory_credentials', '--emit-v2'],
            'Unexpected exporter command')
    require(re.fullmatch('[0-9a-f]{40}', lock['studio_commit']), 'Invalid source commit')
    for field in ('source_sha256', 'wheel_sha256'):
        require(isinstance(lock[field], dict) and lock[field], 'Empty input pins')
        for path, digest in lock[field].items():
            name(path)
            require(HASH.fullmatch(digest), 'Invalid input pin')
            if field == 'wheel_sha256':
                require('/' not in path and path.endswith('.whl'), 'Invalid wheel name')
    for path, field in (('config/base-image.lock.json', 'base_lock_sha256'),
                        ('config/system-packages.lock.json', 'system_packages_lock_sha256'),
                        ('config/test-access-packages.lock.json', 'test_access_packages_lock_sha256')):
        require(sha(ordinary(ROOT / path)) == lock[field], 'OS lock pin mismatch')
    require(strict_json(ordinary(ROOT / 'config/base-image.lock.json'))['image']['extracted_sha256']
            == lock['base_image_sha256'], 'Base image mismatch')
    return lock


def load_cli_lock(args, *, workspace=None):
    path, digest = getattr(args, 'lock', None), getattr(args, 'lock_sha256', None)
    require((path is None) == (digest is None), '--lock and --lock-sha256 must be paired')
    if path is None:
        return load_lock()
    require(isinstance(digest, str) and HASH.fullmatch(digest), 'Invalid exporter lock pin')
    require(args.rootfs.is_absolute() and args.rootfs != Path('/') and path.is_absolute()
            and not path.is_relative_to(args.rootfs), 'Explicit lock must be outside a non-host rootfs')
    if workspace is not None:
        require(path.is_relative_to(workspace), 'Explicit lock must be in the private build workspace')
    return load_lock(path, expected_sha256=digest)


def require_support_pin(lock):
    digest = lock.get('support_manifest_sha256')
    require(isinstance(digest, str) and HASH.fullmatch(digest),
            'System-support manifest is not pinned; staging installation and PASS are disabled')
    return digest


def import_name(path):
    parts = PurePosixPath(path).parts
    require(not any(p.endswith(('.data', '.pth', '._pth', '.egg-link', '.pyc', '.pyo'))
                    or p in {'__pycache__', 'sitecustomize.py', 'usercustomize.py',
                             'sitecustomize', 'usercustomize'} for p in parts),
            'Unsupported import hook or generated payload')
    require(not any(p.startswith(('sitecustomize.', 'usercustomize.')) for p in parts),
            'Import customization refused')


def wheel_payload(raw, filename, *, allowed_filename_tags=None):
    """Constrained wheel bytes; default tags retain the exporter contract.

    Other trusted callers may supply their own closed filename-tag policy. This
    does not bypass WHEEL/RECORD checks or inspect a native object's architecture.
    """
    payload = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as wheel:
        seen = set(); expanded = 0
        for member in wheel.infolist():
            require(member.orig_filename == member.filename, 'Truncated wheel path')
            path = name(member.filename[:-1] if member.is_dir() else member.filename)
            require(path not in seen, 'Duplicate wheel path'); seen.add(path)
            import_name(path)
            mode = member.external_attr >> 16
            require(not member.flag_bits & 1 and
                    (stat.S_IFMT(mode) in (0, stat.S_IFDIR) if member.is_dir()
                     else stat.S_IFMT(mode) in (0, stat.S_IFREG)), 'Special wheel member refused')
            require(not mode & 0o7000, 'Privileged wheel mode refused')
            expanded += member.file_size
            require(member.file_size <= LIMIT and expanded <= LIMIT, 'Oversized wheel payload')
            if not member.is_dir():
                payload[path] = wheel.read(member)
    stem = filename.rsplit('.whl', 1)[0].split('-')
    reviewed_tags = (frozenset({
        ('py3', 'none', 'any'),
        ('cp313', 'cp313', 'manylinux_2_17_aarch64.manylinux2014_aarch64')})
        if allowed_filename_tags is None else allowed_filename_tags)
    require(len(stem) == 5 and tuple(stem[-3:]) in reviewed_tags,
        'Wheel ABI is outside the reviewed contract')
    dist = stem[0] + '-' + stem[1] + '.dist-info'
    require({p.split('/')[0] for p in payload if '.dist-info/' in p} == {dist},
            'Unexpected wheel metadata directory')
    record = dist + '/RECORD'
    require(record in payload and dist + '/WHEEL' in payload, 'Missing wheel metadata')
    wheel_metadata = payload[dist + '/WHEEL'].decode('utf-8')
    tags = {'-'.join(parts) for parts in itertools.product(*(part.split('.') for part in stem[-3:]))}
    require('Wheel-Version: 1.0\n' in wheel_metadata and
            {line[5:] for line in wheel_metadata.splitlines() if line.startswith('Tag: ')} == tags,
            'Unexpected wheel format or tag')
    rows = list(csv.reader(io.StringIO(payload[record].decode('utf-8'))))
    indexed = {}
    for row in rows:
        require(len(row) == 3 and row[0] not in indexed, 'Invalid wheel RECORD')
        name(row[0]); indexed[row[0]] = row[1:]
    require(set(indexed) == set(payload), 'Wheel RECORD does not enumerate exact payload')
    for path, content in payload.items():
        digest, length = indexed[path]
        if path == record:
            require((digest, length) == ('', ''), 'RECORD self-hash must be empty')
        else:
            expected = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b'=').decode()
            require(digest == 'sha256=' + expected and length == str(len(content)),
                    'Wheel RECORD content mismatch')
    for path in payload:
        require(not any(str(parent) in payload for parent in PurePosixPath(path).parents
                        if str(parent) != '.'), 'Wheel file-directory collision')
    return payload


def expected_payload(lock, sources, wheels):
    """Read pins first, derive exact delivered bytes before running a child."""
    checked_path(sources); checked_path(wheels)
    require({p.name for p in wheels.iterdir()} == set(lock['wheel_sha256']),
            'Wheelhouse must contain exactly the pinned wheels')
    payload = {}
    for filename, digest in lock['wheel_sha256'].items():
        raw = ordinary(wheels / filename)
        require(sha(raw) == digest, 'Wheel input hash mismatch')
        for path, content in wheel_payload(raw, filename).items():
            require(path not in payload, 'Cross-wheel path collision')
            payload[path] = content
    for path, digest in lock['source_sha256'].items():
        name(path); import_name(path)
        require(path not in payload, 'Source-wheel collision')
        raw = ordinary(sources / path)
        require(sha(raw) == digest, 'Studio source input hash mismatch')
        payload[path] = raw
    for path in payload:
        require(not any(str(parent) in payload for parent in PurePosixPath(path).parents
                        if str(parent) != '.'), 'Payload file-directory collision')
    return payload


def configuration(version):
    require(re.fullmatch(r'3\.13\.[0-9]+', version), 'Unsupported Python version')
    return ('home = /usr/bin\ninclude-system-site-packages = false\nversion = ' + version +
            '\nexecutable = /usr/bin/python3.13\n').encode()


def file_record(content, mode='0644'):
    return {'type': 'file', 'uid': 0, 'gid': 0, 'mode': mode,
            'size_bytes': len(content), 'sha256': sha(content), 'xattrs': EMPTY_XATTRS}


def bundle_manifest(records, support_digest):
    """Self-exclusion is explicit; every other record is derived from pins."""
    return (json.dumps({'schema_version': 1, 'kind': 'factory-exporter-bundle-manifest',
                        'support_manifest_sha256': support_digest,
                        'records': {path: record for path, record in records.items()
                                    if path != 'manifest.json'}},
                       indent=2, sort_keys=True) + '\n').encode()


def expected_bundle(payload, version, support_digest=None):
    directory = {'type': 'directory', 'uid': 0, 'gid': 0, 'mode': '0755', 'xattrs': EMPTY_XATTRS}
    records = {'.': directory.copy()}
    files = {SITE + '/' + path: raw for path, raw in payload.items()}
    files['venv/pyvenv.cfg'] = configuration(version)
    for path, raw in files.items():
        records[path] = file_record(raw)
    for path, target in {'venv/bin/python': 'python3.13', 'venv/bin/python3': 'python3.13',
                         'venv/bin/python3.13': '/usr/bin/python3.13', 'venv/lib64': 'lib'}.items():
        records[path] = {'type': 'symlink', 'uid': 0, 'gid': 0, 'mode': '0777',
                         'target': target, 'xattrs': EMPTY_XATTRS}
    records['venv/include/python3.13'] = directory.copy()
    for path in list(records):
        for parent in PurePosixPath(path).parents:
            records.setdefault(str(parent), directory.copy())
    records['manifest.json'] = file_record(bundle_manifest(records, support_digest))
    return records


def secure_record(record, *, owner=(0, 0), fixture=False):
    require(record.get('type') in {'directory', 'file', 'symlink'} and
            (record.get('uid'), record.get('gid')) == owner and 'hardlinks' not in record,
            'Unsafe ownership, hardlink or special entry')
    mode = int(record['mode'], 8)
    require(record['type'] == 'symlink' or not mode & 0o7022,
            'Writable or privileged support entry')
    xattrs = record['xattrs']
    require(xattrs == EMPTY_XATTRS or fixture and xattrs ==
            {'status': 'unsupported', 'reason': 'platform'}, 'Uninspected xattrs or ACL refused')


def single_record(path):
    """Reuse schema-2 inventory primitives without walking an entire parent."""
    if path == Path('/'):
        fd = inventory_module._open_root(path)
        try:
            before = os.fstat(fd)
            record = {'type': 'directory', 'uid': before.st_uid, 'gid': before.st_gid,
                      'mode': format(stat.S_IMODE(before.st_mode), '04o'),
                      'xattrs': inventory_module._xattrs(fd)}
            inventory_module._check_stable(before, os.fstat(fd))
            return record
        finally:
            os.close(fd)
    fd = inventory_module._open_root(path.parent)
    try:
        before = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        result = {'uid': before.st_uid, 'gid': before.st_gid,
                  'mode': format(stat.S_IMODE(before.st_mode), '04o')}
        if stat.S_ISREG(before.st_mode):
            require(before.st_nlink == 1, 'System hardlink refused')
            result.update(type='file', **inventory_module._regular_file(fd, path.name, before))
        elif stat.S_ISDIR(before.st_mode):
            child = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                inventory_module._check_stable(before, os.fstat(child))
                result.update(type='directory', xattrs=inventory_module._xattrs(child))
            finally:
                os.close(child)
        elif stat.S_ISLNK(before.st_mode):
            result.update(type='symlink', target=os.readlink(path.name, dir_fd=fd),
                          xattrs=inventory_module._path_xattrs(fd, path.name))
        else:
            raise ValueError('Special system entry refused')
        inventory_module._check_stable(before, os.stat(path.name, dir_fd=fd, follow_symlinks=False))
        return result
    finally:
        os.close(fd)


def support_records(support):
    records = dict(support['paths'])
    for prefix, tree in support['trees'].items():
        name(prefix)
        require('.' in tree, 'Support tree root missing')
        for path, record in tree.items():
            name(path, root=True)
            path = prefix if path == '.' else prefix + '/' + path
            require(path not in records, 'Overlapping support inventory')
            records[path] = record
    for path, record in records.items():
        name(path, root=True); secure_record(record)
    require(records.get('.', {}).get('type') == 'directory', 'Root metadata missing')
    return records


def resolve_record(path, records):
    """Resolve only inside the pinned map, never through host filesystem links."""
    pending = path.split('/'); resolved = []; links = 0
    while pending:
        part = pending.pop(0)
        if part in {'', '.'}:
            continue
        if part == '..':
            require(resolved, 'Symlink escapes root'); resolved.pop(); continue
        candidate = '/'.join(resolved + [part])
        require(candidate in records, 'Symlink target or parent outside pinned support')
        record = records[candidate]
        if record['type'] == 'symlink':
            links += 1; require(links <= 40, 'Symlink loop')
            target = record['target']
            require(isinstance(target, str) and target and '\x00' not in target, 'Invalid symlink target')
            if target.startswith('/'):
                resolved = []
            pending = target.split('/') + pending
        else:
            require(not pending or record['type'] == 'directory', 'Non-directory symlink component')
            resolved.append(part)
    return '/'.join(resolved) or '.'


def load_support(lock, path):
    expected = require_support_pin(lock)
    raw = ordinary(path)
    require(sha(raw) == expected, 'System-support pin mismatch')
    support = strict_json(raw)
    require(support['schema_version'] == 1 and support['kind'] == 'factory-exporter-system-support',
            'Unsupported system-support manifest')
    for field in ('base_image_sha256', 'base_lock_sha256', 'system_packages_lock_sha256',
                  'test_access_packages_lock_sha256'):
        require(support[field] == lock[field], 'Support provenance mismatch')
    configuration(support['python_version'])
    records = support_records(support)
    require('usr/lib/python3.13' in support['trees'] and
            'usr/lib/aarch64-linux-gnu' in support['trees'] and
            'usr/local/lib' in support['trees'] and 'etc/ld.so.conf.d' in support['trees'],
            'Complete reviewed Python and loader search trees required')
    for path in ('usr/bin/python3', 'usr/bin/python3.13', 'etc/ld.so.cache', 'etc/ld.so.conf'):
        require(path in records, 'Required Python/loader support missing')
    require(resolve_record('usr/bin/python3', records) == 'usr/bin/python3.13'
            and records['usr/bin/python3.13']['type'] == 'file', 'External Python interpreter refused')
    absent = support['absent']
    require(isinstance(absent, list) and len(absent) == len(set(absent)) and
            ABSENCE_GUARDS <= set(absent), 'Required absence guards missing')
    for path in absent:
        name(path); require(path not in records, 'Present and absent support path')
    for path in records:
        resolve_record(path, records)
    review = support['elf_closure_review']
    require(isinstance(review['method'], str) and review['method'] and
            HASH.fullmatch(review['evidence_sha256']), 'Independent ELF review missing')
    for key in ('roots', 'files', 'search_paths'):
        require(isinstance(review[key], list) and review[key] and
                len(review[key]) == len(set(review[key])), 'Invalid ELF closure list')
        for path in review[key]:
            name(path)
            if key != 'roots' or not path.startswith(DESTINATION + '/'):
                require(path in records or key == 'search_paths' and path in absent,
                        'ELF review names unpinned support')
    native_roots = {'usr/bin/python3.13'} | {
        path for path, record in records.items()
        if path.startswith('usr/lib/python3.13/') and path.endswith('.so')
        and record['type'] == 'file'}
    require(native_roots <= set(review['roots']), 'Interpreter or stdlib ELF review missing')
    return support, records


def verify_support(rootfs, support, records):
    checked_path(rootfs)
    for prefix, expected in support['trees'].items():
        actual = inventory_module.inventory(rootfs / prefix)
        require(actual == expected, 'System-support tree differs from reviewed inventory')
    for path, expected in support['paths'].items():
        actual = single_record(rootfs if path == '.' else rootfs / path)
        require(actual == expected, 'System-support metadata or bytes differ')
    for path in support['absent']:
        # Verify every existing parent before checking absence; never follow an
        # unreviewed symlink into a host path, including on offline rootfs mounts.
        parent = PurePosixPath(path).parent
        require(str(parent) in records and records[str(parent)]['type'] == 'directory',
                'Absence guard parent is not pinned')
        checked_path(rootfs / str(parent))
        require(not os.path.lexists(rootfs / path), 'Forbidden Python/loader path is present')


def verify_bundle(rootfs, expected, *, owner=(0, 0), fixture=False):
    bundle = rootfs / DESTINATION
    actual = inventory_module.inventory(bundle)
    for path, record in actual.items():
        secure_record(record, owner=owner, fixture=fixture)
        if path.startswith(SITE + '/'):
            import_name(path[len(SITE) + 1:])
    require(actual == expected, 'Exporter tree differs from exact source/wheel payload')
    for path in (rootfs, rootfs / 'usr', rootfs / 'usr/lib', rootfs / 'usr/lib/inkyos'):
        secure_record(single_record(path), owner=owner, fixture=fixture)
    return actual


def verify(rootfs, lock, sources, wheels, support_path):
    support, records = load_support(lock, support_path)
    payload = expected_payload(lock, sources, wheels)
    expected = expected_bundle(payload, support['python_version'], lock['support_manifest_sha256'])
    native = {DESTINATION + '/' + SITE + '/' + path for path, raw in payload.items()
              if raw.startswith(b'\x7fELF')}
    require(native <= set(support['elf_closure_review']['roots']), 'Native wheel ELF review missing')
    verify_support(rootfs, support, records)
    actual = verify_bundle(rootfs, expected)
    return {'schema_version': 1, 'scope': 'staging-factory-exporter-static-closure',
            'passed': True, 'support_manifest_sha256': lock['support_manifest_sha256'],
            'bundle_manifest_sha256': expected['manifest.json']['sha256'],
            'studio_commit': lock['studio_commit'], 'payload_files': len(payload),
            'bundle_entries': len(actual), 'image_code_executed': False,
            'hardware_qualified': False, 'application_candidate_complete': False,
            'runtime_activation_qualified': False,
            'limitations': ['Independent pinned ELF review is a trusted prerequisite; no dynamic loader execution.',
                            'Four sources and ten wheels are not a complete Studio application candidate.',
                            'No readonly runtime mount, factory barrier, credential generation or boot is exercised.']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ('rootfs', 'sources-dir', 'wheels-dir', 'support-manifest', 'output'):
        parser.add_argument('--' + field, type=Path, required=True)
    parser.add_argument('--lock', type=Path)
    parser.add_argument('--lock-sha256')
    args = parser.parse_args(argv)
    try:
        lock = load_cli_lock(args)
        require_support_pin(lock)
        require(sys.platform.startswith('linux'), 'Linux metadata verification required')
        require(args.rootfs.is_absolute() and args.rootfs != Path('/'),
                'Host root is never a verification target')
        checked_path(args.output, missing=True)
        require(not os.path.lexists(args.output) and
                not args.output.is_relative_to(args.rootfs), 'New report outside rootfs required')
        report = verify(args.rootfs, lock, args.sources_dir, args.wheels_dir, args.support_manifest)
        with args.output.open('x', encoding='utf-8') as stream:
            json.dump(report, stream, indent=2, sort_keys=True); stream.write('\n')
        print('Staging exporter static closure: PASS; no runtime or image qualification.')
        return 0
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile,
            inventory_module.ManifestError):
        print('Staging exporter verification refused; no image code executed.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
