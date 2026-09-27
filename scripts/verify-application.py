#!/usr/bin/env python3
"""Check a pinned application manifest and local assets, without installing them.

Integrity and declared compatibility only. External qualification evidence,
archive safety, wheel tags and dependency closure are not verified here.
No network, extraction, target code execution or integration side effect.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from urllib.parse import urlsplit


MAX_MANIFEST = 1024 * 1024
MAX_ASSET = 1024 ** 3
HASH = re.compile(r'[0-9a-f]{64}\Z')
ROLES = {'application': '.tar.gz', 'wheelhouse': '.zip', 'python_lock': '.lock'}
TARGET = {'architecture': 'arm64', 'python_minor': '3.13', 'debian_release': 'trixie'}
CONTRACTS = {'http_contract', 'ble_contract', 'network_helper_contract'}


class ManifestError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ManifestError(message)


def fields(value, expected, name):
    require(isinstance(value, dict) and set(value) == set(expected), f'Invalid {name} fields')


def sha(value):
    return isinstance(value, str) and HASH.fullmatch(value) is not None


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate manifest key')
        result[key] = value
    return result


def read_regular(path, *, directory_fd=None, expected_size=None, limit=MAX_MANIFEST):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), 'Regular files required')
        require(before.st_size <= limit, 'Input exceeds size limit')
        if expected_size is not None:
            require(before.st_size == expected_size, 'Asset size mismatch')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            if expected_size is None:
                data = stream.read(limit + 1)
                require(len(data) <= limit, 'Manifest exceeds size limit')
                result = data
            else:
                digest, total = hashlib.sha256(), 0
                while block := stream.read(1024 * 1024):
                    total += len(block)
                    require(total <= expected_size, 'Asset changed during read')
                    digest.update(block)
                require(total == expected_size, 'Asset changed during read')
                result = digest.hexdigest()
        after = os.fstat(fd)
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'Input changed during read')
        return result
    finally:
        os.close(fd)


def validate_manifest(data):
    fields(data, {'schema_version', 'application_version', 'source_commit', 'assets',
                  'compatibility', 'qualification'}, 'manifest')
    require(type(data['schema_version']) is int and data['schema_version'] == 1, 'Unsupported schema')
    require(isinstance(data['application_version'], str) and
            re.fullmatch(r'\d+\.\d+\.\d+(?:(?:a|b|rc)\d+|-[0-9A-Za-z.-]+)?', data['application_version']),
            'Exact application release version required')
    require(isinstance(data['source_commit'], str) and
            re.fullmatch(r'[0-9a-f]{40}', data['source_commit']), 'Full source commit required')
    compatible = data['compatibility']
    fields(compatible, set(TARGET) | CONTRACTS, 'compatibility')
    require(all(compatible[key] == value for key, value in TARGET.items()), 'Unsupported target compatibility')
    for key in CONTRACTS:
        value = compatible[key]
        require(isinstance(value, str) and len(value) <= 128, 'Pinned contract reference required')
        reference = re.fullmatch(r'git:([0-9a-f]{40})#([A-Za-z0-9][A-Za-z0-9._/-]*)', value)
        require(reference is not None and reference[1] == data['source_commit'],
                'Contract must reference the same immutable source commit')
        path = PurePosixPath(reference[2])
        require('..' not in path.parts and str(path) == reference[2], 'Invalid contract source path')
    require(isinstance(data['assets'], list) and len(data['assets']) == len(ROLES), 'Exactly three assets required')
    roles, names, total = set(), set(), 0
    for asset in data['assets']:
        fields(asset, {'role', 'filename', 'size_bytes', 'sha256'}, 'asset')
        role, name = asset['role'], asset['filename']
        require(isinstance(role, str) and role in ROLES and role not in roles, 'Invalid or duplicate asset role')
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,180}', name)
                and name.endswith(ROLES[role]) and name not in names, 'Invalid or duplicate asset filename')
        require(type(asset['size_bytes']) is int and 0 < asset['size_bytes'] <= MAX_ASSET, 'Invalid asset size')
        require(sha(asset['sha256']), 'Asset SHA-256 required')
        roles.add(role); names.add(name); total += asset['size_bytes']
    require(total <= 2 * MAX_ASSET, 'Combined assets exceed limit')
    fields(data['qualification'], {'evidence'}, 'qualification')
    evidence = data['qualification']['evidence']
    require(isinstance(evidence, list) and len(evidence) <= 128, 'Invalid evidence list')
    for entry in evidence:
        fields(entry, {'kind', 'name', 'url', 'sha256'}, 'evidence')
        require(entry['kind'] in ('software', 'hardware'), 'Unknown evidence kind')
        require(isinstance(entry['name'], str) and 0 < len(entry['name']) <= 200
                and all(ord(c) >= 32 for c in entry['name']), 'Invalid evidence name')
        require(isinstance(entry['url'], str) and len(entry['url']) <= 2048
                and all(ord(c) > 32 for c in entry['url']), 'Evidence URL required')
        url = urlsplit(entry['url'])
        require(url.scheme == 'https' and url.hostname and not url.username and not url.password
                and not url.query and not url.fragment, 'Evidence must have a credential-free HTTPS URL')
        require(sha(entry['sha256']), 'Evidence SHA-256 required')
    return data


def verify(manifest, expected_hash, assets_directory):
    require(sha(expected_hash), 'Pinned manifest SHA-256 required')
    raw = read_regular(manifest)
    require(hashlib.sha256(raw).hexdigest() == expected_hash, 'Pinned manifest hash mismatch')
    data = validate_manifest(json.loads(raw, object_pairs_hook=unique_pairs))
    directory = os.open(assets_directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for asset in data['assets']:
            actual = read_regular(asset['filename'], directory_fd=directory,
                                  expected_size=asset['size_bytes'], limit=MAX_ASSET)
            require(actual == asset['sha256'], 'Asset hash mismatch')
    finally:
        os.close(directory)
    evidence_kinds = {entry['kind'] for entry in data['qualification']['evidence']}
    return {'schema_version': 1, 'scope': 'pinned-application-input-integrity', 'passed': True,
            'manifest_sha256': expected_hash, 'source_commit': data['source_commit'],
            'application_version': data['application_version'], 'compatibility': data['compatibility'],
            'assets': data['assets'], 'evidence_counts': {
                kind: sum(entry['kind'] == kind for entry in data['qualification']['evidence'])
                for kind in ('software', 'hardware')},
            'missing_evidence_categories': sorted({'software', 'hardware'} - evidence_kinds),
            'evidence_content_verified': False, 'integration_enabled': False,
            'limitations': ['No archive extraction or safety check.',
                           'Source commit is declared by the producer, not derived from asset contents.',
                           'No wheel-tag, dependency closure, installation or runtime check.',
                           'External evidence is declared only; this report grants no qualification.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--sha256', required=True, help='Reviewed SHA-256 of the manifest itself')
    parser.add_argument('--assets-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        require(not os.path.lexists(args.output), 'Output already exists')
        require(not args.output.resolve().is_relative_to(args.assets_dir.resolve()),
                'Output must be outside the asset bundle')
        result = verify(args.manifest, args.sha256, args.assets_dir)
        with args.output.open('x', encoding='utf-8') as stream:
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write('\n')
        print('Pinned application inputs verified; integration remains disabled.')
        return 0
    except (OSError, ValueError, TypeError, KeyError):
        print('Application input validation failed; no payload installed.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
