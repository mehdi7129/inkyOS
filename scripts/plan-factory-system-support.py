#!/usr/bin/env python3
"""Propose pinned system support and static ELF observations; never review/install it.

Builder Python only. Target bytes are passed to pinned builder readelf through a
Linux memfd, never executed or imported. Closure includes ALL declared loader
candidates, not a claim about symbol/ABI compatibility or runtime load order.
"""
import argparse
import collections
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import sys


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


exporter = module('_support_plan_exporter', 'verify-factory-exporter-rootfs.py')
runtime = module('_support_plan_runtime', 'factory-runtime-contract.py')
inventory = exporter.inventory_module
HASH = re.compile(r'[0-9a-f]{64}\Z')
PROVENANCE = {'base_image_sha256', 'base_lock_sha256', 'system_packages_lock_sha256',
              'test_access_packages_lock_sha256'}
POLICY = {'schema_version', 'kind', 'trees', 'paths', 'absent', 'elf_roots', 'loader'}
MAX_BYTES = 256 * 1024 * 1024


class Refused(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Refused(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def pinned(path, digest):
    require(type(digest) is str and HASH.fullmatch(digest), 'invalid_pin')
    raw = exporter.ordinary(Path(path), MAX_BYTES)
    require(exporter.sha(raw) == digest, 'input_pin_mismatch')
    return exporter.strict_json(raw)


def names(values, *, root=False, empty=True):
    require(type(values) is list and (empty or values) and len(values) <= 100000
            and all(type(value) is str for value in values)
            and len(values) == len(set(values)), 'invalid_path_list')
    for value in values:
        exporter.name(value, root=root)
    return values


def safe_record(record, owner):
    exporter.secure_record(record, owner=owner)
    # Also enforce the runtime's closed metadata schema. _owner is test-only.
    checked = dict(record, uid=0, gid=0)
    runtime.record_schema(checked)


def policy_schema(value):
    require(type(value) is dict and set(value) == POLICY and value['schema_version'] == 1
            and type(value['schema_version']) is int
            and value['kind'] == 'factory-system-support-policy', 'invalid_policy')
    for key in ('trees', 'paths', 'absent', 'elf_roots'):
        names(value[key], root=key == 'paths', empty=key not in ('trees', 'elf_roots'))
    trees = value['trees']
    require(runtime.SUPPORT_TREES <= set(trees), 'incomplete_support_trees')
    require(runtime.ABSENCE_GUARDS | runtime.TEST_ABSENT | runtime.UNIT_ABSENT
            <= set(value['absent']), 'incomplete_absence_policy')
    require(not any(a == b or a.startswith(b + '/') for a in trees for b in trees if a != b),
            'overlapping_trees')
    require(not any(path == tree or path.startswith(tree + '/')
                    for path in value['paths'] for tree in trees), 'overlapping_paths')
    loader = value['loader']
    require(type(loader) is dict and set(loader) == {'interpreter', 'default_search_paths'}
            and loader['interpreter'] == '/lib/ld-linux-aarch64.so.1', 'unsupported_loader')
    names(loader['default_search_paths'], empty=False)
    require(set(loader['default_search_paths']) == {
        'lib/aarch64-linux-gnu', 'usr/lib/aarch64-linux-gnu', 'lib', 'usr/lib'},
        'unsupported_glibc_default_search_profile')
    return value


def normalize(path):
    """Target POSIX path only; never Path.resolve() through host symlinks."""
    require(type(path) is str and path and '\\' not in path
            and not any(ord(c) < 32 or ord(c) == 127 for c in path), 'unsafe_target_path')
    result = []
    for part in path.split('/'):
        if part in ('', '.'):
            continue
        if part == '..':
            require(result, 'target_path_escape')
            result.pop()
        else:
            result.append(part)
    return '/'.join(result) or '.'


def read_bytes(root, path, expected):
    """Open each physical parent without links; all target links resolve in maps."""
    parent = inventory._open_root(root / str(PurePosixPath(path).parent))
    try:
        fd = os.open(PurePosixPath(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=parent)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and before.st_size <= MAX_BYTES, 'unsafe_elf_input')
            chunks, size = [], 0
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk); size += len(chunk)
                require(size <= before.st_size, 'input_changed')
            inventory._check_stable(before, os.fstat(fd))
            inventory._check_stable(before, os.stat(PurePosixPath(path).name,
                                                    dir_fd=parent, follow_symlinks=False))
            raw = b''.join(chunks)
            require(len(raw) == expected['size_bytes'] and exporter.sha(raw) == expected['sha256'],
                    'input_changed')
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def collect(root, policy, owner):
    trees, paths = {}, {}
    for prefix in policy['trees']:
        trees[prefix] = inventory.inventory(root / prefix)
    for path in policy['paths']:
        paths[path] = exporter.single_record(root if path == '.' else root / path)
    # Parents are structural metadata, never unreviewed traversals.
    for path in list(policy['trees']) + list(policy['paths']):
        for parent in PurePosixPath(path).parents:
            name = str(parent)
            if not any(name == tree or name.startswith(tree + '/') for tree in trees):
                paths.setdefault(name, exporter.single_record(root if name == '.' else root / name))
    result = dict(paths)
    for prefix, tree in trees.items():
        for path, record in tree.items():
            name = prefix if path == '.' else prefix + '/' + path
            require(name not in result, 'support_inventory_collision')
            result[name] = record
    for path, record in result.items():
        safe_record(record, owner)
        for parent in PurePosixPath(path).parents:
            require(result.get(str(parent), {}).get('type') == 'directory', 'unclosed_parent')
    require(len(result) <= 100000, 'support_inventory_limit')
    required = {runtime.HELPER, *runtime.HOOKS, *runtime.SUPERVISOR_FILES, *runtime.WRITER_FILES}
    required |= set(getattr(runtime, 'SETUP_FILES', {})) | set(getattr(runtime, 'NATIVE_COMMANDS', ()))
    required |= {runtime.MODULE_DIR + '/' + name for name in runtime.MODULES}
    require(required <= set(result), 'missing_runtime_support_paths')
    for path, mode in (runtime.SUPERVISOR_FILES | runtime.WRITER_FILES |
                       getattr(runtime, 'SETUP_FILES', {})).items():
        require(path in paths and result[path]['type'] == 'file' and result[path]['mode'] == mode,
                'runtime_support_mode_or_path_mismatch')
    require(runtime.SUPPORT not in result and runtime.MANIFEST not in result,
            'self_referential_support')
    require(not any(path.startswith('usr/local/lib/inkyos/test-access-')
                    or 'inkyos-test-' in PurePosixPath(path).name for path in result), 'test_support_refused')
    return {'trees': trees, 'paths': paths}, result


def check_absent(root, path, records):
    """Share the verifier's stable fd-based sysroot walk, without circular import."""
    try:
        exporter.verify_absent(root, path, records)
    except (ValueError, inventory.ManifestError) as error:
        raise Refused(str(error)) from error


def parse_cache(raw):
    """New glibc cache 1.1, LE; include every ABI/hwcap entry, never choose one."""
    require(len(raw) >= 48 and raw[:20] == b'glibc-ld.so.cache1.1', 'unsupported_loader_cache')
    count, length = struct.unpack_from('<II', raw, 20)
    require(raw[28] in (0, 2) and raw[29:32] == b'\0' * 3
            and count <= 100000 and 48 + count * 24 + length <= len(raw), 'invalid_loader_cache')
    start, end = 48 + count * 24, 48 + count * 24 + length

    def string(offset):
        require(start <= offset < end, 'invalid_loader_cache_string')
        stop = raw.find(b'\0', offset, end)
        require(stop >= 0, 'invalid_loader_cache_string')
        return raw[offset:stop].decode('ascii')

    entries = collections.defaultdict(list)
    for index in range(count):
        flags, key, value, osversion, hwcap = struct.unpack_from('<iIIIQ', raw, 48 + index * 24)
        name, path = string(key), string(value)
        require(name and '/' not in name and path.startswith('/') and '$' not in path,
                'invalid_loader_cache_path')
        entries[name].append({'path': normalize(path), 'flags': flags,
                              'osversion': osversion, 'hwcap': hwcap})
    return dict(entries)


def parse_readelf(raw, text):
    require(len(raw) >= 64 and raw[:7] == b'\x7fELF\x02\x01\x01'
            and raw[7] in (0, 3) and struct.unpack_from('<HHI', raw, 16) in ((2, 183, 1), (3, 183, 1))
            and struct.unpack_from('<H', raw, 52)[0] == 64, 'unsupported_elf_header')
    require('ELF64' in text and 'AArch64' in text and 'little endian' in text,
            'unsupported_readelf_output')
    result = {'needed': [], 'rpath': None, 'runpath': None, 'soname': None, 'interpreter': None}
    matches = re.findall(r'\[Requesting program interpreter: ([^\]\n]+)\]', text)
    require(len(matches) <= 1, 'multiple_interpreters')
    if matches:
        result['interpreter'] = matches[0]
    for tag, value in re.findall(r'^\s*0x[0-9a-fA-F]+\s+\(([^)]+)\)\s+(.*?)\s*$', text, re.M):
        if tag in ('NEEDED', 'RPATH', 'RUNPATH', 'SONAME'):
            match = re.fullmatch(r'(?:Shared library|Library rpath|Library runpath|Library soname): \[([^\]\n]*)\]', value)
            require(match, 'unsupported_readelf_dynamic_string')
            string = match[1]
            require(string and len(string) <= 4096 and not any(ord(c) < 32 for c in string),
                    'invalid_elf_dynamic_string')
            if tag == 'NEEDED':
                require(string not in result['needed'], 'duplicate_needed'); result['needed'].append(string)
            else:
                key = tag.lower(); require(result[key] is None, 'duplicate_dynamic_tag'); result[key] = string
        if tag in ('AUDIT', 'DEPAUDIT', 'FILTER', 'AUXILIARY', 'CONFIG'):
            raise Refused('unsupported_dynamic_tag:' + tag)
        if tag == 'FLAGS_1' and 'NODEFLIB' in value:
            raise Refused('unsupported_nodeflib')
    require('Dynamic section at offset' in text or 'There is no dynamic section' in text,
            'missing_readelf_dynamic_observation')
    return result


class Readelf:
    def __init__(self, path, digest):
        self.path, self.digest = Path(path), digest
        require(self.path.is_absolute() and self.path != Path('/'), 'invalid_readelf_path')
        require(type(digest) is str and HASH.fullmatch(digest), 'invalid_readelf_pin')
        require(exporter.sha(exporter.ordinary(self.path, MAX_BYTES)) == digest, 'readelf_pin_mismatch')
        require(os.access(self.path, os.X_OK), 'readelf_not_executable')

    def __call__(self, raw):
        require(sys.platform.startswith('linux') and hasattr(os, 'memfd_create'), 'linux_memfd_required')
        # Revalidate trusted builder binary before and after every invocation.
        require(exporter.sha(exporter.ordinary(self.path, MAX_BYTES)) == self.digest, 'readelf_changed')
        fd = os.memfd_create('inkyos-static-elf', os.MFD_CLOEXEC)
        try:
            view = memoryview(raw)
            while view:
                view = view[os.write(fd, view):]
            command = [str(self.path), '--wide', '--file-header', '--program-headers', '--dynamic',
                       '/proc/self/fd/' + str(fd)]
            process = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, env={'LC_ALL': 'C'}, pass_fds=(fd,), timeout=30)
            require(process.returncode == 0 and not process.stderr
                    and len(process.stdout) <= 16 * 1024 * 1024, 'readelf_failed')
            result = parse_readelf(raw, process.stdout.decode('ascii'))
        finally:
            os.close(fd)
        require(exporter.sha(exporter.ordinary(self.path, MAX_BYTES)) == self.digest, 'readelf_changed')
        return result


class Closure:
    def __init__(self, records, trees, absent, loader, read, inspect, probe_absent=None):
        self.records, self.trees, self.absent = records, trees, set(absent)
        self.loader, self.read, self.inspect = loader, read, inspect
        self.objects, self.edges, self.problems = {}, [], []
        self.probe_absent, self.observed_absent = probe_absent, set()
        self.cache = {}
        if 'etc/ld.so.cache' in records:
            self.cache = parse_cache(read('etc/ld.so.cache'))
        else:
            require('etc/ld.so.cache' in self.absent, 'unclosed_loader_cache')

    def resolve(self, path):
        return exporter.resolve_record(normalize(path), self.records)

    def directory(self, path):
        path = normalize(path)
        if path in self.absent:
            return None
        resolved = self.resolve(path)
        require(self.records[resolved]['type'] == 'directory', 'non_directory_search_path:' + path)
        return resolved

    def missing(self, path):
        closed = any(path.startswith(tree + '/') for tree in self.trees)
        require(closed or self.probe_absent is not None, 'unclosed_search_path:' + path)
        if not closed:
            self.probe_absent(path)
        self.observed_absent.add(path)

    def expand(self, value, path):
        # Both load-name and resolved origins are retained; no symlink-origin choice.
        origins = {str(PurePosixPath(path).parent), str(PurePosixPath(self.resolve(path)).parent)}
        values = set()
        for item in value.split(':'):
            require(item, 'empty_loader_search_component')
            for origin in origins:
                expanded = item.replace('${ORIGIN}', '/' + origin).replace('$ORIGIN', '/' + origin)
                require(expanded.startswith('/') and '$' not in expanded, 'unsupported_loader_token_or_relative_path')
                values.add(normalize(expanded))
        return sorted(values)

    def candidates(self, needed, path, search):
        if '/' in needed:
            values = self.expand(needed, path)
        else:
            require('$' not in needed and needed, 'invalid_needed')
            values = []
            for directory in search:
                resolved = self.directory(directory)
                if resolved is None:
                    continue
                candidate = resolved + '/' + needed
                if candidate in self.records:
                    values.append(candidate)
                else:
                    self.missing(candidate)
                # Include every pinned glibc-hwcaps variant, without selecting CPU ABI.
                prefix = resolved + '/glibc-hwcaps/'
                if prefix[:-1] not in self.records:
                    self.missing(prefix[:-1])
                else:
                    require(any(prefix[:-1] == tree or prefix.startswith(tree + '/') for tree in self.trees),
                            'unclosed_hwcaps_directory')
                values.extend(name for name in self.records
                              if name.startswith(prefix) and PurePosixPath(name).name == needed)
            values.extend(row['path'] for row in self.cache.get(needed, []))
        resolved = {}
        for value in values:
            target = self.resolve(value)
            require(self.records[target]['type'] == 'file', 'nonfile_loader_candidate')
            resolved.setdefault(target, set()).add(value)
        return {target: sorted(names) for target, names in sorted(resolved.items())}

    def run(self, roots):
        pending = collections.deque((path, ()) for path in roots)
        visited, sonames = set(), collections.defaultdict(set)
        while pending:
            path, inherited = pending.popleft()
            require(len(visited) < 100000, 'closure_limit')
            state = (path, inherited)
            if state in visited:
                continue
            visited.add(state)
            try:
                target = self.resolve(path)
                if target not in self.objects:
                    raw = self.read(target)
                    self.objects[target] = self.inspect(raw)
                item = self.objects[target]
                if item['soname']:
                    sonames[item['soname']].add(target)
                own_rpath = self.expand(item['rpath'], path) if item['rpath'] and not item['runpath'] else []
                runpath = self.expand(item['runpath'], path) if item['runpath'] else []
                # Conservative union retains every ancestor RPATH and every stage,
                # including fallback cache/default candidates. No load-order choice.
                child_rpath = tuple(sorted(set(inherited) | set(own_rpath)))
                search = sorted(set(child_rpath) | set(runpath) | set(self.loader['default_search_paths']))
                dependencies = [(name, self.candidates(name, path, search)) for name in item['needed']]
                if item['interpreter']:
                    require(item['interpreter'] == self.loader['interpreter'], 'unexpected_interpreter')
                    candidate = self.resolve(item['interpreter'])
                    dependencies.append((item['interpreter'], {candidate: [normalize(item['interpreter'])]}))
                for name, candidates in dependencies:
                    self.edges.append({'from': target, 'load_name': path, 'needed': name,
                                       'search_paths': search, 'candidates': candidates})
                    if not candidates:
                        self.problems.append({'kind': 'unresolved', 'from': target, 'needed': name})
                    if len(candidates) > 1:
                        self.problems.append({'kind': 'multiple_candidates', 'from': target,
                                              'needed': name, 'paths': sorted(candidates)})
                    for paths in candidates.values():
                        for candidate in paths:
                            pending.append((candidate, child_rpath))
            except (Refused, ValueError, OSError) as error:
                self.problems.append({'kind': 'unsupported_or_unclosed', 'path': path, 'reason': str(error)})
        for name, paths in sorted(sonames.items()):
            if len(paths) > 1:
                self.problems.append({'kind': 'soname_collision', 'soname': name, 'paths': sorted(paths)})
        self.edges.sort(key=canonical)
        self.problems.sort(key=canonical)
        return {'method': 'pinned-builder-readelf; recursive all-candidate glibc cache/RPATH/RUNPATH union',
                'resolution_model': 'all-candidates-overapproximation-no-ABI-or-load-order-choice',
                'roots': sorted(roots), 'files': sorted(self.objects), 'objects': self.objects,
                'edges': self.edges, 'cache_entries': self.cache, 'problems': self.problems,
                'observed_absent': sorted(self.observed_absent),
                'complete_without_conflicts': not self.problems}


def plan(rootfs, *, policy, policy_sha256, provenance, provenance_sha256,
         app_manifest, app_manifest_sha256, exporter_lock, exporter_lock_sha256,
         sources_dir, wheels_dir, readelf, readelf_sha256, _owner=(0, 0), _inspect=None):
    root = Path(rootfs)
    require(root.is_absolute() and root != Path('/') and root.parent != Path('/'), 'private_rootfs_required')
    exporter.checked_path(root)
    inputs = {'policy': policy, 'provenance': provenance, 'app_manifest': app_manifest,
              'exporter_lock': exporter_lock}
    pins = dict(policy=policy_sha256, provenance=provenance_sha256,
                app_manifest=app_manifest_sha256, exporter_lock=exporter_lock_sha256)
    for path in (*inputs.values(), sources_dir, wheels_dir, readelf):
        path = Path(path)
        require(path.is_absolute() and not path.is_relative_to(root), 'inputs_overlap_rootfs')
    policy_value = policy_schema(pinned(policy, policy_sha256))
    origin = pinned(provenance, provenance_sha256)
    require(type(origin) is dict and set(origin) == PROVENANCE | {'python_version'}
            and all(type(origin[key]) is str and HASH.fullmatch(origin[key]) for key in PROVENANCE),
            'invalid_provenance')
    exporter.configuration(origin['python_version'])
    lock = exporter.load_lock(Path(exporter_lock), expected_sha256=exporter_lock_sha256)
    require(all(lock[key] == origin[key] for key in PROVENANCE), 'provenance_mismatch')
    payload = exporter.expected_payload(lock, Path(sources_dir), Path(wheels_dir))
    # No support digest is invented. These are expected pre-install records only.
    virtual = exporter.expected_bundle(payload, origin['python_version'])
    virtual.pop('manifest.json')
    app = pinned(app_manifest, app_manifest_sha256)
    require(type(app) is dict and set(app) == {'schema_version', 'kind', 'studio_commit', 'records'}
            and app['schema_version'] == 1 and app['kind'] == 'factory-studio-bundle-manifest'
            and type(app['studio_commit']) is str and re.fullmatch('[0-9a-f]{40}', app['studio_commit']),
            'invalid_app_manifest')
    runtime.records_schema({path: dict(record, uid=0, gid=0) for path, record in app['records'].items()})
    app_tree = inventory.inventory(root / runtime.APP)
    expected_app = dict(app['records'])
    manifest_raw = exporter.ordinary(Path(app_manifest), MAX_BYTES)
    expected_app['manifest.json'] = exporter.file_record(manifest_raw)
    if _owner != (0, 0):
        expected_app['manifest.json'].update(uid=_owner[0], gid=_owner[1])
    require(app_tree == expected_app, 'app_inventory_mismatch')
    support, records = collect(root, policy_value, _owner)
    for path in policy_value['absent']:
        require(path not in records, 'present_and_absent')
        check_absent(root, path, records)
    for prefix, bundle in ((runtime.APP, app['records']), (exporter.DESTINATION, virtual)):
        for relative, record in bundle.items():
            path = prefix if relative == '.' else prefix + '/' + relative
            require(path not in records, 'bundle_support_collision')
            safe_record(record, (0, 0) if prefix == exporter.DESTINATION else _owner)
            records[path] = record
    for path in records:
        exporter.resolve_record(path, records)
    virtual_raw = {exporter.DESTINATION + '/' + exporter.SITE + '/' + path: raw
                   for path, raw in payload.items()}

    def read(path):
        if path in virtual_raw:
            return virtual_raw[path]
        return read_bytes(root, path, records[path])

    roots = set(policy_value['elf_roots'])
    for path, record in records.items():
        if record['type'] == 'file' and (path.startswith((runtime.APP + '/', exporter.DESTINATION + '/',
                                                       'usr/lib/python3.13/', 'usr/lib/python3/dist-packages/'))
                                        and re.search(r'\.so(?:\.|$)', PurePosixPath(path).name)):
            roots.add(path)
    roots.add('usr/bin/python3.13')
    roots.update(getattr(runtime, 'NATIVE_COMMANDS', ()))
    roots.add(normalize(policy_value['loader']['interpreter']))
    inspector = _inspect if _inspect is not None else Readelf(readelf, readelf_sha256)
    closed_trees = set(policy_value['trees']) | {runtime.APP, exporter.DESTINATION}
    closure = Closure(records, closed_trees, policy_value['absent'], policy_value['loader'], read, inspector,
                      lambda path: check_absent(root, path, records))
    observation = closure.run(sorted(roots))
    # Verify non-mutation/drift over the complete input snapshots after inspection.
    require(collect(root, policy_value, _owner)[0] == support
            and inventory.inventory(root / runtime.APP) == app_tree, 'input_changed')
    require(exporter.expected_payload(lock, Path(sources_dir), Path(wheels_dir)) == payload, 'input_changed')
    for path in closure.observed_absent:
        if not any(path.startswith(tree + '/') for tree in closed_trees):
            check_absent(root, path, records)
    for key, path in inputs.items():
        pinned(path, pins[key])
    extra_absent = {path for path in closure.observed_absent
                    if not any(path.startswith(tree + '/') for tree in closed_trees)}
    candidate = {'schema_version': 1, 'kind': 'factory-exporter-system-support',
                 **origin, **support, 'absent': sorted(set(policy_value['absent']) | extra_absent)}
    return {'schema_version': 1, 'kind': 'factory-system-support-proposal',
            'status': 'proposal-requires-independent-review', 'input_sha256': pins,
            'studio_commits': {'app': app['studio_commit'], 'exporter': lock['studio_commit']},
            'readelf_sha256': readelf_sha256, 'support_candidate': candidate,
            'elf_observations': observation, 'independent_review_required': True,
            'image_code_executed': False, 'installed': False, 'abi_qualified': False,
            'hardware_qualified': False, 'runtime_activation_qualified': False,
            'limitations': ['No independent review or elf_closure_review is generated.',
                            'All loader candidates are inventoried; no runtime library choice or symbol ABI is certified.',
                            'Declared glibc profile assumes no LD_* override, preload or audit mechanism.',
                            'dlopen/import configuration, CPU instructions, devices and boot require separate qualification.']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, required=True)
    for field in ('policy', 'provenance', 'app-manifest', 'exporter-lock', 'readelf'):
        parser.add_argument('--' + field, type=Path, required=True)
        parser.add_argument('--' + field + '-sha256', required=True)
    for field in ('sources-dir', 'wheels-dir', 'output'):
        parser.add_argument('--' + field, type=Path, required=True)
    args = vars(parser.parse_args(argv))
    output = args.pop('output')
    try:
        exporter.checked_path(output, missing=True)
        require(not os.path.lexists(output) and not output.is_relative_to(args['rootfs'])
                and not any(output.is_relative_to(args[key]) for key in ('sources_dir', 'wheels_dir'))
                and all(output != Path(value) for key, value in args.items() if not key.endswith('sha256')),
                'output_exists_or_overlaps')
        result = plan(**args)
        with output.open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(canonical(result)); stream.flush(); os.fsync(stream.fileno())
        return 0 if result['elf_observations']['complete_without_conflicts'] else 2
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError) as error:
        print('factory_system_support_plan_refused:' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
