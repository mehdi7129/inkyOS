#!/usr/bin/env python3
"""Check a pinned Studio runtime dependency closure; never import candidate code.

Invoke with Python -I -B -S. The only third-party code executed is the pinned
build-tooling wheel, copied privately before import. No install or resolver runs.
"""
import argparse
from collections import deque
from contextlib import contextmanager
from email import policy
from email.parser import BytesParser
import importlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import zipfile
import zipimport
import zlib

ROOT = Path(__file__).resolve().parents[1]
TOOL_SHA = 'd7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c'
TOOL_SIZE = 129956
TOOL_FILE = 'vendor/build-tooling/packaging-26.3-py3-none-any.whl'
TOOL_LOCK = 'config/factory-studio-dependency-tooling.lock.json'
TOOL_URL = 'https://files.pythonhosted.org/packages/63/34/ba1c580383c9eada3711951fef0795c80b829a078d72188184bcab9dd527/packaging-26.3-py3-none-any.whl'
TARGET = {'architecture': 'arm64', 'python_version': '3.13.5', 'debian_release': 'trixie'}
TARGET_ENV = {
    'implementation_name': 'cpython', 'implementation_version': '3.13.5',
    'os_name': 'posix', 'platform_machine': 'aarch64',
    'platform_python_implementation': 'CPython', 'platform_release': '',
    'platform_system': 'Linux', 'platform_version': '', 'python_full_version': '3.13.5',
    'python_version': '3.13', 'sys_platform': 'linux',
}
# Empty kernel fields are placeholders, never values a candidate may query.
ALLOWED_MARKERS = (set(TARGET_ENV) - {'platform_release', 'platform_version'}) | {'extra'}
MAX_METADATA = 1024 * 1024
MAX_REQUIREMENTS = 1024
MAX_EXTRAS = 128

_spec = importlib.util.spec_from_file_location(
    '_factory_dependency_planner', Path(__file__).with_name('plan-factory-studio-bundle.py'))
planner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(planner)


class Refused(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def canonical(value):
    return planner.canonical(value)


@contextmanager
def tooling():
    """Import only the pinned packaging snapshot; never add a candidate to sys.path.

    Single-threaded CLI scope: ambient packaging is refused, not replaced. The
    package namespace and private zip caches are removed before deleting its copy.
    """
    require(not any(key == 'packaging' or key.startswith('packaging.') for key in sys.modules),
            'ambient_packaging')
    lock = planner.exporter.strict_json(planner.exporter.ordinary(ROOT / TOOL_LOCK, 16384))
    require(type(lock) is dict and set(lock) == {'schema_version', 'kind', 'name', 'version',
            'wheel', 'size_bytes', 'sha256', 'source_url', 'licenses'}, 'invalid_tooling')
    require(type(lock['schema_version']) is int and lock['schema_version'] == 1
            and lock['kind'] == 'factory-studio-dependency-tooling' and lock['name'] == 'packaging'
            and lock['version'] == '26.3' and lock['wheel'] == TOOL_FILE
            and type(lock['size_bytes']) is int and lock['size_bytes'] == TOOL_SIZE
            and lock['sha256'] == TOOL_SHA and lock['source_url'] == TOOL_URL, 'invalid_tooling')
    raw = planner.exporter.ordinary(ROOT / TOOL_FILE, TOOL_SIZE)
    require(len(raw) == TOOL_SIZE and planner.exporter.sha(raw) == TOOL_SHA, 'invalid_tooling')
    licenses = lock['licenses']
    expected_licenses = {'packaging-26.3.dist-info/licenses/' + name
                         for name in ('LICENSE', 'LICENSE.APACHE', 'LICENSE.BSD')}
    require(type(licenses) is dict and set(licenses) == expected_licenses, 'invalid_tooling')
    # Exact whole-wheel SHA is authoritative; the notices remain independently
    # reviewable in the lock and repository. No generic tooling wheel is accepted.
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for path, digest in licenses.items():
            require(type(digest) is str and planner.exporter.sha(archive.read(path)) == digest,
                    'invalid_tooling')
    with tempfile.TemporaryDirectory(prefix='inkyos-dependency-tooling-',
            dir=Path(tempfile.gettempdir()).resolve()) as temporary:
        directory = Path(temporary)
        require(stat.S_IMODE(directory.stat().st_mode) == 0o700, 'invalid_tooling')
        snapshot = directory / 'packaging.whl'
        fd = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(raw); stream.flush()
            os.fchmod(fd, 0o400); os.fsync(fd)
        finally:
            os.close(fd)
        require(planner.exporter.ordinary(snapshot, TOOL_SIZE) == raw, 'invalid_tooling')
        try:
            finder = zipimport.zipimporter(str(snapshot))
            spec = finder.find_spec('packaging')
            require(spec is not None and spec.loader is finder, 'invalid_tooling')
            package = importlib.util.module_from_spec(spec)
            sys.modules['packaging'] = package
            spec.loader.exec_module(package)
            modules = {name: importlib.import_module('packaging.' + name)
                       for name in ('requirements', 'specifiers', 'version', 'utils', 'markers', '_parser')}
            require(package.__version__ == '26.3', 'invalid_tooling')
            for key, module in tuple(sys.modules.items()):
                if key == 'packaging' or key.startswith('packaging.'):
                    require(str(getattr(module, '__file__', '')).startswith(str(snapshot) + '/packaging/'),
                            'ambient_packaging')
            yield modules
        finally:
            for key in tuple(sys.modules):
                if key == 'packaging' or key.startswith('packaging.'):
                    del sys.modules[key]
            for key in tuple(sys.path_importer_cache):
                if key == str(snapshot) or key.startswith(str(snapshot) + '/'):
                    del sys.path_importer_cache[key]
            zipimport._zip_directory_cache.pop(str(snapshot), None)


def headers(raw):
    require(len(raw) <= MAX_METADATA, 'metadata_limit')
    raw.decode('utf-8')
    message = BytesParser(policy=policy.default).parsebytes(raw)
    require(not message.defects, 'invalid_metadata')
    return message


def one(message, key, required=True):
    values = message.get_all(key, [])
    require(len(values) == 1 if required else len(values) <= 1, 'duplicate_or_missing_header')
    if not values:
        return None
    value = str(values[0]).strip()
    require(bool(value) and '\x00' not in value, 'invalid_metadata')
    return value


def marker_tree(tree, api, *, depth=0, budget=None):
    """Check actual Variable nodes, including both sides and nested expressions.

    Private packaging AST/evaluator APIs are tied to TOOL_SHA. No lexical marker
    rewriting or host default_environment call participates in this contract.
    """
    budget = [0] if budget is None else budget
    budget[0] += 1
    require(depth <= 32 and budget[0] <= 1024, 'marker_limit')
    if isinstance(tree, list):
        for node in tree:
            marker_tree(node, api, depth=depth + 1, budget=budget)
    elif isinstance(tree, tuple):
        require(len(tree) == 3, 'invalid_marker')
        left, _, right = tree
        variable = api['_parser'].Variable
        value = api['_parser'].Value
        require((isinstance(left, variable) and isinstance(right, value)) or
                (isinstance(left, value) and isinstance(right, variable)), 'invalid_marker')
        for node in (left, right):
            if isinstance(node, variable):
                require(node.value in ALLOWED_MARKERS, 'unknown_marker_variable')
    else:
        require(tree in ('and', 'or'), 'invalid_marker')


def requirements(values, api):
    require(len(values) <= MAX_REQUIREMENTS, 'requirement_limit')
    result, seen = [], set()
    for raw in values:
        require(type(raw) is str and 0 < len(raw) <= 8192, 'invalid_requirement')
        item = api['requirements'].Requirement(raw)
        require(item.url is None, 'url_dependency')
        extras = {api['utils'].canonicalize_name(extra, validate=True) for extra in item.extras}
        require(len(extras) <= MAX_EXTRAS and len(extras) == len(item.extras), 'invalid_extra')
        if item.marker is not None:
            marker_tree(item.marker._markers, api)
        identity = (api['utils'].canonicalize_name(item.name, validate=True), tuple(sorted(extras)),
                    str(item.specifier), str(item.marker))
        require(identity not in seen, 'duplicate_requirement'); seen.add(identity)
        result.append((item, identity[0], extras))
    return result


def load_metadata(raw, filename, api):
    # Same Studio adapter as planner/materializer: tags, paths, ELF header,
    # hooks, collisions and every RECORD hash are checked there, not reimplemented.
    payload = planner.wheel_payload(raw, filename)
    name, version, _, _ = api['utils'].parse_wheel_filename(filename)
    metadata_paths = [path for path in payload if path.endswith('.dist-info/METADATA')]
    require(len(metadata_paths) == 1, 'invalid_metadata')
    message = headers(payload[metadata_paths[0]])
    require(re.fullmatch(r'[12]\.[0-9]+', one(message, 'Metadata-Version')), 'invalid_metadata')
    require(api['utils'].canonicalize_name(one(message, 'Name'), validate=True) == name
            and api['version'].Version(one(message, 'Version')) == version, 'metadata_identity')
    python = one(message, 'Requires-Python', required=False)
    if python is not None:
        require(api['specifiers'].SpecifierSet(python).contains('3.13.5'), 'requires_python')
    dynamic = {str(value).strip().lower() for value in message.get_all('Dynamic', [])}
    require(not dynamic & {'name', 'version', 'requires-python', 'requires-dist', 'provides-extra'},
            'dynamic_metadata')
    extras, declared = set(), message.get_all('Provides-Extra', [])
    require(len(declared) <= MAX_EXTRAS, 'extra_limit')
    for value in declared:
        extra = api['utils'].canonicalize_name(str(value).strip(), validate=True)
        require(extra not in extras, 'duplicate_extra'); extras.add(extra)
    dependencies = requirements([str(value) for value in message.get_all('Requires-Dist', [])], api)
    return {'name': str(name), 'version': version, 'extras': extras, 'requirements': dependencies}


def active(requirement, extras, api):
    if requirement.marker is None:
        return True
    # Exactly eleven fixed target variables plus the per-edge scalar extra.
    return any(api['markers']._evaluate_markers(requirement.marker._markers,
               {**TARGET_ENV, 'extra': extra}) for extra in ('', *sorted(extras)))


def closure(wheels, root, api):
    require('pi' in wheels[root]['extras'], 'missing_root_extra')
    activated = {root: {'pi'}}
    queue, queued = deque([root]), {root}
    steps = 0
    while queue:
        parent = queue.popleft(); queued.remove(parent)
        contexts = activated[parent].copy()
        steps += 1
        require(steps <= 128 * (MAX_EXTRAS + 1), 'closure_limit')
        for requirement, name, requested in wheels[parent]['requirements']:
            if not active(requirement, contexts, api):
                continue
            require(name in wheels, 'missing_dependency')
            wheel = wheels[name]
            # Root rc does not opt transitive edges into prereleases. Each active
            # edge must explicitly permit a pre/dev release on its own terms.
            version = wheel['version']
            require(not (version.is_prerelease or version.is_devrelease)
                    or requirement.specifier.prereleases is True, 'transitive_prerelease')
            require(requirement.specifier.contains(version), 'dependency_version')
            require(requested <= wheel['extras'], 'unknown_extra')
            if name not in activated or requested - activated[name]:
                activated.setdefault(name, set()).update(requested)
                if name not in queued:
                    queue.append(name); queued.add(name)
    require(set(activated) == set(wheels), 'extra_wheels')
    return activated


def verify(input_manifest, input_sha256, sources_dir, wheels_dir):
    try:
        inputs, sources, wheels_path = (Path(value).absolute() for value in
                                       (input_manifest, sources_dir, wheels_dir))
        require(not sources.is_relative_to(wheels_path) and not wheels_path.is_relative_to(sources)
                and not inputs.is_relative_to(sources) and not inputs.is_relative_to(wheels_path), 'input_overlap')
        value = planner.load_inputs(inputs, input_sha256)
        require(value['python_version'] == '3.13.5', 'wrong_python_target')
        # Reuse the complete static input preflight, including sources, app
        # namespace ownership and cross-wheel file/directory collisions.
        planner.derive(value, sources, wheels_path)
        with tooling() as api:
            wheels, root = {}, None
            for filename, digest in sorted(value['wheel_sha256'].items()):
                raw = planner.exporter.ordinary(wheels_path / filename)
                require(planner.exporter.sha(raw) == digest, 'pin_mismatch')
                wheel = load_metadata(raw, filename, api)
                require(wheel['name'] not in wheels, 'duplicate_distribution')
                wheels[wheel['name']] = wheel
                if filename == value['app_wheel']:
                    root = wheel['name']
            require(root is not None, 'missing_app')
            activated = closure(wheels, root, api)
        planner.exact_inputs(sources, value['source_sha256'])
        planner.exact_inputs(wheels_path, value['wheel_sha256'])
        for name, digest in value['source_sha256'].items():
            require(planner.exporter.sha(planner.exporter.ordinary(sources / name)) == digest, 'pin_mismatch')
        require(planner.load_inputs(inputs, input_sha256) == value, 'pin_mismatch')
        return {'schema_version': 1, 'scope': 'factory-studio-dependency-metadata-only',
                'input_manifest_sha256': input_sha256, 'studio_commit': value['studio_commit'],
                'target': TARGET, 'root_distribution': root, 'root_extras': ['pi'],
                'reached_distributions': sorted(activated),
                'activated_extras': {name: sorted(extras) for name, extras in sorted(activated.items())},
                'wheel_count': len(wheels), 'tooling_sha256': TOOL_SHA,
                'candidate_code_executed': False, 'application_candidate_qualified': False}
    except Refused:
        raise
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError,
            ImportError, EOFError, NotImplementedError, zipfile.BadZipFile, zlib.error):
        raise Refused('invalid_inputs') from None


def publish(input_manifest, input_sha256, sources_dir, wheels_dir, *, receipt_output):
    try:
        target = Path(receipt_output).absolute()
        planner.exporter.checked_path(target, missing=True)
        require(not os.path.lexists(target) and target != Path(input_manifest).absolute()
                and not any(target.is_relative_to(Path(root).absolute()) for root in (sources_dir, wheels_dir)),
                'output_exists_or_overlaps')
        receipt = verify(input_manifest, input_sha256, sources_dir, wheels_dir)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(canonical(receipt)); stream.flush(); os.fsync(fd)
        finally:
            os.close(fd)
        return receipt
    except Refused:
        raise
    except (OSError, ValueError, TypeError):
        raise Refused('publication_failed') from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-sha256', required=True)
    for field in ('input-manifest', 'sources-dir', 'wheels-dir', 'receipt'):
        parser.add_argument('--' + field, type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
                'isolated_python_required')
        publish(args.input_manifest, args.input_sha256, args.sources_dir, args.wheels_dir,
                receipt_output=args.receipt)
    except Refused as error:
        print('factory_studio_dependencies_refused:' + error.reason, file=sys.stderr)
        return 1
    print('Pinned runtime dependency metadata verified; no candidate imported or qualified.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
