#!/usr/bin/env python3
"""Copy and read back an inactive factory assembly; never execute target code.

This is a private file-only profile, not an installed graph, first boot or release.
Exclusive failures are retained. No repair, rollback or retry is performed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def module(filename):
    spec = importlib.util.spec_from_file_location('_assembly_' + filename.replace('-', '_'),
                                                ROOT / 'scripts' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


passive = module('factory-passive-profile.py')
writer = module('verify-factory-writer-rootfs.py')
planner = writer.guards.planner
canonical, write_new = passive.canonical, passive.write_new
SOURCE_FILES = tuple(sorted(writer.SOURCE_MAP))
TOOL_FILES = tuple(sorted(set(SOURCE_FILES) | {
    'scripts/factory-assembly-profile.py', 'scripts/factory-passive-profile.py',
    'scripts/install-factory-writer-rootfs.py', 'scripts/verify-factory-writer-rootfs.py',
    'scripts/install-factory-studio-bundle-rootfs.py', 'scripts/plan-factory-studio-bundle.py',
    'scripts/verify-factory-exporter-rootfs.py', 'scripts/manifest-rootfs.py',
    'scripts/install-application-rootfs.py', 'scripts/inspect-application-archives.py',
    'scripts/verify-application.py',
}))
QUALIFICATIONS = frozenset({'abi', 'boot', 'hardware', 'image', 'installed_graph',
                            'release', 'runtime', 'support'})
FIELDS = {'schema_version', 'kind', 'studio_commit', 'os_commit', 'input_manifest_sha256',
          'bundle_manifest_sha256', 'writer_input_manifest_sha256', 'startup', 'qualification'}
INPUT_REPORTS = ('factory-assembly.json', 'factory-studio-inputs.json',
                 'factory-bundle-manifest.json', 'factory-writer-inputs.json')
OUTPUT_REPORTS = ('factory-studio-installation.json', 'factory-studio-verification.json',
                  'factory-writer-installation.json', 'factory-writer-verification.json')
SNAPSHOT_NAMES = ('factory-assembly.json', 'inputs.json', 'factory-bundle-manifest.json',
                  'writer-inputs.json')


def validate_metadata(value):
    if (type(value) is not dict or set(value) != FIELDS
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['kind'] != 'factory-assembly-profile'
            or value['studio_commit'] != writer.STUDIO_COMMIT
            or type(value['os_commit']) is not str or re.fullmatch('[0-9a-f]{40}', value['os_commit']) is None
            or any(type(value[key]) is not str or writer.HASH.fullmatch(value[key]) is None
                   for key in ('input_manifest_sha256', 'bundle_manifest_sha256', 'writer_input_manifest_sha256'))
            or value['startup'] != 'inactive'
            or type(value['qualification']) is not dict or set(value['qualification']) != QUALIFICATIONS
            or any(flag is not False for flag in value['qualification'].values())):
        raise ValueError('Invalid inactive factory assembly profile')
    return value


def validate_writer_inputs(raw, pin, bundle, *, recipe_root=ROOT, recipe_pins=None):
    """Bind the external seven-field manifest to this frozen R35 recipe."""
    value = planner.exporter.strict_json(raw)
    if (type(pin) is not str or writer.HASH.fullmatch(pin) is None
            or hashlib.sha256(raw).hexdigest() != pin
            or type(value) is not dict or set(value) != writer.INPUT_FIELDS or raw != canonical(value)
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['kind'] != 'factory-writer-file-inputs'
            or type(value['os_commit']) is not str or re.fullmatch('[0-9a-f]{40}', value['os_commit']) is None
            or value['studio_commit'] != writer.STUDIO_COMMIT
            or type(value['os_source_sha256']) is not dict or set(value['os_source_sha256']) != set(SOURCE_FILES)
            or any(type(digest) is not str or writer.HASH.fullmatch(digest) is None
                   for digest in value['os_source_sha256'].values())
            or value['studio_bundle_manifest_sha256'] != hashlib.sha256(bundle).hexdigest()
            or type(value['helper_source_sha256']) is not str or writer.HASH.fullmatch(value['helper_source_sha256']) is None):
        raise ValueError('Writer inputs differ from reviewed assembly pins')
    expected = planner.exporter.strict_json(bundle)
    helper = expected.get('records', {}).get(writer.HELPER_SOURCE)
    if (type(helper) is not dict or helper.get('sha256') != value['helper_source_sha256']
            or helper.get('mode') != '0555' or helper.get('uid') != 0 or helper.get('gid') != 0):
        raise ValueError('Writer helper is not bound to the installed bundle')
    # Commit is caller-declared correlation only; the reviewed byte hashes are
    # authoritative. In particular the old fixture38 graph/launcher cannot pass.
    for name, digest in value['os_source_sha256'].items():
        actual = (recipe_pins.get(name) if recipe_pins is not None else
                  hashlib.sha256(planner.exporter.ordinary(Path(recipe_root) / name, writer.LIMIT)).hexdigest())
        if actual != digest:
            raise ValueError('Writer source pin differs from frozen R35 recipe')
    return value


def checked_inputs(input_manifest, input_sha256, sources_dir, wheels_dir,
                   bundle_manifest, writer_manifest, writer_sha256, writer_sources):
    paths = [Path(path).absolute() for path in
             (input_manifest, sources_dir, wheels_dir, bundle_manifest, writer_manifest, writer_sources)]
    inputs, sources, wheels, expected, writer_input, os_sources = paths
    value = planner.load_inputs(inputs, input_sha256)
    if value['studio_commit'] != writer.STUDIO_COMMIT:
        raise ValueError('Assembly requires Studio R35')
    passive.transfer_bound(planner, value, sources, wheels)
    bundle, receipt = planner.plan(inputs, input_sha256, sources, wheels)
    raw_bundle = planner.exporter.ordinary(expected, writer.guards.MAX_MANIFEST)
    if raw_bundle != bundle:
        raise ValueError('External expected bundle differs from the pinned plan')
    raw_writer = planner.exporter.ordinary(writer_input, writer.LIMIT)
    writer_value = validate_writer_inputs(raw_writer, writer_sha256, bundle)
    planner.exact_inputs(os_sources, writer_value['os_source_sha256'])
    payload = {}
    for name, pin in writer_value['os_source_sha256'].items():
        raw = planner.exporter.ordinary(os_sources / name, writer.LIMIT)
        if hashlib.sha256(raw).hexdigest() != pin:
            raise ValueError('Writer source snapshot pin mismatch')
        payload[name] = raw
    profile = validate_metadata({'schema_version': 1, 'kind': 'factory-assembly-profile',
        'studio_commit': writer.STUDIO_COMMIT, 'os_commit': writer_value['os_commit'],
        'input_manifest_sha256': input_sha256, 'bundle_manifest_sha256': receipt['bundle_manifest_sha256'],
        'writer_input_manifest_sha256': writer_sha256, 'startup': 'inactive',
        'qualification': dict.fromkeys(sorted(QUALIFICATIONS), False)})
    return profile, value, bundle, raw_writer, payload


def stage(input_manifest, input_sha256, sources_dir, wheels_dir, bundle_manifest,
          writer_manifest, writer_sha256, writer_sources, output):
    paths = [Path(path).absolute() for path in
             (input_manifest, sources_dir, wheels_dir, bundle_manifest, writer_manifest, writer_sources)]
    output = Path(output).absolute()
    if any(output == path or output.is_relative_to(path) or path.is_relative_to(output) for path in paths):
        raise ValueError('Assembly input/output overlap')
    profile, value, bundle, raw_writer, payload = checked_inputs(
        input_manifest, input_sha256, sources_dir, wheels_dir, bundle_manifest,
        writer_manifest, writer_sha256, writer_sources)
    # All metadata and pins pass before the first exclusive output creation.
    output.mkdir(mode=0o700)
    for leaf in ('sources', 'wheels', 'writer-sources'):
        (output / leaf).mkdir(mode=0o700)
    for base, leaf, field in ((Path(sources_dir), 'sources', 'source_sha256'),
                              (Path(wheels_dir), 'wheels', 'wheel_sha256')):
        for name, pin in sorted(value[field].items()):
            raw = planner.exporter.ordinary(base / name)
            if hashlib.sha256(raw).hexdigest() != pin:
                raise ValueError('Assembly snapshot pin changed')
            target = output / leaf / name
            target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            write_new(target, raw)
    for name, raw in sorted(payload.items()):
        target = output / 'writer-sources' / name
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        write_new(target, raw)
    for name, raw in (('inputs.json', planner.exporter.ordinary(Path(input_manifest), writer.LIMIT)),
                      ('factory-bundle-manifest.json', bundle), ('writer-inputs.json', raw_writer),
                      ('factory-assembly.json', canonical(profile))):
        write_new(output / name, raw)
    if read_inputs(output) != profile:
        raise ValueError('Assembly input readback changed')
    return profile


def read_inputs(inputs):
    inputs = Path(inputs)
    raw = planner.exporter.ordinary(inputs / 'factory-assembly.json', 4096)
    profile = validate_metadata(planner.exporter.strict_json(raw))
    if raw != canonical(profile):
        raise ValueError('Noncanonical assembly profile')
    checked = checked_inputs(inputs / 'inputs.json', profile['input_manifest_sha256'],
        inputs / 'sources', inputs / 'wheels', inputs / 'factory-bundle-manifest.json',
        inputs / 'writer-inputs.json', profile['writer_input_manifest_sha256'], inputs / 'writer-sources')[0]
    if checked != profile:
        raise ValueError('Assembly profile/input mismatch')
    return profile


def verify_inputs(work):
    return read_inputs(Path(work) / 'factory-inputs')


def prepare_rootfs(work):
    work = Path(work)
    profile = verify_inputs(work)
    inputs = work / 'factory-inputs'
    if any(os.path.lexists(work / name) for name in OUTPUT_REPORTS):
        raise ValueError('Assembly receipt already exists; use a new workspace')
    # Reuse the production closed state/unit/destination guards before bundle
    # creation too. No installed-helper read is attempted at this point.
    environment = writer.Environment(work / 'root', inputs / 'writer-inputs.json',
        inputs / 'writer-sources', inputs / 'factory-bundle-manifest.json', work / OUTPUT_REPORTS[2])
    names = {destination: None for destination, _ in writer.SOURCE_MAP.values()}
    names[writer.HELPER] = None
    try:
        writer._preflight(environment, names, installing=True)
        installer = module('install-factory-studio-bundle-rootfs.py')
        installer.install_bundle(work / 'root', inputs / 'inputs.json', profile['input_manifest_sha256'],
            inputs / 'sources', inputs / 'wheels', receipt_output=work / OUTPUT_REPORTS[0])
        receipt = installer.verify_bundle(work / 'root', inputs / 'inputs.json', profile['input_manifest_sha256'],
            inputs / 'sources', inputs / 'wheels')
        write_new(work / OUTPUT_REPORTS[1], canonical(receipt))
        writer._preflight(environment, names, installing=True)
        writer_install = module('install-factory-writer-rootfs.py')
        writer_install.install_writer(work / 'root', inputs / 'writer-inputs.json',
            profile['writer_input_manifest_sha256'], inputs / 'writer-sources',
            inputs / 'factory-bundle-manifest.json', receipt_output=work / OUTPUT_REPORTS[2])
        receipt = writer.verify_writer(work / 'root', inputs / 'writer-inputs.json',
            profile['writer_input_manifest_sha256'], inputs / 'writer-sources', inputs / 'factory-bundle-manifest.json')
        write_new(work / OUTPUT_REPORTS[3], canonical(receipt))
        environment.check()
        if verify_inputs(work) != profile:
            raise ValueError('Assembly inputs changed during materialization')
    finally:
        environment.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('check-inputs', 'verify-inputs', 'prepare-rootfs'))
    parser.add_argument('--work', type=Path)
    for field in ('studio-input-manifest', 'studio-input-sha256', 'studio-sources-dir',
                  'studio-wheels-dir', 'studio-bundle-manifest', 'writer-input-manifest',
                  'writer-input-sha256', 'writer-sources-dir'):
        parser.add_argument('--' + field)
    args = parser.parse_args(argv)
    if args.operation == 'check-inputs':
        fields = ('studio_input_manifest', 'studio_input_sha256', 'studio_sources_dir', 'studio_wheels_dir',
                  'studio_bundle_manifest', 'writer_input_manifest', 'writer_input_sha256', 'writer_sources_dir')
        if args.work is not None or any(not getattr(args, field) for field in fields):
            parser.error('check-inputs requires exactly eight assembly inputs')
        checked_inputs(*(getattr(args, field) for field in fields))
    else:
        if args.work is None or any(getattr(args, field) is not None for field in
                ('studio_input_manifest', 'studio_input_sha256', 'studio_sources_dir', 'studio_wheels_dir',
                 'studio_bundle_manifest', 'writer_input_manifest', 'writer_input_sha256', 'writer_sources_dir')):
            parser.error('workspace operation requires only --work')
        passive.guard_work(args.work)
        (verify_inputs if args.operation == 'verify-inputs' else prepare_rootfs)(args.work)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
