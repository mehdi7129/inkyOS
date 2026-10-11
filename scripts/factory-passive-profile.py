#!/usr/bin/env python3
"""Stage and inspect an inactive factory image profile, without target execution.

Only pinned ordinary Studio inputs are copied. Failed exclusive outputs remain
for inspection; this module never repairs, deploys or qualifies an image.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import stat

ROOT = Path(__file__).resolve().parents[1]
FIELDS = {'schema_version', 'kind', 'studio_commit', 'input_manifest_sha256',
          'bundle_manifest_sha256', 'startup', 'runtime_qualified', 'hardware_qualified'}
MAX_TRANSFER_BYTES = 128 * 1024 * 1024
TOOL_FILES = (
    'scripts/factory-passive-profile.py', 'scripts/configure-factory-rootfs.py',
    'scripts/verify-factory-rootfs.py', 'scripts/factory-authority.py',
    'scripts/factory-credentials-publisher.py', 'scripts/initialization-receipt.py',
    'scripts/initialization-server.py', 'scripts/verify-factory-studio-dependencies.py',
    'scripts/plan-factory-studio-bundle.py', 'scripts/install-factory-studio-bundle-rootfs.py',
    # Planner imports these helpers for inert parsing and inventory only.
    'scripts/verify-factory-exporter-rootfs.py', 'scripts/install-application-rootfs.py',
    'scripts/inspect-application-archives.py', 'scripts/verify-application.py',
    'config/factory-studio-dependency-tooling.lock.json',
    'vendor/build-tooling/packaging-26.3-py3-none-any.whl',
)


def module(filename):
    spec = importlib.util.spec_from_file_location('_passive_' + filename.replace('-', '_'),
                                                ROOT / 'scripts' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def validate_metadata(value):
    if (type(value) is not dict or set(value) != FIELDS
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['kind'] != 'factory-passive-profile'
            or not isinstance(value['studio_commit'], str)
            or re.fullmatch('[0-9a-f]{40}', value['studio_commit']) is None
            or any(not isinstance(value[key], str) or re.fullmatch('[0-9a-f]{64}', value[key]) is None
                   for key in ('input_manifest_sha256', 'bundle_manifest_sha256'))
            or value['startup'] != 'masked'
            or value['runtime_qualified'] is not False or value['hardware_qualified'] is not False):
        raise ValueError('Invalid inactive factory profile')
    return value


def metadata(input_sha256, receipt):
    return validate_metadata({'schema_version': 1, 'kind': 'factory-passive-profile',
                             'studio_commit': receipt['studio_commit'],
                             'input_manifest_sha256': input_sha256,
                             'bundle_manifest_sha256': receipt['bundle_manifest_sha256'],
                             'startup': 'masked', 'runtime_qualified': False, 'hardware_qualified': False})


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), mode)


def transfer_bound(planner, value, sources, wheels):
    total = 0
    for base, field in ((sources, 'source_sha256'), (wheels, 'wheel_sha256')):
        for name in value[field]:
            path = base / name
            planner.exporter.checked_path(path)
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 64 * 1024 * 1024:
                raise ValueError('Invalid bounded staging input')
            total += info.st_size
            if total > MAX_TRANSFER_BYTES:
                raise ValueError('Aggregate Studio staging limit exceeded')


def stage(input_manifest, input_sha256, sources_dir, wheels_dir, output):
    """Verify the metadata closure before producing a bounded input snapshot."""
    planner = module('plan-factory-studio-bundle.py')
    dependencies = module('verify-factory-studio-dependencies.py')
    paths = [Path(path).absolute() for path in (input_manifest, sources_dir, wheels_dir)]
    output = Path(output).absolute()
    if any(output == path or output.is_relative_to(path) or path.is_relative_to(output) for path in paths):
        raise ValueError('Input/output overlap')
    value = planner.load_inputs(paths[0], input_sha256)
    transfer_bound(planner, value, paths[1], paths[2])
    dependencies.verify(paths[0], input_sha256, paths[1], paths[2])
    output.mkdir(mode=0o700)
    sources, wheels = output / 'sources', output / 'wheels'
    sources.mkdir(mode=0o700); wheels.mkdir(mode=0o700)
    for base, destination, field in ((paths[1], sources, 'source_sha256'), (paths[2], wheels, 'wheel_sha256')):
        for name, pin in sorted(value[field].items()):
            raw = planner.exporter.ordinary(base / name)
            if hashlib.sha256(raw).hexdigest() != pin:
                raise ValueError('Snapshot pin mismatch')
            target = destination / name
            target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            write_new(target, raw)
    write_new(output / 'inputs.json', planner.exporter.ordinary(paths[0], 1024 * 1024))
    deps = dependencies.verify(output / 'inputs.json', input_sha256, sources, wheels)
    bundle, receipt = planner.plan(output / 'inputs.json', input_sha256, sources, wheels)
    profile = metadata(input_sha256, receipt)
    for name, raw in (('factory-dependencies.json', canonical(deps)),
                      ('factory-studio-plan.json', canonical(receipt)),
                      ('factory-bundle-manifest.json', bundle),
                      ('factory-passive.json', canonical(profile))):
        write_new(output / name, raw)
    return profile


def verify_inputs(work):
    """Read back the complete staged closure before any rootfs write."""
    work = Path(work)
    inputs = work / 'factory-inputs'
    planner = module('plan-factory-studio-bundle.py')
    dependencies = module('verify-factory-studio-dependencies.py')
    raw = planner.exporter.ordinary(inputs / 'factory-passive.json', 4096)
    profile = validate_metadata(planner.exporter.strict_json(raw))
    if raw != canonical(profile):
        raise ValueError('Noncanonical factory profile')
    pin = profile['input_manifest_sha256']
    value = planner.load_inputs(inputs / 'inputs.json', pin)
    transfer_bound(planner, value, inputs / 'sources', inputs / 'wheels')
    deps = dependencies.verify(inputs / 'inputs.json', pin, inputs / 'sources', inputs / 'wheels')
    bundle, receipt = planner.plan(inputs / 'inputs.json', pin, inputs / 'sources', inputs / 'wheels')
    if metadata(pin, receipt) != profile:
        raise ValueError('Factory profile/plan mismatch')
    for name, expected in (('factory-dependencies.json', canonical(deps)),
                           ('factory-studio-plan.json', canonical(receipt)),
                           ('factory-bundle-manifest.json', bundle)):
        if planner.exporter.ordinary(inputs / name, 32 * 1024 * 1024) != expected:
            raise ValueError('Staged factory receipt mismatch')
    return profile


def prepare_rootfs(work):
    work = Path(work)
    profile = verify_inputs(work)
    layout = module('configure-factory-rootfs.py')
    installer = module('install-factory-studio-bundle-rootfs.py')
    inputs = work / 'factory-inputs'
    layout.configure(work / 'root', work / 'recipe')
    installer.install_bundle(work / 'root', inputs / 'inputs.json', profile['input_manifest_sha256'],
                             inputs / 'sources', inputs / 'wheels',
                             receipt_output=work / 'factory-studio-installation.json')
    receipt = installer.verify_bundle(work / 'root', inputs / 'inputs.json', profile['input_manifest_sha256'],
                                      inputs / 'sources', inputs / 'wheels')
    write_new(work / 'factory-studio-verification.json', canonical(receipt))
    result = layout.verification.verify(work / 'root')
    write_new(work / 'qualification-factory.json', canonical(result))
    if not result['passed']:
        raise ValueError('Factory layout did not pass after installation')


def guard_work(work):
    if (platform.system() != 'Linux' or platform.machine() != 'aarch64'
            or os.geteuid() != 0 or os.getegid() != 0
            or re.fullmatch(r'/var/lib/inkyos-build/factory-image\.[A-Za-z0-9]+', str(work)) is None):
        raise ValueError('Dedicated root ARM64 factory workspace required')
    # The complete path is checked before any rootfs layout mutation.
    for path in (*reversed(work.parents), work):
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or (info.st_uid, info.st_gid) != (0, 0)
                or stat.S_IMODE(info.st_mode) & 0o7022 or os.listxattr(path)
                or path == work and stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError('Private root-owned workspace required')
    marker = work.parent / 'owner'
    fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or (info.st_uid, info.st_gid) != (0, 0)
                or stat.S_IMODE(info.st_mode) & 0o7022 or info.st_size > 256 or os.listxattr(stream.fileno())
                or stream.read(257) != b'inkyos-builder-v1\n'):
            raise ValueError('Dedicated builder marker required')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('verify-inputs', 'prepare-rootfs'))
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args(argv)
    guard_work(args.work)
    if args.operation == 'verify-inputs':
        verify_inputs(args.work)
    else:
        prepare_rootfs(args.work)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
