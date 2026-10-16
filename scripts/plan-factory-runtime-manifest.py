#!/usr/bin/env python3
"""Plan a runtime manifest from an assembled, unbooted factory rootfs.

The real candidate verifier reads the proposed manifest through an in-memory
view. All other reads inspect the installed bytes and metadata. Nothing is
written in the image: this does not create permission, admission or boot state.
The three externally reviewed inventory hashes are required inputs.
"""
import argparse
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location('_runtime_plan_' + name.replace('-', '_'),
                                                ROOT / 'scripts' / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runtime = load('factory-runtime-contract.py')
prerequisites = load('configure-factory-active-prerequisites.py')
Refused = runtime.Refused


class _ManifestView:
    def __init__(self, tree, raw):
        self.tree, self.raw = tree, raw

    def __getattr__(self, name):
        return getattr(self.tree, name)

    def read(self, path, mode, limit=32 * 1024 * 1024):
        if path == runtime.MANIFEST:
            runtime.require(mode == 0o644 and len(self.raw) <= limit, 'invalid_manifest')
            return self.raw
        return self.tree.read(path, mode, limit)


class _PlannedContract(runtime.Contract):
    @contextmanager
    def tree(self):
        with runtime.Tree(self._root, self._uid, self._gid) as tree:
            yield _ManifestView(tree, self._planned_raw)


def _workspace(rootfs):
    runtime.require(sys.platform == 'linux' and os.geteuid() == os.getegid() == 0,
                    'root_linux_builder_required')
    runtime.require(re.fullmatch(r'/var/lib/inkyos-build/factory-image\.[A-Za-z0-9]+/root',
                                 str(rootfs)) is not None, 'private_workspace_required')
    with runtime.Tree(Path('/')) as tree:
        tree.directory('var/lib/inkyos-build', 0o755)
        runtime.require(tree.read('var/lib/inkyos-build/owner', 0o644, 256)
                        == b'inkyos-builder-v1\n', 'builder_marker_required')
        tree.directory(str(rootfs.parent)[1:], 0o700)


def plan(rootfs, *, bundle_sha256, exporter_sha256, support_sha256,
         helper_uid, provisioning_gid, _owner=None):
    """Return proposed bytes and a planning receipt; never change the rootfs.

    ``_owner`` exists only for non-host test roots. It never permits an actual
    runtime root or creates a boot context, and the CLI cannot select it.
    """
    rootfs = Path(rootfs)
    runtime.require(rootfs.is_absolute() and rootfs != Path('/')
                    and '..' not in rootfs.parts, 'host_root_refused')
    if _owner is None:
        _workspace(rootfs)
        uid, gid = 0, 0
    else:
        runtime.require(type(_owner) is tuple and len(_owner) == 2
                        and all(type(value) is int and value >= 0 for value in _owner),
                        'invalid_fixture_owner')
        uid, gid = _owner
    runtime.require(all(type(value) is str and runtime.HASH.fullmatch(value)
                        for value in (bundle_sha256, exporter_sha256, support_sha256)),
                    'reviewed_inventory_pins_required')
    runtime.require(all(type(value) is int and 1 <= value <= 999
                        for value in (helper_uid, provisioning_gid)), 'invalid_identity')
    with runtime.Tree(rootfs, uid, gid) as tree:
        runtime.require(tree.absent(runtime.MANIFEST), 'runtime_manifest_exists')
        runtime.require(all(tree.absent(path) for path in (
            'run/inkyos-factory', 'run/inkyos-admission', 'run/inkyos-bootstrap',
            'run/inkyos-factory-output', 'run/inkyos-writer-parents',
            'run/inky-network')), 'runtime_state_exists')
        app_raw = tree.read(runtime.APP + '/manifest.json', 0o644)
        exporter_raw = tree.read(runtime.EXPORTER + '/manifest.json', 0o644)
        support_raw = tree.read(runtime.SUPPORT, 0o644)
        runtime.require(all(runtime.sha(raw) == pin for raw, pin in (
            (app_raw, bundle_sha256), (exporter_raw, exporter_sha256),
            (support_raw, support_sha256))), 'pin_mismatch')
        app = runtime.decode(app_raw)
        runtime.require(type(app) is dict and type(app.get('studio_commit')) is str
                        and re.fullmatch('[0-9a-f]{40}', app['studio_commit']), 'invalid_candidate')
        pins = {name: runtime.sha(tree.read(runtime.MODULE_DIR + '/' + name, 0o555,
                                           1024 * 1024)) for name in runtime.MODULES}
        support = runtime.decode(support_raw)
        runtime.require(type(support) is dict and type(support.get('paths')) is dict
                        and {'etc/passwd', 'etc/group', 'etc/nsswitch.conf'}
                        <= set(support['paths']), 'account_support_missing')
        # Reuse the full readonly NSS/metadata policy of the account preparer.
        # Its already-configured validation never creates or replaces accounts.
        parent, _ = tree.parent('etc/passwd')
        try:
            environment = SimpleNamespace(rootfs=rootfs, etc=SimpleNamespace(fd=parent))
            accounts, _ = prerequisites._load(environment)
            prerequisites._accounts(accounts, helper_uid, provisioning_gid, configured=True)
        finally:
            os.close(parent)
    value = {'version': 1, 'studio_commit': app['studio_commit'],
             'bundle_manifest_sha256': bundle_sha256,
             'exporter_manifest_sha256': exporter_sha256,
             'support_manifest_sha256': support_sha256,
             'helper_uid': helper_uid, 'provisioning_gid': provisioning_gid,
             'os_module_pins': pins}
    runtime.require(pins['writer-admission.py'] == runtime.ADMISSION_SHA256, 'pin_mismatch')
    raw = runtime.canonical(value)
    contract = _PlannedContract(value, runtime.sha(raw), rootfs, uid, gid, None, None)
    contract._planned_raw = raw
    runtime.verify_candidate(contract)
    return raw, {'schema_version': 1, 'scope': 'offline-factory-runtime-manifest-plan',
                 'manifest_sha256': runtime.sha(raw), 'installed_file_contract_verified': True,
                 'runtime_manifest_installed': False, 'boot_state_created': False,
                 'image_code_executed': False, 'hardware_qualified': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    for name in ('bundle', 'exporter', 'support'):
        parser.add_argument('--' + name + '-sha256', required=True)
    parser.add_argument('--helper-uid', type=int, required=True)
    parser.add_argument('--provisioning-gid', type=int, required=True)
    args = parser.parse_args(argv)
    try:
        rootfs, output = args.rootfs.absolute(), args.output.absolute()
        runtime.require(rootfs == rootfs.resolve(strict=True)
                        and output.parent == output.parent.resolve(strict=True)
                        and not output.is_relative_to(rootfs), 'output_overlap')
        raw, receipt = plan(rootfs, bundle_sha256=args.bundle_sha256,
                            exporter_sha256=args.exporter_sha256,
                            support_sha256=args.support_sha256,
                            helper_uid=args.helper_uid, provisioning_gid=args.provisioning_gid)
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            view = memoryview(raw)
            while view:
                count = os.write(fd, view)
                runtime.require(count > 0, 'output_incomplete')
                view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
    except (OSError, ValueError, TypeError, KeyError, StopIteration):
        print(json.dumps({'scope': 'offline-factory-runtime-manifest-plan', 'passed': False,
                          'error': 'runtime_manifest_plan_refused'}, sort_keys=True))
        return 1
    print(json.dumps({'passed': True, **receipt}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
