#!/usr/bin/env python3
"""Inspect a closed, inactive writer file mapping; never run target code."""
import argparse
import importlib.util
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

_spec = importlib.util.spec_from_file_location(
    '_writer_install_guards', Path(__file__).with_name('install-factory-studio-bundle-rootfs.py'))
guards = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guards)
Refused, require = guards.Refused, guards.require
canonical, sha = guards.planner.canonical, guards.planner.exporter.sha

STUDIO_COMMIT = 'eb117903cb647a14e9722d7387a41058ea8807b3'
BUNDLE = 'usr/lib/inky-studio'
HELPER_SOURCE = 'scripts/inky-network-helper.py'
HELPER = 'usr/local/lib/inky-studio/network-helper.py'
# Only these repository paths may become installed files. Caller input cannot
# select a destination, permission, service, interpreter or executable argument.
SOURCE_MAP = {
    **{'staging/bootstrap/' + name: ('usr/lib/inkyos/' + name, '0555') for name in
       ('factory-main.py', 'writer-graph.py', 'writer-admission.py', 'writer-parents.py')},
    **{'scripts/' + name: ('usr/lib/inkyos/' + name, '0555') for name in
       ('factory-runtime-contract.py', 'factory-supervisor.py', 'writer-launcher.py')},
    **{'scripts/' + name: ('usr/local/lib/inkyos/' + name, '0555') for name in
       ('factory-authority.py', 'factory-credentials-publisher.py',
        'initialization-receipt.py', 'initialization-server.py')},
    **{'staging/bootstrap/' + name: ('usr/lib/systemd/system/' + name, '0644') for name in
       ('inky-studio.service', 'inky-network.service', 'inkyos-initialization.service',
        'inkyos-admission-prepare.service', 'inkyos-factory-supervisor.service')},
}
INPUT_FIELDS = {'schema_version', 'kind', 'os_commit', 'studio_commit',
                'os_source_sha256', 'studio_bundle_manifest_sha256', 'helper_source_sha256'}
HASH = re.compile(r'[0-9a-f]{64}\Z')
LIMIT = 1024 * 1024
UNITS = {PurePosixPath(destination).name for destination, _ in SOURCE_MAP.values()
         if destination.endswith('.service')}
UNIT_VENDOR = 'usr/lib/systemd/system'
UNIT_LOOKUP_DIRS = (
    'etc/systemd/system.control', 'run/systemd/system.control', 'run/systemd/transient',
    'run/systemd/generator.early', 'etc/systemd/system', 'etc/systemd/system.attached',
    'run/systemd/system', 'run/systemd/system.attached', 'run/systemd/generator',
    'usr/local/lib/systemd/system', UNIT_VENDOR, 'run/systemd/generator.late',
)
UNIT_EXTENSION_NAMES = {'service'} | {
    stem for unit in UNITS
    for stem in (unit, *(unit[:match.end()] + '.service' for match in re.finditer('-', unit)))
}
UNIT_ABSENT = {
    directory + '/' + unit for directory in UNIT_LOOKUP_DIRS if directory != UNIT_VENDOR
    for unit in UNITS
} | {
    directory + '/' + stem + '.' + suffix for directory in UNIT_LOOKUP_DIRS
    for stem in UNIT_EXTENSION_NAMES for suffix in ('d', 'wants', 'requires', 'upholds')
}
TEST_SCRIPTS = (
    'test-enrollment-firstboot', 'test-access-policy', 'test-access-enrollment',
    'test-access-contract', 'test-access-import', 'test-access-connect', 'test-access-boot',
    'test-access-network', 'test-access-wifi-gate', 'test-access-bluetooth', 'test-lan-preflight',
    'test-access-activation-gate', 'test-access-activation', 'test-access-drain',
    'observe-test-panel', 'observe-test-radio',
)
TEST_ABSENT = {
    'usr/local/share/inkyos/test-access-manifest.json', 'usr/local/share/inkyos/test-access',
    'etc/inkyos-test-ssh', 'etc/inkyos-test-enrollment', 'etc/inkyos-test-lan.json',
    'var/lib/inkyos-test-access', 'var/lib/inkyos-test-enrollment', 'usr/local/lib/inkyos-test-ssh',
    'etc/sudoers.d/inkyos-test-ssh',
    'etc/systemd/system/NetworkManager.service.d/10-inkyos-test-wifi.conf',
    'etc/NetworkManager/conf.d/10-inkyos-test-loopback.conf',
} | {'usr/local/lib/inkyos/' + name + '.py' for name in TEST_SCRIPTS} | {
    prefix + '/inkyos-test-' + name + '.service'
    for prefix in ('usr/lib/systemd/system', 'etc/systemd/system',
                   'etc/systemd/system/multi-user.target.wants')
    for name in ('access', 'ssh', 'activate', 'drain')
}
STATE_ABSENT = {
    'etc/inky-studio/factory-v1.json', 'etc/inkyos/factory-runtime-v1.json',
    'etc/inkyos/factory-system-support.json', 'usr/lib/inkyos/factory-exporter',
    'var/lib/inkyos/factory-permission', 'var/lib/inkyos/initialization',
    'var/lib/inky-studio', 'var/lib/inky-network',
    'run/inkyos-admission', 'run/inkyos-factory', 'run/inkyos-bootstrap',
    'run/inkyos-factory-output', 'run/inky-network',
}


def _production_environment(rootfs):
    require(rootfs != Path('/'), 'host_root_refused')
    require(sys.platform.startswith('linux') and os.geteuid() == os.getegid() == 0,
            'root_linux_builder_required')
    require(re.fullmatch(r'/var/lib/inkyos-build/factory-image\.[A-Za-z0-9]+/root',
                         str(rootfs)), 'private_workspace_required')
    return rootfs.parent, None


class Environment:
    """Held parent identities, bounded reads and exclusive build workspace."""
    def __init__(self, rootfs, inputs, sources, bundle_manifest, receipt=None):
        self.directories, self.root_dirs = [], {}
        self.rootfs = guards._canonical_path(rootfs)
        work, trust_from = _production_environment(self.rootfs)
        try:
            def directory(path):
                value = guards.Directory(self.rootfs, path, trust_from=trust_from)
                self.directories.append(value)
                return value
            self.work = directory(work)
            require(stat.S_IMODE(os.fstat(self.work.fd).st_mode) == 0o700,
                    'private_workspace_required')
            self.root = directory(self.rootfs)
            self.root_dirs['.'] = self.root
            paths = [guards._canonical_path(path) for path in (inputs, sources, bundle_manifest)]
            if receipt is not None:
                paths.append(guards._canonical_path(receipt))
            require(all(path.is_relative_to(work) and not path.is_relative_to(self.rootfs)
                        and path != work for path in paths), 'workspace_overlap')
            require(all(not first.is_relative_to(second) and not second.is_relative_to(first)
                        for index, first in enumerate(paths) for second in paths[index + 1:]),
                    'input_output_overlap')
            self.inputs_path, self.sources_path, self.bundle_manifest_path = paths[:3]
            self.inputs = directory(self.inputs_path.parent)
            self.sources = directory(self.sources_path)
            self.bundle_manifest = directory(self.bundle_manifest_path.parent)
            self.receipt = directory(paths[3].parent) if receipt is not None else None
            self.receipt_name = paths[3].name if receipt is not None else None
            if self.receipt is not None:
                require(guards._missing(self.receipt.fd, self.receipt_name), 'receipt_exists')
            if trust_from is None:
                marker = directory(Path('/var/lib/inkyos-build'))
                require(guards._read_file(self.rootfs, marker.fd, 'owner', 256)
                        == b'inkyos-builder-v1\n', 'builder_marker_required')
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        for directory in self.directories:
            directory.check()
            guards._trust(self.rootfs, os.fstat(directory.fd))
            require(guards._xattrs(self.rootfs, directory.fd) == guards.EMPTY_XATTRS,
                    'untrusted_xattrs')

    def close(self):
        for directory in reversed(self.directories):
            directory.close()
        self.directories = []

    def directory(self, path, *, missing=False):
        current, relative = self.root.fd, ''
        if path == '.':
            return current
        for part in path.split('/'):
            relative = part if not relative else relative + '/' + part
            held = self.root_dirs.get(relative)
            if held is not None:
                held.check(); current = held.fd
                continue
            if guards._missing(current, part):
                require(missing, 'parent_missing')
                return None
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            try:
                guards._trust(self.rootfs, os.fstat(fd))
                require(guards._xattrs(self.rootfs, fd) == guards.EMPTY_XATTRS, 'untrusted_xattrs')
                held = guards._FdDirectory(self.rootfs, fd, current, part)
            except BaseException:
                os.close(fd); raise
            self.directories.append(held); self.root_dirs[relative] = held
            current = fd
        return current

    def absent(self, path):
        parent, leaf = str(PurePosixPath(path).parent), PurePosixPath(path).name
        fd = self.directory(parent, missing=True)
        return fd is None or guards._missing(fd, leaf)

    def read(self, path, limit=LIMIT, *, mode=None):
        parent, leaf = str(PurePosixPath(path).parent), PurePosixPath(path).name
        fd = self.directory(parent)
        before = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
        if mode is not None:
            require(stat.S_IMODE(before.st_mode) == int(mode, 8), 'input_mode_mismatch')
        raw = guards._read_file(self.rootfs, fd, leaf, limit)
        require(guards._signature(os.stat(leaf, dir_fd=fd, follow_symlinks=False))
                == guards._signature(before), 'input_changed')
        return raw


def _names(fd, limit, reason):
    names = []
    with os.scandir(fd) as entries:
        for entry in entries:
            require(len(names) < limit, reason)
            names.append(entry.name)
    return sorted(names)


def _exact_sources(environment, pins):
    """Inspect only the dedicated sixteen-file source tree, never the OS tree."""
    wanted = {name: 'file' for name in pins}
    for name in pins:
        for parent in PurePosixPath(name).parents:
            if str(parent) != '.':
                wanted[str(parent)] = 'directory'
    seen, payload = {}, {}

    def visit(fd, relative):
        before = os.fstat(fd)
        for name in _names(fd, len(wanted), 'extra_source'):
            path = name if not relative else relative + '/' + name
            require(path in wanted and path not in seen, 'extra_source')
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            guards._trust(environment.rootfs, info)
            if wanted[path] == 'directory':
                require(stat.S_ISDIR(info.st_mode), 'invalid_source')
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    require(guards._signature(os.fstat(child)) == guards._signature(info),
                            'source_changed')
                    require(guards._xattrs(environment.rootfs, child) == guards.EMPTY_XATTRS,
                            'untrusted_xattrs')
                    visit(child, path)
                finally:
                    os.close(child)
            else:
                raw = guards._read_file(environment.rootfs, fd, name, LIMIT)
                require(sha(raw) == pins[path], 'source_pin_mismatch')
                payload[path] = raw
            seen[path] = wanted[path]
        require(guards._signature(os.fstat(fd)) == guards._signature(before), 'source_changed')
    visit(environment.sources.fd, '')
    require(seen == wanted, 'missing_source')
    environment.check()
    return payload


def _load_payload(environment, input_sha256):
    require(type(input_sha256) is str and HASH.fullmatch(input_sha256), 'invalid_pin')
    raw = guards._read_file(environment.rootfs, environment.inputs.fd,
                            environment.inputs_path.name, LIMIT)
    require(sha(raw) == input_sha256, 'input_pin_mismatch')
    value = guards.planner.exporter.strict_json(raw)
    require(type(value) is dict and set(value) == INPUT_FIELDS and raw == canonical(value),
            'invalid_input_manifest')
    require(type(value['schema_version']) is int and value['schema_version'] == 1
            and value['kind'] == 'factory-writer-file-inputs'
            and type(value['os_commit']) is str and re.fullmatch(r'[0-9a-f]{40}', value['os_commit'])
            and value['studio_commit'] == STUDIO_COMMIT, 'invalid_input_manifest')
    pins = value['os_source_sha256']
    require(type(pins) is dict and set(pins) == set(SOURCE_MAP), 'invalid_source_pins')
    require(all(type(pin) is str and HASH.fullmatch(pin) for pin in pins.values()), 'invalid_pin')
    require(all(type(value[field]) is str and HASH.fullmatch(value[field]) for field in
                ('studio_bundle_manifest_sha256', 'helper_source_sha256')), 'invalid_pin')
    manifest = guards._read_file(environment.rootfs, environment.bundle_manifest.fd,
                                 environment.bundle_manifest_path.name, guards.MAX_MANIFEST)
    require(sha(manifest) == value['studio_bundle_manifest_sha256'], 'bundle_manifest_pin_mismatch')
    bundle = guards.planner.exporter.strict_json(manifest)
    require(type(bundle) is dict and set(bundle) == {'schema_version', 'kind', 'studio_commit', 'records'}
            and manifest == canonical(bundle) and type(bundle['schema_version']) is int
            and bundle['schema_version'] == 1 and bundle['kind'] == 'factory-studio-bundle-manifest'
            and bundle['studio_commit'] == STUDIO_COMMIT and type(bundle['records']) is dict
            and 0 < len(bundle['records']) <= 100000, 'invalid_bundle_manifest')
    require(environment.read(BUNDLE + '/manifest.json', guards.MAX_MANIFEST, mode='0644') == manifest,
            'installed_bundle_manifest_mismatch')
    helper = environment.read(BUNDLE + '/' + HELPER_SOURCE, mode='0644')
    helper_record = bundle['records'].get(HELPER_SOURCE)
    require(sha(helper) == value['helper_source_sha256']
            and type(helper_record) is dict
            and all(type(helper_record.get(field)) is int for field in ('uid', 'gid', 'size_bytes'))
            and helper_record == guards.planner.exporter.file_record(helper, '0644'),
            'helper_provenance_mismatch')
    source_payload = _exact_sources(environment, pins)
    payload = {SOURCE_MAP[name][0]: (source_payload[name], SOURCE_MAP[name][1]) for name in SOURCE_MAP}
    payload[HELPER] = helper, '0555'
    environment.check()
    return value, payload


def _unit_influences(environment, *, installed):
    require(all(environment.absent(path) for path in UNIT_ABSENT), 'unit_influence_present')
    if not environment.absent('lib'):
        info = os.stat('lib', dir_fd=environment.root.fd, follow_symlinks=False)
        require(stat.S_ISLNK(info.st_mode) and info.st_nlink == 1
                and (info.st_uid, info.st_gid) == guards._owner_ids(environment.rootfs),
                'split_lib_refused')
        require(guards._xattrs(environment.rootfs,
                              '/proc/self/fd/' + str(environment.root.fd) + '/lib', nofollow=True)
                == guards.EMPTY_XATTRS, 'untrusted_xattrs')
        require(os.readlink('lib', dir_fd=environment.root.fd) in {'usr/lib', '/usr/lib'},
                'split_lib_refused')
        require(guards._signature(os.stat('lib', dir_fd=environment.root.fd, follow_symlinks=False))
                == guards._signature(info), 'unit_scan_changed')
    count = 0

    def visit(fd, path, depth):
        nonlocal count
        require(depth <= 8, 'unit_scan_limit')
        before = os.fstat(fd)
        names = _names(fd, 20000 - count, 'unit_scan_limit')
        for name in names:
            count += 1
            require(count <= 20000 and len(os.fsencode(name)) <= 255, 'unit_scan_limit')
            child_path = path + '/' + name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if name in UNITS:
                require(installed and path == UNIT_VENDOR and stat.S_ISREG(info.st_mode),
                        'unit_influence_present')
            if stat.S_ISDIR(info.st_mode):
                child = environment.directory(child_path)
                visit(child, child_path, depth + 1)
            elif stat.S_ISLNK(info.st_mode):
                require(not name.endswith(('.d', '.wants', '.requires', '.upholds')),
                        'unit_extension_link_present')
                target = os.readlink(name, dir_fd=fd)
                require(PurePosixPath(target).name not in UNITS, 'unit_alias_present')
                require(guards._signature(os.stat(name, dir_fd=fd, follow_symlinks=False))
                        == guards._signature(info), 'unit_scan_changed')
        require(_names(fd, len(names), 'unit_scan_changed') == names
                and guards._signature(os.fstat(fd)) == guards._signature(before), 'unit_scan_changed')
    for path in UNIT_LOOKUP_DIRS:
        fd = environment.directory(path, missing=True)
        if fd is not None:
            visit(fd, path, 0)
    environment.check()


def _preflight(environment, payload, *, installing):
    require(all(environment.absent(path) for path in STATE_ABSENT | TEST_ABSENT),
            'factory_or_test_state_present')
    _unit_influences(environment, installed=not installing)
    for path in payload:
        parent = str(PurePosixPath(path).parent)
        fd = environment.directory(parent, missing=True)
        maximum = os.fpathconf(environment.root.fd if fd is None else fd, 'PC_NAME_MAX')
        require(type(maximum) is int and maximum > 0
                and all(len(os.fsencode(part)) <= maximum for part in path.split('/')),
                'unmaterializable_path')
        if installing:
            require(fd is None or guards._missing(fd, PurePosixPath(path).name), 'destination_exists')
        else:
            require(fd is not None and not guards._missing(fd, PurePosixPath(path).name),
                    'destination_missing')
    if environment.receipt is not None:
        require(guards._missing(environment.receipt.fd, environment.receipt_name), 'receipt_exists')
        maximum = os.fpathconf(environment.receipt.fd, 'PC_NAME_MAX')
        require(type(maximum) is int and maximum > 0
                and len(os.fsencode(environment.receipt_name)) <= maximum, 'unmaterializable_path')
    environment.check()


def _verify_files(environment, payload):
    for path, (wanted, mode) in payload.items():
        parent, name = str(PurePosixPath(path).parent), PurePosixPath(path).name
        fd = environment.directory(parent)
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        require(stat.S_IMODE(info.st_mode) == int(mode, 8), 'destination_mode_mismatch')
        require(environment.read(path, mode=mode) == wanted, 'destination_bytes_mismatch')
    _preflight(environment, payload, installing=False)
    environment.check()


def _receipt(value, input_sha256, payload, operation):
    return {
        'schema_version': 1, 'scope': 'offline-factory-writer-files', 'operation': operation,
        'input_manifest_sha256': input_sha256, 'os_commit': value['os_commit'],
        'os_commit_evidence': 'caller-declared-correlation-only',
        'studio_commit': value['studio_commit'],
        'studio_bundle_manifest_sha256': value['studio_bundle_manifest_sha256'],
        'records': {path: guards.planner.exporter.file_record(raw, mode)
                    for path, (raw, mode) in payload.items()},
        'files_verified': True, 'studio_bundle_qualified': False,
        'services_enabled': False, 'service_actions_issued': False,
        'image_code_executed': False, 'application_code_executed': False,
        'support_verified': False, 'authority_provisioned': False,
        'runtime_qualified': False, 'image_qualified': False, 'hardware_qualified': False,
    }


def verify_writer(rootfs, input_manifest, input_sha256, sources_dir, bundle_manifest):
    environment = None
    try:
        environment = Environment(rootfs, input_manifest, sources_dir, bundle_manifest)
        value, payload = _load_payload(environment, input_sha256)
        _verify_files(environment, payload)
        require(_load_payload(environment, input_sha256) == (value, payload), 'inputs_changed')
        environment.check()
        return _receipt(value, input_sha256, payload, 'verify')
    except Refused:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError, RuntimeError):
        raise Refused('verification_failed') from None
    finally:
        if environment is not None:
            environment.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-sha256', required=True)
    for field in ('rootfs', 'input-manifest', 'sources-dir', 'bundle-manifest'):
        parser.add_argument('--' + field, type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        verify_writer(args.rootfs, args.input_manifest, args.input_sha256,
                      args.sources_dir, args.bundle_manifest)
    except Refused as error:
        print('factory_writer_verify_refused:' + error.reason, file=sys.stderr)
        return 1
    print('Writer files inspected; no service or runtime qualified.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
