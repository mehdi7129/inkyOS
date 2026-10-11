#!/usr/bin/env python3
"""Materialize a pinned Studio bundle offline; never execute target code.

The root-owned build workspace is exclusive to the caller. Directory fds and
identity rechecks prevent accidental link traversal, not concurrent root writers.
A failed operation leaves its exclusive creations for inspection, never repair.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import stat
import sys

_spec = importlib.util.spec_from_file_location(
    '_studio_install_planner', Path(__file__).with_name('plan-factory-studio-bundle.py'))
planner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(planner)
Refused = planner.Refused
require = planner.require
DESTINATION = ('usr', 'lib', 'inky-studio')
EMPTY_XATTRS = {'status': 'inspected', 'entries': {}}
MAX_MANIFEST = 32 * 1024 * 1024
MAX_PATH_PARTS = 64
MAX_PATH_BYTES = 4096


def _owner_ids(rootfs):
    # Fixture tests may replace this helper only for a synthetic root != '/'.
    require(rootfs != Path('/'), 'host_root_refused')
    return 0, 0


def _xattrs(rootfs, target, *, nofollow=False):
    # Production requires actual Linux inspection, including symlink xattrs.
    require(rootfs != Path('/'), 'host_root_refused')
    require(sys.platform.startswith('linux') and hasattr(os, 'listxattr')
            and hasattr(os, 'getxattr'), 'xattrs_unavailable')
    return planner.exporter.inventory_module._xattrs(target, nofollow=nofollow)


def _signature(info):
    return planner.exporter.inventory_module._signature(info)


def _identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _canonical_path(value):
    path = Path(value)
    require(path.is_absolute() and '..' not in path.parts, 'invalid_path')
    return path


def _trust(rootfs, info):
    require((info.st_uid, info.st_gid) == _owner_ids(rootfs)
            and not stat.S_IMODE(info.st_mode) & 0o7022, 'untrusted_metadata')


class Directory:
    """Hold and recheck every parent without resolving any filesystem link."""
    def __init__(self, rootfs, path, *, trust_from=None):
        self.rootfs, self.path = rootfs, _canonical_path(path)
        self.fds, self.infos, self.names = [], [], self.path.parts[1:]
        try:
            self.fds.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
            for name in self.names:
                self.fds.append(os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                        dir_fd=self.fds[-1]))
            self.infos = [os.fstat(fd) for fd in self.fds]
            for index, (fd, info) in enumerate(zip(self.fds, self.infos)):
                path_at = Path('/').joinpath(*self.names[:index])
                if trust_from is None or path_at.is_relative_to(trust_from):
                    _trust(rootfs, info)
                    require(_xattrs(rootfs, fd) == EMPTY_XATTRS, 'untrusted_xattrs')
            self.check()
        except BaseException:
            self.close()
            raise

    @property
    def fd(self):
        return self.fds[-1]

    def check(self):
        for index, (fd, before) in enumerate(zip(self.fds, self.infos)):
            require(_identity(os.fstat(fd)) == _identity(before), 'parent_changed')
            if index:
                current = os.stat(self.names[index - 1], dir_fd=self.fds[index - 1],
                                  follow_symlinks=False)
                require(_identity(current) == _identity(before), 'parent_changed')

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds = []


def _read_file(rootfs, directory, name, limit):
    """Pin a regular inode before opening its bytes on Linux."""
    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    _trust(rootfs, before)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and 0 <= before.st_size <= limit, 'invalid_regular_file')
    pin = fd = None
    try:
        if sys.platform.startswith('linux'):
            require(hasattr(os, 'O_PATH'), 'inode_pinning_unavailable')
            pin = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=directory)
            require(_signature(os.fstat(pin)) == _signature(before), 'input_changed')
            fd = os.open('/proc/self/fd/' + str(pin), os.O_RDONLY | os.O_NONBLOCK)
        else:  # Explicit ownership/xattrs fixture seams still gate this branch.
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        require(_signature(os.fstat(fd)) == _signature(before), 'input_changed')
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk); total += len(chunk)
            require(total <= limit, 'input_limit')
        require(total == before.st_size and _signature(os.fstat(fd)) == _signature(before)
                and _signature(os.stat(name, dir_fd=directory, follow_symlinks=False))
                == _signature(before), 'input_changed')
        require(_xattrs(rootfs, fd) == EMPTY_XATTRS, 'untrusted_xattrs')
        return b''.join(chunks)
    finally:
        if fd is not None:
            os.close(fd)
        if pin is not None:
            os.close(pin)


def _relative_file(rootfs, directory, name, limit):
    parts = name.split('/')
    opened, current = [], directory
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            opened.append(child); current = child
            _trust(rootfs, os.fstat(child))
            require(_xattrs(rootfs, child) == EMPTY_XATTRS, 'untrusted_xattrs')
        return _read_file(rootfs, current, parts[-1], limit)
    finally:
        for fd in reversed(opened):
            os.close(fd)


def _missing(fd, name):
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    return False


def _production_environment(rootfs):
    require(rootfs != Path('/'), 'host_root_refused')
    require(sys.platform.startswith('linux') and os.geteuid() == 0
            and os.getegid() == 0, 'root_linux_builder_required')
    require(re.fullmatch(r'/var/lib/inkyos-build/factory-studio\.[A-Za-z0-9]+/root',
                         str(rootfs)), 'private_workspace_required')
    return rootfs.parent, None


class Environment:
    def __init__(self, rootfs, inputs, sources, wheels, receipt, *, installing):
        self.directories = []
        self.rootfs = _canonical_path(rootfs)
        require(self.rootfs != Path('/'), 'host_root_refused')
        work, trust_from = _production_environment(self.rootfs)
        try:
            def directory(path):
                value = Directory(self.rootfs, path, trust_from=trust_from)
                self.directories.append(value)
                return value
            self.work = directory(work)
            require(stat.S_IMODE(os.fstat(self.work.fd).st_mode) == 0o700,
                    'private_workspace_required')
            self.root = directory(self.rootfs)
            paths = [_canonical_path(path) for path in (inputs, sources, wheels)]
            if receipt is not None:
                paths.append(_canonical_path(receipt))
            require(all(path.is_relative_to(work) and not path.is_relative_to(self.rootfs)
                        and path != work for path in paths), 'workspace_overlap')
            for index, first in enumerate(paths):
                for second in paths[index + 1:]:
                    require(not first.is_relative_to(second) and not second.is_relative_to(first),
                            'input_output_overlap')
            self.inputs_path, self.sources_path, self.wheels_path = paths[:3]
            self.inputs = directory(self.inputs_path.parent)
            self.sources, self.wheels = directory(self.sources_path), directory(self.wheels_path)
            self.receipt = directory(paths[3].parent) if receipt is not None else None
            self.receipt_name = paths[3].name if receipt is not None else None
            if self.receipt is not None:
                require(_missing(self.receipt.fd, self.receipt_name), 'receipt_exists')
            if trust_from is None:
                marker = directory(Path('/var/lib/inkyos-build'))
                require(_read_file(self.rootfs, marker.fd, 'owner', 256)
                        == b'inkyos-builder-v1\n', 'builder_marker_required')
            self.parent_dirs = []
            current = self.root.fd
            missing = False
            for part in DESTINATION[:-1]:
                if missing or _missing(current, part):
                    missing = True
                    self.parent_dirs.append(part)
                    continue
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                self.directories.append(_FdDirectory(self.rootfs, child, current, part))
                _trust(self.rootfs, os.fstat(child))
                require(_xattrs(self.rootfs, child) == EMPTY_XATTRS, 'untrusted_xattrs')
                current = child
            self.destination_parent = current
            require(not installing or missing or _missing(current, DESTINATION[-1]),
                    'destination_exists')
            require(installing or not missing, 'bundle_missing')
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        for directory in self.directories:
            directory.check()

    def close(self):
        for directory in reversed(self.directories):
            directory.close()
        self.directories = []


class _FdDirectory:
    def __init__(self, rootfs, fd, parent, name):
        self.rootfs, self.fd, self.parent, self.name = rootfs, fd, parent, name
        self.before = os.fstat(fd)

    def check(self):
        require(_identity(os.fstat(self.fd)) == _identity(self.before), 'parent_changed')
        require(_identity(os.stat(self.name, dir_fd=self.parent, follow_symlinks=False))
                == _identity(self.before), 'parent_changed')

    def close(self):
        os.close(self.fd)


def _payload(environment, input_sha256, expected):
    rootfs = environment.rootfs
    manifest = _read_file(rootfs, environment.inputs.fd, environment.inputs_path.name, 1024 * 1024)
    require(planner.exporter.sha(manifest) == input_sha256, 'pin_mismatch')
    value = planner.exporter.strict_json(manifest)
    payload, total = {}, 0
    for filename, pin in value['wheel_sha256'].items():
        raw = _relative_file(rootfs, environment.wheels.fd, filename, planner.exporter.LIMIT)
        require(planner.exporter.sha(raw) == pin, 'pin_mismatch')
        for path, content in planner.exporter.wheel_payload(raw, filename).items():
            name = planner.SITE + '/' + path
            require(name not in payload, 'payload_collision')
            payload[name] = content; total += len(content)
    for name, pin in value['source_sha256'].items():
        raw = _relative_file(rootfs, environment.sources.fd, name, planner.exporter.LIMIT)
        require(planner.exporter.sha(raw) == pin and name not in payload, 'pin_mismatch')
        payload[name] = raw; total += len(raw)
    payload[planner.VENV + '/pyvenv.cfg'] = planner.exporter.configuration(value['python_version'])
    require(total <= planner.MAX_BYTES and len(payload) <= planner.MAX_FILES + 1, 'payload_limit')
    wanted = {name for name, record in expected.items() if record['type'] == 'file'}
    require(set(payload) == wanted, 'payload_mismatch')
    for name, raw in payload.items():
        require(planner.exporter.file_record(raw, expected[name]['mode']) == expected[name],
                'payload_mismatch')
    # The planner validates the complete trees again, including extra entries.
    repeat, _ = planner.plan(environment.inputs_path, input_sha256,
                             environment.sources_path, environment.wheels_path)
    require(planner.exporter.strict_json(repeat)['records'] == expected, 'inputs_changed')
    environment.check()
    return payload


def _mkdir(rootfs, parent, name):
    os.mkdir(name, 0o755, dir_fd=parent)
    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        os.fchown(child, *_owner_ids(rootfs)); os.fchmod(child, 0o755)
        require(_xattrs(rootfs, child) == EMPTY_XATTRS, 'created_xattrs')
        os.fsync(child); os.fsync(parent)
        return child
    except BaseException:
        os.close(child)
        raise


def _write_file(rootfs, parent, name, raw, mode):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=parent)
    try:
        os.fchown(fd, *_owner_ids(rootfs)); os.fchmod(fd, int(mode, 8))
        require(_xattrs(rootfs, fd) == EMPTY_XATTRS, 'created_xattrs')
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            require(count > 0, 'write_failed')
            view = view[count:]
        os.fsync(fd); os.fsync(parent)
    finally:
        os.close(fd)


def _write_symlink(rootfs, parent, name, target):
    require(rootfs != Path('/') and sys.platform.startswith('linux'), 'linux_symlink_required')
    os.symlink(target, name, dir_fd=parent)
    os.chown(name, *_owner_ids(rootfs), dir_fd=parent, follow_symlinks=False)
    os.fsync(parent)


def _parent_fd(bundle, name):
    opened, current = [], bundle
    try:
        parts = name.split('/')
        for part in parts[:-1]:
            current = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            opened.append(current)
        return current, parts[-1], opened
    except BaseException:
        for fd in reversed(opened):
            os.close(fd)
        raise


def _inventory(rootfs, bundle):
    records, byte_count = {}, 0
    def metadata(info):
        require((info.st_uid, info.st_gid) == _owner_ids(rootfs), 'bundle_owner_mismatch')
        return {'uid': 0, 'gid': 0, 'mode': format(stat.S_IMODE(info.st_mode), '04o')}
    def visit(fd, relative):
        nonlocal byte_count
        before = os.fstat(fd)
        records[relative] = dict(metadata(before), type='directory', xattrs=_xattrs(rootfs, fd))
        names = []
        with os.scandir(fd) as entries:
            for entry in entries:
                require(len(names) + len(records) <= 100000, 'inventory_limit')
                names.append(entry.name)
        for name in sorted(names):
            path = name if relative == '.' else relative + '/' + name
            require(len(records) <= 100000 and len(path.split('/')) <= MAX_PATH_PARTS
                    and len(path.encode('utf-8')) <= MAX_PATH_BYTES, 'inventory_limit')
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    require(_signature(os.fstat(child)) == _signature(info), 'bundle_changed')
                    visit(child, path)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                raw = _read_file(rootfs, fd, name, max(planner.exporter.LIMIT, MAX_MANIFEST))
                byte_count += len(raw)
                require(byte_count <= planner.MAX_BYTES + MAX_MANIFEST + 1024, 'inventory_limit')
                records[path] = dict(metadata(info), type='file', size_bytes=len(raw),
                                     sha256=planner.exporter.sha(raw), xattrs=_xattrs(
                                         rootfs, '/proc/self/fd/' + str(fd) + '/' + name,
                                         nofollow=True) if sys.platform.startswith('linux') else
                                         _xattrs(rootfs, fd))
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(name, dir_fd=fd)
                records[path] = dict(metadata(info), type='symlink', target=target,
                                     xattrs=_xattrs(rootfs, '/proc/self/fd/' + str(fd) + '/' + name,
                                                   nofollow=True))
                require(_signature(os.stat(name, dir_fd=fd, follow_symlinks=False))
                        == _signature(info), 'bundle_changed')
            else:
                raise Refused('bundle_special_file')
        require(_signature(os.fstat(fd)) == _signature(before), 'bundle_changed')
    visit(bundle, '.')
    return records


def _expected(input_manifest, input_sha256, sources_dir, wheels_dir):
    manifest, receipt = planner.plan(input_manifest, input_sha256, sources_dir, wheels_dir)
    records = planner.exporter.strict_json(manifest)['records']
    return manifest, records, receipt


def _preflight_paths(environment, expected):
    """Check final names, including prefixes and our manifest, before mkdir."""
    name_max = os.fpathconf(environment.destination_parent, 'PC_NAME_MAX')
    require(type(name_max) is int and name_max > 0, 'unsupported_name_limit')
    for path in (*expected, 'manifest.json'):
        if path == '.':
            continue
        parts = path.split('/')
        require(len(parts) <= MAX_PATH_PARTS and len(path.encode('utf-8')) <= MAX_PATH_BYTES
                and all(len(os.fsencode(part)) <= name_max for part in parts),
                'unmaterializable_path')
    if environment.receipt is not None:
        receipt_max = os.fpathconf(environment.receipt.fd, 'PC_NAME_MAX')
        require(type(receipt_max) is int and receipt_max > 0, 'unsupported_name_limit')
        require(len(os.fsencode(environment.receipt_name)) <= receipt_max,
                'unmaterializable_path')


def _receipt(plan_receipt, *, operation):
    return {key: value for key, value in plan_receipt.items()
            if key not in {'scope', 'record_metadata', 'application_candidate_qualified'}} | {
        'scope': 'offline-factory-studio-bundle-install', 'operation': operation,
        'record_metadata': 'inspected-root-owned-no-xattrs', 'bundle_verified': True,
        'support_verified': False, 'image_code_executed': False,
        'application_code_executed': False, 'runtime_qualified': False, 'hardware_qualified': False}


def _verify(environment, bundle, manifest, expected):
    _check_destination(environment, bundle)
    all_records = dict(expected, **{'manifest.json': planner.exporter.file_record(manifest)})
    require(_inventory(environment.rootfs, bundle) == all_records, 'bundle_mismatch')
    require(_read_file(environment.rootfs, bundle, 'manifest.json', MAX_MANIFEST) == manifest,
            'bundle_manifest_mismatch')
    environment.check()
    _check_destination(environment, bundle)


def _check_destination(environment, bundle):
    opened, current = [], environment.root.fd
    try:
        for part in DESTINATION:
            current = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            opened.append(current)
            _trust(environment.rootfs, os.fstat(current))
        require(_identity(os.fstat(current)) == _identity(os.fstat(bundle)), 'destination_changed')
    finally:
        for fd in reversed(opened):
            os.close(fd)


def install_bundle(rootfs, input_manifest, input_sha256, sources_dir, wheels_dir, *, receipt_output):
    environment = None
    opened = []
    try:
        environment = Environment(rootfs, input_manifest, sources_dir, wheels_dir,
                                  receipt_output, installing=True)
        manifest, expected, plan_receipt = _expected(input_manifest, input_sha256, sources_dir, wheels_dir)
        _preflight_paths(environment, expected)
        payload = _payload(environment, input_sha256, expected)
        environment.check()
        parent = environment.destination_parent
        for name in environment.parent_dirs:
            parent = _mkdir(environment.rootfs, parent, name); opened.append(parent)
        bundle = _mkdir(environment.rootfs, parent, DESTINATION[-1]); opened.append(bundle)
        for name, record in sorted(expected.items(), key=lambda item: (item[0].count('/'), item[0])):
            if name == '.':
                continue
            parent_fd, leaf, parents = _parent_fd(bundle, name)
            try:
                if record['type'] == 'directory':
                    child = _mkdir(environment.rootfs, parent_fd, leaf); os.close(child)
                elif record['type'] == 'file':
                    _write_file(environment.rootfs, parent_fd, leaf, payload[name], record['mode'])
                else:
                    require(record['type'] == 'symlink', 'unsupported_record')
                    _write_symlink(environment.rootfs, parent_fd, leaf, record['target'])
            finally:
                for fd in reversed(parents):
                    os.close(fd)
        _check_destination(environment, bundle)
        require(_inventory(environment.rootfs, bundle) == expected, 'bundle_mismatch_before_manifest')
        _payload(environment, input_sha256, expected)
        _write_file(environment.rootfs, bundle, 'manifest.json', manifest, '0644')
        _verify(environment, bundle, manifest, expected)
        receipt = _receipt(plan_receipt, operation='install')
        _write_file(environment.rootfs, environment.receipt.fd, environment.receipt_name,
                    planner.canonical(receipt), '0600')
        require(_read_file(environment.rootfs, environment.receipt.fd,
                           environment.receipt_name, 1024 * 1024) == planner.canonical(receipt),
                'receipt_readback_failed')
        return receipt
    except Refused:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError, RuntimeError):
        raise Refused('installation_failed') from None
    finally:
        for fd in reversed(opened):
            os.close(fd)
        if environment is not None:
            environment.close()


def verify_bundle(rootfs, input_manifest, input_sha256, sources_dir, wheels_dir):
    environment = None
    bundle = None
    try:
        environment = Environment(rootfs, input_manifest, sources_dir, wheels_dir,
                                  None, installing=False)
        manifest, expected, plan_receipt = _expected(input_manifest, input_sha256, sources_dir, wheels_dir)
        _preflight_paths(environment, expected)
        _payload(environment, input_sha256, expected)
        bundle = os.open(DESTINATION[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                         dir_fd=environment.destination_parent)
        _verify(environment, bundle, manifest, expected)
        return _receipt(plan_receipt, operation='verify')
    except Refused:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError, RuntimeError):
        raise Refused('verification_failed') from None
    finally:
        if bundle is not None:
            os.close(bundle)
        if environment is not None:
            environment.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-sha256', required=True)
    for field in ('rootfs', 'input-manifest', 'sources-dir', 'wheels-dir', 'receipt'):
        parser.add_argument('--' + field, type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        install_bundle(args.rootfs, args.input_manifest, args.input_sha256,
                       args.sources_dir, args.wheels_dir, receipt_output=args.receipt)
    except Refused as error:
        print('factory_studio_install_refused:' + error.reason, file=sys.stderr)
        return 1
    print('Pinned bundle materialized and inspected; no target code executed or runtime qualified.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
