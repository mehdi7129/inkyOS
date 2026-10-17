#!/usr/bin/env python3
"""Prepare reserved accounts and empty persistent parents in an offline build.

This standalone primitive is not part of factory-assembly. It never executes
image code, grants factory authority, enables services or initializes app state.
The caller owns an exclusive builder workspace: there is no concurrent-writer
support, rollback, repair, adoption or retry after partial publication.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path


_spec = importlib.util.spec_from_file_location(
    '_factory_prerequisites_safety',
    Path(__file__).with_name('install-factory-studio-bundle-rootfs.py'))
safety = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(safety)
Refused, require = safety.Refused, safety.require
DATABASES = ('passwd', 'group', 'shadow', 'gshadow')
PARENTS = ('inky-studio', 'inky-network')
RESERVED = {'inky-network', 'inky-provisioning'}
NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}\$?')
NUMBER = re.compile(r'0|[1-9][0-9]{0,9}')
TEMPORARY = {name: '.inkyos-active-' + name + '.new' for name in DATABASES}
PASSWORD_LOCK = '.pwd.lock'
LOCKS = ('passwd.lock', 'group.lock', 'shadow.lock', 'gshadow.lock')
BACKUPS = tuple(name + '-' for name in (*DATABASES, 'subuid', 'subgid'))
POLKIT_NAME = '49-inky-network.rules'
# Exact heredoc from Studio 87c0820808a9824885c6009bf6b68354fb0dbbe9,
# scripts/install-bluetooth.sh (SHA-256 e0f301c97830860bcc1778579d7f4181370fb4cef8d64aeac4c226ab8aeafb69).
POLKIT_SHA256 = '894de12a283581ddbc0f50e5d86edf207ad936f9c456fb43f002ae67001643d3'
POLKIT_RAW = b'''polkit.addRule(function(action, subject) {
    if (subject.user !== "inky-network") return polkit.Result.NOT_HANDLED;
    var permitted = [
        "org.freedesktop.NetworkManager.wifi.scan",
        "org.freedesktop.NetworkManager.network-control",
        "org.freedesktop.NetworkManager.settings.modify.system",
        "org.freedesktop.NetworkManager.checkpoint-rollback"
    ];
    if (permitted.indexOf(action.id) !== -1) return polkit.Result.YES;
    return polkit.Result.NOT_HANDLED;
});
'''


def _production_environment(rootfs):
    # These helpers are patched only by explicit non-/ filesystem fixtures.
    require(sys.platform.startswith('linux')
            and (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) == (0, 0, 0, 0)
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0),
            'root_linux_builder_required')
    return safety._production_environment(rootfs)


def _owner_ids(rootfs):
    return safety._owner_ids(rootfs)


def _parent_ids(rootfs, app_uid, helper_uid, provisioning_gid):
    require(rootfs != Path('/'), 'host_root_refused')
    return {'inky-studio': (app_uid, app_uid),
            'inky-network': (helper_uid, provisioning_gid)}


def _xattrs(rootfs, target):
    return safety._xattrs(rootfs, target)


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read(rootfs, parent, name, modes, gids, limit=1024 * 1024):
    """Read bounded configuration without accepting links, ACLs or special files."""
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) in modes
            and before.st_uid == _owner_ids(rootfs)[0] and before.st_gid in gids
            and 0 <= before.st_size <= limit, 'unsafe_account_file')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        require(_signature(os.fstat(fd)) == _signature(before)
                and _xattrs(rootfs, fd) == safety.EMPTY_XATTRS, 'account_file_changed')
        raw = os.read(fd, limit + 1)
        require(len(raw) == before.st_size
                and _signature(os.fstat(fd)) == _signature(before)
                == _signature(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                'account_file_changed')
        return raw, before
    finally:
        os.close(fd)


def _number(value):
    require(NUMBER.fullmatch(value) is not None and int(value) <= 4294967294,
            'malformed_account_database')
    return int(value)


def _records(raw, columns):
    text = raw.decode('ascii')
    require(text.endswith('\n') and '\r' not in text
            and all(32 <= ord(character) <= 126 or character == '\n' for character in text),
            'malformed_account_database')
    records = [line.split(':') for line in text.splitlines()]
    require(records and len(records) <= 4096
            and all(len(row) == columns and NAME.fullmatch(row[0]) for row in records)
            and len({row[0] for row in records}) == len(records),
            'malformed_account_database')
    return {row[0]: row for row in records}


def _members(value, users):
    result = value.split(',') if value else []
    require(len(result) == len(set(result)) and set(result) <= users,
            'malformed_account_membership')
    return set(result)


def _nss(raw):
    """Refuse external/compat NSS authorities for the identities being reserved."""
    entries = {}
    for line in raw.decode('ascii').splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        name, separator, methods = line.partition(':')
        require(separator and name.strip() not in entries, 'nss_configuration_refused')
        entries[name.strip()] = methods.split()
    require(all(entries.get(name) in (['files'], ['files', 'systemd'])
                for name in ('passwd', 'group', 'shadow', 'gshadow')),
            'nss_configuration_refused')


def _accounts(raw, helper_uid, provisioning_gid, *, configured=False):
    users = _records(raw['passwd'], 7)
    groups = _records(raw['group'], 4)
    shadow = _records(raw['shadow'], 9)
    gshadow = _records(raw['gshadow'], 4)
    require(set(users) == set(shadow) and set(groups) == set(gshadow),
            'account_databases_disagree')
    uids = [_number(row[2]) for row in users.values()]
    gids = [_number(row[2]) for row in groups.values()]
    require(len(uids) == len(set(uids)) and len(gids) == len(set(gids))
            and users.get('root', [None] * 4)[2:4] == ['0', '0']
            and groups.get('root', [None] * 3)[2] == '0', 'account_id_collision')
    require(all(row[1] == 'x' and _number(row[3]) in gids for row in users.values())
            and all(row[1] == 'x' for row in groups.values()), 'account_credentials_refused')
    # Fresh image databases must contain locked markers, never password hashes.
    locked = {'!', '*', '!!', '!*'}
    require(all(row[1] in locked and all(not field or NUMBER.fullmatch(field)
                                      for field in row[2:]) for row in shadow.values())
            and all(row[1] in locked for row in gshadow.values()),
            'account_credentials_refused')
    for name, group in groups.items():
        require(_members(group[3], set(users)) == _members(gshadow[name][3], set(users)),
                'account_databases_disagree')
        require('inky' not in _members(gshadow[name][2], set(users)),
                'unexpected_app_group_privileges')
    require('pi' not in users and 'inky-test' not in users
            and users.get('inky', [None] * 7)[1:4] == ['x', '1000', '1000']
            and users['inky'][5:] == ['/home/inky', '/usr/sbin/nologin']
            and groups.get('inky', [None] * 4)[1:] == ['x', '1000', ''],
            'app_account_not_prepared')
    membership = {name for name, row in groups.items()
                  if row[2] == '1000' or 'inky' in _members(row[3], set(users))}
    expected = {'inky', 'spi', 'i2c', 'gpio'} | ({'inky-provisioning'} if configured else set())
    require(membership == expected, 'unexpected_app_group_privileges')
    # The runtime's check_identity() admits only named system-group IDs.
    require(all(1 <= _number(groups[name][2]) <= 999 for name in ('spi', 'i2c', 'gpio')),
            'hardware_group_ids_refused')
    if configured:
        require(users.get('inky-network') == ['inky-network', 'x', str(helper_uid),
                    str(provisioning_gid), '', '/nonexistent', '/usr/sbin/nologin']
                and groups.get('inky-provisioning') == ['inky-provisioning', 'x', str(provisioning_gid), 'inky']
                and shadow.get('inky-network') == ['inky-network', '!', '0', '0', '99999', '7', '', '', '']
                and gshadow.get('inky-provisioning') == ['inky-provisioning', '!', '', 'inky'],
                'reserved_account_mismatch')
        require({name for name, row in groups.items()
                 if row[2] == str(provisioning_gid) or 'inky-network' in _members(row[3], set(users))}
                == {'inky-provisioning'}, 'unexpected_helper_group_privileges')
    else:
        require(not RESERVED & (set(users) | set(groups) | set(shadow) | set(gshadow))
                and helper_uid not in uids and provisioning_gid not in gids,
                'reserved_account_collision')
    return groups


class Environment:
    def __init__(self, rootfs):
        self.directories = []
        self.policy_directory = None
        self.password_lock = None
        self.password_lock_info = None
        self.rootfs = safety._canonical_path(rootfs)
        require(self.rootfs != Path('/'), 'host_root_refused')
        work, trust_from = _production_environment(self.rootfs)
        try:
            def directory(path, mode):
                value = safety.Directory(self.rootfs, path, trust_from=trust_from)
                self.directories.append(value)
                require(stat.S_IMODE(os.fstat(value.fd).st_mode) == mode,
                        'unsafe_parent_directory')
                return value
            directory(work, 0o700)
            self.root = directory(self.rootfs, 0o755)
            self.etc = directory(self.rootfs / 'etc', 0o755)
            directory(self.rootfs / 'var', 0o755)
            self.lib = directory(self.rootfs / 'var/lib', 0o755)
            if trust_from is None:
                marker = safety.Directory(self.rootfs, Path('/var/lib/inkyos-build'))
                self.directories.append(marker)
                require(safety._read_file(self.rootfs, marker.fd, 'owner', 256)
                        == b'inkyos-builder-v1\n', 'builder_marker_required')
            self._acquire_password_lock()
        except BaseException:
            self.close()
            raise

    def _acquire_password_lock(self):
        try:
            info = os.stat(PASSWORD_LOCK, dir_fd=self.etc.fd, follow_symlinks=False)
        except FileNotFoundError:
            # The caller still guarantees an exclusive workspace. Never create
            # or normalize a lock, including during a read-only check.
            return
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == 0
                and stat.S_IMODE(info.st_mode) == 0o600
                and (info.st_uid, info.st_gid) == _owner_ids(self.rootfs),
                'unsafe_password_lock')
        self.password_lock = os.open(PASSWORD_LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
                                     dir_fd=self.etc.fd)
        self.password_lock_info = info
        self._check_password_lock()
        # lckpwdf-compatible POSIX record lock on the entire existing inode.
        # No other descriptor for this inode is opened/closed while it is held:
        # POSIX closes release a process's locks even on a different descriptor.
        fcntl.lockf(self.password_lock, fcntl.LOCK_EX | fcntl.LOCK_NB, 0, 0, os.SEEK_SET)
        self._check_password_lock()

    def _check_password_lock(self):
        if self.password_lock is None:
            require(safety._missing(self.etc.fd, PASSWORD_LOCK), 'password_lock_changed')
            return
        require(_signature(os.fstat(self.password_lock)) == _signature(self.password_lock_info)
                == _signature(os.stat(PASSWORD_LOCK, dir_fd=self.etc.fd, follow_symlinks=False))
                and _xattrs(self.rootfs, self.password_lock) == safety.EMPTY_XATTRS,
                'password_lock_changed')

    def check(self):
        for directory in self.directories:
            directory.check()
        self._check_password_lock()

    def close(self):
        if self.password_lock is not None:
            # Closing this last descriptor releases the POSIX lock only after
            # the readback (or refusal). The lock file itself stays untouched.
            os.close(self.password_lock)
            self.password_lock = None
        for directory in reversed(self.directories):
            directory.close()
        self.directories = []


def _load(environment):
    rootfs, etc = environment.rootfs, environment.etc.fd
    uid, gid = _owner_ids(rootfs)
    raw, metadata = {}, {}
    for name in ('passwd', 'group'):
        raw[name], metadata[name] = _read(rootfs, etc, name, {0o644}, {gid})
    groups = _records(raw['group'], 4)
    # Debian shadow files may be 0640 root:shadow or 0600 root:{root,shadow}.
    shadow_gid = _number(groups['shadow'][2]) if 'shadow' in groups else gid
    for name in ('shadow', 'gshadow'):
        raw[name], metadata[name] = _read(rootfs, etc, name, {0o600, 0o640}, {gid, shadow_gid})
        require(stat.S_IMODE(metadata[name].st_mode) != 0o640
                or 'shadow' in groups and metadata[name].st_gid == shadow_gid,
                'unsafe_account_file')
    nss, _ = _read(rootfs, etc, 'nsswitch.conf', {0o644}, {gid})
    _nss(nss)
    machine_id, _ = _read(rootfs, etc, 'machine-id', {0o444, 0o644}, {gid}, 256)
    require(machine_id == b'uninitialized\n', 'previously_booted_rootfs')
    for name in ('subuid', 'subgid'):
        if not safety._missing(etc, name):
            content, _ = _read(rootfs, etc, name, {0o644}, {gid})
            require(not any(line.split(b':', 1)[0] in {b'pi', b'inky', b'inky-network', b'inky-provisioning'}
                            for line in content.splitlines()), 'reserved_subordinate_ids')
    return raw, metadata


def _preflight(environment, helper_uid, provisioning_gid):
    require(type(helper_uid) is int and type(provisioning_gid) is int
            and 1 <= helper_uid <= 999 and 1 <= provisioning_gid <= 999,
            'reserved_system_ids_required')
    raw, metadata = _load(environment)
    _accounts(raw, helper_uid, provisioning_gid)
    _policy_preflight(environment, raw)
    require(all(safety._missing(environment.etc.fd, name)
                for name in (*LOCKS, *BACKUPS, *TEMPORARY.values()))
            and all(safety._missing(environment.lib.fd, name) for name in PARENTS),
            'existing_prerequisite_state')
    environment.check()
    return raw, metadata


def _policy_preflight(environment, raw):
    require(hashlib.sha256(POLKIT_RAW).hexdigest() == POLKIT_SHA256,
            'network_policy_source_changed')
    if environment.policy_directory is None:
        root_uid, root_gid = _owner_ids(environment.rootfs)
        groups = _records(raw['group'], 4)
        require('polkitd' in groups, 'polkit_group_missing')
        polkit_gid = _number(groups['polkitd'][2])
        require(1 <= polkit_gid <= 999, 'polkit_group_refused')
        parent = environment.etc.fd
        # Preserve Debian's existing root:polkitd0750 rules.d; never normalize it.
        for name, policies in (('polkit-1', {(root_gid, 0o755)}),
                               ('rules.d', {(root_gid, 0o755),
                                            (polkit_gid, 0o750), (polkit_gid, 0o755)})):
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(stat.S_ISDIR(before.st_mode) and before.st_uid == root_uid
                    and (before.st_gid, stat.S_IMODE(before.st_mode)) in policies,
                    'unsafe_network_policy_parent')
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                require(_signature(os.fstat(fd)) == _signature(before)
                        and _xattrs(environment.rootfs, fd) == safety.EMPTY_XATTRS,
                        'unsafe_network_policy_parent')
                held = safety._FdDirectory(environment.rootfs, fd, parent, name)
                environment.directories.append(held)
            except BaseException:
                os.close(fd)
                raise
            parent = fd
        environment.policy_directory = held
    environment.check()
    require(safety._missing(environment.policy_directory.fd, POLKIT_NAME),
            'network_policy_already_exists')


def _write_file(environment, name, raw, metadata):
    fd = os.open(TEMPORARY[name], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=environment.etc.fd)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and _xattrs(environment.rootfs, fd) == safety.EMPTY_XATTRS,
                'unsafe_created_file')
        if (info.st_uid, info.st_gid) != (metadata.st_uid, metadata.st_gid):
            os.fchown(fd, metadata.st_uid, metadata.st_gid)
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            require(count > 0, 'short_write')
            view = view[count:]
        os.fchmod(fd, stat.S_IMODE(metadata.st_mode))
        os.fsync(fd)
    finally:
        os.close(fd)


def _create_parent(environment, name, uid, gid):
    os.mkdir(name, 0o700, dir_fd=environment.lib.fd)
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                 dir_fd=environment.lib.fd)
    try:
        require(_xattrs(environment.rootfs, fd) == safety.EMPTY_XATTRS,
                'unsafe_created_directory')
        info = os.fstat(fd)
        if (info.st_uid, info.st_gid) != (uid, gid):
            os.fchown(fd, uid, gid)
        os.fchmod(fd, 0o700)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(environment.lib.fd)


def _verify(environment, expected, helper_uid, provisioning_gid, parent_ids):
    raw, _ = _load(environment)
    require(raw == expected, 'account_readback_mismatch')
    _accounts(raw, helper_uid, provisioning_gid, configured=True)
    require(all(safety._missing(environment.etc.fd, value) for value in TEMPORARY.values()),
            'incomplete_account_publication')
    for name, ids in parent_ids.items():
        before = os.stat(name, dir_fd=environment.lib.fd, follow_symlinks=False)
        require(stat.S_ISDIR(before.st_mode) and (before.st_uid, before.st_gid) == ids
                and stat.S_IMODE(before.st_mode) == 0o700, 'persistent_parent_mismatch')
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                     dir_fd=environment.lib.fd)
        try:
            require(_signature(os.fstat(fd)) == _signature(before)
                    and not os.listdir(fd)
                    and _xattrs(environment.rootfs, fd) == safety.EMPTY_XATTRS,
                    'persistent_parent_mismatch')
        finally:
            os.close(fd)
    policy, _ = _read(environment.rootfs, environment.policy_directory.fd,
                     POLKIT_NAME, {0o644}, {_owner_ids(environment.rootfs)[1]}, 4096)
    require(policy == POLKIT_RAW, 'network_policy_readback_mismatch')
    environment.check()


def configure(rootfs, helper_uid, provisioning_gid, *, check_only=False):
    environment = Environment(rootfs)
    try:
        raw, metadata = _preflight(environment, helper_uid, provisioning_gid)
        parent_ids = _parent_ids(environment.rootfs, 1000, helper_uid, provisioning_gid)
        if not check_only:
            additions = {
                'passwd': f'inky-network:x:{helper_uid}:{provisioning_gid}::/nonexistent:/usr/sbin/nologin\n',
                'group': f'inky-provisioning:x:{provisioning_gid}:inky\n',
                'shadow': 'inky-network:!:0:0:99999:7:::\n',
                'gshadow': 'inky-provisioning:!::inky\n',
            }
            expected = {name: raw[name] + additions[name].encode('ascii') for name in DATABASES}
            _accounts(expected, helper_uid, provisioning_gid, configured=True)
            # Repeat the whole read-only check immediately before exclusive staging.
            require(_preflight(environment, helper_uid, provisioning_gid)[0] == raw,
                    'prerequisites_changed')
            for name in DATABASES:
                _write_file(environment, name, expected[name], metadata[name])
            os.fsync(environment.etc.fd)
            # Recheck all originals before replacing any database. These four
            # renames are not one transaction: failures require a fresh build.
            current, current_metadata = _load(environment)
            require(current == raw and all(_signature(current_metadata[name]) == _signature(metadata[name])
                                          for name in DATABASES), 'account_file_changed')
            environment.check()
            for name in DATABASES:
                os.replace(TEMPORARY[name], name, src_dir_fd=environment.etc.fd,
                           dst_dir_fd=environment.etc.fd)
                os.fsync(environment.etc.fd)
            for name, ids in parent_ids.items():
                _create_parent(environment, name, *ids)
            safety._write_file(environment.rootfs, environment.policy_directory.fd,
                               POLKIT_NAME, POLKIT_RAW, '0644')
            _verify(environment, expected, helper_uid, provisioning_gid, parent_ids)
        return {'schema_version': 1, 'scope': 'offline-factory-active-prerequisites',
                'operation': 'check' if check_only else 'configure', 'passed': True,
                'helper_uid': helper_uid, 'provisioning_gid': provisioning_gid,
                'accounts_and_parents_prepared': not check_only,
                'network_policy_prepared': not check_only,
                'network_policy_sha256': POLKIT_SHA256,
                'image_code_executed': False, 'factory_authority_created': False,
                'services_enabled': False, 'runtime_qualified': False,
                'hardware_qualified': False, 'wifi_credentials_written': False}
    finally:
        environment.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--helper-uid', type=int, required=True)
    parser.add_argument('--provisioning-gid', type=int, required=True)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args(argv)
    try:
        result = configure(args.rootfs, args.helper_uid, args.provisioning_gid,
                           check_only=args.check_only)
    except (OSError, ValueError, TypeError, KeyError):
        # No paths, database contents, password fields or exception payloads leak.
        result = {'schema_version': 1, 'scope': 'offline-factory-active-prerequisites',
                  'passed': False, 'error': 'prerequisites_refused_or_incomplete',
                  'image_code_executed': False, 'factory_authority_created': False,
                  'runtime_qualified': False, 'hardware_qualified': False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
