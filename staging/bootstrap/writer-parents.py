#!/usr/bin/env python3
"""Fixed OS writer parents; no CLI, service lifecycle or private-state reader.

The trusted prepare-boot caller creates the context first. A separate exclusive
receipt directory latches this operation before the first runtime-parent mkdir.
Existing objects are never repaired, adopted, replaced or removed. The helper's
persistent parent is provisioned by the active assembler, not by this module.
"""
import hashlib
import grp
import json
import os
from pathlib import Path
import pwd
import stat


CONTEXT = 'run/inkyos-factory/context.json'
MANIFEST = 'etc/inkyos/factory-runtime-v1.json'
ADMISSION = 'run/inkyos-admission'
RECEIPT_DIR = 'run/inkyos-writer-parents'
RECEIPT = RECEIPT_DIR + '/parents.json'
RUNTIME_IPC = 'run/inkyos-bootstrap'
RUNTIME_HELPER = 'run/inky-network'
PERSISTENT = 'var/lib/inky-network'


class Refused(ValueError):
    def __init__(self, reason='writer_parents_refused'):
        self.reason = reason
        super().__init__(reason)


def require(value):
    if not value:
        raise Refused()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)
            + '\n').encode('ascii')


def owner(contract):
    # The existing contract's non-/ owner seam is for synthetic fixtures only.
    require(contract._root.is_absolute() and '..' not in contract._root.parts
            and (contract._root != Path('/') or (contract._uid, contract._gid) == (0, 0))
            and (os.getuid(), os.geteuid()) == (contract._uid, contract._uid)
            and (os.getgid(), os.getegid()) == (contract._gid, contract._gid))
    if hasattr(os, 'getresuid'):
        require(os.getresuid() == (contract._uid,) * 3
                and os.getresgid() == (contract._gid,) * 3)


def identities(contract):
    helper = contract.manifest['helper_uid']
    provisioning = contract.manifest['provisioning_gid']
    require(type(helper) is int and type(provisioning) is int
            and 1 <= helper <= 999 and 1 <= provisioning <= 999)
    app = pwd.getpwnam('inky')
    account = pwd.getpwnam('inky-network')
    group = grp.getgrnam('inky-provisioning')
    require(app.pw_uid == app.pw_gid == 1000
            and pwd.getpwuid(1000).pw_name == 'inky'
            and grp.getgrnam('inky').gr_gid == 1000
            and grp.getgrgid(1000).gr_name == 'inky'
            and account.pw_uid == helper and account.pw_gid == provisioning
            and pwd.getpwuid(helper).pw_name == 'inky-network'
            and group.gr_gid == provisioning
            and grp.getgrgid(provisioning).gr_name == 'inky-provisioning')
    return helper, provisioning


def context(contract):
    digest = contract.context_sha256
    with contract.tree() as tree:
        raw = tree.read(CONTEXT, 0o644, 1024)
    require(hashlib.sha256(raw).hexdigest() == digest == contract.context_sha256)
    value = json.loads(raw)
    require(type(value) is dict and set(value) == {'version', 'boot_id', 'candidate_sha256'}
            and value['version'] == 1 and value['candidate_sha256'] == contract.candidate_sha256)
    return value


def policies(contract, helper, provisioning):
    return {RUNTIME_IPC: (contract._uid, provisioning, 0o750),
            RUNTIME_HELPER: (helper, provisioning, 0o750),
            PERSISTENT: (helper, provisioning, 0o700)}


def record(tree, path, expected):
    """Inspect just the directory inode; never list or read helper contents."""
    parent, leaf = tree.parent(path)
    try:
        before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISDIR(before.st_mode)
                and (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) == expected)
        fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            observed = os.fstat(fd)
            current = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            def stable(info):
                return info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode
            require(stable(before) == stable(observed) == stable(current)
                    and not os.listxattr(fd))
            # Directory timestamps/nlink may change during legitimate writes.
            return {'dev': observed.st_dev, 'ino': observed.st_ino,
                    'uid': observed.st_uid, 'gid': observed.st_gid,
                    'mode': format(stat.S_IMODE(observed.st_mode), '04o')}
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def create_directory(tree, path, uid, gid, mode):
    parent, leaf = tree.parent(path)
    try:
        os.mkdir(leaf, 0o700, dir_fd=parent)
        fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            info = os.fstat(fd)
            require(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid) == (tree.uid, tree.gid)
                    and not os.listxattr(fd))
            if (uid, gid) != (info.st_uid, info.st_gid):
                os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)


def _verify(contract, helper, provisioning):
    expected_context = context(contract)
    with contract.tree() as tree:
        _, entries = tree.directory(RECEIPT_DIR, 0o755)
        require(entries == {'parents.json'})
        raw = tree.read(RECEIPT, 0o644, 4096)
        records = {path: record(tree, path, policy)
                   for path, policy in policies(contract, helper, provisioning).items()}
    expected = {**expected_context, 'parents': records}
    require(raw == canonical(expected) and context(contract) == expected_context)
    return {'status': 'writer_parents_verified'}


def _preflight(contract, helper, provisioning):
    with contract.tree() as tree:
        require(hashlib.sha256(tree.read(MANIFEST, 0o644, 16384)).hexdigest()
                == contract.candidate_sha256)
        tree.directory('run', 0o755)
        require(tree.absent(ADMISSION) and tree.absent(RECEIPT_DIR)
                and tree.absent(RUNTIME_IPC) and tree.absent(RUNTIME_HELPER))
        return record(tree, PERSISTENT, policies(contract, helper, provisioning)[PERSISTENT])


def preflight(contract):
    """Read-only prerequisite check, including before context creation."""
    try:
        owner(contract)
        helper, provisioning = identities(contract)
        _preflight(contract, helper, provisioning)
        return {'status': 'writer_parents_preflight'}
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise Refused() from None


def verify(contract):
    try:
        owner(contract)
        helper, provisioning = identities(contract)
        return _verify(contract, helper, provisioning)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise Refused() from None


def prepare(contract):
    try:
        owner(contract)
        helper, provisioning = identities(contract)
        expected_context = context(contract)
        policy = policies(contract, helper, provisioning)
        persistent = _preflight(contract, helper, provisioning)
        with contract.tree() as tree:
            require(context(contract) == expected_context)
            # A partial directory/receipt is deliberately never resumed.
            create_directory(tree, RECEIPT_DIR, contract._uid, contract._gid, 0o755)
            for path in (RUNTIME_IPC, RUNTIME_HELPER):
                require(tree.absent(ADMISSION))
                create_directory(tree, path, *policy[path])
            records = {path: record(tree, path, item) for path, item in policy.items()}
            require(records[PERSISTENT] == persistent and tree.absent(ADMISSION)
                    and context(contract) == expected_context)
            tree.create(RECEIPT, canonical({**expected_context, 'parents': records}), 0o644)
        _verify(contract, helper, provisioning)
        return {'status': 'writer_parents_prepared'}
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise Refused() from None
