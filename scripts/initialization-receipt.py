#!/usr/bin/env python3
"""Uninstalled model of an explicit, one-use OS initialization authorization.

No CLI, image hook, application import, credential or protocol implementation.
A trusted caller explicitly creates a BRAND-NEW directory outside app data;
missing app state is never evidence of authorization. Production ownership is
root:root. The private _owner_uid/_owner_gid arguments exist only for fixtures.

begin() durably consumes authorization BEFORE a caller may create_factory().
Only the call completing both durable writes returns ``newly_consumed``.
``already_consumed`` means reopen an EXISTING store only, never recreate one.
A crash after consumption but before DB creation therefore requires recovery.
An uncertain/interrupted write fails closed; it never produces a new grant.

The stable lock inode serializes readers/writers. Files are replaced atomically
and both file and directory are fsynced. A separate durable consumption record
precedes the terminal state, making incomplete transitions detectable. Missing,
corrupt or inconsistent records in an existing directory require recovery.
This local model cannot detect restoration of a complete old filesystem image.
The digest is an opaque internal binding, NOT cryptographic authorization.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import uuid


class ReceiptError(ValueError):
    """Invalid request or unsafe state location."""


class RecoveryRequired(ReceiptError):
    """Existing state is uncertain: explicit recovery is required."""


class IntentConflict(ReceiptError):
    """An authorization has already been consumed for another intent."""


def _canonical_uuid(value):
    if not isinstance(value, str):
        raise ReceiptError('Canonical lowercase UUID required')
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError
    except ValueError as exc:
        raise ReceiptError('Canonical lowercase UUID required') from exc
    return value


def _ownership(_owner_uid, _owner_gid):
    uid = 0 if _owner_uid is None else _owner_uid
    gid = 0 if _owner_gid is None else _owner_gid
    if type(uid) is not int or type(gid) is not int or uid < 0 or gid < 0 or os.geteuid() != uid:
        raise ReceiptError('Expected state owner must execute the operation')
    return uid, gid


def _check_directory(fd, uid, gid, *, leaf=False):
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, uid}
            or stat.S_IMODE(info.st_mode) & 0o022):
        raise ReceiptError('State ancestors must be trusted and not group/other writable')
    if leaf and (info.st_uid != uid or info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o700):
        raise RecoveryRequired('State directory ownership/mode changed')


@contextmanager
def _parent(path, uid, gid):
    path = Path(path)
    if not path.is_absolute() or len(path.parts) < 2 or '..' in path.parts:
        raise ReceiptError('Absolute canonical state directory required')
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _check_directory(fd, uid, gid)
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            _check_directory(fd, uid, gid)
        if os.fstat(fd).st_uid != uid:
            raise ReceiptError('Immediate parent must belong to the state owner')
        yield fd, path.name
    finally:
        os.close(fd)


def _ordinary(fd, uid, gid):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != uid
            or info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o600):
        raise RecoveryRequired('State files must be private single-link ordinary files')
    return info


def _encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RecoveryRequired('Duplicate state key')
        result[key] = value
    return result


def _read(directory, name, uid, gid):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            info = _ordinary(fd, uid, gid)
            if not 0 < info.st_size <= 4096:
                raise RecoveryRequired('State record size invalid')
            raw = os.read(fd, 4097)
            if len(raw) != info.st_size:
                raise RecoveryRequired('State record changed')
            return json.loads(raw, object_pairs_hook=_unique)
        finally:
            os.close(fd)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RecoveryRequired('State record unavailable or corrupt') from exc


def _atomic_write(directory, name, value, uid, gid):
    # Keep interrupted temporary files as evidence. Never remove/reuse them.
    fd = os.open('.write.pending', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=directory)
    try:
        os.fchmod(fd, 0o600); os.fchown(fd, uid, gid)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(_encode(value)); stream.flush(); os.fsync(fd)
    finally:
        os.close(fd)
    os.replace('.write.pending', name, src_dir_fd=directory, dst_dir_fd=directory)
    os.fsync(directory)


def _binding(authorization, intent, receipt_id):
    material = ['inkyos-initialization-receipt-v1', authorization, intent, receipt_id]
    return hashlib.sha256(_encode(material)).hexdigest()


def _validate_record(value, *, consumed):
    keys = {'schema_version', 'state', 'authorization_id'}
    if consumed:
        keys |= {'intent', 'receipt'}
    if (not isinstance(value, dict) or set(value) != keys or type(value['schema_version']) is not int
            or value['schema_version'] != 1 or value['state'] != ('consumed' if consumed else 'authorized')):
        raise RecoveryRequired('State schema invalid')
    try:
        _canonical_uuid(value['authorization_id'])
        if consumed:
            _canonical_uuid(value['intent'])
            receipt = value['receipt']
            if not isinstance(receipt, dict) or set(receipt) != {'receipt_id', 'digest'}:
                raise ReceiptError('Receipt schema invalid')
            _canonical_uuid(receipt['receipt_id'])
            if receipt['digest'] != _binding(value['authorization_id'], value['intent'], receipt['receipt_id']):
                raise ReceiptError('Receipt binding invalid')
    except ReceiptError as exc:
        raise RecoveryRequired('State binding invalid') from exc
    return value


@contextmanager
def _locked(path, uid, gid, *, exclusive):
    with _parent(path, uid, gid) as (parent, name):
        directory = None; lock = None
        try:
            directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            _check_directory(directory, uid, gid, leaf=True)
            lock = os.open('lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            if _ordinary(lock, uid, gid).st_size != 0:
                raise RecoveryRequired('Lock record changed')
            fcntl.flock(lock, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            if os.stat('lock', dir_fd=directory, follow_symlinks=False).st_ino != os.fstat(lock).st_ino:
                raise RecoveryRequired('Stable lock was replaced')
            yield directory
        except OSError as exc:
            raise RecoveryRequired('Authorization state unavailable; never infer factory state') from exc
        finally:
            if lock is not None:
                os.close(lock)
            if directory is not None:
                os.close(directory)


def _load(directory, uid, gid):
    names = set(os.listdir(directory))
    if names not in ({'lock', 'state.json'}, {'lock', 'state.json', 'consumption.json'}):
        raise RecoveryRequired('Missing, extra or interrupted state records')
    state = _read(directory, 'state.json', uid, gid)
    consumed = isinstance(state, dict) and state.get('state') == 'consumed'
    _validate_record(state, consumed=consumed)
    if consumed:
        if 'consumption.json' not in names or _validate_record(
                _read(directory, 'consumption.json', uid, gid), consumed=True) != state:
            raise RecoveryRequired('Consumption records missing or inconsistent')
    elif 'consumption.json' in names:
        raise RecoveryRequired('Consumption started; interrupted transition requires recovery')
    return state


def create_authorization(path, *, _owner_uid=None, _owner_gid=None):
    """Explicit trusted action; a pre-existing directory is NEVER reused."""
    uid, gid = _ownership(_owner_uid, _owner_gid)
    with _parent(path, uid, gid) as (parent, name):
        # A crash at any point leaves a directory that create() refuses to reuse.
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
        except FileExistsError as exc:
            raise RecoveryRequired('Existing authorization directory is never recreated') from exc
        os.fsync(parent)
        directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            os.fchmod(directory, 0o700); os.fchown(directory, uid, gid)
            lock = os.open('lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                           0o600, dir_fd=directory)
            try:
                os.fchmod(lock, 0o600); os.fchown(lock, uid, gid)
                fcntl.flock(lock, fcntl.LOCK_EX)
                os.fsync(lock); os.fsync(directory)
                state = {'schema_version': 1, 'state': 'authorized',
                         'authorization_id': str(uuid.uuid4())}
                _atomic_write(directory, 'state.json', state, uid, gid)
            finally:
                os.close(lock)
        finally:
            os.close(directory)
    return {'status': 'authorized'}


def inspect(path, *, _owner_uid=None, _owner_gid=None):
    """Read-only inspection; missing/corrupt state raises RecoveryRequired."""
    uid, gid = _ownership(_owner_uid, _owner_gid)
    with _locked(path, uid, gid, exclusive=False) as directory:
        state = _load(directory, uid, gid)
    result = {'status': state['state']}
    if state['state'] == 'consumed':
        result.update(intent=state['intent'], receipt=state['receipt'])
    return result


def begin(path, intent, *, _owner_uid=None, _owner_gid=None):
    """Consume once. A retry may reopen an existing DB; it may NEVER create it."""
    _canonical_uuid(intent)
    uid, gid = _ownership(_owner_uid, _owner_gid)
    with _locked(path, uid, gid, exclusive=True) as directory:
        state = _load(directory, uid, gid)
        if state['state'] == 'consumed':
            if state['intent'] != intent:
                raise IntentConflict('Initialization authorization belongs to another intent')
            return {'status': 'already_consumed', 'intent': intent, 'receipt': state['receipt']}
        receipt_id = str(uuid.uuid4())
        consumed = {**state, 'state': 'consumed', 'intent': intent,
                    'receipt': {'receipt_id': receipt_id,
                                'digest': _binding(state['authorization_id'], intent, receipt_id)}}
        try:
            # The first durable write records irreversible consumption intent.
            # Even when the second write is uncertain, no retry issues a grant.
            _atomic_write(directory, 'consumption.json', consumed, uid, gid)
            _atomic_write(directory, 'state.json', consumed, uid, gid)
        except OSError as exc:
            raise RecoveryRequired('Consumption write uncertain; recover, never create a new store') from exc
    return {'status': 'newly_consumed', 'intent': intent, 'receipt': consumed['receipt']}
