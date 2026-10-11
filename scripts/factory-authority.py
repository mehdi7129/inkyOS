#!/usr/bin/env python3
"""Staging hook: consume an explicit factory permission before creating authority.

Not installed or activated by an image recipe. Never creates a permission, reads
app data, or infers factory state from missing data. Private arguments below are
fixture injection only; the production entry point accepts no arguments.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types


MARKER = Path('etc/inky-studio/factory-v1.json')
PERMISSION = Path('var/lib/inkyos/factory-permission')
AUTHORITY = Path('var/lib/inkyos/initialization')
SOURCE = Path('usr/local/lib/inkyos/initialization-receipt.py')
RECEIPT_SHA256 = '42d2e4ac0b38a3788d41dc4dd85a8df965a5c30fc88dbbfcbd6ed213c3e47de6'
MARKER_VALUE = {'version': 1, 'app_uid': 1000, 'data_dir': '/var/lib/inky-studio'}
PERMISSION_VALUE = {'version': 1, 'operation': 'create-initialization-authority'}
ERRORS = {'configuration_invalid', 'permission_unavailable', 'recovery_required', 'busy'}


class FactoryError(ValueError):
    def __init__(self, code):
        self.code = code if code in ERRORS else 'recovery_required'
        super().__init__(self.code)


def require(value, code='recovery_required'):
    if not value:
        raise FactoryError(code)


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def directory(path, uid, gid, *, private=False):
    require(path.is_absolute() and '..' not in path.parts)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in ('', *path.parts[1:]):
            if name:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = child
            info = os.fstat(fd)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid in {0, uid}
                    and not stat.S_IMODE(info.st_mode) & 0o022)
        require(info.st_uid == uid and info.st_gid == gid)
        if private:
            require(stat.S_IMODE(info.st_mode) == 0o700)
        yield fd
    finally:
        os.close(fd)


def ordinary(fd, uid, gid, mode):
    info = os.fstat(fd)
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == uid and info.st_gid == gid
            and stat.S_IMODE(info.st_mode) == mode)
    return info


def read_at(parent, name, uid, gid, mode, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        before = ordinary(fd, uid, gid, mode)
        require(0 < before.st_size <= limit)
        raw = os.read(fd, limit + 1)
        require(len(raw) == before.st_size and stamp(os.fstat(fd)) == stamp(before)
                and stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)) == stamp(before))
        return raw, stamp(before)
    finally:
        os.close(fd)


def read_file(path, uid, gid, mode, limit):
    with directory(path.parent, uid, gid) as parent:
        return read_at(parent, path.name, uid, gid, mode, limit)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def exact_json(raw, expected):
    value = json.loads(raw, object_pairs_hook=unique)
    require(type(value) is dict and set(value) == set(expected))
    require(all(type(value[k]) is type(v) and value[k] == v for k, v in expected.items()))


def bindings(root, uid, gid):
    marker, marker_stamp = read_file(root / MARKER, uid, gid, 0o644, 4096)
    exact_json(marker, MARKER_VALUE)
    raw, source_stamp = read_file(root / SOURCE, uid, gid, 0o555, 65536)
    require(hashlib.sha256(raw).hexdigest() == RECEIPT_SHA256)
    return raw, (marker_stamp, source_stamp)


def initialize(*, _root=Path('/'), _owner_uid=None, _owner_gid=None,
               _environ=None, _checkpoint=None):
    """Create once after durable permission consumption, or inspect on restart.

    The permission directory and empty stable lock must ALREADY exist, supplied
    by an explicit future opt-in image profile. No app path is inspected.
    """
    uid = 0 if _owner_uid is None else _owner_uid
    gid = 0 if _owner_gid is None else _owner_gid
    require(type(uid) is int and type(gid) is int and uid >= 0 and gid >= 0
            and os.geteuid() == uid, 'configuration_invalid')
    root = Path(_root)
    env = os.environ if _environ is None else _environ
    checkpoint = _checkpoint or (lambda _: None)
    require(env.get('INKY_STUDIO_FACTORY_REQUIRED') == '1'
            and env.get('INKY_STUDIO_DATA_DIR') == '/var/lib/inky-studio', 'configuration_invalid')
    try:
        raw, pinned = bindings(root, uid, gid)
        receipt = types.ModuleType('pinned_factory_receipt')
        exec(compile(raw, '<pinned-initialization-receipt>', 'exec'), receipt.__dict__)
    except (OSError, ValueError, UnicodeError, RecursionError):
        raise FactoryError('configuration_invalid') from None

    try:
        with directory(root / PERMISSION, uid, gid, private=True) as parent:
            lock = os.open('lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                lock_info = ordinary(lock, uid, gid, 0o600)
                require(lock_info.st_size == 0)
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise FactoryError('busy') from None

                def revalidate():
                    require(stamp(os.fstat(lock)) == stamp(lock_info)
                            and stamp(os.stat('lock', dir_fd=parent, follow_symlinks=False)) == stamp(lock_info))
                    with directory(root / PERMISSION, uid, gid, private=True) as current:
                        require((os.fstat(current).st_dev, os.fstat(current).st_ino)
                                == (os.fstat(parent).st_dev, os.fstat(parent).st_ino))
                    require(bindings(root, uid, gid)[1] == pinned)

                revalidate()
                names = set(os.listdir(parent))
                require(names in ({'lock', 'pending.json'}, {'lock', 'consumed.json'}))
                pending = 'pending.json' in names
                name = 'pending.json' if pending else 'consumed.json'
                content, permission_stamp = read_at(parent, name, uid, gid, 0o600, 4096)
                exact_json(content, PERMISSION_VALUE)
                checkpoint('validated')
                revalidate()
                require(set(os.listdir(parent)) == names
                        and stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)) == permission_stamp)
                authority = root / AUTHORITY
                if not pending:
                    result = receipt.inspect(authority, _owner_uid=uid, _owner_gid=gid)
                    revalidate()
                    return {'status': 'existing', 'authority_status': result['status']}

                # Any existing entry, including a dangling symlink, is ambiguous.
                # This check never treats missing app data as factory evidence.
                with directory(authority.parent, uid, gid, private=True) as state_parent:
                    require(authority.name not in os.listdir(state_parent))
                os.rename('pending.json', 'consumed.json', src_dir_fd=parent, dst_dir_fd=parent)
                checkpoint('permission_renamed')
                os.fsync(parent)
                checkpoint('permission_synced')
                revalidate()
                require(set(os.listdir(parent)) == {'lock', 'consumed.json'})
                consumed, _ = read_at(parent, 'consumed.json', uid, gid, 0o600, 4096)
                require(consumed == content)
                checkpoint('before_authority_create')
                result = receipt.create_authorization(authority, _owner_uid=uid, _owner_gid=gid)
                require(result == {'status': 'authorized'})
                checkpoint('authority_created')
                revalidate()
                return {'status': 'created', 'authority_status': 'authorized'}
            finally:
                os.close(lock)
    except FactoryError:
        raise
    except FileNotFoundError:
        raise FactoryError('permission_unavailable') from None
    except (OSError, ValueError, UnicodeError, RecursionError):
        raise FactoryError('recovery_required') from None


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        require(not args and sys.platform == 'linux' and os.geteuid() == 0, 'configuration_invalid')
        result = initialize()
    except FactoryError as exc:
        print(json.dumps({'status': 'refused', 'error': exc.code}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
