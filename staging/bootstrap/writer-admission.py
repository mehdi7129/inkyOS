#!/usr/bin/env python3
"""Cooperative staging admission only; no CLI, worker, service or real-/run default.

The caller supplies a root containing run/. A trusted boot supervisor must keep
this tree stable and must retain each lease until all associated children drain.
No target code, signal, credential, authority or product-ready state is created.
"""
import contextlib
import fcntl
import os
from pathlib import Path
import stat


DIRECTORY = 'run/inkyos-admission'
ATTEMPTED = b'{"schema_version":1,"state":"attempted"}\n'
READY = b'{"schema_version":1,"state":"factory-complete"}\n'


class Refused(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def require(value, reason='invalid_state'):
    if not value:
        raise Refused(reason)


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def owner(uid, gid):
    require((os.geteuid(), os.getegid()) == (uid, gid), 'not_owner')


def directory(fd, uid, gid, mode=None):
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid) == (uid, gid)
            and not stat.S_IMODE(info.st_mode) & 0o7022
            and (mode is None or stat.S_IMODE(info.st_mode) == mode)
            and not os.listxattr(fd))


def open_root(root, uid, gid):
    path = Path(root)
    require(type(uid) is int and type(gid) is int and uid >= 0 and gid >= 0
            and callable(getattr(os, 'listxattr', None))
            and path.is_absolute() and '..' not in path.parts
            and (path != Path('/') or (uid, gid) == (0, 0)))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        directory(fd, uid, gid)
        return fd
    except BaseException:
        os.close(fd)
        raise


def child_directory(parent, name, uid, gid, mode=0o755):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        directory(fd, uid, gid, mode)
        return fd
    except BaseException:
        os.close(fd)
        raise


def regular(parent, name, uid, gid, expected):
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and (before.st_uid, before.st_gid) == (uid, gid)
            and stat.S_IMODE(before.st_mode) == 0o644 and before.st_size == len(expected))
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        require(stamp(os.fstat(fd)) == stamp(before) and not os.listxattr(fd)
                and os.read(fd, len(expected) + 1) == expected
                and stamp(os.fstat(fd)) == stamp(before)
                == stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)))
        return fd
    except BaseException:
        os.close(fd)
        raise


def create(parent, name, raw, uid, gid):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    try:
        if (os.fstat(fd).st_uid, os.fstat(fd).st_gid) != (uid, gid):
            os.fchown(fd, uid, gid)
        view = memoryview(raw)
        while view:
            count = os.write(fd, view); require(count > 0)
            view = view[count:]
        os.fchmod(fd, 0o644)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(parent)


def prepare(root, *, _owner_uid=0, _owner_gid=0):
    """Prepare once, explicitly. Never adopt, replace or repair an existing tree."""
    owner(_owner_uid, _owner_gid)
    fds = []
    try:
        root_fd = open_root(root, _owner_uid, _owner_gid); fds.append(root_fd)
        run = child_directory(root_fd, 'run', _owner_uid, _owner_gid); fds.append(run)
        os.mkdir('inkyos-admission', 0o700, dir_fd=run)
        child = os.open('inkyos-admission', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=run)
        fds.append(child)
        if (os.fstat(child).st_uid, os.fstat(child).st_gid) != (_owner_uid, _owner_gid):
            os.fchown(child, _owner_uid, _owner_gid)
        os.fchmod(child, 0o755)
        create(child, 'lock', b'', _owner_uid, _owner_gid)
        os.fsync(run)
    except (OSError, TypeError):
        raise Refused('invalid_state') from None
    finally:
        for fd in reversed(fds): os.close(fd)


class Lease:
    """A live flock descriptor. close() never issues LOCK_UN; dup/fork retain it."""
    def __init__(self, root, uid, gid, exclusive):
        self.root, self.uid, self.gid = root, uid, gid
        self.exclusive, self.pid = exclusive, os.getpid()
        self._fds = []
        try:
            self.root_fd = open_root(root, uid, gid); self._fds.append(self.root_fd)
            self.run = child_directory(self.root_fd, 'run', uid, gid); self._fds.append(self.run)
            self.parent = child_directory(self.run, 'inkyos-admission', uid, gid); self._fds.append(self.parent)
            self.fd = regular(self.parent, 'lock', uid, gid, b''); self._fds.append(self.fd)
            self._stamp = stamp(os.fstat(self.fd))
            try:
                fcntl.flock(self.fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Refused('busy') from None
            self.check()
        except BaseException:
            self.close()
            raise

    def fileno(self):
        require(bool(self._fds))
        return self.fd

    def check(self):
        require(bool(self._fds))
        current = open_root(self.root, self.uid, self.gid)
        try:
            require((os.fstat(current).st_dev, os.fstat(current).st_ino)
                    == (os.fstat(self.root_fd).st_dev, os.fstat(self.root_fd).st_ino))
        finally:
            os.close(current)
        for parent, name, fd in ((self.root_fd, 'run', self.run), (self.run, 'inkyos-admission', self.parent)):
            directory(fd, self.uid, self.gid, 0o755)
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require((info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
                    == (os.fstat(fd).st_dev, os.fstat(fd).st_ino, os.fstat(fd).st_mode,
                        os.fstat(fd).st_uid, os.fstat(fd).st_gid))
        require(stamp(os.fstat(self.fd)) == self._stamp
                == stamp(os.stat('lock', dir_fd=self.parent, follow_symlinks=False)))
        fd = regular(self.parent, 'lock', self.uid, self.gid, b'')
        os.close(fd)

    def state(self):
        self.check()
        names = set(os.listdir(self.parent))
        require(names in ({'lock'}, {'lock', 'attempted'}, {'lock', 'attempted', 'Ready'}))
        for name, raw in (('attempted', ATTEMPTED), ('Ready', READY)):
            if name in names:
                fd = regular(self.parent, name, self.uid, self.gid, raw)
                os.close(fd)
        self.check()
        return names

    def publish_ready(self):
        """Owner's explicit assertion only: this does not inspect a hook/cgroup/pin."""
        owner(self.uid, self.gid)
        require(self.exclusive and os.getpid() == self.pid, 'not_owner')
        try:
            require(self.state() == {'lock', 'attempted'})
        except (OSError, TypeError):
            raise Refused('invalid_state') from None
        try:
            create(self.parent, 'Ready', READY, self.uid, self.gid)
            self.check()
        except (OSError, TypeError, Refused):
            # A complete Ready may already be visible after EX is released.
            # External success checks must have finished BEFORE this call.
            raise Refused('publication_uncertain') from None

    def close(self):
        fds, self._fds = self._fds, []
        for fd in reversed(fds): os.close(fd)


def acquire(root, uid, gid, exclusive):
    try:
        return Lease(root, uid, gid, exclusive)
    except (OSError, TypeError):
        raise Refused('invalid_state') from None


@contextlib.contextmanager
def factory(root, *, _owner_uid=0, _owner_gid=0):
    owner(_owner_uid, _owner_gid)
    lease = acquire(root, _owner_uid, _owner_gid, True)
    try:
        try:
            names = lease.state()
            require('Ready' not in names, 'already_ready')
            require('attempted' not in names, 'recovery_required')
            create(lease.parent, 'attempted', ATTEMPTED, _owner_uid, _owner_gid)
            lease.check()
        except (OSError, TypeError):
            raise Refused('invalid_state') from None
        yield lease
    finally:
        lease.close()


@contextlib.contextmanager
def writer(root, *, _owner_uid=0, _owner_gid=0):
    lease = acquire(root, _owner_uid, _owner_gid, False)
    try:
        try:
            require(lease.state() == {'lock', 'attempted', 'Ready'}, 'not_ready')
        except (OSError, TypeError):
            raise Refused('invalid_state') from None
        yield lease
    finally:
        lease.close()
