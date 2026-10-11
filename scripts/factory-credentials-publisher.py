"""STAGING ONLY: collect one Studio serializer result and publish opaque bytes.

No CLI, installation, permission creation or authorization creation. The
factory hook MUST first consume and fsync its permission, hold its stable lock,
verify the exporter bundle/system support and exclude app/helper/data writers.
This module neither proves those conditions nor accepts a boolean as their proof.

The factory-exporter-v2 interpreter runs only after dropping uid/gid/groups. Its
pure serializer contract excludes forks and data writes; a process group is
cleanup for a failed invocation, not confinement of hostile descendants. Service
startup ordering, source integrity and cgroup lifecycle remain external duties.

The 30-second producer budget includes bounded reaping. Process creation and
filesystem syscalls (including fsync) can still block in the kernel; this module
does not claim to cancel them. A failure always requires explicit recovery once
the caller consumed its permission. No retry, replacement, unlink or rollback.
Underscored injection arguments are accepted only for synthetic roots.
"""
import math
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time


APP_UID = APP_GID = 1000
DATA = Path('var/lib/inky-studio')
NAME = 'credentials.json'
MAX_OUTPUT = 8192
PRODUCER_TIMEOUT = 30.0
ARGV = (
    '/usr/lib/inkyos/factory-exporter/venv/bin/python', '-I', '-B', '-m',
    'inky_web.provisioning.factory_credentials', '--emit-v2',
)
CWD = '/'
ENV = {'HOME': '/home/inky', 'PATH': '/usr/bin:/bin',
       'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
ERRORS = frozenset({
    'configuration_invalid', 'data_unavailable', 'producer_failed',
    'producer_output_invalid', 'producer_timeout', 'producer_unreaped',
    'publication_failed',
})


class PublisherError(ValueError):
    """Only closed error codes may cross the factory boundary."""
    def __init__(self, code):
        self.code = code if code in ERRORS else 'publication_failed'
        super().__init__(self.code)


def _require(value, code):
    if not value:
        raise PublisherError(code)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _stamp(info):
    return (*_identity(info), info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _open_data(root, uid, gid):
    """Open each component without links; production ancestors must be root-owned."""
    path = root / DATA
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    identities = []
    try:
        for index, name in enumerate(('', *path.parts[1:])):
            if name:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=fd)
                os.close(fd)
                fd = child
            info = os.fstat(fd)
            final = index == len(path.parts) - 1
            _require(stat.S_ISDIR(info.st_mode)
                     and not stat.S_IMODE(info.st_mode) & 0o022,
                     'data_unavailable')
            if final:
                _require(info.st_uid == uid and info.st_gid == gid
                         and stat.S_IMODE(info.st_mode) == 0o700, 'data_unavailable')
            else:
                _require(info.st_uid in {0, os.geteuid()}, 'data_unavailable')
            identities.append(_identity(info))
        return fd, identities
    except BaseException:
        os.close(fd)
        raise


def _revalidate_data(root, uid, gid, parent, identities, names):
    current, observed = _open_data(root, uid, gid)
    try:
        _require(observed == identities
                 and _identity(os.fstat(parent)) == identities[-1]
                 and set(os.listdir(parent)) == names, 'data_unavailable')
    finally:
        os.close(current)


def _stop(process, deadline):
    """Signal the invocation's group, then reap only within the remaining budget."""
    deadline = min(deadline, time.monotonic() + 0.5)
    # Never signal a PID/PGID after reaping, when its number may be reused.
    # The reviewed serializer must not fork; escaped/remaining descendants are
    # an external service-confinement concern, not proven by this observation.
    if process.poll() is not None:
        return True
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        # Some platforms refuse killpg for an already-exited group. Observe the
        # direct child's state even then; this is not proof about descendants.
        pass
    while True:
        if process.poll() is not None:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))


def _collect(spawn, timeout):
    deadline = time.monotonic() + timeout
    work_deadline = deadline - min(0.5, timeout / 5)
    process = None
    try:
        process = spawn(
            ARGV, shell=False, cwd=CWD, env=dict(ENV),
            user=APP_UID, group=APP_GID, extra_groups=[],
            start_new_session=True, close_fds=True, umask=0o077,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=False, bufsize=0,
        )
        _require(process.stdout is not None, 'producer_failed')
        fd = process.stdout.fileno()
        os.set_blocking(fd, False)
        content, eof = bytearray(), False
        with selectors.DefaultSelector() as selector:
            selector.register(fd, selectors.EVENT_READ)
            while True:
                remaining = work_deadline - time.monotonic()
                _require(remaining > 0, 'producer_timeout')
                if eof and process.poll() is not None:
                    break
                for key, _ in selector.select(min(remaining, 0.05)):
                    try:
                        chunk = os.read(key.fd, MAX_OUTPUT + 1 - len(content))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        eof = True
                        selector.unregister(fd)
                        continue
                    content.extend(chunk)
                    _require(len(content) <= MAX_OUTPUT, 'producer_output_invalid')
        _require(process.returncode == 0, 'producer_failed')
        # poll() above has reaped the direct child. No publication before both
        # complete EOF and exit zero, even if a full line arrived much earlier.
        raw = bytes(content)
        _require(1 < len(raw) <= MAX_OUTPUT and raw.isascii()
                 and raw.endswith(b'\n') and raw.count(b'\n') == 1,
                 'producer_output_invalid')
        return raw
    except BaseException as error:
        reaped = process is None or _stop(process, deadline)
        if not reaped:
            raise PublisherError('producer_unreaped') from None
        if isinstance(error, PublisherError):
            raise PublisherError(error.code) from None
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise PublisherError('producer_failed') from None
    finally:
        if process is not None and process.stdout is not None:
            process.stdout.close()


def _publish(parent, raw, uid, gid, checkpoint):
    fd = os.open(NAME, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | os.O_NONBLOCK, 0o600, dir_fd=parent)
    try:
        os.fchmod(fd, 0o600)
        os.fchown(fd, uid, gid)
        checkpoint('file_created')
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            _require(written > 0, 'publication_failed')
            offset += written
        checkpoint('file_written')
        os.fsync(fd)
        checkpoint('file_synced')
        os.fsync(parent)
        checkpoint('directory_synced')
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_uid == uid and before.st_gid == gid
                 and stat.S_IMODE(before.st_mode) == 0o600
                 and before.st_size == len(raw), 'publication_failed')
        os.lseek(fd, 0, os.SEEK_SET)
        reread = bytearray()
        while len(reread) <= len(raw):
            chunk = os.read(fd, len(raw) + 1 - len(reread))
            if not chunk:
                break
            reread.extend(chunk)
        _require(bytes(reread) == raw
                 and _stamp(os.fstat(fd)) == _stamp(before)
                 and _stamp(os.stat(NAME, dir_fd=parent, follow_symlinks=False))
                 == _stamp(before), 'publication_failed')
    finally:
        os.close(fd)


def publish(*, _root=Path('/'), _app_uid=APP_UID, _app_gid=APP_GID,
            _timeout=PRODUCER_TIMEOUT, _spawn=None, _checkpoint=None):
    """Publish once under the caller's already-durable factory admission.

    Returns only {'status': 'published'}. Any exception requires recovery; a
    partial or complete credentials.json is intentionally left in place. There
    is no resume/inspect/create-authority path and no app format interpretation.
    Synthetic-root arguments are tests only, never part of a wire interface.
    """
    root = Path(_root)
    _require(root.is_absolute() and root.anchor == '/' and '..' not in root.parts
             and type(_app_uid) is int and type(_app_gid) is int
             and _app_uid >= 0 and _app_gid >= 0
             and type(_timeout) in (int, float) and math.isfinite(_timeout)
             and 0 < _timeout <= PRODUCER_TIMEOUT, 'configuration_invalid')
    if root == Path('/'):
        _require(sys.platform == 'linux' and os.geteuid() == 0
                 and (_app_uid, _app_gid, _timeout) == (APP_UID, APP_GID, PRODUCER_TIMEOUT)
                 and _spawn is None and _checkpoint is None, 'configuration_invalid')
    spawn = subprocess.Popen if _spawn is None else _spawn
    checkpoint = (lambda _: None) if _checkpoint is None else _checkpoint
    parent = None
    phase = 'guard'
    try:
        parent, identities = _open_data(root, _app_uid, _app_gid)
        _revalidate_data(root, _app_uid, _app_gid, parent, identities, set())
        checkpoint('data_checked')
        phase = 'producer'
        raw = _collect(spawn, _timeout)
        checkpoint('producer_finished')
        phase = 'publication'
        _revalidate_data(root, _app_uid, _app_gid, parent, identities, set())
        _publish(parent, raw, _app_uid, _app_gid, checkpoint)
        _revalidate_data(root, _app_uid, _app_gid, parent, identities, {NAME})
        checkpoint('published')
        return {'status': 'published'}
    except PublisherError:
        raise
    except (OSError, ValueError, TypeError, RuntimeError):
        raise PublisherError('data_unavailable' if phase == 'guard' else
                             'producer_failed' if phase == 'producer' else
                             'publication_failed') from None
    finally:
        if parent is not None:
            os.close(parent)
