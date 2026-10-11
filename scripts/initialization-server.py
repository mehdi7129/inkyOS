#!/usr/bin/env python3
"""Staged IPC-A server; not installed or activated by any image recipe.

The only authority is an existing initialization-receipt state. A killed or
unanswered begin is uncertain, never rolled back. One child isolates blocking
flock/fsync during requests. Shutdown retains both writer and server locks until
that child is actually reaped, even when kernel I/O cannot be interrupted.
"""
import contextlib
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import struct
import sys
import time
import types
import uuid

SOCKET = Path('/run/inkyos-bootstrap/control.sock')
STATE = Path('/var/lib/inkyos/initialization')
RECEIPT_SOURCE = Path('/usr/local/lib/inkyos/initialization-receipt.py')
RECEIPT_SHA256 = '42d2e4ac0b38a3788d41dc4dd85a8df965a5c30fc88dbbfcbd6ed213c3e47de6'
RUNTIME_SOURCE = Path('/usr/lib/inkyos/factory-runtime-contract.py')
RUNTIME_MANIFEST = Path('/etc/inkyos/factory-runtime-v1.json')
SERVER_SOURCE = Path('/usr/local/lib/inkyos/initialization-server.py')
APP_UID = 1000
GROUP = 'inky-provisioning'
REQUEST_LIMIT = 1024
RESPONSE_LIMIT = 2048
DEADLINE_SECONDS = 3.0
REPLY_RESERVE = 0.05
NOTIFY_TIMEOUT_SECONDS = 1.0
ERRORS = {'invalid_request', 'forbidden', 'unavailable', 'intent_conflict',
          'initialization_uncertain'}


class WriterRefused(ValueError):
    pass


def writer_require(condition):
    if not condition:
        raise WriterRefused('writer_admission_refused')


def file_stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def public_source(path, mode, limit):
    """Fixed public OS bootstrap only, before importing the contract module."""
    writer_require(callable(getattr(os, 'listxattr', None)))
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(parent)
        writer_require((info.st_uid, info.st_gid) == (0, 0)
                       and not stat.S_IMODE(info.st_mode) & 0o7022 and not os.listxattr(parent))
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent); parent = child
            info = os.fstat(parent)
            writer_require((info.st_uid, info.st_gid) == (0, 0)
                           and not stat.S_IMODE(info.st_mode) & 0o7022 and not os.listxattr(parent))
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        writer_require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                       and (before.st_uid, before.st_gid) == (0, 0)
                       and stat.S_IMODE(before.st_mode) == mode and 0 < before.st_size <= limit)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            writer_require(file_stamp(before) == file_stamp(os.fstat(fd)) and not os.listxattr(fd))
            raw = os.read(fd, limit + 1)
            writer_require(len(raw) == before.st_size and file_stamp(before) == file_stamp(os.fstat(fd))
                           == file_stamp(os.stat(path.name, dir_fd=parent, follow_symlinks=False)))
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def load_runtime():
    writer_require(Path(__file__) == SERVER_SOURCE)
    manifest = decode(public_source(RUNTIME_MANIFEST, 0o644, 16384))
    writer_require(type(manifest) is dict and type(manifest.get('os_module_pins')) is dict)
    pin = manifest['os_module_pins'].get(RUNTIME_SOURCE.name)
    raw = public_source(RUNTIME_SOURCE, 0o555, 1024 * 1024)
    writer_require(type(pin) is str and re.fullmatch('[0-9a-f]{64}', pin)
                   and hashlib.sha256(raw).hexdigest() == pin)
    module = types.ModuleType('initialization_writer_contract')
    module.__file__ = str(RUNTIME_SOURCE)
    exec(compile(raw, str(RUNTIME_SOURCE), 'exec'), module.__dict__)
    return module


@contextlib.contextmanager
def writer_guard(*, _runtime=None, _contract=None, _environ=None):
    """Bootstrap trusted OS code, then delegate admission to the common guard."""
    with contextlib.ExitStack() as stack:
        try:
            if _contract is None:
                writer_require(_runtime is None and _environ is None)
                runtime = load_runtime()
                context = runtime.writer_guard('ipc')
            else:
                root = Path(_contract._root)
                writer_require(_runtime is not None and root.is_absolute()
                               and root != Path('/') and root == root.resolve(strict=True))
                context = _runtime.writer_guard('ipc', _contract=_contract, _environ=_environ)
            lease = stack.enter_context(context)
        except Exception:
            raise WriterRefused('writer_admission_refused') from None
        yield lease


class StopFlag:
    def __init__(self):
        self.requested = False

    def __call__(self):
        return self.requested

    def request(self, *_):
        self.requested = True


class InvalidRequest(ValueError):
    def __init__(self, request_id=None):
        self.request_id = request_id


def canonical_uuid(value):
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate')
        result[key] = value
    return result


def nonfinite(_):
    raise ValueError('nonfinite')


def decode(raw):
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                      parse_constant=nonfinite)


def parse_request(raw):
    if (type(raw) is not bytes or not 0 < len(raw) <= REQUEST_LIMIT
            or not raw.endswith(b'\n') or b'\n' in raw[:-1]):
        raise InvalidRequest()
    try:
        value = decode(raw[:-1])
    except (ValueError, UnicodeError, RecursionError):
        raise InvalidRequest() from None
    request_id = value.get('id') if type(value) is dict else None
    request_id = request_id if canonical_uuid(request_id) else None
    if type(value) is not dict or type(value.get('op')) is not str:
        raise InvalidRequest(request_id)
    op = value['op']
    fields = {'v', 'id', 'op'} | ({'intent'} if op == 'initialization.begin' else set())
    if (set(value) != fields or type(value.get('v')) is not int or value['v'] != 1
            or request_id is None or op not in {'initialization.inspect', 'initialization.begin'}
            or (op == 'initialization.begin' and not canonical_uuid(value['intent']))):
        raise InvalidRequest(request_id)
    return value


def error(request_id, code):
    if code not in ERRORS:
        code = 'unavailable'
    return {'v': 1, 'id': request_id, 'ok': False, 'error': code}


def encode(value):
    raw = (json.dumps(value, separators=(',', ':'), sort_keys=True, allow_nan=False) + '\n').encode('ascii')
    if len(raw) > RESPONSE_LIMIT:
        raise ValueError('response too large')
    return raw


def validate_result(request, result):
    if type(result) is not dict:
        raise ValueError('result schema')
    op = request['op']
    if op == 'initialization.inspect' and result == {'status': 'authorized'}:
        return result
    states = {'consumed'} if op == 'initialization.inspect' else {'newly_consumed', 'already_consumed'}
    if (set(result) != {'status', 'intent', 'receipt'} or type(result['status']) is not str
            or result['status'] not in states or not canonical_uuid(result['intent'])
            or (op == 'initialization.begin' and result['intent'] != request['intent'])):
        raise ValueError('result schema')
    record = result['receipt']
    if (type(record) is not dict or set(record) != {'receipt_id', 'digest'}
            or not canonical_uuid(record['receipt_id']) or type(record['digest']) is not str
            or re.fullmatch('[0-9a-f]{64}', record['digest']) is None):
        raise ValueError('receipt schema')
    return result


def invoke(receipt, request):
    """Called only in the isolated child; never creates authorization."""
    uncertain = request['op'] == 'initialization.begin'
    try:
        result = (receipt.begin(STATE, request['intent']) if uncertain else receipt.inspect(STATE))
        return {'v': 1, 'id': request['id'], 'ok': True,
                'result': validate_result(request, result)}
    except receipt.IntentConflict:
        return error(request['id'], 'intent_conflict')
    except Exception:
        return error(request['id'], 'initialization_uncertain' if uncertain else 'unavailable')


def peer_uid(connection):
    if sys.platform != 'linux' or not hasattr(socket, 'SO_PEERCRED'):
        raise OSError('Linux peer credentials required')
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
    pid, uid, gid = struct.unpack('3i', raw)
    if pid <= 0 or uid < 0 or gid < 0:
        raise OSError('Invalid peer credentials')
    return uid


def read_request(connection, deadline):
    raw = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        readable, _, _ = select.select([connection], [], [], remaining)
        if not readable:
            raise TimeoutError()
        block = connection.recv(REQUEST_LIMIT + 1 - len(raw))
        if not block:
            raise InvalidRequest()
        raw.extend(block)
        if len(raw) > REQUEST_LIMIT:
            raise InvalidRequest()
        if b'\n' in raw:
            return parse_request(bytes(raw))
        if len(raw) == REQUEST_LIMIT:
            raise InvalidRequest()


class Worker:
    """One outstanding child. An unreaped child prevents any next invocation."""
    def __init__(self, receipt, close_fds=(), *, stopping=None):
        self.receipt = receipt
        self.close_fds = tuple(close_fds)
        self.stopping = stopping or (lambda: False)
        self.pid = None
        self.uncertain = False
        self.kill_sent = False

    def reap(self):
        if self.pid is None:
            return None
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
        except OSError:
            self.uncertain = True
            raise
        if pid == self.pid and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
            self.pid = None
            return status
        if pid:
            self.uncertain = True
            raise OSError('ambiguous worker observation')
        return None

    def stop(self):
        """Bounded request failure: request kill once, retain an unreaped PID."""
        try:
            self.reap()  # WNOHANG confirms the child before any numeric signal.
        except OSError:
            return
        if self.pid is not None:
            if not self.uncertain and not self.kill_sent:
                self.kill_sent = True
                try:
                    os.kill(self.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError:
                    self.uncertain = True
            try:
                self.reap()
            except OSError:
                pass

    def drain(self):
        """Shutdown has no time bound; an ambiguous child never releases locks."""
        try:
            self.stop()
        except BaseException:
            self.uncertain = True
        while self.pid is not None:
            try:
                pid, status = os.waitpid(self.pid, 0)
                if pid == self.pid and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
                    self.pid = None
                    return
                self.uncertain = True
            except InterruptedError:
                continue
            except BaseException:
                # ECHILD is not proof of observed termination. In particular,
                # never signal this numeric PID again after observation failed.
                self.uncertain = True
            try:
                time.sleep(0.1)
            except BaseException:
                pass

    def run(self, connection, request, deadline):
        if self.stopping():
            return error(request['id'], 'unavailable')
        self.reap()
        if self.pid is not None:
            return error(request['id'], 'unavailable')
        uncertain = request['op'] == 'initialization.begin'
        failure = 'initialization_uncertain' if uncertain else 'unavailable'
        if time.monotonic() >= deadline:
            return error(request['id'], 'unavailable')
        read_fd, write_fd = os.pipe()
        try:
            if self.stopping():
                os.close(read_fd); os.close(write_fd)
                return error(request['id'], 'unavailable')
            pid = os.fork()
        except OSError:
            os.close(read_fd); os.close(write_fd)
            return error(request['id'], 'unavailable')
        if pid == 0:
            try:
                for fd in {read_fd, connection.fileno(), *self.close_fds} - {write_fd}:
                    os.close(fd)
                if self.stopping():
                    os._exit(2)
                raw = encode(invoke(self.receipt, request))
                # One bounded write, well below Linux PIPE_BUF; no request logs.
                if os.write(write_fd, raw) != len(raw):
                    os._exit(2)
                os.close(write_fd)
                os._exit(0)
            except BaseException:
                os._exit(2)
        self.pid = pid
        self.uncertain = False; self.kill_sent = False
        os.close(write_fd)
        raw = bytearray(); eof = False; peer_eof = False; status = None
        os.set_blocking(read_fd, False)
        try:
            while True:
                if self.stopping():
                    raise InterruptedError()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                observed = self.reap()
                if observed is not None:
                    status = observed
                if eof and self.pid is None:
                    if status != 0:
                        raise ValueError('worker failed')
                    value = decode(bytes(raw))
                    # Child code is pinned; additionally reject truncation/trailing lines.
                    if not raw.endswith(b'\n') or b'\n' in raw[:-1]:
                        raise ValueError('worker framing')
                    return value
                readers = ([] if eof else [read_fd]) + ([] if peer_eof else [connection])
                # A reaped child may have just closed its pipe; do not busy-spin
                # while waiting for exit after pipe EOF.
                ready, _, _ = select.select(readers, [], [], min(remaining, 0.01) if eof else remaining)
                if connection in ready:
                    extra = connection.recv(1)
                    if extra:
                        raise ValueError('second request')
                    peer_eof = True  # A write-half close is not proof of disconnect.
                if read_fd in ready:
                    block = os.read(read_fd, RESPONSE_LIMIT + 1 - len(raw))
                    raw.extend(block)
                    if len(raw) > RESPONSE_LIMIT:
                        raise ValueError('worker overflow')
                    eof = not block
        except (OSError, ValueError, TimeoutError, RecursionError):
            self.stop()
            return error(request['id'], failure)
        finally:
            os.close(read_fd)


def handle_connection(connection, worker, *, _peer_uid=peer_uid, _budget=DEADLINE_SECONDS):
    """One absolute deadline, including request, receipt operation and response."""
    deadline = time.monotonic() + _budget
    request_id = None
    peer_checked = False
    with connection:
        connection.setblocking(False)
        try:
            uid = _peer_uid(connection)
            peer_checked = True
            if uid != APP_UID:
                # Decide refusal from kernel credentials first. Consume at most
                # one bounded frame, without ever invoking the worker. Closing
                # a Linux AF_UNIX stream with an unread valid request otherwise
                # delivers ECONNRESET after our reply instead of its required EOF.
                try:
                    request_id = read_request(connection, deadline - REPLY_RESERVE)['id']
                except (InvalidRequest, OSError, TimeoutError):
                    request_id = None
                response = error(request_id, 'forbidden')
            else:
                request = read_request(connection, deadline - REPLY_RESERVE)
                request_id = request['id']
                if worker.stopping():
                    raise OSError('shutdown requested')
                # Refuse already-queued trailing bytes before any invocation.
                queued, _, _ = select.select([connection], [], [], 0)
                if queued and connection.recv(1, socket.MSG_PEEK):
                    raise InvalidRequest(request_id)
                response = worker.run(connection, request, deadline - REPLY_RESERVE)
        except InvalidRequest as exc:
            response = error(exc.request_id, 'invalid_request')
        except (OSError, TimeoutError):
            if not peer_checked:
                # Credential lookup already refused this connection. Drain the
                # same bounded frame for Linux EOF, but do not trust its ID or
                # invoke a receipt operation when the peer is unknown.
                try:
                    read_request(connection, deadline - REPLY_RESERVE)
                except (InvalidRequest, OSError, TimeoutError):
                    pass
            response = error(request_id, 'unavailable')
        try:
            raw = encode(response)
            while raw:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                _, writable, _ = select.select([], [connection], [], remaining)
                if not writable:
                    break
                count = connection.send(raw)
                if count <= 0:
                    break
                raw = raw[count:]
        except (OSError, ValueError):
            pass  # Never undo begin because its response was lost.


def trusted_directory(path):
    """Root-owned path, without symlinks or writable ancestors."""
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                raise ValueError('directory ownership')
        return fd
    except BaseException:
        os.close(fd)
        raise


def load_receipt():
    directory = trusted_directory(RECEIPT_SOURCE.parent)
    try:
        fd = os.open(RECEIPT_SOURCE.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0
                    or info.st_gid != 0 or stat.S_IMODE(info.st_mode) & 0o022
                    or not 0 < info.st_size <= 65536):
                raise ValueError('source metadata')
            raw = os.read(fd, 65537)
            if len(raw) != info.st_size or hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
                raise ValueError('source pin')
        finally:
            os.close(fd)
    finally:
        os.close(directory)
    module = types.ModuleType('initialization_receipt_server')
    exec(compile(raw, str(RECEIPT_SOURCE), 'exec'), module.__dict__)
    return module


def listen():
    """RuntimeDirectory is provisioned by systemd, never the authority state."""
    gid = grp.getgrnam(GROUP).gr_gid
    directory = trusted_directory(SOCKET.parent)
    lock = None; listener = None
    try:
        info = os.fstat(directory)
        if info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o750:
            raise ValueError('runtime directory')
        lock = os.open('.server.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                       0o600, dir_fd=directory)
        info = os.fstat(lock)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0
                or info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != 0):
            raise ValueError('server lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            old = os.stat(SOCKET.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            old = None
        if old is not None:
            if (not stat.S_ISSOCK(old.st_mode) or old.st_uid != 0 or old.st_gid != gid
                    or stat.S_IMODE(old.st_mode) != 0o660):
                raise ValueError('stale socket')
            os.unlink(SOCKET.name, dir_fd=directory)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # Trusted root-only writable parent; no group member can replace paths.
        listener.bind(str(SOCKET))
        os.chmod(SOCKET.name, 0o660, dir_fd=directory, follow_symlinks=False)
        listener.listen(8)
        listener.settimeout(1.0)
        return listener, lock, directory
    except BaseException:
        if listener is not None:
            listener.close()
        if lock is not None:
            os.close(lock)
        os.close(directory)
        raise


def notify_ready():
    """One main-process systemd datagram; no notification in standalone fixtures."""
    address = os.environ.pop('NOTIFY_SOCKET', None)
    if address is None:
        return False
    if len(address) < 2 or address[0] not in '/@' or '\0' in address:
        raise ValueError('notification address')
    if address[0] == '@':
        address = '\0' + address[1:]  # Linux abstract AF_UNIX namespace.
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notification:
        # A full manager queue must not stall startup beyond the unit's budget.
        notification.settimeout(NOTIFY_TIMEOUT_SECONDS)
        if notification.sendto(b'READY=1', address) != len(b'READY=1'):
            raise OSError('notification incomplete')
    return True


def main(argv=None):
    if (sys.argv[1:] if argv is None else argv) or sys.platform != 'linux' or os.geteuid() != 0:
        return 1
    listener = None; lock = None; directory = None; worker = None
    stopping = StopFlag(); previous = {}
    try:
        with writer_guard():
            try:
                for signum in (signal.SIGTERM, signal.SIGINT):
                    previous[signum] = signal.signal(signum, stopping.request)
                if stopping():
                    return 0
                receipt = load_receipt()
                if stopping():
                    return 0
                listener, lock, directory = listen()
                # Both the server lock and writer lease survive fork. A dead
                # parent must not admit a replacement while its child still runs.
                worker = Worker(receipt, (listener.fileno(), directory), stopping=stopping)
                if stopping():
                    return 0
                notify_ready()
                while not stopping():
                    worker.reap()
                    try:
                        connection, _ = listener.accept()
                    except socket.timeout:
                        continue
                    if stopping():
                        connection.close()
                        break
                    handle_connection(connection, worker)
                return 0
            finally:
                try:
                    if listener is not None:
                        listener.close()
                finally:
                    # Even a listener/pipe cleanup failure cannot skip drain.
                    # No timeout or observation error counts as a reaped child.
                    if worker is not None:
                        worker.drain()
                    if lock is not None:
                        os.close(lock)
                    if directory is not None:
                        os.close(directory)
    except WriterRefused:
        return 78
    except (OSError, ValueError, KeyError, KeyboardInterrupt):
        return 1
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


if __name__ == '__main__':
    raise SystemExit(main())
