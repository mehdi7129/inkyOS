"""Inactive, fixed Phase A graph proof. No service activation or writer signal.

Only synthetic contracts outside / accept injected dependencies. Installation
requires future support pins and runtime assembly. The source launcher targets
factory-main.py. UID 1000, namespace and Pi budgets are unqualified.
"""
import ast
import contextlib
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import re
import select
import selectors
import signal
import socket
import stat
import struct
import subprocess
import threading
import time
import types

SELF = '/usr/lib/inkyos/writer-graph.py'
MAIN = '/usr/lib/inkyos/factory-main.py'
RUNTIME = '/usr/lib/inkyos/factory-runtime-contract.py'
MANIFEST = '/etc/inkyos/factory-runtime-v1.json'
BUSCTL = '/usr/bin/busctl'
MANAGER = '/org/freedesktop/systemd1'
DESTINATION = 'org.freedesktop.systemd1'
MANAGER_INTERFACE = DESTINATION + '.Manager'
SO_PEERPIDFD = 77  # Linux 6.12 UAPI; availability is required, never emulated.
CHECK_SECONDS = 2.0
INITIAL_SECONDS = 20.0
SOURCE_SECONDS = 90.0
WATCH_SECONDS = 1.0
CLEANUP_SECONDS = 2.0
OUTPUT_LIMIT = 262144
DATA = Path('/var/lib/inky-studio')
APP_ARGV = ('/usr/lib/inky-studio/server/.venv/bin/python', '-I', '-B', MAIN)
STUDIO_COMMIT = 'eb117903cb647a14e9722d7387a41058ea8807b3'
UNITS = {'main': 'inky-studio.service', 'helper': 'inky-network.service',
         'ipc': 'inkyos-initialization.service'}
UNIT_TYPES = {'Id': 's', 'Names': 'as', 'LoadState': 's', 'ActiveState': 's',
              'SubState': 's', 'FragmentPath': 's', 'DropInPaths': 'as',
              'Transient': 'b', 'NeedDaemonReload': 'b', 'InvocationID': 'ay',
              'Job': '(uo)', 'Wants': 'as', 'After': 'as', 'PartOf': 'as',
              'BindsTo': 'as', 'PropagatesStopTo': 'as', 'StopPropagatedFrom': 'as'}
SERVICE_TYPES = {'MainPID': 'u', 'ControlPID': 'u', 'Type': 's', 'User': 's',
                 'Group': 's', 'SupplementaryGroups': 'as',
                 'ExecStart': 'a(sasbttttuii)', 'Restart': 's', 'KillMode': 's',
                 'KillSignal': 'i', 'SendSIGKILL': 'b', 'TimeoutStopUSec': 't',
                 'NoNewPrivileges': 'b', 'PrivateNetwork': 'b'}


class Refused(ValueError):
    def __init__(self, reason='graph_refused'):
        self.reason = reason
        super().__init__(reason)


class ObservationUnknown(Refused):
    """An owned query is not known reaped. Its enclosing SH must remain owned."""


def require(value, reason='graph_refused'):
    if not value:
        raise Refused(reason)


def remaining(deadline):
    value = deadline - time.monotonic()
    require(value > 0, 'observation_timeout')
    return value


def unit_path(name):
    require(name in {*UNITS.values(), 'init.scope'}, 'unsupported_unit')
    return MANAGER + '/unit/' + ''.join(char if char.isalnum() else '_%02x' % ord(char)
                                      for char in name)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'reply_shape')
        result[key] = value
    return result


def decode(raw):
    require(type(raw) is bytes and len(raw) <= OUTPUT_LIMIT, 'reply_shape')
    return json.loads(raw, object_pairs_hook=unique)


def properties(raw, expected):
    value = decode(raw)
    require(type(value) is dict and set(value) == {'type', 'data'}
            and value['type'] == 'a{sv}' and type(value['data']) is list
            and len(value['data']) == 1 and type(value['data'][0]) is dict, 'reply_shape')
    table, result = value['data'][0], {}
    for key, signature in expected.items():
        cell = table.get(key)
        require(type(cell) is dict and set(cell) == {'type', 'data'}
                and cell['type'] == signature, 'property_shape')
        item = cell['data']
        if signature == 's':
            require(type(item) is str and len(item) <= 4096, 'property_shape')
        elif signature == 'b':
            require(type(item) is bool, 'property_shape')
        elif signature in {'u', 't', 'i'}:
            require(type(item) is int and (signature == 'i' or item >= 0), 'property_shape')
        elif signature == 'as':
            require(type(item) is list and len(item) <= 4096
                    and all(type(entry) is str and len(entry) <= 4096 for entry in item)
                    and len(set(item)) == len(item), 'property_shape')
        elif signature == 'ay':
            require(type(item) is list and len(item) == 16
                    and all(type(byte) is int and 0 <= byte <= 255 for byte in item), 'property_shape')
        elif signature == '(uo)':
            require(type(item) is list and len(item) == 2 and type(item[0]) is int
                    and item[0] >= 0 and type(item[1]) is str, 'property_shape')
        else:
            require(signature == 'a(sasbttttuii)' and type(item) is list and len(item) == 1,
                    'property_shape')
            row = item[0]
            require(type(row) is list and len(row) == 10 and type(row[0]) is str
                    and type(row[1]) is list and all(type(arg) is str for arg in row[1])
                    and type(row[2]) is bool
                    and all(type(number) is int for number in row[3:])
                    and all(number >= 0 for number in row[3:8]), 'property_shape')
        result[key] = item
    return result


class ReadOnlyCommands:
    """Only fixed busctl calls; all passed FDs belong to a particular pidfd query."""
    def __init__(self):
        self._pending = None
        self.unknown = False

    def call(self, path, interface, member, signature, arguments, deadline, *, pidfd=None):
        require(not self.unknown and self._pending is None, 'observation_not_quiescent')
        allowed = ((path in {unit_path(name) for name in {*UNITS.values(), 'init.scope'}}
                    and interface == 'org.freedesktop.DBus.Properties' and member == 'GetAll'
                    and signature == 's' and arguments in
                    ((DESTINATION + '.Unit',), (DESTINATION + '.Service',)) and pidfd is None)
                   or (path == MANAGER and interface == MANAGER_INTERFACE
                       and member == 'GetUnitByPIDFD' and signature == 'h'
                       and type(pidfd) is int and arguments == (str(pidfd),)))
        require(allowed, 'unsupported_query')
        require(callable(getattr(os, 'pidfd_open', None))
                and callable(getattr(signal, 'pidfd_send_signal', None)), 'pidfd_unavailable')
        seconds = remaining(deadline)
        argv = (BUSCTL, '--system', '--json=short', '--auto-start=no',
                '--allow-interactive-authorization=no', '--timeout=%.6fs' % seconds,
                'call', DESTINATION, path, interface, member, signature, *arguments)
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, close_fds=True,
                                   pass_fds=() if pidfd is None else (pidfd,),
                                   env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        self._pending = process
        command_fd = None
        output, errors = bytearray(), bytearray()
        failure = None
        try:
            # No numerical PID signal fallback, including when pidfd_open fails.
            command_fd = os.pidfd_open(process.pid, 0)
            with selectors.DefaultSelector() as selector:
                for stream, sink in ((process.stdout, output), (process.stderr, errors)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, sink)
                while selector.get_map():
                    for key, _ in selector.select(remaining(deadline)):
                        part = os.read(key.fd, 8192)
                        if not part:
                            selector.unregister(key.fileobj)
                        else:
                            key.data.extend(part)
                            require(len(output) + len(errors) <= OUTPUT_LIMIT, 'reply_too_large')
                code = process.wait(timeout=remaining(deadline))
            require(code == 0 and not errors, 'query_failed')
            remaining(deadline)
        except BaseException as error:
            failure = error
        finally:
            if process.returncode is None:
                try:
                    if command_fd is not None:
                        try: signal.pidfd_send_signal(command_fd, signal.SIGKILL)
                        except ProcessLookupError: pass
                    process.wait(timeout=CLEANUP_SECONDS)
                except BaseException:
                    self.unknown = True
            if process.returncode is None:
                self.unknown = True
            if not self.unknown:
                self._pending = None
                for stream in (process.stdout, process.stderr):
                    stream.close()
                if command_fd is not None: os.close(command_fd)
            # Unknown ownership deliberately retains process/pipe/pidfd resources.
            elif command_fd is not None:
                self._pending = (process, command_fd)
        if self.unknown:
            raise ObservationUnknown('observation_not_reaped') from None
        if failure is not None:
            raise failure
        return bytes(output)

    def quiescent(self):
        return self._pending is None and not self.unknown

    def drain(self):
        """Only reap an already owned child. Never creates a new query/admission."""
        if self._pending is None:
            return not self.unknown
        pending = self._pending
        process, fd = pending if isinstance(pending, tuple) else (pending, None)
        try:
            process.wait(timeout=CLEANUP_SECONDS)
        except (subprocess.TimeoutExpired, OSError):
            return False
        for stream in (process.stdout, process.stderr): stream.close()
        if fd is not None: os.close(fd)
        self._pending, self.unknown = None, False
        return True


class KernelBackend:
    def __init__(self):
        self.commands = ReadOnlyCommands()

    def open_pid(self, pid):
        require(type(pid) is int and pid > 0 and callable(getattr(os, 'pidfd_open', None)),
                'pidfd_unavailable')
        fd = os.pidfd_open(pid, 0)
        os.set_inheritable(fd, False)
        return fd

    def close_pid(self, fd): os.close(fd)

    def live(self, fd):
        poller = select.poll()
        poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
        return not poller.poll(0)

    def same_pid(self, first, second):
        # Kernel pidfd inode identity must also pass the future UID1000 fixture.
        a, b = os.fstat(first), os.fstat(second)
        return self.live(first) and self.live(second) and (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)

    def resolve(self, fd, deadline):
        require(self.live(fd), 'writer_dead')
        raw = self.commands.call(MANAGER, MANAGER_INTERFACE, 'GetUnitByPIDFD', 'h',
                                 (str(fd),), deadline, pidfd=fd)
        value = decode(raw)
        require(type(value) is dict and set(value) == {'type', 'data'}
                and value['type'] == 'osay' and type(value['data']) is list
                and len(value['data']) == 3, 'manager_reply_shape')
        path, name, invocation = value['data']
        require(type(name) is str and name in {*UNITS.values(), 'init.scope'}
                and path == unit_path(name) and type(invocation) is list and len(invocation) == 16
                and all(type(byte) is int and 0 <= byte <= 255 for byte in invocation)
                and self.live(fd), 'manager_reply_shape')
        return path, name, bytes(invocation)

    def snapshot(self, role, deadline):
        require(role in UNITS, 'unsupported_role')
        path = unit_path(UNITS[role])
        values = []
        for suffix, expected in (('Unit', UNIT_TYPES), ('Service', SERVICE_TYPES)):
            raw = self.commands.call(path, 'org.freedesktop.DBus.Properties', 'GetAll', 's',
                                     (DESTINATION + '.' + suffix,), deadline)
            values.append(properties(raw, expected))
        return values

    def peer(self, connection):
        require(connection.fileno() >= 0, 'peer_closed')
        raw = connection.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD, struct.calcsize('i'))
        require(type(raw) is bytes and len(raw) == struct.calcsize('i'), 'peer_pidfd_shape')
        fd = struct.unpack('i', raw)[0]
        require(fd >= 0, 'peer_pidfd_shape')
        try:
            os.set_inheritable(fd, False)
            credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                struct.calcsize('3i'))
            require(type(credentials) is bytes and len(credentials) == struct.calcsize('3i'),
                    'peer_credentials_shape')
            pid, uid, gid = struct.unpack('3i', credentials)
            require(pid > 0 and uid == 0 and gid >= 0, 'peer_wrong_identity')
            return fd
        except BaseException:
            os.close(fd)
            raise

    def quiescent(self): return self.commands.quiescent()

    def drain(self): return self.commands.drain()


@dataclasses.dataclass(frozen=True)
class Binding:
    pid: int
    path: str
    name: str
    invocation: bytes
    configuration: str


def binding(role, values):
    require(type(values) in {list, tuple} and len(values) == 2, 'property_shape')
    unit, service = values
    require(type(unit) is dict and set(unit) == set(UNIT_TYPES)
            and type(service) is dict and set(service) == set(SERVICE_TYPES), 'property_shape')
    # Validate synthetic observations through the same typed decoder as real ones.
    unit = properties(json.dumps({'type': 'a{sv}', 'data': [{key: {'type': UNIT_TYPES[key], 'data': value}
                                                           for key, value in unit.items()}]}).encode(), UNIT_TYPES)
    service = properties(json.dumps({'type': 'a{sv}', 'data': [{key: {'type': SERVICE_TYPES[key], 'data': value}
                                                              for key, value in service.items()}]}).encode(), SERVICE_TYPES)
    name = UNITS[role]
    require(unit['Id'] == name and unit['Names'] == [name] and unit['LoadState'] == 'loaded'
            and unit['FragmentPath'] == '/usr/lib/systemd/system/' + name
            and unit['DropInPaths'] == [] and not unit['Transient']
            and not unit['NeedDaemonReload'], 'unit_configuration')
    for key in ('PartOf', 'BindsTo', 'PropagatesStopTo', 'StopPropagatedFrom'):
        require(unit[key] == [], 'stop_propagation')
    expected_wants = ({'inkyos-initialization.service', 'inky-network.service', 'bluetooth.service'}
                      if role == 'main' else {'inkyos-initialization.service', 'NetworkManager.service'}
                      if role == 'helper' else {'inkyos-admission-prepare.service',
                                              'inkyos-factory-supervisor.service'})
    require(set(unit['Wants']) == expected_wants and expected_wants <= set(unit['After']),
            'unit_dependencies')
    argv = ['/usr/bin/python3.13', '-I', '-B', '-S', '/usr/lib/inkyos/writer-launcher.py', role]
    row = service['ExecStart'][0]
    require(row[:3] == ['/usr/bin/python3.13', argv, False], 'unit_execstart')
    require(service['User'] == {'main': 'inky', 'helper': 'inky-network', 'ipc': 'root'}[role]
            and service['Group'] == ('inky' if role == 'main' else 'inky-provisioning')
            and set(service['SupplementaryGroups']) == ({'spi', 'i2c', 'gpio', 'inky-provisioning'}
                if role == 'main' else {'root'} if role == 'ipc' else set())
            and service['Type'] == ('notify' if role == 'ipc' else 'exec')
            and service['Restart'] == 'no' and service['KillMode'] == 'mixed'
            and service['KillSignal'] == signal.SIGTERM and not service['SendSIGKILL']
            and service['TimeoutStopUSec'] == 2**64 - 1 and service['NoNewPrivileges']
            and service['PrivateNetwork'] == (role == 'ipc'), 'unit_policy')
    job, path = unit['Job']
    require((job == 0 and path == '/') or (job > 0 and path.startswith(MANAGER + '/job/')),
            'unit_job_shape')
    require(unit['ActiveState'] in {'active', 'activating'}
            and unit['SubState'] in {'running', 'start', 'start-post'}
            and service['ControlPID'] == 0, 'unit_not_running')
    pending = job != 0 or unit['ActiveState'] != 'active' or unit['SubState'] != 'running'
    pid = service['MainPID']
    require(pid > 0 or pending, 'missing_mainpid')
    invocation = bytes(unit['InvocationID'])
    require(any(invocation) or pending, 'missing_invocation')
    configuration = {'unit': {key: sorted(value) if UNIT_TYPES[key] == 'as' else value
                             for key, value in unit.items()
                             if key not in {'ActiveState', 'SubState', 'InvocationID', 'Job'}},
                     'service': {key: sorted(value) if SERVICE_TYPES[key] == 'as' else value
                                 for key, value in service.items()
                                 if key not in {'MainPID', 'ControlPID', 'ExecStart'}}}
    # ExecStart accounting fields change after exec; only immutable launch fields bind.
    configuration['service']['ExecStart'] = row[:3]
    return Binding(pid, unit_path(name), name, invocation,
                   json.dumps(configuration, sort_keys=True, separators=(',', ':'))), pending


class Graph:
    """Owns a fresh SH, fixed anchors and monitor until all callers have drained."""
    def __init__(self, lease_context, sources, backend, *, _root=None):
        if _root is None:
            require(type(sources) is InstalledSources and type(backend) is KernelBackend
                    and sources.contract._root == Path('/') and Path(__file__) == Path(SELF),
                    'invalid_override')
        else:
            root = Path(_root)
            require(root.is_absolute() and root != Path('/')
                    and root == root.resolve(strict=True), 'invalid_override')
        self._lease_context, self._sources, self._backend = lease_context, sources, backend
        self._lease = None
        self._lock, self._query = threading.RLock(), threading.Lock()
        self._state, self.reason = 'BINDING', None
        self._anchors, self._bindings = {}, {}
        self._manager = None
        self._peer_count = 0
        self._monitor, self._monitor_stop = None, threading.Event()
        self._loop, self._stop_requested = None, None
        self._close_unknown = False

    @property
    def state(self):
        with self._lock: return self._state

    def invalidate(self, reason='graph_invalid'):
        with self._lock:
            if self._state != 'CLOSED':
                self._state = 'INVALID'
                if self.reason is None: self.reason = reason
            loop, stop = self._loop, self._stop_requested
        if loop is not None and stop is not None:
            try: loop.call_soon_threadsafe(stop.set)
            except RuntimeError: pass  # State remains INVALID if its owner loop is gone.

    def _owned_check(self, deadline):
        self._lease.check()
        require(self._sources.check(deadline) is None, 'source_check_result')
        self._lease.check()
        remaining(deadline)

    def __enter__(self):
        require(self._lease is None and self.state == 'BINDING', 'graph_reused')
        self._lease = self._lease_context.__enter__()
        try:
            require(self._sources.prepare(self._lease) is None, 'source_prepare_result')
            self._bind(time.monotonic() + INITIAL_SECONDS)
            return self
        except BaseException:
            self.invalidate('initial_binding_failed')
            self.close()
            raise

    def _bind(self, deadline):
        manager_fd = self._backend.open_pid(1)
        self._anchors['manager'] = manager_fd
        manager = self._backend.resolve(manager_fd, deadline)
        require(manager[:2] == (unit_path('init.scope'), 'init.scope'), 'pid_view_unconfirmed')
        self._manager = manager
        while True:
            self._owned_check(deadline)
            current = {role: binding(role, self._backend.snapshot(role, deadline)) for role in UNITS}
            require(current['main'][0].pid == os.getpid(), 'not_mainpid')
            if any(pending for _, pending in current.values()):
                time.sleep(min(0.05, remaining(deadline)))
                continue
            self._bindings = {role: item for role, (item, _) in current.items()}
            for role, item in self._bindings.items():
                fd = self._backend.open_pid(item.pid)
                self._anchors[role] = fd
                require(self._backend.resolve(fd, deadline) == (item.path, item.name, item.invocation),
                        'writer_mapping_changed')
            own = self._backend.open_pid(os.getpid())
            try:
                require(self._backend.same_pid(own, self._anchors['main']), 'not_mainpid')
            finally: self._backend.close_pid(own)
            self._verify(deadline)
            with self._lock:
                require(self._state == 'BINDING', 'graph_invalid')
                self._state = 'ACTIVE'
            return

    def _verify(self, deadline):
        self._owned_check(deadline)
        require(all(self._backend.live(fd) for fd in self._anchors.values()), 'writer_dead')
        require(self._backend.resolve(self._anchors['manager'], deadline) == self._manager,
                'pid_view_changed')
        for role, previous in self._bindings.items():
            current, pending = binding(role, self._backend.snapshot(role, deadline))
            require(not pending and current == previous, 'writer_changed')
            require(self._backend.resolve(self._anchors[role], deadline)
                    == (previous.path, previous.name, previous.invocation), 'writer_mapping_changed')
        self._owned_check(deadline)
        require(all(self._backend.live(fd) for fd in self._anchors.values()), 'writer_dead')

    def _check(self, deadline):
        acquired = False
        try:
            require(self.state == 'ACTIVE', 'graph_invalid')
            acquired = self._query.acquire(timeout=remaining(deadline))
            require(acquired, 'observation_timeout')
            require(self.state == 'ACTIVE', 'graph_invalid')
            self._verify(deadline)
            require(self.state == 'ACTIVE', 'graph_invalid')
            remaining(deadline)
        except BaseException as error:
            self.invalidate(getattr(error, 'reason', 'observation_failed'))
            raise
        finally:
            if acquired: self._query.release()
        return None

    def check(self):
        return self._check(time.monotonic() + CHECK_SECONDS)

    @contextlib.contextmanager
    def initialization_guard(self, connection):
        fd = None
        entered = False
        try:
            deadline = time.monotonic() + CHECK_SECONDS
            self._check(deadline)
            acquired = self._query.acquire(timeout=remaining(deadline))
            require(acquired, 'observation_timeout')
            try:
                require(self.state == 'ACTIVE', 'graph_invalid')
                fd = self._backend.peer(connection)
                expected = self._bindings['ipc']
                require(self._backend.same_pid(fd, self._anchors['ipc']), 'peer_not_mainpid')
                require(self._backend.resolve(fd, deadline)
                        == (expected.path, expected.name, expected.invocation), 'peer_mapping_changed')
                self._owned_check(deadline)
                require(self.state == 'ACTIVE' and self._backend.live(fd)
                        and all(self._backend.live(anchor) for anchor in self._anchors.values()),
                        'graph_invalid')
                with self._lock:
                    self._peer_count += 1
                    entered = True
            finally: self._query.release()
            yield None
        except BaseException as error:
            self.invalidate(getattr(error, 'reason', 'peer_failed'))
            raise
        finally:
            # Never query connection here: Studio has already closed/drained it.
            if fd is not None: self._backend.close_pid(fd)
            if entered:
                with self._lock: self._peer_count -= 1

    def start_monitor(self, loop, stop_requested):
        with self._lock:
            require(self._monitor is None and self._state == 'ACTIVE', 'monitor_state')
            self._loop, self._stop_requested = loop, stop_requested
            self._monitor = threading.Thread(target=self._watch, name='inkyos-graph', daemon=False)
            self._monitor.start()

    def _watch(self):
        while not self._monitor_stop.wait(WATCH_SECONDS):
            try: self.check()
            except BaseException: return

    def close(self):
        # Cleanup never needs positive admission. It cannot release SH early.
        if self.state == 'CLOSED': return None
        self.invalidate('graph_closing')
        self._monitor_stop.set()
        if self._monitor is not None and self._monitor.ident is not None:
            self._monitor.join(timeout=CHECK_SECONDS + CLEANUP_SECONDS)
            if self._monitor.is_alive():
                raise ObservationUnknown('monitor_not_drained')
        acquired = self._query.acquire(timeout=CLEANUP_SECONDS)
        if not acquired:
            raise ObservationUnknown('observation_not_drained')
        try:
            if self._close_unknown:
                raise ObservationUnknown('resource_close_unconfirmed')
            with self._lock:
                if self._peer_count != 0:
                    raise ObservationUnknown('peer_not_drained')
            if not self._backend.quiescent():
                if not self._backend.drain() or not self._backend.quiescent():
                    raise ObservationUnknown('observation_not_reaped')
            for role in tuple(self._anchors):
                fd = self._anchors.pop(role)
                try: self._backend.close_pid(fd)
                except BaseException:
                    self._close_unknown = True
                    raise ObservationUnknown('resource_close_unconfirmed') from None
            self._sources.close()
            if self._lease is not None:
                self._lease_context.__exit__(None, None, None)
                self._lease = None
            with self._lock: self._state = 'CLOSED'
        finally: self._query.release()

    def __exit__(self, *_):
        self.close()
        return False


def _bootstrap_read(path, mode, limit):
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in Path(path).parts[1:-1]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent); parent = fd
            info = os.fstat(parent)
            require((info.st_uid, info.st_gid) == (0, 0) and not stat.S_IMODE(info.st_mode) & 0o7022
                    and not os.listxattr(parent), 'module_metadata')
        leaf = Path(path).name
        info = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == mode
                and (info.st_uid, info.st_gid) == (0, 0) and info.st_nlink == 1
                and 0 <= info.st_size <= limit, 'module_metadata')
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            stable = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                                    value.st_gid, value.st_nlink, value.st_size,
                                    value.st_mtime_ns, value.st_ctime_ns)
            require(stable(os.fstat(fd)) == stable(info) and not os.listxattr(fd), 'module_metadata')
            raw = os.read(fd, limit + 1)
            require(len(raw) == info.st_size and stable(os.fstat(fd)) == stable(info)
                    and stable(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) == stable(info),
                    'module_changed')
            return raw
        finally: os.close(fd)
    finally: os.close(parent)


def installed_runtime():
    require(Path(__file__) == Path(SELF), 'not_installed')
    manifest = decode(_bootstrap_read(MANIFEST, 0o644, 16384))
    require(type(manifest) is dict and type(manifest.get('os_module_pins')) is dict
            and set(manifest['os_module_pins']) == {'writer-admission.py', 'factory-runtime-contract.py',
                                                  'writer-launcher.py'}, 'runtime_pin_shape')
    raw = _bootstrap_read(RUNTIME, 0o555, 1024 * 1024)
    require(hashlib.sha256(raw).hexdigest() == manifest['os_module_pins']['factory-runtime-contract.py'],
            'runtime_pin_mismatch')
    module = types.ModuleType('inkyos_factory_runtime_contract')
    module.__file__ = RUNTIME
    exec(compile(raw, RUNTIME, 'exec'), module.__dict__)
    return module


class InstalledSources:
    def __init__(self, runtime, contract):
        self.runtime, self.contract = runtime, contract
        self._context, self._identity, self._metadata = None, None, {}
        self._lease = None

    def prepare(self, lease):
        self._lease = lease
        runtime, contract = self.runtime, self.contract
        deadline = time.monotonic() + SOURCE_SECONDS
        require(contract.manifest['studio_commit'] == STUDIO_COMMIT, 'studio_candidate_mismatch')
        app, _, support, records = runtime.inventories(contract)
        required = (SELF[1:], MAIN[1:], BUSCTL[1:])
        for path in required:
            require(path in support['paths'] and path in records, 'support_pin_missing')
        require(all(records[path]['type'] == 'file' and records[path]['mode'] == '0555'
                    for path in (SELF[1:], MAIN[1:])), 'support_pin_missing')
        require(runtime.resolve(BUSCTL[1:], records) in support['elf_closure_review']['roots'],
                'command_closure_missing')
        with contract.tree() as tree:
            selected = {SELF[1:], MAIN[1:], BUSCTL[1:], runtime.HELPER, runtime.IPC,
                        runtime.RECEIPT, runtime.MODULE_DIR + '/writer-launcher.py'}
            selected.update(support['elf_closure_review']['files'])
            raw = tree.read(runtime.MODULE_DIR + '/writer-launcher.py', 0o555, 1024 * 1024)
            assignments = [node for node in ast.parse(raw).body if isinstance(node, ast.Assign)
                           and any(isinstance(target, ast.Name) and target.id == 'ARGV'
                                   for target in node.targets)]
            require(len(assignments) == 1
                    and ast.literal_eval(assignments[0].value).get('main') == APP_ARGV,
                    'inactive_launch_contract')
            self._context = tree.read(runtime.CONTEXT, 0o644, 1024)
            self._boot = runtime.validate_context(contract)
            self._identity = self._numeric_identity()
            admission = runtime.import_admission(contract)
            self._tokens = (('attempted', admission.ATTEMPTED), ('Ready', admission.READY))
            self._run = self._run_binding()
            self._state_metadata = {path: self._stamp(tree, path) for path in (
                runtime.MANIFEST, runtime.CONTEXT_DIR, runtime.CONTEXT,
                'run/inkyos-admission/attempted', 'run/inkyos-admission/Ready')}
            # Record closure paths and their parents, without contents/listings on checks.
            require(len(records) <= 20000, 'source_inventory_limit')
            for path in sorted(records):
                remaining(deadline)
                self._record_metadata(tree, path, records[path])
                self._metadata[path] = self._stamp(tree, path)
            # Hash between baseline capture and its fresh comparison. Otherwise a
            # concurrent change after admission could become our accepted baseline.
            for path in sorted(selected):
                remaining(deadline)
                runtime.check_path(tree, path, records)
        remaining(deadline)
        runtime.verify_role(contract, 'main')
        self.check(deadline)
        return None

    @staticmethod
    def _numeric_identity():
        return (tuple(os.getresuid()), tuple(os.getresgid()), tuple(sorted(os.getgroups())))

    def _stamp(self, tree, path):
        parent, leaf = tree.parent(path)
        try:
            info = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            require((info.st_uid, info.st_gid) == (tree.uid, tree.gid), 'source_metadata')
            if stat.S_ISLNK(info.st_mode):
                require(not os.listxattr('/proc/self/fd/%d/%s' % (parent, leaf), follow_symlinks=False),
                        'source_xattrs')
                target = os.readlink(leaf, dir_fd=parent)
            else:
                fd = os.open(leaf, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
                             | (os.O_DIRECTORY if stat.S_ISDIR(info.st_mode) else 0), dir_fd=parent)
                try:
                    require(tree.uid == info.st_uid and tree.gid == info.st_gid
                            and not os.listxattr(fd) and self.runtime.stamp(os.fstat(fd))
                            == self.runtime.stamp(info), 'source_metadata')
                finally: os.close(fd)
                target = None
            require(self.runtime.stamp(info) == self.runtime.stamp(
                os.stat(leaf, dir_fd=parent, follow_symlinks=False)), 'source_changed')
            return self.runtime.stamp(info), target
        finally: os.close(parent)

    @staticmethod
    def _record_metadata(tree, path, record):
        parent, leaf = tree.parent(path)
        try:
            info = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            require((info.st_uid, info.st_gid) == (tree.uid, tree.gid)
                    and format(stat.S_IMODE(info.st_mode), '04o') == record['mode'],
                    'source_metadata')
            kind = ('symlink' if stat.S_ISLNK(info.st_mode) else 'file'
                    if stat.S_ISREG(info.st_mode) else 'directory'
                    if stat.S_ISDIR(info.st_mode) else None)
            require(kind == record['type'], 'source_metadata')
            if kind == 'file':
                require(info.st_nlink == 1 and info.st_size == record['size_bytes'], 'source_metadata')
            elif kind == 'symlink':
                require(info.st_nlink == 1 and os.readlink(leaf, dir_fd=parent) == record['target'],
                        'source_metadata')
        finally: os.close(parent)

    @staticmethod
    def _entries(fd, limit):
        values = set()
        with os.scandir(fd) as iterator:
            for entry in iterator:
                require(len(values) < limit, 'context_inventory_limit')
                values.add(entry.name)
        return values

    def check(self, deadline):
        runtime, contract = self.runtime, self.contract
        require(self._numeric_identity() == self._identity, 'identity_changed')
        with contract.tree() as tree:
            require(hashlib.sha256(tree.read(runtime.MANIFEST, 0o644, 16384)).hexdigest()
                    == contract.candidate_sha256, 'candidate_changed')
            require(tree.read(runtime.CONTEXT, 0o644, 1024) == self._context, 'context_changed')
            parent, leaf = tree.parent(runtime.CONTEXT)
            try:
                tree.directory_fd(parent, 0o755)
                require(self._entries(parent, 2) == {'context.json'}, 'context_changed')
            finally: os.close(parent)
            require(self._entries(self._lease.parent, 4) == {'lock', 'attempted', 'Ready'},
                    'admission_changed')
            for name, raw in self._tokens:
                require(tree.read('run/inkyos-admission/' + name, 0o644, 128) == raw,
                        'admission_changed')
            # boot_state has an unbounded /run listing; do not call it here.
            with open('/proc/sys/kernel/random/boot_id', 'rb') as stream:
                require(stream.read(129) == (self._boot['boot_id'] + '\n').encode(), 'boot_changed')
            require(self._run_binding() == self._run, 'run_mount_changed')
            for path, expected in self._state_metadata.items():
                remaining(deadline)
                require(self._stamp(tree, path) == expected, 'state_binding_changed')
            for path, expected in self._metadata.items():
                remaining(deadline)
                require(self._stamp(tree, path) == expected, 'source_changed')
        remaining(deadline)
        return None

    def _run_binding(self):
        with open('/proc/self/mountinfo', 'rb') as stream:
            mountinfo = stream.read(1024 * 1024 + 1)
        require(len(mountinfo) <= 1024 * 1024, 'run_mount_changed')
        rows = []
        for line in mountinfo.decode('ascii').splitlines():
            fields = line.split()
            require('-' in fields and fields.index('-') >= 6, 'run_mount_changed')
            if fields[4] == '/run': rows.append(fields)
        info = os.fstat(self._lease.run)
        require(len(rows) == 1 and rows[0][3] == '/'
                and len(rows[0]) == rows[0].index('-') + 4
                and rows[0][rows[0].index('-') + 1] == 'tmpfs'
                and set(rows[0][5].split(',')) & {'ro', 'rw'} == {'rw'}
                and rows[0][2] == '%d:%d' % (os.major(info.st_dev), os.minor(info.st_dev)),
                'run_mount_changed')
        return tuple(rows[0])

    def close(self): pass  # No source FD or repair/write is owned by this observer.


def open_main(*, _contract=None, _runtime=None, _backend=None, _sources=None):
    if _contract is None:
        require(_runtime is None and _backend is None and _sources is None, 'invalid_override')
        runtime = installed_runtime()
        contract = runtime.load_contract()
        sources = InstalledSources(runtime, contract)
        lease = runtime.writer_guard('main')  # Fresh SH, never adopt the inherited lease.
        backend = KernelBackend()
    else:
        require(_runtime is not None and isinstance(_contract, _runtime.Contract)
                and _contract._root.is_absolute() and _contract._root != Path('/')
                and _contract._root == _contract._root.resolve(strict=True), 'invalid_override')
        require(_backend is not None and _sources is not None, 'invalid_override')
        runtime, contract, backend, sources = _runtime, _contract, _backend, _sources
        lease = runtime.writer_guard('main', _contract=contract)
    return Graph(lease, sources, backend, _root=None if _contract is None else contract._root)
