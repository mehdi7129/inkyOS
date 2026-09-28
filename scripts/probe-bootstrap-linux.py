#!/usr/bin/env python3
"""Disposable Linux privilege-boundary probe; never a production IPC service.

The only real effects are a temporary AF_UNIX socket, dropped client identities,
and root-owned initialization receipts below the dedicated builder directory.
Time, regulatory and radio adapters are traced fakes. No image, application,
service, clock or radio is changed. One EOF-terminated request per connection is
TEST framing only, not BLE, helper-v1 or a proposed public protocol.

Run without arguments as root in inkyos-build. Emit a bounded JSON summary on
stdout; no generated receipt IDs, bindings, request intents or tokens are logged.
The root server expires independently of its parent after 30 seconds plus at
most 2 seconds of thread drainage. Normal cleanup does not cover SIGKILL of the
parent: its temporary fixture directory may then require builder-side removal.
Clients are forked test processes; this proves filesystem permissions and kernel
peer credentials, not isolation from memory inherited from the test parent.
"""
import hashlib
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import stat
import struct
import sys
import tempfile
import threading
import time

BUILDER = Path('/var/lib/inkyos-build')
PREFIX = 'bootstrap-probe.'
APP_UID, HELPER_UID, FOREIGN_UID = 1000, 65534, 65533
MAX_REQUEST = 256
FRAME_TIMEOUT = 0.3
SERVER_LIFETIME_SECONDS = 30.0
SERVER_DRAIN_SECONDS = 2.0
INTENT = '12345678-1234-4234-8234-123456789abc'
OTHER_INTENT = '22345678-1234-4234-8234-123456789abc'
SOURCE_NAMES = ('probe-bootstrap-linux.py', 'bootstrap-system-model.py', 'initialization-receipt.py')


class ProbeError(RuntimeError):
    pass


class FrameError(ValueError):
    pass


def require(value, message):
    if not value:
        raise ProbeError(message)


def trusted_directory(path):
    require(path.is_absolute() and '..' not in path.parts, 'Canonical absolute directory required')
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                and not info.st_mode & 0o022, 'Trusted root-owned directory required')


def check_environment():
    require(platform.system() == 'Linux' and os.geteuid() == 0,
            'Linux root in the dedicated builder required')
    require(hasattr(socket, 'SO_PEERCRED'), 'Kernel peer credentials required')
    trusted_directory(BUILDER)
    fd = os.open(BUILDER / 'owner', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0
                and not info.st_mode & 0o022 and info.st_size <= 64,
                'Private builder marker required')
        require(stream.read(65) == b'inkyos-builder-v1\n', 'Dedicated builder marker mismatch')


def load(name):
    spec = importlib.util.spec_from_file_location('_probe_' + name.replace('-', '_'),
                                                Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_hashes():
    values = {}
    for name in SOURCE_NAMES:
        fd = os.open(Path(__file__).with_name(name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_size <= 1024**2, 'Ordinary bounded source required')
            values[name] = hashlib.file_digest(stream, 'sha256').hexdigest()
    return values


def read_request(connection):
    """Bound both total bytes and elapsed time; a stream recv is not a frame."""
    deadline = time.monotonic() + FRAME_TIMEOUT
    data = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FrameError('Request deadline exceeded')
        connection.settimeout(remaining)
        try:
            block = connection.recv(MAX_REQUEST + 1 - len(data))
        except socket.timeout as exc:
            raise FrameError('Request deadline exceeded') from exc
        if not block:
            if not data:
                raise FrameError('Empty request')
            return bytes(data)
        data.extend(block)
        if len(data) > MAX_REQUEST:
            raise FrameError('Request exceeds bound')


class FakeAdapter:
    def __init__(self):
        self.calls = []
        self.seconds = None
        self.country = None

    def set_time(self, value):
        self.calls.append('set_time'); self.seconds = value; return True

    def observe_time(self):
        self.calls.append('observe_time'); return self.seconds

    def wifi_status(self):
        self.calls.append('wifi_status')
        return {'disabled': True, 'trial': False, 'connected': False}

    def close_wifi_gate(self):
        self.calls.append('close_gate'); return True

    def persist_country(self, record):
        self.calls.append('persist_' + record['status']); return True

    def apply_country(self, code):
        self.calls.append('apply_country'); self.country = code; return True

    def observe_country(self):
        self.calls.append('observe_country'); return self.country


def server(socket_path, receipt_path, channel, stop, kill_after_begin, *, _lifetime_seconds=None):
    """Root-only fixture process; channels/audit records are never client input."""
    # The optional shorter lifetime is only for the local deadline test. Neither
    # IPC input nor a CLI argument can extend the production fixture ceiling.
    lifetime = SERVER_LIFETIME_SECONDS if _lifetime_seconds is None else _lifetime_seconds
    require(type(lifetime) in (float, int) and 0 < lifetime <= SERVER_LIFETIME_SECONDS,
            'Bounded internal server lifetime required')
    deadline = time.monotonic() + lifetime
    bootstrap, receipt = load('bootstrap-system-model'), load('initialization-receipt')
    adapter = FakeAdapter()
    model = bootstrap.BootstrapSystemModel(
        helper_uid=HELPER_UID, application_uid=APP_UID,
        begin_initialization=lambda intent: receipt.begin(receipt_path, intent),
        inspect_initialization=lambda: receipt.inspect(receipt_path),
        time_bounds=(1000, 2000), country_allowlist={'FR'},
        time_verifier=lambda requested, observed: requested == observed,
        regulatory_verifier=lambda requested, observed: requested == observed, adapter=adapter)
    audit_lock = threading.Lock()

    def audit(value):
        with audit_lock:
            channel.send(value)

    def handle(connection):
        with connection:
            pid, uid, gid = struct.unpack('iII', connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('iII')))
            before, calls = model.inspect(), list(adapter.calls)
            response = {'ok': False, 'error': 'refused'}
            try:
                raw = read_request(connection)
                if uid not in (APP_UID, HELPER_UID):
                    raise FrameError('Caller refused before request parsing')
                result = model.handle(raw, caller_uid=uid)
                response = {'ok': True, 'result': result}
                if kill_after_begin and result['operation'] == 'begin_initialization':
                    audit({'kind': 'consumed_before_reply', 'status': result['initialization']['status']})
                    os._exit(73)
            except (FrameError, bootstrap.Refused):
                pass
            except bootstrap.InitializationUncertain:
                response['error'] = 'recovery'
            except Exception:
                response['error'] = 'internal_error'
            audit({'kind': 'handled', 'pid': pid, 'uid': uid, 'gid': gid,
                   'ok': response['ok'], 'error': response.get('error'),
                   'state_unchanged': model.inspect() == before,
                   'calls_added': adapter.calls[len(calls):]})
            try:
                connection.settimeout(1)
                connection.sendall(json.dumps(response, separators=(',', ':')).encode())
            except (BrokenPipeError, ConnectionResetError, socket.timeout):
                pass  # Lost responses never retry a receipt callback.

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    threads = []
    try:
        listener.bind(str(socket_path))
        # Fixture intentionally admits foreign clients to exercise SO_PEERCRED.
        # Its root-owned parent prevents replacing the socket or authorization.
        os.chmod(socket_path, 0o666)
        listener.listen(8)
        audit({'kind': 'ready'})
        while not stop.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            listener.settimeout(min(0.1, remaining))
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            thread = threading.Thread(target=handle, args=(connection,))
            thread.start(); threads.append(thread)
        listener.close()
        drain_deadline = time.monotonic() + SERVER_DRAIN_SECONDS
        for thread in threads:
            thread.join(max(0, drain_deadline - time.monotonic()))
            if thread.is_alive():
                os._exit(74)
    finally:
        listener.close(); channel.close()


class Server:
    def __init__(self, context, workspace, receipt_path, *, kill_after_begin=False):
        self.socket = workspace / 'ipc.sock'
        self.read, write = context.Pipe(duplex=False)
        self.stop = context.Event()
        self.process = context.Process(target=server, args=(self.socket, receipt_path, write,
                                                          self.stop, kill_after_begin))
        self.process.start(); write.close()
        try:
            require(self.event()['kind'] == 'ready', 'Fixture server did not start')
        except BaseException:
            self.close()
            raise

    def event(self):
        require(self.read.poll(5), 'Fixture server audit deadline exceeded')
        return self.read.recv()

    def close(self):
        self.stop.set(); self.process.join(3)
        if self.process.is_alive():
            self.process.kill(); self.process.join(3)
        require(not self.process.is_alive(), 'Fixture server cleanup failed')
        self.read.close()
        if self.socket.exists():
            require(stat.S_ISSOCK(self.socket.lstat().st_mode), 'Unexpected fixture socket replacement')
            self.socket.unlink()


def client(uid, socket_path, raw, mode, receipt_path, channel):
    # Inherit no root-owned state descriptors. Connect only AFTER dropping IDs;
    # a preconnected socket would retain the original peer credentials.
    keep = channel.fileno()
    for name in os.listdir('/proc/self/fd'):
        fd = int(name)
        if fd > 2 and fd != keep:
            try:
                os.close(fd)
            except OSError:
                pass
    os.setgroups([]); os.setgid(uid); os.setuid(uid)
    value = {'pid': os.getpid(), 'uid': os.geteuid(), 'gid': os.getegid(), 'groups': os.getgroups()}
    try:
        if mode == 'filesystem':
            denied = []
            for flags in (os.O_RDONLY, os.O_WRONLY):
                try:
                    fd = os.open(receipt_path / 'state.json', flags | os.O_NOFOLLOW)
                except PermissionError:
                    denied.append(True)
                else:
                    os.close(fd); denied.append(False)
            try:
                os.rename(receipt_path, receipt_path.with_name('unauthorized-replacement'))
            except PermissionError:
                denied.append(True)
            else:
                denied.append(False)
            value['filesystem_denied'] = denied
        else:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(3); connection.connect(str(socket_path))
                if mode == 'fragmented':
                    for part in (raw[:3], raw[3:11], raw[11:]):
                        connection.sendall(part)
                else:
                    connection.sendall(raw)
                if mode == 'slow':
                    time.sleep(FRAME_TIMEOUT * 2)
                else:
                    connection.shutdown(socket.SHUT_WR)
                response = bytearray()
                while True:
                    try:
                        block = connection.recv(8193 - len(response))
                    except ConnectionResetError:
                        if response:
                            break
                        raise
                    if not block:
                        break
                    response.extend(block)
                    if len(response) > 8192:
                        raise ProbeError('Fixture response exceeds bound')
                value['response'] = json.loads(response) if response else None
    except Exception as exc:
        value['transport_error'] = type(exc).__name__
    channel.send(value); channel.close(); os._exit(0)


def clients(context, socket_path, requests, receipt_path):
    processes = []
    try:
        for uid, raw, mode in requests:
            read, write = context.Pipe(duplex=False)
            process = context.Process(target=client, args=(uid, socket_path, raw, mode, receipt_path, write))
            process.start(); write.close(); processes.append((process, read))
        results = []
        for process, read in processes:
            require(read.poll(5), 'Client deadline exceeded')
            results.append(read.recv()); process.join(2)
            require(process.exitcode == 0, 'Client did not exit cleanly')
        return results
    finally:
        for process, read in processes:
            if process.is_alive():
                process.kill(); process.join(2)
            read.close()


def request(operation, **values):
    return json.dumps({'operation': operation, **values}, separators=(',', ':')).encode()


def receipt_bytes(path):
    return {entry.name: entry.read_bytes() for entry in path.iterdir()}


def run_probe():
    check_environment()
    hashes = source_hashes()
    receipt = load('initialization-receipt')
    context = multiprocessing.get_context('fork')
    workspace = Path(tempfile.mkdtemp(prefix=PREFIX, dir=BUILDER))
    os.chmod(workspace, 0o755)
    require(workspace.parent == BUILDER and workspace.name.startswith(PREFIX), 'Dedicated workspace required')
    trusted_directory(workspace)
    checks, running = [], None
    path = workspace / 'receipt'
    begin = request('begin_initialization', intent=INTENT)
    inspect_initialization = request('inspect_initialization')
    country = request('country', country_code='FR')
    utc = request('time', unix_seconds=1500)

    def check(name, condition):
        checks.append({'name': name, 'passed': bool(condition)})
        if not condition:
            error = ProbeError('Fixture assertion failed')
            error.failed_check = name
            raise error

    def exchange(uid, raw, mode='normal'):
        result = clients(context, running.socket, [(uid, raw, mode)], path)[0]
        audit = running.event()
        require(isinstance(result.get('response'), dict), 'Fixture client received no response')
        check('kernel_credentials_' + str(len(checks)),
              audit['kind'] == 'handled' and audit['pid'] == result['pid']
              and audit['uid'] == uid == result['uid'] and audit['gid'] == uid == result['gid']
              and result['groups'] == [])
        return result.get('response'), audit

    try:
        receipt.create_authorization(path)
        check('root_receipt_permissions', path.stat().st_uid == path.stat().st_gid == 0
              and stat.S_IMODE(path.stat().st_mode) == 0o700
              and all(p.stat().st_uid == p.stat().st_gid == 0 and stat.S_IMODE(p.stat().st_mode) == 0o600
                      for p in path.iterdir()))
        running = Server(context, workspace, path)
        baseline = receipt_bytes(path)
        response, audit = exchange(APP_UID, inspect_initialization)
        check('authorized_inspection_is_readonly', response['ok']
              and response['result']['initialization'] == {'status': 'authorized'}
              and audit['state_unchanged'] and not audit['calls_added'] and receipt_bytes(path) == baseline)
        for uid in (APP_UID, HELPER_UID, FOREIGN_UID):
            result = clients(context, running.socket, [(uid, b'', 'filesystem')], path)[0]
            check('private_receipt_denied_uid_' + str(uid), result.get('filesystem_denied') == [True] * 3)
        for uid, raw in ((0, begin), (FOREIGN_UID, begin), (HELPER_UID, begin),
                         (HELPER_UID, inspect_initialization),
                         (APP_UID, utc), (APP_UID, country)):
            response, audit = exchange(uid, raw)
            check('role_refused_' + str(len(checks)), response == {'ok': False, 'error': 'refused'}
                  and audit['state_unchanged'] and not audit['calls_added'] and receipt_bytes(path) == baseline)
        response, audit = exchange(APP_UID, request('inspect_initialization', intent=INTENT))
        check('inspection_rejects_arguments_without_effect', response == {'ok': False, 'error': 'refused'}
              and audit['state_unchanged'] and not audit['calls_added'] and receipt_bytes(path) == baseline)
        for raw, mode in ((b'{}', 'normal'), (b'{' , 'normal'), (b'', 'normal'),
                          (b'x' * (MAX_REQUEST + 1), 'normal'), (b'{', 'slow'),
                          (b'{"operation":"time","operation":"time","unix_seconds":1500}', 'normal'),
                          (request('time', unix_seconds=1500, caller_uid=HELPER_UID), 'normal')):
            response, audit = exchange(HELPER_UID, raw, mode)
            check('framing_or_parser_refused_' + str(len(checks)),
                  response == {'ok': False, 'error': 'refused'} and audit['state_unchanged']
                  and not audit['calls_added'] and receipt_bytes(path) == baseline)
        response, audit = exchange(HELPER_UID, utc, 'fragmented')
        check('fragmented_time_fake_only', response['ok'] and audit['calls_added'] == ['set_time', 'observe_time'])
        response, audit = exchange(HELPER_UID, country)
        check('country_fake_order', response['ok'] and response['result']['wifi_gate_open'] is True
              and audit['calls_added'] == ['wifi_status', 'close_gate', 'wifi_status', 'persist_pending',
                    'wifi_status', 'apply_country', 'wifi_status', 'observe_country', 'wifi_status',
                    'persist_confirmed', 'wifi_status'])
        results = clients(context, running.socket, [(APP_UID, begin, 'normal')] * 2, path)
        events = [running.event(), running.event()]
        check('concurrent_clients_one_initial_grant',
              sorted(r['response']['result']['initialization']['status'] for r in results)
              == ['already_consumed', 'newly_consumed'] and
              all(e['uid'] == APP_UID and e['gid'] == APP_UID and not e['calls_added'] for e in events)
              and {e['pid'] for e in events} == {r['pid'] for r in results})
        consumed = {**results[0]['response']['result']['initialization'], 'status': 'consumed'}
        baseline = receipt_bytes(path)
        response, audit = exchange(APP_UID, inspect_initialization)
        check('consumed_inspection_preserves_binding_and_files', response['ok']
              and response['result']['initialization'] == consumed and response['result']['wifi_gate_open'] is True
              and audit['state_unchanged'] and not audit['calls_added'] and receipt_bytes(path) == baseline)
        response, audit = exchange(APP_UID, request('begin_initialization', intent=OTHER_INTENT))
        check('conflicting_intent_requires_recovery', response == {'ok': False, 'error': 'recovery'}
              and audit['state_unchanged'] and not audit['calls_added'])
        running.close(); running = Server(context, workspace, path)
        response, _ = exchange(APP_UID, begin)
        check('restart_never_reissues_grant', response['result']['initialization']['status'] == 'already_consumed')
        response, _ = exchange(HELPER_UID, country)
        check('failure_checks_begin_with_confirmed_fake_gate', response['ok'] and response['result']['wifi_gate_open'] is True)
        # Absence of the whole root authority is not interpreted as authorized.
        retained = workspace / 'retained-receipt'; baseline = receipt_bytes(path)
        path.rename(retained)
        response, audit = exchange(APP_UID, inspect_initialization)
        check('absent_authority_inspection_refused_without_default',
              response == {'ok': False, 'error': 'refused'} and audit['state_unchanged']
              and not audit['calls_added'] and not path.exists() and receipt_bytes(retained) == baseline)
        retained.rename(path)
        # Deliberately corrupt only our own synthetic fixture, not image/app data.
        state = path / 'state.json'; original = state.read_bytes(); state.unlink()
        baseline = receipt_bytes(path)
        response, audit = exchange(APP_UID, inspect_initialization)
        check('missing_record_inspection_refused_without_default',
              response == {'ok': False, 'error': 'refused'} and audit['state_unchanged']
              and not audit['calls_added'] and receipt_bytes(path) == baseline)
        response, audit = exchange(APP_UID, begin)
        check('missing_receipt_requires_recovery', response == {'ok': False, 'error': 'recovery'} and not state.exists())
        state.write_bytes(b'corrupt'); state.chmod(0o600)
        baseline = receipt_bytes(path)
        response, audit = exchange(APP_UID, inspect_initialization)
        check('corrupt_record_inspection_refused_without_default',
              response == {'ok': False, 'error': 'refused'} and audit['state_unchanged']
              and not audit['calls_added'] and receipt_bytes(path) == baseline)
        response, _ = exchange(APP_UID, begin)
        check('corrupt_receipt_requires_recovery', response == {'ok': False, 'error': 'recovery'}
              and state.read_bytes() == b'corrupt')
        state.write_bytes(original)
        running.close(); running = None
        lost = workspace / 'lost-reply'; receipt.create_authorization(lost)
        running = Server(context, workspace, lost, kill_after_begin=True)
        result = clients(context, running.socket, [(APP_UID, begin, 'normal')], lost)[0]
        event = running.event(); running.process.join(2)
        check('killed_after_durable_consumption_before_reply', event == {
              'kind': 'consumed_before_reply', 'status': 'newly_consumed'}
              and running.process.exitcode == 73 and result.get('response') is None)
        running.close(); running = Server(context, workspace, lost)
        response, _ = exchange(APP_UID, begin)
        check('lost_response_retry_is_already_consumed', response['result']['initialization']['status'] == 'already_consumed')
        check('source_bytes_unchanged', source_hashes() == hashes)
    finally:
        if running is not None:
            running.close()
        require(shutil.rmtree.avoids_symlink_attacks, 'Safe fixture cleanup unavailable')
        trusted_directory(workspace)
        shutil.rmtree(workspace)
    checks.append({'name': 'fixtures_removed', 'passed': not workspace.exists()})
    return {'schema_version': 1, 'scope': 'linux-root-peercred-fixture-only',
            'passed': all(c['passed'] for c in checks), 'checks': checks, 'source_sha256': hashes,
            'platform': {'system': platform.system(), 'machine': platform.machine(), 'python': platform.python_version()},
            'method': {'kernel_peer_credentials': True, 'receipt_owner_overrides': False,
                       'app_uid': APP_UID, 'helper_uid': HELPER_UID, 'foreign_uid': FOREIGN_UID,
                       'client_groups_cleared_before_connect': True, 'real_root_receipt': True,
                       'initialization_inspection': 'real-readonly-receipt-callback-app-uid-only',
                       'server_lifetime_limit_seconds': SERVER_LIFETIME_SECONDS + SERVER_DRAIN_SECONDS,
                       'time_country_adapters': 'injected-fakes-only', 'runtime_installed': False,
                       'image_modified': False, 'clock_radio_services_changed': False,
                       'app_lifespan_started': False, 'hardware_qualified': False,
                       'generated_receipt_or_token_values_included': False},
            'limits': ['Socket framing and messages are private fixture mechanics, not a production wire contract.',
                       'UID authentication alone does not prove authenticated phone authorization.',
                       'Threads share one model; receipt locking is real, but the time/country model is not durable.',
                       'SIGKILL of the parent can leave the fixture directory; the server expires independently within 32 seconds.',
                       'Forked clients inherit parent memory; this proves filesystem permissions/SO_PEERCRED, not memory isolation.',
                       'Process termination is not physical power-loss or SD qualification.',
                       'No time syscall, regulatory observation, BLE, QR, app database or first boot is qualified.']}


def main():
    def interrupted(_signum, _frame):
        raise ProbeError('Fixture interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    try:
        require(len(sys.argv) == 1, 'This fixture accepts no paths or runtime arguments')
        result = run_probe()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result['passed'] else 1
    except Exception as exc:
        # Exception messages may contain synthetic paths/bindings. Keep failures
        # typed and generic; normal reports contain assertion names only.
        print(json.dumps({'schema_version': 1, 'scope': 'linux-root-peercred-fixture-only',
                          'passed': False, 'error_type': type(exc).__name__,
                          'failed_check': getattr(exc, 'failed_check', None),
                          'refusal': str(exc) if isinstance(exc, ProbeError) else None,
                          'clock_radio_services_changed': False}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
