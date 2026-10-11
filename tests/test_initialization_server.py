from contextlib import ExitStack
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


server = load('initialization_server', 'initialization-server.py')
receipt = load('initialization_receipt_ipc_tests', 'initialization-receipt.py')
ID = '11111111-1111-4111-8111-111111111111'
INTENT = '22222222-2222-4222-8222-222222222222'
OTHER = '33333333-3333-4333-8333-333333333333'


def request(begin=False):
    result = {'v': 1, 'id': ID, 'op': 'initialization.begin' if begin else 'initialization.inspect'}
    if begin:
        result['intent'] = INTENT
    return result


def wire(value):
    return json.dumps(value, separators=(',', ':')).encode() + b'\n'


def receive(client):
    data = b''
    client.settimeout(1)
    while True:
        block = client.recv(4096)
        if not block:
            break
        data += block
    assert data.endswith(b'\n') and data.count(b'\n') == 1
    assert len(data) <= server.RESPONSE_LIMIT
    return json.loads(data)


class ParsingTests(unittest.TestCase):
    def test_exact_requests(self):
        for begin in (False, True):
            self.assertEqual(server.parse_request(wire(request(begin))), request(begin))

    def test_wrong_types_unknown_fields_and_noncanonical_uuids(self):
        invalid = [[], None, True, {'v': 1}]
        for key, values in {
            'v': [True, 1.0, '1', None, 2],
            'id': [1, None, ID.upper().replace('1111', 'AAAA', 1), ID.replace('-', ''), '{' + ID + '}'],
            'op': [True, None, [], 'create_authorization', 'initialization.reset'],
            'intent': [None, False, INTENT.replace('-', '')],
        }.items():
            for value in values:
                item = request(True); item[key] = value; invalid.append(item)
        invalid.extend([{**request(), 'uid': 1000}, {**request(), 'intent': INTENT},
                        {key: value for key, value in request(True).items() if key != 'intent'}])
        for item in invalid:
            with self.subTest(item=item), self.assertRaises(server.InvalidRequest):
                server.parse_request(wire(item))

    def test_duplicates_nonfinite_utf8_and_framing_refused(self):
        raw = wire(request())
        for bad in [b'', raw[:-1], raw + b'\n', raw + raw, b'\xff\n',
                    raw.replace(b'"v":1', b'"v":1,"v":1'),
                    raw.replace(b'"v":1', b'"v":NaN'),
                    raw.replace(b'"v":1', b'"v":Infinity'), b'[' * 1010 + b'\n']:
            with self.subTest(raw=bad[:50]), self.assertRaises(server.InvalidRequest):
                server.parse_request(bad)

    def test_limit_includes_lf_and_request_id_recovery(self):
        raw = wire(request())
        maximum = raw[:-1] + b' ' * (1024 - len(raw)) + b'\n'
        self.assertEqual(len(maximum), 1024)
        self.assertEqual(server.parse_request(maximum), request())
        with self.assertRaises(server.InvalidRequest):
            server.parse_request(maximum[:-1] + b' \n')
        with self.assertRaises(server.InvalidRequest) as ctx:
            server.parse_request(wire({**request(), 'v': False}))
        self.assertEqual(ctx.exception.request_id, ID)

    def test_result_projection_closed(self):
        for result in [None, [], {'status': 'authorized', 'path': '/secret'},
                       {'status': 'newly_consumed', 'intent': OTHER,
                        'receipt': {'receipt_id': ID, 'digest': 'a' * 64}}]:
            with self.subTest(result=result), self.assertRaises(ValueError):
                server.validate_result(request(True), result)
        good = {'status': 'newly_consumed', 'intent': INTENT,
                'receipt': {'receipt_id': OTHER, 'digest': 'a' * 64}}
        self.assertIs(server.validate_result(request(True), good), good)
        with self.assertRaises(ValueError):
            server.encode({'x': 'a' * 2048})

    def test_pin_matches_unchanged_receipt(self):
        self.assertEqual(hashlib.sha256((ROOT / 'scripts/initialization-receipt.py').read_bytes()).hexdigest(),
                         server.RECEIPT_SHA256)

    def test_peer_credentials_decode_and_unsupported_fail_closed(self):
        connection = types.SimpleNamespace(getsockopt=lambda *args: struct.pack('3i', 123, 1000, 20))
        with patch.object(server.sys, 'platform', 'linux'), patch.object(server.socket, 'SO_PEERCRED', 17, create=True):
            self.assertEqual(server.peer_uid(connection), 1000)
        with patch.object(server.sys, 'platform', 'darwin'), self.assertRaises(OSError):
            server.peer_uid(connection)

    def test_invalid_peer_credentials_refused(self):
        for triple in ((0, 1000, 20), (123, -1, 20), (123, 1000, -1)):
            connection = types.SimpleNamespace(getsockopt=lambda *args: struct.pack('3i', *triple))
            with patch.object(server.sys, 'platform', 'linux'), \
                    patch.object(server.socket, 'SO_PEERCRED', 17, create=True), self.assertRaises(OSError):
                server.peer_uid(connection)

    @unittest.skipUnless(hasattr(socket, 'SO_PEERCRED') and server.sys.platform == 'linux',
                         'Linux kernel peer credentials only')
    def test_actual_kernel_peer_credentials_for_current_test_uid(self):
        left, right = socket.socketpair()
        with left, right:
            self.assertEqual(server.peer_uid(left), os.geteuid())


@unittest.skipUnless(hasattr(os, 'fork'), 'isolated receipt worker requires fork')
class SocketTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='.inkyos-ipc-test-', dir=Path.home().resolve())
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / 'authorization'
        self.owner = {'_owner_uid': os.geteuid(), '_owner_gid': os.getegid()}
        self.api = types.SimpleNamespace(IntentConflict=receipt.IntentConflict)
        self.api.inspect = lambda path: self.checked_call(path, receipt.inspect)
        self.api.begin = lambda path, intent: self.checked_call(path, receipt.begin, intent)
        self.worker = server.Worker(self.api)
        self.addCleanup(self.finish_worker)

    def checked_call(self, path, function, *args):
        if path != server.STATE:
            raise AssertionError('nonfixed production path')
        return function(self.path, *args, **self.owner)

    def finish_worker(self):
        self.worker.stop()
        # Fixture children are not in uninterruptible I/O; bounded reap for hygiene.
        end = time.monotonic() + 1
        while self.worker.pid is not None and time.monotonic() < end:
            self.worker.reap(); time.sleep(.005)
        self.assertIsNone(self.worker.pid)

    def create(self):
        receipt.create_authorization(self.path, **self.owner)

    def exchange(self, raw, *, uid=1000, budget=.5, half_close=False):
        client, connection = socket.socketpair()
        with client:
            client.sendall(raw)
            if half_close:
                client.shutdown(socket.SHUT_WR)
            server.handle_connection(connection, self.worker, _peer_uid=lambda _: uid, _budget=budget)
            return receive(client)

    def test_inspect_begin_retry_and_other_intent(self):
        self.create()
        self.assertEqual(self.exchange(wire(request()))['result'], {'status': 'authorized'})
        first = self.exchange(wire(request(True)))
        self.assertTrue(first['ok']); self.assertEqual(first['result']['status'], 'newly_consumed')
        again = self.exchange(wire(request(True)))
        self.assertEqual(again['result'], {**first['result'], 'status': 'already_consumed'})
        other = self.exchange(wire({**request(True), 'intent': OTHER}))
        self.assertEqual(other, server.error(ID, 'intent_conflict'))
        self.assertEqual(self.exchange(wire(request()))['result'], {**first['result'], 'status': 'consumed'})

    def test_root_and_network_helper_refused_before_consumption(self):
        self.create()
        for uid in (0, 997, 1001):
            result = self.exchange(wire(request(True)), uid=uid)
            self.assertEqual(result, server.error(ID, 'forbidden'))
        self.assertEqual(receipt.inspect(self.path, **self.owner), {'status': 'authorized'})

    def test_malformed_unauthorized_request_stays_forbidden_without_worker(self):
        self.create()
        with patch.object(self.worker, 'run') as operation:
            self.assertEqual(self.exchange(b'{broken}\n', uid=0), server.error(None, 'forbidden'))
            operation.assert_not_called()
        self.assertEqual(receipt.inspect(self.path, **self.owner), {'status': 'authorized'})

    def test_invalid_requests_and_pipelining_never_consume(self):
        self.create()
        for raw in [wire({**request(True), 'owner': True}), wire(request(True)) + wire(request()),
                    b'a' * 1025, b'{"v":1,"v":1}\n']:
            self.assertEqual(self.exchange(raw)['error'], 'invalid_request')
        self.assertEqual(receipt.inspect(self.path, **self.owner), {'status': 'authorized'})

    def test_absent_authority_is_not_created(self):
        self.assertEqual(self.exchange(wire(request()))['error'], 'unavailable')
        self.assertEqual(self.exchange(wire(request(True)))['error'], 'initialization_uncertain')
        self.assertFalse(self.path.exists())

    def test_corrupt_authority_is_not_recreated(self):
        self.create()
        (self.path / 'state.json').write_bytes(b'broken')
        before = {p.name: p.read_bytes() for p in self.path.iterdir()}
        self.assertEqual(self.exchange(wire(request(True)))['error'], 'initialization_uncertain')
        self.assertEqual({p.name: p.read_bytes() for p in self.path.iterdir()}, before)

    def test_worker_failure_is_closed_and_does_not_leak_exception(self):
        def failure(*args):
            raise RuntimeError('/private/network-data')
        self.api.begin = failure
        result = self.exchange(wire(request(True)))
        self.assertEqual(result, server.error(ID, 'initialization_uncertain'))
        self.assertNotIn('private', json.dumps(result))

    def test_peer_lookup_failure_never_consumes(self):
        self.create()
        for raw in (wire(request(True)), wire(request()), b'{broken}\n'):
            with self.subTest(raw=raw):
                client, connection = socket.socketpair()
                with client:
                    client.sendall(raw)
                    with patch.object(self.worker, 'run') as operation:
                        server.handle_connection(connection, self.worker,
                                                 _peer_uid=lambda _: (_ for _ in ()).throw(OSError()))
                        self.assertEqual(receive(client), server.error(None, 'unavailable'))
                        operation.assert_not_called()
        self.assertEqual(receipt.inspect(self.path, **self.owner), {'status': 'authorized'})

    def test_peer_lookup_failure_waits_only_within_original_deadline(self):
        self.create()
        for raw in (b'', wire(request(True))[:-1]):
            with self.subTest(raw=raw):
                client, connection = socket.socketpair()
                with client:
                    client.sendall(raw)
                    with patch.object(self.worker, 'run') as operation:
                        started = time.monotonic()
                        server.handle_connection(connection, self.worker, _budget=.15,
                                                 _peer_uid=lambda _: (_ for _ in ()).throw(OSError()))
                        self.assertLess(time.monotonic() - started, .5)
                        self.assertEqual(receive(client), server.error(None, 'unavailable'))
                        operation.assert_not_called()
        self.assertEqual(receipt.inspect(self.path, **self.owner), {'status': 'authorized'})

    def test_invalid_backend_result_after_begin_is_uncertain(self):
        self.api.begin = lambda *_: {'status': 'authorized', 'secret': 'never exposed'}
        self.assertEqual(self.exchange(wire(request(True))), server.error(ID, 'initialization_uncertain'))

    def test_timeout_after_durable_consume_never_reissues_grant(self):
        self.create()
        original = self.api.begin
        completed = self.path.parent / 'durable-consume-completed.json'
        def delayed(*args):
            result = original(*args)
            # Explicit evidence that BOTH receipt fsync transitions completed.
            # A short timeout alone could kill the child before it consumed,
            # in which case a later newly_consumed result would be legitimate.
            completed.write_text(json.dumps(result))
            time.sleep(5)
            return result
        self.api.begin = delayed
        started = time.monotonic()
        result = self.exchange(wire(request(True)), budget=1.5)
        self.assertLess(time.monotonic() - started, 2.5)
        self.assertEqual(result, server.error(ID, 'initialization_uncertain'))
        self.finish_worker()
        self.assertTrue(completed.is_file(), 'Fixture child did not finish durable consumption before timeout')
        first = json.loads(completed.read_text())
        self.assertEqual(first['status'], 'newly_consumed')
        self.api.begin = original
        self.assertEqual(self.exchange(wire(request(True)))['result'], {**first, 'status': 'already_consumed'})

    def test_flock_wait_is_bounded_and_authority_preserved(self):
        self.create()
        with receipt._locked(self.path, self.owner['_owner_uid'], self.owner['_owner_gid'], exclusive=True):
            started = time.monotonic()
            result = self.exchange(wire(request(True)), budget=.15)
            self.assertLess(time.monotonic() - started, .4)
            self.assertEqual(result['error'], 'initialization_uncertain')
        self.finish_worker()
        self.assertEqual(receipt.inspect(self.path, **self.owner), {'status': 'authorized'})

    def test_unreaped_child_blocks_next_invocation(self):
        self.worker.pid = 123456
        client, connection = socket.socketpair()
        try:
            with patch.object(server.os, 'waitpid', return_value=(0, 0)), patch.object(server.os, 'fork') as fork:
                self.assertEqual(self.worker.run(connection, request(True), time.monotonic() + 1),
                                 server.error(ID, 'unavailable'))
                fork.assert_not_called()
        finally:
            self.worker.pid = None
            client.close(); connection.close()

    def test_fork_failure_does_not_invoke_receipt(self):
        self.create()
        with patch.object(server.os, 'fork', side_effect=OSError()):
            self.assertEqual(self.exchange(wire(request(True))), server.error(ID, 'unavailable'))
        self.assertEqual(receipt.inspect(self.path, **self.owner), {'status': 'authorized'})

    def test_dead_child_without_response_is_uncertain(self):
        self.api.begin = lambda *_: os._exit(91)
        self.assertEqual(self.exchange(wire(request(True))), server.error(ID, 'initialization_uncertain'))

    def test_disconnect_after_consumption_leaves_same_intent_receipt(self):
        self.create()
        client, connection = socket.socketpair()
        client.sendall(wire(request(True))); client.close()
        server.handle_connection(connection, self.worker, _peer_uid=lambda _: 1000, _budget=.5)
        self.assertEqual(self.exchange(wire(request(True)))['result']['status'], 'already_consumed')

    def test_write_half_close_still_receives_single_response_and_eof(self):
        self.create()
        self.assertTrue(self.exchange(wire(request(True)), half_close=True)['ok'])

    def test_slow_stream_uses_absolute_deadline(self):
        client, connection = socket.socketpair()
        pid = os.fork()
        if pid == 0:
            connection.close()
            try:
                for char in wire(request(True)):
                    client.send(bytes([char])); time.sleep(.015)
            except OSError:
                pass
            os._exit(0)
        client.close()
        started = time.monotonic()
        try:
            server.handle_connection(connection, self.worker, _peer_uid=lambda _: 1000, _budget=.15)
            self.assertLess(time.monotonic() - started, .4)
            self.assertFalse(self.path.exists())
        finally:
            os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0)

    def test_parallel_servers_share_receipt_lock_and_only_one_new_grant(self):
        self.create()
        children = []
        for index in range(2):
            output = self.path.parent / f'result-{index}.json'
            pid = os.fork()
            if pid == 0:
                try:
                    output.write_text(json.dumps(self.exchange(wire(request(True)))))
                    os._exit(0)
                except BaseException:
                    os._exit(1)
            children.append((pid, output))
        results = []
        for pid, output in children:
            self.assertEqual(os.waitpid(pid, 0)[1], 0)
            results.append(json.loads(output.read_text())['result'])
        self.assertEqual(sorted(r['status'] for r in results), ['already_consumed', 'newly_consumed'])
        self.assertEqual(results[0]['receipt'], results[1]['receipt'])


class NotificationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='.inkyos-notify-', dir=Path.home().resolve())
        self.addCleanup(temporary.cleanup)
        self.address = str(Path(temporary.name) / 'notify.sock')

    def test_no_manager_does_not_open_socket_or_claim_notification(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(server.socket, 'socket') as opening:
            self.assertFalse(server.notify_ready())
            opening.assert_not_called()

    def test_pathname_receives_one_ready_and_environment_is_removed(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as manager:
            manager.bind(self.address)
            manager.settimeout(.05)
            with patch.dict(os.environ, {'NOTIFY_SOCKET': self.address}):
                self.assertTrue(server.notify_ready())
                self.assertNotIn('NOTIFY_SOCKET', os.environ)
                self.assertEqual(manager.recv(128), b'READY=1')
                self.assertFalse(server.notify_ready())
                with self.assertRaises(socket.timeout):
                    manager.recv(128)

    @unittest.skipUnless(server.sys.platform == 'linux', 'Linux abstract namespace and credentials only')
    def test_abstract_address_preserves_kernel_sender_identity(self):
        address = '@inkyos-ready-' + os.urandom(12).hex()
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as manager:
            manager.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            manager.bind('\0' + address[1:])
            manager.settimeout(.5)
            with patch.dict(os.environ, {'NOTIFY_SOCKET': address}):
                self.assertTrue(server.notify_ready())
                self.assertNotIn('NOTIFY_SOCKET', os.environ)
            raw, ancillary, _, _ = manager.recvmsg(128, socket.CMSG_SPACE(struct.calcsize('3i')))
            self.assertEqual(raw, b'READY=1')
            credentials = [data for level, kind, data in ancillary
                           if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS]
            self.assertEqual(len(credentials), 1)
            self.assertEqual(struct.unpack('3i', credentials[0]), (os.getpid(), os.getuid(), os.getgid()))

    def test_invalid_address_is_not_a_fallback_to_standalone(self):
        for address in ('', '@', '/', 'relative.sock', 'tcp:localhost:9', 'vsock:1:2'):
            with self.subTest(address=address), patch.dict(os.environ, {'NOTIFY_SOCKET': address}), \
                    patch.object(server.socket, 'socket') as opening:
                with self.assertRaises(ValueError):
                    server.notify_ready()
                self.assertNotIn('NOTIFY_SOCKET', os.environ)
                opening.assert_not_called()

    def test_unreachable_manager_closes_notification_socket(self):
        notification = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        with patch.dict(os.environ, {'NOTIFY_SOCKET': self.address}), \
                patch.object(server.socket, 'socket', return_value=notification), self.assertRaises(OSError):
            try:
                server.notify_ready()
            finally:
                self.assertNotIn('NOTIFY_SOCKET', os.environ)
                self.assertEqual(notification.fileno(), -1)

    def test_short_send_fails_closed_and_closes_notification_socket(self):
        notification = Mock()
        notification.sendto.return_value = 1
        context = Mock(__enter__=Mock(return_value=notification), __exit__=Mock(return_value=False))
        with patch.dict(os.environ, {'NOTIFY_SOCKET': self.address}), \
                patch.object(server.socket, 'socket', return_value=context), self.assertRaises(OSError):
            server.notify_ready()
        context.__exit__.assert_called_once()

    @unittest.skipUnless(server.sys.platform == 'linux', 'Linux UNIX datagram queue semantics only')
    def test_full_manager_queue_has_bounded_notification_failure(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as manager, ExitStack() as fillers:
            manager.bind(self.address)
            sent = 0
            for _ in range(32):
                filler = fillers.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM))
                filler.setblocking(False)
                sender_sent = 0
                while sent < 4096:
                    try:
                        filler.sendto(b'occupied', self.address)
                    except BlockingIOError:
                        break
                    sent += 1
                    sender_sent += 1
                else:
                    self.fail('Fixture manager queue exceeded its datagram budget')
                # A previously used sender can exhaust its own SO_SNDBUF while
                # the manager still has room. A fresh sender must also block.
                if sender_sent == 0:
                    break
            else:
                self.fail('Fixture manager queue exceeded its sender budget')
            with patch.dict(os.environ, {'NOTIFY_SOCKET': self.address}), \
                    patch.object(server, 'NOTIFY_TIMEOUT_SECONDS', .05):
                started = time.monotonic()
                with self.assertRaises(socket.timeout):
                    server.notify_ready()
                self.assertLess(time.monotonic() - started, .5)
                self.assertNotIn('NOTIFY_SOCKET', os.environ)


class StartupReadinessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='.inkyos-start-', dir=Path.home().resolve())
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name)
        self.runtime = self.parent / 'runtime'; self.runtime.mkdir(mode=0o750)
        self.control = self.runtime / 'control.sock'
        self.authorization = self.parent / 'authorization'
        self.owner = {'_owner_uid': os.geteuid(), '_owner_gid': os.getegid()}
        receipt.create_authorization(self.authorization, **self.owner)
        self.before = {p.name: p.read_bytes() for p in self.authorization.iterdir()}
        self.api = Mock()
        self.events = []
        self.resources = None
        self.real_fstat = os.fstat
        self.real_listen = server.listen
        self.real_worker = server.Worker

    def root_metadata(self, fd):
        info = self.real_fstat(fd)
        return types.SimpleNamespace(st_mode=info.st_mode, st_nlink=info.st_nlink,
                                     st_uid=0, st_gid=info.st_gid, st_size=info.st_size)

    def listen(self):
        self.events.append('listen')
        self.resources = self.real_listen()
        return self.resources

    def worker(self, *args):
        self.events.append('worker')
        return self.real_worker(*args)

    def loaded(self):
        self.events.append('load')
        return self.api

    def run_main(self, *, address=None, load_error=None, listen_error=None, worker_error=None,
                 accept=None):
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {}, clear=True))
            if address is not None:
                os.environ['NOTIFY_SOCKET'] = address
            for target, name, value in (
                (server.sys, 'platform', 'linux'), (server.os, 'geteuid', lambda: 0),
                (server, 'SOCKET', self.control), (server.os, 'fstat', self.root_metadata),
                (server, 'trusted_directory', lambda _: os.open(self.runtime, os.O_RDONLY)),
                (server.grp, 'getgrnam', lambda _: types.SimpleNamespace(gr_gid=os.getegid())),
            ):
                stack.enter_context(patch.object(target, name, value))
            stack.enter_context(patch.object(server, 'load_receipt', side_effect=load_error or self.loaded))
            stack.enter_context(patch.object(server, 'listen', side_effect=listen_error or self.listen))
            stack.enter_context(patch.object(server, 'Worker', side_effect=worker_error or self.worker))
            accept_mock = stack.enter_context(patch.object(socket.socket, 'accept',
                                                          side_effect=accept or OSError('fixture stop')))
            self.assertEqual(server.main([]), 1)
        self.api.inspect.assert_not_called(); self.api.begin.assert_not_called()
        self.assertEqual({p.name: p.read_bytes() for p in self.authorization.iterdir()}, self.before)
        self.assertEqual(receipt.inspect(self.authorization, **self.owner), {'status': 'authorized'})
        return accept_mock

    def assert_resources_closed(self):
        listener, lock, directory = self.resources
        self.assertEqual(listener.fileno(), -1)
        for fd in (lock, directory):
            with self.assertRaises(OSError):
                os.fstat(fd)
        with self.assertRaises(OSError), socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(self.control))
        with (self.runtime / '.server.lock').open('rb') as reopened:
            fcntl.flock(reopened.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_ready_only_after_source_listener_permissions_and_worker_before_accept(self):
        address = str(self.parent / 'notify.sock')
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as manager:
            manager.bind(address); manager.settimeout(.05)
            def accept():
                self.assertEqual(self.events, ['load', 'listen', 'worker'])
                listener, _, _ = self.resources
                self.assertEqual(listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN), 1)
                self.assertEqual(stat.S_IMODE(self.control.stat().st_mode), 0o660)
                self.assertEqual(manager.recv(128), b'READY=1')
                self.assertNotIn('NOTIFY_SOCKET', os.environ)
                with self.assertRaises(socket.timeout):
                    manager.recv(128)
                raise OSError('fixture stop')
            self.run_main(address=address, accept=accept).assert_called_once()
        self.assert_resources_closed()

    def test_startup_failure_never_notifies_or_accepts(self):
        address = str(self.parent / 'notify.sock')
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as manager:
            manager.bind(address); manager.settimeout(.05)
            for failure in ('load_error', 'listen_error', 'worker_error'):
                with self.subTest(failure=failure):
                    self.run_main(address=address, **{failure: ValueError('fixture failure')}).assert_not_called()
                    with self.assertRaises(socket.timeout):
                        manager.recv(128)
            self.assert_resources_closed()

    def test_failed_notification_closes_server_and_releases_lock_without_consuming(self):
        for address in ('', str(self.parent / 'absent.sock')):
            with self.subTest(address=address):
                self.run_main(address=address).assert_not_called()
                self.assert_resources_closed()

    def test_standalone_fixture_still_accepts_without_notification(self):
        notification = server.notify_ready
        def absent():
            self.assertNotIn('NOTIFY_SOCKET', os.environ)
            self.assertFalse(notification())
        with patch.object(server, 'notify_ready', side_effect=absent) as notify:
            self.run_main().assert_called_once()
            notify.assert_called_once()
        self.assert_resources_closed()


class StagingTests(unittest.TestCase):
    def test_unit_is_uninstalled_without_state_creation_or_capabilities(self):
        raw = (ROOT / 'staging/bootstrap/inkyos-initialization.service').read_text()
        for line in ('Type=notify', 'NotifyAccess=main', 'TimeoutStartSec=10s',
                     'User=root', 'Group=inky-provisioning', 'SupplementaryGroups=root',
                     'RuntimeDirectoryMode=0750', 'CapabilityBoundingSet=', 'KillMode=control-group',
                     'RestrictAddressFamilies=AF_UNIX', 'ProtectSystem=strict'):
            self.assertIn(line + '\n', raw)
        self.assertNotIn('StateDirectory=', raw)
        self.assertNotIn('[Install]', raw)
        self.assertNotIn('create_authorization', (ROOT / 'scripts/initialization-server.py').read_text())

    def test_main_arguments_and_platform_refused_without_side_effects(self):
        with patch.object(server, 'listen') as listen, patch.object(server, 'load_receipt') as source:
            self.assertEqual(server.main(['--create']), 1)
            with patch.object(server.sys, 'platform', 'darwin'):
                self.assertEqual(server.main([]), 1)
            listen.assert_not_called(); source.assert_not_called()

    def test_no_runtime_directory_creation_or_unsafe_ancestors(self):
        temporary = tempfile.TemporaryDirectory(prefix='.inkyos-ipc-path-', dir=Path.home().resolve())
        self.addCleanup(temporary.cleanup)
        parent = Path(temporary.name)
        with self.assertRaises((ValueError, FileNotFoundError)):
            server.trusted_directory(parent / 'absent')
        self.assertFalse((parent / 'absent').exists())
        target = parent / 'target'; target.mkdir()
        link = parent / 'link'; link.symlink_to(target)
        with self.assertRaises((ValueError, OSError)):
            server.trusted_directory(link)

    def test_load_source_checks_pin_before_execution(self):
        temporary = tempfile.TemporaryDirectory(prefix='.inkyos-ipc-source-', dir=Path.home().resolve())
        self.addCleanup(temporary.cleanup)
        parent = Path(temporary.name)
        source = parent / 'receipt.py'
        source.write_bytes(b'raise AssertionError("must not execute")\n'); source.chmod(0o444)
        real_fstat = os.fstat
        def root_metadata(fd):
            info = real_fstat(fd)
            return types.SimpleNamespace(st_mode=info.st_mode, st_nlink=info.st_nlink,
                                         st_uid=0, st_gid=0, st_size=info.st_size)
        with patch.object(server, 'RECEIPT_SOURCE', source), \
                patch.object(server, 'trusted_directory', side_effect=lambda _: os.open(parent, os.O_RDONLY)), \
                patch.object(server.os, 'fstat', side_effect=root_metadata), self.assertRaisesRegex(ValueError, 'source pin'):
            server.load_receipt()

    def test_load_source_rejects_symlink(self):
        temporary = tempfile.TemporaryDirectory(prefix='.inkyos-ipc-source-', dir=Path.home().resolve())
        self.addCleanup(temporary.cleanup)
        parent = Path(temporary.name)
        source = parent / 'receipt.py'
        source.symlink_to(ROOT / 'scripts/initialization-receipt.py')
        with patch.object(server, 'RECEIPT_SOURCE', source), \
                patch.object(server, 'trusted_directory', side_effect=lambda _: os.open(parent, os.O_RDONLY)), \
                self.assertRaises(OSError):
            server.load_receipt()


if __name__ == '__main__':
    unittest.main()
