"""Inert graph observations, with no PID1, service, process signal or hardware.

The lease, sources and kernel backend below are explicit synthetic dependencies.
Their handles are logical tokens, not pidfds; these tests do not qualify Linux
permissions, pidfd inode identity, a sandbox, an installed graph or Pi budgets.
"""
import copy
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'inkyos_writer_graph_tests', ROOT / 'staging/bootstrap/writer-graph.py')
graph = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = graph
spec.loader.exec_module(graph)


def observations(role, pid, invocation):
    name = graph.UNITS[role]
    wants = ({'inkyos-initialization.service', 'inky-network.service', 'bluetooth.service'}
             if role == 'main' else {'inkyos-initialization.service', 'NetworkManager.service'}
             if role == 'helper' else {'inkyos-admission-prepare.service',
                                      'inkyos-factory-supervisor.service'})
    unit = {
        'Id': name, 'Names': [name], 'LoadState': 'loaded', 'ActiveState': 'active',
        'SubState': 'running', 'FragmentPath': '/usr/lib/systemd/system/' + name,
        'DropInPaths': [], 'Transient': False, 'NeedDaemonReload': False,
        'InvocationID': list(invocation), 'Job': [0, '/'], 'Wants': sorted(wants),
        'After': sorted(wants), 'PartOf': [], 'BindsTo': [], 'PropagatesStopTo': [],
        'StopPropagatedFrom': [],
    }
    argv = ['/usr/bin/python3.13', '-I', '-B', '-S',
            '/usr/lib/inkyos/writer-launcher.py', role]
    service = {
        'MainPID': pid, 'ControlPID': 0, 'Type': 'notify' if role == 'ipc' else 'exec',
        'User': {'main': 'inky', 'helper': 'inky-network', 'ipc': 'root'}[role],
        'Group': 'inky' if role == 'main' else 'inky-provisioning',
        'SupplementaryGroups': (['spi', 'i2c', 'gpio', 'inky-provisioning']
                                if role == 'main' else ['root'] if role == 'ipc' else []),
        'ExecStart': [['/usr/bin/python3.13', argv, False, 0, 0, 0, 0, 0, 0, 0]],
        'Restart': 'no', 'KillMode': 'mixed', 'KillSignal': signal.SIGTERM,
        'SendSIGKILL': False, 'TimeoutStopUSec': 2**64 - 1,
        'NoNewPrivileges': True, 'PrivateNetwork': role == 'ipc',
    }
    return [unit, service]


class Lease:
    def __init__(self):
        self.held = False
        self.enters = self.exits = self.checks = 0
        self.failure = None

    def __enter__(self):
        if self.held:
            raise AssertionError('synthetic lease adopted twice')
        self.held = True
        self.enters += 1
        return self

    def check(self):
        if not self.held:
            raise AssertionError('observation without synthetic lease')
        self.checks += 1
        if self.failure is not None:
            raise self.failure

    def __exit__(self, *_):
        self.held = False
        self.exits += 1
        return False


class Sources:
    def __init__(self):
        self.lease = None
        self.prepares = self.checks = self.closes = 0
        self.prepare_result = self.check_result = None
        self.failure = self.check_hook = None

    def prepare(self, lease):
        self.lease = lease
        self.prepares += 1
        if not lease.held:
            raise AssertionError('sources prepared before lease')
        return self.prepare_result

    def check(self, deadline):
        if not self.lease.held:
            raise AssertionError('source check after lease release')
        graph.remaining(deadline)
        self.checks += 1
        if self.check_hook is not None:
            self.check_hook()
        if self.failure is not None:
            raise self.failure
        return self.check_result

    def close(self):
        if not self.lease.held:
            raise AssertionError('source close after lease release')
        self.closes += 1


class Connection:
    def __init__(self, pid):
        self.pid, self.closed, self.accesses = pid, False, 0

    def fileno(self):
        self.accesses += 1
        if self.closed:
            raise AssertionError('closed connection inspected')
        return 700


class Backend:
    """Snapshots and handle identity are entirely synthetic, including pidfd liveness."""
    def __init__(self):
        self.pids = {'main': os.getpid(), 'helper': os.getpid() + 10000,
                     'ipc': os.getpid() + 20000}
        self.invocations = {role: bytes([index]) * 16
                            for index, role in enumerate(graph.UNITS, 1)}
        self.rows = {role: observations(role, self.pids[role], self.invocations[role])
                     for role in graph.UNITS}
        self.handles, self.dead, self.closed = {}, set(), []
        self.next_handle = 100
        self.calls = []
        self.snapshot_hook = self.resolve_hook = None
        self.error = None
        self.is_quiescent = True

    def _new(self, pid, role):
        self.next_handle += 1
        invocation = b'\x09' * 16 if role == 'manager' else self.invocations[role]
        name = 'init.scope' if role == 'manager' else graph.UNITS[role]
        self.handles[self.next_handle] = (pid, graph.unit_path(name), name, invocation)
        return self.next_handle

    def open_pid(self, pid):
        self.calls.append(('open', pid))
        if pid == 1:
            return self._new(pid, 'manager')
        for role, rows in self.rows.items():
            if rows[1]['MainPID'] == pid:
                return self._new(pid, role)
        raise graph.Refused('synthetic_unknown_pid')

    def close_pid(self, fd):
        if fd in self.closed:
            raise AssertionError('synthetic handle closed twice')
        self.closed.append(fd)

    def live(self, fd):
        return fd in self.handles and fd not in self.dead and fd not in self.closed

    def same_pid(self, first, second):
        return (self.live(first) and self.live(second)
                and self.handles[first] == self.handles[second])

    def resolve(self, fd, deadline):
        graph.remaining(deadline)
        self.calls.append(('resolve', fd))
        if self.error is not None:
            raise self.error
        if self.resolve_hook is not None:
            result = self.resolve_hook(fd)
            if result is not None:
                return result
        if not self.live(fd):
            raise graph.Refused('writer_dead')
        return self.handles[fd][1:]

    def snapshot(self, role, deadline):
        graph.remaining(deadline)
        self.calls.append(('snapshot', role))
        if self.snapshot_hook is not None:
            self.snapshot_hook(role)
        if self.error is not None:
            raise self.error
        return copy.deepcopy(self.rows[role])

    def peer(self, connection):
        connection.fileno()
        self.calls.append(('peer', connection.pid))
        return self._new(connection.pid, 'ipc')

    def quiescent(self):
        return self.is_quiescent

    def drain(self):
        self.calls.append(('drain',))
        return self.is_quiescent


class GraphFixture(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='inkyos-graph-inert-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.lease, self.sources, self.backend = Lease(), Sources(), Backend()
        self.proof = graph.Graph(self.lease, self.sources, self.backend, _root=self.root)
        self.addCleanup(self.cleanup_proof)

    def cleanup_proof(self):
        self.backend.is_quiescent = True
        self.sources.failure = self.sources.check_hook = None
        self.lease.failure = None
        if (self.proof._lease is not None and self.proof._peer_count == 0
                and not self.proof._query.locked()):
            self.proof.close()

    def active(self):
        self.assertIs(self.proof.__enter__(), self.proof)
        return self.proof

    def refused(self, operation, reason=None):
        with self.assertRaises(graph.Refused) as caught:
            operation()
        if reason is not None:
            self.assertEqual(caught.exception.reason, reason)
        return caught.exception


class WriterGraphTests(GraphFixture):
    def test_admission_owns_fresh_lease_and_all_four_anchors(self):
        self.active()
        self.assertEqual(self.proof.state, 'ACTIVE')
        self.assertEqual(self.sources.prepares, 1)
        self.assertEqual(set(self.proof._anchors), {'manager', 'main', 'helper', 'ipc'})
        self.assertTrue(self.lease.held)
        self.assertIsNone(self.proof.check())
        self.proof.close()
        self.assertEqual((self.proof.state, self.lease.exits), ('CLOSED', 1))
        self.assertFalse(self.lease.held)
        self.assertEqual(set(self.backend.handles), set(self.backend.closed))

    def test_type_exec_start_job_stabilizes_readonly_before_admission(self):
        unit = self.backend.rows['main'][0]
        unit.update(ActiveState='activating', SubState='start',
                    Job=[8, graph.MANAGER + '/job/8'])
        visits = []
        def settle(role):
            if role == 'main':
                visits.append(self.proof.state)
                if len(visits) == 2:
                    unit.update(ActiveState='active', SubState='running', Job=[0, '/'])
        self.backend.snapshot_hook = settle
        self.active()
        self.assertGreaterEqual(len(visits), 3)
        self.assertEqual(visits[:2], ['BINDING', 'BINDING'])
        self.assertEqual(self.sources.prepares, 1)
        self.assertFalse(any(call[0] == 'peer' for call in self.backend.calls))

    def test_initial_wait_has_a_deadline_and_releases_known_ownership(self):
        self.backend.rows['helper'][0]['Job'] = [9, graph.MANAGER + '/job/9']
        with patch.object(graph, 'INITIAL_SECONDS', 0.01):
            self.refused(self.proof.__enter__, 'observation_timeout')
        self.assertEqual(self.proof.state, 'CLOSED')
        self.assertFalse(self.lease.held)
        self.assertFalse(any(call[0] == 'peer' for call in self.backend.calls))

    def test_same_unit_child_cannot_claim_main_self_identity(self):
        self.backend.rows['main'][1]['MainPID'] += 1
        self.refused(self.proof.__enter__, 'not_mainpid')
        self.assertFalse(self.lease.held)

    def test_aliases_and_dropins_refuse_before_pid_anchors(self):
        for key, value in (('Names', [graph.UNITS['helper'], 'alias.service']),
                           ('DropInPaths', ['/inert/override.conf'])):
            with self.subTest(property=key):
                lease, sources, backend = Lease(), Sources(), Backend()
                backend.rows['helper'][0][key] = value
                proof = graph.Graph(lease, sources, backend, _root=self.root)
                self.refused(proof.__enter__, 'unit_configuration')
                self.assertFalse(lease.held)
                self.assertFalse(any(call == ('open', backend.pids['helper'])
                                     for call in backend.calls))

    def test_loaded_reload_or_transient_unit_is_never_admitted(self):
        for key in ('Transient', 'NeedDaemonReload'):
            with self.subTest(property=key):
                lease, sources, backend = Lease(), Sources(), Backend()
                backend.rows['ipc'][0][key] = True
                self.refused(graph.Graph(lease, sources, backend, _root=self.root).__enter__, 'unit_configuration')
                self.assertFalse(lease.held)

    def test_stop_propagation_is_rejected(self):
        self.backend.rows['main'][0]['PropagatesStopTo'] = [graph.UNITS['ipc']]
        self.refused(self.proof.__enter__, 'stop_propagation')

    def test_fixed_dependencies_and_execstart_are_enforced(self):
        for mutation, reason in (
            (lambda rows: rows[0]['Wants'].append('unrelated.service'), 'unit_dependencies'),
            (lambda rows: rows[1]['ExecStart'][0][1].append('--override'), 'unit_execstart')):
            with self.subTest(reason=reason):
                lease, sources, backend = Lease(), Sources(), Backend()
                mutation(backend.rows['main'])
                self.refused(graph.Graph(lease, sources, backend, _root=self.root).__enter__, reason)
                self.assertFalse(lease.held)

    def test_loaded_identity_and_kill_policy_remain_closed(self):
        for key, value in (('User', 'root'), ('SendSIGKILL', True), ('NoNewPrivileges', False)):
            with self.subTest(property=key):
                lease, sources, backend = Lease(), Sources(), Backend()
                backend.rows['main'][1][key] = value
                self.refused(graph.Graph(lease, sources, backend, _root=self.root).__enter__, 'unit_policy')
                self.assertFalse(lease.held)

    def test_active_writer_requires_nonzero_invocation(self):
        self.backend.rows['ipc'][0]['InvocationID'] = [0] * 16
        self.refused(self.proof.__enter__, 'missing_invocation')

    def test_pid_one_must_resolve_to_init_scope_before_writer_observation(self):
        self.backend.resolve_hook = lambda fd: (
            graph.unit_path(graph.UNITS['main']), graph.UNITS['main'], b'x' * 16)
        self.refused(self.proof.__enter__, 'pid_view_unconfirmed')
        self.assertFalse(any(call[0] == 'snapshot' for call in self.backend.calls))

    def test_pid_mapping_change_during_bind_refuses_and_closes_anchors(self):
        def change(fd):
            if self.backend.handles[fd][2] == graph.UNITS['helper']:
                path, name, _ = self.backend.handles[fd][1:]
                return path, name, b'z' * 16
        self.backend.resolve_hook = change
        self.refused(self.proof.__enter__, 'writer_mapping_changed')
        self.assertEqual(set(self.backend.handles), set(self.backend.closed))
        self.assertFalse(self.lease.held)

    def test_dead_writer_invalidates_permanently_without_rebinding(self):
        self.active()
        fd = self.proof._anchors['helper']
        self.backend.dead.add(fd)
        self.refused(self.proof.check, 'writer_dead')
        calls = len(self.backend.calls)
        self.backend.dead.remove(fd)
        self.refused(self.proof.check, 'graph_invalid')
        self.assertEqual(len(self.backend.calls), calls)
        self.assertEqual(self.proof.reason, 'writer_dead')
        self.assertTrue(self.lease.held)

    def test_invocation_or_mainpid_replacement_is_not_readmitted(self):
        for table, key, value in ((0, 'InvocationID', [8] * 16),
                                  (1, 'MainPID', os.getpid() + 30000)):
            with self.subTest(property=key):
                lease, sources, backend = Lease(), Sources(), Backend()
                with graph.Graph(lease, sources, backend, _root=self.root) as proof:
                    previous = backend.rows['helper'][table][key]
                    backend.rows['helper'][table][key] = value
                    self.refused(proof.check, 'writer_changed')
                    backend.rows['helper'][table][key] = previous
                    self.refused(proof.check, 'graph_invalid')
                    self.assertTrue(lease.held)

    def test_new_start_job_after_admission_is_invalid_not_initial_wait(self):
        self.active()
        self.backend.rows['main'][0]['Job'] = [4, graph.MANAGER + '/job/4']
        self.refused(self.proof.check, 'writer_changed')
        self.assertEqual(self.proof.state, 'INVALID')

    def test_source_callbacks_require_exact_none(self):
        self.sources.prepare_result = False
        self.refused(self.proof.__enter__, 'source_prepare_result')
        self.assertFalse(self.lease.held)
        lease, sources, backend = Lease(), Sources(), Backend()
        with graph.Graph(lease, sources, backend, _root=self.root) as proof:
            sources.check_result = True
            self.refused(proof.check, 'source_check_result')
            self.assertTrue(lease.held)

    def test_source_or_lease_change_blocks_further_observations(self):
        self.active()
        self.lease.failure = graph.Refused('lease_replaced')
        calls = len(self.backend.calls)
        self.refused(self.proof.check, 'lease_replaced')
        self.assertEqual(len(self.backend.calls), calls)
        self.assertEqual(self.proof.reason, 'lease_replaced')
        self.assertTrue(self.lease.held)

    def test_source_failure_is_not_converted_to_success(self):
        self.active()
        self.sources.failure = PermissionError('INERT_SOURCE_DENIED')
        with self.assertRaises(PermissionError):
            self.proof.check()
        self.assertEqual((self.proof.state, self.proof.reason), ('INVALID', 'observation_failed'))
        self.assertTrue(self.lease.held)

    def test_manager_identity_is_rechecked_with_retained_anchor(self):
        self.active()
        manager = self.proof._anchors['manager']
        self.backend.resolve_hook = lambda fd: (
            graph.unit_path('init.scope'), 'init.scope', b'\x0a' * 16) if fd == manager else None
        self.refused(self.proof.check, 'pid_view_changed')

    def test_execstart_accounting_changes_do_not_replace_launch_configuration(self):
        self.active()
        for rows in self.backend.rows.values():
            rows[1]['ExecStart'][0][3:] = [1, 2, 3, 4, 5, 0, 0]
        self.assertIsNone(self.proof.check())
        self.backend.rows['ipc'][1]['ExecStart'][0][2] = True
        self.refused(self.proof.check, 'unit_execstart')

    def test_concurrent_queries_serialize_with_a_bounded_wait(self):
        self.active()
        entered, release = threading.Event(), threading.Event()
        errors = []
        def blocked(role):
            if role == 'main':
                entered.set()
                if not release.wait(1):
                    raise AssertionError('test barrier not released')
        self.backend.snapshot_hook = blocked
        def verify():
            try:
                self.proof.check()
            except BaseException as error:
                errors.append(error)
        with patch.object(graph, 'CHECK_SECONDS', 0.05):
            worker = threading.Thread(target=verify)
            worker.start()
            try:
                self.assertTrue(entered.wait(1))
                self.refused(self.proof.check, 'observation_timeout')
                self.assertTrue(self.lease.held)
            finally:
                release.set()
                worker.join(1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], graph.Refused)
        self.assertEqual(self.proof.state, 'INVALID')

    def test_invalidation_from_source_thread_wins_over_a_successful_query(self):
        self.active()
        self.sources.check_hook = lambda: self.proof.invalidate('INERT_EXTERNAL_STOP')
        self.refused(self.proof.check, 'graph_invalid')
        self.assertEqual(self.proof.reason, 'INERT_EXTERNAL_STOP')

    def test_monitor_requests_owner_stop_from_its_thread_without_writer_actions(self):
        self.active()
        stopped, observed_thread = threading.Event(), []
        owner_thread = threading.get_ident()
        class Loop:
            def call_soon_threadsafe(_, callback):
                observed_thread.append(threading.get_ident())
                callback()
        self.backend.dead.add(self.proof._anchors['ipc'])
        with patch.object(graph, 'WATCH_SECONDS', 0.01):
            self.proof.start_monitor(Loop(), stopped)
            self.assertTrue(stopped.wait(1))
        self.assertEqual(self.proof.state, 'INVALID')
        self.assertTrue(any(identity != owner_thread for identity in observed_thread))
        self.assertTrue(self.lease.held)
        self.assertFalse(any(call[0] in {'signal', 'stop', 'restart'} for call in self.backend.calls))

    def test_invalid_latch_retains_first_reason_and_tolerates_closed_loop(self):
        self.active()
        class ClosedLoop:
            def call_soon_threadsafe(_, callback):
                raise RuntimeError('INERT_LOOP_CLOSED')
        self.proof._loop, self.proof._stop_requested = ClosedLoop(), threading.Event()
        self.proof.invalidate('first_failure')
        self.proof.invalidate('later_failure')
        self.assertEqual((self.proof.state, self.proof.reason), ('INVALID', 'first_failure'))
        self.assertTrue(self.lease.held)

    def test_actual_peer_proof_remains_owned_until_socket_drained(self):
        self.active()
        connection = Connection(self.backend.pids['ipc'])
        with self.proof.initialization_guard(connection) as value:
            self.assertIsNone(value)
            peer = self.backend.next_handle
            self.assertNotIn(peer, self.backend.closed)
            self.assertTrue(self.lease.held)
            connection.closed = True
        self.assertIn(peer, self.backend.closed)
        self.assertEqual(connection.accesses, 1)
        self.assertEqual(self.proof._peer_count, 0)

    def test_connected_same_unit_child_is_refused_before_scope_yields(self):
        self.active()
        connection = Connection(self.backend.pids['ipc'] + 1)
        with self.assertRaises(graph.Refused) as caught:
            with self.proof.initialization_guard(connection):
                self.fail('same-unit child was admitted')
        self.assertEqual(caught.exception.reason, 'peer_not_mainpid')
        self.assertEqual(self.proof.state, 'INVALID')
        self.assertIn(self.backend.next_handle, self.backend.closed)
        self.assertTrue(self.lease.held)

    def test_peer_unit_invocation_change_refuses_even_with_identity_match(self):
        self.active()
        anchor = self.proof._anchors['ipc']
        def changed(fd):
            if fd != anchor and self.backend.handles[fd][2] == graph.UNITS['ipc']:
                return graph.unit_path(graph.UNITS['ipc']), graph.UNITS['ipc'], b'z' * 16
        self.backend.resolve_hook = changed
        with self.assertRaises(graph.Refused) as caught:
            with self.proof.initialization_guard(Connection(self.backend.pids['ipc'])):
                self.fail('changed peer invocation was admitted')
        self.assertEqual(caught.exception.reason, 'peer_mapping_changed')
        self.assertTrue(self.lease.held)

    def test_exception_inside_peer_scope_propagates_and_releases_only_peer(self):
        self.active()
        with self.assertRaisesRegex(RuntimeError, 'INERT_RESPONSE_FAILED'):
            with self.proof.initialization_guard(Connection(self.backend.pids['ipc'])):
                raise RuntimeError('INERT_RESPONSE_FAILED')
        self.assertEqual(self.proof.state, 'INVALID')
        self.assertEqual(self.proof._peer_count, 0)
        self.assertTrue(self.lease.held)
        self.assertTrue(all(self.backend.live(fd) for fd in self.proof._anchors.values()))

    def test_close_with_admitted_peer_retains_lease_until_its_exit(self):
        self.active()
        connection = Connection(self.backend.pids['ipc'])
        with self.proof.initialization_guard(connection):
            self.refused(self.proof.close, 'peer_not_drained')
            self.assertTrue(self.lease.held)
            self.assertEqual(self.sources.closes, 0)
            connection.closed = True
        self.proof.close()
        self.assertFalse(self.lease.held)
        self.assertEqual(connection.accesses, 1)

    def test_unreaped_owned_query_retains_all_anchors_and_lease(self):
        self.active()
        self.backend.is_quiescent = False
        before = set(self.proof._anchors.values())
        with self.assertRaises(graph.ObservationUnknown):
            self.proof.close()
        self.assertTrue(self.lease.held)
        self.assertTrue(all(self.backend.live(fd) for fd in before))
        self.assertEqual(self.sources.closes, 0)
        self.backend.is_quiescent = True
        self.proof.close()
        self.assertFalse(self.lease.held)

    def test_busy_query_prevents_close_and_lease_release(self):
        self.active()
        self.proof._query.acquire()
        try:
            with patch.object(graph, 'CLEANUP_SECONDS', 0.01):
                with self.assertRaises(graph.ObservationUnknown):
                    self.proof.close()
            self.assertTrue(self.lease.held)
            self.assertEqual(self.sources.closes, 0)
        finally:
            self.proof._query.release()
        self.proof.close()
        self.assertFalse(self.lease.held)


class TypedObservationTests(unittest.TestCase):
    @staticmethod
    def service_reply():
        service = observations('main', os.getpid(), b'\x01' * 16)[1]
        table = {key: {'type': signature, 'data': service[key]}
                 for key, signature in graph.SERVICE_TYPES.items()}
        return {'type': 'a{sv}', 'data': [table]}, service

    def test_getall_refuses_wrong_signature_or_extra_cell_fields(self):
        reply, expected = self.service_reply()
        self.assertEqual(graph.properties(json.dumps(reply).encode(), graph.SERVICE_TYPES), expected)
        for mutation in (
            lambda table: table['MainPID'].update(type='i'),
            lambda table: table['NoNewPrivileges'].update(extra='INERT_UNEXPECTED')):
            with self.subTest(mutation=mutation):
                altered = copy.deepcopy(reply)
                mutation(altered['data'][0])
                with self.assertRaises(graph.Refused) as caught:
                    graph.properties(json.dumps(altered).encode(), graph.SERVICE_TYPES)
                self.assertEqual(caught.exception.reason, 'property_shape')

    def test_getall_unsigned_pid_rejects_boolean_despite_matching_signature(self):
        reply, _ = self.service_reply()
        reply['data'][0]['MainPID']['data'] = True
        with self.assertRaises(graph.Refused) as caught:
            graph.properties(json.dumps(reply).encode(), graph.SERVICE_TYPES)
        self.assertEqual(caught.exception.reason, 'property_shape')

    def test_getall_missing_required_property_is_not_a_partial_observation(self):
        reply, _ = self.service_reply()
        del reply['data'][0]['MainPID']
        with self.assertRaises(graph.Refused) as caught:
            graph.properties(json.dumps(reply).encode(), graph.SERVICE_TYPES)
        self.assertEqual(caught.exception.reason, 'property_shape')

    def test_query_allowlist_refuses_mutation_before_spawning_any_command(self):
        commands = graph.ReadOnlyCommands()
        with patch.object(graph.subprocess, 'Popen', side_effect=AssertionError('command spawned')):
            with self.assertRaises(graph.Refused) as caught:
                commands.call(graph.MANAGER, graph.MANAGER_INTERFACE, 'StopUnit', 'ss',
                              (graph.UNITS['ipc'], 'replace'), 0)
        self.assertEqual(caught.exception.reason, 'unsupported_query')
        self.assertTrue(commands.quiescent())

    def test_duplicate_reply_fields_and_wrong_dbus_types_are_refused(self):
        with self.assertRaises(graph.Refused):
            graph.decode(b'{"type":"a{sv}","type":"other","data":[]}')
        rows = observations('main', os.getpid(), b'\x01' * 16)
        for key, bad in (('MainPID', True), ('NoNewPrivileges', 1)):
            with self.subTest(property=key):
                altered = copy.deepcopy(rows)
                altered[1][key] = bad
                with self.assertRaises(graph.Refused):
                    graph.binding('main', altered)

    def test_synthetic_contract_must_be_canonical_and_cannot_be_root(self):
        class Contract:
            def __init__(self, root):
                self._root = root
        runtime = SimpleNamespace(Contract=Contract,
                                  writer_guard=lambda *_args, **_kwargs: Lease())
        with tempfile.TemporaryDirectory(prefix='inkyos-graph-inert-') as directory:
            root = Path(directory).resolve()
            for rejected in (Path('/'), root / 'missing', Path('relative')):
                with self.subTest(root=str(rejected)), self.assertRaises((graph.Refused, FileNotFoundError)):
                    graph.open_main(_contract=Contract(rejected), _runtime=runtime,
                                    _backend=Backend(), _sources=Sources())
            proof = graph.open_main(_contract=Contract(root), _runtime=runtime,
                                    _backend=Backend(), _sources=Sources())
            with proof:
                self.assertEqual(proof.state, 'ACTIVE')

    def test_production_entry_refuses_every_injected_dependency_before_loading(self):
        for override in ({}, {'_root': Path('/')}):
            with self.subTest(constructor=override), self.assertRaises(graph.Refused):
                graph.Graph(Lease(), Sources(), Backend(), **override)
        with patch.object(graph, 'installed_runtime', side_effect=AssertionError('production load')):
            for override in ({'_runtime': object()}, {'_backend': Backend()}, {'_sources': Sources()}):
                with self.subTest(override=next(iter(override))), self.assertRaises(graph.Refused) as caught:
                    graph.open_main(**override)
                self.assertEqual(caught.exception.reason, 'invalid_override')


class InstalledSourceRefusalTests(unittest.TestCase):
    class AfterLaunchContract(RuntimeError):
        """The inert fixture stops immediately after the launch AST guard."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='inkyos-support-inert-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.actions = []
        self.support = {
            'paths': [graph.SELF[1:], graph.MAIN[1:], graph.BUSCTL[1:]],
            'elf_closure_review': {'roots': [graph.BUSCTL[1:]], 'files': []},
        }
        self.records = {path: {'type': 'file', 'mode': '0555'}
                        for path in self.support['paths']}
        def inventories(contract):
            self.actions.append('inventories')
            return {}, {}, self.support, self.records
        def resolve(path, records):
            self.actions.append('resolve')
            return path
        def forbidden_tree():
            self.actions.append('tree')
            raise AssertionError('refusal must precede tree/read')
        def forbidden_hash(*args):
            self.actions.append('hash')
            raise AssertionError('refusal must precede source reads')
        self.runtime = SimpleNamespace(inventories=inventories, resolve=resolve,
                                       check_path=forbidden_hash)
        self.contract = SimpleNamespace(_root=self.root,
                                        manifest={'studio_commit': graph.STUDIO_COMMIT},
                                        tree=forbidden_tree)
        self.sources = graph.InstalledSources(self.runtime, self.contract)

    def refused_before_tree(self, reason):
        with Lease() as lease, \
                patch.object(graph.subprocess, 'Popen', side_effect=AssertionError('command spawned')):
            with self.assertRaises(graph.Refused) as caught:
                self.sources.prepare(lease)
        self.assertEqual(caught.exception.reason, reason)
        self.assertNotIn('tree', self.actions)
        self.assertNotIn('hash', self.actions)

    def test_different_studio_candidate_refuses_before_inventory_or_source_access(self):
        for candidate in ('0a0d4bd6456b3fcd1fcdbcaf0b5269c317e3ea91', '0' * 40):
            with self.subTest(candidate=candidate):
                self.contract.manifest['studio_commit'] = candidate
                self.refused_before_tree('studio_candidate_mismatch')
                self.assertEqual(self.actions, [])

    def launcher_tree(self, raw):
        self.runtime.MODULE_DIR = 'usr/lib/inkyos'
        self.runtime.HELPER = 'usr/local/lib/inky-studio/network-helper.py'
        self.runtime.IPC = 'usr/local/lib/inkyos/initialization-server.py'
        self.runtime.RECEIPT = 'usr/local/lib/inkyos/initialization-receipt.py'
        self.runtime.CONTEXT = 'run/inkyos-factory/context.json'

        @contextmanager
        def tree():
            self.actions.append('tree')
            def read(path, mode, limit):
                self.actions.append(('read', path))
                if path == self.runtime.MODULE_DIR + '/writer-launcher.py':
                    self.assertEqual((mode, limit), (0o555, 1024 * 1024))
                    return raw
                self.assertEqual((path, mode, limit), (self.runtime.CONTEXT, 0o644, 1024))
                raise self.AfterLaunchContract()
            yield SimpleNamespace(read=read)
        self.contract.tree = tree

    def test_real_launcher_bytes_pass_ast_binding_to_factory_wrapper(self):
        raw = (ROOT / 'scripts/writer-launcher.py').read_bytes()
        self.assertEqual(graph.STUDIO_COMMIT, 'eb117903cb647a14e9722d7387a41058ea8807b3')
        self.assertEqual(graph.APP_ARGV, (
            '/usr/lib/inky-studio/server/.venv/bin/python', '-I', '-B',
            '/usr/lib/inkyos/factory-main.py'))
        self.launcher_tree(raw)
        with Lease() as lease, \
                patch.object(graph.subprocess, 'Popen', side_effect=AssertionError('command spawned')):
            with self.assertRaises(self.AfterLaunchContract):
                self.sources.prepare(lease)
        self.assertEqual(self.actions, ['inventories', 'resolve', 'tree',
            ('read', 'usr/lib/inkyos/writer-launcher.py'), ('read', self.runtime.CONTEXT)])

    def test_legacy_module_argv_refuses_at_ast_guard_before_context_access(self):
        raw = (b"ARGV = {'main': ('/usr/lib/inky-studio/server/.venv/bin/python', "
               b"'-I', '-B', '-m', 'inky_web.main')}\n"
               b"raise AssertionError('inert launcher must not execute')\n")
        self.launcher_tree(raw)
        with Lease() as lease, \
                patch.object(graph.subprocess, 'Popen', side_effect=AssertionError('command spawned')):
            with self.assertRaises(graph.Refused) as caught:
                self.sources.prepare(lease)
        self.assertEqual(caught.exception.reason, 'inactive_launch_contract')
        self.assertEqual(self.actions, ['inventories', 'resolve', 'tree',
                                      ('read', 'usr/lib/inkyos/writer-launcher.py')])

    def test_missing_graph_or_wrapper_support_path_refuses_before_tree(self):
        for missing in (graph.SELF[1:], graph.MAIN[1:]):
            with self.subTest(path=missing):
                self.actions.clear()
                self.support['paths'] = [path for path in self.records if path != missing]
                self.refused_before_tree('support_pin_missing')
                self.assertEqual(self.actions, ['inventories'])

    def test_busctl_without_reviewed_elf_root_refuses_before_tree_or_command(self):
        self.support['elf_closure_review']['roots'] = []
        self.refused_before_tree('command_closure_missing')
        self.assertEqual(self.actions, ['inventories', 'resolve'])


class OwnedQueryDrainTests(unittest.TestCase):
    class Pipe:
        def __init__(self):
            self.closed = False
        def close(self):
            if self.closed:
                raise AssertionError('synthetic pipe closed twice')
            self.closed = True

    class Child:
        def __init__(self, outcomes):
            self.stdout = OwnedQueryDrainTests.Pipe()
            self.stderr = OwnedQueryDrainTests.Pipe()
            self.outcomes = list(outcomes)
            self.waits = []
        def wait(self, *, timeout):
            self.waits.append(timeout)
            result = self.outcomes.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result

    def test_fake_child_timeout_retains_pending_unknown_and_unclosed_resources(self):
        child = self.Child([graph.subprocess.TimeoutExpired(['INERT_QUERY'], 0.01)])
        commands = graph.ReadOnlyCommands()
        pending = (child, 61801)  # Logical token; never a real descriptor.
        commands._pending, commands.unknown = pending, True
        with patch.object(graph.subprocess, 'Popen', side_effect=AssertionError('new child')), \
                patch.object(commands, 'call', side_effect=AssertionError('new query')), \
                patch.object(graph.os, 'close', side_effect=AssertionError('descriptor closed')):
            self.assertFalse(commands.drain())
        self.assertIs(commands._pending, pending)
        self.assertTrue(commands.unknown)
        self.assertFalse(commands.quiescent())
        self.assertFalse(child.stdout.closed or child.stderr.closed)
        self.assertEqual(child.waits, [graph.CLEANUP_SECONDS])

    def test_later_fake_child_wait_confirms_drain_without_new_query_or_admission(self):
        child = self.Child([graph.subprocess.TimeoutExpired(['INERT_QUERY'], 0.01), 0])
        commands = graph.ReadOnlyCommands()
        commands._pending, commands.unknown = (child, 61802), True
        closed = []
        with patch.object(graph.subprocess, 'Popen', side_effect=AssertionError('new child')), \
                patch.object(commands, 'call', side_effect=AssertionError('new query')), \
                patch.object(graph.os, 'close', side_effect=closed.append):
            self.assertFalse(commands.drain())
            self.assertEqual(closed, [])
            self.assertTrue(commands.drain())
            self.assertTrue(commands.drain())
        self.assertIsNone(commands._pending)
        self.assertFalse(commands.unknown)
        self.assertTrue(commands.quiescent())
        self.assertTrue(child.stdout.closed and child.stderr.closed)
        self.assertEqual(closed, [61802])
        self.assertEqual(child.waits, [graph.CLEANUP_SECONDS, graph.CLEANUP_SECONDS])


if __name__ == '__main__':
    unittest.main()
