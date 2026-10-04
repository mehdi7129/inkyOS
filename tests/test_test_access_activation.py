"""Asynchronous admission and consumable permits; synthetic files only."""
import contextlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


activation = load('activation_tests', 'scripts/test-access-activation.py')
legacy = load('activation_legacy_tests', 'scripts/test-enrollment-firstboot.py')


def request():
    return {'schema_version': 1, 'confirm_test_refresh': True, 'utc_reference': 1791118800,
            'utc_reference_age': 0, 'utc_reference_source': 'independent-device'}


class WorkerFixture:
    def __init__(self, fail=None, drain_at=None):
        self.fail, self.drain_at, self.calls = fail, drain_at, []
        self.locked, self.draining = False, False
        self.report_value = activation.result('queued', request_accepted=True, passed=True)
        self.record = {'request': request()}
        self.published, self.starts = [], []

    def step(self, name):
        self.calls.append(name)
        if name == self.drain_at: self.draining = True
        if name == self.fail: raise OSError('PRIVATE_PATH PRIVATE_IDENTITY PRIVATE_SSID')
        return True

    def bind(self): return self.step('bind')
    def acquire(self): return self.step('lock')
    @contextlib.contextmanager
    def operation(self):
        if self.locked: raise AssertionError('nested operation lock')
        self.locked = True
        try: yield
        finally: self.locked = False
    def request(self): self.step('request'); return self.record
    def report(self, value): self.step('report'); return self.report_value
    def publish(self, record, value):
        assert self.locked
        self.step('publish-' + value['phase'])
        self.report_value = copy.deepcopy(value)
        self.published.append(self.report_value)
    def no_drain(self):
        self.step('no-drain')
        activation.require(not self.draining, 'activation_drain_requested')
        return True
    def unchanged(self): return self.step('unchanged')
    def assess(self, value):
        assert not self.locked
        return self.step('gate')
    def prepare_units(self): assert self.locked; return self.step('units')
    def permit(self, value, *, helper_verified=False):
        assert self.locked
        return self.step('permit-verified' if helper_verified else 'permit')
    def start(self, role):
        assert self.locked
        self.step('start-' + role); self.starts.append(role)
        return True
    def wait_ready(self, role): assert not self.locked; return self.step('ready-' + role)
    def fresh_utc(self, record): return self.step('utc')
    def invalidate(self): assert self.locked; return self.step('invalidate')
    def close(self): return self.step('close')


class WorkerTests(unittest.TestCase):
    def test_closed_request_requires_explicit_true_and_recent_independent_utc(self):
        self.assertTrue(activation.valid_request(request()))
        for key, value in [('schema_version', True), ('confirm_test_refresh', 1),
                           ('confirm_test_refresh', False), ('utc_reference', True),
                           ('utc_reference_age', True), ('utc_reference_age', 61),
                           ('utc_reference_age', -1), ('utc_reference_source', 'ntp'),
                           ('unexpected', 'PRIVATE')]:
            with self.subTest(key=key, value=value):
                self.assertFalse(activation.valid_request({**request(), key: value}))

    def test_order_health_and_fresh_utc_before_app_without_hardware_claim(self):
        adapter = WorkerFixture()
        code, report = activation.activate(adapter)
        self.assertEqual(code, 0)
        self.assertTrue(report['application_active_observed'])
        self.assertEqual(adapter.starts, ['helper', 'app'])
        self.assertLess(adapter.calls.index('gate'), adapter.calls.index('units'))
        self.assertLess(adapter.calls.index('ready-helper'), adapter.calls.index('permit-verified'))
        self.assertLess(adapter.calls.index('utc'), adapter.calls.index('start-app'))
        self.assertLess(adapter.calls.index('ready-app'), adapter.calls.index('publish-active'))
        for field in ('physical_refresh_verified', 'hardware_qualified', 'release_qualified'):
            self.assertFalse(report[field])
        self.assertEqual(adapter.calls[-1], 'close')

    def test_failures_are_closed_invalidate_permit_without_stop_or_kill(self):
        for stage in ('bind', 'lock', 'gate', 'units', 'permit', 'start-helper',
                      'ready-helper', 'utc', 'permit-verified', 'start-app', 'ready-app', 'close'):
            with self.subTest(stage=stage):
                adapter = WorkerFixture(fail=stage)
                code, report = activation.activate(adapter)
                self.assertEqual(code, 1)
                self.assertFalse(report['passed'])
                self.assertNotIn('PRIVATE', repr(report))
                self.assertEqual(set(report), activation.REPORT_FIELDS)
                if stage not in ('bind', 'lock', 'close'):
                    self.assertIn('invalidate', adapter.calls)
                if stage in ('gate', 'units', 'permit', 'ready-helper', 'utc', 'permit-verified'):
                    self.assertNotIn('app', adapter.starts)
                self.assertFalse(any('kill' in name or 'stop' in name for name in adapter.calls))

    def test_drain_races_before_permit_or_start_close_admission(self):
        for stage in ('gate', 'units', 'permit', 'ready-helper', 'utc', 'permit-verified'):
            with self.subTest(stage=stage):
                adapter = WorkerFixture(drain_at=stage)
                code, report = activation.activate(adapter)
                self.assertEqual(code, 1)
                self.assertEqual(report['error'], 'activation_drain_requested')
                self.assertNotIn('app', adapter.starts)
                if stage in ('gate', 'units', 'permit'):
                    self.assertEqual(adapter.starts, [])

    def test_replay_preserves_terminal_status_and_permit(self):
        for phase in ('active', 'failed', 'gating', 'preparing'):
            with self.subTest(phase=phase):
                adapter = WorkerFixture()
                adapter.report_value = activation.result(phase)
                before = copy.deepcopy(adapter.report_value)
                code, report = activation.activate(adapter)
                self.assertEqual(code, 1)
                self.assertEqual(report['error'], 'activation_already_admitted')
                self.assertEqual(adapter.report_value, before)
                self.assertNotIn('invalidate', adapter.calls)
                self.assertEqual(adapter.published, [])

    def test_live_gate_requires_all_closed_native_evidence_flags(self):
        adapter = activation.NativeAdapter()
        observed = {'passed': True, 'ready_for_test_activation': True,
                    'live_evidence': True, 'error': None, 'test_profile': 'ac073-800x480',
                    'gate_checks': dict.fromkeys(activation.GATE_CHECKS, True),
                    'historical_checks': {}, 'radio_checks': dict.fromkeys(activation.RADIO_CHECKS, True)}
        queries = []
        adapter.gate = {'NativeAdapter': lambda: object(),
                        'assess': lambda _a, value: queries.append(value) or observed}
        adapter.elapsed = lambda _value: 2.1
        self.assertTrue(adapter.assess({'request': request()}))
        self.assertEqual(queries[0]['utc_reference_age'], 3)
        self.assertEqual(set(queries[0]), activation.UTC_FIELDS)
        for key in ('passed', 'ready_for_test_activation', 'live_evidence'):
            observed[key] = 1
            self.assertFalse(adapter.assess({'request': request()}))
            observed[key] = True

    def test_gate_diagnostic_projects_only_closed_names_and_boolean_results(self):
        gate = load('gate_contract_tests', 'scripts/test-access-activation-gate.py')
        self.assertEqual(activation.GATE_CHECKS, set(gate.CHECKS))
        self.assertEqual(activation.HISTORICAL_CHECKS, set(gate.HISTORICAL_CHECKS))
        self.assertEqual(activation.RADIO_CHECKS, set(gate.RADIO_CHECKS))
        self.assertEqual(activation.ASSESSMENT_ERRORS, gate.ERRORS)
        raw = gate.empty_result()
        raw['error'] = 'historical_blocked'
        raw['historical_checks'] = {name: {'passed': name != 'utc_synchronized',
                    'status': 'PRIVATE', 'reason': 'PRIVATE'} for name in gate.HISTORICAL_CHECKS}
        raw['panel'] = {'identity': 'PRIVATE'}
        projection = activation.assessment_projection(raw, from_gate=True)
        self.assertFalse(projection['historical_checks']['utc_synchronized'])
        self.assertNotIn('PRIVATE', repr(projection))
        adapter = WorkerFixture()
        adapter.assessment = projection
        adapter.assess = lambda value: False
        code, report = activation.activate(adapter)
        self.assertEqual(code, 1)
        self.assertEqual(report['assessment'], projection)
        self.assertEqual(adapter.report_value['assessment'], projection)
        for value in ({**projection, 'identity': 'PRIVATE'},
                      {**projection, 'error': 'PRIVATE'},
                      {**projection, 'gate_checks': {**projection['gate_checks'], 'PRIVATE': True}}):
            with self.assertRaises(activation.ActivationError): activation.assessment_projection(value)

    def test_helper_readiness_retries_only_transient_socket_startup(self):
        adapter = activation.NativeAdapter()
        adapter.deadline = time.monotonic() + 5
        adapter.no_drain = adapter.unchanged = lambda: True
        adapter.active = lambda role: True
        adapter.health = Mock(side_effect=[FileNotFoundError(), ConnectionRefusedError(), socket.timeout(), True])
        with patch.object(activation.time, 'sleep'):
            self.assertTrue(adapter.wait_ready('helper'))
            self.assertEqual(adapter.health.call_count, 4)
            adapter.health = Mock(side_effect=activation.ActivationError('activation_helper_failed'))
            with self.assertRaises(activation.ActivationError): adapter.wait_ready('helper')
            self.assertEqual(adapter.health.call_count, 1)

    def test_cli_rejects_override_without_constructing_native_adapter(self):
        with patch.object(activation, 'NativeAdapter', side_effect=AssertionError('no native')):
            for argv in ([], ['--root', '/tmp'], ['--activate', '--yes'], ['--consume-permit']):
                self.assertEqual(activation.main(argv), 2)

    def test_status_projection_rejects_private_fields_and_qualification_claims(self):
        for value in ({**activation.result(), 'identity': 'PRIVATE'},
                      activation.result(error='PRIVATE'),
                      activation.result(physical_refresh_verified=True),
                      activation.result(passed=1), activation.result(application_active_observed=True)):
            with self.subTest(value=value), self.assertRaises(activation.ActivationError):
                activation.status_projection(value)


class RuntimeFilesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for path, mode in [(activation.DIRECTORY, 0o700), ('/proc/sys/kernel/random', 0o755),
                           ('/etc/systemd/system', 0o755), ('/run/systemd/system', 0o755),
                           ('/usr/lib/systemd/system', 0o755)]:
            target = self.root / path[1:]
            parent = self.root
            for part in target.relative_to(self.root).parts:
                parent /= part
                parent.mkdir(mode=0o755, exist_ok=True)
            target.chmod(mode)
        boot_id = self.root / 'proc/sys/kernel/random/boot_id'
        boot_id.write_text('12345678-1234-1234-1234-123456789abc\n')
        boot_id.chmod(0o644)
        self.files = legacy.Files(str(self.root), owner=os.getuid())
        self.addCleanup(self.files.close)
        self.directory = self.files.directory(activation.DIRECTORY, private=True)
        self.addCleanup(os.close, self.directory)
        def rename(directory, source, target):
            # Fixture-only portable exclusive publication, never used live.
            os.link(source, target, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
            os.unlink(source, dir_fd=directory)
        def write(directory, name, raw, **kwargs):
            return legacy.write_atomic(directory, name, raw, owner=os.getuid(), rename=rename, **kwargs)
        self.commands = []
        def command(argv, **kwargs): self.commands.append(argv); return 0, b''
        self.lib = {**vars(legacy), 'write_atomic': write, 'command': command,
                    '_metadata': lambda info, **kwargs: legacy._metadata(info, owner=os.getuid(), **kwargs)}
        manifest = activation.canonical({'fixture': True})
        self.operator = SimpleNamespace(runtime=self.lib, files=self.files, directory=self.directory,
            profile={'schema_version': 2, 'access_runtime_manifest_sha256': activation.digest(manifest)},
            snapshot={activation.PROFILE: (b'fixture-profile', 0o600, True),
                      activation.MANIFEST: (manifest, 0o644, False)}, unchanged=lambda: True)
        self.store = activation.borrowed(self.operator)

    def admit(self):
        code, report = activation.enqueue(request(), self.operator)
        self.assertEqual(code, 0)
        return self.store.request(), report

    def native(self):
        adapter = activation.NativeAdapter()
        adapter.store, adapter.files, adapter.lib = self.store, self.files, self.lib
        adapter.bind = lambda: True
        adapter.operation = contextlib.nullcontext
        adapter.unchanged = lambda: True
        adapter.fresh_utc = lambda record: True
        adapter.close = lambda: None
        return adapter

    def test_queue_ack_is_distinct_from_start_and_replay_cannot_replace_request(self):
        _, report = self.admit()
        self.assertTrue(report['request_accepted'])
        self.assertEqual(report['phase'], 'queued')
        self.assertFalse(report['application_started'])
        self.assertEqual(self.commands, [('/usr/bin/systemctl', '--no-block', 'start', activation.WORKER)])
        path = self.root / activation.DIRECTORY[1:] / activation.REQUEST
        before = path.read_bytes()
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(activation.enqueue(request(), self.operator)[0], 1)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(activation.status(self.operator)[1], report)
        os.fstat(self.directory)  # Borrowed descriptors stay owned by runner.

    def test_failed_queue_preserves_request_and_terminal_status(self):
        self.lib['command'] = lambda *args, **kwargs: (1, b'PRIVATE')
        code, report = activation.enqueue(request(), self.operator)
        self.assertEqual(code, 1)
        self.assertTrue(report['request_accepted'])
        self.assertEqual(report['error'], 'activation_queue_failed')
        self.assertEqual(activation.status(self.operator)[1], report)
        self.assertEqual(activation.enqueue(request(), self.operator)[0], 1)

    def test_any_drain_sentinel_blocks_admission_without_opening_contents(self):
        path = self.root / activation.DIRECTORY[1:] / activation.DRAIN
        path.symlink_to('/never-read-a-private-target')
        code, report = activation.enqueue(request(), self.operator)
        self.assertEqual(code, 1)
        self.assertEqual(report['error'], 'activation_drain_requested')
        self.assertFalse(self.store.exists(activation.REQUEST))

    def test_status_closed_for_changed_binding_noncanonical_or_unsafe_mode(self):
        record, _ = self.admit()
        path = self.root / activation.DIRECTORY[1:] / activation.REQUEST
        original = path.read_bytes()
        for raw in (activation.canonical({**record, 'boot_id': 'bad'}), json.dumps(record).encode()):
            path.write_bytes(raw)
            self.assertEqual(activation.status(self.operator)[0], 1)
        path.write_bytes(original); path.chmod(0o644)
        self.assertEqual(activation.status(self.operator)[0], 1)

    def test_permit_requires_helper_then_health_then_app_and_disappears(self):
        record, _ = self.admit()
        native = self.native()
        native.permit(record)
        self.assertEqual(activation.consume(native, 'app'), 1)
        self.assertEqual(activation.consume(native, 'helper'), 0)
        self.assertEqual(activation.consume(native, 'helper'), 1)
        self.assertEqual(activation.consume(native, 'app'), 1)
        native.permit(record, helper_verified=True)
        self.assertEqual(activation.consume(native, 'app'), 0)
        self.assertFalse(self.store.exists(activation.PERMIT))
        self.assertEqual(activation.consume(native, 'app'), 1)
        self.assertEqual(activation.status(self.operator)[0], 0)

    def test_expired_cross_boot_cross_request_or_invalid_flags_cannot_consume(self):
        record, _ = self.admit()
        native = self.native()
        native.permit(record)
        original = self.store.read(activation.PERMIT)
        for key, value in [('boot_id', 'other'), ('profile_sha256', '0' * 64),
                           ('access_runtime_manifest_sha256', '0' * 64), ('request_sha256', '0' * 64),
                           ('expires_monotonic_ns', time.monotonic_ns() - 1),
                           ('expires_monotonic_ns', time.monotonic_ns() + 60_000_000_000),
                           ('helper_pending', 1), ('schema_version', True)]:
            with self.subTest(key=key, value=value):
                self.store.put(activation.PERMIT, {**original, key: value}, replace=True)
                self.assertEqual(activation.consume(native, 'helper'), 1)

    def test_app_consumption_rechecks_utc_and_stop_sentinel(self):
        record, _ = self.admit()
        native = self.native()
        native.permit(record)
        self.assertEqual(activation.consume(native, 'helper'), 0)
        native.permit(record, helper_verified=True)
        native.fresh_utc = lambda value: False
        self.assertEqual(activation.consume(native, 'app'), 1)
        native.fresh_utc = lambda value: True
        self.store.put(activation.DRAIN, {'fixture': True})
        self.assertEqual(activation.consume(native, 'app'), 1)

    def test_enabling_links_and_runtime_unit_are_refused(self):
        native = self.native()
        self.assertTrue(native.no_boot_links())
        for path in ('etc/systemd/system/multi-user.target.wants/inky-studio.service',
                     'run/systemd/system/fixture.target.requires/alias.service',
                     'usr/lib/systemd/system/alias.service'):
            target = self.root / path
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            target.symlink_to('/usr/lib/systemd/system/inky-studio.service')
            with self.subTest(path=path), self.assertRaises(activation.ActivationError):
                native.no_boot_links()
            target.unlink()
        target = self.root / 'run/systemd/system/inky-studio.service'
        target.write_text('[Service]\nExecStart=/bad\n')
        with self.assertRaises(activation.ActivationError): native.no_runtime_unit('inky-studio.service')

    def test_status_idle_never_invokes_service(self):
        code, report = activation.status(self.operator)
        self.assertEqual(code, 0)
        self.assertEqual(report['phase'], 'idle')
        self.assertEqual(self.commands, [])

    def test_effective_units_reject_extra_dropins_restart_and_wrong_environment(self):
        native = self.native()
        role = 'app'
        raw = (ROOT / 'overlay-test-access/inky-studio.conf').read_bytes()
        destination = self.root / activation.DROPINS[role][1:]
        destination.parent.mkdir(mode=0o755)
        destination.write_bytes(raw); destination.chmod(0o644)
        native.boot = SimpleNamespace(sources={activation.TEMPLATES[role]: raw})
        value = {'LoadState': 'loaded', 'UnitFileState': 'disabled', 'Restart': 'no', 'KillSignal': '15',
                 'FragmentPath': '/usr/lib/systemd/system/inky-studio.service',
                 'KillMode': 'mixed', 'TimeoutStopUSec': 'infinity', 'SendSIGKILL': 'no',
                 'ExecCondition': '{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I ' + activation.SELF
                    + ' --consume-app-permit ; ignore_errors=no ; }',
                 'DropInPaths': activation.DROPINS[role] + ' /etc/systemd/system/inky-studio.service.d/bluetooth.conf'
                    + ' /etc/systemd/system/inky-studio.service.d/10-inkyos-firstboot.conf',
                 'Environment': 'INKY_STUDIO_DISPLAY_MODE=hardware INKY_STUDIO_DISPLAY_PROFILE=ac073-800x480'}
        native.properties = lambda *args: value
        self.assertTrue(native.effective('app'))
        for key, replacement in [('Restart', 'on-failure'), ('SendSIGKILL', 'yes'), ('TimeoutStopUSec', '30s'),
                                 ('FragmentPath', '/etc/systemd/system/inky-studio.service'),
                                 ('UnitFileState', 'enabled'), ('Environment', 'INKY_STUDIO_DISPLAY_MODE=mock'),
                                 ('DropInPaths', value['DropInPaths'] + ' /tmp/unknown.conf'),
                                 ('ExecCondition', value['ExecCondition'] + value['ExecCondition'])]:
            old = value[key]
            value[key] = replacement
            with self.subTest(key=key): self.assertFalse(native.effective('app'))
            value[key] = old

    def test_consumer_close_failure_is_closed_after_permit_consumption(self):
        record, _ = self.admit()
        native = self.native()
        native.permit(record)
        native.close = Mock(side_effect=OSError('PRIVATE'))
        self.assertEqual(activation.consume(native, 'helper'), 1)
        self.assertFalse(self.store.read(activation.PERMIT)['helper_pending'])

    def test_helper_leaf_uses_helper_metadata_and_exact_authenticated_socket(self):
        native = self.native()
        native.deadline = time.monotonic() + 5
        directory = self.root / 'run/inky-network'
        directory.mkdir(mode=0o750)
        directory.chmod(0o750)
        endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(endpoint.close)
        endpoint.bind(str(directory / 'control.sock'))
        (directory / 'control.sock').chmod(0o660)
        native.properties = lambda *args: {'ActiveState': 'active', 'SubState': 'running', 'MainPID': '42',
                                           'User': 'inky-network', 'Group': 'inky-provisioning'}
        connection = Mock()
        connection.getsockopt.return_value = struct.pack('3i', 42, os.getuid(), os.getgid())
        connection.recv.side_effect = [b'{"ok":true,"result":{"ready":true,"protocol":1}}\n', b'']
        wrapper = Mock()
        wrapper.__enter__ = Mock(return_value=connection)
        wrapper.__exit__ = Mock(return_value=False)
        real_directory = self.files.directory
        def root_only(path, **kwargs):
            self.assertEqual(path, '/run')  # Leaf is owned by service, not root.
            return real_directory(path, **kwargs)
        with patch.object(self.files, 'directory', side_effect=root_only), \
             patch('pwd.getpwnam', return_value=SimpleNamespace(pw_uid=os.getuid())), \
             patch('grp.getgrnam', return_value=SimpleNamespace(gr_gid=os.getgid())), \
             patch.object(socket, 'SO_PEERCRED', 17, create=True), \
             patch.object(socket, 'socket', return_value=wrapper):
            self.assertTrue(native.health())
            connection.sendall.assert_called_once_with(b'{"op":"health"}\n')
            connection.recv.side_effect = [b'{"ok":true,"result":{"ready":true,"protocol":true}}\n', b'']
            with self.assertRaises(activation.ActivationError): native.health()
            connection.getsockopt.return_value = struct.pack('3i', 43, os.getuid(), os.getgid())
            with self.assertRaises(activation.ActivationError): native.health()


if __name__ == '__main__':
    unittest.main()
