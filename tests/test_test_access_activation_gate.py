"""Initial TEST assessment fixtures; no bus, network, service or activation."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


gate = load('test_access_activation_gate_fixture', ROOT / 'scripts/test-access-activation-gate.py')


def request():
    return {'schema_version': 1, 'utc_reference': 1791040000, 'utc_reference_age': 2,
            'utc_reference_source': 'independent-device'}


def historical():
    checks = {}
    for name in gate.HISTORICAL_CHECKS:
        passed = name not in gate.REPLACED_CHECKS
        reason = ('panel_runtime_observation_pending' if name == 'panel_runtime_evidence_verified'
                  else 'precondition_unverified')
        checks[name] = {'passed': passed, 'status': 'PASS' if passed else 'BLOCKED',
                        'reason': None if passed else reason}
    return {'schema_version': 1, 'kind': 'test-lan-preflight', 'live_selected': True,
            'scope': 'test_lan_preconditions_only', 'checks': checks, 'passed': False,
            'activation_authorized': False, 'live_evidence': False, 'observation_source': 'fixture',
            'hardware_qualified': False, 'release_qualified': False, 'limitations': [], 'error': None}


class Fixture:
    def __init__(self):
        self.events = []
        self.fail = None
        self.report = historical()
        self.panel_value = {'width': 800, 'height': 480, 'color_code': 4, 'display_variant': 20}
        self.radio_value = {'mapping_consistent': True, 'checks': dict.fromkeys(gate.RADIO_CHECKS, True)}
        self.preflight_request = None

    def ok(self, name):
        self.events.append(name)
        return name != self.fail

    def target(self): return self.ok('target')
    def bind(self): return self.ok('bind')
    def authenticate_cache(self): return self.ok('authenticate')
    def country_confirmed(self): return self.ok('country')
    def unchanged(self): return self.ok('unchanged')
    def connected(self): return self.ok('connected')
    def templates(self): return self.ok('templates')
    def inactive(self): return self.ok('inactive')

    def preflight(self, value):
        self.events.append('preflight')
        self.preflight_request = value
        return copy.deepcopy(self.report)

    def panel(self):
        self.events.append('panel')
        return self.panel_value

    def radio(self):
        self.events.append('radio')
        return self.radio_value

    def reference_current(self, value, elapsed):
        return self.ok('reference')

    def close(self): self.events.append('close')


class GateTests(unittest.TestCase):
    def assess(self, fixture=None, value=None):
        return gate.assess(fixture or Fixture(), request() if value is None else value)

    def assert_blocked(self, result):
        self.assertFalse(result['passed'])
        self.assertFalse(result['ready_for_test_activation'])
        self.assertFalse(result['live_evidence'])

    def test_fixture_pass_preserves_three_historical_failures_but_never_native_readiness(self):
        fixture = Fixture()
        result = self.assess(fixture)
        self.assertTrue(result['passed'], result)
        self.assertTrue(all(result['gate_checks'].values()))
        self.assertEqual(len(result['gate_checks']), 18)
        self.assertEqual(result['historical_checks'], fixture.report['checks'])
        self.assertFalse(result['historical_preflight_passed'])
        self.assertEqual([k for k, v in result['historical_checks'].items() if not v['passed']], list(gate.REPLACED_CHECKS))
        for key in ('live_evidence', 'ready_for_test_activation', 'permit_written', 'application_started',
                    'helper_started', 'activation_authorized', 'hardware_qualified', 'release_qualified',
                    'firmware_tuple_qualified'):
            self.assertIs(result[key], False)
        self.assertEqual(fixture.events, ['target', 'bind', 'authenticate', 'country', 'unchanged', 'connected',
            'templates', 'preflight', 'inactive', 'panel', 'radio', 'unchanged', 'connected', 'inactive',
            'templates', 'reference', 'close'])

    def test_request_is_closed_strict_and_rejected_before_target_access(self):
        bad = [dict(request(), schema_version=True), dict(request(), utc_reference=True),
               dict(request(), utc_reference_age=1.0), dict(request(), utc_reference_age=61),
               dict(request(), utc_reference_source='host-clock'), dict(request(), path='PRIVATE'),
               {'schema_version': 1}, None]
        for value in bad:
            fixture = Fixture()
            result = gate.assess(fixture, value)
            self.assert_blocked(result)
            self.assertEqual(result['error'], 'invalid_request')
            self.assertEqual(fixture.events, ['close'])

    def test_every_required_historical_gate_remains_mandatory_before_i2c(self):
        for name in set(gate.HISTORICAL_CHECKS) - set(gate.REPLACED_CHECKS):
            with self.subTest(check=name):
                fixture = Fixture()
                fixture.report['checks'][name] = {'passed': False, 'status': 'BLOCKED', 'reason': 'precondition_unverified'}
                result = self.assess(fixture)
                self.assert_blocked(result)
                self.assertEqual(result['error'], 'historical_blocked')
                self.assertNotIn('panel', fixture.events)
                self.assertNotIn('radio', fixture.events)

    def test_required_checks_are_not_coerced_and_historical_private_data_never_echoed(self):
        changes = [lambda x: x['checks']['utc_synchronized'].update(passed=1),
                   lambda x: x['checks']['utc_synchronized'].update(status='BLOCKED'),
                   lambda x: x['checks']['utc_synchronized'].update(reason='PRIVATE_PATH'),
                   lambda x: x.update(passed=True), lambda x: x.update(live_evidence=True),
                   lambda x: x.update(extra='PRIVATE_PATH'), lambda x: x['checks'].pop('utc_synchronized')]
        for change in changes:
            fixture = Fixture(); change(fixture.report)
            result = self.assess(fixture)
            self.assert_blocked(result)
            self.assertNotIn('PRIVATE_PATH', json.dumps(result))
            self.assertNotIn('panel', fixture.events)

    def test_auth_binding_templates_country_and_connection_fail_before_observers(self):
        for step in ('target', 'bind', 'authenticate', 'country', 'unchanged', 'connected', 'templates', 'inactive'):
            fixture = Fixture(); fixture.fail = step
            result = self.assess(fixture)
            self.assert_blocked(result)
            self.assertNotIn('panel', fixture.events)
            self.assertNotIn('radio', fixture.events)

    def test_panel_accepts_only_exact_unsigned_test_tuple(self):
        for value in ({'width': 800, 'height': 480, 'color_code': 5, 'display_variant': 20},
                      {'width': 800, 'height': 480, 'color_code': 4, 'display_variant': 22},
                      {'width': 800.0, 'height': 480, 'color_code': 4, 'display_variant': 20},
                      {'width': 600, 'height': 448, 'color_code': 4, 'display_variant': 14},
                      dict(Fixture().panel_value, serial='PRIVATE_SERIAL')):
            fixture = Fixture(); fixture.panel_value = value
            result = self.assess(fixture)
            self.assert_blocked(result)
            self.assertEqual(result['error'], 'panel_unconfirmed')
            self.assertIsNone(result['panel'])
            self.assertNotIn('PRIVATE_SERIAL', json.dumps(result))
            self.assertNotIn('radio', fixture.events)

    def test_each_radio_policy_check_and_mapping_is_mandatory(self):
        for name in gate.RADIO_CHECKS:
            fixture = Fixture(); fixture.radio_value['checks'][name] = False
            result = self.assess(fixture)
            self.assert_blocked(result)
            self.assertEqual(result['error'], 'radio_unconfirmed')
        for value in (False, 1, None):
            fixture = Fixture(); fixture.radio_value['mapping_consistent'] = value
            self.assert_blocked(self.assess(fixture))
        fixture = Fixture(); fixture.radio_value['checks']['PRIVATE'] = True
        result = self.assess(fixture)
        self.assert_blocked(result)
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_final_state_connection_inactive_templates_and_utc_rechecked(self):
        for name in ('unchanged', 'connected', 'inactive', 'templates'):
            fixture = Fixture()
            original = getattr(fixture, name)
            calls = []
            def operation():
                calls.append(None)
                return original() if len(calls) == 1 else False
            setattr(fixture, name, operation)
            result = self.assess(fixture)
            self.assert_blocked(result)
            self.assertIn('radio', fixture.events)
        fixture = Fixture(); fixture.fail = 'reference'
        self.assertEqual(self.assess(fixture)['error'], 'reference_expired')

    def test_operation_guard_uses_exact_true_and_exceptions_are_closed(self):
        for value in (None, 1, 'yes', {}, []):
            fixture = Fixture(); fixture.bind = lambda: value
            self.assert_blocked(self.assess(fixture))
        fixture = Fixture(); fixture.panel = mock.Mock(side_effect=OSError('PRIVATE_DEVICE'))
        result = self.assess(fixture)
        self.assert_blocked(result)
        self.assertEqual(result['error'], 'assessment_unavailable')
        self.assertNotIn('PRIVATE_DEVICE', json.dumps(result))
        self.assertEqual(fixture.events[-1], 'close')

    def test_reference_age_counts_collection_time_and_does_not_modify_original_request(self):
        fixture = Fixture(); value = request(); initial = dict(value)
        clock = [0.0]
        original = fixture.bind
        def bind():
            clock[0] = 3.1
            return original()
        fixture.bind = bind
        with mock.patch.object(gate.time, 'monotonic', side_effect=lambda: clock[0]):
            self.assertTrue(self.assess(fixture, value)['passed'])
        self.assertEqual(fixture.preflight_request['utc_reference_age'], value['utc_reference_age'] + 4)
        self.assertEqual(value, initial)
        fixture = Fixture(); value = dict(request(), utc_reference_age=60)
        self.assertEqual(self.assess(fixture, value)['error'], 'reference_expired')
        self.assertNotIn('panel', fixture.events)

    def test_global_budget_refuses_work_after_slow_preflight(self):
        fixture = Fixture(); clock = [0.0]
        def preflight(_value):
            clock[0] = 46.0
            return historical()
        fixture.preflight = preflight
        with mock.patch.object(gate.time, 'monotonic', side_effect=lambda: clock[0]):
            result = self.assess(fixture)
        self.assertEqual(result['error'], 'runtime_timeout')
        self.assertNotIn('panel', fixture.events)

    def test_utc_reference_helper_is_readonly_strict_and_bounded(self):
        value = request()
        with mock.patch.object(gate.time, 'time', return_value=value['utc_reference'] + 10):
            self.assertIs(gate.reference_current(value, 8), True)
            for elapsed in (True, -1, float('nan'), float('inf'), 59, '8'):
                self.assertIs(gate.reference_current(value, elapsed), False)
            self.assertFalse(gate.reference_current(dict(value, utc_reference_source='local')))
        with mock.patch.object(gate.time, 'time', return_value=value['utc_reference'] + 33):
            self.assertFalse(gate.reference_current(value))
        with mock.patch.object(gate.time, 'time', return_value=float('nan')):
            self.assertFalse(gate.reference_current(value))

    def test_native_panel_reuses_single_bounded_reader_without_old_catalogue_override(self):
        adapter = gate.NativeAdapter()
        reader = mock.Mock()
        reader.sample.return_value = struct.pack('<HHBBB22p', 800, 480, 4, 7, 20, b'PRIVATE_TIMESTAMP')
        adapter.panel_module = {'ProductionAdapter': mock.Mock(return_value=reader),
                                'parse_eeprom': mock.Mock(side_effect=AssertionError('Old parser must stay unchanged'))}
        self.assertEqual(adapter.panel(), Fixture().panel_value)
        reader.sample.assert_called_once_with()
        adapter.panel_module['parse_eeprom'].assert_not_called()
        reader.sample.return_value = b'bad'
        with self.assertRaises(gate.GateError): adapter.panel()

    def test_native_radio_observes_once_and_never_calls_country_setter_or_wifi_toggle(self):
        adapter = gate.NativeAdapter(); adapter.deadline = 45
        country = mock.Mock()
        country.mapping.side_effect = [0, 0]
        firmware, kernel, channels = {'firmware': 'fixture'}, {'kernel': 'fixture'}, []
        country.observe.return_value = (0, firmware, kernel, channels)
        evaluator = mock.Mock(return_value=dict.fromkeys(gate.RADIO_CHECKS, True))
        adapter.connection = types.SimpleNamespace(country=country, country_module={'evaluate': evaluator})
        self.assertTrue(adapter.radio()['mapping_consistent'])
        country.observe.assert_called_once_with()
        self.assertEqual(country.mapping.call_count, 2)
        evaluator.assert_called_once_with(firmware, kernel, channels)
        self.assertEqual([call[0] for call in country.mock_calls], ['mapping', 'observe', 'mapping'])

    def test_native_connected_requires_runtime_file_exact_then_readonly_connector_checks(self):
        adapter = gate.NativeAdapter()
        files = mock.Mock(); files.read.return_value = b'exact fixture profile'
        connection = mock.Mock()
        connection.auth = types.SimpleNamespace(files=files)
        connection.network = b'exact fixture profile'
        connection.profiles_closed.return_value = connection.profile_restricted.return_value = connection.connected.return_value = True
        adapter.connection = connection; adapter.connect = {'PROFILE': '/run/fixed-fixture-profile'}
        self.assertTrue(adapter.connected())
        self.assertEqual([call[0] for call in connection.mock_calls], ['profiles_closed', 'profile_restricted', 'connected'])
        files.read.return_value = b'changed'
        connection.reset_mock()
        self.assertFalse(adapter.connected())
        self.assertEqual(connection.mock_calls, [])

    def test_native_preflight_passes_true_live_adapter_and_explicit_fr_without_panel_file(self):
        adapter = gate.NativeAdapter(); sentinel = object()
        adapter.preflight_module = {'LiveAdapter': mock.Mock(return_value=sentinel), 'preflight': mock.Mock()}
        value = request(); adapter.preflight(value)
        adapter.preflight_module['preflight'].assert_called_once_with(sentinel, live=True,
            operator_access_confirmed=True, country='FR', country_confirmed=True, panel_inventory=None,
            utc_reference=value['utc_reference'], utc_reference_age=value['utc_reference_age'],
            utc_reference_source=value['utc_reference_source'])

    def test_real_pinned_preflight_fixture_result_is_preserved_without_promoting_its_pass(self):
        path = ROOT / 'scripts/test-lan-preflight.py'
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), gate.PREFLIGHT_SHA256)
        preflight = load('activation_historical_preflight_fixture', path)
        class HistoricalFixture:
            def collect(self, _request):
                return {name: name not in gate.REPLACED_CHECKS for name in preflight.CHECKS}
        value = request()
        result = preflight.preflight(HistoricalFixture(), live=True, operator_access_confirmed=True,
            country='FR', country_confirmed=True, utc_reference=value['utc_reference'],
            utc_reference_age=value['utc_reference_age'], utc_reference_source=value['utc_reference_source'])
        projected = gate.historical_projection(result, native=False)
        self.assertEqual(projected, result['checks'])
        self.assertFalse(result['passed'])
        with self.assertRaises(gate.GateError):
            gate.historical_projection(result, native=True)

    def test_native_templates_refuse_changed_vendor_unknown_dropin_and_hidden_runtime_unit(self):
        adapter = gate.NativeAdapter()
        adapter.lib = {'strict_json': json.loads}
        payload = b'SYNTHETIC_VENDOR'
        paths = {path: (hashlib.sha256(payload).hexdigest(), mode) for path, (_pin, mode) in gate.APP_FILES.items()}
        marker = json.dumps({'source_commit': gate.SOURCE, 'manifest_sha256': gate.APP_MANIFEST_SHA256,
                             'state': 'prepared-inactive'}).encode()
        manifest_raw = (ROOT / 'tests/fixtures/application-manifest-c31b13af.json').read_bytes()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for path, expected in gate.DROPIN_NAMES.items():
                directory = root / path.lstrip('/'); directory.mkdir(parents=True)
                for name in expected: (directory / name).write_bytes(payload)
            (root / 'run/systemd/system').mkdir(parents=True, exist_ok=True)
            files = mock.Mock()
            files.read.side_effect = lambda path, **_kwargs: (marker if path == gate.MARKER
                else manifest_raw if path == gate.APP_MANIFEST else payload)
            files.directory.side_effect = lambda path: os.open(root / path.lstrip('/'), os.O_RDONLY | os.O_DIRECTORY)
            adapter.connection = types.SimpleNamespace(auth=types.SimpleNamespace(files=files))
            with mock.patch.object(gate, 'APP_FILES', paths):
                self.assertTrue(adapter.templates())
                hidden = root / 'run/systemd/system/inky-studio.service'; hidden.write_bytes(b'HIDDEN')
                self.assertFalse(adapter.templates())
                hidden.unlink()
                unknown = root / 'etc/systemd/system/inky-studio.service.d/override.conf'; unknown.write_bytes(b'EXTRA')
                self.assertFalse(adapter.templates())
                unknown.unlink()
                def changed(path, **_kwargs):
                    return (b'CHANGED' if path in paths else marker if path == gate.MARKER
                            else manifest_raw if path == gate.APP_MANIFEST else payload)
                files.read.side_effect = changed
                self.assertFalse(adapter.templates())

    def test_native_wrong_source_pin_refuses_before_any_module_execution(self):
        sources = {path: (ROOT / 'scripts' / Path(path).name).read_bytes()
                   for path in (gate.SELF, gate.CONNECT, gate.PREFLIGHT, gate.PANEL)}
        sources[gate.PANEL] = b'raise AssertionError("DO_NOT_EXECUTE")\n'
        manifest = {'schema_version': 1, 'kind': 'test-access-runtime', 'application_source_commit': gate.SOURCE,
            'application_manifest_sha256': gate.APP_MANIFEST_SHA256, 'parent_image_sha256': gate.PARENT,
            'files': {path[1:]: {'sha256': hashlib.sha256(raw).hexdigest(), 'mode': '0555'} for path, raw in sources.items()}}
        files = mock.Mock()
        files.read.side_effect = lambda path, **_kwargs: json.dumps(manifest).encode() if path == gate.MANIFEST else sources[path]
        adapter = gate.NativeAdapter(); adapter.lib = {'Files': lambda: files, 'strict_json': json.loads}
        with mock.patch.object(gate, 'load', side_effect=AssertionError('No module execution')) as load_module:
            with self.assertRaises(gate.GateError): adapter.bind()
            load_module.assert_not_called()
        files.close.assert_called_once_with()

    def test_native_target_refuses_non_linux_before_bootstrap(self):
        with mock.patch.object(gate.sys, 'platform', 'darwin'), mock.patch.object(gate, 'bootstrap') as bootstrap:
            self.assertIs(gate.NativeAdapter().target(), False)
            bootstrap.assert_not_called()

    def test_strict_input_duplicates_floats_extras_and_cli_alt_paths_are_refused(self):
        for raw in (b'{"schema_version":1,"schema_version":1}', b'{"value":NaN}', b'{"value":1.0}', b'x' * 4097):
            with self.assertRaises((ValueError, UnicodeError)):
                gate.strict_json(raw)
        import contextlib
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(gate.main(['--root', 'PRIVATE_PATH']), 1)
        result = json.loads(output.getvalue())
        self.assertFalse(result['ready_for_test_activation'])
        self.assertEqual(result['error'], 'invalid_arguments')
        self.assertNotIn('PRIVATE_PATH', output.getvalue())


if __name__ == '__main__':
    unittest.main()
