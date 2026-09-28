import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest

spec = importlib.util.spec_from_file_location(
    'bootstrap_system_model', Path(__file__).parents[1] / 'scripts/bootstrap-system-model.py')
bootstrap = importlib.util.module_from_spec(spec); spec.loader.exec_module(bootstrap)


def request(operation, **fields):
    return json.dumps({'operation': operation, **fields}).encode()


class FakeAdapter:
    def __init__(self):
        self.calls = []
        self.status = {'disabled': True, 'trial': False, 'connected': False}
        self.time = 1500
        self.observation = {'radio': 'fixture0', 'country': 'FR', 'accepted': True}
        self.fail_at = None
        self.raise_at = None
        self.persisted = None
        self.model = None
        self.apply_entered = None
        self.apply_continue = None
        self.turn_on_after_confirm = False

    def step(self, name):
        self.calls.append(name)
        if name.startswith(('close', 'persist', 'apply', 'observe_country')):
            assert self.model._gate_open is False, 'Gate opened before country transaction completed'
        if name == self.raise_at:
            raise OSError('injected adapter failure')
        return name != self.fail_at

    def set_time(self, value):
        if not self.step('set_time'):
            return False
        self.time = value
        return True

    def observe_time(self):
        self.step('observe_time')
        return self.time

    def wifi_status(self):
        self.step('wifi_status')
        return dict(self.status)

    def close_wifi_gate(self):
        if not self.step('close_gate'):
            return False
        self.status['disabled'] = True
        return True

    def persist_country(self, record):
        if not self.step('persist_' + record['status']):
            return False
        self.persisted = dict(record)
        if record['status'] == 'confirmed' and self.turn_on_after_confirm:
            self.status['disabled'] = False
        return True

    def apply_country(self, code):
        result = self.step('apply_country')
        if self.apply_entered is not None:
            self.apply_entered.set()
            assert self.apply_continue.wait(timeout=5), 'Fixture blocked'
        return result

    def observe_country(self):
        self.step('observe_country')
        return self.observation


class BootstrapSystemModelTests(unittest.TestCase):
    def setUp(self):
        self.adapter = FakeAdapter()
        self.regulatory_checks = []
        def regulatory_verifier(code, observed):
            self.regulatory_checks.append((code, dict(observed)))
            return observed == {'radio': 'fixture0', 'country': code, 'accepted': True}
        self.config = {
            'helper_uid': 991, 'time_bounds': (1000, 2000),
            'country_allowlist': {'FR', 'GB'}, 'time_verifier': lambda requested, observed: requested == observed,
            'regulatory_verifier': regulatory_verifier, 'adapter': self.adapter,
        }
        self.model = bootstrap.BootstrapSystemModel(**self.config); self.adapter.model = self.model

    def country(self, code='FR', uid=991):
        return self.model.handle(request('country', country_code=code), caller_uid=uid)

    def time(self, value=1500, uid=991):
        return self.model.handle(request('time', unix_seconds=value), caller_uid=uid)

    def test_constructor_and_inspection_are_inert_and_closed(self):
        self.assertEqual(self.adapter.calls, [])
        state = self.model.inspect()
        self.assertFalse(state['wifi_gate_open'])
        self.assertTrue(state['experimental_model']); self.assertFalse(state['hardware_qualified'])
        self.assertEqual(state['country'], {'requested': None, 'persisted': None, 'observed': None})
        self.assertEqual(self.adapter.calls, [])

    def test_explicit_config_required_without_defaults_or_root_uid(self):
        cases = [dict(helper_uid=0), dict(helper_uid=True), dict(helper_uid=-1),
                 dict(helper_uid=2**32 - 1), dict(time_bounds=(2000, 1000)),
                 dict(time_bounds=(True, 2000)), dict(time_bounds=None),
                 dict(country_allowlist=set()), dict(country_allowlist={'EU'}),
                 dict(country_allowlist={'00'}), dict(country_allowlist={'Fr'}),
                 dict(country_allowlist=['FR']), dict(regulatory_verifier=None)]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(bootstrap.Refused):
                bootstrap.BootstrapSystemModel(**{**self.config, **change})
        self.assertEqual(self.adapter.calls, [])

    def test_strict_parser_rejects_extra_nested_duplicate_and_noninteger_inputs(self):
        cases = [b'', b' ' * 257, b'[]', b'true', b'null', b'{', b'\xff',
                 b'{"operation":"time","unix_seconds":true}',
                 b'{"operation":"time","unix_seconds":1500.0}',
                 b'{"operation":"time","unix_seconds":1e3}',
                 b'{"operation":"time","unix_seconds":NaN}',
                 b'{"operation":"time","unix_seconds":Infinity}',
                 b'{"operation":"time","unix_seconds":{"value":1500}}',
                 b'{"operation":"time","unix_seconds":1500,"unix_seconds":1501}',
                 b'{"operation":"time","operation":"country","unix_seconds":1500}',
                 b'{"operation":"time","unix_seconds":1500,"path":"/etc/passwd"}',
                 b'{"operation":"time","unix_seconds":1500,"argv":["date"]}',
                 b'{"operation":"country","country_code":["FR"]}',
                 b'{"operation":"shutdown"}', b'{"operation":{},"unix_seconds":1500}',
                 '{"operation":"time","unix_seconds":1500}',
                 bytearray(b'{"operation":"time","unix_seconds":1500}')]
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(bootstrap.Refused):
                self.model.handle(raw, caller_uid=991)
        self.assertEqual(self.adapter.calls, [])
        self.assertFalse(self.model.inspect()['wifi_gate_open'])

    def test_uid_must_match_exact_nonroot_numeric_helper_identity(self):
        for uid in (0, 992, '991', 991.0, True, None):
            with self.subTest(uid=uid), self.assertRaises(bootstrap.Refused):
                self.country(uid=uid)
        self.assertEqual(self.adapter.calls, [])
        # UID 1 remains valid configuration, but bool True cannot impersonate it.
        model = bootstrap.BootstrapSystemModel(**{**self.config, 'helper_uid': 1})
        with self.assertRaises(bootstrap.Refused):
            model.handle(request('time', unix_seconds=1500), caller_uid=True)

    def test_identity_and_parser_refusal_preserve_previously_confirmed_gate(self):
        self.country()
        state = self.model.inspect(); calls = list(self.adapter.calls)
        cases = [(request('country', country_code='FR'), 992),
                 (b'{"operation":"country","country_code":"FR","argv":[]}', 991),
                 (b'{"operation":"time","unix_seconds":true}', 991)]
        for raw, uid in cases:
            with self.subTest(raw=raw, uid=uid), self.assertRaises(bootstrap.Refused):
                self.model.handle(raw, caller_uid=uid)
            self.assertEqual(self.model.inspect(), state)
            self.assertEqual(self.adapter.calls, calls)

    def test_valid_authorized_but_unsupported_country_closes_gate(self):
        self.country(); calls = list(self.adapter.calls)
        with self.assertRaisesRegex(bootstrap.Refused, 'trusted allowlist'):
            self.country('US')
        self.assertFalse(self.model.inspect()['wifi_gate_open'])
        self.assertEqual(self.adapter.calls, calls)

    def test_time_ack_requires_setter_and_observed_trusted_value(self):
        result = self.time()
        self.assertTrue(result['acknowledged'])
        self.assertEqual(result['time'], {'requested': 1500, 'observed': 1500, 'confirmed': True})
        self.assertFalse(result['wifi_gate_open'])
        self.assertEqual(self.adapter.calls, ['set_time', 'observe_time'])
        self.assertIsNone(result['country']['persisted'])

    def test_time_boundaries_are_injected_and_range_checked_before_adapter(self):
        for value in (-1, 999, 2001, 2**90):
            with self.subTest(value=value), self.assertRaises(bootstrap.Refused):
                self.time(value)
        self.assertEqual(self.adapter.calls, [])
        for value in (1000, 2000):
            self.assertTrue(self.time(value)['acknowledged'])

    def test_time_observation_cannot_be_bool_untrusted_or_out_of_bounds(self):
        for observation in (True, 1501, 2001, '1500', None):
            with self.subTest(observation=observation):
                self.adapter.observe_time = lambda: observation
                with self.assertRaises(bootstrap.Refused):
                    self.time()
                self.assertFalse(self.model.inspect()['time']['confirmed'])
                self.assertFalse(self.model.inspect()['wifi_gate_open'])

    def test_country_confirms_only_after_pending_apply_observe_and_durable_confirmation(self):
        result = self.country()
        self.assertEqual(self.adapter.calls, ['wifi_status', 'close_gate', 'wifi_status',
                         'persist_pending', 'wifi_status', 'apply_country', 'wifi_status', 'observe_country', 'wifi_status',
                         'persist_confirmed', 'wifi_status'])
        self.assertEqual(result['country']['requested'], 'FR')
        self.assertEqual(result['country']['persisted'], {'status': 'confirmed', 'country_code': 'FR'})
        self.assertEqual(result['country']['observed'], self.adapter.observation)
        self.assertTrue(result['acknowledged']); self.assertTrue(result['wifi_gate_open'])
        self.assertTrue(self.adapter.status['disabled'])  # Gate decision never enables Wi-Fi.
        self.assertEqual(len(self.regulatory_checks), 1)

    def test_country_requires_ascii_uppercase_and_explicit_allowlist(self):
        for code in ('00', 'EU', 'fr', 'Fr', 'ＦＲ', 'F', 'FRA', 'F\n', 'US', '../FR', '', None):
            with self.subTest(code=code), self.assertRaises(bootstrap.Refused):
                self.country(code)
        self.assertEqual(self.adapter.calls, [])

    def test_pending_persistence_apply_or_confirmation_failure_leaves_gate_closed(self):
        for point, expected_status in (('close_gate', None), ('persist_pending', None),
                                       ('apply_country', 'pending'), ('persist_confirmed', 'pending')):
            with self.subTest(point=point):
                self.setUp(); self.adapter.fail_at = point
                with self.assertRaises(bootstrap.Refused):
                    self.country()
                state = self.model.inspect(); self.assertFalse(state['wifi_gate_open'])
                self.assertEqual(state['country']['requested'], 'FR')
                persisted = state['country']['persisted']
                self.assertEqual(persisted['status'] if persisted else None, expected_status)
                self.assertNotIn('set_time', self.adapter.calls)

    def test_successful_apply_never_substitutes_for_verified_radio_observation(self):
        self.adapter.observation['accepted'] = False
        with self.assertRaisesRegex(bootstrap.Refused, 'Regulatory observation'):
            self.country()
        self.assertIn('apply_country', self.adapter.calls)
        self.assertNotIn('persist_confirmed', self.adapter.calls)
        state = self.model.inspect()
        self.assertEqual(state['country']['persisted']['status'], 'pending')
        self.assertFalse(state['wifi_gate_open'])
        self.assertFalse(state['country']['observed']['accepted'])

    def test_verifier_and_persistence_require_explicit_true_not_truthy_exit_status(self):
        self.model._regulatory_verifier = lambda *_: 1
        with self.assertRaises(bootstrap.Refused):
            self.country()
        self.assertNotIn('persist_confirmed', self.adapter.calls)
        self.setUp(); self.adapter.persist_country = lambda _: 1
        with self.assertRaises(bootstrap.Refused):
            self.country()
        self.assertNotIn('apply_country', self.adapter.calls)

    def test_active_connection_or_trial_refuses_before_disable_apply_or_persist(self):
        for field in ('trial', 'connected'):
            with self.subTest(field=field):
                self.setUp(); self.adapter.status[field] = True
                with self.assertRaisesRegex(bootstrap.Refused, 'Wi-Fi activity'):
                    self.country()
                self.assertEqual(self.adapter.calls, ['wifi_status'])
                self.assertFalse(self.model.inspect()['wifi_gate_open'])

    def test_wifi_stays_disabled_through_final_persist_and_observation(self):
        self.adapter.close_wifi_gate = lambda: True
        self.adapter.status['disabled'] = False
        with self.assertRaisesRegex(bootstrap.Refused, 'remain disabled'):
            self.country()
        self.assertNotIn('persist_pending', self.adapter.calls)
        self.setUp(); self.adapter.turn_on_after_confirm = True
        with self.assertRaisesRegex(bootstrap.Refused, 'remain disabled'):
            self.country()
        state = self.model.inspect()
        self.assertEqual(state['country']['persisted']['status'], 'confirmed')
        self.assertFalse(state['wifi_gate_open'])

    def test_adapter_exception_closes_previous_open_gate(self):
        self.country(); self.adapter.raise_at = 'set_time'
        with self.assertRaises(OSError):
            self.time()
        self.assertFalse(self.model.inspect()['wifi_gate_open'])
        self.assertFalse(self.model.inspect()['time']['confirmed'])

    def test_interruption_also_leaves_gate_closed(self):
        self.country()
        def interrupted(_):
            raise KeyboardInterrupt
        self.adapter.set_time = interrupted
        with self.assertRaises(KeyboardInterrupt):
            self.time()
        self.assertFalse(self.model.inspect()['wifi_gate_open'])

    def test_pending_write_cannot_enable_radio_before_apply(self):
        original = self.adapter.persist_country
        def persistence(record):
            result = original(record)
            self.adapter.status['disabled'] = False
            return result
        self.adapter.persist_country = persistence
        with self.assertRaisesRegex(bootstrap.Refused, 'remain disabled'):
            self.country()
        self.assertNotIn('apply_country', self.adapter.calls)
        self.assertFalse(self.model.inspect()['wifi_gate_open'])

    def test_inspected_state_cannot_mutate_internal_observation_or_persistence(self):
        self.country(); state = self.model.inspect()
        state['country']['observed']['accepted'] = False
        state['country']['persisted']['country_code'] = 'GB'
        state = self.model.inspect()
        self.assertTrue(state['country']['observed']['accepted'])
        self.assertEqual(state['country']['persisted']['country_code'], 'FR')

    def initializer(self, callback, inspection=None):
        self.model = bootstrap.BootstrapSystemModel(
            **self.config, application_uid=1000, begin_initialization=callback,
            inspect_initialization=inspection)
        self.adapter.model = self.model
        return self.model

    def initialization_result(self, status='newly_consumed'):
        return {'status': status, 'intent': '12345678-1234-4234-8234-123456789abc',
                'receipt': {'receipt_id': 'abcdef01-1234-4234-8234-123456789abc', 'digest': 'a' * 64}}

    def begin(self, uid=1000):
        return self.model.handle(request('begin_initialization',
                                 intent=self.initialization_result()['intent']), caller_uid=uid)

    def inspect_initialization(self, uid=1000):
        return self.model.handle(request('inspect_initialization'), caller_uid=uid)

    def test_inspection_configuration_optional_but_requires_existing_initialization(self):
        for change in (dict(inspect_initialization=lambda: {'status': 'authorized'}),
                       dict(application_uid=1000, begin_initialization=lambda _: None,
                            inspect_initialization=True)):
            with self.subTest(change=change), self.assertRaises(bootstrap.Refused):
                bootstrap.BootstrapSystemModel(**self.config, **change)
        began = []
        self.initializer(lambda intent: began.append(intent)); self.country()
        before = self.model.inspect(); calls = list(self.adapter.calls)
        with self.assertRaisesRegex(bootstrap.Refused, 'not configured'):
            self.inspect_initialization()
        self.assertEqual(began, []); self.assertEqual(self.model.inspect(), before)
        self.assertEqual(self.adapter.calls, calls)

    def test_inspection_roles_exact_noargs_and_duplicates_refused_before_callback(self):
        inspected = []; began = []
        self.initializer(lambda intent: began.append(intent),
                         lambda: inspected.append('called') or {'status': 'authorized'})
        self.country(); before = self.model.inspect(); calls = list(self.adapter.calls)
        cases = [(request('inspect_initialization'), uid) for uid in (991, 0, 1001, True, '1000')]
        cases += [(request('inspect_initialization', **extra), 1000) for extra in
                  ({'path': '/state'}, {'intent': self.initialization_result()['intent']}, {'argv': []},
                   {'nested': {'status': 'authorized'}})]
        cases.append((b'{"operation":"inspect_initialization","operation":"inspect_initialization"}', 1000))
        for raw, uid in cases:
            with self.subTest(raw=raw, uid=uid), self.assertRaises(bootstrap.Refused):
                self.model.handle(raw, caller_uid=uid)
            self.assertEqual(inspected, []); self.assertEqual(began, [])
            self.assertEqual(self.model.inspect(), before); self.assertEqual(self.adapter.calls, calls)

    def test_inspection_strict_shapes_returns_observation_not_initialization_grant(self):
        consumed = {**self.initialization_result(), 'status': 'consumed'}
        for expected in ({'status': 'authorized'}, consumed):
            with self.subTest(expected=expected):
                inspected = []; began = []
                self.initializer(lambda intent: began.append(intent),
                                 lambda: inspected.append('called') or expected)
                self.country(); before = self.model.inspect(); calls = list(self.adapter.calls)
                result = self.inspect_initialization()
                self.assertEqual(result['initialization'], expected)
                self.assertEqual(inspected, ['called']); self.assertEqual(began, [])
                self.assertEqual(self.model.inspect(), before); self.assertEqual(self.adapter.calls, calls)
                if expected['status'] == 'consumed':
                    result['initialization']['receipt']['digest'] = 'b' * 64
                    self.assertEqual(expected['receipt']['digest'], 'a' * 64)

    def test_inspection_failure_never_defaults_authorized_or_changes_gate(self):
        consumed = {**self.initialization_result(), 'status': 'consumed'}
        cases = [None, True, {}, {'status': True}, {'status': ['authorized']},
                 {'status': 'authorized', 'intent': consumed['intent']},
                 {'status': 'authorized', 'receipt': consumed['receipt']},
                 self.initialization_result(), {**consumed, 'extra': 'ignored'},
                 {**consumed, 'intent': consumed['intent'].upper()},
                 {**consumed, 'receipt': {**consumed['receipt'], 'receipt_id': True}},
                 {**consumed, 'receipt': {**consumed['receipt'], 'digest': 'A' * 64}},
                 {**consumed, 'receipt': {**consumed['receipt'], 'digest': ['a' * 64]}}]
        for value in cases:
            with self.subTest(value=value):
                inspected = []; began = []
                self.initializer(lambda intent: began.append(intent),
                                 lambda: inspected.append('called') or copy.deepcopy(value))
                self.country(); before = self.model.inspect(); calls = list(self.adapter.calls)
                with self.assertRaises(bootstrap.Refused):
                    self.inspect_initialization()
                self.assertEqual(inspected, ['called']); self.assertEqual(began, [])
                self.assertEqual(self.model.inspect(), before); self.assertEqual(self.adapter.calls, calls)
        inspected = []
        def unavailable():
            inspected.append('called')
            raise OSError('fixture state unavailable')
        self.initializer(lambda _: None, unavailable); self.country(); before = self.model.inspect()
        with self.assertRaises(bootstrap.Refused) as error:
            self.inspect_initialization()
        self.assertIsInstance(error.exception.__cause__, OSError)
        self.assertEqual(inspected, ['called']); self.assertEqual(self.model.inspect(), before)

    def test_initialization_configuration_is_optional_paired_and_role_separated(self):
        # Legacy constructors keep time/country; no initialization callback is invented.
        self.country(); before = self.model.inspect(); calls = list(self.adapter.calls)
        with self.assertRaisesRegex(bootstrap.Refused, 'not configured'):
            self.begin(uid=991)
        self.assertEqual(self.model.inspect(), before); self.assertEqual(self.adapter.calls, calls)
        cases = [dict(application_uid=1000), dict(begin_initialization=lambda _: None),
                 dict(application_uid=991, begin_initialization=lambda _: None),
                 dict(application_uid=0, begin_initialization=lambda _: None),
                 dict(application_uid=True, begin_initialization=lambda _: None),
                 dict(application_uid=2**32 - 1, begin_initialization=lambda _: None)]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(bootstrap.Refused):
                bootstrap.BootstrapSystemModel(**self.config, **change)

    def test_helper_and_application_cannot_invoke_each_others_operations(self):
        called = []
        self.initializer(lambda intent: called.append(intent))
        self.country(); before = self.model.inspect(); calls = list(self.adapter.calls)
        cases = [(request('time', unix_seconds=1500), 1000),
                 (request('country', country_code='FR'), 1000),
                 (request('begin_initialization', intent=self.initialization_result()['intent']), 991),
                 (request('begin_initialization', intent=self.initialization_result()['intent']), 0),
                 (request('begin_initialization', intent=self.initialization_result()['intent']), '1000')]
        for raw, uid in cases:
            with self.subTest(uid=uid, raw=raw), self.assertRaises(bootstrap.Refused):
                self.model.handle(raw, caller_uid=uid)
            self.assertEqual(self.model.inspect(), before)
            self.assertEqual(self.adapter.calls, calls)
            self.assertEqual(called, [])

    def test_initialization_parser_exposes_only_canonical_intent(self):
        called = []; self.initializer(lambda intent: called.append(intent))
        intent = self.initialization_result()['intent']
        cases = [request('begin_initialization', intent=intent.upper()),
                 request('begin_initialization', intent=intent.replace('-', '')),
                 request('begin_initialization', intent={'intent': intent}),
                 request('begin_initialization', intent=True),
                 request('begin_initialization', intent=intent, path='/state'),
                 request('begin_initialization', intent=intent, argv=[]),
                 request('create_authorization', intent=intent)]
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(bootstrap.Refused):
                self.model.handle(raw, caller_uid=1000)
        self.assertEqual(called, []); self.assertEqual(self.adapter.calls, [])

    def test_initialization_callback_status_is_preserved_and_invoked_once(self):
        for status in ('newly_consumed', 'already_consumed'):
            with self.subTest(status=status):
                expected = self.initialization_result(status); called = []
                def callback(intent):
                    called.append(intent)
                    return expected
                self.initializer(callback)
                result = self.begin()
                self.assertEqual(called, [expected['intent']])
                self.assertEqual(result['initialization'], expected)
                self.assertTrue(result['acknowledged'])
                self.assertFalse(result['hardware_qualified'])
                result['initialization']['receipt']['digest'] = 'b' * 64
                self.assertEqual(expected['receipt']['digest'], 'a' * 64)
                self.assertEqual(self.adapter.calls, [])

    def test_invalid_initialization_callback_never_upgrades_or_retries_a_grant(self):
        valid = self.initialization_result()
        cases = [None, {}, {**valid, 'status': 'authorized'}, {**valid, 'status': True},
                 {**valid, 'intent': '00000000-0000-0000-0000-000000000000'},
                 {**valid, 'extra': 'ignored'}, {**valid, 'receipt': {}},
                 {**valid, 'receipt': {**valid['receipt'], 'digest': 'A' * 64}},
                 {**valid, 'receipt': {**valid['receipt'], 'digest': 'a' * 63}},
                 {**valid, 'receipt': {**valid['receipt'], 'digest': ['a' * 64]}},
                 {**valid, 'receipt': {**valid['receipt'], 'receipt_id': valid['receipt']['receipt_id'].upper()}},
                 {**valid, 'receipt': {**valid['receipt'], 'secret': 'unexpected'}}]
        for value in cases:
            with self.subTest(value=value):
                called = []
                def callback(intent):
                    called.append(intent)
                    return copy.deepcopy(value)
                self.initializer(callback); self.country()
                before = self.model.inspect(); calls = list(self.adapter.calls)
                with self.assertRaises(bootstrap.InitializationUncertain) as error:
                    self.begin()
                self.assertIsInstance(error.exception.__cause__, bootstrap.Refused)
                self.assertEqual(len(called), 1)
                self.assertEqual(self.model.inspect(), before)
                self.assertEqual(self.adapter.calls, calls)
        called = []
        def uncertain(intent):
            called.append(intent)
            raise OSError('injected uncertain receipt write')
        self.initializer(uncertain); self.country(); before = self.model.inspect()
        with self.assertRaises(bootstrap.InitializationUncertain) as error:
            self.begin()
        self.assertIsInstance(error.exception.__cause__, OSError)
        self.assertEqual(len(called), 1); self.assertEqual(self.model.inspect(), before)

    def test_initialization_interruptions_propagate_without_retry_or_gate_change(self):
        for interruption in (KeyboardInterrupt, SystemExit):
            with self.subTest(interruption=interruption):
                called = []
                def callback(intent):
                    called.append(intent)
                    raise interruption
                self.initializer(callback); self.country(); before = self.model.inspect()
                with self.assertRaises(bootstrap.Refused):
                    self.begin(uid=991)
                self.assertEqual(called, [])
                with self.assertRaises(interruption):
                    self.begin()
                self.assertEqual(len(called), 1)
                self.assertEqual(self.model.inspect(), before)

    def test_real_receipt_fixture_retry_remains_consumed_without_app_store(self):
        receipt_spec = importlib.util.spec_from_file_location(
            'bootstrap_receipt_fixture', Path(__file__).parents[1] / 'scripts/initialization-receipt.py')
        receipts = importlib.util.module_from_spec(receipt_spec); receipt_spec.loader.exec_module(receipts)
        with tempfile.TemporaryDirectory(prefix='.inkyos-bootstrap-test-', dir=Path.home().resolve()) as temporary:
            path = Path(temporary) / 'authorization'
            owner = {'_owner_uid': os.geteuid(), '_owner_gid': os.getegid()}
            called = []
            def callback(intent):
                called.append(intent)
                return receipts.begin(path, intent, **owner)
            self.initializer(callback, lambda: receipts.inspect(path, **owner))
            with self.assertRaises(bootstrap.Refused) as missing:
                self.inspect_initialization()
            self.assertIsInstance(missing.exception.__cause__, receipts.RecoveryRequired)
            self.assertFalse(path.exists()); self.assertEqual(called, [])
            receipts.create_authorization(path, **owner)  # Explicit fixture setup, never an operation.
            def bytes_snapshot():
                return {entry.name: entry.read_bytes() for entry in path.iterdir()}
            authorized_bytes = bytes_snapshot()
            for _ in range(2):
                self.assertEqual(self.inspect_initialization()['initialization'], {'status': 'authorized'})
                self.assertEqual(bytes_snapshot(), authorized_bytes)
            self.assertEqual(called, [])
            first = self.begin()['initialization']
            consumed_bytes = bytes_snapshot()
            for _ in range(2):
                self.assertEqual(self.inspect_initialization()['initialization'], {**first, 'status': 'consumed'})
                self.assertEqual(bytes_snapshot(), consumed_bytes)
            retry = self.begin()['initialization']
            self.assertEqual(first['status'], 'newly_consumed')
            self.assertEqual(retry['status'], 'already_consumed')
            self.assertEqual(first['receipt'], retry['receipt'])
            self.assertEqual(len(called), 2)
            self.assertFalse((Path(temporary) / 'application-store').exists())
            self.assertEqual(self.adapter.calls, [])

    def test_country_transaction_serializes_concurrent_time_operation(self):
        self.adapter.apply_entered = threading.Event(); self.adapter.apply_continue = threading.Event()
        second_started = threading.Event(); second_finished = threading.Event()
        results = []; errors = []
        def country():
            try:
                results.append(self.country())
            except BaseException as exc:
                errors.append(exc)
        def time():
            second_started.set()
            try:
                results.append(self.time())
            except BaseException as exc:
                errors.append(exc)
            finally:
                second_finished.set()
        first = threading.Thread(target=country); second = threading.Thread(target=time)
        first.start()
        try:
            self.assertTrue(self.adapter.apply_entered.wait(timeout=5))
            second.start(); self.assertTrue(second_started.wait(timeout=5))
            self.assertFalse(second_finished.wait(timeout=0.03))
            self.assertNotIn('set_time', self.adapter.calls)
            self.assertFalse(self.model._gate_open)
        finally:
            self.adapter.apply_continue.set()
            first.join(timeout=5)
            if second.ident is not None:
                second.join(timeout=5)
        self.assertFalse(first.is_alive()); self.assertFalse(second.is_alive())
        self.assertEqual(errors, []); self.assertEqual(len(results), 2)
        self.assertGreater(self.adapter.calls.index('set_time'), self.adapter.calls.index('persist_confirmed'))


if __name__ == '__main__':
    unittest.main()
