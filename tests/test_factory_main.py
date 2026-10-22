"""Inert Phase A composition and owned cleanup, without importing Studio.

Explicit components, lease proof and signal fixtures live under a canonical
temporary root. No installed source, app, bus, service, socket or radio is used.
The existing Phase A runner's own drains have their separate Studio tests.
"""
import ast
import asyncio
from contextlib import contextmanager, redirect_stderr
import importlib.util
import io
import logging
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'inkyos_factory_main_tests', ROOT / 'staging/bootstrap/factory-main.py')
main = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = main
spec.loader.exec_module(main)


class PhaseAPending(RuntimeError):
    pass


class CleanupUnknown(RuntimeError):
    pass


class SyntheticProof:
    def __init__(self, events):
        self.events = events
        self.held = self.invalid = False
        self.enters = self.closes = 0
        self.enter_error = self.monitor_error = None
        self.enter_hook = None
        self.check_result = None
        self.close_failures = []
        self.close_hook = None
        self.stop_requested = None

    def __enter__(self):
        self.events.append('enter')
        if self.enter_hook is not None:
            self.enter_hook()
        self.enters += 1
        self.held = True
        if self.enter_error is not None:
            raise self.enter_error
        return self

    def start_monitor(self, loop, stop_requested):
        if not self.held:
            raise AssertionError('monitor before owned proof')
        self.events.append('monitor')
        self.stop_requested = stop_requested
        if self.monitor_error is not None:
            raise self.monitor_error

    def check(self):
        self.events.append('check')
        if not self.held:
            raise AssertionError('check after synthetic lease release')
        if self.invalid:
            raise main.Refused('INERT_GRAPH_INVALID')
        return self.check_result

    @contextmanager
    def initialization_guard(self, connection):
        self.check()
        self.events.append('peer_enter')
        try:
            yield None
        finally:
            self.events.append('peer_exit')

    def setup_guard(self, connection): return self.initialization_guard(connection)

    def network_guard(self, connection): return self.initialization_guard(connection)

    def invalidate(self, reason):
        self.invalid = True
        self.events.append(('invalid', reason))

    def close(self):
        self.events.append('close')
        self.closes += 1
        if self.close_hook is not None:
            self.close_hook()
        if self.close_failures:
            raise self.close_failures.pop(0)
        self.held = False


class FactoryMainFixture(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='inkyos-main-inert-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.events = []
        self.proof = SyntheticProof(self.events)
        self.proof.enter_hook = self.assert_handlers_at_enter
        self.shutdown = None
        self.handlers_active = False
        self.serve_call = None
        self.display_instances = []
        self.bootstrap_instances = []
        self.serve_body = None
        self.diagnostics = io.StringIO()
        capture = redirect_stderr(self.diagnostics)
        capture.__enter__()
        self.addCleanup(capture.__exit__, None, None, None)

    def signals(self, loop, shutdown):
        self.assertFalse(self.proof.held)
        self.events.append('signals')
        self.shutdown = shutdown
        self.handlers_active = True
        def remove():
            self.assertTrue(self.handlers_active)
            self.assertFalse(self.proof.held)
            self.events.append('remove_signals')
            self.handlers_active = False
        return remove

    def assert_handlers_at_enter(self):
        self.assertTrue(self.handlers_active)
        self.assertTrue(callable(self.shutdown))
        self.assertFalse(self.proof.held)

    def components(self):
        self.assertTrue(self.proof.held)
        self.events.append('components')
        owner = self
        class Display:
            def __init__(self, *, mode):
                owner.assertTrue(owner.proof.held)
                self.mode = mode
                owner.display_instances.append(self)
        class Bootstrap:
            def __init__(self, result, verify_epoch, controller, directory, *, system_setup, network, softap):
                owner.assertTrue(callable(system_setup.peer_guard))
                owner.assertTrue(callable(network.peer_guard))
                owner.assertTrue(owner.proof.held)
                owner.assertIs(softap.system_setup, system_setup)
                self.arguments = (result, verify_epoch, controller, directory)
                self.system_setup, self.network, self.softap = system_setup, network, softap
                owner.bootstrap_instances.append(self)
        async def serve(directory, **kwargs):
            self.assertTrue(self.proof.held)
            self.events.append('serve')
            self.serve_call = (directory, kwargs)
            if self.serve_body is not None:
                return await self.serve_body(directory, kwargs)
            raise PhaseAPending('INERT_PHASE_A_PENDING')
        class Client:
            def __init__(self, *, peer_guard): self.peer_guard = peer_guard
        class SoftAP:
            def __init__(self, system_setup):
                owner.assertTrue(owner.proof.held)
                self.system_setup = system_setup
        return serve, Display, Bootstrap, Client, Client, SoftAP

    async def run_candidate(self, **overrides):
        values = {'_root': self.root, '_proof': self.proof,
                  '_components': self.components, '_signals': self.signals}
        values.update(overrides)
        return await main.run_phase_a(**values)


class FactoryMainTests(FactoryMainFixture):
    async def test_bootstrap_milestones_are_visible_without_global_info_logging(self):
        logger = logging.getLogger('inky_web.provisioning.bootstrap_runtime')
        before = (logger.level, logger.propagate, list(logger.handlers))
        root_level = logging.getLogger().level

        async def exercise(directory, kwargs):
            logger.info('Factory bootstrap %s', 'qr_ready')
            logger.info('Factory bootstrap %s', 'ble_advertised')
            logger.debug('INERT_PRIVATE_DEBUG')
            self.assertEqual(logging.getLogger().level, root_level)
            raise PhaseAPending('INERT_PHASE_A_PENDING')

        self.serve_body = exercise
        with self.assertRaises(PhaseAPending):
            await self.run_candidate()
        self.assertIn('Factory bootstrap qr_ready\n', self.diagnostics.getvalue())
        self.assertIn('Factory bootstrap ble_advertised\n', self.diagnostics.getvalue())
        self.assertNotIn('INERT_PRIVATE_DEBUG', self.diagnostics.getvalue())
        self.assertEqual((logger.level, logger.propagate, list(logger.handlers)), before)

    async def test_fixed_composition_runs_only_inside_owned_graph(self):
        result, verify_epoch = object(), lambda: 'INERT_EPOCH'
        async def exercise(directory, kwargs):
            self.assertEqual(directory, Path('/var/lib/inky-studio'))
            self.assertEqual(set(kwargs), {'stop_requested', 'display_factory', 'runtime_factory',
                                           'admission_check', 'initialization_peer_guard'})
            self.assertIsNone(kwargs['admission_check']())
            controller = kwargs['display_factory']()
            self.assertEqual(controller.mode, 'hardware')
            runtime = kwargs['runtime_factory'](result, controller, verify_epoch)
            self.assertEqual(runtime.arguments, (result, verify_epoch, controller, directory / "provisioning"))
            self.assertIs(runtime.softap.system_setup, runtime.system_setup)
            self.assertEqual(runtime.system_setup.peer_guard, self.proof.setup_guard)
            self.assertEqual(runtime.network.peer_guard, self.proof.network_guard)
            with kwargs['initialization_peer_guard'](object()) as value:
                self.assertIsNone(value)
            self.assertFalse(kwargs['stop_requested'].is_set())
            raise PhaseAPending('INERT_PHASE_A_PENDING')
        self.serve_body = exercise
        with self.assertRaises(PhaseAPending):
            await self.run_candidate()
        self.assertEqual(self.events[:6], ['signals', 'enter', 'monitor', 'components', 'check', 'serve'])
        self.assertEqual(self.events[-2:], ['close', 'remove_signals'])
        self.assertFalse(self.proof.held)
        self.assertEqual((self.proof.enters, self.proof.closes), (1, 1))

    async def test_binding_refusal_precedes_components_and_always_cleans_ownership(self):
        self.proof.enter_error = main.Refused('INERT_INITIAL_BINDING_REFUSED')
        with self.assertRaisesRegex(main.Refused, 'INERT_INITIAL_BINDING_REFUSED'):
            await self.run_candidate()
        self.assertEqual(self.events, ['signals', 'enter', 'close', 'remove_signals'])
        self.assertFalse(self.proof.held)
        self.assertFalse(self.handlers_active)
        self.assertIsNone(self.serve_call)
        self.assertEqual(self.diagnostics.getvalue(), 'factory_main_phase:graph_binding\n')

    async def test_static_breadcrumbs_bound_real_composition_steps_without_hardware(self):
        phases = ['graph_binding', 'graph_bound', 'components_loading',
                  'components_loaded', 'phase_a_enter']
        def observed():
            return self.diagnostics.getvalue().splitlines()
        def expected(count):
            return ['factory_main_phase:' + phase for phase in phases[:count]]
        def entering():
            self.assert_handlers_at_enter()
            self.assertEqual(observed(), expected(1))
        self.proof.enter_hook = entering
        def components():
            self.assertEqual(observed(), expected(3))
            return self.components()
        original_check = self.proof.check
        def check():
            self.assertEqual(observed(), expected(4))
            return original_check()
        self.proof.check = check
        async def serve(directory, kwargs):
            self.assertTrue(self.proof.held)
            self.assertEqual(observed(), expected(5))
            raise PhaseAPending('INERT_PRIVATE_PENDING_TEXT')
        self.serve_body = serve
        with self.assertRaises(PhaseAPending):
            await self.run_candidate(_components=components)
        self.assertEqual(observed(), expected(5))
        self.assertEqual(self.events[-2:], ['close', 'remove_signals'])
        self.assertFalse(self.proof.held or self.handlers_active)

    async def test_uncertain_enter_failure_retries_only_owned_cleanup(self):
        self.proof.enter_error = CleanupUnknown('INERT_BINDING_UNCERTAIN')
        self.proof.close_failures = [CleanupUnknown('INERT_QUERY_STILL_OWNED')]
        held_during_close = []
        self.proof.close_hook = lambda: held_during_close.append(
            (self.proof.held, self.handlers_active, callable(self.shutdown)))
        with self.assertRaisesRegex(CleanupUnknown, 'INERT_BINDING_UNCERTAIN'):
            await self.run_candidate()
        self.assertEqual(self.events, ['signals', 'enter', 'close', 'close', 'remove_signals'])
        self.assertEqual(held_during_close, [(True, True, True), (True, True, True)])
        self.assertEqual(self.proof.enters, 1)
        self.assertFalse(self.proof.held)
        self.assertFalse(self.handlers_active)

    async def test_signal_registration_failure_never_attempts_proof_acquisition(self):
        def failed_registration(loop, shutdown):
            self.assertFalse(self.proof.held)
            self.assertEqual(self.proof.enters, 0)
            self.events.append('signals_failed')
            raise RuntimeError('INERT_SIGNAL_REGISTRATION_FAILED')
        with self.assertRaisesRegex(RuntimeError, 'INERT_SIGNAL_REGISTRATION_FAILED'):
            await self.run_candidate(_signals=failed_registration)
        self.assertEqual(self.proof.enters, 0)
        self.assertFalse(self.proof.held)
        for forbidden in ('enter', 'monitor', 'components', 'serve'):
            self.assertNotIn(forbidden, self.events)
        self.assertFalse(self.handlers_active)

    async def test_production_source_loading_is_deferred_until_handlers_are_active(self):
        def load_proof():
            self.assertTrue(self.handlers_active)
            self.assertTrue(callable(self.shutdown))
            self.assertEqual(self.proof.enters, 0)
            self.events.append('installed_proof')
            return self.proof
        with patch.object(main, 'installed_proof', side_effect=load_proof), \
                patch.object(main, 'install_signals', side_effect=self.signals), \
                patch.object(main, 'load_components', side_effect=self.components):
            with self.assertRaises(PhaseAPending):
                await main.run_phase_a()
        self.assertEqual(self.events[:4], ['signals', 'installed_proof', 'enter', 'monitor'])
        self.assertEqual(self.events[-2:], ['close', 'remove_signals'])
        self.assertFalse(self.proof.held or self.handlers_active)

    async def test_production_source_loading_failure_removes_handlers_without_enter(self):
        def failed_load():
            self.assertTrue(self.handlers_active)
            self.events.append('installed_proof_failed')
            raise PermissionError('INERT_SOURCE_DENIED')
        with patch.object(main, 'installed_proof', side_effect=failed_load), \
                patch.object(main, 'install_signals', side_effect=self.signals):
            with self.assertRaisesRegex(PermissionError, 'INERT_SOURCE_DENIED'):
                await main.run_phase_a()
        self.assertEqual(self.events, ['signals', 'installed_proof_failed', 'remove_signals'])
        self.assertEqual(self.proof.enters, 0)
        self.assertFalse(self.proof.held or self.handlers_active)

    async def test_shutdown_during_registration_refuses_before_production_source_loading(self):
        def early_shutdown(loop, shutdown):
            remove = self.signals(loop, shutdown)
            shutdown()
            return remove
        with patch.object(main, 'installed_proof', side_effect=AssertionError('proof loaded after stop')), \
                patch.object(main, 'install_signals', side_effect=early_shutdown):
            with self.assertRaisesRegex(main.Refused, 'shutdown_requested'):
                await main.run_phase_a()
        self.assertEqual(self.events, ['signals', 'remove_signals'])
        self.assertFalse(self.proof.invalid)
        self.assertEqual(self.proof.enters, 0)
        self.assertFalse(self.handlers_active)

    async def test_shutdown_callback_available_during_enter_prevents_monitor_and_app(self):
        def interrupted_enter():
            self.assert_handlers_at_enter()
            self.shutdown()
        self.proof.enter_hook = interrupted_enter
        with self.assertRaisesRegex(main.Refused, 'shutdown_requested'):
            await self.run_candidate()
        self.assertEqual(self.events, ['signals', 'enter', ('invalid', 'shutdown_requested'),
                                      'close', 'remove_signals'])
        self.assertEqual(self.proof.enters, 1)
        self.assertTrue(self.proof.invalid)
        self.assertFalse(self.proof.held or self.handlers_active)

    async def test_monitor_failure_does_not_load_app_components(self):
        self.proof.monitor_error = RuntimeError('INERT_MONITOR_UNAVAILABLE')
        with self.assertRaisesRegex(RuntimeError, 'INERT_MONITOR_UNAVAILABLE'):
            await self.run_candidate()
        self.assertEqual(self.events, ['signals', 'enter', 'monitor', 'close', 'remove_signals'])
        self.assertFalse(self.proof.held)

    async def test_admission_callback_must_return_exact_none_before_serve(self):
        for value in (False, True, 'allowed'):
            with self.subTest(value=value):
                self.events.clear()
                self.proof = SyntheticProof(self.events)
                self.proof.enter_hook = self.assert_handlers_at_enter
                self.proof.check_result = value
                with self.assertRaises(main.Refused):
                    await self.run_candidate()
                self.assertNotIn('serve', self.events)
                self.assertEqual(self.events[-2:], ['close', 'remove_signals'])
                self.assertFalse(self.proof.held)

    async def test_component_import_failure_has_no_main_or_normal_mode_fallback(self):
        def unavailable():
            self.events.append('components_failed')
            raise ImportError('INERT_CANDIDATE_COMPONENT_MISSING')
        with self.assertRaisesRegex(ImportError, 'INERT_CANDIDATE_COMPONENT_MISSING'):
            await self.run_candidate(_components=unavailable)
        self.assertNotIn('serve', self.events)
        self.assertEqual(self.events[-2:], ['close', 'remove_signals'])
        self.assertFalse(self.proof.held)
        self.assertEqual(self.diagnostics.getvalue().splitlines(), [
            'factory_main_phase:graph_binding', 'factory_main_phase:graph_bound',
            'factory_main_phase:components_loading'])

    async def test_shutdown_invalidates_admission_and_sets_studio_stop_event(self):
        async def shutdown_and_drain(directory, kwargs):
            self.shutdown()
            self.assertTrue(kwargs['stop_requested'].is_set())
            self.assertTrue(self.proof.held)
            with self.assertRaises(main.Refused):
                kwargs['admission_check']()
            self.events.append('owned_drain_finished')
            raise PhaseAPending('INERT_STOPPED_AFTER_DRAIN')
        self.serve_body = shutdown_and_drain
        with self.assertRaises(PhaseAPending):
            await self.run_candidate()
        self.assertIn(('invalid', 'shutdown_requested'), self.events)
        self.assertLess(self.events.index('owned_drain_finished'), self.events.index('close'))
        self.assertEqual(self.proof.enters, 1)

    async def test_returning_runner_is_refused_and_cleanup_still_finishes(self):
        async def returned(directory, kwargs):
            return None
        self.serve_body = returned
        with self.assertRaisesRegex(main.Refused, 'phase_a_returned'):
            await self.run_candidate()
        self.assertFalse(self.proof.held)
        self.assertEqual(self.events[-2:], ['close', 'remove_signals'])

    async def test_unconfirmed_cleanup_retains_lease_without_restarting_runner(self):
        self.proof.close_failures = [CleanupUnknown('INERT_PEER_NOT_DRAINED'),
                                     CleanupUnknown('INERT_QUERY_NOT_REAPED')]
        ownership = []
        self.proof.close_hook = lambda: ownership.append((self.proof.held, self.handlers_active))
        with self.assertRaises(PhaseAPending):
            await self.run_candidate()
        self.assertEqual(ownership, [(True, True), (True, True), (True, True)])
        self.assertEqual((self.events.count('enter'), self.events.count('components'),
                          self.events.count('serve'), self.events.count('remove_signals')), (1, 1, 1, 1))
        self.assertFalse(self.proof.held)

    async def test_cancellation_during_cleanup_cannot_release_before_owned_drain(self):
        closing, permit_drain = asyncio.Event(), asyncio.Event()
        ownership = []
        def pending():
            ownership.append((self.proof.held, self.handlers_active))
            closing.set()
            if not permit_drain.is_set():
                raise CleanupUnknown('INERT_DRAIN_PENDING')
        self.proof.close_hook = pending
        task = asyncio.create_task(self.run_candidate())
        try:
            await asyncio.wait_for(closing.wait(), 1)
            self.assertTrue(self.proof.held)
            task.cancel()
            permit_drain.set()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 1)
        finally:
            permit_drain.set()
            if not task.done():
                task.cancel()
                try:
                    await asyncio.wait_for(task, 1)
                except asyncio.CancelledError:
                    pass
        self.assertGreaterEqual(len(ownership), 2)
        self.assertTrue(all(held and handlers for held, handlers in ownership))
        self.assertFalse(self.proof.held)
        self.assertEqual((self.proof.enters, self.events.count('serve'),
                          self.events.count('remove_signals')), (1, 1, 1))

    async def test_production_entry_rejects_all_overrides_before_loading_sources(self):
        with patch.object(main, 'installed_proof', side_effect=AssertionError('installed proof loaded')):
            for override in ({'_proof': self.proof}, {'_components': self.components},
                             {'_signals': self.signals}):
                with self.subTest(override=next(iter(override))), self.assertRaises(main.Refused):
                    await main.run_phase_a(**override)
        self.assertEqual(self.events, [])

    async def test_synthetic_injection_rejects_root_relative_missing_and_alias_paths(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        for rejected in (Path('/'), Path('relative'), self.root / 'missing', alias):
            with self.subTest(root=str(rejected)), self.assertRaises((main.Refused, FileNotFoundError)):
                await self.run_candidate(_root=rejected)
        self.assertEqual(self.events, [])


class FactoryMainEntryTests(unittest.TestCase):
    def entry_output(self, error):
        output = io.StringIO()
        def refused(coroutine):
            coroutine.close()
            raise error
        with patch.object(main.asyncio, 'run', side_effect=refused), redirect_stderr(output):
            self.assertEqual(main.main([]), 78)
        return output.getvalue()

    def test_uninstalled_entry_refuses_before_any_fixed_source_read(self):
        with patch.object(main, 'read_fixed', side_effect=AssertionError('installed file read')):
            with self.assertRaises(main.Refused):
                main.installed_proof()

    def test_cli_rejects_options_and_never_reports_private_exception_details(self):
        output = io.StringIO()
        with patch.object(main.asyncio, 'run', side_effect=AssertionError('runner started')), \
                redirect_stderr(output):
            result = main.main(['--data-dir', '/INERT_PRIVATE_OVERRIDE'])
        self.assertEqual(result, 78)
        self.assertEqual(output.getvalue(), 'factory_main_refused\n')

    def test_cli_logs_only_fixed_nonprivate_refusal_code(self):
        for reason in ('observation_timeout', 'source_changed', '/INERT_PRIVATE_PATH',
                       'INERT_PRIVATE_SECRET', [], None):
            error = ValueError('INERT_PRIVATE_EXCEPTION_MESSAGE')
            error.reason = reason
            output = io.StringIO()
            def refused(coroutine):
                coroutine.close()
                raise error
            with patch.object(main.asyncio, 'run', side_effect=refused), redirect_stderr(output):
                self.assertEqual(main.main([]), 78)
            expected = ('factory_main_refused:' + reason
                        if type(reason) is str and reason in main.DIAGNOSTIC_REASONS
                        else 'factory_main_refused')
            self.assertEqual(output.getvalue(), expected + '\n')

    def test_all_literal_graph_runtime_refusals_have_exact_public_diagnostics(self):
        reasons = set()
        for path in ('staging/bootstrap/writer-graph.py', 'scripts/factory-runtime-contract.py'):
            for node in ast.walk(ast.parse((ROOT / path).read_bytes())):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    position = (1 if node.func.id == 'require' else 0
                                if node.func.id in {'Refused', 'ObservationUnknown', 'boundary'} else None)
                    if position is not None and len(node.args) > position:
                        value = node.args[position]
                        if isinstance(value, ast.Constant) and type(value.value) is str:
                            reasons.add(value.value)
                if isinstance(node, ast.FunctionDef):
                    arguments = node.args.posonlyargs + node.args.args
                    for argument, value in zip(arguments[len(arguments) - len(node.args.defaults):],
                                               node.args.defaults):
                        if argument.arg == 'reason' and isinstance(value, ast.Constant) and type(value.value) is str:
                            reasons.add(value.value)
        self.assertEqual(main.DIAGNOSTIC_REASONS, reasons)
        self.assertTrue({'unit_not_running', 'unit_configuration', 'support_pin_missing',
                         'writer_admission_refused', 'contract_unavailable'} <= reasons)
        for reason in sorted(reasons):
            with self.subTest(reason=reason):
                error = ValueError('INERT_PRIVATE_MESSAGE')
                error.reason = reason
                self.assertEqual(self.entry_output(error), 'factory_main_refused:' + reason + '\n')

    def test_backend87_factory_runtime_codes_are_distinct_and_keep_exit78(self):
        # Exact public FactoryRuntimeError._CODES contract at Studio 87c082.
        codes = {'factory_runtime_refused', 'factory_runtime_uncertain', 'factory_runtime_pending'}
        self.assertEqual(main.DIAGNOSTIC_CODES, codes)
        for code in sorted(codes):
            with self.subTest(code=code):
                error = RuntimeError('INERT_PRIVATE_BACKEND_MESSAGE')
                error.reason = '/INERT_PRIVATE_REASON'
                error.code, error.exit_status = code, 0
                self.assertEqual(self.entry_output(error), 'factory_main_refused:' + code + '\n')

    def test_backend_wrapper_preserves_graph_reason_before_cleanup_and_exit78(self):
        events, output = [], io.StringIO()
        proof = SyntheticProof(events)
        error = RuntimeError('INERT_PRIVATE_BACKEND_MESSAGE')
        error.code = 'factory_runtime_refused'
        graph_line = 'factory_main_graph_refused:observation_timeout'
        observation = (2, 4, 1, 100000, 100000, 116000, 0, 16000, 16000, 15000)
        timing_line = 'factory_main_observation_timeout:[2,4,1,100000,100000,116000,0,16000,16000,15000]'
        async def serve(*args, **kwargs):
            events.append('serve')
            proof.reason = 'observation_timeout'
            proof._timeout_observation = observation
            raise error
        def before_close():
            self.assertTrue(proof.held)
            self.assertEqual(output.getvalue().splitlines()[-2:], [graph_line, timing_line])
            proof.reason = 'graph_invalid'
        proof.close_hook = before_close
        original = main.run_phase_a
        with tempfile.TemporaryDirectory(prefix='inkyos-main-masked-refusal-') as directory:
            async def candidate():
                try:
                    await original(_root=Path(directory).resolve(), _proof=proof,
                                   _components=lambda: (serve, lambda: None, lambda: None, None, None, None),
                                   _signals=lambda *_: lambda: events.append('remove_signals'))
                except BaseException as observed:
                    self.assertIs(observed, error)
                    raise
            with patch.object(main, 'run_phase_a', candidate), redirect_stderr(output):
                self.assertEqual(main.main([]), 78)
        self.assertEqual(output.getvalue().splitlines()[-3:], [
            graph_line, timing_line, 'factory_main_refused:factory_runtime_refused'])
        self.assertEqual(events[-2:], ['close', 'remove_signals'])
        self.assertEqual((proof.enters, proof.closes), (1, 1))
        self.assertFalse(proof.held)

    def test_timeout_diagnostic_accepts_only_closed_bounded_numeric_records(self):
        proof = SyntheticProof([])
        proof.reason = 'observation_timeout'
        valid = (1, 1, 0, 100000, 0, 115000, 15000, 0, 15000, 15000)
        proof._timeout_observation = valid
        self.assertEqual(main.public_timeout_diagnostic(proof),
                         'factory_main_observation_timeout:[1,1,0,100000,0,115000,15000,0,15000,15000]')
        invalid = [None, list(valid), '/INERT_PRIVATE_VALUE', valid[:-1],
                   (4, *valid[1:]), (1, 6, *valid[2:]), (1, 1, 1, *valid[3:]),
                   (True, *valid[1:]), (1.0, *valid[1:]),
                   (*valid[:3], 2**53, *valid[4:]), (*valid[:-1], 0),
                   (*valid[:6], -1, *valid[7:]), (*valid[:8], 14998, 15000)]
        for value in invalid:
            proof._timeout_observation = value
            self.assertIsNone(main.public_timeout_diagnostic(proof))
        proof._timeout_observation = valid
        proof.reason = 'source_changed'
        self.assertIsNone(main.public_timeout_diagnostic(proof))

    def test_timeout_diagnostic_does_not_access_private_properties_or_numeric_hooks(self):
        accessed = []
        class PrivateProof:
            @property
            def reason(self):
                accessed.append('reason')
                raise AssertionError('reason property accessed')
            @property
            def _timeout_observation(self):
                accessed.append('observation')
                raise AssertionError('observation property accessed')
            @property
            def __dict__(self):
                accessed.append('dictionary')
                raise AssertionError('dictionary property accessed')
        class PrivateNumber(int):
            def __str__(self):
                accessed.append('str')
                raise AssertionError('number formatted')
            def __eq__(self, _):
                accessed.append('eq')
                raise AssertionError('number compared')
        self.assertIsNone(main.public_timeout_diagnostic(PrivateProof()))
        proof = SyntheticProof([])
        proof.reason = 'observation_timeout'
        proof._timeout_observation = (PrivateNumber(1), 1, 0, 100000, 0, 115000, 15000, 0, 15000, 15000)
        self.assertIsNone(main.public_timeout_diagnostic(proof))
        self.assertEqual(accessed, [])

    def test_graph_diagnostics_ignore_private_values_text_and_properties(self):
        accessed = []
        class StringSubclass(str):
            def __hash__(self):
                accessed.append('hash')
                raise AssertionError('string subclass must not enter whitelist lookup')
        for value in ('INERT_PRIVATE_SECRET', '/INERT_PRIVATE_PATH', None, [],
                      StringSubclass('observation_timeout')):
            proof = SyntheticProof([])
            proof.reason = value
            self.assertIsNone(main.public_graph_diagnostic(proof))
        class PrivateProof:
            def __str__(self):
                accessed.append('str')
                raise AssertionError('graph text must not be formatted')
            def __repr__(self):
                accessed.append('repr')
                raise AssertionError('graph repr must not be formatted')
            @property
            def reason(self):
                accessed.append('reason')
                raise AssertionError('graph reason property must not be invoked')
        class PrivateDictionary(PrivateProof):
            @property
            def __dict__(self):
                accessed.append('__dict__')
                raise AssertionError('graph dictionary property must not be invoked')
        for proof in (PrivateProof(), PrivateDictionary()):
            self.assertIsNone(main.public_graph_diagnostic(proof))
        self.assertEqual(accessed, [])

    def test_private_unknown_unicode_and_nonexact_string_types_remain_generic(self):
        class StringSubclass(str):
            def __hash__(self):
                raise AssertionError('string subclass must never enter whitelist lookup')
        values = ('/INERT_PRIVATE_PATH', 'INERT_PRIVATE_SECRET', 'clé🔑',
                  'source_changed\nINERT_PRIVATE_TEXT', 'sourcе_changed',
                  'factory_runtime_pending ', None, [], {}, 78, True,
                  b'source_changed', StringSubclass('source_changed'))
        for value in values:
            with self.subTest(kind=type(value).__name__):
                error = ValueError('INERT_PRIVATE_EXCEPTION_MESSAGE')
                error.reason = error.code = value
                self.assertEqual(self.entry_output(error), 'factory_main_refused\n')

    def test_exception_text_unknown_attributes_and_properties_are_never_read(self):
        class PrivateError(Exception):
            def __str__(self):
                raise AssertionError('exception text must not be formatted')
            def __repr__(self):
                raise AssertionError('exception repr must not be formatted')
            @property
            def reason(self):
                raise AssertionError('reason property must not be invoked')
            @property
            def code(self):
                raise AssertionError('code property must not be invoked')
            @property
            def secret(self):
                raise AssertionError('unknown attribute must not be read')
        self.assertEqual(self.entry_output(PrivateError('INERT_PRIVATE_ARGS')), 'factory_main_refused\n')

    def test_known_code_in_wrong_public_field_is_not_authorized(self):
        for field, value in (('code', 'source_changed'), ('reason', 'factory_runtime_pending')):
            error = ValueError('INERT_PRIVATE_EXCEPTION_MESSAGE')
            setattr(error, field, value)
            self.assertEqual(self.entry_output(error), 'factory_main_refused\n')

    def test_signal_registration_failure_removes_only_owned_handlers(self):
        calls = []
        class Loop:
            def add_signal_handler(self, number, callback):
                calls.append(('add', number))
                if number == signal.SIGINT:
                    raise RuntimeError('INERT_SIGNAL_REGISTRATION_FAILED')
            def remove_signal_handler(self, number):
                calls.append(('remove', number))
        with self.assertRaisesRegex(RuntimeError, 'INERT_SIGNAL_REGISTRATION_FAILED'):
            main.install_signals(Loop(), lambda: None)
        self.assertEqual(calls, [('add', signal.SIGTERM), ('add', signal.SIGINT),
                                 ('remove', signal.SIGTERM)])


if __name__ == '__main__':
    unittest.main()
