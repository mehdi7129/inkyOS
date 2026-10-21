"""Bounded diagnostic counters under inert graph/backend and clock fixtures.

Admission clocks, budgets, service observations, scans and owned cleanup remain
the production paths. No image, PID1, hardware, radio or VM is executed.
"""
import io
import logging
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_writer_graph import Connection, GraphFixture, graph
from test_factory_main import FactoryMainFixture, PhaseAPending, SyntheticProof, main


class GraphCostTests(GraphFixture):
    def test_source_and_pid1_block_totals_count_the_existing_two_scans(self):
        self.active()
        self.proof._cost_observation = (0,) * 16
        clock = SimpleNamespace(value=100.0)
        def advance(seconds):
            clock.value += seconds
        self.sources.check_hook = lambda: advance(2)
        self.backend.snapshot_hook = lambda _: advance(1)
        self.backend.resolve_hook = lambda _: advance(1)
        with patch.object(graph, '_COST_CLOCK', lambda: clock.value):
            self.assertIsNone(self.proof.check())
        value = self.proof._cost_observation
        self.assertEqual(value[:9], (0, 0, 2, 4000, 1, 9000, 1, 0, 13000))
        self.assertEqual(value[9:], (0,) * 7)

    def test_prepare_is_measured_separately_from_binding_checks(self):
        clock = SimpleNamespace(value=100.0)
        original = self.sources.prepare
        def prepare(lease):
            clock.value += 3
            return original(lease)
        self.sources.prepare = prepare
        with patch.object(graph, '_COST_CLOCK', lambda: clock.value):
            self.active()
        self.assertEqual(self.proof._cost_observation[:6], (1, 3000, 3, 0, 1, 0))

    def test_check_monitor_and_peer_have_distinct_wait_and_hold_groups(self):
        self.active()
        self.proof._cost_observation = (0,) * 16
        clock = SimpleNamespace(value=100.0)
        real_query = self.proof._query
        class Query:
            def acquire(inner, **kwargs):
                clock.value += 2
                return real_query.acquire(**kwargs)
            def release(inner): return real_query.release()
            def locked(inner): return real_query.locked()
        verify = self.proof._verify
        def measured_verify(*args):
            result = verify(*args)
            clock.value += 5
            return result
        with patch.object(graph, '_COST_CLOCK', lambda: clock.value), \
                patch.object(self.proof, '_query', Query()), \
                patch.object(self.proof, '_verify', measured_verify):
            self.proof.check()
            with patch.object(self.proof, '_monitor', threading.current_thread()):
                self.proof.check()
            with self.proof.initialization_guard(Connection(self.backend.pids['ipc'])):
                # Operation time after attestation is outside the query hold.
                clock.value += 100
        self.assertEqual(self.proof._cost_observation[6:15], (1, 2000, 5000) * 3)
        self.assertEqual(self.proof._cost_observation[2], 7)  # 2+2+3 scans retained.
        self.assertEqual(self.proof._cost_observation[4], 3)

    def test_failed_query_wait_is_counted_without_inventing_hold_time(self):
        self.active()
        self.proof._cost_observation = (0,) * 16
        clock = SimpleNamespace(value=100.0)
        def acquire(**kwargs):
            clock.value += 2
            return False
        with patch.object(graph, '_COST_CLOCK', lambda: clock.value), \
                patch.object(self.proof, '_query', SimpleNamespace(acquire=acquire)):
            self.refused(self.proof.check, 'observation_timeout')
        self.assertEqual(self.proof._cost_observation[6:9], (1, 2000, 0))

    def test_source_failure_counts_work_and_preserves_exact_original_exception(self):
        self.active()
        self.proof._cost_observation = (0,) * 16
        clock = SimpleNamespace(value=100.0)
        def work(): clock.value += 2
        self.sources.check_hook = work
        original = RuntimeError('INERT_PRIVATE_SOURCE_FAILURE')
        self.sources.failure = original
        with patch.object(graph, '_COST_CLOCK', lambda: clock.value):
            with self.assertRaises(RuntimeError) as caught:
                self.proof.check()
        self.assertIs(caught.exception, original)
        self.assertEqual(self.proof._cost_observation[2:6], (1, 2000, 0, 0))
        self.assertTrue(self.lease.held)
        self.assertFalse(self.proof._query.locked())

    def test_counts_and_elapsed_values_saturate_at_native_int_limit(self):
        limit = 2**31 - 1
        self.proof._cost_observation = (limit,) * 16
        with patch.object(graph, '_COST_CLOCK', side_effect=(1.0, 10_000_000.0)):
            with self.proof._cost_scope(0):
                pass
        self.assertEqual(self.proof._cost_observation, (limit,) * 16)
        self.proof._cost_observation = (0,) * 16
        with patch.object(graph, '_COST_CLOCK', side_effect=(1.0, 10_000_000.0)):
            with self.proof._cost_scope(0):
                pass
        self.assertEqual(self.proof._cost_observation[:2], (1, limit))

    def test_invalid_or_reversed_diagnostic_clocks_record_no_duration(self):
        for start, end in ((None, 100), (100, None), (True, 100), (-1, 100),
                           (float('nan'), 100), (100, float('inf')), (100, 99),
                           (2**53, 2**53)):
            with self.subTest(start=start, end=end):
                self.proof._cost_observation = (0,) * 16
                with patch.object(graph, '_COST_CLOCK', side_effect=(start, end)):
                    with self.proof._cost_scope(0):
                        pass
                self.assertEqual(self.proof._cost_observation[:2], (1, 0))
                self.assertEqual(self.proof._cost_observation[15], 1)

    def test_diagnostic_clock_exceptions_do_not_replace_source_refusal_or_cleanup(self):
        self.active()
        self.proof._cost_observation = (0,) * 16
        original = graph.Refused('source_changed')
        self.sources.failure = original
        with patch.object(graph, '_COST_CLOCK', side_effect=KeyboardInterrupt('INERT_CLOCK')):
            self.assertIs(self.refused(self.proof.check, 'source_changed'), original)
        self.assertGreater(self.proof._cost_observation[15], 0)
        self.assertTrue(self.lease.held)
        self.assertFalse(self.proof._query.locked())


class CostEmissionTests(FactoryMainFixture):
    async def test_snapshots_emit_once_per_milestone_and_before_refusal_cleanup(self):
        self.proof._cost_observation = tuple(range(16))
        logger = logging.getLogger('inky_web.provisioning.bootstrap_runtime')
        async def exercise(*_):
            for stage in ('qr_ready', 'ble_advertised', 'qr_ready', 'ble_advertised'):
                logger.info('Factory bootstrap %s', stage)
            raise PhaseAPending('INERT_PENDING')
        self.serve_body = exercise
        def before_close():
            self.assertIn('factory_main_graph_cost:refused:', self.diagnostics.getvalue())
        self.proof.close_hook = before_close
        with self.assertRaises(PhaseAPending):
            await self.run_candidate()
        output = self.diagnostics.getvalue()
        for stage in ('qr_ready', 'ble_advertised', 'refused'):
            self.assertEqual(output.count('factory_main_graph_cost:' + stage + ':'), 1)
        self.assertNotIn('INERT_PENDING', output)
        self.assertFalse(self.proof.held)

    async def test_optional_cost_formatter_failure_never_changes_phase_a_exception(self):
        original = PhaseAPending('INERT_ORIGINAL')
        logger = logging.getLogger('inky_web.provisioning.bootstrap_runtime')
        async def exercise(*_):
            logger.info('Factory bootstrap %s', 'qr_ready')
            raise original
        self.serve_body = exercise
        with patch.object(main, 'public_cost_diagnostic', side_effect=KeyboardInterrupt('INERT_FORMAT')):
            with self.assertRaises(PhaseAPending) as caught:
                await self.run_candidate()
        self.assertIs(caught.exception, original)
        self.assertFalse(self.proof.held)

    def test_public_schema_accepts_only_exact_closed_native_numeric_tuple(self):
        proof = SyntheticProof([])
        valid = tuple(range(16))
        proof._cost_observation = valid
        self.assertEqual(main.public_cost_diagnostic(proof, 'qr_ready'),
                         'factory_main_graph_cost:qr_ready:[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]')
        for value in (list(valid), valid[:-1], (True, *valid[1:]), (-1, *valid[1:]),
                      (2**31, *valid[1:]), (1.0, *valid[1:]), ('INERT_PRIVATE', *valid[1:])):
            proof._cost_observation = value
            self.assertIsNone(main.public_cost_diagnostic(proof, 'refused'))
        proof._cost_observation = valid
        self.assertIsNone(main.public_cost_diagnostic(proof, 'INERT_PRIVATE_STAGE'))

    def test_public_schema_avoids_properties_and_number_formatting_hooks(self):
        accessed = []
        class Private:
            @property
            def _cost_observation(self):
                accessed.append('cost')
                raise AssertionError('private')
            @property
            def __dict__(self):
                accessed.append('dict')
                raise AssertionError('private')
        class PrivateInt(int):
            def __str__(self):
                accessed.append('str')
                raise AssertionError('private')
            def __le__(self, _):
                accessed.append('compare')
                raise AssertionError('private')
        self.assertIsNone(main.public_cost_diagnostic(Private(), 'refused'))
        proof = SyntheticProof([])
        proof._cost_observation = (PrivateInt(1),) + (0,) * 15
        self.assertIsNone(main.public_cost_diagnostic(proof, 'refused'))
        self.assertEqual(accessed, [])

    def test_output_error_is_always_optional(self):
        proof = SyntheticProof([])
        proof._cost_observation = (0,) * 16
        class Unwritable(io.StringIO):
            def write(self, _): raise KeyboardInterrupt('INERT_OUTPUT')
        self.assertIsNone(main.emit_cost_diagnostic(proof, 'refused', Unwritable()))


if __name__ == '__main__':
    unittest.main()
