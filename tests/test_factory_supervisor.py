"""Real admission leases, inert runtime/PID1 adapters. Never starts a service."""
import configparser
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


supervisor = load('factory_supervisor_test', ROOT / 'scripts/factory-supervisor.py')
admission = load('factory_supervisor_admission_test', ROOT / 'staging/bootstrap/writer-admission.py')
CONTEXT = {'version': 1, 'boot_id': '12345678-1234-1234-1234-123456789abc',
           'candidate_sha256': 'a' * 64}


class Runtime:
    """No candidate or /run claim: the real contract module is tested separately."""
    def __init__(self, root, events):
        self.root, self.events = root, events
        self.context = copy.deepcopy(CONTEXT)
        self.checks = 0; self.fail_check = None; self.fail_context = False
        self.fail_import = False; self.change_context = False; self.validations = 0
        self.prepared = False

    def load_contract(self):
        self.events.append('contract')
        return types.SimpleNamespace(candidate_sha256='a' * 64, manifest={})

    def prepare_boot_context(self, contract):
        self.events.append('prepare-context')
        if self.prepared:
            raise supervisor.Refused('invalid_state')
        self.prepared = True
        return copy.deepcopy(self.context)

    def validate_context(self, contract):
        self.events.append('context'); self.validations += 1
        if self.fail_context:
            raise supervisor.Refused('invalid_state')
        result = copy.deepcopy(self.context)
        if self.change_context and self.validations > 1:
            result['candidate_sha256'] = 'b' * 64
        return result

    def verify_candidate(self, contract):
        self.events.append('pins'); self.checks += 1
        if self.checks == self.fail_check:
            raise supervisor.Refused('invalid_state')

    def import_admission(self, contract):
        self.events.append('admission-import')
        if self.fail_import:
            raise supervisor.Refused('invalid_state')
        uid, gid = os.geteuid(), os.getegid()
        return types.SimpleNamespace(
            factory=lambda root: admission.factory(self.root, _owner_uid=uid, _owner_gid=gid),
            prepare=lambda root: admission.prepare(self.root, _owner_uid=uid, _owner_gid=gid))


class Manager:
    """Simulated PID1/cgroups; never delegates to the production Manager."""
    def __init__(self, events):
        self.events = events; self.started = False; self.stopped = False
        self.start_count = self.stop_count = 0; self.descendants = 0
        self.start_error = False; self.stop_errors = 0; self.output_error = False
        self.preexisting = False; self.running = False; self.failed = False
        self.invalid_properties = False; self.exit_status = '0'; self.interrupt_start = None
        self.raw = b'{"status":"created","authority_status":"authorized"}\n'
        self.change_result = False

    def assert_group(self, unit):
        self.events.append('self-group')

    def inspect(self, unit):
        self.events.append('inspect')
        result = {**supervisor.EXPECTED, 'LoadState': 'loaded', 'ActiveState': 'active',
                  'SubState': 'exited', 'Result': 'success', 'ExecMainCode': '1',
                  'ExecMainStatus': self.exit_status, 'ControlGroup': '/system.slice/' + unit}
        if not self.started and not self.preexisting:
            result.update(LoadState='not-found', ActiveState='inactive', SubState='dead', ControlGroup='')
        elif self.stopped:
            result.update(ActiveState='inactive', SubState='dead', ControlGroup='')
        elif self.failed:
            result.update(ActiveState='failed', SubState='failed', Result='exit-code')
        elif self.running:
            result.update(SubState='running')
        if self.invalid_properties and self.started and not self.stopped:
            result['TasksMax'] = '3'
        return result

    def empty(self, unit):
        self.events.append('empty')
        if not self.started:
            return not self.preexisting
        if self.stopped:
            if self.descendants:
                self.descendants -= 1
                return False
            return True
        return False

    def create_output(self):
        self.events.append('output')
        if self.output_error:
            raise OSError('inert output fault')

    def start(self, unit, candidate_sha256):
        self.events.append('start'); self.started = True; self.start_count += 1
        if self.interrupt_start:
            self.interrupt_start()
        if self.start_error:
            raise OSError('inert lost start reply')

    def stop(self, unit):
        self.events.append('stop'); self.stop_count += 1
        if self.stop_errors:
            self.stop_errors -= 1
            raise OSError('inert lost stop reply')
        self.stopped = True

    def result(self):
        self.events.append('result')
        return self.raw + (b'changed' if self.change_result and self.stopped else b'')


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / 'run').mkdir(mode=0o755)
        (self.root / 'run').chmod(0o755)
        # macOS cannot inspect these fd xattrs through the Linux API. This
        # explicit substitute is absent on Linux, where actual xattrs are used.
        if sys.platform != 'linux':
            patch = mock.patch.object(admission.os, 'listxattr', return_value=[], create=True)
            patch.start(); self.addCleanup(patch.stop)
        self.events = []
        self.runtime = Runtime(self.root, self.events)
        self.manager = Manager(self.events)
        admission.prepare(self.root, _owner_uid=os.geteuid(), _owner_gid=os.getegid())
        self.elapsed = 0
        self.drain_observations = 0

    def clock(self):
        return self.elapsed

    def sleep(self, amount):
        self.elapsed += amount
        with self.assertRaises(admission.Refused) as caught:
            with admission.factory(self.root, _owner_uid=os.geteuid(), _owner_gid=os.getegid()):
                self.fail('EX lost while simulated worker was live')
        self.assertEqual(caught.exception.reason, 'busy')
        self.assertNotIn('Ready', self.names())
        self.drain_observations += 1

    def names(self):
        return {path.name for path in (self.root / 'run/inkyos-admission').iterdir()}

    def run_factory(self, **kwargs):
        return supervisor.run_factory(self.runtime, self.manager,
                                      _clock=self.clock, _sleep=self.sleep, **kwargs)

    def refused(self, reason=None, **kwargs):
        with self.assertRaises((supervisor.Refused, admission.Refused)) as caught:
            self.run_factory(**kwargs)
        if reason:
            self.assertEqual(caught.exception.reason, reason)
        self.assertNotIn('Ready', self.names())

    def test_success_orders_latch_pins_worker_drain_ready(self):
        original = self.runtime.verify_candidate
        def check(contract):
            self.assertIn('attempted', self.names())
            original(contract)
        self.runtime.verify_candidate = check
        self.assertEqual(self.run_factory(), {'status': 'factory_complete'})
        self.assertEqual(self.manager.start_count, 1)
        self.assertEqual(self.names(), {'lock', 'attempted', 'Ready'})
        self.assertLess(self.events.index('pins'), self.events.index('output'))
        self.assertLess(self.events.index('output'), self.events.index('start'))
        self.assertLess(self.events.index('start'), self.events.index('stop'))
        self.assertEqual(self.runtime.checks, 2)
        with admission.writer(self.root, _owner_uid=os.geteuid(), _owner_gid=os.getegid()):
            pass

    def test_consumed_existing_hook_success_is_admitted(self):
        # Simulates the hook's read-only consumed result after a fresh boot;
        # this does not exercise ledger recovery or an actual reboot.
        self.manager.raw = b'{"status":"existing","authority_status":"consumed"}\n'
        self.assertEqual(self.run_factory(), {'status': 'factory_complete'})
        self.assertEqual(self.manager.start_count, 1)

    def test_existing_authorized_success(self):
        self.manager.raw = b'{"status":"existing","authority_status":"authorized"}\n'
        self.assertEqual(self.run_factory(), {'status': 'factory_complete'})

    def test_already_ready_has_no_output_start_stop_or_pin_read(self):
        self.run_factory(); before = self.names(); self.events.clear()
        with self.assertRaises(admission.Refused) as caught:
            self.run_factory()
        self.assertEqual(caught.exception.reason, 'already_ready')
        self.assertEqual(self.names(), before)
        self.assertFalse({'pins', 'output', 'start', 'stop'} & set(self.events))

    def test_busy_preserves_ready_and_writer_without_side_effect(self):
        self.run_factory(); self.events.clear()
        with admission.writer(self.root, _owner_uid=os.geteuid(), _owner_gid=os.getegid()):
            with self.assertRaises(admission.Refused) as caught:
                self.run_factory()
            self.assertEqual(caught.exception.reason, 'busy')
            self.assertEqual(self.names(), {'lock', 'attempted', 'Ready'})
            self.assertFalse({'pins', 'output', 'start', 'stop'} & set(self.events))

    def test_attempted_is_never_retried(self):
        with admission.factory(self.root, _owner_uid=os.geteuid(), _owner_gid=os.getegid()):
            pass
        self.refused('recovery_required')
        self.assertEqual(self.manager.start_count, 0)
        self.assertEqual(self.manager.stop_count, 0)

    def test_context_failure_precedes_attempt(self):
        self.runtime.fail_context = True
        self.refused('invalid_state')
        self.assertEqual(self.names(), {'lock'})
        self.assertEqual(self.manager.stop_count, 0)

    def test_candidate_failure_consumes_attempt_but_does_not_launch_or_stop(self):
        self.runtime.fail_check = 1
        self.refused('invalid_state')
        self.assertEqual(self.names(), {'lock', 'attempted'})
        self.assertEqual(self.manager.start_count, 0)
        self.assertEqual(self.manager.stop_count, 0)

    def test_preexisting_worker_is_not_stopped(self):
        self.manager.preexisting = True
        self.refused('worker_preexisting')
        self.assertEqual(self.manager.stop_count, 0)
        self.assertNotIn('output', self.events)

    def test_output_failure_never_starts_or_stops_worker(self):
        self.manager.output_error = True
        with self.assertRaises(OSError):
            self.run_factory()
        self.assertEqual(self.names(), {'lock', 'attempted'})
        self.assertEqual(self.manager.stop_count, 0)

    def test_lost_start_reply_still_drains_without_retry(self):
        self.manager.start_error = True; self.manager.descendants = 3
        self.refused('execution_unconfirmed')
        self.assertEqual(self.manager.start_count, 1)
        self.assertGreaterEqual(self.drain_observations, 3)

    def test_lost_stop_reply_retains_ex_until_success_and_empty(self):
        self.manager.stop_errors = 2; self.manager.descendants = 3
        self.assertEqual(self.run_factory(), {'status': 'factory_complete'})
        self.assertGreaterEqual(self.drain_observations, 5)
        self.assertEqual(self.manager.start_count, 1)

    def test_descendant_survives_many_stop_polls_and_ex_is_held(self):
        self.manager.descendants = 12
        self.assertEqual(self.run_factory(), {'status': 'factory_complete'})
        self.assertEqual(self.drain_observations, 12)

    def test_timeout_is_failure_but_only_releases_after_descendant_drain(self):
        self.manager.running = True; self.manager.descendants = 3
        self.refused('worker_timeout')
        self.assertGreaterEqual(self.elapsed, 150)
        self.assertEqual(self.manager.start_count, 1)
        self.assertGreaterEqual(self.manager.stop_count, 4)

    def test_worker_failure_drains_and_never_publishes(self):
        self.manager.failed = True
        self.refused('worker_failed')
        self.assertTrue(self.manager.stopped)

    def test_nonzero_worker_exit_drains_and_refuses(self):
        self.manager.exit_status = '1'
        self.refused('worker_failed')

    def test_worker_property_failure_drains_and_refuses(self):
        self.manager.invalid_properties = True
        self.refused('worker_properties_invalid')

    def test_hook_refusal_never_publishes(self):
        self.manager.raw = b'{"status":"refused","error":"recovery_required"}\n'
        self.refused('worker_result_invalid')

    def test_output_changes_during_drain_refuses(self):
        self.manager.change_result = True
        self.refused('worker_result_invalid')

    def test_pins_change_after_worker_refuses(self):
        self.runtime.fail_check = 2
        self.refused('invalid_state')
        self.assertTrue(self.manager.stopped)

    def test_context_changes_after_worker_refuses(self):
        self.runtime.change_context = True
        self.refused('context_changed')

    def test_final_nonempty_observation_redrains_under_ex_and_refuses(self):
        original = self.runtime.verify_candidate
        def check(contract):
            original(contract)
            if self.runtime.checks == 2:
                self.manager.descendants = 3
        self.runtime.verify_candidate = check
        self.refused('cgroup_unavailable')
        self.assertGreaterEqual(self.drain_observations, 2)
        self.assertEqual(self.manager.start_count, 1)

    def test_failed_drain_observation_retains_ex_until_observation_recovers(self):
        original = self.manager.inspect
        faults = [2]
        def inspect(unit):
            if self.manager.stopped and faults[0]:
                faults[0] -= 1
                raise OSError('inert lost observation')
            return original(unit)
        self.manager.inspect = inspect
        self.assertEqual(self.run_factory(), {'status': 'factory_complete'})
        self.assertEqual(self.drain_observations, 2)

    def test_uncertain_ready_publication_is_not_replayed(self):
        original = admission.create
        def create(parent, name, raw, uid, gid):
            original(parent, name, raw, uid, gid)
            if name == 'Ready':
                raise OSError('inert lost publication reply')
        with mock.patch.object(admission, 'create', side_effect=create):
            with self.assertRaises(admission.Refused) as caught:
                self.run_factory()
        self.assertEqual(caught.exception.reason, 'publication_uncertain')
        self.assertEqual(self.names(), {'lock', 'attempted', 'Ready'})
        self.assertTrue(self.manager.stopped)
        self.events.clear()
        with self.assertRaises(admission.Refused) as caught:
            self.run_factory()
        self.assertEqual(caught.exception.reason, 'already_ready')
        self.assertFalse({'pins', 'output', 'start', 'stop'} & set(self.events))
        self.assertEqual(self.manager.start_count, 1)

    def test_signal_before_launch_leaves_attempt_without_worker(self):
        self.refused('interrupted', _stopped=lambda: True)
        self.assertEqual(self.names(), {'lock', 'attempted'})
        self.assertEqual(self.manager.start_count, 0)
        self.assertEqual(self.manager.stop_count, 0)

    def test_signal_during_worker_drains_then_refuses(self):
        halted = [False]
        self.manager.interrupt_start = lambda: halted.__setitem__(0, True)
        self.manager.descendants = 3
        self.refused('interrupted', _stopped=lambda: halted[0])
        self.assertGreaterEqual(self.drain_observations, 3)

    def test_signal_observed_during_final_quiescence_refuses_publication(self):
        halted = [False]; original = self.manager.inspect
        def inspect(unit):
            result = original(unit)
            if self.runtime.checks == 2:
                halted[0] = True
            return result
        self.manager.inspect = inspect
        self.refused('interrupted', _stopped=lambda: halted[0])
        self.assertEqual(self.manager.start_count, 1)
        self.assertTrue(self.manager.stopped)

    def test_prepare_partial_context_is_not_repaired(self):
        self.runtime.fail_import = True
        with self.assertRaises(supervisor.Refused):
            supervisor.prepare_boot(self.runtime, self.manager)
        self.assertTrue(self.runtime.prepared)
        self.assertEqual(self.names(), {'lock'})
        self.runtime.fail_import = False
        with self.assertRaises(supervisor.Refused):
            supervisor.prepare_boot(self.runtime, self.manager)
        self.assertEqual(self.events.count('prepare-context'), 2)
        self.assertEqual(self.names(), {'lock'})

    def test_worker_preflight_refuses_another_unit_before_candidate(self):
        with self.assertRaises(supervisor.Refused) as caught:
            supervisor.worker_preflight(self.runtime, self.manager, 'inky-studio.service', 'a' * 64)
        self.assertEqual(caught.exception.reason, 'wrong_cgroup')
        self.assertEqual(self.runtime.checks, 0)

    def test_worker_preflight_requires_parent_candidate_before_pins(self):
        with self.assertRaises(supervisor.Refused) as caught:
            supervisor.worker_preflight(self.runtime, self.manager,
                                        supervisor.worker_unit(CONTEXT), 'b' * 64)
        self.assertEqual(caught.exception.reason, 'candidate_changed')
        self.assertEqual(self.runtime.checks, 0)


class InterfaceTests(unittest.TestCase):
    def test_closed_hook_results_and_duplicate_extra_records(self):
        for value in supervisor.HOOK_RESULTS:
            self.assertEqual(supervisor.validate_hook(json.dumps(value).encode() + b'\n'), value)
        for raw in (b'{}\n', b'{"status":"created","status":"created","authority_status":"authorized"}\n',
                    b'{"status":"created","authority_status":"consumed"}\n',
                    b'{"status":"created","authority_status":"authorized","extra":1}\n',
                    b'[]\n', b'{"status":NaN}\n', b'{}\n{}\n', b'x' * 513, b'{}'):
            with self.subTest(raw=raw[:70]), self.assertRaises(supervisor.Refused):
                supervisor.validate_hook(raw)

    def test_cli_rejects_arbitrary_roots_workers_and_extra_arguments(self):
        for argv in (['--rootfs', '/tmp', '--run'], ['--worker-command', 'true', '--run'],
                     ['--run', '--prepare-boot'], ['--worker-preflight', 'unit'],
                     ['--worker-preflight', 'unit', 'hash', 'extra'], []):
            with mock.patch.object(supervisor, 'load_runtime') as loader, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    supervisor.main(argv)
                self.assertEqual(caught.exception.code, 2)
                loader.assert_not_called()

    def test_worker_command_is_fixed_and_contains_no_directory_lifecycle(self):
        manager = supervisor.Manager(); commands = []
        manager.command = lambda argv: commands.append(argv)
        unit = supervisor.worker_unit(CONTEXT)
        manager.start(unit, 'a' * 64)
        argv = commands[0]
        self.assertEqual(argv[-5:], ['/usr/bin/python3.13', '-I', '-B', '-S', supervisor.HOOK])
        self.assertIn('--property=TasksMax=2', argv)
        self.assertIn('--property=KillMode=control-group', argv)
        self.assertIn('--property=Restart=no', argv)
        self.assertIn('--property=Delegate=no', argv)
        self.assertIn('--property=ExecStartPre=/usr/bin/python3.13 -I -B -S ' +
                      supervisor.SUPERVISOR + ' --worker-preflight ' + unit + ' ' + 'a' * 64, argv)
        self.assertFalse(any('RuntimeDirectory=' in arg or 'StateDirectory=' in arg
                             or arg.startswith('--property=User=') for arg in argv))

    def test_templates_have_no_install_or_runtime_directory_or_stop_propagation(self):
        for name in (supervisor.PREPARE_UNIT, supervisor.SUPERVISOR_UNIT):
            config = configparser.ConfigParser(interpolation=None)
            config.read(ROOT / 'staging/bootstrap' / name)
            self.assertNotIn('Install', config)
            self.assertEqual(config['Service']['Restart'], 'no')
            self.assertEqual(config['Service']['SendSIGKILL'], 'no')
            self.assertEqual(config['Service']['TimeoutStopSec'], 'infinity')
            for key in ('RuntimeDirectory', 'StateDirectory', 'ExecStop', 'ExecStopPost'):
                self.assertNotIn(key, config['Service'])
            for key in ('Requires', 'Requisite', 'BindsTo', 'PartOf'):
                self.assertNotIn(key, config['Unit'])

    def test_worker_name_is_derived_only_from_boot(self):
        changed = dict(CONTEXT, candidate_sha256='b' * 64)
        self.assertEqual(supervisor.worker_unit(CONTEXT), supervisor.worker_unit(changed))
        changed['boot_id'] = '12345678-1234-1234-1234-123456789abd'
        self.assertNotEqual(supervisor.worker_unit(CONTEXT), supervisor.worker_unit(changed))


if __name__ == '__main__':
    unittest.main()
