"""Inactive trigger composition, with no PID1, service, network or hardware.

Exercise the real closed-unit file checker and supervisor refusal CLI. The
small command adapter models only ordered oneshot exit propagation: it does not
claim that systemd parsed/executed this template or observed a native graph.
"""
import contextlib
import io
import shlex
import shutil
import subprocess
from unittest import mock

from test_factory_runtime_contract import ContractFixture, ROOT, runtime
from test_factory_supervisor import Runtime, Manager, supervisor


NAME = 'inkyos-factory-start.service'
READY = '/run/inkyos-admission/Ready'
FIRSTBOOT = 'inkyos-firstboot.service'
SUPERVISOR = 'inkyos-factory-supervisor.service'
MAIN = 'inky-studio.service'


def directives():
    section, result = None, {}
    for raw in (ROOT / 'staging/bootstrap' / NAME).read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]
        else:
            key, value = line.split('=', 1)
            result.setdefault((section, key), []).append(value)
    return result


class FactoryBootTriggerTests(ContractFixture):
    def setUp(self):
        super().setUp()
        self.values = directives()
        self.starts = []

    def dispatch(self, *, firstboot_exit=0, supervisor_exit=0, main_exit=0):
        # Requires+After is the only dependency propagation represented here.
        self.assertIn(FIRSTBOOT, self.values['Unit', 'Requires'][0].split())
        self.assertIn(FIRSTBOOT, self.values['Unit', 'After'][0].split())
        if firstboot_exit:
            return firstboot_exit
        for directive in ('ExecStartPre', 'ExecStart'):
            for raw in self.values['Service', directive]:
                argv = shlex.split(raw)
                if argv[0] == '/usr/bin/test':
                    self.assertEqual(argv[1], '!')
                    self.assertIn(argv[2], ('-e', '-L'))
                    self.assertEqual(argv[-1], READY)
                    # macOS stores the equivalent test tool under /bin, while
                    # the target usr-merged Linux profile must pin /usr/bin/test.
                    argv[0] = shutil.which('test')
                    self.assertIsNotNone(argv[0])
                    argv[-1] = str(self.root / READY[1:])
                    status = subprocess.run(argv, check=False).returncode
                else:
                    self.assertEqual(argv[:-1], ['/usr/bin/systemctl', '--no-ask-password', 'start'])
                    self.starts.append(argv[-1])
                    status = {SUPERVISOR: supervisor_exit, MAIN: main_exit}[argv[-1]]
                if status:
                    return status
        return 0

    def test_firstboot_failure_does_not_issue_any_factory_start(self):
        self.assertEqual(self.dispatch(firstboot_exit=1), 1)
        self.assertEqual(self.starts, [])

    def test_supervisor_failure_or_refusal_never_starts_main(self):
        for status in (1, 78, 255):
            with self.subTest(status=status):
                self.starts.clear()
                self.assertEqual(self.dispatch(supervisor_exit=status), status)
                self.assertEqual(self.starts, [SUPERVISOR])

    def test_success_starts_main_only_after_supervisor_and_propagates_main_failure(self):
        self.assertEqual(self.dispatch(), 0)
        self.assertEqual(self.starts, [SUPERVISOR, MAIN])
        self.starts.clear()
        self.assertEqual(self.dispatch(main_exit=1), 1)
        self.assertEqual(self.starts, [SUPERVISOR, MAIN])

    def test_existing_ready_including_dangling_symlink_is_a_refusal(self):
        path = self.write(READY[1:], b'not inspected by this veto\n')
        for kind in ('file', 'dangling_symlink'):
            with self.subTest(kind=kind):
                self.assertNotEqual(self.dispatch(), 0)
                self.assertEqual(self.starts, [])
            path.unlink()
            if kind == 'file':
                path.symlink_to('absent-ready-target')

    def test_template_keeps_existing_prepare_dependency_and_no_stop_propagation(self):
        self.assertEqual(self.values['Service', 'Type'], ['oneshot'])
        self.assertEqual(self.values['Service', 'Restart'], ['no'])
        self.assertNotIn(('Service', 'SuccessExitStatus'), self.values)
        self.assertNotIn(('Service', 'ExecCondition'), self.values)
        self.assertNotIn(('Unit', 'ConditionPathExists'), self.values)
        for key in ('PartOf', 'BindsTo', 'PropagatesStopTo', 'StopPropagatedFrom'):
            self.assertNotIn(('Unit', key), self.values)
        raw = (ROOT / 'staging/bootstrap' / (SUPERVISOR)).read_text()
        self.assertIn('Wants=inkyos-admission-prepare.service\n', raw)
        self.assertIn('After=local-fs.target inkyos-admission-prepare.service\n', raw)

    def test_distinct_trigger_enable_link_passes_real_closed_unit_checker(self):
        self.full_candidate()
        self.write(runtime.UNIT_VENDOR_DIR + '/' + NAME,
                   (ROOT / 'staging/bootstrap' / NAME).read_bytes())
        self.symlink('etc/systemd/system/multi-user.target.wants/' + NAME,
                     '/usr/lib/systemd/system/' + NAME)
        with self.contract().tree() as tree:
            runtime.check_unit_files(tree)
        # No relaxation: enabling any of the five pinned units is still refused.
        for name in runtime.UNIT_TEMPLATES:
            link = self.symlink('etc/systemd/system/multi-user.target.wants/' + name,
                                '/usr/lib/systemd/system/' + name)
            with self.subTest(unit=name), self.contract().tree() as tree:
                self.assert_refused(lambda: runtime.check_unit_files(tree), 'invalid_candidate')
            link.unlink()

    def test_real_supervisor_cli_already_ready_is_failure_not_success(self):
        # Use real admission and real run_factory, only replace the PID1/runtime
        # boundary. This closes the status mapping used by blocking start.
        events = []
        candidate, manager = Runtime(self.root, events), Manager(events)
        admission = candidate.import_admission(candidate.load_contract())
        admission.prepare(self.root)
        self.assertEqual(supervisor.run_factory(candidate, manager), {'status': 'factory_complete'})
        events.clear()
        output = io.StringIO()
        with mock.patch.object(supervisor, 'load_runtime', return_value=candidate), \
                mock.patch.object(supervisor, 'Manager', return_value=manager), \
                mock.patch.object(supervisor.signal, 'signal'), \
                contextlib.redirect_stdout(output):
            status = supervisor.main(['--run'])
        self.assertEqual(status, 78)
        self.assertIn('"error": "already_ready"', output.getvalue())
        self.assertFalse({'start', 'stop', 'output'} & set(events))
