"""Inert bench safety fixtures; unit tests never call systemctl or enter a VM."""
import base64
import importlib.util
import os
from pathlib import Path
import re
import stat
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('lifecycle_probe_fixture', ROOT / 'scripts/probe-test-access-lifecycle.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def state(**changes):
    return {'ActiveState': 'inactive', 'SubState': 'dead', 'MainPID': '0', 'ControlPID': '0',
            'Job': '', 'LoadState': 'loaded', 'NRestarts': '0', **changes}


class LifecycleProbeTests(unittest.TestCase):
    def test_unique_templates_have_root_condition_nonroot_principals_and_unbounded_stop(self):
        work = Path('/var/tmp/inkyos-work/test-access-lifecycle.1234abcd')
        app = probe.unit_bytes('inkyos-lifecycle-probe-1234abcd', 'app', work, 65534, 65534).decode()
        helper = probe.unit_bytes('inkyos-lifecycle-probe-1234abcd', 'helper', work, 65534, 65534).decode()
        for unit in (app, helper):
            for setting in ('User=nobody\n', 'Restart=no\n', 'TimeoutStopSec=infinity\n',
                            'SendSIGKILL=no\n', 'KillMode=mixed\n', 'PrivateNetwork=yes\n', 'PrivateDevices=yes\n'):
                self.assertIn(setting, unit)
            for forbidden in ('inky-studio.service', 'inky-network.service', 'poweroff', '/dev/spi', 'test-access-drain.py'):
                self.assertNotIn(forbidden, unit)
            payload = re.search(r"b64decode\('([A-Za-z0-9+/=]+)'\)", unit)[1]
            self.assertEqual(base64.b64decode(payload), probe.PROGRAM.encode())
        self.assertIn('ExecCondition=+/usr/bin/python3 -I -c ', app)
        self.assertNotIn('ExecCondition=', helper)
        self.assertIn('Requires=inkyos-lifecycle-probe-1234abcd-helper.service\n', app)

    def test_names_paths_and_identity_arguments_cannot_target_an_existing_service(self):
        args = ['inkyos-lifecycle-probe-1234abcd', 'app', Path('/var/tmp/inkyos-work/test-access-lifecycle.1234abcd'), 65534, 65534]
        for index, value in ((0, 'inky-studio'), (0, 'prefix;poweroff'), (1, 'network'),
                             (2, Path('/run')), (3, 0), (3, True), (4, -1)):
            changed = list(args); changed[index] = value
            with self.assertRaises(ValueError): probe.unit_bytes(*changed)

    def test_property_parser_rejects_duplicate_unknown_missing_and_invalid_values(self):
        fields = ('MainPID', 'Job')
        self.assertEqual(probe.properties(b'MainPID=0\nJob=\n', fields), {'MainPID': '0', 'Job': ''})
        for raw in (b'MainPID=0\nJob=\nJob=1\n', b'MainPID=0\n', b'MainPID=0\nJob=\nPRIVATE=x\n', b'\xff'):
            with self.assertRaises((ValueError, UnicodeError)): probe.properties(raw, fields)

    def test_inactive_requires_no_pid_no_control_and_no_job(self):
        self.assertTrue(probe.inactive(state()))
        self.assertTrue(probe.inactive(state(Job='0')))
        for key, value in (('MainPID', '17'), ('ControlPID', '18'), ('Job', '23'),
                           ('Job', None), ('MainPID', 0), ('ActiveState', 'deactivating'), ('SubState', 'failed')):
            self.assertFalse(probe.inactive(state(**{key: value})))

    def test_private_outputs_are_exclusive_and_never_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'proof'
            probe.write_new(path, b'keep')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError): probe.write_new(path, b'replace')
            link = Path(temp) / 'link'; link.symlink_to(path)
            with self.assertRaises(FileExistsError): probe.write_new(link, b'replace')
            self.assertEqual(path.read_bytes(), b'keep')
            with self.assertRaises(OSError): probe.read(link, owner=os.geteuid(), group=os.getegid())

    def test_mask_refuses_active_process_or_pending_job_before_filesystem_mutation(self):
        value = probe.Probe(Path('/var/tmp/inkyos-work/test-access-lifecycle.1234abcd'), 65534, 65534)
        value.verified_owned = mock.Mock(side_effect=AssertionError('No filesystem mutation'))
        for observed in (state(MainPID='22'), state(Job='1'), state(ActiveState='deactivating')):
            value.state = lambda _role: observed
            with self.assertRaises(ValueError): value.mask('app')
        value.verified_owned.assert_not_called()

    def test_mask_preserves_inode_guard_and_never_force_masks(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'own.service'; path.write_bytes(b'fixture')
            value = probe.Probe(Path('/var/tmp/inkyos-work/test-access-lifecycle.1234abcd'), 65534, 65534)
            value.paths['app'] = path
            value.owned['app'] = probe.stamp(path.lstat())
            value.state = mock.Mock(side_effect=[state(), state(LoadState='masked')])
            value.verified_owned = mock.Mock()
            value.ctl = mock.Mock(return_value=types.SimpleNamespace(returncode=0))
            value.mask('app')
            value.verified_owned.assert_called_once_with('app')
            self.assertTrue(path.is_symlink())
            self.assertEqual(os.readlink(path), '/dev/null')
            value.ctl.assert_called_once_with('daemon-reload')

    def test_cleanup_never_touches_preexisting_paths_that_were_not_created(self):
        with tempfile.TemporaryDirectory() as temp:
            value = probe.Probe(Path('/var/tmp/inkyos-work/test-access-lifecycle.1234abcd'), 65534, 65534)
            for role in value.names:
                value.paths[role] = Path(temp) / (role + '.service')
                value.paths[role].write_bytes(b'PREEXISTING')
                value.runtime[role] = Path(temp) / (role + '-runtime')
                value.runtime[role].mkdir()
            value.ctl = mock.Mock(return_value=types.SimpleNamespace(returncode=0))
            value.state = mock.Mock(side_effect=AssertionError('No foreign unit inspection'))
            result = value.cleanup()
            self.assertTrue(all(result.values()))
            for role in value.names:
                self.assertEqual(value.paths[role].read_bytes(), b'PREEXISTING')
                self.assertTrue(value.runtime[role].is_dir())

    def test_cleanup_stops_before_commands_if_unit_identity_changed(self):
        value = probe.Probe(Path('/var/tmp/inkyos-work/test-access-lifecycle.1234abcd'), 65534, 65534)
        value.owned['app'] = ('SYNTHETIC',)
        value.verified_owned = mock.Mock(side_effect=ValueError('changed'))
        value.ctl = mock.Mock(side_effect=AssertionError('No command'))
        with self.assertRaises(ValueError): value.cleanup()
        value.ctl.assert_not_called()

    def test_command_allowlist_never_accepts_real_poweroff_or_nonfixture_unit(self):
        value = probe.Probe(Path('/var/tmp/inkyos-work/test-access-lifecycle.1234abcd'), 65534, 65534)
        with mock.patch.object(probe, 'command', side_effect=AssertionError('No subprocess')) as command:
            for operation, role in (('poweroff', None), ('kill', 'app'), ('mask', 'app'), ('stop', 'inky-studio')):
                with self.assertRaises(ValueError): value.ctl(operation, role)
            command.assert_not_called()

    def test_report_distinguishes_vm_mechanisms_from_production_and_hardware(self):
        value = probe.report_template()
        self.assertEqual(len(value['checks']), 28)
        for name in ('passed', 'live_systemd_evidence', 'production_runtime_executed', 'real_application_started',
                     'real_helper_started', 'real_poweroff_requested', 'hardware_qualified', 'release_qualified'):
            self.assertIs(value[name], False)
        compile(probe.PROGRAM, 'inert-fixture', 'exec')


if __name__ == '__main__':
    unittest.main()
