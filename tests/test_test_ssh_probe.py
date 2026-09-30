"""Inert probe-fixture contract tests; no keys, SSH daemon, chroot or namespace."""
import ast
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import types
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/probe-test-ssh-linux.sh'
source = SCRIPT.read_text()
embedded = source.split("<<'PY_PROBE'\n", 1)[1].rsplit('\nPY_PROBE', 1)[0]
probe = {'__name__': 'inert_probe_contract'}
exec(compile(embedded, str(SCRIPT) + ':PY_PROBE', 'exec'), probe)
mac_source = (SCRIPT.parent / 'probe-test-ssh.sh').read_text()
receipt_source = mac_source.split("<<'PY_RECEIPT'\n", 1)[1].rsplit('\nPY_RECEIPT', 1)[0]
receipt_ast = ast.parse(receipt_source)
receipt_function = next(node for node in receipt_ast.body if isinstance(node, ast.FunctionDef) and node.name == 'validate_report')
receipt = {}
exec(compile(ast.Module(body=[receipt_function], type_ignores=[]), '<transport-receipt>', 'exec'), receipt)


def fixture(name):
    namespace = {'__name__': 'inert_' + name.lower()}
    exec(compile(probe[name], '<' + name + '>', 'exec'), namespace)
    return namespace


class TestSshProbeTests(unittest.TestCase):
    def test_transport_diagnostics_export_only_closed_reasons(self):
        for raw, expected in (
                (b'', 'none'),
                (b'PRIVATE_HOST: Permission denied (publickey). PRIVATE_KEY', 'authentication_refused'),
                (b'PRIVATE_PATH: Permission denied', 'permission_denied'),
                (b'PRIVATE_KEY PRIVATE_FINGERPRINT PRIVATE_RAW_LOG', 'other_diagnostic')):
            self.assertEqual(probe['transport_reason'](raw), expected)
            self.assertNotIn('PRIVATE', probe['transport_reason'](raw))

    def test_tunnel_refusal_requires_local_open_and_exact_remote_policy_failure(self):
        lines = [b'debug1: Tunnel forwarding using interface tun0',
                 b'debug1: Remote: Server has rejected tunnel device forwarding',
                 b'channel 0: open failed: connect failed: open failed',
                 b'Tunnel forwarding failed']
        raw = b'\r\n'.join(lines) + b'\r\nPRIVATE_FINGERPRINT\r\n'
        result = types.SimpleNamespace(returncode=255, stderr=raw)
        passed, facts = probe['tunnel_observation'](result, {'lo'})
        self.assertTrue(passed)
        self.assertNotIn('PRIVATE', json.dumps(facts))
        for removed in lines:
            result.stderr = raw.replace(removed, b'')
            self.assertFalse(probe['tunnel_observation'](result, {'lo'})[0])
        for invalid in (b'Tunnel device open failed.\n',
                        b'channel 0: open failed: administratively prohibited: open failed\n',
                        raw + b'Tunnel device open failed.\n'):
            result.stderr = invalid
            self.assertFalse(probe['tunnel_observation'](result, {'lo'})[0])
        result.stderr = raw
        self.assertFalse(probe['tunnel_observation'](result, {'lo', 'tun0'})[0])
        for status in (0, 1):
            result.returncode = status
            self.assertFalse(probe['tunnel_observation'](result, {'lo'})[0])

    def transport_receipt(self):
        inputs = {'files': {'probe-test-ssh-linux.sh': 'source', 'parent-manifest.json': 'manifest',
                            'parent-filesystem-manifest.json': 'inventory'},
                  'parent_image': {'sha256': 'image'},
                  'parent_application': {'source_commit': 'application', 'manifest_sha256': 'application-manifest'},
                  'expected_checks': list(probe['CHECKS'])}
        report = {'schema_version': 1, 'scope': 'linux-test-ssh-pam-transport-probe',
                  'source_sha256': 'source', 'activation_stub_only': True, 'application_activated': False,
                  'hardware_qualified': False, 'release_qualified': False,
                  'parent': {'manifest_sha256': 'manifest', 'image_sha256': 'image',
                             'filesystem_manifest_sha256': 'inventory', 'application_source_commit': 'application',
                             'application_manifest_sha256': 'application-manifest'},
                  'checks': dict.fromkeys(probe['CHECKS'], True), 'failed_checks': [], 'error_stage': None, 'passed': True}
        return report, inputs

    def test_mac_receipt_does_not_pass_after_nonzero_exit(self):
        report, inputs = self.transport_receipt()
        self.assertTrue(receipt['validate_report'](report, inputs, 0))
        for status in (1, 124, 137):
            self.assertFalse(receipt['validate_report'](report, inputs, status))

    def test_mac_receipt_rejects_unbound_parent_or_inconsistent_checks(self):
        report, inputs = self.transport_receipt()
        changes = [('scope', 'another-probe'), ('schema_version', True), ('source_sha256', 'changed'),
                   ('passed', False), ('failed_checks', ['loop_detached']), ('activation_stub_only', False)]
        for field, value in changes:
            altered = copy.deepcopy(report); altered[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                receipt['validate_report'](altered, inputs, 0)
        for field in report['parent']:
            altered = copy.deepcopy(report); altered['parent'][field] = 'changed'
            with self.subTest(parent=field), self.assertRaises(ValueError):
                receipt['validate_report'](altered, inputs, 0)
        for value in (1, False):
            altered = copy.deepcopy(report); altered['checks']['loop_detached'] = value
            with self.subTest(check=value), self.assertRaises(ValueError):
                receipt['validate_report'](altered, inputs, 0)
        altered = copy.deepcopy(report); del altered['checks']['loop_detached']
        with self.assertRaises(ValueError):
            receipt['validate_report'](altered, inputs, 0)

    def test_mac_receipt_preserves_coherent_failure(self):
        report, inputs = self.transport_receipt()
        report['checks']['loop_detached'] = False
        report.update(passed=False, failed_checks=['loop_detached'], error_stage='cleanup_failed')
        self.assertFalse(receipt['validate_report'](report, inputs, 1))

    def test_help_is_unprivileged_and_documents_disposable_input(self):
        result = subprocess.run(['bash', str(SCRIPT), '--help'], capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn(b'parent-manifest.sha256', result.stdout)
        self.assertIn(b'Consumes only the disposable image copy', result.stdout)

    def test_sshd_configuration_is_closed_and_cannot_include_operator_config(self):
        raw = probe['configuration'](22222)
        rows = [line.split(None, 1) for line in raw.splitlines()]
        values = dict(rows)
        self.assertEqual(len(rows), len(values))
        for key in ('Include', 'Match', 'AcceptEnv', 'AuthorizedKeysCommand', 'AuthorizedPrincipalsCommand'):
            self.assertNotIn(key, values)
        for key in ('PasswordAuthentication', 'KbdInteractiveAuthentication', 'PermitRootLogin', 'PermitTTY',
                    'PermitTunnel', 'PermitUserRC', 'PermitUserEnvironment', 'AllowTcpForwarding',
                    'AllowStreamLocalForwarding', 'AllowAgentForwarding', 'X11Forwarding'):
            self.assertEqual(values[key], 'no', key)
        self.assertEqual(values['DisableForwarding'], 'yes')
        self.assertEqual(values['AuthenticationMethods'], 'publickey')
        self.assertEqual(values['UsePAM'], 'yes')
        self.assertEqual(values['AllowUsers'], 'inky-test')
        self.assertEqual(values['ListenAddress'], '127.0.0.1')
        self.assertEqual(values['ForceCommand'], probe['DISPATCH_PATH'])
        for invalid in (True, 22, 65536, '22222\nPermitRootLogin yes'):
            with self.subTest(port=invalid), self.assertRaises(ValueError):
                probe['configuration'](invalid)

    def test_dispatcher_accepts_only_three_exact_original_commands(self):
        dispatcher = fixture('DISPATCHER')
        for value in ('preflight', 'activate', 'stop'):
            self.assertEqual(dispatcher['operation'](value), value)
        for value in ('', ' preflight', 'preflight ', 'preflight extra', 'activate; id', 'preflight\nstop',
                      '$(id)', 'internal-sftp', 'scp -t /tmp/file', '/bin/sh', 'sudo -l'):
            with self.subTest(command=value), self.assertRaises(ValueError):
                dispatcher['operation'](value)

    def test_dispatcher_request_rejects_duplicates_extensions_and_oversize(self):
        dispatcher = fixture('DISPATCHER')
        self.assertEqual(dispatcher['request'](b'{"schema_version":1}\n'), {'schema_version': 1})
        for raw in (b'', b'[]', b'null', b'{}', b'{"schema_version":true}',
                    b'{"schema_version":1,"operation":"activate"}', b'{"schema_version":1,"schema_version":1}',
                    b'{"schema_version":1}' + b' ' * 4096, b'\xff'):
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                dispatcher['request'](raw)

    def test_receive_requires_eof_and_has_a_monotonic_deadline(self):
        dispatcher = fixture('DISPATCHER')
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b'{"schema_version":1}')
            os.close(write_fd); write_fd = None
            self.assertEqual(dispatcher['receive'](read_fd), {'schema_version': 1})
        finally:
            os.close(read_fd)
            if write_fd is not None:
                os.close(write_fd)
        read_fd, write_fd = os.pipe()
        try:
            with patch.object(dispatcher['time'], 'monotonic', side_effect=(0, 6)), self.assertRaisesRegex(ValueError, 'timeout'):
                dispatcher['receive'](read_fd)
        finally:
            os.close(read_fd); os.close(write_fd)

    def test_dispatcher_invokes_only_zero_argument_sudo_runner(self):
        dispatcher = fixture('DISPATCHER')
        stdout = types.SimpleNamespace(buffer=io.BytesIO())
        with patch.dict(dispatcher['os'].environ, {'SSH_ORIGINAL_COMMAND': 'activate'}, clear=True), \
             patch.dict(dispatcher, {'receive': lambda _fd: {'schema_version': 1}}), \
             patch.object(dispatcher['sys'], 'stdout', stdout), \
             patch.object(dispatcher['subprocess'], 'run', return_value=types.SimpleNamespace(returncode=0, stdout=b'stub')) as run:
            self.assertEqual(dispatcher['main'](), 0)
            self.assertEqual(run.call_args.args[0], ['/usr/bin/sudo', '-n', '--', probe['RUNNER_PATH']])
            envelope = json.loads(run.call_args.kwargs['input'])
            self.assertEqual(envelope, {'schema_version': 1, 'operation': 'activate', 'request': {'schema_version': 1}})
            self.assertNotIn('shell', run.call_args.kwargs)
            self.assertEqual(run.call_args.kwargs['timeout'], 5)
        with patch.dict(dispatcher['os'].environ, {'SSH_ORIGINAL_COMMAND': 'activate; id'}, clear=True), \
             patch.object(dispatcher['subprocess'], 'run', side_effect=AssertionError('must not execute')):
            self.assertEqual(dispatcher['main'](), 64)

    def test_runner_schema_is_inert_closed_and_rejects_extra_argv(self):
        runner = fixture('RUNNER')
        for verb in ('preflight', 'activate', 'stop'):
            raw = json.dumps({'schema_version': 1, 'operation': verb, 'request': {'schema_version': 1}}).encode()
            self.assertEqual(runner['validate'](raw), verb)
        for raw in (b'{}', b'[]', b'{"schema_version":1,"operation":"activate","request":{},"command":"id"}',
                    b'{"schema_version":1,"operation":"stop","operation":"activate","request":{"schema_version":1}}',
                    b'x' * 4097):
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                runner['validate'](raw)
        with patch.object(runner['sys'], 'argv', ['runner', 'extra']), \
             patch.object(runner['os'], 'open', side_effect=AssertionError('must not access state')):
            self.assertEqual(runner['main'](), 64)
        self.assertEqual(probe['SUDOERS'], 'inky-test ALL=(root) NOPASSWD: ' + probe['RUNNER_PATH'] + ' ""\n')


if __name__ == '__main__':
    unittest.main()
