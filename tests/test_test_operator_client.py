"""Private synthetic files and mocked ssh/keygen only; never connect or sign."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('test_operator_client_fixture', ROOT / 'scripts/test-operator-client.py')
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)


def key(byte):
    wire = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + byte * 32
    return 'ssh-ed25519 ' + base64.b64encode(wire).decode(), wire


PUBLIC, _ = key(b'o')
HOST_KEY, HOST_WIRE = key(b'h')
HOST = 'inky-' + 'a' * 32 + '.local'


def reply(operation, *, passed=True, error=None):
    value = {'schema_version': 1, 'kind': 'test-operator-result', 'operation': operation,
        'passed': passed, 'status': 'PASS' if passed else 'BLOCKED', 'error': error, 'live_evidence': True,
        'preflight': None, 'stop': None, 'activation': None, 'lifecycle_status': None,
        'activation_authorized': False, 'hardware_qualified': False, 'release_qualified': False,
        'limits': ['PRODUCER PRIVATE PROSE MUST NOT BE FORWARDED']}
    if passed:
        field, kind = {'preflight': ('preflight', 'test-lan-preflight'),
                      'activate': ('activation', 'test-access-activation-result'),
                      'stop': ('stop', 'test-access-drain-enqueue'),
                      'status': ('lifecycle_status', 'test-access-lifecycle-status')}[operation]
        value[field] = {'schema_version': 1, 'kind': kind, 'hardware_qualified': False, 'release_qualified': False}
    return value


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.context_dir = self.root / 'private context'
        self.context_dir.mkdir(mode=0o700)
        self.keys = self.root / 'operator'
        self.keys.mkdir(mode=0o700)
        self.identity = self.keys / 'identity'
        self.identity.write_bytes(b'INERT FIXTURE; NOT A PRIVATE KEY; PYTHON MUST NOT READ IT\n')
        self.identity.chmod(0o600)
        self.context = {'schema_version': 1, 'kind': 'verified-test-access-context', 'operator_public_key': PUBLIC,
            'bindings': {'profile_sha256': 'b' * 64, 'challenge': 'c' * 64,
                'host_public_key_sha256': hashlib.sha256(HOST_WIRE).hexdigest(),
                'application_source_commit': 'd' * 40, 'application_manifest_sha256': 'e' * 64,
                'access_runtime_manifest_sha256': 'f' * 64}}
        self.context_path = self.context_dir / 'context.json'
        self.known_path = self.context_dir / 'known_hosts'
        self.write_context()
        self.write_known(('[' + HOST + ']:2222 ' + HOST_KEY + '\n').encode())
        self.calls, self.after_keygen, self.after_ssh = [], None, None
        self.keygen_answer, self.ssh_code, self.ssh_reply = (0, (PUBLIC + ' fixture-comment\n').encode()), 0, None
        self.ssh_error = None

    def write_context(self):
        self.context_path.write_bytes(client.private.contract.canonical(self.context))
        self.context_path.chmod(0o600)

    def write_known(self, value):
        self.known_path.write_bytes(value)
        self.known_path.chmod(0o600)

    def invoke(self, argv, payload, **options):
        self.calls.append((argv, payload, options))
        if argv[0] == '/usr/bin/ssh-keygen':
            if self.after_keygen:
                self.after_keygen()
            return self.keygen_answer
        self.assertEqual(argv[0], '/usr/bin/ssh')
        if self.ssh_error:
            raise self.ssh_error
        if self.after_ssh:
            self.after_ssh()
        value = self.ssh_reply if self.ssh_reply is not None else reply(argv[-1], passed=self.ssh_code == 0)
        raw = value if type(value) is bytes else json.dumps(value).encode()
        return self.ssh_code, raw

    def run_client(self, operation='status', **options):
        return client.operate(self.context_dir, self.identity, operation, invoke=self.invoke,
                              wall_clock=lambda: 1791110000.75, **options)

    def assert_private_result(self, result):
        raw = json.dumps(result)
        for private in (str(self.root), HOST, PUBLIC, HOST_KEY, self.context['bindings']['challenge'],
                        'fixture-comment', 'PRODUCER PRIVATE', 'INERT FIXTURE', 'SENTINEL_SECRET'):
            self.assertNotIn(private, raw)
        self.assertFalse(result['hardware_qualified'])
        self.assertFalse(result['release_qualified'])
        self.assertFalse(result['remote_worker_cancelled'])
        self.assertFalse(result['context_provenance_verified'])

    def test_exact_identity_host_and_options_without_private_key_read(self):
        read = client.private.read_private
        def checked(path, **options):
            self.assertNotEqual(Path(path), self.identity)
            return read(path, **options)
        with mock.patch.object(client.private, 'read_private', side_effect=checked):
            code, result = self.run_client()
        self.assertEqual(code, 0, result)
        self.assertTrue(result['response_verified'])
        self.assertEqual(len(self.calls), 2)
        keygen, ssh = self.calls
        self.assertEqual(keygen[0], ('/usr/bin/ssh-keygen', '-y', '-f', str(self.identity)))
        self.assertIsNone(keygen[1])
        argv = ssh[0]
        self.assertEqual(argv[:9], ('/usr/bin/ssh', '-F', '/dev/null', '-p', '2222', '-l', 'inky-test', '-i', str(self.identity)))
        for option in ('BatchMode=yes', 'IdentitiesOnly=yes', 'IdentityAgent=none', 'StrictHostKeyChecking=yes',
                       'GlobalKnownHostsFile=/dev/null', 'ClearAllForwardings=yes', 'RequestTTY=no',
                       'ControlMaster=no', 'ControlPath=none', 'UpdateHostKeys=no',
                       'UserKnownHostsFile="' + str(self.known_path) + '"'):
            self.assertIn(option, argv)
        self.assertEqual(argv[-3:], ('--', HOST, 'status'))
        self.assertEqual(json.loads(ssh[1]), {'schema_version': 1})
        self.assertEqual(ssh[2]['limit'], 32768)
        self.assertLessEqual(ssh[2]['timeout'], 50)
        self.assert_private_result(result)

    def test_fresh_mac_utc_is_sampled_after_keygen_for_preflight_and_activate(self):
        for operation in ('preflight', 'activate'):
            with self.subTest(operation=operation):
                self.calls = []
                clocks = []
                def clock():
                    self.assertEqual(len(self.calls), 1)
                    clocks.append(True)
                    return 1791111234.9
                code, result = client.operate(self.context_dir, self.identity, operation, invoke=self.invoke,
                    wall_clock=clock, confirm_test_refresh=operation == 'activate')
                self.assertEqual(code, 0, result)
                query = json.loads(self.calls[-1][1])
                self.assertEqual(query['utc_reference'], 1791111234)
                self.assertEqual(query['utc_reference_age'], 0)
                self.assertEqual(query['utc_reference_source'], 'independent-device')
                self.assertEqual(query.get('confirm_test_refresh'), True if operation == 'activate' else None)
                self.assertEqual(clocks, [True])

    def test_confirmation_required_only_for_activate_and_commands_closed(self):
        for operation, confirm in (('activate', False), ('status', True), ('stop', True),
                                   ('reboot', False), ('status; cat /etc/shadow', False)):
            with self.subTest(operation=operation):
                code, result = self.run_client(operation, confirm_test_refresh=confirm)
                self.assertEqual(code, 1)
                self.assertEqual(result['error'], 'invalid_arguments')
                self.assertFalse(result['ssh_attempted'])
        self.assertEqual(self.calls, [])

    def test_keygen_mismatch_failure_or_excess_output_never_attempt_ssh(self):
        other, _wire = key(b'x')
        for answer in ((1, b'SENTINEL_SECRET'), (0, (other + '\n').encode()), (0, b'x' * 1025)):
            with self.subTest(answer_code=answer[0]):
                self.calls = []
                self.keygen_answer = answer
                code, result = self.run_client()
                self.assertEqual(code, 1)
                self.assertEqual(result['error'], 'identity_unverified')
                self.assertEqual(len(self.calls), 1)
                self.assert_private_result(result)

    def test_host_wire_must_match_context_and_line_is_closed(self):
        valid = ('[' + HOST + ']:2222 ' + HOST_KEY + '\n').encode()
        for raw in (valid + valid, valid.replace(b':2222', b':22'), valid.replace(b'inky-', b'host-'),
                    valid.rstrip(b'\n') + b' PRIVATE COMMENT\n', b'@cert-authority * ' + HOST_KEY.encode() + b'\n',
                    valid.replace(HOST_KEY.encode(), PUBLIC.encode())):
            with self.subTest(raw=raw[:20]):
                self.write_known(raw)
                code, result = self.run_client()
                self.assertEqual(code, 1)
                self.assertFalse(result['ssh_attempted'])
                self.assertEqual(self.calls, [])

    def test_permissions_symlinks_hardlinks_and_expansion_paths_are_refused(self):
        for path in (self.identity, self.context_path, self.known_path):
            with self.subTest(mode=path.name):
                path.chmod(0o644)
                code, result = self.run_client()
                self.assertEqual(code, 1)
                self.assertFalse(result['ssh_attempted'])
                path.chmod(0o600)
        link = self.keys / 'second-name'
        os.link(self.identity, link)
        code, result = self.run_client()
        self.assertEqual(code, 1)
        link.unlink()
        original = self.identity
        self.identity = self.keys / 'symlink'
        self.identity.symlink_to(original)
        code, result = self.run_client()
        self.assertEqual(code, 1)
        for name in ('percent%h', 'env${HOME}', 'line\nbreak', 'quote"name'):
            with self.assertRaises(client.ClientError):
                client.safe_path(self.keys / name)
        self.assertEqual(self.calls, [])

    def test_context_extension_duplicate_keys_or_noncanonical_bytes_refused(self):
        valid = self.context_path.read_bytes()
        cases = (valid.replace(b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1'),
                 json.dumps(dict(self.context, private='SENTINEL_SECRET')).encode(),
                 json.dumps(self.context).encode())
        for raw in cases:
            self.context_path.write_bytes(raw)
            code, result = self.run_client()
            self.assertEqual(code, 1)
            self.assertEqual(self.calls, [])
            self.assert_private_result(result)

    def test_changed_identity_before_ssh_is_refused_and_after_ssh_is_unconfirmed(self):
        self.after_keygen = lambda: self.identity.chmod(0o400)
        code, result = self.run_client()
        self.assertEqual(code, 1)
        self.assertFalse(result['ssh_attempted'])
        self.identity.chmod(0o600)
        self.after_keygen = None
        self.after_ssh = lambda: self.known_path.write_bytes(b'CHANGED')
        code, result = self.run_client()
        self.assertEqual(code, 1)
        self.assertEqual(result['status'], 'UNCONFIRMED')
        self.assertFalse(result['response_verified'])
        self.assert_private_result(result)

    def test_timeout_disconnect_excess_output_have_no_remote_cancellation_claim(self):
        for error, expected_code in ((client.ClientError('client_timeout_unconfirmed'), 124),
                                     (client.ClientError('output_excessive_unconfirmed'), 1),
                                     (OSError('SENTINEL_SECRET'), 1), (KeyboardInterrupt(), 1)):
            with self.subTest(error=type(error).__name__):
                self.ssh_error = error
                code, result = self.run_client('stop')
                self.assertEqual(code, expected_code)
                self.assertEqual(result['status'], 'UNCONFIRMED')
                self.assertFalse(result['response_verified'])
                self.assert_private_result(result)

    def test_remote_exit255_and_malformed_or_wrong_operation_response_are_unconfirmed(self):
        self.ssh_code = 255
        code, result = self.run_client()
        self.assertEqual((code, result['error']), (1, 'transport_unconfirmed'))
        self.ssh_code = 0
        for value in (b'SENTINEL_SECRET', b'x' * 32769, reply('activate'), dict(reply('status'), passed=False),
                      dict(reply('status'), hardware_qualified=True), dict(reply('status'), error='SENTINEL_SECRET')):
            self.ssh_reply = value
            code, result = self.run_client()
            self.assertEqual(code, 1)
            self.assertEqual(result['status'], 'UNCONFIRMED')
            self.assert_private_result(result)

    def test_remote_rejection_is_distinct_from_transport_failure(self):
        self.ssh_code = 1
        self.ssh_reply = reply('activate', passed=False, error='lifecycle_failed')
        self.ssh_reply['activation'] = {'schema_version': 1, 'kind': 'test-access-activation-result',
            'phase': 'failed', 'passed': False, 'request_accepted': True, 'error': 'activation_gate_failed',
            'hardware_qualified': False, 'release_qualified': False, 'private': 'SENTINEL_SECRET'}
        code, result = self.run_client('activate', confirm_test_refresh=True)
        self.assertEqual(code, 1)
        self.assertTrue(result['response_verified'])
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(result['remote']['activation']['error'], 'activation_gate_failed')
        self.assert_private_result(result)

    def test_preflight_only_forwards_named_boolean_checks(self):
        self.ssh_reply = reply('preflight')
        self.ssh_reply['preflight'] = {'kind': 'test-lan-preflight', 'passed': True, 'error': None,
            'checks': {name: {'passed': True, 'reason': 'SENTINEL_SECRET'} for name in client.PREFLIGHT_CHECKS}}
        code, result = self.run_client('preflight')
        self.assertEqual(code, 0, result)
        self.assertEqual(result['remote']['preflight']['checks'], dict.fromkeys(client.PREFLIGHT_CHECKS, True))
        self.assert_private_result(result)

    def test_failed_gate_assessment_preserves_all_named_booleans_and_closed_error(self):
        assessment = {'error': 'historical_blocked', **{
            field: {name: name != 'utc_synchronized' for name in names}
            for field, names in client.activation.ASSESSMENT_CHECKS.items()}}
        self.assertEqual(sum(len(rows) for name, rows in assessment.items() if name != 'error'), 47)
        failed = {'schema_version': 1, 'kind': 'test-access-activation-result', 'phase': 'failed',
            'passed': False, 'error': 'activation_gate_failed', 'assessment': assessment,
            'private': 'SENTINEL_SECRET'}
        for operation in ('activate', 'status'):
            with self.subTest(operation=operation):
                self.ssh_code = 1 if operation == 'activate' else 0
                self.ssh_reply = reply(operation, passed=operation == 'status',
                                       error='lifecycle_failed' if operation == 'activate' else None)
                if operation == 'activate':
                    self.ssh_reply['activation'] = failed
                else:
                    self.ssh_reply['lifecycle_status']['activation'] = failed
                code, result = self.run_client(operation, confirm_test_refresh=operation == 'activate')
                self.assertEqual(code, self.ssh_code, result)
                self.assertTrue(result['response_verified'])
                projected = result['remote']['activation'] if operation == 'activate' else (
                    result['remote']['lifecycle_status']['activation'])
                self.assertEqual(projected['assessment'], assessment)
                self.assertFalse(projected['assessment']['historical_checks']['utc_synchronized'])
                self.assert_private_result(result)

    def test_assessment_rejects_unknown_prose_errors_checks_or_nonboolean_values(self):
        valid = {'error': 'historical_blocked', **{
            field: dict.fromkeys(names, False) for field, names in client.activation.ASSESSMENT_CHECKS.items()}}
        cases = [dict(valid, private='SENTINEL_SECRET'), dict(valid, error='SENTINEL_SECRET')]
        for field, rows in valid.items():
            if field == 'error':
                continue
            name = next(iter(rows))
            cases.extend((dict(valid, **{field: dict(rows, **{name: 'SENTINEL_SECRET'})}),
                          dict(valid, **{field: dict(rows, unknown=False)}),
                          dict(valid, **{field: {key: value for key, value in rows.items() if key != name}})))
        for assessment in cases:
            with self.subTest(assessment_keys=set(assessment)):
                self.ssh_reply = reply('status')
                self.ssh_reply['lifecycle_status']['activation'] = {
                    'kind': 'test-access-activation-result', 'phase': 'failed',
                    'error': 'activation_gate_failed', 'assessment': assessment}
                code, result = self.run_client()
                self.assertEqual((code, result['error']), (1, 'remote_response_invalid'), result)
                self.assertFalse(result['response_verified'])
                self.assert_private_result(result)

    def test_total_budget_includes_keygen_and_no_utc_for_status_or_stop(self):
        ticks = iter((100.0, 101.0, 110.0))
        code, result = client.operate(self.context_dir, self.identity, 'stop', invoke=self.invoke,
            wall_clock=lambda: self.fail('stop never samples UTC'), monotonic=lambda: next(ticks))
        self.assertEqual(code, 0, result)
        self.assertEqual(self.calls[0][2]['timeout'], 10.0)
        self.assertEqual(self.calls[1][2]['timeout'], 40.0)

    def test_cli_help_and_invalid_arguments_never_invoke_ssh(self):
        # The only executable CLI probe permitted by this suite is --help.
        observed = subprocess.run([sys.executable, str(ROOT / 'scripts/test-operator-client.py'), '--help'],
                                  capture_output=True, timeout=5)
        self.assertEqual(observed.returncode, 0)
        self.assertIn(b'--confirm-test-refresh', observed.stdout)
        with (mock.patch.object(client, 'operate', side_effect=AssertionError('Must not connect')),
              mock.patch('builtins.print') as output):
            code = client.main(['--host', 'SENTINEL_SECRET'])
        self.assertEqual(code, 64)
        self.assertNotIn('SENTINEL', str(output.call_args))


class PipeTests(unittest.TestCase):
    """Popen and selectors are mocked; no keygen, SSH or other child is run."""
    def process(self):
        streams = []
        for descriptor in (10, 11):
            stream = mock.Mock()
            stream.fileno.return_value = descriptor
            streams.append(stream)
        process = mock.Mock(stdin=streams[0], stdout=streams[1])
        process.poll.return_value = 0
        process.wait.return_value = 0
        return process

    def selector(self):
        items = {}
        value = mock.Mock()
        value.register.side_effect = lambda stream, events: items.setdefault(stream.fileno(),
            (SimpleNamespace(fd=stream.fileno(), fileobj=stream), events))
        value.unregister.side_effect = lambda stream: items.pop(stream.fileno())
        value.get_map.side_effect = lambda: dict(items)
        value.select.side_effect = lambda _timeout: list(items.values())
        return value

    def test_json_is_delivered_then_eof_and_environment_has_no_agent_or_prompt(self):
        process, selector = self.process(), self.selector()
        with (mock.patch.object(client.subprocess, 'Popen', return_value=process) as popen,
              mock.patch.object(client.selectors, 'DefaultSelector', return_value=selector),
              mock.patch.object(client.os, 'set_blocking'),
              mock.patch.object(client.os, 'read', side_effect=[b'{"ok":true}', b'']),
              mock.patch.object(client.os, 'write', side_effect=lambda _fd, data: len(data)) as write):
            code, raw = client.bounded(('/usr/bin/ssh', 'FIXTURE_ONLY'), b'{"schema_version":1}\n', timeout=2, limit=32768)
        self.assertEqual((code, raw), (0, b'{"ok":true}'))
        self.assertEqual(write.call_args.args[1], b'{"schema_version":1}\n')
        self.assertTrue(process.stdin.close.called)
        options = popen.call_args.kwargs
        self.assertEqual(options['stderr'], subprocess.DEVNULL)
        self.assertTrue(options['start_new_session'])
        self.assertTrue(options['close_fds'])
        self.assertNotIn('SSH_AUTH_SOCK', options['env'])
        self.assertEqual(options['env']['SSH_ASKPASS_REQUIRE'], 'never')
        self.assertFalse(process.kill.called)

    def test_excess_output_stops_only_mock_local_child(self):
        process, selector = self.process(), self.selector()
        process.stdin = None
        process.poll.return_value = None
        with (mock.patch.object(client.subprocess, 'Popen', return_value=process),
              mock.patch.object(client.selectors, 'DefaultSelector', return_value=selector),
              mock.patch.object(client.os, 'set_blocking'),
              mock.patch.object(client.os, 'read', return_value=b'x' * 17)):
            with self.assertRaisesRegex(client.ClientError, '^output_excessive_unconfirmed$'):
                client.bounded(('/usr/bin/ssh-keygen', 'FIXTURE_ONLY'), None, timeout=2, limit=16)
        process.kill.assert_called_once()

    def test_timeout_stops_only_mock_local_child_without_output(self):
        process, selector = self.process(), self.selector()
        process.stdin = None
        process.poll.return_value = None
        with (mock.patch.object(client.subprocess, 'Popen', return_value=process),
              mock.patch.object(client.selectors, 'DefaultSelector', return_value=selector),
              mock.patch.object(client.os, 'set_blocking'),
              mock.patch.object(client.time, 'monotonic', side_effect=[100, 103]),
              mock.patch.object(client.os, 'read') as read):
            with self.assertRaisesRegex(client.ClientError, '^client_timeout_unconfirmed$'):
                client.bounded(('/usr/bin/ssh', 'FIXTURE_ONLY'), None, timeout=2, limit=32768)
        self.assertFalse(read.called)
        process.kill.assert_called_once()


if __name__ == '__main__':
    unittest.main()
