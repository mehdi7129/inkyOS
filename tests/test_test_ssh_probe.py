"""Inert probe-fixture contract tests; no keys, SSH daemon, chroot or namespace."""
import ast
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import Mock, patch


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
operator = {'__name__': 'inert_operator_probe'}
exec(compile((SCRIPT.parent/'probe-test-operator-runtime.py').read_bytes(), '<operator-probe>', 'exec'), operator)


def fixture(name):
    namespace = {'__name__': 'inert_' + name.lower()}
    exec(compile(probe[name], '<' + name + '>', 'exec'), namespace)
    return namespace


class TestSshProbeTests(unittest.TestCase):
    def access_sources(self):
        return {name: (SCRIPT.parent / name).read_bytes() for name in operator['ACCESS_FILES'].values()}

    def test_access_mode_selects_only_exact_c31_application_parent_without_changing_legacy(self):
        def parent(source, manifest):
            return {'schema_version': 1, 'kind': 'application-prototype', 'hardware_qualified': False,
                    'application': {'source_commit': source, 'manifest_sha256': manifest,
                        'application_version': '0.5.0-rc.2', 'startup': 'masked-pending-firstboot-contract',
                        'release_qualified': False}, 'image': {'sha256': probe['ACCESS_IMAGE']}}
        legacy = parent(probe['EXACT_SOURCE'], probe['EXACT_MANIFEST'])
        access = parent(probe['ACCESS_SOURCE'], probe['ACCESS_MANIFEST'])
        self.assertEqual(probe['parent_candidate'](legacy), (probe['EXACT_SOURCE'], probe['EXACT_MANIFEST']))
        self.assertEqual(probe['parent_candidate'](access, access_runtime=True),
                         (probe['ACCESS_SOURCE'], probe['ACCESS_MANIFEST']))
        for value, mode in ((access, False), (legacy, True), (access, 1)):
            with self.assertRaises(ValueError): probe['parent_candidate'](value, access_runtime=mode)
        for section, field, value in (('image', 'sha256', 'e' * 64),
                                      ('application', 'manifest_sha256', probe['EXACT_MANIFEST']),
                                      ('application', 'release_qualified', True)):
            bad = copy.deepcopy(access); bad[section][field] = value
            with self.assertRaises(ValueError): probe['parent_candidate'](bad, access_runtime=True)
        self.assertEqual(probe['ACCESS_IMAGE'], '8b951d84bf6925e531d643bd3c785283f37bb847372ab9265356cbf3b12a7727')
        self.assertEqual(len(probe['CHECKS']), 39)
        self.assertEqual(len(operator['CHECKS']), 22)
        self.assertEqual(len(operator['ACCESS_CHECKS']), 3)

    def test_access_fixture_is_bound_to_real_sources_and_accepted_by_production_runner(self):
        # Reuse the safe file-reader fixture, never authenticate as host root or
        # invoke any service. Its NativeAdapter subclass cannot claim live proof.
        import importlib.util
        path = SCRIPT.parent.parent / 'tests/test_test_operator_runtime.py'
        spec = importlib.util.spec_from_file_location('ssh_probe_native_binding_fixture', path)
        seed = importlib.util.module_from_spec(spec); spec.loader.exec_module(seed)
        installed = seed.NativeBindingTests()
        installed.setUp()
        self.addCleanup(installed.tearDown)
        public = json.loads(installed.raw[seed.runner.PROFILE])['operator_public_key']
        sources = self.access_sources()
        value, manifest_raw = operator['access_fixture'](sources, public)
        manifest = json.loads(manifest_raw)
        self.assertEqual(value['schema_version'], 2)
        self.assertEqual(value['application_source_commit'], probe['ACCESS_SOURCE'])
        self.assertEqual(value['access_runtime_manifest_sha256'], hashlib.sha256(manifest_raw).hexdigest())
        self.assertEqual(set(manifest['files']), {name[1:] for name in operator['ACCESS_FILES']})
        for name, source_name in operator['ACCESS_FILES'].items():
            self.assertEqual(manifest['files'][name[1:]], {'sha256': hashlib.sha256(sources[source_name]).hexdigest(), 'mode': '0555'})
        installed.install_v2(manifest, profile_changes=value)
        before = {path: (installed.root / path.lstrip('/')).read_bytes() for path in installed.raw}
        self.assertTrue(installed.adapter.bind())
        self.assertTrue(installed.adapter.unchanged())
        self.assertEqual(json.loads(installed.raw[seed.runner.STATE])['schema_version'], 1)
        self.assertEqual(before, {path: (installed.root / path.lstrip('/')).read_bytes() for path in installed.raw})
        for path, raw, mode in ((seed.runner.ACCESS_POLICY, sources['test-access-policy.py'], 0o555),
                                (seed.runner.ACCESS_MANIFEST, manifest_raw, 0o644)):
            installed.put(path, raw + b'\n', mode)
            with self.assertRaises(seed.runner.Refused): installed.adapter.bind()
            installed.put(path, raw, mode)
        self.assertTrue(installed.adapter.bind())

    def test_changed_access_policy_is_refused_before_exec_or_fixture_install(self):
        sources = self.access_sources(); sources['test-access-policy.py'] += b'\n'
        with patch('builtins.exec') as execute:
            with self.assertRaisesRegex(ValueError, '^access_policy_source_changed$'):
                operator['access_fixture'](sources, 'unused fixture public key')
            execute.assert_not_called()
        sources['test-access-contract.py'] = (SCRIPT.parent / 'test-access-contract.py').read_bytes()
        create, target, ssh = Mock(), Mock(), Mock()
        result = operator['probe'](Path('/unused'), create, target, ssh, sources, [], access_runtime=True)
        self.assertFalse(result['passed'])
        self.assertEqual(result['error_stage'], 'install_sources')
        self.assertEqual(set(result['checks']), set(operator['CHECKS']) | set(operator['ACCESS_CHECKS']))
        self.assertIs(result['enrollment_fixture_only'], True)
        self.assertIs(result['physical_identity_verified'], False)
        create.assert_not_called(); target.assert_not_called(); ssh.assert_not_called()

    def test_access_receipt_cannot_downgrade_to_legacy_or_claim_physical_enrollment(self):
        report, inputs = self.operator_receipt()
        inputs['access_runtime'] = True
        inputs['expected_operator_checks'] += list(operator['ACCESS_CHECKS'])
        report['access_runtime'] = True
        report['operator_runtime'].update(access_runtime=True, profile_schema_version=2,
                                         enrollment_fixture_only=True, physical_identity_verified=False)
        report['operator_runtime']['checks'].update(dict.fromkeys(operator['ACCESS_CHECKS'], True))
        self.assertTrue(receipt['validate_report'](report, inputs, 0))
        for field, value in (('access_runtime', False), ('profile_schema_version', 1),
                             ('enrollment_fixture_only', False), ('physical_identity_verified', True)):
            bad = copy.deepcopy(report); bad['operator_runtime'][field] = value
            with self.assertRaises(ValueError): receipt['validate_report'](bad, inputs, 0)
        for field in ('access_runtime', 'operator_runtime'):
            bad = copy.deepcopy(report); del bad[field]
            with self.assertRaises(ValueError): receipt['validate_report'](bad, inputs, 0)
        for field in operator['ACCESS_CHECKS']:
            bad = copy.deepcopy(report); del bad['operator_runtime']['checks'][field]
            with self.assertRaises(ValueError): receipt['validate_report'](bad, inputs, 0)
        old_inputs = copy.deepcopy(inputs); del old_inputs['access_runtime']
        with self.assertRaises(ValueError): receipt['validate_report'](report, old_inputs, 0)

    def test_access_cli_is_explicit_and_help_stays_inert(self):
        mac = SCRIPT.parent / 'probe-test-ssh.sh'
        help_result = subprocess.run(['bash', str(mac), '--help'], capture_output=True)
        self.assertEqual(help_result.returncode, 0)
        self.assertIn(b'--access-runtime', help_result.stdout)
        for args in (['--access-runtime'], ['--access-runtime', '--operator-runtime', '/unused']):
            result = subprocess.run(['bash', str(mac), *args], capture_output=True)
            self.assertEqual(result.returncode, 2)
        self.assertEqual(probe['ACCESS_INPUTS'], {'test-access-policy.py'})
        self.assertEqual(probe['ACCESS_TMPFS'], ('etc/inkyos-test-enrollment', 'var/lib/inkyos-test-enrollment', 'var/lib/inkyos'))

    def test_access_capsule_signs_the_selected_fixture_bindings(self):
        wire = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + bytes(range(32))
        public = 'ssh-ed25519 ' + base64.b64encode(wire).decode()
        profile, manifest_raw = operator['access_fixture'](self.access_sources(), public)
        expected = {'profile_sha256': operator['sha'](operator['canonical'](profile)),
            'challenge': profile['challenge'], 'host_public_key_sha256': operator['sha'](wire),
            'application_source_commit': profile['application_source_commit'],
            'application_manifest_sha256': profile['application_manifest_sha256'],
            'access_runtime_manifest_sha256': operator['sha'](manifest_raw)}
        calls = []
        def target(argv, *, data, timeout):
            calls.append((argv, data, timeout))
            if len(calls) < 3:
                capsule = json.loads(data)
                self.assertEqual(capsule['nonce'], expected['challenge'])
                for key, value in expected.items():
                    if key != 'challenge': self.assertEqual(capsule[key], value)
                return types.SimpleNamespace(returncode=0, stdout=b'synthetic-signature')
            payload = json.loads(data)
            self.assertEqual(payload['expected'], expected)
            self.assertEqual(base64.b64decode(payload['raw']), calls[0][1])
            self.assertEqual(calls[0][1], calls[1][1])
            return types.SimpleNamespace(returncode=0, stdout=json.dumps(dict.fromkeys(operator['CAPSULE_CHECKS'], True)).encode())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / (operator['RUNTIME'] + '/good.pub').lstrip('/')
            path.parent.mkdir(parents=True); path.write_text(public + '\n')
            result = operator['capsule_checks'](root, target, expected=expected)
        self.assertEqual(result, dict.fromkeys(operator['CAPSULE_CHECKS'], True))
        self.assertEqual(len(calls), 3)

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

    def operator_receipt(self):
        report, inputs = self.transport_receipt()
        inputs['operator_sources'] = {'runner.py': 'pinned-runner', 'test-access-contract.py': operator['CONTRACT_SHA256']}
        inputs['expected_operator_checks'] = list(operator['CHECKS'])
        report['operator_runtime'] = {
            'scope': 'isolated-test-operator-runtime-probe',
            'source_sha256': dict(inputs['operator_sources']),
            'application_activated': False, 'stop_mutations_fixture_only': True,
            'hardware_qualified': False, 'release_qualified': False,
            'checks': dict.fromkeys(inputs['expected_operator_checks'], True),
            'passed': True, 'error_stage': None,
        }
        return report, inputs

    def test_operator_receipt_binds_executed_sources_and_every_check(self):
        report, inputs = self.operator_receipt()
        self.assertTrue(receipt['validate_report'](report, inputs, 0))
        self.assertFalse(receipt['validate_report'](report, inputs, 124))
        for field, value in (('source_sha256', {'runner.py': 'other'}), ('checks', {}),
                             ('stop_mutations_fixture_only', False), ('application_activated', True),
                             ('passed', 1), ('hardware_qualified', True)):
            changed = copy.deepcopy(report)
            changed['operator_runtime'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                receipt['validate_report'](changed, inputs, 0)
        changed = copy.deepcopy(report)
        changed['operator_runtime']['checks']['activation_explicitly_refused'] = 1
        with self.assertRaises(ValueError):
            receipt['validate_report'](changed, inputs, 0)

    def test_operator_receipt_preserves_early_failure_but_rejects_missing_success(self):
        report, inputs = self.operator_receipt()
        del report['operator_runtime']
        with self.assertRaises(ValueError):
            receipt['validate_report'](report, inputs, 0)
        report.update(passed=False, error_stage='parent_validation')
        self.assertFalse(receipt['validate_report'](report, inputs, 1))
        report, inputs = self.operator_receipt()
        report['operator_runtime']['checks']['activation_explicitly_refused'] = False
        report['operator_runtime'].update(passed=False, error_stage='operator_runtime')
        report.update(passed=False, error_stage='operator_runtime_extension')
        self.assertFalse(receipt['validate_report'](report, inputs, 1))

    def test_capsule_checks_and_source_pin_are_required_without_changing_default_checks(self):
        self.assertEqual(len(probe['CHECKS']), 39)
        self.assertEqual(len(operator['CHECKS']), 22)
        self.assertTrue(operator['CAPSULE_CHECKS'] <= set(operator['CHECKS']))
        self.assertIn('test-access-contract.py', probe['OPERATOR_INPUTS'])
        self.assertEqual(hashlib.sha256((SCRIPT.parent/'test-access-contract.py').read_bytes()).hexdigest(),
                         operator['CONTRACT_SHA256'])
        for check in operator['CAPSULE_CHECKS']:
            report, inputs = self.operator_receipt()
            del report['operator_runtime']['checks'][check]
            with self.assertRaises(ValueError): receipt['validate_report'](report, inputs, 0)
        create, target, ssh = Mock(), Mock(), Mock()
        result = operator['probe'](Path('/unused'), create, target, ssh,
                                   {'test-access-contract.py': b'changed source'}, [])
        self.assertIs(result['passed'], False)
        self.assertEqual(result['error_stage'], 'install_sources')
        create.assert_not_called(); target.assert_not_called(); ssh.assert_not_called()

    def test_capsule_orchestration_uses_target_keys_and_contract_with_closed_results(self):
        contract = {'__name__': 'inert_capsule_contract'}
        exec(compile((SCRIPT.parent/'test-access-contract.py').read_bytes(), '<contract>', 'exec'), contract)
        verifier = {'__name__': 'inert_capsule_verifier'}
        exec(compile(operator['CAPSULE_VERIFY'], '<capsule-verifier>', 'exec'), verifier)
        expected = dict.fromkeys(operator['CAPSULE_CHECKS'], True)
        wire = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + bytes(range(32))
        public = 'ssh-ed25519 '+base64.b64encode(wire).decode()
        calls = []
        def fixture_verify(raw, signature, key):
            self.assertEqual(key, public)
            if signature != b'synthetic-good-signature' or json.loads(raw)['wifi']['psk'] != 'inert-fixture-password':
                raise contract['ContractError']('signature_invalid')
        def target(argv, *, data, timeout):
            calls.append((argv,data,timeout))
            if len(calls) <= 2:
                name = 'good' if len(calls) == 1 else 'bad'
                self.assertEqual(argv, ['/usr/bin/ssh-keygen','-q','-Y','sign','-f',operator['RUNTIME']+'/'+name,
                                        '-n','inkyos-test-access-v1'])
                self.assertEqual(timeout, 5)
                return types.SimpleNamespace(returncode=0, stdout=('synthetic-'+name+'-signature').encode())
            self.assertEqual(argv, ['/usr/bin/python3','-I','-c',operator['CAPSULE_VERIFY']])
            self.assertEqual(timeout, 15)
            payload = json.loads(data)
            self.assertEqual(base64.b64decode(payload['raw']), calls[0][1])
            self.assertEqual(calls[0][1], calls[1][1])
            with patch.dict(contract, {'_verify': fixture_verify}):
                checks = verifier['verify_cases'](types.SimpleNamespace(**contract), payload)
                self.assertEqual(checks, expected)
                # A producer claiming authorization or adding raw data must not pass.
                unsafe = dict(contract['verify_capsule'](base64.b64decode(payload['raw']),
                    b'synthetic-good-signature', expected=payload['expected'], operator_public_key=public),
                    connection_authorized=True, extra='PRIVATE')
                bad_module = types.SimpleNamespace(canonical=contract['canonical'], verify_capsule=lambda *a,**k:unsafe)
                self.assertEqual(verifier['verify_cases'](bad_module,payload), dict.fromkeys(expected,False))
            return types.SimpleNamespace(returncode=0, stdout=json.dumps(checks).encode())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); public_path = root/(operator['RUNTIME']+'/good.pub').lstrip('/')
            public_path.parent.mkdir(parents=True); public_path.write_text(public+'\n')
            result = operator['capsule_checks'](root,target)
        self.assertEqual(result, expected)
        self.assertEqual(len(calls), 3)
        self.assertNotIn('synthetic-good-signature',json.dumps(result))

    def test_capsule_orchestration_refuses_bad_signing_and_unclosed_verifier_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root/(operator['RUNTIME']+'/good.pub').lstrip('/')
            path.parent.mkdir(parents=True); path.write_text('synthetic fixture public\n')
            for code, raw in ((1,b'PRIVATE'),(0,b''),(0,b'x'*2049)):
                target = Mock(return_value=types.SimpleNamespace(returncode=code,stdout=raw))
                with self.assertRaisesRegex(ValueError,'^capsule_signing_failed$'):
                    operator['capsule_checks'](root,target)
                self.assertEqual(target.call_count,1)
            good = dict.fromkeys(operator['CAPSULE_CHECKS'],True)
            for code, raw in ((1,b'PRIVATE'),(0,b'x'*1025),(0,b'[]'),
                              (0,json.dumps({**good,'extra':'PRIVATE'}).encode()),
                              (0,json.dumps({**good,'valid_signature':1}).encode())):
                target = Mock(side_effect=[types.SimpleNamespace(returncode=0,stdout=b'synthetic-signature')]*2
                    + [types.SimpleNamespace(returncode=code,stdout=raw)])
                with self.assertRaises(ValueError) as error: operator['capsule_checks'](root,target)
                self.assertNotIn('PRIVATE',str(error.exception))

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
