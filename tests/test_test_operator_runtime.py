"""Operator protocol and filesystem fixtures; never use host services or keys."""
import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


dispatch = module("operator_dispatch_test", "scripts/test-operator-dispatch.py")
runner = module("operator_runner_test", "scripts/test-operator-runner.py")
runtime = module("operator_enrollment_test", "scripts/test-enrollment-firstboot.py")
preflight = module("operator_preflight_test", "scripts/test-lan-preflight.py")
access_policy = module("operator_access_policy_test", "scripts/test-access-policy.py")


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def envelope(verb="preflight", request=None):
    return {"schema_version": 1, "operation": verb,
            "request": {"schema_version": 1} if request is None else request}


REFERENCE = {"utc_reference": 1800000000, "utc_reference_age": 0, "utc_reference_source": "gnss"}


class Facts:
    def collect(self, _request):
        return dict.fromkeys(preflight.CHECKS, True)


class FixtureAdapter:
    def __init__(self):
        self.calls = []
        self.failures = {}
        self.preflight_value = preflight.preflight(Facts(), live=True, operator_access_confirmed=True,
            country="FR", country_confirmed=True, **REFERENCE)

    def record(self, key):
        self.calls.append(key)
        value = self.failures.get(key, True)
        if isinstance(value, BaseException):
            raise value
        return value

    def authenticate(self): return self.record("authenticate")
    def bind(self): return self.record("bind")
    def acquire(self): return self.record("acquire")
    def unchanged(self): return self.record("unchanged")
    def preflight(self, request): self.record("preflight"); return copy.deepcopy(self.preflight_value)
    def stop_ready(self): return self.record("stop_ready")
    def invalidate_permit(self): return self.record("invalidate")
    def stop_unit(self, unit): return self.record("stop:" + unit)
    def mask_unit(self, unit): return self.record("mask:" + unit)
    def verify_unit(self, unit): return self.record("verify:" + unit)
    def poweroff(self): return self.record("poweroff")
    def close(self): self.record("close")


class ProtocolTests(unittest.TestCase):
    def test_exact_verbs_and_closed_request_schema_at_both_boundaries(self):
        for verb in dispatch.VERBS:
            self.assertEqual(dispatch.request(b'{"schema_version":1}', verb), {"schema_version": 1})
            self.assertEqual(runner.parse_envelope(canonical(envelope(verb))), envelope(verb))
        for command in ("", " preflight", "preflight\n", "stop now", "activate;id", "sh", "scp -t .", None, True):
            invoke = Mock()
            self.assertEqual(dispatch.dispatch(command, b'{"schema_version":1}', invoke=invoke), (64, b""))
            invoke.assert_not_called()
        bad = (b'', b'null', b'[]', b'{"schema_version":true}', b'{"schema_version":1.0}',
            b'{"schema_version":1,"schema_version":1}', b'{"schema_version":1,"x":NaN}',
            b'{"schema_version":1,"x":1}', b'\xff', b'{"schema_version":1} trailing', b'x'*4097)
        for raw in bad:
            for verb in dispatch.VERBS:
                self.assertEqual(dispatch.dispatch(verb, raw, invoke=Mock()), (64, b""))
        for bad_envelope in (None, [], {**envelope(), "schema_version": True},
                             {**envelope(), "operation": []}, {**envelope(), "extra": "PRIVATE"}):
            with self.assertRaises(runner.Refused):
                runner.parse_envelope(canonical(bad_envelope))
        for request in ({"schema_version": True}, {"schema_version": 1.0}, {"schema_version": 1, "extra": 0}):
            with self.assertRaises(runner.Refused):
                runner.parse_envelope(canonical(envelope(request=request)))
        with self.assertRaises(runner.Refused):
            runner.parse_envelope(b'{"schema_version":1,"operation":"stop","request":{"schema_version":1,"schema_version":1}}')

    def test_optional_utc_trio_is_atomic_and_only_for_preflight(self):
        request = {"schema_version": 1, **REFERENCE}
        self.assertEqual(dispatch.request(canonical(request), "preflight"), request)
        self.assertEqual(runner.parse_envelope(canonical(envelope(request=request)))["request"], request)
        for verb in ("activate", "stop"):
            with self.assertRaises(ValueError): dispatch.request(canonical(request), verb)
            with self.assertRaises(runner.Refused): runner.parse_envelope(canonical(envelope(verb, request)))
        for key, value in (("utc_reference", True), ("utc_reference", 1.0), ("utc_reference", 0),
                           ("utc_reference_age", True), ("utc_reference_age", 61),
                           ("utc_reference_age", -1), ("utc_reference_source", "host-clock")):
            changed = {**request, key: value}
            with self.assertRaises(ValueError): dispatch.request(canonical(changed), "preflight")
            with self.assertRaises(runner.Refused): runner.parse_envelope(canonical(envelope(request=changed)))
        for key in REFERENCE:
            changed = dict(request); del changed[key]
            with self.assertRaises(ValueError): dispatch.request(canonical(changed), "preflight")
            with self.assertRaises(runner.Refused): runner.parse_envelope(canonical(envelope(request=changed)))

    def test_both_receivers_require_eof_within_size_and_total_deadline(self):
        for receive in (dispatch.receive, runner.receive):
            wait = Mock(return_value=([9], [], []))
            self.assertEqual(receive(9, clock=lambda: 0, wait=wait, read=Mock(side_effect=[b'a', b''])), b'a')
            with self.assertRaises(ValueError):
                receive(9, clock=lambda: 0, wait=wait, read=Mock(side_effect=[b'x'*4096, b'x']))
            with self.assertRaises(ValueError):
                receive(9, clock=Mock(side_effect=[0, 0, 6]), wait=wait, read=Mock(return_value=b'a'))
            with self.assertRaises(ValueError):
                receive(9, clock=lambda: 0, wait=Mock(return_value=([], [], [])), read=Mock())

    def test_dispatch_builds_fixed_envelope_and_preserves_only_known_exit_codes(self):
        invoke = Mock(return_value=(1, b'{"blocked":true}\n'))
        self.assertEqual(dispatch.dispatch("preflight", canonical({"schema_version": 1, **REFERENCE}), invoke=invoke)[0], 1)
        self.assertEqual(json.loads(invoke.call_args.args[0]), envelope(request={"schema_version": 1, **REFERENCE}))
        for value in ((0, b'x'*32769), (True, b''), (137, b'PRIVATE'), (0, 'PRIVATE')):
            self.assertEqual(dispatch.dispatch("stop", b'{"schema_version":1}', invoke=Mock(return_value=value)), (64, b''))

    def test_sudo_is_zero_arguments_closed_environment_and_bounded_io(self):
        real = subprocess.Popen
        def fixture(argv, **kwargs):
            self.assertEqual(argv, ('/usr/bin/sudo', '-n', '--', dispatch.RUNNER))
            self.assertEqual(kwargs['env'], {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
            self.assertNotIn('shell', kwargs)
            return real([sys.executable, '-I', '-c', 'import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'], **kwargs)
        with patch.object(dispatch.subprocess, 'Popen', side_effect=fixture):
            code, output = dispatch.invoke(b'fixed payload')
        self.assertEqual((code, output), (0, b'fixed payload'))

    def test_production_cli_has_no_fixture_or_alternate_root(self):
        with patch.object(runner, 'receive') as receive, patch.object(runner, 'NativeAdapter') as native, patch('sys.stdout', io.StringIO()):
            self.assertEqual(runner.main(['--root', '/fixture']), 64)
            receive.assert_not_called(); native.assert_not_called()
        with patch.object(dispatch, 'receive') as receive:
            self.assertEqual(dispatch.main(['--fixture']), 64)
            receive.assert_not_called()


class OperationTests(unittest.TestCase):
    def test_activation_refused_even_with_complete_good_fixture_preflight(self):
        adapter = FixtureAdapter()
        code, result = runner.operate(envelope('activate'), adapter)
        self.assertEqual((code, result['status'], result['error']), (1, 'BLOCKED', 'activation_unavailable'))
        self.assertEqual(adapter.calls, ['authenticate', 'bind', 'acquire', 'unchanged', 'close'])
        self.assertFalse(result['activation_authorized'])

    def test_preflight_reports_checked_results_and_fixture_never_claims_live(self):
        adapter = FixtureAdapter()
        adapter.preflight_value.update(live_evidence=True, observation_source='live-system')
        code, result = runner.operate(envelope(), adapter)
        self.assertEqual(code, 0)
        self.assertFalse(result['live_evidence']); self.assertFalse(result['preflight']['live_evidence'])
        self.assertEqual(result['preflight']['observation_source'], 'fixture')
        self.assertFalse(result['activation_authorized'])
        self.assertEqual(adapter.calls, ['authenticate', 'bind', 'acquire', 'unchanged', 'preflight', 'unchanged', 'close'])
        adapter = FixtureAdapter()
        adapter.preflight_value = preflight.preflight(Facts(), live=True, country='FR', country_confirmed=True)
        code, result = runner.operate(envelope(), adapter)
        self.assertEqual((code, result['error']), (1, 'preflight_blocked'))

    def test_malformed_preflight_and_state_change_do_not_return_success(self):
        for change in ({'passed': True, 'extra': 'PRIVATE'}, {'passed': 1}, {'activation_authorized': True}):
            adapter = FixtureAdapter(); adapter.preflight_value.update(change)
            code, result = runner.operate(envelope(), adapter)
            self.assertNotEqual(code, 0); self.assertFalse(result['passed'])
            self.assertEqual(result['error'], 'preflight_unavailable')
            self.assertNotIn('PRIVATE', json.dumps(result))
        adapter = FixtureAdapter(); adapter.unchanged = Mock(side_effect=[True, False])
        code, result = runner.operate(envelope(), adapter)
        self.assertEqual(result['error'], 'state_changed'); self.assertNotEqual(code, 0)

    def test_auth_binding_lock_and_changed_state_refuse_before_any_operation(self):
        for stage in ('authenticate', 'bind', 'acquire', 'unchanged'):
            for failure in (False, 1, RuntimeError('PRIVATE')):
                adapter = FixtureAdapter(); adapter.failures[stage] = failure
                code, result = runner.operate(envelope('stop'), adapter)
                self.assertEqual(code, 64)
                self.assertNotIn('invalidate', adapter.calls); self.assertNotIn('poweroff', adapter.calls)
                self.assertNotIn('PRIVATE', json.dumps(result)); self.assertEqual(adapter.calls[-1], 'close')

    def test_stop_requires_exact_true_readonly_guard_before_any_mutation(self):
        expected = ['authenticate','bind','acquire','unchanged','stop_ready','close']
        for value in (False, None, 0, 1, 'true', RuntimeError('PRIVATE')):
            adapter = FixtureAdapter(); adapter.failures['stop_ready'] = value
            code, result = runner.operate(envelope('stop'), adapter)
            self.assertEqual((code,result['error']), (1,'stop_requires_inactive_runtime'))
            self.assertEqual(adapter.calls, expected)
            self.assertIsNone(result['stop']); self.assertFalse(result['passed'])
            self.assertNotIn('PRIVATE', json.dumps(result))
        fixture = FixtureAdapter()
        class WithoutGuard:
            def __getattr__(self, name):
                if name == 'stop_ready': raise AttributeError(name)
                return getattr(fixture, name)
        code, result = runner.operate(envelope('stop'), WithoutGuard())
        self.assertEqual((code,result['error']), (1,'stop_requires_inactive_runtime'))
        self.assertEqual(fixture.calls, expected[:4]+['close'])
        self.assertIsNone(result['stop'])

    def test_stop_order_and_poweroff_survive_individual_failures_without_preflight(self):
        expected = ['authenticate','bind','acquire','unchanged','stop_ready','invalidate']
        expected += [prefix + ':' + unit for prefix in ('stop','mask','verify') for unit in runner.UNITS]
        expected += ['unchanged','poweroff','close']
        adapter = FixtureAdapter()
        code, result = runner.operate(envelope('stop'), adapter)
        self.assertEqual(adapter.calls, expected); self.assertEqual(code, 0)
        self.assertTrue(result['stop']['poweroff_requested'])
        for step in expected[5:-3] + ['poweroff']:
            adapter = FixtureAdapter(); adapter.failures[step] = RuntimeError('PRIVATE')
            code, result = runner.operate(envelope('stop'), adapter)
            self.assertEqual(code, 1); self.assertEqual(result['error'], 'stop_incomplete')
            self.assertEqual(adapter.calls, expected); self.assertNotIn('PRIVATE', json.dumps(result))
        adapter = FixtureAdapter(); adapter.unchanged = Mock(side_effect=[True, False])
        code, result = runner.operate(envelope('stop'), adapter)
        self.assertEqual(code, 1); self.assertTrue(result['stop']['poweroff_requested'])


class NativeFixture(runner.NativeAdapter):
    """A fixture subclass is deliberately never native live evidence."""
    pass


class NativeBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.adapter = NativeFixture()
        self.adapter.runtime = dict(vars(runtime))
        self.adapter.runtime['_metadata'] = lambda info, **kwargs: runtime._metadata(info, owner=os.getuid(), **kwargs)
        self.adapter.files = runtime.Files(self.tmp.name, owner=os.getuid())
        wire = struct.pack('>I',11)+b'ssh-ed25519'+struct.pack('>I',32)+b'x'*32
        public = 'ssh-ed25519 '+base64.b64encode(wire).decode()
        profile = {'schema_version':1, 'kind':'test-lan-enrollment','purpose':'test-enroll-and-stop',
            'state':'enrollment-pending','application_source_commit':runtime.SOURCE,
            'application_manifest_sha256':runtime.MANIFEST_HASH,'parent_image_sha256':runtime.PARENT_IMAGE_SHA256,
            'operator_public_key':public,'challenge':'a'*64,'country_requested':'FR',
            **dict.fromkeys(runtime.FALSE_FIELDS,False)}
        self.raw = {runner.PROFILE:canonical(profile),
            runner.STATE:canonical({'schema_version':1,'kind':'test-lan-enrollment-state','state':'enrolled',
                'profile_sha256':hashlib.sha256(canonical(profile)).hexdigest(),'application_activation_authorized':False}),
            runner.SYSTEM:canonical({'version':1,'hostname':'inky-'+'1'*32}),
            runner.HOST_PUBLIC:(public+' inkyos-test-host\n').encode(),
            runner.ENROLLMENT:(ROOT/'scripts/test-enrollment-firstboot.py').read_bytes(),
            runner.PREFLIGHT:(ROOT/'scripts/test-lan-preflight.py').read_bytes(),
            runner.DISPATCH:(ROOT/'scripts/test-operator-dispatch.py').read_bytes(),
            runner.RUNNER:(ROOT/'scripts/test-operator-runner.py').read_bytes()}
        keys = ('profile_sha256','state_sha256','system_identity_sha256','host_public_key_sha256',
                'enrollment_source_sha256','preflight_sha256','dispatcher_sha256','runner_sha256')
        config = {'schema_version':1,'kind':'test-operator-runtime','operator_uid':1200,'operator_gid':1200,
                  'country_confirmed':True,**{key:hashlib.sha256(raw).hexdigest() for key,raw in zip(keys,self.raw.values())}}
        self.adapter.config = config; self.adapter.config_raw = canonical(config)
        for path, data in {**self.raw,runner.CONFIG:self.adapter.config_raw}.items():
            mode = 0o555 if path in {runner.ENROLLMENT,runner.PREFLIGHT,runner.DISPATCH,runner.RUNNER} else (0o644 if path==runner.HOST_PUBLIC else 0o600)
            self.put(path,data,mode)
        for path in ('etc/inkyos-test-enrollment','var/lib/inkyos-test-enrollment','var/lib/inkyos'):
            (self.root/path).chmod(0o700)
        (self.root/'run').mkdir(mode=0o755)

    def tearDown(self):
        self.adapter.close(); self.tmp.cleanup()

    def put(self, path, data, mode):
        file = self.root/path.lstrip('/')
        # Every newly created ancestor must remain safe with a group-writable
        # process umask (Path.mkdir(parents=True) uses 0777 for ancestors).
        parent = self.root
        for component in file.relative_to(self.root).parts[:-1]:
            parent /= component
            parent.mkdir(mode=0o755, exist_ok=True)
        if file.exists():
            file.chmod(0o600)
        file.write_bytes(data); file.chmod(mode)

    def install_v2(self, manifest=None, *, profile_changes=None):
        """Publish only synthetic enrollment bindings under the fixture root."""
        policy_raw = (ROOT/'scripts/test-access-policy.py').read_bytes()
        if manifest is None:
            manifest = {'schema_version':1, 'kind':'test-access-runtime',
                'application_source_commit':access_policy.SOURCE,
                'application_manifest_sha256':access_policy.MANIFEST_HASH,
                'parent_image_sha256':access_policy.PARENT_IMAGE_SHA256,
                'files':{path[1:]:{'sha256':hashlib.sha256(raw).hexdigest(),'mode':'0555'}
                    for path,raw in {runner.ACCESS_POLICY:policy_raw,
                        **{path:self.raw[path] for path in (runner.ENROLLMENT,runner.PREFLIGHT,runner.DISPATCH,runner.RUNNER)}}.items()}}
        manifest_raw = canonical(manifest)
        self.put(runner.ACCESS_POLICY, policy_raw, 0o555)
        self.put(runner.ACCESS_MANIFEST, manifest_raw, 0o644)
        profile = json.loads(self.raw[runner.PROFILE])
        profile.update(schema_version=2, application_source_commit=access_policy.SOURCE,
            application_manifest_sha256=access_policy.MANIFEST_HASH, parent_image_sha256=access_policy.PARENT_IMAGE_SHA256,
            access_runtime_manifest_sha256=hashlib.sha256(manifest_raw).hexdigest())
        profile.update(profile_changes or {})
        self.raw[runner.PROFILE] = canonical(profile)
        state = json.loads(self.raw[runner.STATE])
        state['profile_sha256'] = hashlib.sha256(self.raw[runner.PROFILE]).hexdigest()
        self.raw[runner.STATE] = canonical(state)
        for path,key in ((runner.PROFILE,'profile_sha256'),(runner.STATE,'state_sha256')):
            self.put(path,self.raw[path],0o600)
            self.adapter.config[key] = hashlib.sha256(self.raw[path]).hexdigest()
        self.adapter.config_raw = canonical(self.adapter.config)
        self.put(runner.CONFIG,self.adapter.config_raw,0o600)
        return manifest

    def test_native_caller_matches_passwd_and_sudo_fields_before_binding(self):
        self.put('/etc/passwd',b'root:x:0:0:root:/root:/bin/sh\ninky-test:x:1200:1200:test:/nonexistent:/bin/sh\n',0o644)
        ns=dict(vars(runtime));ns['Files']=lambda: runtime.Files(self.tmp.name,owner=os.getuid())
        # Capture real fixture uid before patching the production caller check.
        owner=os.getuid();ns['Files']=lambda: runtime.Files(self.tmp.name,owner=owner)
        good={'SUDO_USER':'inky-test','SUDO_UID':'1200','SUDO_GID':'1200'}
        for change in (None,{'SUDO_USER':'root'},{'SUDO_UID':'01200'},{'SUDO_UID':'1201'},
                       {'SUDO_GID':'0'},{'SUDO_GID':''}):
            adapter=NativeFixture()
            try:
                with patch.object(runner.sys,'platform','linux'), patch.object(runner.platform,'machine',return_value='aarch64'), \
                        patch.object(runner.os,'getuid',return_value=0), patch.object(runner.os,'geteuid',return_value=0), \
                        patch.object(runner,'bootstrap',return_value=ns), patch.dict(os.environ,{**good,**(change or {})},clear=True):
                    if change is None:self.assertTrue(adapter.authenticate())
                    else:
                        with self.assertRaisesRegex(runner.Refused,'caller_unverified'):adapter.authenticate()
            finally:adapter.close()
        adapter=NativeFixture()
        try:
            with patch.object(runner.sys,'platform','darwin'),patch.object(runner,'bootstrap') as load:
                with self.assertRaisesRegex(runner.Refused,'target_unverified'):adapter.authenticate()
                load.assert_not_called()
        finally:adapter.close()

    def test_native_subclass_never_exports_live_evidence(self):
        fixture=FixtureAdapter()
        class Injected(runner.NativeAdapter):
            def __init__(self):pass
        adapter=Injected()
        for name in ('authenticate','bind','acquire','unchanged','preflight','close'):
            setattr(adapter,name,getattr(fixture,name))
        code,result=runner.operate(envelope(),adapter)
        self.assertEqual(code,0);self.assertFalse(result['live_evidence']);self.assertFalse(result['preflight']['live_evidence'])

    def test_exact_bindings_read_public_only_and_detect_source_or_state_change(self):
        private = self.root/'etc/inkyos-test-enrollment/ssh_host_ed25519_key'
        private.symlink_to('/nonexistent/never-open-this')
        self.assertTrue(runner.valid_config(self.adapter.config))
        self.assertTrue(self.adapter.bind()); self.assertTrue(self.adapter.unchanged())
        self.assertNotIn(runner.ACCESS_POLICY,self.adapter.snapshot)
        self.assertNotIn(runner.ACCESS_MANIFEST,self.adapter.snapshot)
        self.put(runner.STATE, self.raw[runner.STATE]+b' ',0o600)
        self.assertFalse(self.adapter.unchanged())
        with self.assertRaises(runner.Refused): self.adapter.bind()

    def test_v2_binds_exact_policy_manifest_sources_and_preserves_immutable_state(self):
        self.install_v2()
        before = {path:(self.root/path.lstrip('/')).read_bytes() for path in self.raw}
        private = self.root/'etc/inkyos-test-enrollment/ssh_host_ed25519_key'
        private.symlink_to('/nonexistent/never-open-this')
        self.assertEqual(hashlib.sha256((ROOT/'scripts/test-access-policy.py').read_bytes()).hexdigest(), runner.ACCESS_POLICY_SHA256)
        self.assertEqual(set(self.adapter.config), runner.CONFIG_FIELDS)
        with patch.object(self.adapter.files,'read',wraps=self.adapter.files.read) as read:
            self.assertTrue(self.adapter.bind())
        self.assertEqual({call.args[0] for call in read.call_args_list},
            set(self.raw)|{runner.ACCESS_POLICY,runner.ACCESS_MANIFEST})
        self.assertTrue(self.adapter.unchanged())
        self.assertEqual(json.loads(self.raw[runner.STATE])['schema_version'],1)
        self.assertEqual(before,{path:(self.root/path.lstrip('/')).read_bytes() for path in self.raw})
        self.assertEqual(self.adapter.config['host_public_key_sha256'],hashlib.sha256(self.raw[runner.HOST_PUBLIC]).hexdigest())

    def test_v2_changed_policy_is_refused_before_any_module_exec(self):
        self.install_v2()
        self.put(runner.ACCESS_POLICY,b"raise RuntimeError('PRIVATE')\n",0o555)
        with patch('builtins.exec') as execute:
            with self.assertRaisesRegex(runner.Refused,'^binding_invalid$'):
                self.adapter.bind()
            execute.assert_not_called()

    def test_v2_profile_and_manifest_bindings_refuse_crossed_candidates(self):
        for key,value in (('application_source_commit',runtime.SOURCE),
                          ('application_manifest_sha256',runtime.MANIFEST_HASH),
                          ('parent_image_sha256','0'*64), ('access_runtime_manifest_sha256','0'*64)):
            with self.subTest(key=key):
                self.install_v2(profile_changes={key:value})
                with self.assertRaises(runner.Refused): self.adapter.bind()
        manifest = self.install_v2()
        for key,value in (('schema_version',True),('kind','other'),('application_source_commit',runtime.SOURCE),
                          ('application_manifest_sha256',runtime.MANIFEST_HASH),('parent_image_sha256','0'*64),('extra',False)):
            changed = copy.deepcopy(manifest); changed[key] = value
            self.install_v2(changed)
            with self.subTest(key=key), self.assertRaises(runner.Refused): self.adapter.bind()

    def test_v2_manifest_program_pins_and_modes_are_required(self):
        manifest = self.install_v2()
        for path in (runner.ACCESS_POLICY,runner.ENROLLMENT,runner.PREFLIGHT,runner.DISPATCH,runner.RUNNER):
            for change in ('missing','hash','mode'):
                changed = copy.deepcopy(manifest)
                if change == 'missing': del changed['files'][path[1:]]
                else: changed['files'][path[1:]]['sha256' if change == 'hash' else 'mode'] = '0'*64 if change == 'hash' else '0644'
                self.install_v2(changed)
                with self.subTest(path=path,change=change), self.assertRaises(runner.Refused): self.adapter.bind()

    def test_v2_manifest_never_selects_extra_paths_for_reading(self):
        manifest = self.install_v2()
        manifest['files']['etc/shadow'] = {'sha256':'a'*64,'mode':'0644'}
        self.install_v2(manifest)
        with patch.object(self.adapter.files,'read',wraps=self.adapter.files.read) as read:
            self.assertTrue(self.adapter.bind())
        self.assertNotIn('/etc/shadow',[call.args[0] for call in read.call_args_list])
        for path in ('/etc/shadow','etc/../shadow','etc//shadow','etc/./shadow'):
            changed = copy.deepcopy(manifest)
            changed['files'][path] = {'sha256':'a'*64,'mode':'0644'}
            self.install_v2(changed)
            with self.subTest(path=path), self.assertRaises(runner.Refused): self.adapter.bind()

    def test_v2_new_bindings_are_monitored_and_require_safe_permissions(self):
        for path,mode in ((runner.ACCESS_POLICY,0o555),(runner.ACCESS_MANIFEST,0o644)):
            self.install_v2()
            self.assertTrue(self.adapter.bind())
            file = self.root/path.lstrip('/')
            self.put(path,file.read_bytes()+b' ',mode)
            self.assertFalse(self.adapter.unchanged())
            self.install_v2()
            file.chmod(0o666)
            with self.subTest(path=path), self.assertRaises(runtime.EnrollmentError): self.adapter.bind()

    def test_profile_state_identity_public_key_and_program_changes_fail_closed(self):
        for path in self.raw:
            original = self.raw[path]
            file = self.root/path.lstrip('/')
            mode=stat.S_IMODE(file.stat().st_mode)
            self.put(path, original+b'changed',mode)
            with self.subTest(path=path), self.assertRaises(Exception): self.adapter.bind()
            self.put(path,original,mode)
        for key,value in (('schema_version',True),('operator_uid',True),('operator_gid',0),
                          ('country_confirmed',1),('preflight_sha256','0'*64),('runner_sha256','bad')):
            self.assertFalse(runner.valid_config({**self.adapter.config,key:value}))

    def test_lock_serializes_and_permit_invalidation_never_follows_symlink(self):
        self.assertTrue(self.adapter.bind()); self.assertTrue(self.adapter.acquire())
        other=NativeFixture(); other.runtime=self.adapter.runtime; other.files=runtime.Files(self.tmp.name,owner=os.getuid())
        try:
            with self.assertRaisesRegex(runner.Refused,'operation_busy'): other.acquire()
        finally: other.close()
        directory=self.root/'run/inkyos-test-operator'; secret=self.root/'keep-data'
        secret.write_bytes(b'preserve'); (directory/runner.PERMIT).symlink_to(secret)
        with self.assertRaises(Exception): self.adapter.invalidate_permit()
        self.assertTrue((directory/runner.PERMIT).is_symlink()); self.assertEqual(secret.read_bytes(),b'preserve')
        (directory/runner.PERMIT).unlink(); self.assertTrue(self.adapter.invalidate_permit())
        self.put('/run/inkyos-test-operator/'+runner.PERMIT,b'opaque permission',0o600)
        self.assertTrue(self.adapter.invalidate_permit()); self.assertFalse((directory/runner.PERMIT).exists())

    def test_stop_commands_are_fixed_persistent_masks_without_force(self):
        self.adapter.stop_deadline=100
        calls=[]
        def command(argv,**kwargs):
            calls.append((argv,kwargs))
            if 'show' in argv:
                return 0,b'ActiveState=inactive\nSubState=dead\nLoadState=masked\nUnitFileState=masked\n'
            return 0,b''
        self.adapter.runtime['command']=command
        self.adapter.preflight_module=vars(preflight)
        with patch.object(runner.time,'monotonic',return_value=90):
            for unit in runner.UNITS:
                self.assertTrue(self.adapter.stop_unit(unit));self.assertTrue(self.adapter.mask_unit(unit));self.assertTrue(self.adapter.verify_unit(unit))
            self.assertTrue(self.adapter.poweroff())
        self.assertEqual(calls[-1][0],('/usr/bin/systemctl','--no-block','poweroff'))
        self.assertTrue(all('--force' not in argv and '--runtime' not in argv for argv,_ in calls))
        self.assertTrue(all(kwargs['timeout']<=3 for _,kwargs in calls))

    def test_stop_readiness_uses_exact_masked_inactive_states_with_one_budget(self):
        self.adapter.preflight_module = vars(preflight)
        good = b'ActiveState=inactive\nSubState=dead\nLoadState=masked\nUnitFileState=masked\n'
        calls = []
        def command(argv, **kwargs):
            self.assertEqual(self.adapter.stop_deadline, 90+runner.STOP_BUDGET)
            calls.append(argv)
            return 0, good
        self.adapter.runtime['command'] = command
        with patch.object(runner.time, 'monotonic', return_value=90):
            self.assertTrue(self.adapter.stop_ready())
        self.assertEqual(calls, [('/usr/bin/systemctl','--no-pager','show',unit,
            '--property=ActiveState,SubState,LoadState,UnitFileState') for unit in runner.UNITS])
        self.assertTrue(self.adapter.bind()); self.assertTrue(self.adapter.acquire())
        with patch.object(runner.time, 'monotonic', return_value=95):
            self.assertTrue(self.adapter.invalidate_permit())
        self.assertEqual(self.adapter.stop_deadline, 90+runner.STOP_BUDGET)
        for bad in (None, (1,b''), (0,good.replace(b'inactive',b'active')),
                    (0,good.replace(b'dead',b'running')), (0,good.replace(b'LoadState=masked',b'LoadState=loaded')),
                    (0,good.replace(b'UnitFileState=masked',b'UnitFileState=masked-runtime')), (0,b'')):
            self.adapter.runtime['command'] = Mock(return_value=bad)
            with patch.object(runner.time, 'monotonic', return_value=90):
                self.assertFalse(self.adapter.stop_ready())
        for failed_index in range(len(runner.UNITS)):
            for bad in (good.replace(b'inactive',b'active'),
                        good.replace(b'UnitFileState=masked',b'UnitFileState=enabled')):
                replies = [(0,good)] * len(runner.UNITS)
                replies[failed_index] = (0,bad)
                command = Mock(side_effect=replies)
                self.adapter.runtime['command'] = command
                with patch.object(runner.time, 'monotonic', return_value=90):
                    self.assertFalse(self.adapter.stop_ready())
                self.assertEqual(command.call_count, failed_index+1)


if __name__ == '__main__':
    unittest.main()
