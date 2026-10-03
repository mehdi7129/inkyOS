#!/usr/bin/env python3
"""Optional SSH bench extension: production reads, fixture-only stop mutations.

Called only by the sealed disposable-image SSH/PAM probe, inside its namespaces.
This is not an installer or a production runtime entry point.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time


CHECKS = (
    'production_sources_installed', 'native_preflight_blocked_with_evidence',
    'optional_utc_reference_accepted', 'activation_explicitly_refused',
    'partial_utc_refused', 'extended_request_refused', 'duplicate_request_refused',
    'missing_marker_refused', 'changed_profile_refused', 'changed_runner_refused',
    'direct_root_without_sudo_refused', 'sudo_extra_argument_refused',
    'concurrent_operation_refused', 'slow_ssh_stdin_bounded',
    'fixture_stop_order_and_projection', 'production_sources_restored',
    'enrollment_bytes_preserved', 'no_activation_permit_created',
)
DISPATCH = '/usr/local/lib/inkyos-test-ssh/dispatch.py'
RUNNER = '/usr/local/lib/inkyos-test-ssh/runner'
CONFIG = '/etc/inkyos-test-operator.json'
RUNTIME = '/run/inkyos-test-ssh'


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def probe(root, create, target, ssh, sources, client):
    checks = dict.fromkeys(CHECKS, False)
    report = {'schema_version': 1, 'scope': 'isolated-test-operator-runtime-probe',
        'source_sha256': {name: sha(raw) for name, raw in sources.items()},
        'checks': checks, 'passed': False, 'error_stage': None,
        'application_activated': False, 'stop_mutations_fixture_only': True,
        'hardware_qualified': False, 'release_qualified': False,
        'limits': ['Native preflight uses synthetic enrolled files on a disposable image, not a Raspberry Pi.',
            'The production stop algorithm is called with a fixture adapter; no systemctl stop, mask or poweroff is run.',
            'No Wi-Fi connection, clock mutation, application, GPIO, display or physical card is exercised.']}
    stage = 'install_sources'
    owned = {}
    def replace(path, raw, mode):
        destination = root / path.lstrip('/')
        info = destination.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or destination.read_bytes() != owned[path]):
            raise ValueError('changed_probe_fixture')
        temporary = str(Path(path).with_name('.' + Path(path).name + '.operator-probe.tmp'))
        create(temporary, raw, mode)
        os.replace(root / temporary.lstrip('/'), destination)
        owned[path] = raw
    def new(path, raw, mode):
        create(path, raw, mode)
        owned[path] = raw
    def response(result):
        value = json.loads(result.stdout)
        if (type(value) is not dict or value.get('kind') != 'test-operator-result'
                or value.get('activation_authorized') is not False
                or value.get('hardware_qualified') is not False or value.get('release_qualified') is not False):
            raise ValueError('unexpected_operator_response')
        return value
    def blocked(result, error, code=1):
        value = response(result)
        return (result.returncode == code and value['passed'] is False and value['status'] == 'BLOCKED'
                and value['error'] == error)
    try:
        for path, source in ((DISPATCH, 'test-operator-dispatch.py'), (RUNNER, 'test-operator-runner.py')):
            owned[path] = (root / path.lstrip('/')).read_bytes()
            replace(path, sources[source], 0o555)
        for path, source in (
            ('/usr/local/lib/inkyos/test-lan-preflight.py', 'test-lan-preflight.py'),
            ('/usr/local/lib/inkyos/test-enrollment-firstboot.py', 'test-enrollment-firstboot.py'),
            ('/usr/local/share/inkyos/inky-studio-manifest-v1.json', 'application-manifest.json')):
            new(path, sources[source], 0o444 if source.endswith('.json') else 0o555)
        checks['production_sources_installed'] = all((root / path.lstrip('/')).read_bytes() == raw
                                                    for path, raw in owned.items())
        stage = 'synthetic_enrollment'
        enrollment = {'__name__': 'operator_probe_schema', '__file__': 'test-enrollment-firstboot.py'}
        exec(compile(sources['test-enrollment-firstboot.py'], 'test-enrollment-firstboot.py', 'exec'), enrollment)
        # Only new bench identities; no key or identity from a physical device.
        public = (root / (RUNTIME + '/good.pub').lstrip('/')).read_text().strip()
        public = ' '.join(public.split()[:2])
        profile = {'schema_version': 1, 'kind': 'test-lan-enrollment', 'purpose': 'test-enroll-and-stop',
            'state': 'enrollment-pending', 'application_source_commit': enrollment['SOURCE'],
            'application_manifest_sha256': enrollment['MANIFEST_HASH'],
            'parent_image_sha256': enrollment['PARENT_IMAGE_SHA256'], 'operator_public_key': public,
            'challenge': '12' * 32, 'country_requested': 'FR',
            **dict.fromkeys(enrollment['FALSE_FIELDS'], False)}
        if enrollment['validate_profile'](profile) is not True:
            raise ValueError('invalid_probe_profile')
        for relative in ('etc/inkyos-test-enrollment', 'var/lib/inkyos-test-enrollment', 'var/lib/inkyos'):
            directory = root / relative
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
        profile_raw = canonical(profile)
        state = {'schema_version': 1, 'kind': 'test-lan-enrollment-state', 'state': 'enrolled',
            'profile_sha256': sha(profile_raw), 'application_activation_authorized': False}
        identity = {'version': 1, 'hostname': 'inky-' + '34' * 16}
        host = ' '.join((root / (RUNTIME + '/host.pub').lstrip('/')).read_text().split()[:2])
        bindings = {
            '/etc/inkyos-test-enrollment/profile.json': (profile_raw, 'profile_sha256', 0o600),
            '/var/lib/inkyos-test-enrollment/state.json': (canonical(state), 'state_sha256', 0o600),
            '/var/lib/inkyos/system.json': (canonical(identity), 'system_identity_sha256', 0o600),
            '/etc/inkyos-test-enrollment/ssh_host_ed25519_key.pub':
                ((host + ' inkyos-test-host\n').encode(), 'host_public_key_sha256', 0o644),
        }
        for path, (raw, _key, mode) in bindings.items():
            new(path, raw, mode)
        user = next(line.split(':') for line in (root / 'etc/passwd').read_text().splitlines()
                    if line.startswith('inky-test:'))
        marker = {'schema_version': 1, 'kind': 'test-operator-runtime',
            'operator_uid': int(user[2]), 'operator_gid': int(user[3]), 'country_confirmed': True,
            **{key: sha(raw) for raw, key, _mode in bindings.values()},
            'preflight_sha256': sha(sources['test-lan-preflight.py']),
            'enrollment_source_sha256': sha(sources['test-enrollment-firstboot.py']),
            'dispatcher_sha256': sha(sources['test-operator-dispatch.py']),
            'runner_sha256': sha(sources['test-operator-runner.py'])}
        new(CONFIG, canonical(marker), 0o600)
        new('/etc/inkyos-test-lan.json', canonical({'schema_version': 1, 'kind': 'test-lan-prepared',
            'state': 'prepared-inactive', 'application_runtime': 'masked', 'activation_authorized': False,
            'ready_for_activation': False, 'factory_authority': False,
            'source_commit': enrollment['SOURCE'], 'manifest_sha256': enrollment['MANIFEST_HASH']}), 0o644)
        stage = 'production_ssh_runtime'
        result = ssh('preflight')
        value = response(result)
        checks['native_preflight_blocked_with_evidence'] = (blocked(result, 'preflight_blocked')
            and value['live_evidence'] is True and value['preflight']['live_evidence'] is True
            and value['preflight']['checks']['prepared_profile']['passed'] is True
            and value['preflight']['checks']['exact_payload_pin']['passed'] is True
            and value['preflight']['checks']['panel_runtime_evidence_verified']['passed'] is False)
        utc = {'schema_version': 1, 'utc_reference': 1791028800, 'utc_reference_age': 0,
               'utc_reference_source': 'independent-device'}
        checks['optional_utc_reference_accepted'] = blocked(ssh('preflight', data=canonical(utc)), 'preflight_blocked')
        checks['activation_explicitly_refused'] = blocked(ssh('activate'), 'activation_unavailable')
        checks['partial_utc_refused'] = ssh('preflight', data=b'{"schema_version":1,"utc_reference_age":0}').returncode == 64
        checks['extended_request_refused'] = ssh('preflight', data=b'{"schema_version":1,"country":"FR"}').returncode == 64
        checks['duplicate_request_refused'] = ssh('preflight', data=b'{"schema_version":1,"schema_version":1}').returncode == 64
        stage = 'binding_and_caller_refusals'
        marker_raw = owned[CONFIG]
        parked = root / 'etc/inkyos-test-operator.probe-backup'
        os.rename(root / CONFIG.lstrip('/'), parked)
        try:
            checks['missing_marker_refused'] = blocked(ssh('preflight'), 'binding_invalid', 64)
        finally:
            os.rename(parked, root / CONFIG.lstrip('/'))
        profile_path = '/etc/inkyos-test-enrollment/profile.json'
        replace(profile_path, profile_raw + b'\n', 0o600)
        checks['changed_profile_refused'] = blocked(ssh('preflight'), 'binding_invalid', 64)
        replace(profile_path, profile_raw, 0o600)
        replace(RUNNER, sources['test-operator-runner.py'] + b'\n# changed bench source\n', 0o555)
        checks['changed_runner_refused'] = blocked(ssh('preflight'), 'binding_invalid', 64)
        replace(RUNNER, sources['test-operator-runner.py'], 0o555)
        envelope = canonical({'schema_version': 1, 'operation': 'preflight', 'request': {'schema_version': 1}})
        checks['direct_root_without_sudo_refused'] = blocked(target([RUNNER], data=envelope), 'caller_unverified', 64)
        extra = target(['/usr/sbin/runuser', '-u', 'inky-test', '--', '/usr/bin/sudo', '-n', '--', RUNNER, 'extra'], data=envelope)
        checks['sudo_extra_argument_refused'] = extra.returncode != 0
        stage = 'real_lock_and_input_deadline'
        import fcntl
        fd = os.open(root / 'run/inkyos-test-operator/operation.lock', os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            checks['concurrent_operation_refused'] = blocked(ssh('preflight'), 'operation_busy', 64)
        finally:
            os.close(fd)
        child = subprocess.Popen([*client, 'preflight'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        started = time.monotonic()
        try:
            child.stdin.write(b'{"schema_version":1}')
            child.stdin.flush()  # Deliberately no EOF.
            status = child.wait(timeout=9)
            elapsed = time.monotonic() - started
            checks['slow_ssh_stdin_bounded'] = status == 64 and 4.5 <= elapsed < 9
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=2)
            child.stdin.close()
            child.stdout.close()
        stage = 'fixture_only_stop_algorithm'
        fixture = r'''import importlib.machinery,importlib.util,json
path='/usr/local/lib/inkyos-test-ssh/runner'
loader=importlib.machinery.SourceFileLoader('operator_probe_runner',path)
spec=importlib.util.spec_from_loader(loader.name,loader)
module=importlib.util.module_from_spec(spec);loader.exec_module(module)
class Fixture:
 def __init__(self):self.calls=[]
 def authenticate(self):self.calls.append('auth');return True
 def bind(self):self.calls.append('bind');return True
 def acquire(self):self.calls.append('lock');return True
 def unchanged(self):self.calls.append('unchanged');return True
 def stop_ready(self):self.calls.append('stop-ready');return True
 def invalidate_permit(self):self.calls.append('invalidate');return True
 def stop_unit(self,u):self.calls.append('stop:'+u);return True
 def mask_unit(self,u):self.calls.append('mask:'+u);return True
 def verify_unit(self,u):self.calls.append('verify:'+u);return True
 def poweroff(self):self.calls.append('poweroff-fixture');return True
 def close(self):self.calls.append('close')
adapter=Fixture()
code,result=module.operate({'schema_version':1,'operation':'stop','request':{'schema_version':1}},adapter)
expected=['auth','bind','lock','unchanged','stop-ready','invalidate','stop:inky-studio.service','stop:inky-network.service',
 'mask:inky-studio.service','mask:inky-network.service','verify:inky-studio.service','verify:inky-network.service',
 'unchanged','poweroff-fixture','close']
print(json.dumps({'passed':code==0 and result['passed'] is True and result['live_evidence'] is False
 and result['activation_authorized'] is False and adapter.calls==expected}))
'''
        observed = target(['/usr/bin/python3', '-I', '-c', fixture], timeout=5)
        checks['fixture_stop_order_and_projection'] = observed.returncode == 0 and json.loads(observed.stdout) == {'passed': True}
        stage = 'final_preservation'
        checks['production_sources_restored'] = ((root / DISPATCH.lstrip('/')).read_bytes() == sources['test-operator-dispatch.py']
            and (root / RUNNER.lstrip('/')).read_bytes() == sources['test-operator-runner.py'])
        checks['enrollment_bytes_preserved'] = (all((root / path.lstrip('/')).read_bytes() == raw
            for path, (raw, _key, _mode) in bindings.items()) and (root / CONFIG.lstrip('/')).read_bytes() == marker_raw)
        checks['no_activation_permit_created'] = not (root / 'run/inkyos-test-operator/activation-permit.json').exists()
    except (OSError, ValueError, KeyError, TypeError, StopIteration, subprocess.SubprocessError):
        report['error_stage'] = stage
    report['passed'] = all(checks.values()) and report['error_stage'] is None
    return report
