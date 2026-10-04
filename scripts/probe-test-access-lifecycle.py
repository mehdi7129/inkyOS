#!/usr/bin/env python3
"""Real VM systemd mechanisms with two uniquely named, inert fixture units.

No production runtime is executed. No real app/helper name, device, network,
display, SD, image mount, package installation or poweroff command is used.
The host entry seals source copies; --inside requires the marked build VM.
Only exact files and units created by this invocation may be cleaned up.
"""
import sys
sys.dont_write_bytecode = True

import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import stat
import subprocess
import time


VM = 'inkyos-build'
SOURCES = ('probe-test-access-lifecycle.py', 'probe-test-access-lifecycle-linux.sh')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
HOLD_SECONDS = 36.0
CHECKS = (
    'marked_vm_verified', 'sources_sealed', 'systemd_257_verified', 'unique_names_initially_absent',
    'units_created_exclusively', 'effective_drain_properties', 'helper_started_inert',
    'condition_executed_as_root', 'permit_consumed_once', 'application_principal_nonroot',
    'helper_principal_nonroot', 'application_started_inert', 'sigterm_observed',
    'stop_pending_over_35_seconds', 'application_activity_continues_during_stop',
    'helper_remains_active_during_application_stop', 'no_automatic_restart',
    'explicit_release_observed', 'application_inactive_before_mask', 'consumed_permit_replay_refused',
    'application_masked_after_exit', 'helper_inactive_before_mask', 'helper_masked_after_exit',
    'poweroff_substitute_only', 'fixture_processes_stopped', 'created_units_removed',
    'fixture_runtime_directories_removed', 'daemon_reloaded_after_cleanup',
)
STATE_PROPERTIES = ('ActiveState', 'SubState', 'MainPID', 'ControlPID', 'Job', 'LoadState', 'NRestarts')
SAFE_PROPERTIES = {'Restart': 'no', 'KillMode': 'mixed', 'KillSignal': '15',
                   'TimeoutStopUSec': 'infinity', 'SendSIGKILL': 'no'}
STATE_FIELDS = {'schema_version', 'kind', 'euid', 'egid', 'heartbeat', 'term_seen',
                'release_seen', 'term_monotonic'}

# The same literal source is embedded in both fixture units. It is not an
# import, copy or adaptation of the production activation/drain runtime.
PROGRAM = r'''
import json,os,pathlib,signal,stat,sys,time
role,path,uid=sys.argv[1],pathlib.Path(sys.argv[2]),int(sys.argv[3])
def write(name,value):
 raw=(json.dumps(value,sort_keys=True)+'\n').encode()
 temp=path/('.'+name+'.tmp')
 fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as stream:
  stream.write(raw);stream.flush();os.fsync(stream.fileno())
 os.replace(temp,path/name)
if role=='condition':
 assert os.geteuid()==os.getegid()==0
 info=path.lstat();assert stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700
 try:
  fd=os.open(path/'permit',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 except FileNotFoundError:
  write('condition-denied.json',{'schema_version':1,'root':os.geteuid()==0,'missing_permit':True})
  sys.exit(1)
 with os.fdopen(fd,'rb') as stream:
  info=os.fstat(stream.fileno())
  assert stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600
  assert info.st_size==10 and stream.read(11)==b'permit-v1\n'
 fd=os.open(path/'permit-consumed',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as stream:
  stream.write(b'consumed\n');stream.flush();os.fsync(stream.fileno())
 os.unlink(path/'permit')
 write('condition-ok.json',{'schema_version':1,'root':os.geteuid()==0,'consumed':True})
 sys.exit(0)
assert role in {'app','helper'} and os.geteuid()==uid and uid!=0
info=path.lstat();assert stat.S_ISDIR(info.st_mode) and info.st_uid==uid and stat.S_IMODE(info.st_mode)==0o700
state={'schema_version':1,'kind':'fixture-'+role,'euid':os.geteuid(),'egid':os.getegid(),
       'heartbeat':0,'term_seen':False,'release_seen':False,'term_monotonic':None}
def term(_number,_frame):
 if not state['term_seen']:
  state['term_seen']=True;state['term_monotonic']=time.monotonic()
signal.signal(signal.SIGTERM,term)
while True:
 state['heartbeat']+=1
 if state['term_seen']:
  if role=='helper':
   write('state.json',state);break
  try:
   fd=os.open(path/'release',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  except FileNotFoundError:
   pass
  else:
   with os.fdopen(fd,'rb') as stream:
    info=os.fstat(stream.fileno())
    assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and info.st_size==8
    assert stream.read(9)==b'release\n'
   state['release_seen']=True;write('state.json',state);break
 write('state.json',state)
 time.sleep(0.1)
'''


def require(value):
    if value is not True:
        raise ValueError('probe_refused')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read(path, *, owner=0, group=0, mode=None, limit=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == owner and before.st_gid == group
                and before.st_nlink == 1 and 0 < before.st_size <= limit
                and (mode is None or stat.S_IMODE(before.st_mode) == mode))
        raw = os.read(fd, limit + 1)
        require(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd))
                == stamp(os.stat(path, follow_symlinks=False)))
        return raw
    finally:
        os.close(fd)


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:]); require(count > 0); offset += count
        os.fsync(fd)
    finally:
        os.close(fd)


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def command(argv, timeout=10):
    return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=ENV if sys.platform.startswith('linux') else None, timeout=timeout)


def unit_bytes(prefix, role, work, uid, gid):
    require(re.fullmatch(r'inkyos-lifecycle-probe-[0-9a-f]{8}', prefix) is not None and role in {'app', 'helper'})
    require(re.fullmatch(r'/var/tmp/inkyos-work/test-access-lifecycle\.[0-9a-f]{8}', str(work)) is not None)
    require(type(uid) is int and uid > 0 and type(gid) is int and gid > 0)
    code = "import base64;exec(base64.b64decode('" + base64.b64encode(PROGRAM.encode()).decode() + "'))"
    launch = '/usr/bin/python3 -I -c "' + code + '" '
    lines = ['[Unit]', 'Description=Inert lifecycle mechanism fixture']
    if role == 'app':
        lines += ['Requires=' + prefix + '-helper.service', 'After=' + prefix + '-helper.service']
    lines += ['', '[Service]', 'Type=exec', 'User=nobody', 'Group=' + str(gid), 'UMask=0077',
              'RuntimeDirectory=' + prefix + '-' + role, 'RuntimeDirectoryMode=0700',
              'RuntimeDirectoryPreserve=yes']
    if role == 'app':
        lines += ['ExecCondition=+' + launch + 'condition ' + str(work) + ' ' + str(uid)]
    lines += ['ExecStart=' + launch + role + ' /run/' + prefix + '-' + role + ' ' + str(uid),
              'Restart=no', 'TimeoutStartSec=15s', 'TimeoutStopSec=infinity', 'KillSignal=SIGTERM',
              'KillMode=mixed', 'SendSIGKILL=no', 'PrivateNetwork=yes', 'PrivateDevices=yes',
              'NoNewPrivileges=yes', 'StandardInput=null', 'StandardOutput=null', 'StandardError=null', '']
    return '\n'.join(lines).encode()


def properties(raw, names):
    require(type(raw) is bytes and len(raw) <= 16384)
    value = {}
    for line in raw.decode('ascii').splitlines():
        key, separator, item = line.partition('=')
        require(separator == '=' and key in names and key not in value)
        value[key] = item
    require(set(value) == set(names))
    return value


def inactive(value):
    return (type(value) is dict and value.get('ActiveState') == 'inactive' and value.get('SubState') == 'dead'
            and all(value.get(key) == '0' for key in ('MainPID', 'ControlPID'))
            and value.get('Job') in {'', '0'})


class Probe:
    def __init__(self, work, uid, gid):
        self.work, self.uid, self.gid = work, uid, gid
        self.prefix = 'inkyos-lifecycle-probe-' + work.name.rsplit('.', 1)[1]
        self.names = {role: self.prefix + '-' + role + '.service' for role in ('app', 'helper')}
        self.paths = {role: Path('/run/systemd/system') / name for role, name in self.names.items()}
        self.runtime = {role: Path('/run') / (self.prefix + '-' + role) for role in self.names}
        self.owned = {}
        self.created_roles = set()
        self.runtime_owned = {}
        self.units = {role: unit_bytes(self.prefix, role, work, uid, gid) for role in self.names}

    def ctl(self, operation, role=None):
        require(operation in {'start', 'stop', 'show', 'daemon-reload', 'reset-failed'})
        require(role in self.names if role is not None else operation == 'daemon-reload')
        args = ['/usr/bin/systemctl', '--no-pager']
        if operation == 'stop': args.append('--no-block')
        args.append(operation)
        if role is not None: args.append(self.names[role])
        return command(args)

    def state(self, role, names=STATE_PROPERTIES):
        require(role in self.names)
        result = command(['/usr/bin/systemctl', '--no-pager', 'show', self.names[role],
                          '--property=' + ','.join(names)])
        require(result.returncode == 0)
        return properties(result.stdout, names)

    def publish(self):
        for role, path in self.paths.items():
            require(not path.exists() and not path.is_symlink()
                    and not self.runtime[role].exists() and not self.runtime[role].is_symlink())
            require(self.state(role)['LoadState'] == 'not-found')
        for role, path in self.paths.items():
            write_new(self.work / (role + '.service'), self.units[role], 0o444)
            write_new(path, self.units[role], 0o644)
            self.owned[role] = stamp(path.lstat())
            self.created_roles.add(role)
        require(self.ctl('daemon-reload').returncode == 0)

    def verified_owned(self, role):
        path = self.paths[role]
        info = path.lstat()
        require(stamp(info) == self.owned[role] and info.st_uid == info.st_gid == 0)
        if stat.S_ISLNK(info.st_mode):
            require(os.readlink(path) == '/dev/null')
        else:
            require(read(path, mode=0o644) == self.units[role])

    def mask(self, role):
        require(inactive(self.state(role)))
        self.verified_owned(role)
        self.paths[role].unlink()
        self.owned.pop(role)
        os.symlink('/dev/null', self.paths[role])
        self.owned[role] = stamp(self.paths[role].lstat())
        require(self.ctl('daemon-reload').returncode == 0)
        state = self.state(role)
        require(inactive(state) and state['LoadState'] == 'masked')

    def wait(self, operation, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = operation()
            if value: return value
            time.sleep(0.1)
        raise ValueError('probe_refused')

    def sample(self, role):
        directory = self.runtime[role]
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == self.uid and info.st_gid == self.gid
                and stat.S_IMODE(info.st_mode) == 0o700)
        identity = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
        require(role in self.created_roles and (role not in self.runtime_owned or self.runtime_owned[role] == identity))
        self.runtime_owned.setdefault(role, identity)
        raw = read(directory / 'state.json', owner=self.uid, group=self.gid, mode=0o600, limit=4096)
        value = json.loads(raw)
        require(type(value) is dict and set(value) == STATE_FIELDS and type(value['schema_version']) is int
                and value['schema_version'] == 1 and value['kind'] == 'fixture-' + role
                and type(value['euid']) is int and value['euid'] == self.uid
                and type(value['egid']) is int and value['egid'] == self.gid
                and type(value['heartbeat']) is int and value['heartbeat'] > 0
                and type(value['term_seen']) is bool and type(value['release_seen']) is bool
                and (value['term_monotonic'] is None if not value['term_seen']
                     else type(value['term_monotonic']) in {int, float} and value['term_monotonic'] > 0))
        return value

    def ready(self, role):
        try:
            return self.sample(role)
        except (FileNotFoundError, ValueError):
            return None

    def release(self):
        info = self.runtime['app'].lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == self.uid and info.st_gid == self.gid
                and stat.S_IMODE(info.st_mode) == 0o700)
        path = self.runtime['app'] / 'release'
        try:
            write_new(path, b'release\n', 0o644)
        except FileExistsError:
            require(read(path, mode=0o644, limit=16) == b'release\n')

    def cleanup(self):
        result = dict.fromkeys(CHECKS[-4:], False)
        # The fixture handles SIGTERM and the explicit release; never cancel a
        # job, send SIGKILL, force-mask or touch any unrelated unit/process.
        if 'app' in self.owned:
            self.verified_owned('app')
            if not inactive(self.state('app')):
                self.release()
                self.ctl('stop', 'app')
                self.wait(lambda: inactive(self.state('app')))
        if 'helper' in self.owned:
            self.verified_owned('helper')
            if not inactive(self.state('helper')):
                self.ctl('stop', 'helper')
                self.wait(lambda: inactive(self.state('helper')))
        result['fixture_processes_stopped'] = all(inactive(self.state(role)) for role in self.owned)
        require(result['fixture_processes_stopped'])
        for role in list(self.owned):
            self.verified_owned(role)
            self.ctl('reset-failed', role)
            self.paths[role].unlink()
            self.owned.pop(role)
        require(self.ctl('daemon-reload').returncode == 0)
        result['created_units_removed'] = all(not self.paths[role].exists() and not self.paths[role].is_symlink()
                                              for role in self.created_roles)
        result['daemon_reloaded_after_cleanup'] = all(self.state(role)['LoadState'] == 'not-found' for role in self.created_roles)
        for role in self.created_roles:
            directory = self.runtime[role]
            if not directory.exists(): continue
            info = directory.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == self.uid and info.st_gid == self.gid
                    and stat.S_IMODE(info.st_mode) == 0o700 and self.runtime_owned.get(role)
                        == (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid))
            names = set(os.listdir(directory))
            require(names <= {'state.json', '.state.json.tmp', 'release'})
            for name in names:
                path = directory / name
                before = stamp(path.lstat())
                owner, group = (0, 0) if name == 'release' else (self.uid, self.gid)
                data = read(path, owner=owner, group=group, mode=0o644 if name == 'release' else 0o600, limit=4096)
                write_new(self.work / ('final-' + role + '-' + name.lstrip('.')), data)
                require(stamp(path.lstat()) == before)
                path.unlink()
            directory.rmdir()
        result['fixture_runtime_directories_removed'] = all(not self.runtime[role].exists() for role in self.created_roles)
        return result


def report_template():
    return {'schema_version': 1, 'scope': 'isolated-inert-systemd-lifecycle-mechanisms', 'passed': False,
        'checks': dict.fromkeys(CHECKS, False), 'error_stage': None, 'cleanup_error': False,
        'systemd_package': None, 'systemd_binary_sha256': None, 'source_sha256': {}, 'unit_sha256': {},
        'fixture_program_sha256': sha(PROGRAM.encode()), 'observed_hold_milliseconds': None,
        'live_systemd_evidence': False, 'production_runtime_executed': False,
        'real_application_started': False, 'real_helper_started': False, 'real_poweroff_requested': False,
        'hardware_qualified': False, 'release_qualified': False,
        'limits': ['Only uniquely named inert fixture units run in the marked build VM.',
                   'Production activation/drain workers, Pi devices and display refresh are not executed.',
                   'The VM systemd build is recorded; Raspberry Pi runtime behaviour is not attested.',
                   'A local marker substitutes for poweroff; no shutdown command is invoked.',
                   'Command timeout is not evidence that a submitted systemd job was cancelled.']}


def inside(work):
    require(sys.platform.startswith('linux') and os.getuid() == os.geteuid() == 0
            and re.fullmatch(r'/var/tmp/inkyos-work/test-access-lifecycle\.[0-9a-f]{8}', str(work)) is not None)
    require(read(Path('/var/lib/inkyos-build/owner'), limit=64).strip() == b'inkyos-builder-v1')
    info = work.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700)
    inputs = json.loads(read(work / 'inputs.json', mode=0o444))
    require(set(inputs) == {'schema_version', 'files'} and inputs['schema_version'] == 1
            and set(inputs['files']) == set(SOURCES)
            and set(os.listdir(work)) == set(SOURCES) | {'inputs.json'})
    for name, pin in inputs['files'].items():
        require(sha(read(work / name, mode=0o444)) == pin)
    report = report_template(); checks = report['checks']; probe = None; stage = 'environment'
    report['source_sha256'] = dict(inputs['files'])
    checks['marked_vm_verified'] = checks['sources_sealed'] = True
    def interrupted(_number, _frame): raise InterruptedError('probe_interrupted')
    old_term, old_int = signal.signal(signal.SIGTERM, interrupted), signal.signal(signal.SIGINT, interrupted)
    try:
        require(Path('/proc/1/comm').read_bytes() == b'systemd\n')
        version = command(['/usr/bin/systemctl', '--version'])
        require(version.returncode == 0 and re.match(rb'systemd 257(?:[. (]|$)', version.stdout) is not None)
        package = command(['/usr/bin/dpkg-query', '-W', '-f=${Version}', 'systemd'])
        require(package.returncode == 0 and re.fullmatch(rb'257[A-Za-z0-9.+:~_-]{0,80}', package.stdout) is not None)
        report['systemd_package'] = package.stdout.decode('ascii')
        report['systemd_binary_sha256'] = sha(read(Path('/usr/lib/systemd/systemd'), limit=32 * 1024**2))
        checks['systemd_257_verified'] = True
        account = pwd.getpwnam('nobody')
        require(account.pw_uid > 0 and account.pw_gid > 0)
        probe = Probe(work, account.pw_uid, account.pw_gid)
        stage = 'publish'
        require(all(not path.exists() and not path.is_symlink() for path in (*probe.paths.values(), *probe.runtime.values())))
        checks['unique_names_initially_absent'] = True
        probe.publish(); checks['units_created_exclusively'] = True
        report['unit_sha256'] = {role: sha(raw) for role, raw in probe.units.items()}
        require(all(probe.state(role, tuple(SAFE_PROPERTIES)) == SAFE_PROPERTIES for role in probe.names))
        checks['effective_drain_properties'] = True
        write_new(work / 'permit', b'permit-v1\n')
        stage = 'start'
        require(probe.ctl('start', 'app').returncode == 0)
        app = probe.wait(lambda: probe.ready('app')); helper = probe.wait(lambda: probe.ready('helper'))
        app_state, helper_state = probe.state('app'), probe.state('helper')
        require(all(value['ActiveState'] == 'active' and value['SubState'] == 'running'
                    and re.fullmatch(r'[1-9][0-9]*', value['MainPID']) is not None for value in (app_state, helper_state)))
        checks['application_started_inert'] = checks['helper_started_inert'] = True
        checks['application_principal_nonroot'] = app['euid'] == account.pw_uid != 0
        checks['helper_principal_nonroot'] = helper['euid'] == account.pw_uid != 0
        receipt = json.loads(read(work / 'condition-ok.json', mode=0o600, limit=4096))
        checks['condition_executed_as_root'] = receipt == {'schema_version': 1, 'root': True, 'consumed': True}
        checks['permit_consumed_once'] = (not (work / 'permit').exists()
            and read(work / 'permit-consumed', mode=0o600, limit=16) == b'consumed\n')
        require(checks['condition_executed_as_root'] and checks['permit_consumed_once'])
        stage = 'stop_pending'
        require(probe.ctl('stop', 'app').returncode == 0)
        term = probe.wait(lambda: (value if value['term_seen'] else None) if (value := probe.ready('app')) else None)
        checks['sigterm_observed'] = True
        while time.monotonic() - term['term_monotonic'] < HOLD_SECONDS:
            current = probe.state('app'); current_helper = probe.state('helper')
            require(current['ActiveState'] == 'deactivating' and current['MainPID'] == app_state['MainPID']
                    and re.fullmatch(r'[1-9][0-9]*', current['Job']) is not None
                    and current_helper['ActiveState'] == 'active' and current_helper['MainPID'] == helper_state['MainPID'])
            time.sleep(0.5)
        elapsed = time.monotonic() - term['term_monotonic']
        report['observed_hold_milliseconds'] = int(elapsed * 1000)
        checks['stop_pending_over_35_seconds'] = elapsed > 35
        app_later = probe.wait(lambda: probe.ready('app'))
        helper_later = probe.wait(lambda: probe.ready('helper'))
        checks['application_activity_continues_during_stop'] = app_later['heartbeat'] > term['heartbeat']
        checks['helper_remains_active_during_application_stop'] = (not helper_later['term_seen']
            and helper_later['heartbeat'] > helper['heartbeat'])
        checks['no_automatic_restart'] = probe.state('app')['NRestarts'] == probe.state('helper')['NRestarts'] == '0'
        stage = 'release'
        probe.release()
        probe.wait(lambda: inactive(probe.state('app')))
        released = probe.sample('app')
        checks['explicit_release_observed'] = released['release_seen'] is True
        checks['application_inactive_before_mask'] = inactive(probe.state('app'))
        stage = 'replay'
        require(probe.ctl('start', 'app').returncode == 0)
        probe.wait(lambda: inactive(probe.state('app')))
        denied = json.loads(read(work / 'condition-denied.json', mode=0o600, limit=4096))
        checks['consumed_permit_replay_refused'] = (denied == {'schema_version': 1, 'root': True, 'missing_permit': True}
            and probe.sample('app') == released and not (work / 'permit').exists())
        stage = 'mask_and_helper_stop'
        probe.mask('app'); checks['application_masked_after_exit'] = True
        require(probe.state('helper')['ActiveState'] == 'active')
        require(probe.ctl('stop', 'helper').returncode == 0)
        probe.wait(lambda: inactive(probe.state('helper')))
        checks['helper_inactive_before_mask'] = inactive(probe.state('helper'))
        probe.mask('helper'); checks['helper_masked_after_exit'] = True
        require(all(inactive(probe.state(role)) and probe.state(role)['LoadState'] == 'masked' for role in probe.names))
        marker = {'schema_version': 1, 'kind': 'poweroff-substitute', 'substituted': True, 'real_poweroff': False}
        write_new(work / 'poweroff-substitute.json', canonical(marker))
        checks['poweroff_substitute_only'] = json.loads(read(work / 'poweroff-substitute.json', mode=0o600)) == marker
        report['live_systemd_evidence'] = True
    except (Exception, KeyboardInterrupt):
        report['error_stage'] = stage
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN); signal.signal(signal.SIGINT, signal.SIG_IGN)
        if probe is not None:
            try:
                checks.update(probe.cleanup())
            except Exception:
                report['cleanup_error'] = True
        signal.signal(signal.SIGTERM, old_term); signal.signal(signal.SIGINT, old_int)
        report['passed'] = all(checks.values()) and report['error_stage'] is None and not report['cleanup_error']
        write_new(work / 'report.json', canonical(report))
    return 0 if report['passed'] else 1


def host():
    require(sys.platform == 'darwin')
    repo = Path(__file__).resolve().parents[1]
    work = repo / 'build' / ('test-access-lifecycle.' + os.urandom(4).hex())
    work.mkdir(mode=0o700)
    sources = {name: (repo / 'scripts' / name).read_bytes() for name in SOURCES}
    inputs = {'schema_version': 1, 'files': {name: sha(raw) for name, raw in sources.items()}}
    for name, raw in {**sources, 'inputs.json': canonical(inputs)}.items(): write_new(work / name, raw)
    vm = lambda *argv: ['limactl', 'shell', '--workdir=/tmp', VM, *argv]
    require(command(vm('cat', '/var/lib/inkyos-build/owner')).stdout.strip() == b'inkyos-builder-v1')
    guest = '/var/tmp/inkyos-work/' + work.name
    require(command(vm('mkdir', '-m', '700', guest)).returncode == 0)
    for name in (*SOURCES, 'inputs.json'):
        require(command(['limactl', 'copy', str(work / name), VM + ':' + guest + '/' + name], timeout=30).returncode == 0)
    seal = r'''
import hashlib,json,os,pathlib,stat,sys
p=pathlib.Path(sys.argv[1]);assert set(x.name for x in p.iterdir())=={'inputs.json','probe-test-access-lifecycle.py','probe-test-access-lifecycle-linux.sh'}
raw=(p/'inputs.json').read_bytes();assert hashlib.sha256(raw).hexdigest()==sys.argv[2]
for path in [p,*p.iterdir()]:
 info=path.lstat();assert stat.S_ISDIR(info.st_mode) if path==p else stat.S_ISREG(info.st_mode) and info.st_nlink==1
 os.chown(path,0,0,follow_symlinks=False);os.chmod(path,0o700 if path==p else 0o444,follow_symlinks=False)
for name,pin in json.loads(raw)['files'].items():assert hashlib.sha256((p/name).read_bytes()).hexdigest()==pin
'''
    require(command(vm('sudo', 'python3', '-I', '-c', seal, guest, sha(canonical(inputs)))).returncode == 0)
    run = command(vm('sudo', 'bash', guest + '/probe-test-access-lifecycle-linux.sh', guest), timeout=190)
    exported = command(vm('sudo', 'cat', guest + '/report.json'))
    require(exported.returncode == 0)
    report = json.loads(exported.stdout)
    require(type(report) is dict and set(report) == set(report_template()) and set(report['checks']) == set(CHECKS)
            and all(type(value) is bool for value in report['checks'].values())
            and report['source_sha256'] == inputs['files']
            and report['passed'] is (all(report['checks'].values()) and report['error_stage'] is None and not report['cleanup_error']))
    write_new(work / 'report.json', exported.stdout)
    require((work / 'report.json').read_bytes() == exported.stdout)
    receipt = {'schema_version': 1, 'scope': 'inert-lifecycle-probe-export', 'report_sha256': sha(exported.stdout),
        'inputs_sha256': sha(canonical(inputs)), 'probe_exit_status': run.returncode,
        'passed': report['passed'], 'cleanup_complete': all(report['checks'][name] for name in CHECKS[-4:]),
        'production_runtime_executed': False, 'hardware_qualified': False}
    write_new(work / 'receipt.json', canonical(receipt))
    print(json.dumps({'report_directory': str(work.relative_to(repo)), 'passed': report['passed'],
        'checks_passed': sum(report['checks'].values()), 'checks_total': len(CHECKS),
        'error_stage': report['error_stage'], 'cleanup_complete': receipt['cleanup_complete']}, sort_keys=True))
    return 0 if report['passed'] and run.returncode == 0 else 1


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--inside':
        sys.exit(inside(Path(sys.argv[2])))
    if len(sys.argv) == 1:
        sys.exit(host())
    raise SystemExit('Usage: probe-test-access-lifecycle.py')
