#!/usr/bin/env python3
"""Opt-in inert factory unit fixture, only in the marked Linux builder VM.

  sudo /usr/bin/python3 -I -B staging/bootstrap/probe-factory-service-linux.py --run

Creates only new fixture paths and unique transient units. Leaves its data for
review, stops every attempted unit and requires empty cgroups. No Studio code,
app/helper service, authority, radio, device or production path is exercised.
The template is not installed and does not establish the factory writer barrier.
"""
import configparser
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import types
import uuid


BUILDER = Path('/var/lib/inkyos-build')
PUBLISHER = 'scripts/factory-credentials-publisher.py'
TEMPLATE = 'staging/bootstrap/inkyos-factory-fixture.service'
PUBLISHER_SHA = 'ae8d8898315631e4f5ed016fd21c1393073ae611137ece35c8f3fd4f9201bbfe'
TEMPLATE_SHA = '69eed59cac22e76d0e152f02a0568672f47e1f898c017199e060367da36d6d3f'
CAPS = {'CAP_CHOWN': 0, 'CAP_DAC_OVERRIDE': 1, 'CAP_KILL': 5,
        'CAP_SETGID': 6, 'CAP_SETUID': 7}
PROPERTIES = ('Type', 'TasksMax', 'EffectiveTasksMax', 'KillMode', 'Delegate',
              'NoNewPrivileges', 'PrivateDevices', 'PrivateNetwork',
              'ProtectSystem', 'ProtectHome', 'ProtectControlGroups',
              'CapabilityBoundingSet', 'AmbientCapabilities', 'ControlGroup',
              'Result', 'ActiveState', 'SubState')
CASES = (
    ('single', None, 'published'), ('fork', None, 'published'),
    ('thread', None, 'published'), ('stall', None, 'producer_timeout'),
    ('unit_timeout', None, None),
    ('single', 'CAP_CHOWN', 'publication_failed'),
    ('single', 'CAP_DAC_OVERRIDE', 'data_unavailable'),
    ('single', 'CAP_SETUID', 'producer_failed'),
    ('single', 'CAP_SETGID', 'producer_failed'),
    ('stall', 'CAP_KILL', 'producer_unreaped'),
)


def require(value):
    if not value:
        raise ValueError('fixture_check_failed')


def command(argv, *, timeout=12, accepted=(0,)):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    require(result.returncode in accepted and len(result.stdout) <= 65536)
    return result.stdout


def regular(path, maximum=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and 0 < info.st_size <= maximum)
        raw = os.read(fd, maximum + 1)
        require(len(raw) == info.st_size)
        return raw
    finally:
        os.close(fd)


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)


def control(path):
    """Bounded read of cgroup pseudo-files, whose stat size is normally zero."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode))
        raw = os.read(fd, 4097)
        require(0 < len(raw) <= 4096)
        return raw
    finally:
        os.close(fd)


def trusted_builder():
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in ('', *BUILDER.parts[1:]):
            if part:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=fd)
                os.close(fd); fd = child
            info = os.fstat(fd)
            require(info.st_uid == 0 and info.st_gid == 0
                    and not stat.S_IMODE(info.st_mode) & 0o022)
        marker = os.open('owner', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            info = os.fstat(marker)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and info.st_uid == info.st_gid == 0
                    and stat.S_IMODE(info.st_mode) in {0o600, 0o644}
                    and os.read(marker, 64) == b'inkyos-builder-v1\n')
        finally:
            os.close(marker)
        return fd
    except BaseException:
        os.close(fd)
        raise


def properties(unit):
    raw = command(['/usr/bin/systemctl', 'show', unit,
                   '--property=' + ','.join(PROPERTIES)])
    return dict(line.split('=', 1) for line in raw.decode().splitlines())


def group_path(value):
    require(value.startswith('/system.slice/inkyos-factory-probe-')
            and '..' not in Path(value).parts and '\n' not in value)
    return Path('/sys/fs/cgroup') / value.lstrip('/')


def empty_group(path):
    if not path.exists():
        return True
    try:
        raw = control(path / 'cgroup.events')
    except FileNotFoundError:
        return not path.exists()
    events = dict(line.split() for line in raw.decode().splitlines())
    return events['populated'] == '0'


def stop_unit(unit, group):
    command(['/usr/bin/systemctl', 'stop', unit], accepted=(0, 5))
    raw = command(['/usr/bin/systemctl', 'is-active', unit], accepted=(3, 4)).strip()
    if raw == b'failed':
        command(['/usr/bin/systemctl', 'reset-failed', unit])
        raw = command(['/usr/bin/systemctl', 'is-active', unit], accepted=(3, 4)).strip()
    require(raw in {b'inactive', b'unknown'})
    deadline = time.monotonic() + 3
    while not empty_group(group):
        require(time.monotonic() < deadline); time.sleep(.02)


def producer_code(mode):
    # Only fixture booleans cross stdout; no generated key or personal data.
    common = '''import errno,json,os,signal,threading,time
s=dict(line.split(':',1) for line in open('/proc/self/status') if ':' in line)
out={'uid1000':os.getresuid()==(1000,1000,1000),
     'gid1000':os.getresgid()==(1000,1000,1000),'groups_empty':os.getgroups()==[],
     'no_new_privs':s['NoNewPrivs'].strip()=='1',
     'capabilities_dropped':all(int(s[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapInh','CapAmb')),
     'single_task':len(os.listdir('/proc/self/task'))==1}
'''
    if mode == 'fork':
        common += '''try:
 child=os.fork()
except OSError as error:
 out['fork_refused']=error.errno==errno.EAGAIN
else:
 if child==0:os._exit(0)
 os.waitpid(child,0);out['fork_refused']=False
'''
    if mode == 'thread':
        common += '''task=threading.Thread(target=lambda:None)
try:
 task.start()
except RuntimeError:
 out['thread_refused']=True
else:
 task.join();out['thread_refused']=False
'''
    common += "os.write(1,(json.dumps(out,sort_keys=True)+'\\n').encode())\n"
    if mode in {'stall', 'unit_timeout'}:
        common += "signal.signal(signal.SIGTERM,signal.SIG_IGN)\nwhile True:time.sleep(.1)\n"
    return common


def worker(work, mode, omitted):
    """Runs only in the transient unit, imports pinned OS code under root."""
    raw = regular(work.parent / 'publisher.py')
    require(hashlib.sha256(raw).hexdigest() == PUBLISHER_SHA)
    publisher = types.ModuleType('inert_factory_publisher')
    exec(compile(raw, '<pinned-publisher>', 'exec'), publisher.__dict__)
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    expected_caps = sum(1 << bit for name, bit in CAPS.items() if name != omitted)
    require(os.getuid() == 0 and int(status['CapEff'].strip(), 16) == expected_caps
            and int(status['CapBnd'].strip(), 16) == expected_caps
            and status['NoNewPrivs'].strip() == '1')
    baseline = json.loads(regular(work.parent / 'namespaces.json'))
    require(os.readlink('/proc/self/ns/net') != baseline['net']
            and os.stat('/dev').st_dev != baseline['dev'])
    try:
        with (work / 'read-only-canary').open('wb'):
            pass
    except OSError as error:
        require(error.errno == errno.EROFS)
    else:
        raise ValueError('fixture_readonly_failed')
    require(not list(Path('/dev').glob('spidev*')))
    actual_group = Path('/proc/self/cgroup').read_text().strip().split(':', 2)[2]
    cg = group_path(actual_group)
    require(control(cg / 'pids.max').strip() == b'2')
    initial_max = int(dict(line.split() for line in control(cg / 'pids.events').decode().splitlines())['max'])
    write_new(work / 'out' / 'started.json',
              json.dumps({'started': True, 'control_group': actual_group}).encode())
    calls = []

    def spawn(argv, **options):
        require(tuple(argv) == publisher.ARGV and options['user'] == options['group'] == 1000
                and options['extra_groups'] == [] and options['start_new_session'] is True)
        process = subprocess.Popen(['/usr/bin/python3', '-I', '-B', '-c', producer_code(mode)], **options)
        calls.append(process)
        return process

    result = None
    try:
        publisher.publish(_root=work / 'root', _app_uid=1000, _app_gid=1000,
                          _timeout=30 if mode == 'unit_timeout' else 1.5, _spawn=spawn)
        result = 'published'
    except publisher.PublisherError as error:
        result = error.code
    if mode == 'unit_timeout':
        raise ValueError('unit_timeout_not_observed')
    if result == 'published':
        data = work / 'root' / publisher.DATA / publisher.NAME
        decoded = json.loads(regular(data))
        require(decoded and all(value is True for value in decoded.values()))
        info = data.stat()
        require(info.st_uid == info.st_gid == 1000 and stat.S_IMODE(info.st_mode) == 0o600)
    if mode in {'fork', 'thread'}:
        maximum = int(dict(line.split() for line in control(cg / 'pids.events').decode().splitlines())['max'])
        require(maximum > initial_max)
    if omitted != 'CAP_KILL':
        require(all(process.poll() is not None for process in calls))
    report = {'result': result, 'parent_capabilities_exact': True,
              'network_namespace_private': True, 'device_namespace_private': True,
              'filesystem_readonly_observed': True, 'pids_max_two_observed': True,
              'spawn_count': len(calls)}
    write_new(work / 'out' / 'result.json', (json.dumps(report, sort_keys=True) + '\n').encode())


def worker_entry(work, mode, omitted):
    """Keep only closed fixture diagnostics when a sandbox assertion fails."""
    try:
        worker(work, mode, omitted)
    except Exception as error:
        trace = error.__traceback__
        lines = []
        while trace is not None:
            if trace.tb_frame.f_code.co_filename == __file__:
                lines.append(trace.tb_lineno)
            trace = trace.tb_next
        status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        diagnostic = {'fixture_lines': lines, 'uid': os.getuid(),
                      'effective_capabilities': int(status['CapEff'].strip(), 16),
                      'bounding_capabilities': int(status['CapBnd'].strip(), 16),
                      'no_new_privs': status['NoNewPrivs'].strip() == '1'}
        write_new(work / 'out' / 'failure.json', json.dumps(diagnostic).encode())
        raise


def main():
    report = {'schema_version': 1, 'scope': 'factory-service-inert-linux-fixture',
              'status': 'FAIL', 'checks': {}, 'cases': [], 'all_units_stopped': False,
              'fixture_state_preserved': False, 'production_recipe_activated': False,
              'writer_barrier_qualified': False, 'candidate_qualified': False,
              'real_serializer_executed': False, 'hardware_qualified': False}
    attempted = []; cleanup_ok = True
    try:
        require(sys.argv[1:] == ['--run'] and sys.platform == 'linux' and os.geteuid() == 0
                and 'pids' in control(Path('/sys/fs/cgroup/cgroup.controllers')).decode().split())
        source = Path(__file__).resolve().parents[2]
        raw_publisher = regular(source / PUBLISHER)
        require(hashlib.sha256(raw_publisher).hexdigest() == PUBLISHER_SHA)
        raw_template = regular(source / TEMPLATE)
        require(hashlib.sha256(raw_template).hexdigest() == TEMPLATE_SHA)
        config = configparser.ConfigParser(interpolation=None); config.optionxform = str
        config.read_string(raw_template.decode()); base_properties = dict(config['Service'])
        require(base_properties.pop('ExecStart') == '/usr/bin/false'
                and base_properties['TasksMax'] == '2'
                and base_properties['CapabilityBoundingSet'].split() == list(CAPS))
        parent = trusted_builder()
        name = 'inkyos-factory-probe-' + uuid.uuid4().hex[:8]
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
        finally:
            os.close(parent)
        work = BUILDER / name
        write_new(work / 'probe.py', regular(Path(__file__)), 0o400)
        write_new(work / 'publisher.py', raw_publisher, 0o400)
        write_new(work / 'unit.service', raw_template, 0o400)
        write_new(work / 'namespaces.json', json.dumps({'net': os.readlink('/proc/self/ns/net'),
                                                       'dev': os.stat('/dev').st_dev}).encode())
        report['fixture_state_preserved'] = True
        report['source_pins'] = {PUBLISHER: PUBLISHER_SHA, TEMPLATE: hashlib.sha256(raw_template).hexdigest(),
                                 'staging/bootstrap/probe-factory-service-linux.py': hashlib.sha256(regular(Path(__file__))).hexdigest()}
        for index, (mode, omitted, expected) in enumerate(CASES):
            unit = name + '-' + str(index) + '.service'
            case = work / str(index); case.mkdir(mode=0o700)
            for relative in ('out', 'root', 'root/var', 'root/var/lib', 'root/var/lib/inky-studio'):
                (case / relative).mkdir(mode=0o700)
            data = case / 'root/var/lib/inky-studio'; os.chown(data, 1000, 1000)
            write_new(case / 'read-only-canary', b'fixture\n')
            require(command(['/usr/bin/systemctl', 'show', unit, '--property=LoadState', '--value']).strip() == b'not-found')
            props = dict(base_properties)
            props.update(ReadWritePaths=f'{data} {case / "out"}')
            if omitted:
                props['CapabilityBoundingSet'] = ' '.join(cap for cap in CAPS if cap != omitted)
            bootstrap = ('import runpy,pathlib; m=runpy.run_path(%r,run_name="fixture_module");'
                         'm["worker_entry"](pathlib.Path(%r),%r,%r)') % (str(work / 'probe.py'), str(case), mode, omitted)
            argv = ['/usr/bin/systemd-run', '--quiet', '--no-block', '--unit=' + unit]
            argv += ['--property=' + key + '=' + value for key, value in props.items()]
            group = Path('/sys/fs/cgroup/system.slice') / unit
            attempted.append((unit, group))
            command(argv + ['/usr/bin/python3', '-I', '-B', '-c', bootstrap])
            deadline = time.monotonic() + 12
            while True:
                observed = properties(unit)
                if observed['ActiveState'] == 'failed' or observed['SubState'] == 'exited':
                    break
                require(time.monotonic() < deadline); time.sleep(.03)
            require(observed['TasksMax'] == observed['EffectiveTasksMax'] == '2'
                    and observed['KillMode'] == 'control-group'
                    and observed['Delegate'] == 'no'
                    and observed['NoNewPrivileges'] == 'yes'
                    and observed['PrivateDevices'] == observed['PrivateNetwork'] == 'yes'
                    and observed['ProtectSystem'] == 'strict'
                    and observed['ProtectHome'] == 'read-only')
            expected_group = '/system.slice/' + unit
            started = json.loads(regular(case / 'out/started.json'))
            require(started == {'started': True, 'control_group': expected_group}
                    and observed['ControlGroup'] in {'', expected_group})
            # systemd may remove an empty failed-unit cgroup before this poll.
            # The worker's kernel path binds cleanup even when show is empty.
            require(group_path(started['control_group']) == group)
            if mode == 'unit_timeout':
                require(observed['Result'] == 'timeout' and (case / 'out/started.json').is_file()
                        and not (case / 'out/result.json').exists() and not (data / 'credentials.json').exists())
            else:
                require(observed['Result'] == 'success')
                result = json.loads(regular(case / 'out/result.json'))
                require(result['result'] == expected)
            stop_unit(unit, group)
            report['cases'].append({'mode': mode, 'omitted_capability': omitted,
                                    'expected_result_observed': True, 'cgroup_empty_after_stop': True})
        report['checks'] = {'single_task_publishes': True, 'fork_refused_by_pids_controller': True,
                            'thread_refused_by_pids_controller': True, 'publisher_timeout_reaps': True,
                            'unit_timeout_kills_ignoring_child': True, 'each_capability_usage_observed': True,
                            'sandbox_observed': True}
        report['status'] = 'PASS'
    except Exception:
        report['status'] = 'FAIL'
    finally:
        for unit, group in attempted:
            try:
                stop_unit(unit, group)
            except Exception:
                cleanup_ok = False
        report['all_units_stopped'] = bool(attempted) and cleanup_ok
        if not report['all_units_stopped']:
            report['status'] = 'FAIL'
        print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
