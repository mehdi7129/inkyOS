#!/usr/bin/env python3
"""Opt-in PID1 test of the boot trigger, only in the marked ARM64 builder.

Usage: sudo python3 -I -B probe-factory-boot-trigger-linux.py --run TEMPLATE REPORT SHA256
Only unique /run fixture units are installed, started and removed. The five
real factory unit names are never passed to systemctl. No product code runs.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid


BUILDER = Path('/var/lib/inkyos-build')
UNITS = Path('/run/systemd/system')
REAL = {'firstboot': 'inkyos-firstboot.service',
        'supervisor': 'inkyos-factory-supervisor.service',
        'main': 'inky-studio.service'}
READY = '/run/inkyos-admission/Ready'
CASES = (('success', 0, 0, 0, None), ('supervisor_failure', 0, 78, 0, None),
         ('firstboot_failure', 1, 0, 0, None), ('ready_file', 0, 0, 0, 'file'),
         ('ready_dangling_symlink', 0, 0, 0, 'symlink'),
         ('main_failure', 0, 0, 79, None))
EVENT = b'''import json,os,sys
path,role,status=sys.argv[1:]
fd=os.open(path,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600)
try:
 os.write(fd,(json.dumps({'role':role,'exit':int(status),'pid':os.getpid()})+'\\n').encode())
 os.fsync(fd)
finally:os.close(fd)
sys.exit(int(status))
'''


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def regular(path, maximum=1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and 0 < info.st_size <= maximum, 'input_not_regular')
        raw = os.read(fd, maximum + 1)
        require(len(raw) == info.st_size, 'input_read_changed')
        return raw
    finally:
        os.close(fd)


def create(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def command(argv, *, accepted=(0,), timeout=15):
    # Control commands are constrained to this probe's unique service names.
    if argv[0] == '/usr/bin/systemctl':
        require(not any(value in REAL.values() for value in argv), 'real_service_refused')
        require(all(not value.endswith('.service') or value.startswith('inkyos-trigger-probe-')
                    for value in argv[1:]), 'unowned_service_refused')
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False)
    require(len(result.stdout) + len(result.stderr) <= 262144, 'command_output_limit')
    require(result.returncode in accepted, 'command_failed:' + str(result.returncode)
            + ':' + result.stderr.decode(errors='replace')[-1000:])
    return result


def properties(name):
    raw = command(['/usr/bin/systemctl', 'show', name,
                   '--property=LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,ControlGroup'])
    return dict(line.split('=', 1) for line in raw.stdout.decode().splitlines())


def guard():
    require(platform.system() == 'Linux' and platform.machine() == 'aarch64'
            and os.getresuid() == os.getresgid() == (0, 0, 0), 'marked_arm64_root_required')
    require(Path('/proc/1/comm').read_text() == 'systemd\n', 'real_systemd_pid1_required')
    current = Path('/')
    for part in BUILDER.parts[1:]:
        current /= part
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and not stat.S_IMODE(info.st_mode) & 0o022, 'untrusted_builder_parent')
    marker = BUILDER / 'owner'
    info = marker.lstat()
    require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) in (0o600, 0o644)
            and regular(marker, 64) == b'inkyos-builder-v1\n', 'builder_marker_required')
    info = UNITS.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and not stat.S_IMODE(info.st_mode) & 0o022, 'untrusted_runtime_unit_directory')


def payload_unit(work, role, status):
    return ('[Unit]\nDescription=Inert InkyOS trigger probe ' + role
            + '\n[Service]\nType=oneshot\nRemainAfterExit=yes\nRestart=no\n'
            + 'TimeoutStartSec=5s\nTimeoutStopSec=5s\n'
            + 'ExecStart=/usr/bin/python3 -I -B ' + str(work / 'event.py') + ' '
            + str(work / 'events.jsonl') + ' ' + role + ' ' + str(status) + '\n').encode()


def one_case(raw_template, name, firstboot, supervisor, main, ready):
    token = uuid.uuid4().hex
    prefix = 'inkyos-trigger-probe-' + token + '-'
    names = {role: prefix + role + '.service' for role in (*REAL, 'start')}
    work = Path(tempfile.mkdtemp(prefix=prefix, dir='/run'))
    work.chmod(0o700)
    installed = {}
    result = {'case': name, 'units': names, 'passed': False, 'cleanup_passed': False}
    try:
        create(work / 'event.py', EVENT)
        if ready == 'file':
            create(work / 'Ready', b'inert existing ready\n')
        elif ready == 'symlink':
            (work / 'Ready').symlink_to('absent-ready-target')
        text = raw_template.decode()
        for role, real in REAL.items():
            require(real in text, 'template_dependency_missing')
            text = text.replace(real, names[role])
        require(READY in text, 'template_ready_guard_missing')
        text = text.replace(READY, str(work / 'Ready'))
        require(not any(value in text for value in REAL.values()) and READY not in text,
                'real_name_survived_substitution')
        units = {role: payload_unit(work, role, status)
                 for role, status in (('firstboot', firstboot), ('supervisor', supervisor), ('main', main))}
        units['start'] = text.encode()
        for role, raw in units.items():
            path = UNITS / names[role]
            create(path, raw, 0o644)
            installed[path] = sha(raw)
        result['fixture_unit_sha256'] = {path.name: digest for path, digest in installed.items()}
        # Verify the exact adapted trigger plus all inert dependency units before
        # the first daemon-reload/start. This does not inspect product units.
        verify = command(['/usr/bin/systemd-analyze', 'verify', '--man=no',
                          *map(str, installed)], accepted=(0, 1))
        result['systemd_analyze_verify'] = {'exit': verify.returncode,
                                          'stderr': verify.stderr.decode(errors='replace')}
        require(verify.returncode == 0, 'fixture_unit_syntax_invalid')
        command(['/usr/bin/systemctl', 'daemon-reload'])
        started = command(['/usr/bin/systemctl', '--no-ask-password', 'start', names['start']],
                          accepted=(0, 1), timeout=20)
        result['start_exit'] = started.returncode
        result['observed_units'] = {role: properties(unit) for role, unit in names.items()}
        events = (work / 'events.jsonl').read_text().splitlines() if (work / 'events.jsonl').exists() else []
        result['events'] = [json.loads(line) for line in events]
        roles = [event['role'] for event in result['events']]
        expected = (['firstboot'] if firstboot or ready else
                    ['firstboot', 'supervisor'] if supervisor else
                    ['firstboot', 'supervisor', 'main'])
        require(roles == expected, 'event_order_or_forbidden_launch')
        require((started.returncode == 0) == (name == 'success'), 'start_exit_incorrect')
        for role, status in (('firstboot', firstboot), ('supervisor', supervisor), ('main', main)):
            if role in roles:
                require(result['observed_units'][role]['ExecMainStatus'] == str(status),
                        'inert_payload_status_mismatch')
        result['passed'] = True
    except Exception as exc:
        result['error'] = str(exc)
    finally:
        errors = []
        if installed:
            # All names belong to this invocation; no wildcard/global reset.
            try:
                command(['/usr/bin/systemctl', 'stop', *reversed(list(names.values()))], timeout=20)
                for role, unit in names.items():
                    observed = properties(unit)
                    # Inactive units can already be garbage-collected; blindly
                    # resetting them returns an error. Reset only observed
                    # failure, and still verify the terminal state afterwards.
                    if observed.get('ActiveState') == 'failed':
                        command(['/usr/bin/systemctl', 'reset-failed', unit])
                        observed = properties(unit)
                    require(observed.get('ActiveState') == 'inactive', 'fixture_still_active')
                    group = observed.get('ControlGroup', '')
                    require(not group or group == '/system.slice/' + unit, 'unexpected_fixture_cgroup')
                    if group:
                        events = Path('/sys/fs/cgroup' + group) / 'cgroup.events'
                        if events.exists():
                            require('populated 0\n' in events.read_text(), 'fixture_cgroup_populated')
            except Exception as exc:
                errors.append('stop:' + str(exc))
            try:
                for path, digest in installed.items():
                    require(sha(regular(path)) == digest, 'fixture_unit_changed_before_cleanup')
                    path.unlink()
                command(['/usr/bin/systemctl', 'daemon-reload'])
                result['cleanup_final_load_states'] = {
                    role: properties(unit)['LoadState'] for role, unit in names.items()}
                require(all(value == 'not-found' for value in result['cleanup_final_load_states'].values()),
                        'fixture_unit_still_loaded')
            except Exception as exc:
                errors.append('remove:' + str(exc))
        # Only this random private /run directory is removed.
        try:
            shutil.rmtree(work)
        except Exception as exc:
            errors.append('scratch:' + str(exc))
        result['cleanup_passed'] = not errors
        if errors:
            result['cleanup_errors'] = errors
            result['passed'] = False
    return result


def main():
    require(len(sys.argv) == 5 and sys.argv[1] == '--run', 'usage')
    # Fourth argument pins the caller's exact template; refuse before mutations.
    template, report_path, expected_sha = Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4]
    guard()
    raw = regular(template)
    require(sha(raw) == expected_sha, 'template_sha_mismatch')
    report = {'schema_version': 1, 'scope': 'native-pid1-inert-factory-boot-trigger',
              'passed': False, 'template_sha256': sha(raw),
              'probe_sha256': sha(regular(Path(__file__))),
              'event_fixture_sha256': sha(EVENT),
              'environment': {'machine': platform.machine(), 'kernel': platform.release(),
                              'systemd': command(['/usr/bin/systemd-analyze', '--version']).stdout.decode()},
              'executables_sha256': {path: sha(Path(path).read_bytes()) for path in
                                     ('/usr/bin/test', '/usr/bin/systemctl', '/usr/bin/python3')},
              'cases': [],
              'limits': ['No product service, code, native factory authority or support manifest executed.',
                         'Unit names and Ready path are substituted; all other trigger bytes retained.',
                         'The firstboot/supervisor/main payloads are inert fixtures.',
                         'No Pi, SD, Bluetooth, network provisioning, photo or reboot qualification.']}
    for case in CASES:
        result = one_case(raw, *case)
        report['cases'].append(result)
        if not result['cleanup_passed']:
            break
    report['passed'] = len(report['cases']) == len(CASES) and all(case['passed'] for case in report['cases'])
    raw_report = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode()
    create(report_path, raw_report)
    print(json.dumps({'passed': report['passed'], 'cases': len(report['cases']),
                      'report_sha256': sha(raw_report)}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
