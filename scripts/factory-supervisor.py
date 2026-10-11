#!/usr/bin/env python3
"""Fixed factory supervisor entry point; installation/activation is separate.

The EX owner runs outside the disposable worker cgroup. No CLI argument can
select a rootfs, producer, hook, unit properties or candidate overlay.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time


RUNTIME = Path('/usr/lib/inkyos/factory-runtime-contract.py')
SUPERVISOR = '/usr/lib/inkyos/factory-supervisor.py'
HOOK = '/usr/local/lib/inkyos/factory-authority.py'
OUTPUT_DIRECTORY = Path('/run/inkyos-factory-output')
OUTPUT = OUTPUT_DIRECTORY / 'worker-result.json'
PREPARE_UNIT = 'inkyos-admission-prepare.service'
SUPERVISOR_UNIT = 'inkyos-factory-supervisor.service'
GROUP_ROOT = Path('/sys/fs/cgroup')
PROPERTIES = ('LoadState', 'ActiveState', 'SubState', 'Result', 'ExecMainCode',
              'ExecMainStatus', 'ControlGroup', 'Type', 'RemainAfterExit',
              'Restart', 'TasksMax', 'EffectiveTasksMax', 'KillMode', 'Delegate',
              'NoNewPrivileges', 'PrivateDevices', 'PrivateNetwork',
              'ProtectSystem', 'ProtectControlGroups')
EXPECTED = {'Type': 'oneshot', 'RemainAfterExit': 'yes', 'Restart': 'no',
            'TasksMax': '2', 'EffectiveTasksMax': '2', 'KillMode': 'control-group',
            'Delegate': 'no', 'NoNewPrivileges': 'yes', 'PrivateDevices': 'yes',
            'PrivateNetwork': 'yes', 'ProtectSystem': 'strict',
            'ProtectControlGroups': 'yes'}
HOOK_RESULTS = ({'status': 'created', 'authority_status': 'authorized'},
                {'status': 'existing', 'authority_status': 'authorized'},
                {'status': 'existing', 'authority_status': 'consumed'})
ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}


class Refused(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def require(value, reason='invalid_state'):
    if not value:
        raise Refused(reason)


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_regular(path, maximum, mode):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_uid == before.st_gid == 0
            and stat.S_IMODE(before.st_mode) == mode and before.st_size <= maximum)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(stamp(os.fstat(fd)) == stamp(before) and not os.listxattr(fd))
        raw = os.read(fd, maximum + 1)
        require(len(raw) == before.st_size and stamp(os.fstat(fd)) == stamp(before)
                == stamp(path.lstat()))
        return raw
    finally:
        os.close(fd)


def load_runtime():
    require(sys.platform == 'linux' and os.geteuid() == os.getegid() == 0,
            'runtime_unavailable')
    require(callable(getattr(os, 'listxattr', None)), 'runtime_unavailable')
    for entry in reversed(RUNTIME.parents):
        info = entry.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and not stat.S_IMODE(info.st_mode) & 0o7022
                and not os.listxattr(entry, follow_symlinks=False))
    raw = read_regular(RUNTIME, 1024 * 1024, 0o555)
    spec = importlib.util.spec_from_file_location('_inkyos_factory_contract', RUNTIME)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    exec(compile(raw, str(RUNTIME), 'exec'), module.__dict__)
    return module


def worker_unit(context):
    digest = hashlib.sha256(context['boot_id'].encode('ascii')).hexdigest()[:16]
    return 'inkyos-factory-worker-' + digest + '.service'


def current_group():
    raw = Path('/proc/self/cgroup').read_text(encoding='ascii')
    lines = raw.splitlines()
    require(len(lines) == 1 and lines[0].startswith('0::'), 'wrong_cgroup')
    return lines[0][3:]


def validate_hook(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 512 and raw.isascii()
            and raw.endswith(b'\n') and raw.count(b'\n') == 1, 'worker_result_invalid')
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'worker_result_invalid'); result[key] = value
        return result
    def invalid(_):
        raise Refused('worker_result_invalid')
    try:
        result = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    except (UnicodeError, ValueError, RecursionError):
        raise Refused('worker_result_invalid') from None
    require(type(result) is dict and result in HOOK_RESULTS, 'worker_result_invalid')
    return result


def create_output():
    # No PID1 RuntimeDirectory: these writes occur only after EX + attempted.
    os.mkdir(OUTPUT_DIRECTORY, 0o700)
    parent = os.open(OUTPUT_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(parent)
        require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700
                and not os.listxattr(parent))
        fd = os.open(OUTPUT.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        try:
            require(os.fstat(fd).st_uid == os.fstat(fd).st_gid == 0)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)


class Manager:
    """Only fixed PID1 commands; the admission FD is never passed to children."""
    def command(self, argv, *, accepted=(0,), timeout=5):
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, env=ENVIRONMENT,
                                   close_fds=True)
        selector = selectors.DefaultSelector()
        raw = bytearray(); deadline = time.monotonic() + timeout
        try:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, 'manager_unavailable')
                for key, _ in selector.select(min(remaining, .1)):
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        raw.extend(chunk)
                        require(len(raw) <= 65536, 'manager_unavailable')
            require(process.wait(timeout=max(.001, deadline - time.monotonic())) in accepted,
                    'manager_unavailable')
            return bytes(raw)
        except (OSError, subprocess.SubprocessError):
            raise Refused('manager_unavailable') from None
        finally:
            selector.close()
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()

    def inspect(self, unit):
        raw = self.command(['/usr/bin/systemctl', 'show', unit,
                            '--property=' + ','.join(PROPERTIES)])
        try:
            rows = [line.split('=', 1) for line in raw.decode('ascii').splitlines()]
            require(all(len(row) == 2 for row in rows)
                    and len({row[0] for row in rows}) == len(rows))
            result = dict(rows)
            require(set(result) == set(PROPERTIES))
            return result
        except (UnicodeError, ValueError):
            raise Refused('manager_unavailable') from None

    def empty(self, unit):
        path = GROUP_ROOT / 'system.slice' / unit
        try:
            fd = os.open(path / 'cgroup.events', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return not path.exists()
        try:
            require(stat.S_ISREG(os.fstat(fd).st_mode))
            raw = os.read(fd, 4097)
            require(0 < len(raw) <= 4096)
        finally:
            os.close(fd)
        try:
            rows = [line.split() for line in raw.decode('ascii').splitlines()]
            require(all(len(row) == 2 for row in rows)
                    and len({row[0] for row in rows}) == len(rows))
            events = dict(rows)
            require(events.get('populated') in {'0', '1'})
            return events['populated'] == '0'
        except (UnicodeError, ValueError):
            raise Refused('cgroup_unavailable') from None

    def assert_group(self, unit):
        require(current_group() == '/system.slice/' + unit, 'wrong_cgroup')

    def create_output(self):
        create_output()

    def result(self):
        return read_regular(OUTPUT, 512, 0o600)

    def start(self, unit, candidate_sha256):
        require(re.fullmatch(r'inkyos-factory-worker-[a-f0-9]{16}\.service', unit)
                and re.fullmatch(r'[a-f0-9]{64}', candidate_sha256))
        properties = {
            **EXPECTED, 'Description': 'InkyOS isolated factory worker',
            'UMask': '0077', 'TimeoutStartSec': '120s', 'TimeoutStopSec': '1s',
            'SendSIGKILL': 'yes', 'StandardInput': 'null', 'StandardError': 'null',
            'StandardOutput': 'append:' + str(OUTPUT), 'LimitFSIZE': '8192',
            'LimitCORE': '0', 'PrivateTmp': 'yes', 'ProtectHome': 'read-only',
            'ProtectClock': 'yes', 'ProtectKernelTunables': 'yes',
            'ProtectKernelModules': 'yes', 'ProtectKernelLogs': 'yes',
            'RestrictAddressFamilies': 'AF_UNIX', 'RestrictNamespaces': 'yes',
            'RestrictSUIDSGID': 'yes', 'LockPersonality': 'yes',
            'CapabilityBoundingSet': 'CAP_CHOWN CAP_DAC_OVERRIDE CAP_KILL CAP_SETGID CAP_SETUID',
            'AmbientCapabilities': '',
            'ReadWritePaths': '/var/lib/inkyos /var/lib/inky-studio',
            'Environment': 'HOME=/home/inky PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 '
                           'INKY_STUDIO_FACTORY_REQUIRED=1 INKY_STUDIO_DATA_DIR=/var/lib/inky-studio',
            'UnsetEnvironment': 'LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG LD_PROFILE LD_ORIGIN_PATH '
                                'GLIBC_TUNABLES GCONV_PATH LOCPATH PYTHONPATH PYTHONHOME PYTHONUSERBASE '
                                'OPENSSL_CONF OPENSSL_CONF_INCLUDE OPENSSL_MODULES OPENSSL_ENGINES',
            'ExecStartPre': '/usr/bin/python3.13 -I -B -S ' + SUPERVISOR +
                            ' --worker-preflight ' + unit + ' ' + candidate_sha256,
        }
        properties.pop('EffectiveTasksMax')
        self.command(['/usr/bin/systemd-run', '--quiet', '--no-block', '--unit=' + unit]
                     + ['--property=' + key + '=' + value for key, value in properties.items()]
                     + ['/usr/bin/python3.13', '-I', '-B', '-S', HOOK])

    def stop(self, unit):
        self.command(['/usr/bin/systemctl', 'stop', '--no-block', unit], accepted=(0, 5))


def prepare_boot(runtime, manager):
    manager.assert_group(PREPARE_UNIT)
    contract = runtime.load_contract()
    runtime.prepare_boot_context(contract)
    admission = runtime.import_admission(contract)
    admission.prepare(Path('/'))
    return {'status': 'admission_prepared'}


def check_worker_properties(observed, unit):
    require(observed['LoadState'] == 'loaded'
            and observed['ControlGroup'] in {'', '/system.slice/' + unit}
            and all(observed[key] == value for key, value in EXPECTED.items()),
            'worker_properties_invalid')


def quiescent(manager, unit):
    observed = manager.inspect(unit)
    terminal = observed['LoadState'] == 'not-found' or (
        observed['ActiveState'] in {'inactive', 'failed'}
        and observed['SubState'] in {'dead', 'failed'})
    require(observed['ControlGroup'] in {'', '/system.slice/' + unit})
    return terminal and manager.empty(unit)


def drain(manager, unit, sleep):
    # Caller still owns EX. No deadline can release it while a descendant may
    # write; stop replies alone do not establish quiescence.
    while True:
        try:
            manager.stop(unit)
            if quiescent(manager, unit):
                return
        except Exception:
            pass
        sleep(.2)


def worker_preflight(runtime, manager, unit, candidate_sha256):
    contract = runtime.load_contract()
    require(type(candidate_sha256) is str and re.fullmatch(r'[a-f0-9]{64}', candidate_sha256)
            and candidate_sha256 == contract.candidate_sha256, 'candidate_changed')
    context = runtime.validate_context(contract)
    require(unit == worker_unit(context), 'wrong_cgroup')
    manager.assert_group(unit)
    runtime.verify_candidate(contract)
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines()
                  if ':' in line)
    require(os.getresuid() == os.getresgid() == (0, 0, 0)
            and all(int(status[key].strip(), 16) == 0xe3 for key in ('CapEff', 'CapPrm', 'CapBnd'))
            and all(int(status[key].strip(), 16) == 0 for key in ('CapInh', 'CapAmb'))
            and status['NoNewPrivs'].strip() == '1', 'worker_properties_invalid')
    group = GROUP_ROOT / 'system.slice' / unit
    require((group / 'pids.max').read_text().strip() == '2'
            and not manager.empty(unit), 'worker_properties_invalid')
    require(not list(Path('/dev').glob('spidev*')), 'worker_properties_invalid')
    for path in ('/usr/lib/inkyos', '/usr/local/lib/inkyos', '/etc/inkyos'):
        require(os.statvfs(path).f_flag & os.ST_RDONLY, 'worker_properties_invalid')
    runtime.validate_context(contract)


def run_factory(runtime, manager, *, _clock=time.monotonic, _sleep=time.sleep,
                _stopped=lambda: False):
    manager.assert_group(SUPERVISOR_UNIT)
    contract = runtime.load_contract()
    context = runtime.validate_context(contract)
    admission = runtime.import_admission(contract)
    unit = worker_unit(context)
    with admission.factory(Path('/')) as lease:
        runtime.verify_candidate(contract)
        require(not _stopped(), 'interrupted')
        observed = manager.inspect(unit)
        require(observed['LoadState'] == 'not-found' and manager.empty(unit),
                'worker_preexisting')
        manager.create_output()
        started = False; successful = False; failure = 'worker_failed'; hook_raw = None
        try:
            require(not _stopped(), 'interrupted')
            # A failed start reply may still mean PID1 admitted the worker.
            started = True
            manager.start(unit, contract.candidate_sha256)
            deadline = _clock() + 150
            while True:
                require(not _stopped(), 'interrupted')
                observed = manager.inspect(unit)
                check_worker_properties(observed, unit)
                if observed['ActiveState'] == 'failed':
                    raise Refused('worker_failed')
                if observed['ActiveState'] == 'active' and observed['SubState'] == 'exited':
                    require(observed['ExecMainCode'] == '1' and observed['ExecMainStatus'] == '0'
                            and observed['Result'] == 'success', 'worker_failed')
                    hook_raw = manager.result()
                    validate_hook(hook_raw)
                    successful = True
                    break
                require(_clock() < deadline, 'worker_timeout')
                _sleep(.05)
        except Exception as exc:
            failure = exc.reason if isinstance(exc, Refused) else 'execution_unconfirmed'
        finally:
            if started:
                drain(manager, unit, _sleep)
        require(successful and not _stopped(), failure if not successful else 'interrupted')
        require(manager.result() == hook_raw, 'worker_result_invalid')
        runtime.verify_candidate(contract)
        require(runtime.validate_context(contract) == context, 'context_changed')
        lease.check()
        require(not _stopped(), 'interrupted')
        try:
            drained = quiescent(manager, unit)
        except Exception:
            drained = False
        if not drained:
            drain(manager, unit, _sleep)
            raise Refused('cgroup_unavailable')
        require(not _stopped(), 'interrupted')
        lease.publish_ready()
    return {'status': 'factory_complete'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--prepare-boot', action='store_true')
    group.add_argument('--run', action='store_true')
    group.add_argument('--worker-preflight', metavar=('BOOT_UNIT', 'SHA256'), nargs=2)
    args = parser.parse_args(argv)
    stopped = [False]
    def stop(_signum, _frame):
        stopped[0] = True
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, stop)
    try:
        runtime = load_runtime(); manager = Manager()
        if args.prepare_boot:
            result = prepare_boot(runtime, manager)
        elif args.worker_preflight:
            worker_preflight(runtime, manager, *args.worker_preflight)
            return 0  # stdout belongs exclusively to the hook.
        else:
            result = run_factory(runtime, manager, _stopped=lambda: stopped[0])
    except Exception as exc:
        if not args.worker_preflight:
            allowed = {'busy', 'already_ready', 'recovery_required', 'publication_uncertain',
                       'invalid_state', 'runtime_unavailable', 'wrong_cgroup', 'interrupted',
                       'worker_preexisting', 'worker_failed', 'worker_timeout',
                       'worker_result_invalid', 'worker_properties_invalid',
                       'manager_unavailable', 'execution_unconfirmed', 'context_changed',
                       'candidate_changed', 'cgroup_unavailable'}
            reason = getattr(exc, 'reason', None)
            print(json.dumps({'status': 'refused',
                              'error': reason if reason in allowed else 'factory_supervisor_refused'},
                             sort_keys=True))
        return 78
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
