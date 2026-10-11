#!/usr/bin/env python3
"""Opt-in builder-VM fixture; never installs/starts the production unit.

Run only after the image build releases the VM:
  sudo /usr/bin/python3 -I -B staging/bootstrap/probe-initialization-linux.py --run

Requires the existing private builder marker. Uses a new root-owned directory,
one transient unit, numeric groups/UIDs (no account changes), and synthetic
authority only. Production paths and group lookup are replaced in the fixture;
all staging-unit hardening properties are retained. Leaves fixture state for
review, stops its unit, and prints only a closed summary. Not a Pi qualification.
"""
import configparser
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid

PINS = {
    'scripts/initialization-server.py': '946d8bc1823852839058389f59e90b3ae34810b7508aca069c43e40ed6084057',
    'scripts/initialization-receipt.py': '42d2e4ac0b38a3788d41dc4dd85a8df965a5c30fc88dbbfcbd6ed213c3e47de6',
    'staging/bootstrap/inkyos-initialization.service': '8119065639719473be2a22fd65cfa2a84924603cd293c578e3993e48cb1629de',
}
BUILDER = Path('/var/lib/inkyos-build')
# Numeric existing unprivileged group: systemd still resolves Group through NSS.
# No group/account is created or altered by this fixture.
GID = 65534
ID = '11111111-1111-4111-8111-111111111111'
INTENT = '22222222-2222-4222-8222-222222222222'


def require(value):
    if not value:
        raise ValueError('fixture check failed')


def command(argv, *, timeout=8, accepted=(0,)):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    require(result.returncode in accepted and len(result.stdout) <= 65536)
    return result.stdout


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def request(path, uid, *, begin=False, timeout=4):
    """Real fork/setuid peer, no inherited authority/lock descriptors."""
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            for name in os.listdir('/proc/self/fd'):
                fd = int(name)
                if fd not in {0, 1, 2, write_fd}:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            os.setgroups([GID]); os.setgid(GID); os.setuid(uid)
            deadline = time.monotonic() + timeout
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(deadline - time.monotonic()); client.connect(str(path))
                peer = struct.unpack('3i', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                require(peer[0] > 0 and peer[1] == 0)
                value = {'v': 1, 'id': ID, 'op': 'initialization.begin' if begin else 'initialization.inspect'}
                if begin:
                    value['intent'] = INTENT
                client.sendall((json.dumps(value) + '\n').encode())
                raw = b''
                while True:
                    client.settimeout(max(.001, deadline - time.monotonic()))
                    require(time.monotonic() < deadline)
                    block = client.recv(2049 - len(raw))
                    if not block:
                        break
                    raw += block
                    require(len(raw) <= 2048)
                require(raw.endswith(b'\n') and raw.count(b'\n') == 1)
                response = json.loads(raw)
                os.write(write_fd, json.dumps(response).encode())
                os.close(write_fd)
                os._exit(0)
        except BaseException:
            os._exit(2)
    os.close(write_fd)
    data = b''; deadline = time.monotonic() + timeout + .5
    try:
        while True:
            remaining = deadline - time.monotonic(); require(remaining > 0)
            ready, _, _ = select.select([read_fd], [], [], remaining); require(bool(ready))
            block = os.read(read_fd, 4097 - len(data))
            if not block:
                break
            data += block; require(len(data) <= 4096)
        # The child closes its pipe just before exit; never wait on kernel I/O.
        while True:
            child, status = os.waitpid(pid, os.WNOHANG)
            if child:
                pid = None; require(status == 0); break
            require(time.monotonic() < deadline); time.sleep(.01)
        return json.loads(data)
    finally:
        os.close(read_fd)
        if pid is not None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, os.WNOHANG)


def main():
    report = {'schema_version': 1, 'status': 'FAIL', 'checks': {},
              'synthetic_authority_only': True, 'production_paths_qualified': False,
              'writer_guard': 'explicit-fixture-substitution', 'installed_writer_guard_qualified': False,
              'production_recipe_activated': False, 'hardware_qualified': False,
              'fixture_state_preserved': False, 'unit_stopped': False,
              'unit_cgroup_empty': False}
    unit = None; unit_attempted = False; cgroup = None
    try:
        require(sys.argv[1:] == ['--run'] and sys.platform == 'linux' and os.geteuid() == 0)
        require(grp.getgrgid(GID).gr_gid == GID and grp.getgrgid(0).gr_gid == 0)
        root = Path(__file__).resolve().parents[2]
        material = {}
        for relative, pin in PINS.items():
            fd = os.open(root / relative, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                info = os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 65536)
                raw = os.read(fd, 65537)
                require(len(raw) == info.st_size and hashlib.sha256(raw).hexdigest() == pin)
                material[relative] = raw
            finally:
                os.close(fd)
        # Import only verified bytes, then use its root/ancestor guard.
        namespace = {'__name__': 'fixture_server_guard'}
        exec(compile(material['scripts/initialization-server.py'], '<pinned-server>', 'exec'), namespace)
        parent = namespace['trusted_directory'](BUILDER)
        try:
            marker = os.open('owner', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                info = os.fstat(marker)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0
                        and info.st_gid == 0 and stat.S_IMODE(info.st_mode) in {0o600, 0o644})
                require(os.read(marker, 64) == b'inkyos-builder-v1\n')
            finally:
                os.close(marker)
            unit = 'inkyos-init-probe-' + uuid.uuid4().hex[:8]
            os.mkdir(unit, 0o700, dir_fd=parent)
        finally:
            os.close(parent)
        work = BUILDER / unit
        for relative, raw in material.items():
            target = work / Path(relative).name
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
        receipt = load(work / 'initialization-receipt.py', 'fixture_receipt')
        state = work / 'authority'
        receipt.create_authorization(state)
        report['fixture_state_preserved'] = True
        runtime = Path('/run') / unit; control = runtime / 'control.sock'
        config = configparser.ConfigParser(interpolation=None); config.optionxform = str
        config.read_string(material['staging/bootstrap/inkyos-initialization.service'].decode())
        properties = dict(config['Service'])
        properties.pop('ExecStart')
        properties.update(Group=str(GID), SupplementaryGroups='0', RuntimeDirectory=unit,
                          Slice='system.slice',
                          ReadWritePaths=f'{state} {runtime}')
        bootstrap = '''import contextlib, importlib.util, pathlib, types
p=pathlib.Path(%r)
s=importlib.util.spec_from_file_location('fixture_server',p/'initialization-server.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
m.STATE=p/'authority';m.RECEIPT_SOURCE=p/'initialization-receipt.py'
m.SOCKET=pathlib.Path(%r)/'control.sock'
m.grp=types.SimpleNamespace(getgrnam=lambda name: types.SimpleNamespace(gr_gid=%d))
# This IPC wire/readiness fixture does not install or exercise a factory contract.
m.writer_guard=lambda: contextlib.nullcontext()
raise SystemExit(m.main([]))
''' % (str(work), str(runtime), GID)
        argv = ['/usr/bin/systemd-run', '--quiet', '--unit=' + unit]
        for key, value in properties.items():
            argv.append('--property=' + key + '=' + value)
        require(command(['/usr/bin/systemctl', 'show', unit, '--property=LoadState', '--value']).strip() == b'not-found')
        unit_attempted = True
        command(argv + ['/usr/bin/python3', '-I', '-B', '-c', bootstrap], timeout=12)
        def manager_ready():
            observed = dict(line.split('=', 1) for line in command([
                '/usr/bin/systemctl', 'show', unit,
                '--property=Type,NotifyAccess,ActiveState,SubState,Slice,ControlGroup',
            ]).decode().splitlines())
            require(observed == {
                'Type': 'notify', 'NotifyAccess': 'main', 'ActiveState': 'active',
                'SubState': 'running', 'Slice': 'system.slice',
                'ControlGroup': '/system.slice/' + unit + '.service',
            })
            return Path('/sys/fs/cgroup') / observed['ControlGroup'].lstrip('/')
        cgroup = manager_ready()
        report['checks']['manager_ready_after_start'] = True
        def ready():
            deadline = time.monotonic() + 5
            # A restart can preserve the old socket path. Require an actual
            # read-only response; path existence or inode changes alone do not
            # establish readiness. Never retry begin here.
            while True:
                remaining = deadline - time.monotonic(); require(remaining > 0)
                try:
                    observation = request(control, 1000, timeout=min(.5, remaining))
                    require(set(observation) == {'v', 'id', 'ok', 'result'}
                            and observation['v'] == 1 and observation['id'] == ID
                            and observation['ok'] is True)
                    namespace['validate_result']({'op': 'initialization.inspect'}, observation['result'])
                    break
                except (ValueError, OSError):
                    time.sleep(.05)
            directory = runtime.stat(); leaf = control.lstat()
            require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 0 and directory.st_gid == GID
                    and stat.S_IMODE(directory.st_mode) == 0o750)
            require(stat.S_ISSOCK(leaf.st_mode) and leaf.st_uid == 0 and leaf.st_gid == GID
                    and stat.S_IMODE(leaf.st_mode) == 0o660)
            pid = int(command(['/usr/bin/systemctl', 'show', unit, '--property=MainPID', '--value']))
            require(pid > 1)
            status = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
            require(all(int(status[name].strip(), 16) == 0 for name in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')))
            require(status['NoNewPrivs'].strip() == '1')
        ready(); report['checks']['socket_owners_modes_and_empty_capabilities'] = True
        for uid, name in ((0, 'root_refused'), (1001, 'helper_refused')):
            require(request(control, uid, begin=True) == {'v': 1, 'id': ID, 'ok': False, 'error': 'forbidden'})
            report['checks'][name] = True
        require(request(control, 1000)['result'] == {'status': 'authorized'})
        report['checks']['app_uid_admitted_without_earlier_consumption'] = True
        first = request(control, 1000, begin=True)
        require(first['ok'] is True and first['result']['status'] == 'newly_consumed')
        report['checks']['begin_durable_with_empty_capabilities'] = True
        command(['/usr/bin/systemctl', 'restart', unit], timeout=12)
        require(manager_ready() == cgroup)
        report['checks']['manager_ready_after_restart'] = True
        ready()
        require(request(control, 1000, begin=True)['result'] == {**first['result'], 'status': 'already_consumed'})
        report['checks']['same_receipt_after_service_restart'] = True
        lock = os.open(state / 'lock', os.O_RDONLY | os.O_NOFOLLOW)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            start = time.monotonic(); blocked = request(control, 1000, begin=True)
            require(time.monotonic() - start < 3.8)
            require(blocked == {'v': 1, 'id': ID, 'ok': False, 'error': 'initialization_uncertain'})
        finally:
            os.close(lock)
        report['checks']['locked_receipt_bounded_and_uncertain'] = True
        require(receipt.inspect(state)['receipt'] == first['result']['receipt'])
        report['checks']['no_duplicate_authority_after_timeout'] = True
        report['status'] = 'PASS'
    except Exception:
        report['status'] = 'FAIL'
    finally:
        if unit_attempted:
            try:
                command(['/usr/bin/systemctl', 'stop', unit])
                status = command(['/usr/bin/systemctl', 'is-active', unit], accepted=(3, 4)).strip()
                if status == b'failed':
                    command(['/usr/bin/systemctl', 'reset-failed', unit])
                    status = command(['/usr/bin/systemctl', 'is-active', unit], accepted=(3, 4)).strip()
                require(status in {b'inactive', b'unknown'})
                report['unit_stopped'] = True
                if cgroup is not None:
                    deadline = time.monotonic() + 2
                    while cgroup.exists():
                        try:
                            events = (cgroup / 'cgroup.events').read_text()
                        except FileNotFoundError:
                            require(not cgroup.exists()); break
                        if 'populated 0' in events.splitlines():
                            break
                        require(time.monotonic() < deadline); time.sleep(.02)
                    report['unit_cgroup_empty'] = True
                else:
                    report['status'] = 'FAIL'
            except Exception:
                report['status'] = 'FAIL'
        print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'PASS' and report['unit_stopped'] and report['unit_cgroup_empty'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
