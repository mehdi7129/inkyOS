#!/usr/bin/env bash
# Real SSH/PAM/sudo on a disposable image copy; the privileged runner is inert.
set -Eeuo pipefail
umask 077
if [[ ${1:-} == --help && $# == 1 ]]; then
  echo 'Usage: sudo bash probe-test-ssh-linux.sh /var/tmp/inkyos-work/test-ssh-probe.XXXXXXXX'
  echo 'Root-owned 0700 staging: this script (0444), probe.img (0600), parent-manifest.json,'
  echo 'parent-manifest.sha256, parent-filesystem-manifest.json, parent-integrity.json (0444).'
  echo 'Consumes only the disposable image copy. Produces report.json; no Pi/SD or existing SSH keys.'
  exit 0
fi
[[ $# == 1 && $(uname -s) == Linux && $(uname -m) == aarch64 && $EUID == 0 ]] || {
  echo 'SSH probe requires root in the marked ARM64 build VM and one disposable staging directory.' >&2; exit 2;
}
[[ $(cat /var/lib/inkyos-build/owner) == inkyos-builder-v1 ]] || exit 2
work=$(readlink -e -- "$1")
[[ $work == "$1" && $work =~ ^/var/tmp/inkyos-work/test-ssh-probe\.[A-Za-z0-9]{8}$ ]] || exit 2
[[ $(readlink -e -- "$0") == "$work/probe-test-ssh-linux.sh" ]] || {
  echo 'Execute only the reviewed script copy inside the sealed staging directory.' >&2; exit 2;
}
for tool in unshare timeout ip hostname losetup lsblk blkid mount umount findmnt python3 chroot; do
  command -v "$tool" >/dev/null || { echo 'A required VM probe utility is missing.' >&2; exit 2; }
done
if [[ ${INKYOS_TEST_SSH_NAMESPACE:-} != 1 ]]; then
  # PID namespace teardown kills sshd descendants even if its monitor forks or
  # creates a session. Keep the VM's /proc view here for namespace comparisons.
  exec timeout --signal=TERM --kill-after=40s 180s \
    unshare --mount --net --uts --pid --fork --kill-child=KILL --propagation private \
    env INKYOS_TEST_SSH_NAMESPACE=1 bash "$0" "$work"
fi
for namespace in mnt net uts pid; do
  [[ $(readlink "/proc/self/ns/$namespace") != $(readlink "/proc/1/ns/$namespace") ]] || exit 2
done
[[ $(findmnt -n -o PROPAGATION /) == private ]] || exit 2
cd "$work"
python3 -I - "$work" <<'PY_PROBE'
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import time


# One reviewed candidate only. Replace BOTH constants when the final candidate
# arrives; this transport probe is not an application release registry.
EXACT_SOURCE = '758a2bf7ed099aad41ef35316e53228e797b0b2b'
EXACT_MANIFEST = '0d587792433d924ad1c4e71af19c2a46279f573791cb690571fa1019e7703551'
USER = 'inky-test'
DISPATCH_PATH = '/usr/local/lib/inkyos/test-lan-ssh-dispatch.py'
RUNNER_PATH = '/usr/local/lib/inkyos/test-lan-runner'
RUNTIME = '/run/inkyos-test-ssh'
SUDOERS = 'inky-test ALL=(root) NOPASSWD: /usr/local/lib/inkyos/test-lan-runner ""\n'
INPUTS = {'probe-test-ssh-linux.sh', 'probe.img', 'parent-manifest.json',
          'parent-manifest.sha256', 'parent-filesystem-manifest.json', 'parent-integrity.json'}
PROGRAMS = (
    'usr/sbin/sshd', 'usr/bin/ssh', 'usr/bin/ssh-keygen', 'usr/bin/scp',
    'usr/bin/sudo', 'usr/sbin/visudo', 'etc/pam.d/sshd', 'etc/pam.d/common-auth',
    'etc/pam.d/common-account', 'etc/pam.d/common-session',
    'usr/lib/aarch64-linux-gnu/security/pam_unix.so',
)
PACKAGES = ('openssh-server', 'openssh-client', 'libpam0g', 'libpam-modules', 'libpam-runtime', 'sudo', 'passwd')
CHECKS = (
    'parent_bytes_pinned', 'private_namespaces', 'loopback_only', 'no_new_privileges_unset',
    'target_programs_match_parent_inventory', 'target_sudo_is_setuid', 'dedicated_account_locked_unaged',
    'root_public_key_readable', 'effective_sshd_restrictions', 'sudoers_syntax', 'sudo_listing_exact',
    'key_preflight', 'key_activate_stub', 'key_stop_stub', 'wrong_key_refused', 'root_login_refused',
    'password_method_not_offered', 'keyboard_interactive_not_offered',
    'shell_refused', 'sftp_refused', 'scp_sftp_refused', 'scp_legacy_refused',
    'command_arguments_refused', 'command_injection_refused', 'request_schema_refused',
    'direct_tcpip_channel_refused', 'remote_forward_refused', 'tunnel_channel_refused', 'tty_refused',
    'nologin_prevents_dispatch', 'expired_password_prevents_dispatch', 'restored_account_key_works',
    'sudo_zero_arguments_only', 'sudo_other_commands_refused', 'application_still_masked',
    'processes_stopped', 'mounts_removed', 'loop_detached', 'disposable_image_removed',
)


DISPATCHER = r'''#!/usr/bin/python3 -I
import json, os, select, subprocess, sys, time

def pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError('duplicate field')
        value[key] = item
    return value

def operation(command):
    if command not in ('preflight', 'activate', 'stop'):
        raise ValueError('unsupported command')
    return command

def request(raw):
    if not raw or len(raw) > 4096:
        raise ValueError('request size')
    value = json.loads(raw, object_pairs_hook=pairs)
    if value != {'schema_version': 1} or type(value.get('schema_version')) is not int:
        raise ValueError('request schema')
    return value

def receive(fd):
    deadline = time.monotonic() + 5
    raw = b''
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise ValueError('request timeout')
        chunk = os.read(fd, min(4097 - len(raw), 1024))
        if not chunk:
            return request(raw)
        raw += chunk
        if len(raw) > 4096:
            raise ValueError('request size')

def main():
    try:
        verb = operation(os.environ.get('SSH_ORIGINAL_COMMAND', ''))
        payload = {'schema_version': 1, 'operation': verb, 'request': receive(0)}
        result = subprocess.run(['/usr/bin/sudo', '-n', '--', '/usr/local/lib/inkyos/test-lan-runner'],
            input=json.dumps(payload).encode(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}, timeout=5)
        sys.stdout.buffer.write(result.stdout)
        return result.returncode
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        return 64

if __name__ == '__main__':
    sys.exit(main())
'''

RUNNER = r'''#!/usr/bin/python3 -I
import json, os, sys

def pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError('duplicate field')
        value[key] = item
    return value

def validate(raw):
    if not raw or len(raw) > 4096:
        raise ValueError('stub request size')
    value = json.loads(raw, object_pairs_hook=pairs)
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'operation', 'request'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['operation'] not in ('preflight', 'activate', 'stop')
            or value['request'] != {'schema_version': 1}
            or type(value['request'].get('schema_version')) is not int):
        raise ValueError('invalid stub envelope')
    return value['operation']

def main():
    if len(sys.argv) != 1 or os.geteuid() != 0:
        return 64
    try:
        verb = validate(sys.stdin.buffer.read(4097))
        fd = os.open('/run/inkyos-test-ssh/invocations', os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        with os.fdopen(fd, 'w') as stream:
            stream.write(verb + '\n')
        print(json.dumps({'schema_version': 1, 'scope': 'inert-test-ssh-runner',
                          'operation': verb, 'euid': 0, 'application_activated': False}))
        return 0
    except (OSError, ValueError, TypeError):
        return 64

if __name__ == '__main__':
    sys.exit(main())
'''


def require(condition, label):
    if not condition:
        raise ValueError(label)


def unique(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate_json_field')
        result[key] = value
    return result


def regular(path, mode, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == mode and info.st_size <= limit, 'unsafe_input_file')
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        require(len(data) == info.st_size and (info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                == (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'input_changed')
    return data


def sha_file(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def configuration(port):
    require(type(port) is int and 1024 < port < 65536, 'invalid_probe_port')
    return f'''AddressFamily inet
ListenAddress 127.0.0.1
Port {port}
HostKey {RUNTIME}/host
PidFile {RUNTIME}/sshd.pid
AuthorizedKeysFile /etc/inkyos-test-ssh/authorized_keys
AllowUsers {USER}
PermitRootLogin no
UsePAM yes
AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
HostbasedAuthentication no
GSSAPIAuthentication no
StrictModes yes
ForceCommand {DISPATCH_PATH}
DisableForwarding yes
AllowTcpForwarding no
AllowStreamLocalForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
PermitTTY no
PermitUserRC no
PermitUserEnvironment no
GatewayPorts no
PermitOpen none
PermitListen none
MaxAuthTries 2
MaxSessions 1
MaxStartups 2
LoginGraceTime 10
UseDNS no
PrintMotd no
PrintLastLog no
LogLevel ERROR
Subsystem sftp internal-sftp
'''


def main(work):
    root = work / 'root'
    checks = {name: False for name in CHECKS}
    methods = {'transport_probe': True, 'privileged_runner': 'inert-stub',
               'application_activated': False, 'hardware_qualified': False, 'release_qualified': False,
               'existing_keys_used': False, 'external_network_used': False,
               'namespaces': ['mount', 'network', 'uts', 'pid'], 'parent_authenticity_verified': False}
    report = {'schema_version': 1, 'scope': 'linux-test-ssh-pam-transport-probe', 'passed': False,
              'activation_stub_only': True, 'application_activated': False,
              'hardware_qualified': False, 'release_qualified': False,
              'checks': checks, 'method': methods, 'parent': {}, 'package_versions': {}, 'program_sha256': {},
              'fixture_sha256': {name: hashlib.sha256(value.encode()).hexdigest()
                                 for name, value in {'dispatcher': DISPATCHER, 'runner': RUNNER, 'sudoers': SUDOERS}.items()},
              'error_stage': None, 'source_sha256': None,
              'limits': ['Unsigned parent hashes establish local consistency, not independent authenticity.',
                         'The forced dispatcher and privileged runner are probe fixtures; activation is an inert stub.',
                         'No real application activation, Pi/SD, display, Wi-Fi, BLE or release is qualified.',
                         'Forced namespace termination can prevent the final report and loop cleanup; a missing report is failure.']}
    loop = None
    mounts = []
    daemon = None
    stage = 'input_validation'
    disposable = False
    staging_valid = False
    report_written = False

    def interrupted(_signum, _frame):
        raise InterruptedError('probe_interrupted')

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)

    def command(argv, *, data=None, timeout=12):
        return subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}, timeout=timeout)

    def must(argv, **kw):
        result = command(argv, **kw)
        require(result.returncode == 0, 'probe_command_failed')
        return result

    def target(argv, **kw):
        return command(['chroot', str(root), *argv], **kw)

    def target_must(argv, **kw):
        result = target(argv, **kw)
        require(result.returncode == 0, 'target_command_failed')
        return result

    def create(relative, raw, mode):
        path = root / relative.lstrip('/')
        for ancestor in reversed(path.parents):
            if ancestor == root or root in ancestor.parents:
                if not ancestor.exists():
                    ancestor.mkdir(mode=0o755)
                    ancestor.chmod(0o755)
                info = ancestor.lstat()
                require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                        'unsafe_target_directory')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(raw.encode() if isinstance(raw, str) else raw)

    def mount(kind, source, relative, options):
        path = root / relative
        require(path.is_dir() and not path.is_symlink(), 'unsafe_mountpoint')
        must(['mount', '-t', kind, '-o', options, source, str(path)])
        mounts.append(path)

    def invocations():
        return (root / RUNTIME.lstrip('/') / 'invocations').read_bytes().splitlines()

    def account():
        users = [line.split(':') for line in (root / 'etc/passwd').read_text().splitlines()]
        shadow = [line.split(':') for line in (root / 'etc/shadow').read_text().splitlines() if line.startswith(USER + ':')]
        groups = [line.split(':') for line in (root / 'etc/group').read_text().splitlines()]
        rows = [row for row in users if row[0] == USER]
        return (len(rows) == len(shadow) == 1 and len(rows[0]) == 7 and len(shadow[0]) == 9
                and rows[0][2].isdigit() and int(rows[0][2]) not in (0, 1000)
                and rows[0][6] == '/bin/sh' and shadow[0][1].startswith('!')
                and shadow[0][2] == '' and shadow[0][4] == '' and shadow[0][6:8] == ['', '']
                and {row[0] for row in groups if row[2] == rows[0][3] or USER in row[3].split(',')} == {USER})

    try:
        info = work.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
                'unsafe_staging_directory')
        require({entry.name for entry in work.iterdir()} == INPUTS, 'unexpected_staging_files')
        staging_valid = True
        manifest_raw = regular(work / 'parent-manifest.json', 0o444, 64 * 1024**2)
        expected = regular(work / 'parent-manifest.sha256', 0o444, 65).decode('ascii').strip()
        require(re.fullmatch('[0-9a-f]{64}', expected) and hashlib.sha256(manifest_raw).hexdigest() == expected,
                'parent_manifest_hash_mismatch')
        parent = json.loads(manifest_raw, object_pairs_hook=unique)
        require(type(parent.get('schema_version')) is int and parent['schema_version'] == 1
                and parent['kind'] == 'application-prototype' and parent['hardware_qualified'] is False
                and parent['application'] == {'source_commit': EXACT_SOURCE, 'manifest_sha256': EXACT_MANIFEST,
                    'application_version': '0.5.0-rc.2', 'startup': 'masked-pending-firstboot-contract', 'release_qualified': False}
                and parent['application']['release_qualified'] is False,
                'parent_candidate_pin_mismatch')
        integrity = json.loads(regular(work / 'parent-integrity.json', 0o444, 64 * 1024**2), object_pairs_hook=unique)
        require(integrity.get('scope') == 'local-export-integrity' and integrity.get('passed') is True
                and integrity.get('image_sha256_verified') is True and integrity.get('authenticity_verified') is False
                and integrity.get('hardware_qualified') is False,
                'parent_integrity_receipt_mismatch')
        inventory_raw = regular(work / 'parent-filesystem-manifest.json', 0o444, 64 * 1024**2)
        require(hashlib.sha256(inventory_raw).hexdigest() == parent['reports']['filesystem-manifest.json'],
                'parent_inventory_hash_mismatch')
        inventory = json.loads(inventory_raw, object_pairs_hook=unique)
        require(inventory['schema_version'] == 2, 'parent_inventory_schema')
        source_raw = regular(work / 'probe-test-ssh-linux.sh', 0o444, 1024**2)
        image = work / 'probe.img'
        info = image.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == parent['image']['size_bytes']
                and 0 < info.st_size <= 32 * 1024**3, 'unsafe_disposable_image')
        require(sha_file(image) == parent['image']['sha256'], 'parent_image_hash_mismatch')
        disposable = True
        report['parent'] = {'manifest_sha256': expected, 'image_sha256': parent['image']['sha256'],
                            'filesystem_manifest_sha256': hashlib.sha256(inventory_raw).hexdigest(),
                            'application_source_commit': EXACT_SOURCE, 'application_manifest_sha256': EXACT_MANIFEST}
        report['source_sha256'] = hashlib.sha256(source_raw).hexdigest()
        checks['parent_bytes_pinned'] = True
        checks['private_namespaces'] = all(os.readlink('/proc/self/ns/' + name) != os.readlink('/proc/1/ns/' + name)
                                          for name in ('mnt', 'net', 'uts', 'pid'))
        interfaces = lambda: {line.split(':', 1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]}
        require(interfaces() == {'lo'}, 'namespace_has_external_interface')
        checks['loopback_only'] = True
        checks['no_new_privileges_unset'] = '\nNoNewPrivs:\t0\n' in Path('/proc/self/status').read_text()
        require(checks['no_new_privileges_unset'], 'sudo_requires_no_new_privileges_unset')
        must(['ip', 'link', 'set', 'lo', 'up'])
        must(['hostname', 'inkyos-ssh-probe'])

        stage = 'mount_disposable_image'
        root.mkdir(mode=0o700)
        loop = must(['losetup', '--find', '--show', '--partscan', '--', str(image)]).stdout.decode().strip()
        require(re.fullmatch('/dev/loop[0-9]+', loop), 'unexpected_loop_device')
        for _ in range(20):
            if Path(loop + 'p2').exists():
                break
            time.sleep(0.1)
        require(must(['lsblk', '-nr', '-o', 'TYPE', loop]).stdout.splitlines() == [b'loop', b'part', b'part'], 'partition_layout')
        require(must(['blkid', '-p', '-s', 'TYPE', '-o', 'value', loop + 'p2']).stdout.strip() == b'ext4', 'root_filesystem_type')
        # sudo must retain the target filesystem's real setuid semantics. This
        # exception is confined to the disposable image and private namespaces.
        mount('ext4', loop + 'p2', '', 'rw,noatime,suid,nodev')
        for relative in PROGRAMS:
            pin = inventory['rootfs'][relative]
            path = root / relative
            require(pin['type'] == 'file' and path.is_file() and not path.is_symlink()
                    and sha_file(path) == pin['sha256'], 'target_program_changed')
            report['program_sha256'][relative] = pin['sha256']
        checks['target_programs_match_parent_inventory'] = True
        sudo_info = (root / 'usr/bin/sudo').stat()
        checks['target_sudo_is_setuid'] = sudo_info.st_uid == 0 and stat.S_IMODE(sudo_info.st_mode) == 0o4755
        require(checks['target_sudo_is_setuid'], 'target_sudo_not_setuid')
        require(not (root / 'etc/ssh/sshrc').exists()
                and not any(path.name.startswith('ssh_host_') for path in (root / 'etc/ssh').iterdir()),
                'existing_ssh_identity_or_rc_refused')
        require(not any(line.startswith(USER + ':') for line in (root / 'etc/passwd').read_text().splitlines()),
                'test_account_already_exists')
        require(not (root / 'nonexistent').exists(), 'unexpected_test_account_home')
        hosts = root / 'etc/hosts'
        require(hosts.is_file() and not hosts.is_symlink(), 'unsafe_hosts_file')
        with hosts.open('a') as stream:
            stream.write('\n127.0.1.1 inkyos-ssh-probe\n')
        mount('tmpfs', 'tmpfs', 'run', 'mode=0755,nosuid,nodev,noexec')
        mount('tmpfs', 'tmpfs', 'dev', 'mode=0755,nosuid,noexec')
        for name, minor in (('null', 3), ('zero', 5), ('random', 8), ('urandom', 9)):
            os.mknod(root / 'dev' / name, stat.S_IFCHR | 0o666, os.makedev(1, minor))
            (root / 'dev' / name).chmod(0o666)
        (root / 'dev/net').mkdir(mode=0o755)
        os.mknod(root / 'dev/net/tun', stat.S_IFCHR | 0o600, os.makedev(10, 200))
        mount('proc', 'proc', 'proc', 'nosuid,nodev,noexec')
        (root / RUNTIME.lstrip('/')).mkdir(mode=0o700)
        (root / 'run/sshd').mkdir(mode=0o755)
        create(RUNTIME + '/invocations', b'', 0o600)
        versions = target_must(['/usr/bin/dpkg-query', '-W', '-f=${Package}=${Version}\n', *PACKAGES]).stdout.decode('ascii')
        report['package_versions'] = dict(line.split('=', 1) for line in versions.splitlines())
        require(set(report['package_versions']) == set(PACKAGES), 'package_inventory_incomplete')

        stage = 'prepare_isolated_account_and_fixtures'
        target_must(['/usr/sbin/useradd', '--system', '--no-create-home', '--home-dir', '/nonexistent',
                     '--shell', '/bin/sh', '--user-group', '--password', '!', USER])
        target_must(['/usr/bin/chage', '-d', '-1', '-m', '0', '-M', '-1', '-I', '-1', '-E', '-1', USER])
        checks['dedicated_account_locked_unaged'] = account()
        require(checks['dedicated_account_locked_unaged'], 'account_not_locked_unaged_and_separate')
        for name in ('host', 'good', 'bad'):
            target_must(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', '', '-f', RUNTIME + '/' + name])
        public = (root / RUNTIME.lstrip('/') / 'good.pub').read_bytes()
        create('/etc/inkyos-test-ssh/authorized_keys', b'restrict ' + public, 0o644)
        create(DISPATCH_PATH, DISPATCHER, 0o555)
        create(RUNNER_PATH, RUNNER, 0o555)
        create('/etc/sudoers.d/inkyos-test-ssh-probe', SUDOERS, 0o440)
        checks['root_public_key_readable'] = target(['/usr/sbin/runuser', '-u', USER, '--',
            '/usr/bin/test', '-r', '/etc/inkyos-test-ssh/authorized_keys']).returncode == 0
        checks['sudoers_syntax'] = target(['/usr/sbin/visudo', '-c']).returncode == 0
        listing = target_must(['/usr/bin/sudo', '-n', '-l', '-U', USER]).stdout.decode('utf-8')
        grants = [line.strip() for line in listing.splitlines() if line.lstrip().startswith('(')]
        checks['sudo_listing_exact'] = grants == ['(root) NOPASSWD: ' + RUNNER_PATH + ' ""']
        require(checks['sudoers_syntax'] and checks['sudo_listing_exact'], 'sudo_policy_not_exact')
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        conf = configuration(port)
        create('/etc/inkyos-test-ssh/sshd_config', conf, 0o644)
        report['fixture_sha256']['sshd_config'] = hashlib.sha256(conf.encode()).hexdigest()
        host_fields = (root / RUNTIME.lstrip('/') / 'host.pub').read_text().split()
        create(RUNTIME + '/known_hosts', f'[127.0.0.1]:{port} {host_fields[0]} {host_fields[1]}\n', 0o600)
        config_args = ['-f', '/etc/inkyos-test-ssh/sshd_config']
        target_must(['/usr/sbin/sshd', '-t', *config_args])
        effective = target_must(['/usr/sbin/sshd', '-T', *config_args,
                                '-C', f'user={USER},host=localhost,addr=127.0.0.1']).stdout.decode('utf-8')
        values = dict(line.split(' ', 1) for line in effective.splitlines())
        expected = {'usepam': 'yes', 'authenticationmethods': 'publickey', 'pubkeyauthentication': 'yes',
            'passwordauthentication': 'no', 'kbdinteractiveauthentication': 'no', 'permitrootlogin': 'no',
            'allowusers': USER, 'forcecommand': DISPATCH_PATH, 'disableforwarding': 'yes',
            'allowtcpforwarding': 'no', 'allowstreamlocalforwarding': 'no', 'allowagentforwarding': 'no',
            'x11forwarding': 'no', 'permittunnel': 'no', 'permittty': 'no', 'permituserrc': 'no',
            'permituserenvironment': 'no', 'authorizedkeysfile': '/etc/inkyos-test-ssh/authorized_keys'}
        checks['effective_sshd_restrictions'] = all(values.get(key) == value for key, value in expected.items()) and 'acceptenv' not in values
        require(checks['effective_sshd_restrictions'], 'effective_sshd_configuration_differs')

        stage = 'actual_ssh_transport'
        daemon = subprocess.Popen(['chroot', str(root), '/usr/sbin/sshd', '-D', '-e', *config_args],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        for _ in range(40):
            require(daemon.poll() is None, 'sshd_stopped_early')
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise ValueError('sshd_not_ready')
        options = ['-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
            '-o', 'IdentityAgent=none', '-o', 'CertificateFile=none', '-o', 'AddKeysToAgent=no',
            '-o', 'UserKnownHostsFile=' + RUNTIME + '/known_hosts',
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'ConnectTimeout=3', '-o', 'ConnectionAttempts=1', '-o', 'ControlMaster=no',
            '-o', 'ControlPath=none', '-o', 'UpdateHostKeys=no']
        def ssh(verb=None, *, key='good', extra=(), user=USER, data=b'{"schema_version":1}\n'):
            argv = ['/usr/bin/ssh', *options, '-p', str(port), '-i', RUNTIME + '/' + key, *extra, user + '@127.0.0.1']
            if verb is not None:
                argv.append(verb)
            return target(argv, data=data, timeout=10)

        def successful(verb):
            before = invocations()
            result = ssh(verb)
            try:
                value = json.loads(result.stdout)
            except (ValueError, UnicodeError):
                return False
            return (result.returncode == 0 and value == {'schema_version': 1, 'scope': 'inert-test-ssh-runner',
                'operation': verb, 'euid': 0, 'application_activated': False}
                and invocations() == before + [verb.encode()])

        def refused(verb, **kw):
            before = invocations()
            result = ssh(verb, **kw)
            return result.returncode != 0 and invocations() == before, result

        for verb, check in (('preflight', 'key_preflight'), ('activate', 'key_activate_stub'), ('stop', 'key_stop_stub')):
            checks[check] = successful(verb)
        require(all(checks[name] for name in ('key_preflight', 'key_activate_stub', 'key_stop_stub')), 'baseline_key_or_stub_failed')
        checks['wrong_key_refused'], _ = refused('preflight', key='bad')
        checks['root_login_refused'], _ = refused('preflight', user='root')
        for method, check in (('password', 'password_method_not_offered'), ('keyboard-interactive', 'keyboard_interactive_not_offered')):
            denied, result = refused('preflight', extra=('-o', 'PubkeyAuthentication=no', '-o', 'PreferredAuthentications=' + method))
            checks[check] = denied and b'Permission denied (publickey)' in result.stderr
        checks['shell_refused'], _ = refused(None)
        checks['sftp_refused'], _ = refused('sftp', extra=('-s',))
        create(RUNTIME + '/scp-source', 'inert probe fixture\n', 0o600)
        for flag, check in (([], 'scp_sftp_refused'), (['-O'], 'scp_legacy_refused')):
            before = invocations()
            result = target(['/usr/bin/scp', '-q', *flag, *options, '-P', str(port), '-i', RUNTIME + '/good',
                RUNTIME + '/scp-source', USER + '@127.0.0.1:' + RUNTIME + '/unexpected-copy'], timeout=10)
            checks[check] = result.returncode != 0 and invocations() == before and not (root / RUNTIME.lstrip('/') / 'unexpected-copy').exists()
        checks['command_arguments_refused'] = all(refused(value)[0] for value in ('preflight extra', ' preflight', 'stop ', 'activate --help'))
        checks['command_injection_refused'] = all(refused(value)[0] for value in ('preflight; id', 'preflight\nactivate', '$(id)', 'preflight | sh'))
        checks['request_schema_refused'] = all(refused('preflight', data=value)[0] for value in
            (b'', b'{}', b'{"schema_version":true}', b'{"schema_version":1,"command":"id"}',
             b'{"schema_version":1,"schema_version":1}', b'x' * 4097))
        # -W requests an actual direct-tcpip channel. An unused -L listener alone
        # would not prove the server's forwarding restriction.
        with socket.socket() as sink:
            sink.bind(('127.0.0.1', 0)); sink.listen(1); sink.settimeout(0.2)
            sink_port = sink.getsockname()[1]
            result = ssh(extra=('-W', '127.0.0.1:' + str(sink_port)), data=b'inert')
            try:
                connection, _ = sink.accept(); connection.close(); reached = True
            except socket.timeout:
                reached = False
            checks['direct_tcpip_channel_refused'] = result.returncode != 0 and not reached and b'administratively prohibited' in result.stderr
            result = ssh(extra=('-N', '-o', 'ExitOnForwardFailure=yes', '-R', '127.0.0.1:0:127.0.0.1:' + str(sink_port)), data=b'')
            checks['remote_forward_refused'] = result.returncode != 0 and b'remote port forwarding failed' in result.stderr
        result = ssh(extra=('-vv', '-N', '-o', 'ExitOnForwardFailure=yes', '-w', 'any:any'), data=b'')
        checks['tunnel_channel_refused'] = (result.returncode != 0 and b'administratively prohibited' in result.stderr
            and b'Tunnel device open failed' not in result.stderr and interfaces() == {'lo'})
        result = ssh('preflight', extra=('-tt',))
        checks['tty_refused'] = b'PTY allocation request failed' in result.stderr

        stage = 'pam_and_sudo_negative_cases'
        target_must(['/usr/sbin/usermod', '--shell', '/usr/sbin/nologin', USER])
        checks['nologin_prevents_dispatch'], _ = refused('preflight')
        target_must(['/usr/sbin/usermod', '--shell', '/bin/sh', USER])
        target_must(['/usr/bin/chage', '-d', '0', USER])
        checks['expired_password_prevents_dispatch'], _ = refused('preflight')
        target_must(['/usr/bin/chage', '-d', '-1', USER])
        checks['restored_account_key_works'] = account() and successful('preflight')
        envelope = b'{"schema_version":1,"operation":"preflight","request":{"schema_version":1}}'
        before = invocations()
        zero = target(['/usr/sbin/runuser', '-u', USER, '--', '/usr/bin/sudo', '-n', '--', RUNNER_PATH], data=envelope)
        extra = target(['/usr/sbin/runuser', '-u', USER, '--', '/usr/bin/sudo', '-n', '--', RUNNER_PATH, 'extra'], data=envelope)
        checks['sudo_zero_arguments_only'] = zero.returncode == 0 and extra.returncode != 0 and invocations() == before + [b'preflight']
        checks['sudo_other_commands_refused'] = all(target(['/usr/sbin/runuser', '-u', USER, '--',
            '/usr/bin/sudo', '-n', '--', *argv]).returncode != 0 for argv in (['/usr/bin/id', '-u'], ['/bin/sh', '-c', 'id -u']))
        checks['application_still_masked'] = all(os.readlink(root / 'etc/systemd/system' / unit) == '/dev/null'
                                                for unit in ('inky-studio.service', 'inky-network.service'))
        stage = 'complete'
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        report['error_stage'] = stage
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        # No key, fingerprint, SSH diagnostic stream or arbitrary exception text
        # leaves the namespace. Keys lived only on the throwaway /run tmpfs.
        if daemon is not None:
            try:
                daemon.terminate(); daemon.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    daemon.kill(); daemon.wait(timeout=3)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        def live_children():
            if root / 'proc' not in mounts:
                return []
            result = []
            for path in (root / 'proc').iterdir():
                if not path.name.isdigit() or int(path.name) in (1, os.getpid()):
                    continue
                try:
                    if os.readlink(path / 'ns/pid') != os.readlink('/proc/self/ns/pid'):
                        continue
                    status = (path / 'status').read_text()
                    if not re.search(r'^State:\s+Z\b', status, re.MULTILINE):
                        result.append(int(path.name))
                except (FileNotFoundError, ProcessLookupError):
                    continue
            return result

        # Enumerate only this probe's PID namespace, never VM-wide processes.
        # Teardown of namespace PID 1 remains the bound after a forced kill.
        try:
            for pid in live_children():
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            deadline = time.monotonic() + 2
            while live_children() and time.monotonic() < deadline:
                time.sleep(0.05)
            for pid in live_children():
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            deadline = time.monotonic() + 1
            while live_children() and time.monotonic() < deadline:
                time.sleep(0.05)
            checks['processes_stopped'] = (daemon is None or daemon.poll() is not None) and not live_children()
        except OSError:
            checks['processes_stopped'] = False
        for path in reversed(mounts[:]):
            try:
                if command(['umount', str(path)], timeout=5).returncode == 0:
                    mounts.remove(path)
                else:
                    break
            except (OSError, subprocess.TimeoutExpired):
                break
        checks['mounts_removed'] = not mounts
        if loop is not None and not mounts:
            try:
                checks['loop_detached'] = command(['losetup', '-d', loop], timeout=5).returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                pass
        else:
            checks['loop_detached'] = loop is None
        if disposable and checks['mounts_removed'] and checks['loop_detached']:
            try:
                (work / 'probe.img').unlink()
                if root.exists():
                    root.rmdir()
                checks['disposable_image_removed'] = True
            except OSError:
                pass
        report['passed'] = all(checks.values()) and report['error_stage'] is None
        report['failed_checks'] = [name for name, passed in checks.items() if not passed]
        if staging_valid:
            try:
                fd = os.open(work / 'report.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'w') as stream:
                    json.dump(report, stream, indent=2, sort_keys=True); stream.write('\n')
                report_written = True
            except OSError:
                pass
    if not staging_valid:
        print('SSH/PAM probe refused unsafe staging; no report written.', file=sys.stderr)
        return 2
    if not report_written:
        print('SSH/PAM probe could not create its report.', file=sys.stderr)
        return 1
    print('SSH/PAM transport probe ' + ('PASS' if report['passed'] else 'FAIL') + '; closed report.json retained.')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main(Path(sys.argv[1])))
PY_PROBE
