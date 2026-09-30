#!/usr/bin/env bash
# Synthetic filesystem helpers only: no runtime, key generator or target image.
set -Eeuo pipefail
umask 077
if [[ ${1:-} == --help && $# == 1 ]]; then
  echo 'Usage: sudo bash STAGING/probe-test-enrollment-filesystem-linux.sh STAGING RUNTIME_SHA256'
  echo 'STAGING: /var/tmp/inkyos-work/enrollment-fs.<8 lowercase hex>, root 0700.'
  echo 'Exactly this script and test-enrollment-firstboot.py, root 0444; runtime hash required.'
  echo 'Creates only synthetic ext4 32 MiB and FAT32 64 MiB regular images; keeps them and report.json.'
  exit 0
fi
[[ $# == 2 && $(uname -s) == Linux && $(uname -m) == aarch64 && $EUID == 0 ]] || exit 2
[[ $(cat /var/lib/inkyos-build/owner) == inkyos-builder-v1 ]] || exit 2
work=$(readlink -e -- "$1")
[[ $work == "$1" && $work =~ ^/var/tmp/inkyos-work/enrollment-fs\.[0-9a-f]{8}$ && $2 =~ ^[0-9a-f]{64}$ ]] || exit 2
[[ $(readlink -e -- "$0") == "$work/probe-test-enrollment-filesystem-linux.sh" ]] || exit 2
for tool in unshare timeout findmnt losetup mount umount mkfs.ext4 mkfs.vfat python3; do
  command -v "$tool" >/dev/null || exit 2
done
if [[ ${INKYOS_ENROLLMENT_FS_NAMESPACE:-} != 1 ]]; then
  exec timeout --signal=TERM --kill-after=70s 90s \
    unshare --mount --net --uts --propagation private \
    env INKYOS_ENROLLMENT_FS_NAMESPACE=1 bash "$0" "$work" "$2"
fi
for namespace in mnt net uts; do
  [[ $(readlink "/proc/self/ns/$namespace") != $(readlink "/proc/1/ns/$namespace") ]] || exit 2
done
[[ $(findmnt -n -o PROPAGATION /) == private ]] || exit 2
exec python3 -I - "$work" "$2" <<'PY_FILESYSTEM'
import ast, ctypes, hashlib, json, os, pathlib, re, signal, stat, subprocess, sys

HELPERS = ('EnrollmentError', '_metadata', '_stamp', 'mount_is_fat', 'rename_noreplace', 'write_atomic')
CHECKS = ('sealed_inputs', 'private_namespaces', 'ext4_publish_fsync', 'fat_publish_fsync',
          'ext4_existing_final_refused', 'fat_existing_final_refused',
          'ext4_existing_temp_refused', 'fat_existing_temp_refused',
          'ext4_rename_noreplace', 'fat_rename_noreplace',
          'ext4_partial_preserved', 'fat_partial_preserved',
          'ext4_owned_state_transition', 'ext4_stale_state_refused',
          'fat_open_fd_verified', 'mounts_removed', 'loops_detached')


def require(value):
    if not value:
        raise ValueError('probe_refused')


def helpers(raw):
    tree = ast.parse(raw)
    nodes = [node for node in tree.body if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name in HELPERS]
    require(tuple(node.name for node in nodes) == HELPERS and all(not node.decorator_list for node in nodes))
    namespace = dict(os=os, stat=stat, ctypes=ctypes, re=re)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<pinned-filesystem-helpers>', 'exec'), namespace)
    return namespace


def regular(path, mode):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == mode and info.st_size < 131072)
        raw = stream.read(131072)
        after = os.fstat(stream.fileno())
        require((info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                == (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and len(raw) == info.st_size)
    return raw


def command(*args, allow_failure=False):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=10, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if not allow_failure:
        require(result.returncode == 0)
    return result


def exercise(ns, path, fat, passed):
    label = 'fat' if fat else 'ext4'
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    raw = b'SYNTHETIC ENROLLMENT FILESYSTEM FIXTURE\n'
    calls = []
    class TraceOS:
        def __getattr__(self, name):
            return getattr(os, name)
        def fsync(self, descriptor):
            os.fsync(descriptor)
            calls.append('directory' if stat.S_ISDIR(os.fstat(descriptor).st_mode) else 'file')
    ns['os'] = TraceOS()
    def write(name, data=raw, **kwargs):
        return ns['write_atomic'](fd, name, data, fat=fat, **kwargs)
    def refused(action):
        try:
            action()
        except (ns['EnrollmentError'], OSError):
            return
        raise ValueError('unexpected_success')
    try:
        stamp = write('published.json')
        require((path / 'published.json').read_bytes() == raw and not (path / '.published.json.tmp').exists()
                and calls == ['file', 'directory'])
        if not fat:
            require(stat.S_IMODE((path / 'published.json').stat().st_mode) == 0o600)
        passed.add(label + '_publish_fsync')
        refused(lambda: write('published.json', b'REPLACEMENT'))
        require((path / 'published.json').read_bytes() == raw)
        passed.add(label + '_existing_final_refused')
        (path / '.occupied.json.tmp').write_bytes(raw)
        refused(lambda: write('occupied.json'))
        require((path / '.occupied.json.tmp').read_bytes() == raw and not (path / 'occupied.json').exists())
        passed.add(label + '_existing_temp_refused')
        (path / 'source.json').write_bytes(b'SOURCE')
        refused(lambda: ns['rename_noreplace'](fd, 'source.json', 'published.json'))
        require((path / 'source.json').read_bytes() == b'SOURCE' and (path / 'published.json').read_bytes() == raw)
        passed.add(label + '_rename_noreplace')
        def interrupted(*_args):
            raise OSError('synthetic_before_rename')
        refused(lambda: write('partial.json', rename=interrupted))
        require((path / '.partial.json.tmp').read_bytes() == raw and not (path / 'partial.json').exists())
        passed.add(label + '_partial_preserved')
        if fat:
            require(ns['mount_is_fat'](pathlib.Path('/proc/self/mountinfo').read_bytes(),
                    pathlib.Path(f'/proc/self/fdinfo/{fd}').read_bytes(), os.fstat(fd).st_dev))
            passed.add('fat_open_fd_verified')
        else:
            stamp = write('published.json', b'OWNED', replace_stamp=stamp)
            require((path / 'published.json').read_bytes() == b'OWNED')
            passed.add('ext4_owned_state_transition')
            (path / 'published.json').write_bytes(b'FOREIGN STATE')
            refused(lambda: write('published.json', replace_stamp=stamp))
            require((path / 'published.json').read_bytes() == b'FOREIGN STATE')
            passed.add('ext4_stale_state_refused')
    finally:
        ns['os'] = os
        os.close(fd)


def main(work, expected):
    info = work.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700)
    require({item.name for item in work.iterdir()} == {'probe-test-enrollment-filesystem-linux.sh', 'test-enrollment-firstboot.py'})
    source = regular(work / 'test-enrollment-firstboot.py', 0o444)
    script = regular(work / 'probe-test-enrollment-filesystem-linux.sh', 0o444)
    require(hashlib.sha256(source).hexdigest() == expected)
    ns, passed, mounts, loops = helpers(source), {'sealed_inputs'}, [], []
    stage, error = 'private_namespaces', None
    def interrupted(_signum, _frame):
        raise InterruptedError('probe_interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        require(all(os.readlink(f'/proc/self/ns/{name}') != os.readlink(f'/proc/1/ns/{name}') for name in ('mnt', 'net', 'uts')))
        require({line.split(':')[0].strip() for line in pathlib.Path('/proc/net/dev').read_text().splitlines()[2:]} == {'lo'})
        passed.add(stage)
        stage = 'create_synthetic_filesystems'
        for kind in ('ext4', 'fat'):
            image = work / (kind + '.img')
            fd = os.open(image, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            try:
                os.ftruncate(fd, (32 if kind == 'ext4' else 64) * 1024 * 1024)
            finally:
                os.close(fd)
            command('mkfs.ext4', '-q', '-F', str(image)) if kind == 'ext4' else command('mkfs.vfat', '-F', '32', str(image))
            loop = command('losetup', '--find', '--show', '--', str(image)).stdout.decode().strip()
            require(re.fullmatch(r'/dev/loop[0-9]+', loop) is not None)
            loops.append(loop)
        (work / 'ext4').mkdir()
        (work / 'boot/firmware').mkdir(parents=True)
        require(pathlib.Path('/boot').is_dir() and not pathlib.Path('/boot').is_symlink())
        command('mount', '--bind', str(work / 'boot'), '/boot'); mounts.append('/boot')
        command('mount', '-t', 'ext4', '-o', 'rw,nosuid,nodev,noexec', loops[0], str(work / 'ext4')); mounts.append(str(work / 'ext4'))
        command('mount', '-t', 'vfat', '-o', 'rw,nosuid,nodev,noexec,uid=0,gid=0,fmask=0177,dmask=0077', loops[1], '/boot/firmware'); mounts.append('/boot/firmware')
        for path, fat in ((work / 'ext4', False), (pathlib.Path('/boot/firmware'), True)):
            stage = 'fat_helpers' if fat else 'ext4_helpers'
            exercise(ns, path, fat, passed)
    except Exception:
        error = stage
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        for target in reversed(mounts[:]):
            try:
                command('umount', target)
                require(command('findmnt', '-rn', '-M', target, allow_failure=True).returncode == 1)
                mounts.remove(target)
            except Exception:
                error = 'cleanup_incomplete'
        if not mounts:
            passed.add('mounts_removed')
            for loop in loops[:]:
                try:
                    command('losetup', '-d', loop)
                    require(command('losetup', loop, allow_failure=True).returncode != 0)
                    loops.remove(loop)
                except Exception:
                    error = 'cleanup_incomplete'
        if not loops:
            passed.add('loops_detached')
    report = dict(schema_version=1, scope='native-test-enrollment-filesystem-helpers',
        runtime_sha256=expected, probe_sha256=hashlib.sha256(script).hexdigest(),
        passed=error is None and passed == set(CHECKS), error_stage=error,
        checks=[dict(id=name, passed=name in passed) for name in CHECKS],
        failed_checks=[name for name in CHECKS if name not in passed],
        hardware_qualified=False, application_activated=False, release_qualified=False,
        runtime_executed=False, power_loss_tested=False, synthetic_images_preserved=True)
    fd = os.open(work / 'report.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        output.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print('Filesystem helper probe PASS.' if report['passed'] else 'Filesystem helper probe FAIL; inspect the closed report.')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    try:
        result = main(pathlib.Path(sys.argv[1]), sys.argv[2])
    except Exception:
        print('Filesystem helper probe refused before a report could be written.', file=sys.stderr)
        result = 1
    sys.exit(result)
PY_FILESYSTEM
