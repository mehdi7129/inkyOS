#!/usr/bin/env bash
# Read-only consistency check of an acquired SD image; never boots or activates it.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
if [[ ${1:-} == --help && $# == 1 ]]; then
  echo 'Usage: sudo bash STAGING/check-test-enrollment-return-linux.sh STAGING INPUTS_SHA256 RETURNED_SIZE RETURNED_SHA256'
  echo 'STAGING: /var/lib/inkyos-build/enrollment-return.<8 hex> or /mnt/inkyos-return.<8 hex>, root0700.'
  echo 'Closed layout: runner0444, inputs.json0444, sources/9 files0444, expected/19 files0600, returned.img0600.'
  echo 'inputs.json: {"schema_version":1,"files":{"relative/path":"sha256",...}} seals all 30 input files.'
  echo 'Expected image is pinned enrollment 7a1b7046; returned image has explicit full size and SHA256.'
  echo 'No standalone profile/client key. Mounts READ ONLY; ext4 journal replay is disabled.'
  echo 'Exit 0/1/2 preserves the closed controller result; setup/cleanup failure exits 2.'
  exit 0
fi
[[ $# == 4 && $(uname -s) == Linux && $(uname -m) == aarch64 && $EUID == 0 ]] || exit 2
work=$(readlink -e -- "$1") || exit 2
[[ $work == "$1" && $work =~ ^(/var/lib/inkyos-build/enrollment-return|/mnt/inkyos-return)\.[0-9a-f]{8}$
   && $2 =~ ^[0-9a-f]{64}$ && $3 =~ ^[1-9][0-9]{0,10}$ && $4 =~ ^[0-9a-f]{64}$ ]] || exit 2
[[ $(readlink -e -- "$0") == "$work/check-test-enrollment-return-linux.sh" ]] || exit 2
for tool in unshare timeout findmnt losetup lsblk blkid mount umount python3; do
  command -v "$tool" >/dev/null || exit 2
done
if [[ ${INKYOS_ENROLLMENT_CHECK_NAMESPACE:-} != 1 ]]; then
  exec timeout --signal=TERM --kill-after=100s 900s \
    unshare --mount --net --uts --propagation private \
    env INKYOS_ENROLLMENT_CHECK_NAMESPACE=1 bash "$0" "$work" "$2" "$3" "$4"
fi
for namespace in mnt net uts; do
  [[ $(readlink "/proc/self/ns/$namespace") != $(readlink "/proc/1/ns/$namespace") ]] || exit 2
done
[[ $(findmnt -n -o PROPAGATION /) == private ]] || exit 2
exec python3 -I - "$work" "$2" "$3" "$4" <<'PY_RETURN'
import ast, hashlib, json, os, pathlib, re, signal, stat, subprocess, sys, time

IMAGE = 'inkyos-test-enrollment.img'
IMAGE_SHA256 = '7a1b70463e5501830f67e9c4b2ffcb69d8970a154115a8e9f8aa2e27eeb9d86e'
IMAGE_SIZE = 3061841920
CONTROLLER_SHA256 = '1846114c44253f5102cd99318394c22cd1aa58a8541e3bbd00baf95eccbc58f5'
RUNNER = 'check-test-enrollment-return-linux.sh'
SOURCES = {'verify-test-enrollment-return.py', 'test-enrollment-firstboot.py',
    'verify-test-enrollment.py', 'verify-test-lan.py', 'configure-test-enrollment-rootfs.py',
    'configure-test-lan-rootfs.py', 'verify-sd-diagnostic.py', 'verify-artifacts.py', 'configure-rootfs.py'}
REPORTS = {'parent-manifest.json', 'parent-filesystem-manifest.json', 'parent-integrity.json',
    'recipe.tar', 'test-enrollment-configuration.json', 'qualification-prepared.json',
    'qualification-static.json', 'qualification-application.json', 'application-manifest.json',
    'filesystem-manifest.json', 'image-inspection.json', 'systemd-verify.txt',
    'boot-preserved.sha256', 'fsck-ext4.txt', 'fsck-fat.txt', 'build.log'}
EXPORT = REPORTS | {'manifest.json', 'recipe-inputs.json', IMAGE}
INPUT_FILES = {RUNNER, 'returned.img'} | {'sources/' + name for name in SOURCES} | {'expected/' + name for name in EXPORT}
FIRST_CHECKS = ('rootfs_readonly_ext4', 'bootfs_readonly_vfat', 'expected_export_consistent', 'expected_image_stat_checked')
FALSE_FIELDS = ('application_activation_authorized', 'ssh_access_enabled', 'network_profile_present',
    'hardware_qualified', 'release_qualified', 'authenticity_verified', 'runtime_execution_attested',
    'image_sha256_verified', 'shutdown_observed')
CHECKS = ('sealed_inputs', 'expected_image_bytes_pinned', 'returned_image_bytes_pinned', 'private_namespaces',
          'readonly_loop', 'expected_partition_layout', 'controller_result_closed',
          'mounts_removed', 'loop_detached', 'image_metadata_unchanged')


def require(value):
    if value is not True:
        raise ValueError('return_check_refused')


def parse(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value)
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs)


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_uid, info.st_gid, info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)


def directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700)


def read_file(path, mode, *, image_size=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == mode and info.st_size <= (image_size if image_size is not None else 64 * 1024**2))
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        require(stamp(info) == stamp(os.fstat(stream.fileno())) == stamp(path.lstat()))
        if image_size is not None:
            require(info.st_size == image_size)
            raw = None
        else:
            stream.seek(0)
            raw = stream.read()
            require(stamp(info) == stamp(os.fstat(stream.fileno())) == stamp(path.lstat()))
    return raw, digest, stamp(info)


def controller_contract(raw):
    values = {}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id in {'CHECKS', 'LIMITS'}:
            require(node.targets[0].id not in values)
            values[node.targets[0].id] = ast.literal_eval(node.value)
    require(set(values) == {'CHECKS', 'LIMITS'} and type(values['CHECKS']) is tuple
            and len(values['CHECKS']) == len(set(values['CHECKS'])) == 21 and values['CHECKS'][:4] == FIRST_CHECKS
            and type(values['LIMITS']) is list and all(type(value) is str for value in values['LIMITS']))
    return values


def validate_result(code, raw, contract):
    require(type(code) is int and code in (0, 1, 2) and len(raw) <= 65536)
    value = parse(raw)
    fixed = dict(schema_version=1, kind='test-enrollment-return-comparison',
        scope='offline-readonly-enrollment-consistency', observation_source='native-read-only',
        limits=contract['LIMITS'], **{key: False for key in FALSE_FIELDS})
    require(type(value) is dict and set(value) == set(fixed) | {'status', 'passed', 'checks', 'error', 'native_readonly_evidence'}
            and type(value['schema_version']) is int and all(value[key] == item for key, item in fixed.items())
            and all(value[key] is False for key in FALSE_FIELDS)
            and type(value['checks']) is dict and set(value['checks']) == set(contract['CHECKS'])
            and all(type(item) is bool for item in value['checks'].values())
            and type(value['passed']) is bool and type(value['native_readonly_evidence']) is bool)
    require(value['status'] == ('PASS', 'FAIL', 'INVALID')[code] and value['passed'] is (code == 0))
    errors = {0: (None,), 1: ('readonly_mount_required', 'return_incomplete', 'return_inconsistent'), 2: ('invalid_input',)}
    require(value['error'] in errors[code])
    mounts_ro = all(value['checks'][name] for name in contract['CHECKS'][:2])
    require(value['native_readonly_evidence'] is mounts_ro)
    if code == 0:
        require(all(value['checks'].values()))
    else:
        require(not all(value['checks'].values()))
    return value


def command(*args, timeout=10, allow_failure=False):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=timeout, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if not allow_failure:
        require(result.returncode == 0)
    return result


def ancestors(path):
    require(path.is_absolute() and str(path.resolve()) == str(path))
    for parent in (path, *path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022)


def associated(image, *, timeout=10):
    result = command('losetup', '--list', '--associated', str(image), '--noheadings', '--output', 'NAME', timeout=timeout)
    names = result.stdout.decode('ascii').split()
    require(len(names) <= 16 and len(set(names)) == len(names)
            and all(re.fullmatch(r'/dev/loop[0-9]+', name) for name in names))
    return names


def cleanup(mounts, image):
    """Inspect attempted mounts, including a mount command interrupted after success."""
    # At most (2 mounts * 3 commands + 16 detach commands + 2 queries) * 3s = 72s.
    # The outer kill-after budget is 100s; kernel-blocked IO remains a platform limit.
    success = True
    for target in reversed(mounts):
        try:
            mounted = command('findmnt', '-rn', '-M', target, allow_failure=True, timeout=3)
            require(mounted.returncode in (0, 1))
            if mounted.returncode == 0:
                command('umount', target, timeout=3)
            require(command('findmnt', '-rn', '-M', target, allow_failure=True, timeout=3).returncode == 1)
        except Exception:
            success = False
    detached = False
    if success:
        try:
            # Also finds an attach which completed just before interruption/timeout.
            for loop in associated(image, timeout=3):
                command('losetup', '-d', loop, timeout=3)
            require(not associated(image, timeout=3))
            detached = True
        except Exception:
            pass
    return success, detached


def main(work, inputs_sha, returned_size, returned_sha):
    require(IMAGE_SIZE <= returned_size <= 32 * 1024**3 and returned_size % 512 == 0
            and re.fullmatch(r'[0-9a-f]{64}', inputs_sha) is not None
            and re.fullmatch(r'[0-9a-f]{64}', returned_sha) is not None)
    ancestors(work); directory(work)
    require({item.name for item in work.iterdir()} == {RUNNER, 'inputs.json', 'sources', 'expected', 'returned.img'})
    for name, expected in (('sources', SOURCES), ('expected', EXPORT)):
        directory(work / name)
        require({item.name for item in (work / name).iterdir()} == expected)
    raw, digest, _ = read_file(work / 'inputs.json', 0o444)
    require(digest == inputs_sha)
    inputs = parse(raw)
    require(type(inputs) is dict and set(inputs) == {'schema_version', 'files'} and type(inputs['schema_version']) is int
            and inputs['schema_version'] == 1 and type(inputs['files']) is dict and set(inputs['files']) == INPUT_FILES
            and all(type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) for value in inputs['files'].values()))
    stamps = {}; contract = None
    for name in sorted(INPUT_FILES):
        size = returned_size if name == 'returned.img' else IMAGE_SIZE if name == 'expected/' + IMAGE else None
        raw, digest, current = read_file(work / name,
            0o600 if name == 'returned.img' or name.startswith('expected/') else 0o444, image_size=size)
        require(inputs['files'][name] == digest)
        if size is not None:
            require(digest == (returned_sha if name == 'returned.img' else IMAGE_SHA256))
            stamps[name] = current
        elif name == 'expected/manifest.json':
            require(parse(raw).get('image') == {'filename': IMAGE, 'size_bytes': IMAGE_SIZE, 'sha256': IMAGE_SHA256})
        elif name == 'sources/verify-test-enrollment-return.py':
            require(digest == CONTROLLER_SHA256)
            contract = controller_contract(raw)
    image = work / 'returned.img'
    require(not associated(image))
    passed = {'sealed_inputs', 'expected_image_bytes_pinned', 'returned_image_bytes_pinned'}
    mounts, outcome, code, error = [], None, None, None
    stage = 'private_namespaces'
    def interrupted(_signum, _frame):
        raise InterruptedError('return_check_interrupted')
    signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
    try:
        require(all(os.readlink(f'/proc/self/ns/{name}') != os.readlink(f'/proc/1/ns/{name}') for name in ('mnt', 'net', 'uts')))
        require({line.split(':')[0].strip() for line in pathlib.Path('/proc/net/dev').read_text().splitlines()[2:]} == {'lo'})
        passed.add(stage); stage = 'readonly_loop'
        loop = command('losetup', '--read-only', '--find', '--show', '--partscan', '--', str(image)).stdout.decode().strip()
        require(re.fullmatch(r'/dev/loop[0-9]+', loop) is not None and associated(image) == [loop])
        require(pathlib.Path('/sys/class/block', pathlib.Path(loop).name, 'ro').read_text().strip() == '1')
        passed.add(stage); stage = 'expected_partition_layout'
        for _ in range(30):
            if all(pathlib.Path(loop + suffix).exists() for suffix in ('p1', 'p2')):
                break
            time.sleep(0.1)
        require(command('lsblk', '-nr', '-o', 'TYPE', loop).stdout.split() == [b'loop', b'part', b'part'])
        require(command('blkid', '-p', '-s', 'TYPE', '-o', 'value', loop + 'p1').stdout.strip() == b'vfat'
                and command('blkid', '-p', '-s', 'TYPE', '-o', 'value', loop + 'p2').stdout.strip() == b'ext4')
        passed.add(stage); stage = 'readonly_mounts'
        for name, suffix, filesystem, options in (('root', 'p2', 'ext4', 'ro,noload,noatime,nosuid,nodev,noexec'),
                                                ('boot', 'p1', 'vfat', 'ro,noatime,nosuid,nodev,noexec')):
            target = work / name; target.mkdir(mode=0o700)
            mounts.append(str(target))
            command('mount', '-t', filesystem, '-o', options, loop + suffix, str(target))
        stage = 'controller_outcome'
        result = command('/usr/bin/python3', '-I', str(work / 'sources/verify-test-enrollment-return.py'),
            '--rootfs', str(work / 'root'), '--bootfs', str(work / 'boot'), '--expected-export', str(work / 'expected'),
            timeout=40, allow_failure=True)
        outcome = validate_result(result.returncode, result.stdout, contract)
        code = result.returncode
        passed.add('controller_result_closed')
    except Exception:
        error = stage
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN); signal.signal(signal.SIGINT, signal.SIG_IGN)
        removed, detached = cleanup(mounts, image)
        if removed:
            passed.add('mounts_removed')
        if detached:
            passed.add('loop_detached')
        if not (removed and detached):
            error = 'cleanup_incomplete'
        try:
            require(all(stamp((work / name).lstat()) == original for name, original in stamps.items()))
            passed.add('image_metadata_unchanged')
        except Exception:
            error = 'image_metadata_changed'
    infrastructure = error is None and passed == set(CHECKS)
    report = dict(schema_version=1, scope='native-acquired-sd-enrollment-return',
        infrastructure_verified=infrastructure, error_stage=error, inputs_sha256=inputs_sha,
        returned_image_sha256=returned_sha, returned_image_size_bytes=returned_size,
        expected_image_sha256=IMAGE_SHA256, runner_sha256=inputs['files'][RUNNER],
        sources_sha256={name: inputs['files']['sources/' + name] for name in sorted(SOURCES)},
        checks={name: name in passed for name in CHECKS}, controller_exit_code=code, controller_result=outcome,
        hardware_qualified=False, application_activated=False, release_qualified=False,
        authenticity_verified=False, shutdown_observed=False, private_key_file_read=False,
        returned_image_container_hashed=True, expected_image_bytes_hashed=True)
    fd = os.open(work / 'report.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        output.write(json.dumps(report, sort_keys=True, indent=2) + '\n')
        output.flush(); os.fsync(output.fileno())
    print(json.dumps(report, sort_keys=True))
    return code if infrastructure else 2


if __name__ == '__main__':
    try:
        status = main(pathlib.Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4])
    except Exception:
        print('Return check refused; no private data emitted.', file=sys.stderr)
        status = 2
    sys.exit(status)
PY_RETURN
