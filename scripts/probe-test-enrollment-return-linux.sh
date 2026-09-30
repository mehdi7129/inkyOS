#!/usr/bin/env bash
# Negative return test only, on an unbooted private export COPY; never boot it.
set -Eeuo pipefail
umask 077
if [[ ${1:-} == --help && $# == 1 ]]; then
  echo 'Usage: sudo bash STAGING/probe-test-enrollment-return-linux.sh STAGING INPUTS_SHA256'
  echo 'STAGING: /var/lib/inkyos-build/return-probe.<8 lowercase hex>, root0700.'
  echo 'Exactly probe script0444, inputs.json0444, sources/9 files0444, expected/19 files0600.'
  echo 'No standalone profile/client key. Requires the pinned unbooted image COPY; mounts READ ONLY.'
  exit 0
fi
[[ $# == 2 && $(uname -s) == Linux && $(uname -m) == aarch64 && $EUID == 0 ]] || exit 2
[[ $(cat /var/lib/inkyos-build/owner) == inkyos-builder-v1 ]] || exit 2
work=$(readlink -e -- "$1")
[[ $work == "$1" && $work =~ ^/var/lib/inkyos-build/return-probe\.[0-9a-f]{8}$ && $2 =~ ^[0-9a-f]{64}$ ]] || exit 2
[[ $(readlink -e -- "$0") == "$work/probe-test-enrollment-return-linux.sh" ]] || exit 2
for tool in unshare timeout findmnt losetup lsblk blkid mount umount python3; do
  command -v "$tool" >/dev/null || exit 2
done
if [[ ${INKYOS_ENROLLMENT_RETURN_NAMESPACE:-} != 1 ]]; then
  exec timeout --signal=TERM --kill-after=50s 120s \
    unshare --mount --net --uts --propagation private \
    env INKYOS_ENROLLMENT_RETURN_NAMESPACE=1 bash "$0" "$work" "$2"
fi
for namespace in mnt net uts; do
  [[ $(readlink "/proc/self/ns/$namespace") != $(readlink "/proc/1/ns/$namespace") ]] || exit 2
done
[[ $(findmnt -n -o PROPAGATION /) == private ]] || exit 2
exec python3 -I - "$work" "$2" <<'PY_RETURN'
import ast, hashlib, json, os, pathlib, re, signal, stat, subprocess, sys, time

IMAGE = 'inkyos-test-enrollment.img'
IMAGE_SHA256 = '7a1b70463e5501830f67e9c4b2ffcb69d8970a154115a8e9f8aa2e27eeb9d86e'
IMAGE_SIZE = 3061841920
CONTROLLER_SHA256 = '1846114c44253f5102cd99318394c22cd1aa58a8541e3bbd00baf95eccbc58f5'
PROBE = 'probe-test-enrollment-return-linux.sh'
SOURCES = {'verify-test-enrollment-return.py', 'test-enrollment-firstboot.py',
    'verify-test-enrollment.py', 'verify-test-lan.py', 'configure-test-enrollment-rootfs.py',
    'configure-test-lan-rootfs.py', 'verify-sd-diagnostic.py', 'verify-artifacts.py', 'configure-rootfs.py'}
REPORTS = {'parent-manifest.json', 'parent-filesystem-manifest.json', 'parent-integrity.json',
    'recipe.tar', 'test-enrollment-configuration.json', 'qualification-prepared.json',
    'qualification-static.json', 'qualification-application.json', 'application-manifest.json',
    'filesystem-manifest.json', 'image-inspection.json', 'systemd-verify.txt',
    'boot-preserved.sha256', 'fsck-ext4.txt', 'fsck-fat.txt', 'build.log'}
EXPORT = REPORTS | {'manifest.json', 'recipe-inputs.json', IMAGE}
INPUT_FILES = {PROBE} | {'sources/' + name for name in SOURCES} | {'expected/' + name for name in EXPORT}
FIRST_CHECKS = ('rootfs_readonly_ext4', 'bootfs_readonly_vfat', 'expected_export_consistent', 'expected_image_stat_checked')
FALSE_FIELDS = ('application_activation_authorized', 'ssh_access_enabled', 'network_profile_present',
    'hardware_qualified', 'release_qualified', 'authenticity_verified', 'runtime_execution_attested',
    'image_sha256_verified', 'shutdown_observed')
CHECKS = ('sealed_inputs', 'expected_image_bytes_pinned', 'private_namespaces', 'readonly_loop',
          'expected_partition_layout', 'expected_negative_return', 'mounts_removed', 'loop_detached', 'image_metadata_unchanged')


def require(value):
    if value is not True:
        raise ValueError('probe_refused')


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


def read_file(path, mode, *, image=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == mode and info.st_size <= (IMAGE_SIZE if image else 64 * 1024**2))
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        require(stamp(info) == stamp(os.fstat(stream.fileno())) == stamp(path.lstat()))
        if image:
            require(info.st_size == IMAGE_SIZE)
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
    require(type(code) is int and code == 1 and len(raw) <= 65536)
    value = parse(raw)
    expected = dict(schema_version=1, kind='test-enrollment-return-comparison',
        scope='offline-readonly-enrollment-consistency', status='FAIL', passed=False,
        observation_source='native-read-only', native_readonly_evidence=True,
        error='return_incomplete', checks={name: index < 4 for index, name in enumerate(contract['CHECKS'])},
        limits=contract['LIMITS'], **{key: False for key in FALSE_FIELDS})
    require(type(value) is dict and set(value) == set(expected) and value == expected
            and type(value['schema_version']) is int and type(value['checks']) is dict
            and all(type(item) is bool for item in value['checks'].values())
            and all(type(value[key]) is bool for key in (*FALSE_FIELDS, 'passed', 'native_readonly_evidence')))
    return value


def command(*args, timeout=10, allow_failure=False):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=timeout, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if not allow_failure:
        require(result.returncode == 0)
    return result


def main(work, inputs_sha):
    directory(work)
    require({item.name for item in work.iterdir()} == {PROBE, 'inputs.json', 'sources', 'expected'})
    for name, expected in (('sources', SOURCES), ('expected', EXPORT)):
        directory(work / name)
        require({item.name for item in (work / name).iterdir()} == expected)
    raw, digest, _stamp = read_file(work / 'inputs.json', 0o444)
    require(digest == inputs_sha)
    inputs = parse(raw)
    require(type(inputs) is dict and set(inputs) == {'schema_version', 'files'} and type(inputs['schema_version']) is int
            and inputs['schema_version'] == 1 and type(inputs['files']) is dict and set(inputs['files']) == INPUT_FILES)
    controller = None
    for name in sorted(INPUT_FILES):
        is_image = name == 'expected/' + IMAGE
        raw, digest, current = read_file(work / name, 0o600 if name.startswith('expected/') else 0o444, image=is_image)
        require(inputs['files'][name] == digest)
        if is_image:
            require(digest == IMAGE_SHA256)
            image_stamp = current
        elif name == 'expected/manifest.json':
            require(parse(raw).get('image') == {'filename': IMAGE, 'size_bytes': IMAGE_SIZE, 'sha256': IMAGE_SHA256})
        elif name == 'sources/verify-test-enrollment-return.py':
            require(digest == CONTROLLER_SHA256)
            controller = controller_contract(raw)
    passed, mounts, loop, error, outcome = {'sealed_inputs', 'expected_image_bytes_pinned'}, [], None, None, None
    stage = 'private_namespaces'
    def interrupted(_signum, _frame):
        raise InterruptedError('probe_interrupted')
    signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
    try:
        require(all(os.readlink(f'/proc/self/ns/{name}') != os.readlink(f'/proc/1/ns/{name}') for name in ('mnt', 'net', 'uts')))
        require({line.split(':')[0].strip() for line in pathlib.Path('/proc/net/dev').read_text().splitlines()[2:]} == {'lo'})
        passed.add(stage); stage = 'readonly_loop'
        loop = command('losetup', '--read-only', '--find', '--show', '--partscan', '--', str(work / 'expected' / IMAGE)).stdout.decode().strip()
        require(re.fullmatch(r'/dev/loop[0-9]+', loop) is not None)
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
            command('mount', '-t', filesystem, '-o', options, loop + suffix, str(target)); mounts.append(str(target))
        stage = 'controller_outcome'
        result = command('/usr/bin/python3', '-I', str(work / 'sources/verify-test-enrollment-return.py'),
            '--rootfs', str(work / 'root'), '--bootfs', str(work / 'boot'), '--expected-export', str(work / 'expected'),
            timeout=40, allow_failure=True)
        outcome = validate_result(result.returncode, result.stdout, controller)
        passed.add('expected_negative_return')
    except Exception:
        error = stage
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN); signal.signal(signal.SIGINT, signal.SIG_IGN)
        for target in reversed(mounts[:]):
            try:
                command('umount', target)
                require(command('findmnt', '-rn', '-M', target, allow_failure=True).returncode == 1)
                mounts.remove(target)
            except Exception:
                error = 'cleanup_incomplete'
        if not mounts:
            passed.add('mounts_removed')
            try:
                if loop is not None:
                    require(re.fullmatch(r'/dev/loop[0-9]+', loop) is not None)
                    command('losetup', '-d', loop)
                    require(command('losetup', loop, allow_failure=True).returncode != 0)
                passed.add('loop_detached')
            except Exception:
                error = 'cleanup_incomplete'
        if stamp((work / 'expected' / IMAGE).lstat()) == image_stamp:
            passed.add('image_metadata_unchanged')
        else:
            error = 'image_metadata_changed'
    report = dict(schema_version=1, scope='native-unbooted-enrollment-return-negative-probe',
        outcome_expected=error is None and passed == set(CHECKS), error_stage=error, inputs_sha256=inputs_sha,
        image_sha256=IMAGE_SHA256, sources_sha256={name: inputs['files']['sources/' + name] for name in sorted(SOURCES)},
        probe_sha256=inputs['files'][PROBE], checks={name: name in passed for name in CHECKS},
        failed_checks=[name for name in CHECKS if name not in passed], controller_result=outcome,
        hardware_qualified=False, application_activated=False, release_qualified=False, target_runtime_executed=False,
        authenticity_verified=False, controller_image_bytes_hashed=False, probe_image_bytes_hashed=True)
    fd = os.open(work / 'report.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        output.write(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print('Expected negative return confirmed.' if report['outcome_expected'] else 'Return probe failed; inspect the closed report.')
    return 0 if report['outcome_expected'] else 1


if __name__ == '__main__':
    try:
        status = main(pathlib.Path(sys.argv[1]), sys.argv[2])
    except Exception:
        print('Return probe refused before a report could be written.', file=sys.stderr)
        status = 1
    sys.exit(status)
PY_RETURN
