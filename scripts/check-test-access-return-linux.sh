#!/usr/bin/env bash
# Check an already acquired PRIVATE image; never open an SD or boot target code.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
if [[ ${1:-} == --help && $# == 1 ]]; then
  echo 'Usage: sudo bash STAGING/check-test-access-return-linux.sh STAGING INPUTS_SHA256 RETURNED_SIZE RETURNED_SHA256 EXPECTED_SIZE EXPECTED_SHA256'
  echo 'STAGING: /var/lib/inkyos-build/access-return.<8 lowercase hex>, root0700, dedicated builder VM only.'
  echo 'Closed inputs: runner0444, inputs.json0444, sources/16 files0444, expected/20 files0600, returned.img0600.'
  echo 'inputs.json: {"schema_version":1,"files":{"relative/path":"sha256",...}} seals all 38 files.'
  echo 'READ ONLY loop, ext4 ro,noload and FAT ro; no replay, boot, radio, application or private-key file read.'
  echo 'After native PASS, re-read and cleanup: two files0600 in new /var/lib/inkyos-build/access-context.<same nonce>.'
  echo 'Export owner is the verified nonroot SUDO_USER/SUDO_UID/SUDO_GID; directory0700, no arbitrary destination.'
  exit 0
fi
[[ $# == 6 && $(uname -s) == Linux && $(uname -m) == aarch64 && $EUID == 0 ]] || exit 2
work=$(readlink -e -- "$1") || exit 2
[[ $work == "$1" && $work =~ ^/var/lib/inkyos-build/access-return\.[0-9a-f]{8}$
   && $2 =~ ^[0-9a-f]{64}$ && $3 =~ ^[1-9][0-9]{0,10}$ && $4 =~ ^[0-9a-f]{64}$
   && $5 =~ ^[1-9][0-9]{0,10}$ && $6 =~ ^[0-9a-f]{64}$ ]] || exit 2
[[ $(readlink -e -- "$0") == "$work/check-test-access-return-linux.sh" ]] || exit 2
for tool in unshare timeout findmnt losetup lsblk blkid mount umount python3; do
  command -v "$tool" >/dev/null || exit 2
done
if [[ ${INKYOS_ACCESS_RETURN_NAMESPACE:-} != 1 ]]; then
  exec timeout --signal=TERM --kill-after=100s 900s \
    unshare --mount --net --uts --propagation private \
    env INKYOS_ACCESS_RETURN_NAMESPACE=1 bash "$0" "$work" "$2" "$3" "$4" "$5" "$6"
fi
for namespace in mnt net uts; do
  [[ $(readlink "/proc/self/ns/$namespace") != $(readlink "/proc/1/ns/$namespace") ]] || exit 2
done
[[ $(findmnt -n -o PROPAGATION /) == private ]] || exit 2
exec python3 -I - "$work" "$2" "$3" "$4" "$5" "$6" <<'PY_ACCESS_RETURN'
import ast, hashlib, importlib.util, json, os, pathlib, pwd, re, signal, stat, subprocess, sys, time
sys.dont_write_bytecode = True

RUNNER = 'check-test-access-return-linux.sh'
PRIMITIVES = 'check-test-enrollment-return-linux.sh'
PRIMITIVES_SHA256 = '52feb5b9e191c21ae4eff6caa34499cdb9eb57e6021446f1af7a260e4b8d2ec6'
CONTROLLER = 'verify-test-access-return.py'
CONTROLLER_SHA256 = 'ba54b5a988f33e4a63217ef7eb54ea89b59674dbe7b67e0a9613cd612e781c71'
IMAGE = 'inkyos-test-access.img'
SOURCES = {PRIMITIVES, CONTROLLER, 'verify-test-enrollment-return.py', 'test-enrollment-firstboot.py',
    'verify-test-enrollment.py', 'verify-test-lan.py', 'configure-test-enrollment-rootfs.py',
    'configure-test-lan-rootfs.py', 'verify-sd-diagnostic.py', 'verify-artifacts.py', 'configure-rootfs.py',
    'verify-test-access.py', 'configure-test-access-rootfs.py', 'test-access-policy.py',
    'test-access-enrollment.py', 'build-test-access.py'}
REPORTS = {'parent-manifest.json', 'parent-filesystem-manifest.json', 'parent-integrity.json', 'recipe.tar',
    'test-access-configuration.json', 'qualification-prepared.json', 'qualification-static.json',
    'qualification-application.json', 'application-manifest.json', 'filesystem-manifest.json',
    'image-inspection.json', 'systemd-verify.txt', 'boot-preserved.sha256', 'fsck-ext4.txt', 'fsck-fat.txt',
    'build.log', 'sudoers-verify.txt'}
EXPORT = REPORTS | {'manifest.json', 'recipe-inputs.json', IMAGE}
INPUT_FILES = {RUNNER, 'returned.img'} | {'sources/' + name for name in SOURCES} | {'expected/' + name for name in EXPORT}
OUTPUT_FILES = {'context.json', 'known_hosts'}
FALSE_FIELDS = ('application_activation_authorized', 'ssh_access_enabled', 'network_profile_present',
    'hardware_qualified', 'release_qualified', 'authenticity_verified', 'runtime_execution_attested',
    'image_sha256_verified', 'shutdown_observed')
CHECKS = ('sealed_inputs', 'expected_image_bytes_pinned', 'returned_image_bytes_pinned', 'private_namespaces',
    'readonly_loop', 'expected_partition_layout', 'controller_result_closed', 'mounts_removed',
    'loop_detached', 'input_metadata_unchanged')


def require(value):
    if value is not True:
        raise ValueError('access_return_refused')


def primitives(path):
    """Import only definitions from an exact local, sealed historical source."""
    # Parent safety is checked before loading even this first trusted source.
    require(path.is_absolute() and path.resolve() == path)
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o444 and info.st_size <= 65536)
        raw = os.read(fd, 65537)
        require(len(raw) == info.st_size and hashlib.sha256(raw).hexdigest() == PRIMITIVES_SHA256)
        stamp = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
                              item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        require(stamp(info) == stamp(os.fstat(fd)) == stamp(path.lstat()))
    finally:
        os.close(fd)
    source = raw.decode('utf-8').split("<<'PY_RETURN'\n", 1)[1].rsplit('\nPY_RETURN', 1)[0]
    # Omit the historical CLI guard entirely; never evaluate or call v1 main.
    tree = ast.parse(source)
    require(isinstance(tree.body[-1], ast.If) and ast.unparse(tree.body[-1].test) == "__name__ == '__main__'")
    tree.body.pop()
    require(all(isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef)) for node in tree.body))
    namespace = {'__name__': 'sealed_return_primitives'}
    exec(compile(tree, str(path), 'exec'), namespace)
    return namespace


def account(environment):
    name, uid, gid = (environment.get(key, '') for key in ('SUDO_USER', 'SUDO_UID', 'SUDO_GID'))
    require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', name) is not None
            and re.fullmatch(r'[1-9][0-9]{0,9}', uid) is not None
            and re.fullmatch(r'[1-9][0-9]{0,9}', gid) is not None)
    info = pwd.getpwnam(name)
    require(info.pw_uid == int(uid) and info.pw_gid == int(gid)
            and pwd.getpwuid(int(uid)).pw_name == name)
    return int(uid), int(gid)


def load_controller(work):
    path = work / 'sources' / CONTROLLER
    spec = importlib.util.spec_from_file_location('sealed_access_return_contract', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    require(type(module.CHECKS) is tuple and len(module.CHECKS) == len(set(module.CHECKS)) == 35
            and tuple(module.CHECKS[:4]) == ('rootfs_readonly_ext4', 'bootfs_readonly_vfat',
                'expected_export_consistent', 'expected_image_stat_checked'))
    return module


def validate_result(code, raw, controller, parse):
    require(type(code) is int and code in (0, 1, 2) and len(raw) <= 65536)
    value = parse(raw)
    fixed = dict(schema_version=1, kind='test-access-return-comparison',
        scope='offline-readonly-v2-enrollment-consistency', observation_source='native-read-only',
        limits=controller.LIMITS, **dict.fromkeys(FALSE_FIELDS, False))
    require(type(value) is dict and set(value) == set(fixed) | {'status', 'passed', 'checks', 'error',
            'native_readonly_evidence', 'context_written', 'private_output_files_written'}
        and type(value['schema_version']) is int and all(value[key] == expected for key, expected in fixed.items())
        and all(value[key] is False for key in FALSE_FIELDS)
        and type(value['checks']) is dict and set(value['checks']) == set(controller.CHECKS)
        and all(type(flag) is bool for flag in value['checks'].values())
        and all(type(value[key]) is bool for key in ('passed', 'context_written', 'native_readonly_evidence'))
        and type(value['private_output_files_written']) is int and value['private_output_files_written'] in (0, 2))
    require(value['status'] == ('PASS', 'FAIL', 'INVALID')[code] and value['passed'] is (code == 0))
    errors = {0: {None}, 1: {'readonly_mount_required', 'return_incomplete', 'return_inconsistent', 'context_output_refused'},
              2: {'invalid_input', 'context_output_refused', 'readonly_cleanup_failed'}}
    require(value['error'] in errors[code])
    require(value['native_readonly_evidence'] is all(value['checks'][name] for name in controller.CHECKS[:2]))
    if code == 0:
        require(all(value['checks'].values()) and value['context_written'] is True and value['private_output_files_written'] == 2)
    else:
        require(value['context_written'] is False)
    return value


def validate_context(raws, controller, expected):
    require(type(raws) is dict and set(raws) == OUTPUT_FILES)
    policy = controller.policy
    value = policy.strict_json(raws['context.json'])
    profile = policy.strict_json(expected['profile_bytes'])
    require(policy.validate_profile(profile) is True)
    match = re.fullmatch(rb'\[inky-[0-9a-f]{32}\.local\]:2222 (ssh-ed25519 [A-Za-z0-9+/]{68})\n', raws['known_hosts'])
    require(match is not None)
    wire = policy.public_key(match[1].decode('ascii'))
    require(wire is not None)
    expected_value = controller._context(profile, expected['profile_sha256'], controller.digest(wire),
                                          controller.digest(expected['manifest_bytes']))
    require(raws['context.json'] == policy.canonical(expected_value) and value == expected_value)
    return True


def read_context(path, lib, controller, expected):
    lib['directory'](path)
    require({child.name for child in path.iterdir()} == OUTPUT_FILES)
    raws = {name: lib['read_file'](path / name, 0o600)[0] for name in OUTPUT_FILES}
    require(all(len(raw) <= 4096 for raw in raws.values()))
    validate_context(raws, controller, expected)
    return raws


def export_context(destination, raws, owner, lib):
    """Publish two files, re-read while root-private, give directory access last."""
    require(set(raws) == OUTPUT_FILES)
    lib['ancestors'](destination.parent)
    parent = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    directory = output = None
    try:
        parent_info = os.fstat(parent)
        require(stat.S_IMODE(parent_info.st_mode) == 0o755)
        os.mkdir(destination.name, 0o700, dir_fd=parent)
        directory = os.open(destination.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        for name, raw in raws.items():
            output = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            offset = 0
            while offset < len(raw):
                count = os.write(output, raw[offset:]); require(count > 0); offset += count
            os.fsync(output)
            os.close(output); output = None
        require(set(os.listdir(directory)) == OUTPUT_FILES)
        for name, raw in raws.items():
            output = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            before = os.fstat(output)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                    and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
                    and before.st_size == len(raw) and os.read(output, len(raw) + 1) == raw)
            os.fchown(output, *owner)
            after = os.fstat(output)
            require((after.st_uid, after.st_gid) == owner and stat.S_IMODE(after.st_mode) == 0o600
                    and lib['stamp'](after) == lib['stamp'](os.stat(name, dir_fd=directory, follow_symlinks=False)))
            os.fsync(output)
            os.close(output); output = None
        os.fsync(directory)
        os.fchown(directory, *owner)
        info = os.fstat(directory)
        require((info.st_uid, info.st_gid) == owner and stat.S_IMODE(info.st_mode) == 0o700
                and lib['stamp'](info) == lib['stamp'](os.stat(destination.name, dir_fd=parent, follow_symlinks=False)))
        os.fsync(directory); os.fsync(parent)
    finally:
        for fd in (output, directory, parent):
            if fd is not None: os.close(fd)


def main(work, inputs_sha, returned_size, returned_sha, expected_size, expected_sha):
    require(0 < expected_size <= returned_size <= 32 * 1024**3 and expected_size % 512 == returned_size % 512 == 0
            and all(re.fullmatch(r'[0-9a-f]{64}', value) is not None for value in (inputs_sha, returned_sha, expected_sha))
            and re.fullmatch(r'/var/lib/inkyos-build/access-return\.[0-9a-f]{8}', str(work)) is not None)
    lib = primitives(work / 'sources' / PRIMITIVES)
    lib['ancestors'](work); lib['directory'](work)
    require({item.name for item in work.iterdir()} == {RUNNER, 'inputs.json', 'sources', 'expected', 'returned.img'})
    owner = account(os.environ)
    marker, _, _ = lib['read_file'](pathlib.Path('/var/lib/inkyos-build/owner'), 0o644)
    require(marker == b'inkyos-builder-v1\n')
    destination = work.parent / ('access-context.' + work.name.rsplit('.', 1)[1])
    require(not destination.exists() and not destination.is_symlink())
    for name, names in (('sources', SOURCES), ('expected', EXPORT)):
        lib['directory'](work / name)
        require({item.name for item in (work / name).iterdir()} == names)
    raw, seal, inputs_stamp = lib['read_file'](work / 'inputs.json', 0o444)
    require(seal == inputs_sha)
    inputs = lib['parse'](raw)
    require(type(inputs) is dict and set(inputs) == {'schema_version', 'files'} and type(inputs['schema_version']) is int
            and inputs['schema_version'] == 1 and type(inputs['files']) is dict and set(inputs['files']) == INPUT_FILES
            and all(type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) for value in inputs['files'].values()))
    stamps = {'inputs.json': inputs_stamp}
    for name in sorted(INPUT_FILES):
        size = returned_size if name == 'returned.img' else expected_size if name == 'expected/' + IMAGE else None
        raw, pin, stamps[name] = lib['read_file'](work / name,
            0o600 if name == 'returned.img' or name.startswith('expected/') else 0o444, image_size=size)
        require(pin == inputs['files'][name])
        if size is not None:
            require(pin == (returned_sha if name == 'returned.img' else expected_sha))
        elif name == 'sources/' + CONTROLLER:
            require(pin == CONTROLLER_SHA256)
        elif name == 'expected/manifest.json':
            require(lib['parse'](raw).get('image') == {'filename': IMAGE, 'size_bytes': expected_size, 'sha256': expected_sha})
    controller = load_controller(work)
    tree = controller.ReadTree(str(work / 'expected'), private=True)
    try: expected = controller.expected_export(tree)
    finally: tree.close()
    image = work / 'returned.img'
    require(not lib['associated'](image))
    passed = {'sealed_inputs', 'expected_image_bytes_pinned', 'returned_image_bytes_pinned'}
    mounts, outcome, code, error, private = [], None, None, None, None
    stage = 'private_namespaces'
    def interrupted(_signum, _frame): raise InterruptedError('return_check_interrupted')
    signal.signal(signal.SIGTERM, interrupted); signal.signal(signal.SIGINT, interrupted)
    try:
        require(all(os.readlink('/proc/self/ns/' + name) != os.readlink('/proc/1/ns/' + name) for name in ('mnt', 'net', 'uts')))
        require({line.split(':')[0].strip() for line in pathlib.Path('/proc/net/dev').read_text().splitlines()[2:]} == {'lo'})
        passed.add(stage); stage = 'readonly_loop'
        loop = lib['command']('losetup', '--read-only', '--find', '--show', '--partscan', '--', str(image)).stdout.decode().strip()
        require(re.fullmatch(r'/dev/loop[0-9]+', loop) is not None and lib['associated'](image) == [loop])
        require(pathlib.Path('/sys/class/block', pathlib.Path(loop).name, 'ro').read_text().strip() == '1')
        passed.add(stage); stage = 'expected_partition_layout'
        for _ in range(30):
            if all(pathlib.Path(loop + suffix).exists() for suffix in ('p1', 'p2')): break
            time.sleep(0.1)
        require(lib['command']('lsblk', '-nr', '-o', 'TYPE', loop).stdout.split() == [b'loop', b'part', b'part'])
        require(lib['command']('blkid', '-p', '-s', 'TYPE', '-o', 'value', loop + 'p1').stdout.strip() == b'vfat'
                and lib['command']('blkid', '-p', '-s', 'TYPE', '-o', 'value', loop + 'p2').stdout.strip() == b'ext4')
        passed.add(stage); stage = 'readonly_mounts'
        for name, suffix, filesystem, options in (('root', 'p2', 'ext4', 'ro,noload,noatime,nosuid,nodev,noexec'),
                                                ('boot', 'p1', 'vfat', 'ro,noatime,nosuid,nodev,noexec')):
            target = work / name; target.mkdir(mode=0o700); mounts.append(str(target))
            lib['command']('mount', '-t', filesystem, '-o', options, loop + suffix, str(target))
        stage = 'controller_outcome'
        result = lib['command']('/usr/bin/python3', '-I', str(work / 'sources' / CONTROLLER),
            '--rootfs', str(work / 'root'), '--bootfs', str(work / 'boot'), '--expected-export', str(work / 'expected'),
            '--context-output', str(work / 'private-context'), timeout=60, allow_failure=True)
        outcome = validate_result(result.returncode, result.stdout, controller, lib['parse'])
        code = result.returncode; passed.add('controller_result_closed')
        if code == 0:
            stage = 'private_context'
            private = read_context(work / 'private-context', lib, controller, expected)
    except Exception:
        error = stage
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN); signal.signal(signal.SIGINT, signal.SIG_IGN)
        removed, detached = lib['cleanup'](mounts, image)
        if removed: passed.add('mounts_removed')
        if detached: passed.add('loop_detached')
        if not (removed and detached): error = 'cleanup_incomplete'
        try:
            require(all(lib['stamp']((work / name).lstat()) == before for name, before in stamps.items()))
            passed.add('input_metadata_unchanged')
        except Exception:
            error = 'input_metadata_changed'
    infrastructure = error is None and passed == set(CHECKS)
    exported = False
    if infrastructure and code == 0:
        try:
            require(read_context(work / 'private-context', lib, controller, expected) == private)
            export_context(destination, private, owner, lib)
            exported = True
        except Exception:
            infrastructure = False; error = 'context_export_refused'
    report = dict(schema_version=1, scope='native-acquired-sd-access-return', infrastructure_verified=infrastructure,
        error_stage=error, inputs_sha256=inputs_sha, returned_image_sha256=returned_sha,
        returned_image_size_bytes=returned_size, expected_image_sha256=expected_sha, expected_image_size_bytes=expected_size,
        runner_sha256=inputs['files'][RUNNER], checks={name: name in passed for name in CHECKS},
        controller_exit_code=code, controller_result=outcome, private_context_exported=exported,
        private_output_files_exported=2 if exported else 0, hardware_qualified=False, release_qualified=False,
        application_activated=False, connection_authorized=False, private_key_file_read=False,
        returned_image_container_hashed=True, expected_image_bytes_hashed=True)
    fd = os.open(work / 'report.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        output.write(json.dumps(report, sort_keys=True, indent=2) + '\n'); output.flush(); os.fsync(output.fileno())
    print(json.dumps({key: report[key] for key in ('scope', 'infrastructure_verified', 'error_stage',
        'controller_exit_code', 'controller_result', 'private_context_exported', 'connection_authorized',
        'application_activated', 'hardware_qualified', 'release_qualified')}, sort_keys=True))
    return code if infrastructure and (code != 0 or exported) else 2


if __name__ == '__main__':
    try:
        status = main(pathlib.Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4], int(sys.argv[5]), sys.argv[6])
    except Exception:
        print('Access return check refused; no private data emitted.', file=sys.stderr)
        status = 2
    sys.exit(status)
PY_ACCESS_RETURN
