#!/usr/bin/env python3
"""Install pinned application bytes offline into a disposable image rootfs.

Only the dedicated ARM64 builder's private mount/network namespace is accepted.
The candidate build backend runs as UID/GID 1000 inside the target rootfs; no
application, helper, service or runtime smoke is started. A successful result is
an installation check, not first-boot, hardware or release qualification.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import zipfile

_spec = importlib.util.spec_from_file_location(
    'rootfs_archive_inspector', Path(__file__).with_name('inspect-application-archives.py'))
inspector = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(inspector)

APPLICATION = Path('/home/inky/inky-studio')
SCRATCH = Path('/var/tmp/inkyos-application-install')
BUILD_ID = 'inkyos-builder-v1'
LOCK_LINE = re.compile(
    r'[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9][A-Za-z0-9.!+_-]*'
    r'(?:\s+--hash=sha256:[0-9a-f]{64})+')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def checked_path(path, *, missing=False):
    """Reject symlinks in every component, traversal and non-ordinary leaves."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'Absolute canonical path required')
    current = Path(path.anchor)
    for index, part in enumerate(path.parts[1:]):
        current /= part
        if missing and index == len(path.parts) - 2 and not os.path.lexists(current):
            return path
        info = current.lstat()
        require(not stat.S_ISLNK(info.st_mode), 'Symlink in path refused')
        if current != path:
            require(stat.S_ISDIR(info.st_mode), 'Directory parent required')
        else:
            require(stat.S_ISDIR(info.st_mode) or
                    (stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
                    'Ordinary directory or single-link file required')
    return path


def check_environment(rootfs, manifest, assets, output):
    require(platform.system() == 'Linux' and platform.machine() == 'aarch64'
            and os.geteuid() == 0, 'Dedicated root ARM64 builder required')
    marker = checked_path(Path('/var/lib/inkyos-build/owner'))
    require(marker.read_text().strip() == BUILD_ID and marker.stat().st_uid == 0,
            'Dedicated builder marker required')
    require(os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net') and
            sorted(name for _, name in socket.if_nameindex()) == ['lo'],
            'Private network namespace with only loopback required')
    require(os.readlink('/proc/self/ns/mnt') != os.readlink('/proc/1/ns/mnt'),
            'Private mount namespace required')
    require(re.fullmatch(r'/var/tmp/inkyos-work/prototype\.[A-Za-z0-9]+/root', str(rootfs)),
            'Dedicated prototype rootfs path required')
    checked_path(rootfs)
    require(os.path.ismount(rootfs) and rootfs.stat().st_uid == 0,
            'Mounted root-owned image rootfs required')
    # Accept only the regular image's ext4 loop partition, never a physical disk.
    mounts = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    records = [fields for fields in mounts if fields[4] == str(rootfs)]
    require(len(records) == 1, 'Unique image mount required')
    fields = records[0]; split = fields.index('-')
    require(fields[split + 1] == 'ext4' and
            re.fullmatch(r'/dev/loop\d+p2', fields[split + 2]) and
            {'rw', 'nosuid', 'nodev'} <= set(fields[5].split(',')),
            'Writable nosuid/nodev ext4 image loop mount required')
    work = rootfs.parent
    for path in (manifest, assets):
        checked_path(path)
        require(path.is_relative_to(work) and not path.is_relative_to(rootfs),
                'Application inputs must stay outside rootfs within prototype workspace')
    checked_path(output, missing=True)
    require(output.parent == work and not os.path.lexists(output),
            'New report in prototype workspace required')
    home = checked_path(rootfs / 'home/inky')
    require(home.stat().st_uid == 1000 and home.stat().st_gid == 1000,
            'Prepared inky home UID/GID 1000 required')
    require(not os.path.lexists(rootfs / APPLICATION.relative_to('/')),
            'Application destination already exists')
    checked_path(rootfs / SCRATCH.parent.relative_to('/'))
    require(not os.path.lexists(rootfs / SCRATCH.relative_to('/')),
            'Application scratch already exists')


def copy_regular(source, target, limit):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                before.st_size <= limit, 'Bounded single-link regular input required')
        with target.open('xb') as out:
            total = 0
            while block := stream.read(1024**2):
                total += len(block)
                require(total <= limit, 'Snapshot input exceeds size limit')
                out.write(block)
        after = os.fstat(stream.fileno())
        require(inspector.file_signature(before) == inspector.file_signature(after) ==
                inspector.file_signature(source.lstat()), 'Snapshot input changed')
    target.chmod(0o600)
    return target


def validate_lock(path):
    require(path.stat().st_size <= inspector.verifier.MAX_MANIFEST, 'Python lock exceeds size limit')
    entries = []
    for line in path.read_text(encoding='utf-8').replace('\\\n', ' ').splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            require(LOCK_LINE.fullmatch(line), 'Only exact package versions and SHA-256 hashes accepted')
            entries.append(re.sub(r'[-_.]+', '-', line.split('==')[0]).lower())
    require(entries and len(entries) == len(set(entries)), 'Nonempty unique package lock required')


def extract_inputs(data, assets, application, scratch):
    """Extract pre-inspected immutable snapshots; retain independent path guards."""
    application.mkdir(mode=0o755)
    wheelhouse = scratch / 'wheelhouse'; wheelhouse.mkdir(mode=0o755)
    by_role = {asset['role']: assets / asset['filename'] for asset in data['assets']}
    with tarfile.open(by_role['application'], 'r:gz') as archive:
        paths = inspector.Paths()
        for member in archive:
            require(member.isfile() or member.isdir(), 'Ordinary tar members required')
            kind = 'directory' if member.isdir() else 'file'
            name = inspector.safe_name(member.name, member.isdir(), inspector.DEFAULT_LIMITS)
            inspector.application_path(name, kind); paths.add(name, kind)
            require(not (name == 'server/.venv' or name.startswith('server/.venv/')),
                    'Candidate must not contain a pre-existing venv')
            require(not (member.mode & 0o6000), 'Privileged source modes refused')
            target = application / name
            if member.isdir():
                target.mkdir(mode=0o755, parents=True, exist_ok=True)
            else:
                require(member.size <= inspector.DEFAULT_LIMITS.member_bytes, 'Source member exceeds limit')
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                with target.open('xb') as out, archive.extractfile(member) as source:
                    shutil.copyfileobj(source, out, 1024**2)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
    with zipfile.ZipFile(by_role['wheelhouse']) as archive:
        paths = inspector.Paths()
        for member in archive.infolist():
            kind = 'directory' if member.is_dir() else 'file'
            name = inspector.safe_name(member.filename, member.is_dir(), inspector.DEFAULT_LIMITS)
            inspector.wheelhouse_path(name, kind); paths.add(name, kind)
            mode = member.external_attr >> 16
            require(not stat.S_IFMT(mode) or
                    (stat.S_ISDIR(mode) if member.is_dir() else stat.S_ISREG(mode)),
                    'Ordinary zip members required')
            target = wheelhouse / name
            if member.is_dir():
                target.mkdir(mode=0o755, parents=True, exist_ok=True)
            else:
                require(member.file_size <= inspector.DEFAULT_LIMITS.member_bytes, 'Wheelhouse member exceeds limit')
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                with target.open('xb') as out, archive.open(member) as source:
                    shutil.copyfileobj(source, out, 1024**2)
                target.chmod(0o644)
    lock = scratch / 'requirements.lock'
    copy_regular(by_role['python_lock'], lock, inspector.verifier.MAX_MANIFEST)
    validate_lock(lock); lock.chmod(0o644)
    return wheelhouse, lock


def install_steps():
    venv = APPLICATION / 'server/.venv'
    pip = [str(venv / 'bin/python'), '-m', 'pip', '--isolated',
           '--disable-pip-version-check', '--no-cache-dir']
    return [
        ('venv', ['/usr/bin/python3', '-m', 'venv', str(venv)]),
        ('dependencies', pip + ['install', '--no-index', '--only-binary=:all:',
                               '--require-hashes', '--no-compile', '--find-links',
                               str(SCRATCH / 'wheelhouse'), '-r', str(SCRATCH / 'requirements.lock')]),
        ('editable', pip + ['install', '--no-index', '--no-deps', '--no-build-isolation',
                           '--no-compile', '-e', str(APPLICATION / 'server') + '[pi]']),
        ('pip-check', pip + ['check']),
    ]


def child_command(rootfs, command):
    # chroot must happen before dropping privileges. All candidate/build code is
    # then unprivileged; the host environment never reaches the target command.
    return ['/usr/bin/unshare', '--pid', '--ipc', '--fork', '--kill-child=KILL',
            '/usr/sbin/chroot', str(rootfs), '/usr/bin/setpriv', '--reuid=1000',
            '--regid=1000', '--clear-groups', '--no-new-privs', '/usr/bin/env', '-i',
            'PATH=/usr/bin:/bin', 'LANG=C.UTF-8', 'LC_ALL=C.UTF-8', 'TZ=UTC',
            'PYTHONNOUSERSITE=1', 'PYTHONDONTWRITEBYTECODE=1', 'PYTHONHASHSEED=0',
            'PIP_CONFIG_FILE=/dev/null', 'SOURCE_DATE_EPOCH=1789430400',
            'TMPDIR=' + str(SCRATCH / 'tmp'), *command]


def child_limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (256 * 1024**2, 256 * 1024**2))


def run_step(rootfs, command, log, timeout=300):
    with log.open('xb') as out:
        process = subprocess.Popen(child_command(rootfs, command), cwd=rootfs,
                                   env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'}, stdout=out,
                                   stderr=subprocess.STDOUT, start_new_session=True,
                                   preexec_fn=child_limits)
        try:
            return process.wait(timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise


def finish_tree(application):
    """Remove incidental bytecode without following links, then audit ownership."""
    allowed_links = {
        'server/.venv/bin/python': 'python3',
        'server/.venv/bin/python3': '/usr/bin/python3',
        'server/.venv/bin/python3.13': 'python3',
        'server/.venv/lib64': 'lib',
    }
    removed = 0; files = 0; size = 0
    for directory, dirs, names in os.walk(application, followlinks=False):
        for name in dirs + names:
            path = Path(directory) / name; info = path.lstat()
            require(info.st_uid == 1000 and info.st_gid == 1000, 'Unexpected delivered file ownership')
            if stat.S_ISLNK(info.st_mode):
                require(allowed_links.get(path.relative_to(application).as_posix()) == os.readlink(path),
                        'Unexpected delivered symlink')
            elif stat.S_ISREG(info.st_mode):
                require(info.st_nlink == 1 and not info.st_mode & 0o6000,
                        'Unexpected delivered hardlink or privileged mode')
                if path.suffix == '.pyc':
                    path.unlink(); removed += 1
                else:
                    files += 1; size += info.st_size
            else:
                require(stat.S_ISDIR(info.st_mode), 'Unexpected delivered special file')
    # Empty cache directories are generated content too. Nonempty source dirs
    # are retained; no recursive deletion follows application-controlled links.
    for directory, _, _ in os.walk(application, topdown=False, followlinks=False):
        path = Path(directory)
        if path.name == '__pycache__' and not path.is_symlink() and not any(path.iterdir()):
            path.rmdir()
    return {'files': files, 'file_bytes': size, 'removed_bytecode_files': removed,
            'uid': 1000, 'gid': 1000, 'unexpected_links': 0, 'bytecode_files': 0}


def stop(signum, frame):
    raise KeyboardInterrupt


def main(argv=None):
    signal.signal(signal.SIGTERM, stop)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--assets-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    check_environment(args.rootfs, args.manifest, args.assets_dir, args.output)
    os.umask(0o022)
    logs = args.output.with_name(args.output.stem + '.logs'); logs.mkdir(mode=0o700)
    snapshot = logs / 'inputs'; snapshot.mkdir(mode=0o700)
    data = inspector.verifier.verify(args.manifest, args.sha256, args.assets_dir)
    manifest = copy_regular(args.manifest, snapshot / 'manifest.json', inspector.verifier.MAX_MANIFEST)
    for asset in data['assets']:
        copy_regular(args.assets_dir / asset['filename'], snapshot / asset['filename'], asset['size_bytes'])
    inspection = inspector.inspect_application(manifest, args.sha256, snapshot)
    free_before = shutil.disk_usage(args.rootfs).free
    require(sum(item['expanded_file_bytes'] for item in inspection['archives'].values()) < free_before,
            'Insufficient rootfs space for extracted inputs')
    application = args.rootfs / APPLICATION.relative_to('/')
    scratch = args.rootfs / SCRATCH.relative_to('/'); scratch.mkdir(mode=0o755)
    extract_inputs(data, snapshot, application, scratch)
    # No candidate code has run: all extracted nodes are ordinary files/dirs.
    for path in [application, *application.rglob('*')]:
        require(not path.is_symlink(), 'Unexpected extracted link')
        os.chown(path, 1000, 1000)
    temporary = scratch / 'tmp'; temporary.mkdir(mode=0o700); os.chown(temporary, 1000, 1000)
    report = {
        'schema_version': 1, 'scope': 'offline-application-rootfs-install', 'passed': False,
        'manifest_sha256': args.sha256, 'source_commit': data['source_commit'],
        'application_version': data['application_version'], 'recipe_sha256': sha(Path(__file__)),
        'application_path': str(APPLICATION), 'venv_path': str(APPLICATION / 'server/.venv'),
        'build_uid': 1000, 'build_gid': 1000, 'network_interfaces': ['lo'],
        'inputs_snapshotted_root_only': True, 'input_snapshot_removed': False,
        'scratch_removed': False, 'app_started': False,
        'hardware_qualified': False, 'release_qualified': False,
        'free_bytes_before': free_before, 'archive_inspection': inspection, 'steps': [],
        'limits': ['Build backend and pip execute; no application or helper startup.',
                   'No system boot, radio, GPIO/SPI, first adoption or hardware qualification.'],
    }
    for name, command in install_steps():
        log = logs / (name + '.txt')
        try:
            code = run_step(args.rootfs, command, log)
        except subprocess.TimeoutExpired:
            code = 124
        except KeyboardInterrupt:
            code = 130
        report['steps'].append({'name': name, 'exit_code': code,
                                'log': logs.name + '/' + log.name, 'log_sha256': sha(log)})
        if code:
            break
    if len(report['steps']) == len(install_steps()) and all(step['exit_code'] == 0 for step in report['steps']):
        report['installed_tree'] = finish_tree(application)
        require(shutil.rmtree.avoids_symlink_attacks, 'Safe scratch removal unavailable')
        shutil.rmtree(scratch); shutil.rmtree(snapshot)
        report['scratch_removed'] = True; report['input_snapshot_removed'] = True
        report['passed'] = True
    report['free_bytes_after'] = shutil.disk_usage(args.rootfs).free
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2, sort_keys=True); stream.write('\n')
    print(json.dumps({'passed': report['passed'], 'source_commit': data['source_commit'],
                      'application_path': str(APPLICATION), 'steps': report['steps']}, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError) as exc:
        print(f'Application image installation refused: {exc}', file=sys.stderr)
        sys.exit(1)
