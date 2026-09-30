#!/usr/bin/env bash
# Private enrollment-only image derivation. No build-time target identity.
set -Eeuo pipefail
umask 077
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"
PYTHON=${PYTHON:-python3}
exec "$PYTHON" -I - "$@" <<'PY_ENROLLMENT'
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile


VM = 'inkyos-build'
PARENT_IMAGE = '4cd9d6fa8183dfb8a7a04c350ab3d3366900264fab2fa0dff90192a7e4cc9a04'
SOURCE = '758a2bf7ed099aad41ef35316e53228e797b0b2b'
APPLICATION_MANIFEST = '0d587792433d924ad1c4e71af19c2a46279f573791cb690571fa1019e7703551'
PROFILE = 'private-profile.json'
PRIVATE_KEY = 'client_ed25519'
RECIPE_FILES = (
    'scripts/build-test-enrollment.sh', 'scripts/build-test-enrollment-linux.sh',
    'scripts/configure-test-enrollment-rootfs.py', 'scripts/verify-test-enrollment.py',
    'scripts/test-enrollment-firstboot.py', 'overlay-test-enrollment/inkyos-test-enrollment.service',
    'scripts/observe-test-panel.py', 'scripts/observe-test-radio.py',
    'scripts/configure-test-lan-rootfs.py', 'scripts/test-lan-preflight.py', 'scripts/verify-test-lan.py',
    'scripts/configure-rootfs.py', 'scripts/manifest-rootfs.py', 'scripts/inspect-image.sh',
    'scripts/inspect-rootfs.py', 'scripts/verify-prototype.py', 'scripts/verify-application-rootfs.py',
    'scripts/configure-application-rootfs.py', 'scripts/verify-application.py',
    'scripts/verify-sd-diagnostic.py', 'scripts/verify-artifacts.py',
    'config/base-image.lock.json', 'config/system-packages.lock.json',
)
INHERITED = ('config/base-image.lock.json', 'config/system-packages.lock.json',
             'scripts/configure-application-rootfs.py', 'scripts/verify-application-rootfs.py')
REPORTS = (
    'parent-manifest.json', 'parent-filesystem-manifest.json', 'parent-integrity.json', 'recipe.tar',
    'test-enrollment-configuration.json', 'qualification-prepared.json', 'qualification-static.json',
    'qualification-application.json', 'application-manifest.json', 'filesystem-manifest.json',
    'image-inspection.json', 'systemd-verify.txt', 'boot-preserved.sha256', 'fsck-ext4.txt', 'fsck-fat.txt',
    'build.log',
)
VM_REPORTS = ('test-enrollment-configuration.json', 'qualification-prepared.json', 'qualification-static.json',
              'qualification-application.json', 'filesystem-manifest.json', 'image-inspection.json',
              'systemd-verify.txt', 'boot-preserved.sha256', 'fsck-ext4.txt', 'fsck-fat.txt')


class ClosedError(ValueError):
    pass


def require(condition):
    if not condition:
        raise ClosedError('enrollment_preparation_refused')


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ClosedError('invalid_arguments')


def arguments(argv):
    parser = Parser(prog='build-test-enrollment.sh', allow_abbrev=False,
        description='Prepare a PRIVATE enrollment-and-stop image; requires the marked build VM. '
                    'Creates one new Mac client key; never copies its private half to the image or VM.')
    parser.add_argument('parent', type=Path, help='Existing pinned TEST LAN prepared export')
    parser.add_argument('--country', required=True, choices=('FR',),
                        help='Explicit operator request; this phase never applies the country or enables networking')
    return parser.parse_args(argv)


def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('ascii')


def read_regular(path, limit=64 * 1024**2):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit)
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    require(len(raw) == before.st_size and
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
    return raw


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)


def public_key(raw):
    require(type(raw) is bytes and len(raw) <= 1024)
    words = raw.split()
    require(len(words) == 2 and words[0] == b'ssh-ed25519')
    try:
        decoded = base64.b64decode(words[1], validate=True)
    except ValueError:
        raise ClosedError('invalid_generated_public_key') from None
    require(len(decoded) == 51 and decoded[:19] == b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'
            and base64.b64encode(decoded) == words[1])
    return b' '.join(words).decode('ascii')


def profile(public, challenge, country):
    require(country == 'FR' and type(challenge) is str and re.fullmatch('[0-9a-f]{64}', challenge)
            and challenge != '0' * 64 and public_key(public.encode()) == public)
    return {'schema_version': 1, 'kind': 'test-lan-enrollment', 'purpose': 'test-enroll-and-stop',
        'state': 'enrollment-pending', 'application_source_commit': SOURCE,
        'application_manifest_sha256': APPLICATION_MANIFEST, 'parent_image_sha256': PARENT_IMAGE,
        'operator_public_key': public, 'challenge': challenge, 'country_requested': country,
        'network_profile_present': False, 'ssh_access_enabled': False,
        'application_activation_authorized': False, 'hardware_qualified': False, 'release_qualified': False}


def validate_parent(raw):
    data = json.loads(raw)
    require(type(data.get('schema_version')) is int and data['schema_version'] == 1
            and data.get('kind') == 'test-lan-prepared' and data.get('hardware_qualified') is False
            and data.get('release_qualified') is False and data.get('no_active_application') is True
            and data.get('ready_for_activation') is False
            and data.get('application') == {'source_commit': SOURCE, 'manifest_sha256': APPLICATION_MANIFEST,
                'application_version': '0.5.0-rc.2', 'startup': 'masked-pending-firstboot-contract', 'release_qualified': False})
    image = data.get('image')
    require(isinstance(image, dict) and image.get('sha256') == PARENT_IMAGE
            and type(image.get('size_bytes')) is int and 0 < image['size_bytes'] <= 32 * 1024**3
            and type(image.get('filename')) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]*\\.img', image['filename']))
    return data


def private_directory(repo):
    base = repo / 'private'
    try:
        base.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = base.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
    for _ in range(20):
        work = base / ('test-enrollment.' + os.urandom(4).hex())
        try:
            work.mkdir(mode=0o700)
            return work
        except FileExistsError:
            continue
    raise ClosedError('private_directory_unavailable')


def invoke(argv, *, input=None, destination=None, capture=False, timeout=900):
    # Never forward raw command output: even an error may contain profile data.
    if destination is None:
        result = subprocess.run(argv, input=input, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=timeout)
    else:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            result = subprocess.run(argv, input=input, stdout=stream, stderr=subprocess.DEVNULL, timeout=timeout)
    require(result.returncode == 0)
    return result.stdout if capture else None


def guest(*argv):
    return ['limactl', 'shell', '--workdir=/tmp', VM, *argv]


def snapshot(work, parent, parent_raw, sources, profile_raw, commit, dirty):
    data = validate_parent(parent_raw)
    require(set(sources) == set(RECIPE_FILES) and re.fullmatch('[0-9a-f]{40}', commit) and type(dirty) is bool)
    for name in INHERITED:
        require(hashlib.sha256(sources[name]).hexdigest() == data['recipe']['files'][name])
    application = read_regular(parent / 'application-manifest.json')
    inventory = read_regular(parent / 'filesystem-manifest.json')
    require(hashlib.sha256(application).hexdigest() == APPLICATION_MANIFEST
            and hashlib.sha256(inventory).hexdigest() == data['reports']['filesystem-manifest.json'])
    blobs = dict(sources, **{'parent-manifest.json': parent_raw, 'application-manifest.json': application, PROFILE: profile_raw})
    recipe = {'schema_version': 1, 'source_commit': commit, 'worktree_dirty': dirty,
              'files': {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(blobs.items())}}
    encoded = canonical(recipe)
    for name, raw in (('recipe-inputs.json', encoded), ('parent-manifest.json', parent_raw),
                      ('parent-filesystem-manifest.json', inventory), ('application-manifest.json', application)):
        write_new(work / name, raw)
    blobs['recipe-inputs.json'] = encoded
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(blobs.items()):
            member = tarfile.TarInfo('recipe/' + name)
            member.size = len(raw); member.mode = 0o600 if name == PROFILE else 0o444; member.mtime = 1789430400
            archive.addfile(member, io.BytesIO(raw))
    write_new(work / 'recipe.tar', buffer.getvalue())
    return recipe


SEAL = r'''
import hashlib,json,os,pathlib,re,stat,sys
data=json.load(sys.stdin); work=pathlib.Path(data['directory'])
assert re.fullmatch(r'/var/tmp/inkyos-work/test-enrollment\.[0-9a-f]{8}',str(work))
assert set(data['files'])=={'recipe.tar','test-enrollment.img'}
assert {p.name for p in work.iterdir()}==set(data['files'])|{'recipe'}
for entry in [work,*work.rglob('*')]:
    info=entry.lstat()
    assert stat.S_ISDIR(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink==1)
    os.chown(entry,0,0,follow_symlinks=False)
    mode=0o755 if stat.S_ISDIR(info.st_mode) else 0o444
    if entry==work: mode=0o700
    elif entry.name in ('recipe.tar','test-enrollment.img','private-profile.json'): mode=0o600
    os.chmod(entry,mode,follow_symlinks=False)
for name,pin in data['files'].items():
    with (work/name).open('rb') as stream:
        assert hashlib.file_digest(stream,'sha256').hexdigest()==pin
recipe=json.loads((work/'recipe/recipe-inputs.json').read_bytes())
assert hashlib.sha256((work/'recipe/recipe-inputs.json').read_bytes()).hexdigest()==data['recipe_inputs_sha256']
assert recipe['files']==data['recipe_files']
expected={'recipe-inputs.json',*recipe['files']}
assert {str(p.relative_to(work/'recipe')) for p in (work/'recipe').rglob('*') if p.is_file()}==expected
for name,pin in recipe['files'].items():
    relative=pathlib.PurePosixPath(name)
    assert not relative.is_absolute() and '..' not in relative.parts and str(relative)==name
    with (work/'recipe'/name).open('rb') as stream:
        assert hashlib.file_digest(stream,'sha256').hexdigest()==pin
'''


def transfers(work, parent, parent_data):
    require(re.fullmatch('test-enrollment\\.[0-9a-f]{8}', work.name) is not None)
    directory = '/var/tmp/inkyos-work/' + work.name
    return directory, ((work / 'recipe.tar', directory + '/recipe.tar'),
                       (parent / parent_data['image']['filename'], directory + '/test-enrollment.img'))


def transfer_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
    finally:
        os.close(fd)


def manifest(work, parent_data, profile_sha256):
    image = work / 'inkyos-test-enrollment.img'
    fd = os.open(image, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size == parent_data['image']['size_bytes'])
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_size, after.st_mtime_ns, after.st_ctime_ns))
    value = {'schema_version': 1, 'kind': 'test-lan-enrollment', 'private_artifact': True,
        'bootstrap_action': 'enroll-and-stop', 'no_active_application': True, 'ready_for_activation': False,
        'hardware_qualified': False, 'release_qualified': False, 'application': parent_data['application'],
        'parent': {'kind': 'test-lan-prepared', 'image_sha256': PARENT_IMAGE, 'size_bytes': before.st_size,
                   'manifest_sha256': hashlib.sha256(read_regular(work / 'parent-manifest.json')).hexdigest()},
        'personalization': {'profile_sha256': profile_sha256, 'network_profile_present': False, 'country_requested': 'FR'},
        'image': {'filename': image.name, 'size_bytes': before.st_size, 'sha256': digest},
        'recipe': json.loads(read_regular(work / 'recipe-inputs.json')),
        'reports': {name: hashlib.sha256(read_regular(work / name)).hexdigest() for name in REPORTS}}
    write_new(work / 'manifest.json', canonical(value))
    write_new(work / 'SHA256SUMS', (digest + '  ' + image.name + '\n').encode())


def main(argv=None):
    stage = 'arguments'
    try:
        args = arguments(argv)
        require(sys.platform == 'darwin' and os.geteuid() != 0)
        repo = Path.cwd()
        stage = 'parent_pin'
        info = args.parent.lstat()
        require(stat.S_ISDIR(info.st_mode))
        parent_raw = read_regular(args.parent / 'manifest.json')
        parent_data = validate_parent(parent_raw)
        stage = 'recipe_sources'
        sources = {name: read_regular(repo / name) for name in RECIPE_FILES}
        stage = 'private_workspace'
        work = private_directory(repo)
        stage = 'parent_integrity'
        invoke([sys.executable, '-I', 'scripts/verify-test-lan.py', str(args.parent),
                '--output', str(work / 'parent-integrity.json')])
        require(read_regular(args.parent / 'manifest.json') == parent_raw)
        stage = 'builder_identity'
        require(invoke(guest('cat', '/var/lib/inkyos-build/owner'), capture=True, timeout=30).strip() == b'inkyos-builder-v1')
        stage = 'new_local_client_key'
        # New path only. Never read, copy, hash or reuse any private key bytes.
        invoke(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', '', '-f', str(work / PRIVATE_KEY)], timeout=30)
        info = (work / PRIVATE_KEY).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600)
        public = public_key(read_regular(work / (PRIVATE_KEY + '.pub'), 1024))
        challenge = os.urandom(32).hex()
        profile_raw = canonical(profile(public, challenge, args.country))
        write_new(work / PROFILE, profile_raw)
        stage = 'private_snapshot'
        commit = invoke(['git', 'rev-parse', 'HEAD'], capture=True, timeout=30).decode('ascii').strip()
        dirty = bool(invoke(['git', 'status', '--porcelain'], capture=True, timeout=30))
        recipe = snapshot(work, args.parent, parent_raw, sources, profile_raw, commit, dirty)
        directory, copies = transfers(work, args.parent, parent_data)
        stage = 'private_vm_staging'
        invoke(guest('mkdir', '-m', '700', '--', directory), timeout=30)
        for local, remote in copies:
            transfer_file(local)
            invoke(['limactl', 'copy', str(local), VM + ':' + remote])
        invoke(guest('tar', '-xf', directory + '/recipe.tar', '-C', directory))
        seal = {'directory': directory, 'files': {'recipe.tar': hashlib.sha256(read_regular(work / 'recipe.tar')).hexdigest(),
                                                'test-enrollment.img': PARENT_IMAGE},
                'recipe_files': recipe['files'],
                'recipe_inputs_sha256': hashlib.sha256(read_regular(work / 'recipe-inputs.json')).hexdigest()}
        invoke(guest('sudo', 'python3', '-I', '-c', SEAL), input=canonical(seal))
        stage = 'offline_enrollment_build'
        invoke(guest('sudo', 'bash', directory + '/recipe/scripts/build-test-enrollment-linux.sh', directory))
        write_new(work / 'build.log', b'Offline enrollment preparation completed; target runtime was not started.\n')
        stage = 'private_reception'
        for name in VM_REPORTS:
            invoke(guest('sudo', 'cat', directory + '/' + name), destination=work / name)
        invoke(guest('sudo', 'cat', directory + '/test-enrollment.img'), destination=work / 'inkyos-test-enrollment.img')
        stage = 'private_export_integrity'
        manifest(work, parent_data, hashlib.sha256(profile_raw).hexdigest())
        invoke([sys.executable, '-I', 'scripts/verify-test-enrollment.py', str(work),
                '--output', str(work.parent / (work.name + '.integrity.json'))])
        stage = 'completed_vm_copy_cleanup'
        invoke(guest('sudo', 'rm', '--', directory + '/test-enrollment.img'), timeout=30)
        print('Private enrollment image and evidence prepared in ' + str(work))
        print('Enrollment boot, host identity, operator access and application activation remain unqualified.')
        return 0
    except Exception:
        print('Enrollment preparation failed at ' + stage + '; private evidence retained, no activation authorized.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
PY_ENROLLMENT
