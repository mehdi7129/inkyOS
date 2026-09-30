#!/usr/bin/env python3
"""Configure only a private enroll-and-stop COPY of the exact PREPARED image.

Offline Linux builder only. No keys, account, Wi-Fi profile, radio country,
runtime state or FAT report are generated. Profile contents are never printed.
"""
import sys
sys.dont_write_bytecode = True

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat


SCRIPT_DIR = Path(__file__).resolve().parent
def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPT_DIR / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

prepared = module('_enrollment_prepared_contract', 'configure-test-lan-rootfs.py')
require = prepared.require
SOURCE_COMMIT = '758a2bf7ed099aad41ef35316e53228e797b0b2b'
MANIFEST_SHA256 = '0d587792433d924ad1c4e71af19c2a46279f573791cb690571fa1019e7703551'
PARENT_IMAGE_SHA256 = '4cd9d6fa8183dfb8a7a04c350ab3d3366900264fab2fa0dff90192a7e4cc9a04'
PRIVATE_PROFILE = 'private-profile.json'
PROFILE_PATH = 'etc/inkyos-test-enrollment/profile.json'
PROFILE_DIRECTORY = 'etc/inkyos-test-enrollment'
STATE_DIRECTORY = 'var/lib/inkyos-test-enrollment'
UNIT = 'inkyos-test-enrollment.service'
ENABLE_PATH = 'etc/systemd/system/multi-user.target.wants/' + UNIT
UNIT_TARGET = '/usr/lib/systemd/system/' + UNIT
SOURCES = frozenset({
    'scripts/configure-test-enrollment-rootfs.py', 'scripts/configure-rootfs.py',
    'scripts/test-enrollment-firstboot.py', 'scripts/observe-test-panel.py',
    'scripts/observe-test-radio.py', 'overlay-test-enrollment/inkyos-test-enrollment.service',
})
DEPENDENCIES = frozenset({'scripts/configure-test-lan-rootfs.py'})
RECIPE_FILES = frozenset({
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
    'application-manifest.json', 'parent-manifest.json', PRIVATE_PROFILE,
})
PAYLOADS = {
    'scripts/test-enrollment-firstboot.py': ('usr/local/lib/inkyos/test-enrollment-firstboot.py', 0o555),
    'scripts/observe-test-panel.py': ('usr/local/lib/inkyos/observe-test-panel.py', 0o555),
    'scripts/observe-test-radio.py': ('usr/local/lib/inkyos/observe-test-radio.py', 0o555),
    'overlay-test-enrollment/inkyos-test-enrollment.service': ('usr/lib/systemd/system/' + UNIT, 0o644),
}
MASKS = prepared.MASKS
PROTECTED_FILES = prepared.PROTECTED_FILES
PRESERVED_FILES = frozenset(prepared.STATIC_PARENT_FILES) | {
    'etc/passwd', 'etc/shadow', 'etc/group', 'etc/gshadow', 'etc/machine-id',
    'etc/inkyos-release.json', prepared.MARKER_PATH,
    'var/lib/NetworkManager/NetworkManager.state',
    'home/inky/inky-studio/server/SOURCE_COMMIT',
    'usr/local/lib/inkyos/test-lan-preflight.py',
    'usr/local/share/inkyos/inky-studio-manifest-v1.json',
}
CHECKS = frozenset({
    'exact_prepared_parent', 'private_profile_valid', 'profile_hash_matches',
    'profile_private_mode', 'state_directory_empty_private', 'enrollment_service_enabled_only',
    'payload_hashes_match', 'payload_modes_match', 'application_helper_ssh_masked',
    'updates_masked', 'wifi_disabled_no_profiles', 'no_precreated_identity_or_report',
    'not_booted', 'prepared_and_parent_files_preserved', 'bootfs_unchanged',
    'protected_boot_grow_files_preserved',
})


def parse_json(raw):
    def pairs(items):
        value = {}
        for name, item in items:
            require(name not in value, 'Invalid enrollment JSON')
            value[name] = item
        return value
    def invalid(_item):
        raise ValueError('Invalid enrollment JSON')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    except (UnicodeError, RecursionError):
        raise ValueError('Invalid enrollment JSON') from None


def validate_profile(data):
    # Shared pure schema validator, never the runtime main entry point.
    return module('_enrollment_pure_schema', 'test-enrollment-firstboot.py').validate_profile(data) is True


def profile_canonical(data):
    return module('_enrollment_pure_canonical', 'test-enrollment-firstboot.py').canonical(data)


def read_profile(path, *, owner_uid=0, owner_gid=0):
    path = Path(path).absolute()
    prepared.safe_tree(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid == owner_uid and before.st_gid == owner_gid
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size <= 4096,
                'Unsafe enrollment profile input')
        raw = bytearray()
        while len(raw) <= 4096:
            chunk = os.read(fd, min(4096, 4097 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after, current = os.fstat(fd), path.lstat()
        stamp = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        require(len(raw) <= 4096 and stamp(before) == stamp(after) == stamp(current), 'Enrollment profile input changed')
        raw = bytes(raw)
        data = parse_json(raw)
        require(validate_profile(data) and raw == profile_canonical(data), 'Enrollment profile contract refused')
        return raw
    finally:
        os.close(fd)


def owned(path, mode, owner_uid, owner_gid, *, directory=False):
    info = path.lstat()
    return ((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
            and info.st_uid == owner_uid and info.st_gid == owner_gid and stat.S_IMODE(info.st_mode) == mode)


def boot_snapshot(tree):
    result = {}
    for path in sorted(tree.root.rglob('*')):
        name = str(path.relative_to(tree.root))
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'Unexpected bootfs entry')
        result[name] = {'type': 'directory' if path.is_dir() else 'file', 'mode': stat.S_IMODE(info.st_mode),
                        'uid': info.st_uid, 'gid': info.st_gid}
        if path.is_file():
            result[name]['sha256'] = prepared.digest(tree, name)
    return hashlib.sha256(json.dumps(result, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def wifi_off(root):
    if root.read('var/lib/NetworkManager/NetworkManager.state') != '[main]\nWirelessEnabled=false\n':
        return False
    for relative in ('etc/NetworkManager/system-connections', 'run/NetworkManager/system-connections'):
        if not prepared.absent(root, relative):
            path = root.path(relative)
            if not stat.S_ISDIR(path.lstat().st_mode) or any(path.iterdir()):
                return False
    return True


def no_identity(root, boot):
    return (not any(entry.name.startswith('ssh_host_') for entry in root.path('etc/ssh').iterdir())
            and prepared.no_runtime_hooks(root, boot)
            and all(prepared.absent(root, name) for name in (
                'var/lib/inkyos/system.json', 'var/lib/inky-network', 'var/lib/systemd/random-seed',
                'etc/default/crda', 'etc/wpa_supplicant/wpa_supplicant.conf'))
            and all(prepared.absent(boot, name) for name in (
                'inkyos-enrollment', 'inkyos-test-enrollment.json', '.inkyos-test-enrollment.json.tmp',
                'ssh', 'ssh.txt', 'userconf', 'userconf.txt', 'user-data', 'network-config', 'meta-data')))


def only_enrollment_hook(root):
    allowed = {ENABLE_PATH, 'usr/lib/systemd/system/' + UNIT}
    for relative in ('etc/systemd/system', 'usr/lib/systemd/system'):
        for path in root.path(relative).rglob('*'):
            if 'inkyos-test-' in str(path.relative_to(root.root)):
                if str(path.relative_to(root.root)) not in allowed:
                    return False
    return True


def parent_valid(root, boot, *, owner_uid=0, owner_gid=0, app_uid=1000, app_gid=1000):
    marker = parse_json(prepared.read_bytes(root, prepared.MARKER_PATH))
    require(type(marker) is dict and marker.get('schema_version') == 1 and type(marker['schema_version']) is int
            and marker.get('kind') == 'test-lan-prepared' and marker.get('state') == 'prepared-inactive'
            and marker.get('source_commit') == SOURCE_COMMIT and marker.get('manifest_sha256') == MANIFEST_SHA256
            and marker.get('application_runtime') == 'masked'
            and all(marker.get(name) is False for name in ('ready_for_activation', 'activation_authorized',
                                                         'factory_authority', 'hardware_qualified', 'release_qualified')),
            'Exact inactive PREPARED parent required')
    require(owned(root.path(prepared.MARKER_PATH), 0o644, owner_uid, owner_gid), 'Prepared marker metadata differs')
    release = parse_json(prepared.read_bytes(root, 'etc/inkyos-release.json'))
    application = release.get('application') if type(release) is dict else None
    require(type(release) is dict and release.get('kind') == 'application-prototype' and prepared.reviewed_application(application)
            and application['source_commit'] == SOURCE_COMMIT and application['manifest_sha256'] == MANIFEST_SHA256,
            'Enrollment parent application pin differs')
    require(root.read('home/inky/inky-studio/server/SOURCE_COMMIT') == SOURCE_COMMIT + '\n'
            and prepared.digest(root, 'usr/local/share/inkyos/inky-studio-manifest-v1.json') == MANIFEST_SHA256,
            'Installed parent source declaration or manifest differs')
    prepared.static_parent(root, owner_uid=owner_uid, owner_gid=owner_gid)
    require(prepared.masked(root, MASKS) and wifi_off(root) and no_identity(root, boot), 'Inactive prepared parent policy differs')
    require(root.read('etc/machine-id') == 'uninitialized\n' and prepared.app_data_empty(root, app_uid=app_uid, app_gid=app_gid),
            'Enrollment requires never-booted parent and empty application data')
    require(owned(root.path('usr/local/lib/inkyos'), 0o700, owner_uid, owner_gid, directory=True), 'Private parent runtime directory differs')
    require(prepared.update_artifacts_absent(boot) and boot.read('config.txt').endswith(prepared.BOOT_APPEND), 'Parent firmware policy differs')
    for entry in root.path('etc').iterdir():
        require(not (entry.name.casefold().startswith('inkyos-') and entry.name.casefold().endswith('.json'))
                or entry.name in {'inkyos-release.json', 'inkyos-test-lan.json'}, 'Unknown image marker')
    require('inky-test' not in {line.partition(':')[0] for line in root.read('etc/passwd').splitlines()}, 'Operator account already exists')
    shadow = [line.split(':') for line in root.read('etc/shadow').splitlines()]
    require(shadow and all(len(row) == 9 and row[1].startswith(('!', '*')) for row in shadow)
            and {'root', 'inky', 'inky-network'} <= {row[0] for row in shadow}, 'Locked generic parent accounts required')
    return True


def configure(root, boot, source, profile, parent_sha256, *, _owner_uid=0, _owner_gid=0, _app_uid=1000, _app_gid=1000):
    require(parent_sha256 == PARENT_IMAGE_SHA256, 'Exact prepared parent image pin required')
    root, boot, source = (prepared.safe_tree(path) for path in (root, boot, source))
    trees = (root.root, boot.root, source.root)
    require(all(a != b and a not in b.parents and b not in a.parents for i, a in enumerate(trees) for b in trees[i + 1:]), 'Independent trees required')
    require(Path(profile).absolute() == source.root / PRIVATE_PROFILE, 'Only the private recipe profile is accepted')
    parent_valid(root, boot, owner_uid=_owner_uid, owner_gid=_owner_gid, app_uid=_app_uid, app_gid=_app_gid)
    require(only_enrollment_hook(root), 'Unknown TEST runtime hook present')
    additions = {PROFILE_DIRECTORY, STATE_DIRECTORY, ENABLE_PATH} | {path for path, _mode in PAYLOADS.values()}
    require(all(prepared.absent(root, path) for path in additions), 'Existing enrollment payload or state refused')
    payloads = {name: prepared.read_bytes(source, name) for name in RECIPE_FILES - {PRIVATE_PROFILE}}
    require(all(raw and len(raw) <= 1048576 for raw in payloads.values()), 'Missing or oversized enrollment source')
    for name in ('scripts/configure-test-enrollment-rootfs.py', 'scripts/configure-rootfs.py', 'scripts/configure-test-lan-rootfs.py', 'scripts/test-enrollment-firstboot.py'):
        require(payloads[name] == (SCRIPT_DIR / Path(name).name).read_bytes(), 'Executing enrollment contract differs from recipe')
    require(hashlib.sha256(payloads['application-manifest.json']).hexdigest() == MANIFEST_SHA256, 'Recipe application manifest differs from installed parent')
    inputs_raw = prepared.read_bytes(source, 'recipe-inputs.json')
    inputs = parse_json(inputs_raw)
    hashes = {name: hashlib.sha256(payloads[name]).hexdigest() for name in SOURCES}
    require(type(inputs) is dict and inputs.get('schema_version') == 1 and type(inputs['schema_version']) is int
            and type(inputs.get('worktree_dirty')) is bool and type(inputs.get('source_commit')) is str
            and len(inputs['source_commit']) == 40 and all(c in '0123456789abcdef' for c in inputs['source_commit'])
            and type(inputs.get('files')) is dict and set(inputs['files']) == RECIPE_FILES
            and all(inputs['files'].get(name) == hashlib.sha256(raw).hexdigest() for name, raw in payloads.items()), 'Enrollment recipe provenance differs')
    raw_profile = read_profile(profile, owner_uid=_owner_uid, owner_gid=_owner_gid)
    require(inputs['files'].get(PRIVATE_PROFILE) == hashlib.sha256(raw_profile).hexdigest(), 'Private profile hash differs from recipe')
    preserved = {name: prepared.digest(root, name) for name in PRESERVED_FILES}
    protected = prepared.protected_hashes(root, boot)
    boot_hash = boot_snapshot(boot)
    for relative in (PROFILE_DIRECTORY, STATE_DIRECTORY):
        path = root.path(relative)
        path.mkdir(mode=0o700)
        path.chmod(0o700)
        if os.geteuid() == 0:
            os.chown(path, _owner_uid, _owner_gid, follow_symlinks=False)
    prepared.write_owned(root, PROFILE_PATH, raw_profile.decode('utf-8'), 0o600)
    for name, (path, mode) in PAYLOADS.items():
        prepared.write_owned(root, path, payloads[name].decode('utf-8'), mode)
    root.link(ENABLE_PATH, UNIT_TARGET)
    return {'parent_image_sha256': parent_sha256, 'profile_sha256': hashlib.sha256(raw_profile).hexdigest(),
            'source_file_sha256': hashes, 'recipe_source_commit': inputs['source_commit'],
            'recipe_worktree_dirty': inputs['worktree_dirty'], 'recipe_inputs_sha256': hashlib.sha256(inputs_raw).hexdigest(),
            'preserved_parent_file_sha256': preserved, 'protected_boot_grow_sha256': protected, 'bootfs_snapshot_sha256': boot_hash}


def verification(root, boot, metadata, *, _owner_uid=0, _owner_gid=0, _app_uid=1000, _app_gid=1000):
    root, boot = (prepared.safe_tree(path) for path in (root, boot))
    raw_profile = read_profile(root.path(PROFILE_PATH), owner_uid=_owner_uid, owner_gid=_owner_gid)
    checks = {
        'exact_prepared_parent': parent_valid(root, boot, owner_uid=_owner_uid, owner_gid=_owner_gid, app_uid=_app_uid, app_gid=_app_gid)
            and metadata['parent_image_sha256'] == PARENT_IMAGE_SHA256,
        'private_profile_valid': validate_profile(parse_json(raw_profile)),
        'profile_hash_matches': hashlib.sha256(raw_profile).hexdigest() == metadata['profile_sha256'],
        'profile_private_mode': owned(root.path(PROFILE_DIRECTORY), 0o700, _owner_uid, _owner_gid, directory=True)
            and {path.name for path in root.path(PROFILE_DIRECTORY).iterdir()} == {'profile.json'},
        'state_directory_empty_private': owned(root.path(STATE_DIRECTORY), 0o700, _owner_uid, _owner_gid, directory=True)
            and not any(root.path(STATE_DIRECTORY).iterdir()),
        'enrollment_service_enabled_only': root.path(ENABLE_PATH).is_symlink() and os.readlink(root.path(ENABLE_PATH)) == UNIT_TARGET
            and only_enrollment_hook(root),
        'payload_hashes_match': all(prepared.digest(root, path) == metadata['source_file_sha256'][name] for name, (path, _mode) in PAYLOADS.items()),
        'payload_modes_match': all(owned(root.path(path), mode, _owner_uid, _owner_gid) for path, mode in PAYLOADS.values()),
        'application_helper_ssh_masked': prepared.masked(root, ('inky-studio.service', 'inky-network.service', 'ssh.service', 'ssh.socket', 'sshswitch.service')),
        'updates_masked': prepared.masked(root, MASKS),
        'wifi_disabled_no_profiles': wifi_off(root), 'no_precreated_identity_or_report': no_identity(root, boot),
        'not_booted': root.read('etc/machine-id') == 'uninitialized\n',
        'prepared_and_parent_files_preserved': all(prepared.digest(root, name) == digest for name, digest in metadata['preserved_parent_file_sha256'].items()),
        'bootfs_unchanged': boot_snapshot(boot) == metadata['bootfs_snapshot_sha256'],
        'protected_boot_grow_files_preserved': prepared.protected_hashes(root, boot) == metadata['protected_boot_grow_sha256'],
    }
    require(set(checks) == CHECKS and all(value is True for value in checks.values()), 'Enrollment static verification failed')
    return {'schema_version': 1, 'kind': 'test-lan-enrollment', 'scope': 'offline-test-enrollment-configuration',
            'passed': True, 'private_artifact': True, 'bootstrap_action': 'enroll-and-stop', 'application_started': False,
            'no_active_application': True, 'ready_for_activation': False, 'hardware_qualified': False, 'release_qualified': False,
            'removed_rootfs_paths': [], 'removed_bootfs_paths': [], 'checks': checks, **metadata}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('rootfs', 'bootfs', 'recipe', 'profile', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--parent-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        require(sys.platform == 'linux' and os.geteuid() == 0 and Path('/var/lib/inkyos-build/owner').read_text().strip() == 'inkyos-builder-v1', 'Isolated root Linux builder required')
        require(all(path.is_absolute() and path != Path('/') for path in (args.rootfs, args.bootfs, args.recipe, args.profile, args.output)), 'Absolute private build paths required')
        prepared.safe_tree(args.output.parent)
        require(not args.output.exists() and not args.output.is_symlink()
                and all(path != args.output and path not in args.output.parents for path in (args.rootfs, args.bootfs, args.recipe)), 'Independent new report required')
        metadata = configure(args.rootfs, args.bootfs, args.recipe, args.profile, args.parent_sha256)
        report = verification(args.rootfs, args.bootfs, metadata)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print('Private enrollment copy prepared; application and network access remain inactive.')
        return 0
    except (OSError, ValueError, TypeError, KeyError):
        print('Private enrollment configuration refused.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
