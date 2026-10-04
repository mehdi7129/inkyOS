#!/usr/bin/env python3
"""Offline private TEST child: fresh enrollment, then signed operator access.

Only a copy of the exact unbooted c31 PREPARED parent is accepted. This step
creates no host key, capsule, Wi-Fi profile or runtime state and runs no target
commands. The four account databases receive one explicit append; existing
application, generic system, and boot/grow bytes are preserved.
"""
import sys
sys.dont_write_bytecode = True

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat


SCRIPT_DIR = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPT_DIR / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


prepared = module('_access_prepared_configuration', 'configure-test-lan-rootfs.py')
policy = module('_access_private_policy', 'test-access-policy.py')
runtime = module('_access_enrollment_sources', 'test-access-enrollment.py')
require = prepared.require
SOURCE_COMMIT = policy.SOURCE
MANIFEST_SHA256 = policy.MANIFEST_HASH
PARENT_IMAGE_SHA256 = policy.PARENT_IMAGE_SHA256
PRIVATE_PROFILE = 'private-profile.json'
PRIVATE_MANIFEST = 'test-access-manifest.json'
PROFILE_DIRECTORY = 'etc/inkyos-test-enrollment'
PROFILE_PATH = PROFILE_DIRECTORY + '/profile.json'
STATE_DIRECTORY = 'var/lib/inkyos-test-enrollment'
CACHE_DIRECTORY = 'var/lib/inkyos-test-access'
SSH_DIRECTORY = 'etc/inkyos-test-ssh'
SSH_PUBLIC_DIRECTORY = 'usr/local/lib/inkyos-test-ssh'
AUTHORIZED_KEYS = SSH_DIRECTORY + '/authorized_keys'
MANIFEST_PATH = 'usr/local/share/inkyos/test-access-manifest.json'
UNIT = 'inkyos-test-access.service'
ENABLE_PATH = 'etc/systemd/system/multi-user.target.wants/' + UNIT
UNIT_TARGET = '/usr/lib/systemd/system/' + UNIT
MASKS = prepared.MASKS
PAYLOADS = {
    **{'scripts/' + name + '.py': ('usr/local/lib/inkyos/' + name + '.py', 0o555) for name in (
        'test-enrollment-firstboot', 'test-access-policy', 'test-access-enrollment',
        'test-access-contract', 'test-access-import', 'test-access-connect', 'test-access-boot',
        'test-access-network', 'test-access-wifi-gate', 'wifi-boot-gate', 'test-lan-preflight',
        'observe-test-panel', 'observe-test-radio')},
    'scripts/test-operator-dispatch.py': ('usr/local/lib/inkyos-test-ssh/dispatch.py', 0o555),
    'scripts/test-operator-runner.py': ('usr/local/lib/inkyos-test-ssh/runner', 0o555),
    'overlay-test-access/inkyos-test-access.service': ('usr/lib/systemd/system/' + UNIT, 0o644),
    'overlay-test-access/inkyos-test-ssh.service': ('usr/lib/systemd/system/inkyos-test-ssh.service', 0o644),
    'overlay-test-access/NetworkManager.service.d/10-inkyos-test-wifi.conf': (
        'etc/systemd/system/NetworkManager.service.d/10-inkyos-test-wifi.conf', 0o644),
    'overlay-test-access/NetworkManager.conf.d/10-inkyos-test-loopback.conf': (
        'etc/NetworkManager/conf.d/10-inkyos-test-loopback.conf', 0o644),
    'overlay-test-access/sshd_config': ('etc/inkyos-test-ssh/sshd_config', 0o644),
    'overlay-test-access/sudoers': ('etc/sudoers.d/inkyos-test-ssh', 0o440),
}
SOURCES = frozenset(PAYLOADS) | {
    'scripts/configure-test-access-rootfs.py', 'scripts/configure-test-lan-rootfs.py',
    'scripts/configure-rootfs.py', 'application-manifest.json',
}
RECIPE_FILES = SOURCES | {PRIVATE_PROFILE, PRIVATE_MANIFEST, 'parent-manifest.json'}
INHERITED_PAYLOADS = frozenset({'usr/local/lib/inkyos/test-lan-preflight.py'})
PRESERVED_FILES = frozenset(prepared.DRAIN_STATIC_PARENT_FILES) | {
    'etc/machine-id', 'etc/inkyos-release.json', prepared.MARKER_PATH,
    'var/lib/NetworkManager/NetworkManager.state', 'home/inky/inky-studio/server/SOURCE_COMMIT',
    'usr/local/lib/inkyos/test-lan-preflight.py', 'usr/local/share/inkyos/inky-studio-manifest-v1.json',
}
ACCOUNT_APPEND = {
    'etc/passwd': b'inky-test:x:1001:1001:InkyOS TEST operator:/nonexistent:/bin/sh\n',
    'etc/shadow': b'inky-test:!::0:::::\n',
    'etc/group': b'inky-test:x:1001:\n',
    'etc/gshadow': b'inky-test:!::\n',
}
CHECKS = frozenset({
    'exact_prepared_parent', 'private_profile_valid_and_bound', 'profile_private_mode',
    'enrollment_and_cache_empty_private', 'access_service_enabled_only',
    'static_manifest_exact_and_bound', 'payload_hashes_match', 'payload_modes_match',
    'application_helper_vendor_ssh_masked', 'updates_masked', 'wifi_disabled_no_profiles',
    'no_precreated_identity_capsule_or_report', 'not_booted', 'parent_files_preserved',
    'bootfs_unchanged', 'protected_boot_grow_files_preserved',
    'operator_account_exact_append_locked_unaged', 'operator_public_key_restricted_readable',
})


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def owned(path, mode, uid, gid, *, directory=False):
    info = path.lstat()
    return ((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
            and info.st_uid == uid and info.st_gid == gid and stat.S_IMODE(info.st_mode) == mode)


def read_bytes(tree, relative, *, limit=1048576):
    path = tree.path(relative)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit,
                'Regular bounded recipe or parent input required')
        raw = bytearray()
        while len(raw) <= limit:
            block = os.read(fd, min(65536, limit + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        stamp = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                             info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        require(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
                'Input changed while reading')
        return bytes(raw)
    finally:
        os.close(fd)


def read_profile(path, *, owner_uid=0, owner_gid=0):
    path = Path(path).absolute()
    tree = prepared.safe_tree(path.parent)
    require(owned(tree.root, 0o700, owner_uid, owner_gid, directory=True)
            and owned(tree.path(path.name), 0o600, owner_uid, owner_gid), 'Private profile metadata differs')
    raw = read_bytes(tree, path.name, limit=4096)
    value = policy.strict_json(raw)
    require(policy.validate_profile(value) and raw == policy.canonical(value), 'Private v2 profile refused')
    return raw


def _manifest(payloads):
    require({path for path, _mode in PAYLOADS.values()} == runtime.STATIC_PATHS, 'Static path contract differs')
    files = {path: {'sha256': sha256(payloads[name]), 'mode': f'{mode:04o}'}
             for name, (path, mode) in PAYLOADS.items()}
    for path, expected in runtime.SOURCE_PINS.items():
        require(files[path[1:]]['sha256'] == expected, 'Pinned enrollment dependency differs')
    return {'schema_version': 1, 'kind': 'test-access-runtime', 'application_source_commit': SOURCE_COMMIT,
            'application_manifest_sha256': MANIFEST_SHA256, 'parent_image_sha256': PARENT_IMAGE_SHA256, 'files': files}


def build_manifest(source):
    """Hash only fixed static recipe payloads. Profile/key paths are never read."""
    tree = prepared.safe_tree(source)
    return _manifest({name: read_bytes(tree, name) for name in PAYLOADS})


def boot_snapshot(tree):
    """Portable content/metadata snapshot: no inode, timestamps or mount IDs."""
    result = {}
    for path in sorted(tree.root.rglob('*')):
        relative = path.relative_to(tree.root).as_posix()
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'Unexpected bootfs entry')
        result[relative] = {'type': 'directory' if stat.S_ISDIR(info.st_mode) else 'file',
                            'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
        if stat.S_ISREG(info.st_mode):
            result[relative]['sha256'] = prepared.digest(tree, relative)
    return sha256(policy.canonical(result))


def wifi_off(root):
    if root.read('var/lib/NetworkManager/NetworkManager.state') != '[main]\nWirelessEnabled=false\n':
        return False
    for relative in ('etc/NetworkManager/system-connections', 'run/NetworkManager/system-connections'):
        if not prepared.absent(root, relative):
            directory = root.path(relative)
            if not stat.S_ISDIR(directory.lstat().st_mode) or any(directory.iterdir()):
                return False
    return True


def no_identity(root, boot):
    if (any(path.name.startswith('ssh_host_') for path in root.path('etc/ssh').iterdir())
            or not prepared.no_runtime_hooks(root, boot)):
        return False
    if any(not prepared.absent(root, path) for path in (
        'var/lib/inkyos/system.json', 'var/lib/inky-network', 'var/lib/systemd/random-seed',
        'etc/default/crda', 'etc/wpa_supplicant/wpa_supplicant.conf', 'etc/ssh/sshrc', 'nonexistent',
        PROFILE_DIRECTORY + '/ssh_host_ed25519_key', PROFILE_DIRECTORY + '/ssh_host_ed25519_key.pub')):
        return False
    forbidden = {'inkyos-enrollment', 'inkyos-test-enrollment.json', '.inkyos-test-enrollment.json.tmp',
                 'ssh', 'ssh.txt', 'userconf', 'userconf.txt', 'user-data', 'network-config', 'meta-data'}
    return not any(entry.name.casefold() in forbidden or entry.name.casefold().startswith(('inkyacc.', '.inkyacc.'))
                   for entry in boot.root.iterdir())


def only_access_hooks(root, *, configured):
    allowed = ({ENABLE_PATH} | {path for path, _mode in PAYLOADS.values()}) if configured else set()
    for relative in ('etc/systemd/system', 'usr/lib/systemd/system'):
        for path in root.path(relative).rglob('*'):
            name = path.relative_to(root.root).as_posix()
            if 'inkyos-test-' in name and name not in allowed:
                return False
    return True


def parent_valid(root, boot, *, owner_uid=0, owner_gid=0, app_uid=1000, app_gid=1000):
    marker = policy.strict_json(read_bytes(root, prepared.MARKER_PATH))
    require(type(marker) is dict and type(marker.get('schema_version')) is int and marker['schema_version'] == 1
            and marker.get('kind') == 'test-lan-prepared' and marker.get('state') == 'prepared-inactive'
            and marker.get('source_commit') == SOURCE_COMMIT and marker.get('manifest_sha256') == MANIFEST_SHA256
            and marker.get('application_runtime') == 'masked'
            and all(marker.get(key) is False for key in ('ready_for_activation', 'activation_authorized',
                'factory_authority', 'hardware_qualified', 'release_qualified'))
            and owned(root.path(prepared.MARKER_PATH), 0o644, owner_uid, owner_gid), 'Exact inactive PREPARED parent required')
    release = policy.strict_json(read_bytes(root, 'etc/inkyos-release.json'))
    app = release.get('application') if type(release) is dict else None
    require(type(release) is dict and release.get('kind') == 'application-prototype'
            and release.get('status') == 'not-hardware-qualified' and prepared.reviewed_application(app)
            and app['source_commit'] == SOURCE_COMMIT and app['manifest_sha256'] == MANIFEST_SHA256,
            'Exact inactive application parent required')
    require(root.read('home/inky/inky-studio/server/SOURCE_COMMIT') == SOURCE_COMMIT + '\n'
            and prepared.digest(root, 'usr/local/share/inkyos/inky-studio-manifest-v1.json') == MANIFEST_SHA256,
            'Parent source or manifest differs')
    prepared.static_parent(root, application=app, owner_uid=owner_uid, owner_gid=owner_gid)
    require(prepared.masked(root, MASKS) and wifi_off(root) and no_identity(root, boot), 'Inactive parent policy differs')
    require(root.read('etc/machine-id') == 'uninitialized\n'
            and prepared.app_data_empty(root, app_uid=app_uid, app_gid=app_gid), 'Never-booted parent with empty app data required')
    require(owned(root.path('usr/local/lib/inkyos'), 0o700, owner_uid, owner_gid, directory=True), 'Private runtime directory differs')
    require(prepared.update_artifacts_absent(boot) and boot.read('config.txt').endswith(prepared.BOOT_APPEND)
            and 'resize' in boot.read('cmdline.txt').split()
            and boot.read('inkyos.txt') == prepared.EXPECTED_INKYOS_CONFIG, 'Parent boot/grow or firmware policy differs')
    for entry in root.path('etc').iterdir():
        require(not (entry.name.casefold().startswith('inkyos-') and entry.name.casefold().endswith('.json'))
                or entry.name in {'inkyos-release.json', 'inkyos-test-lan.json'}, 'Unknown image marker')
    return True


def account_plan(root, *, owner_uid=0):
    raw = {name: read_bytes(root, name, limit=262144) for name in ACCOUNT_APPEND}
    rows = {}
    for name, count in (('etc/passwd', 7), ('etc/shadow', 9), ('etc/group', 4), ('etc/gshadow', 4)):
        require(raw[name].endswith(b'\n') and b'\0' not in raw[name], 'Malformed account database')
        rows[name] = [line.split(':') for line in raw[name].decode('ascii').splitlines()]
        require(rows[name] and all(len(row) == count and re.fullmatch(r'[a-z_][a-z0-9_-]*\$?', row[0]) for row in rows[name])
                and len({row[0] for row in rows[name]}) == len(rows[name])
                and all(row[0] != 'inky-test' for row in rows[name]), 'Existing or malformed operator account')
        info = root.path(name).lstat()
        require(info.st_uid == owner_uid and not info.st_mode & 0o022, 'Unsafe account database ownership or mode')
    passwd, groups = rows['etc/passwd'], rows['etc/group']
    require(all(re.fullmatch(r'0|[1-9][0-9]*', row[index]) and row[index] != '1001'
                for row in passwd for index in (2, 3))
            and all(re.fullmatch(r'0|[1-9][0-9]*', row[2]) and row[2] != '1001' for row in groups),
            'Operator UID or GID 1001 already used')
    require(all('inky-test' not in row[3].split(',') for row in groups)
            and all('inky-test' not in (row[2] + ',' + row[3]).split(',') for row in rows['etc/gshadow']),
            'Operator already referenced by a group')
    require(all(row[1].startswith(('!', '*')) for row in rows['etc/shadow'])
            and {'root', 'inky', 'inky-network'} <= {row[0] for row in passwd}
            and {row[0] for row in passwd} == {row[0] for row in rows['etc/shadow']}
            and {row[0] for row in groups} == {row[0] for row in rows['etc/gshadow']}, 'Locked consistent generic accounts required')
    metadata = {}
    for name, content in raw.items():
        info = root.path(name).lstat()
        metadata[name] = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
    return raw, metadata


def accounts_match(root, metadata, hashes):
    if (type(metadata) is not dict or set(metadata) != set(ACCOUNT_APPEND)
            or type(hashes) is not dict or set(hashes) != set(ACCOUNT_APPEND)):
        return False
    for name, line in ACCOUNT_APPEND.items():
        value, before = read_bytes(root, name, limit=262144), metadata[name]
        if (not value.endswith(line) or sha256(value[:-len(line)]) != hashes[name]['before']
                or sha256(value) != hashes[name]['after']
                or not owned(root.path(name), before['mode'], before['uid'], before['gid'])):
            return False
    return True


def configure(root, boot, source, profile, parent_sha256, *, _owner_uid=0, _owner_gid=0, _app_uid=1000, _app_gid=1000):
    require(parent_sha256 == PARENT_IMAGE_SHA256, 'Exact prepared parent image pin required')
    root, boot, source = (prepared.safe_tree(path) for path in (root, boot, source))
    trees = (root.root, boot.root, source.root)
    require(all(a != b and a not in b.parents and b not in a.parents for index, a in enumerate(trees) for b in trees[index + 1:]),
            'Independent image and recipe trees required')
    require(Path(profile).absolute() == source.root / PRIVATE_PROFILE, 'Only the private recipe profile is accepted')
    require(owned(source.root, 0o700, _owner_uid, _owner_gid, directory=True), 'Private recipe directory required')
    parent_valid(root, boot, owner_uid=_owner_uid, owner_gid=_owner_gid, app_uid=_app_uid, app_gid=_app_gid)
    require(only_access_hooks(root, configured=False), 'Previous TEST hook refused')
    additions = {PROFILE_DIRECTORY, STATE_DIRECTORY, CACHE_DIRECTORY, SSH_DIRECTORY, SSH_PUBLIC_DIRECTORY,
                 MANIFEST_PATH, ENABLE_PATH} | ({path for path, _mode in PAYLOADS.values()} - INHERITED_PAYLOADS)
    require(all(prepared.absent(root, path) for path in additions), 'Existing access payload, profile or state refused')
    account_bytes, account_before = account_plan(root, owner_uid=_owner_uid)
    payloads = {name: read_bytes(source, name) for name in SOURCES | {'parent-manifest.json'}}
    texts = {name: raw.decode('utf-8') for name, raw in payloads.items()}
    for name in ('configure-test-access-rootfs.py', 'configure-test-lan-rootfs.py', 'configure-rootfs.py',
                 'test-access-policy.py', 'test-access-enrollment.py'):
        require(payloads['scripts/' + name] == (SCRIPT_DIR / name).read_bytes(), 'Executing configuration differs from recipe')
    require(sha256(payloads['application-manifest.json']) == MANIFEST_SHA256, 'Recipe application manifest differs')
    manifest = _manifest(payloads)
    manifest_raw = read_bytes(source, PRIVATE_MANIFEST, limit=65536)
    require(manifest_raw == policy.canonical(manifest), 'Prepared static manifest differs from recipe payloads')
    for name, (path, mode) in PAYLOADS.items():
        if path in INHERITED_PAYLOADS:
            require(read_bytes(root, path) == payloads[name] and owned(root.path(path), mode, _owner_uid, _owner_gid),
                    'Inherited parent payload differs')
    inputs_raw = read_bytes(source, 'recipe-inputs.json', limit=262144)
    inputs = policy.strict_json(inputs_raw)
    require(type(inputs) is dict and type(inputs.get('schema_version')) is int and inputs['schema_version'] == 1
            and type(inputs.get('worktree_dirty')) is bool and type(inputs.get('source_commit')) is str
            and re.fullmatch(r'[0-9a-f]{40}', inputs['source_commit']) is not None
            and type(inputs.get('files')) is dict and RECIPE_FILES <= set(inputs['files'])
            and all(inputs['files'].get(name) == sha256(raw) for name, raw in payloads.items())
            and inputs['files'][PRIVATE_MANIFEST] == sha256(manifest_raw), 'Recipe provenance differs')
    profile_raw = read_profile(profile, owner_uid=_owner_uid, owner_gid=_owner_gid)
    value = policy.strict_json(profile_raw)
    require(inputs['files'][PRIVATE_PROFILE] == sha256(profile_raw)
            and value['access_runtime_manifest_sha256'] == sha256(manifest_raw), 'Private profile binding differs')
    preserved = {name: prepared.digest(root, name) for name in PRESERVED_FILES}
    protected, boot_hash = prepared.protected_hashes(root, boot), boot_snapshot(boot)
    for relative, mode in ((PROFILE_DIRECTORY, 0o700), (STATE_DIRECTORY, 0o700), (CACHE_DIRECTORY, 0o700),
                           (SSH_DIRECTORY, 0o755), (SSH_PUBLIC_DIRECTORY, 0o755)):
        directory = root.path(relative, create_parents=True)
        directory.mkdir(mode=mode)
        directory.chmod(mode)
        if os.geteuid() == 0:
            os.chown(directory, _owner_uid, _owner_gid, follow_symlinks=False)
    for name, (path, mode) in PAYLOADS.items():
        if path not in INHERITED_PAYLOADS:
            prepared.write_owned(root, path, texts[name], mode)
    # The manifest is published before its private profile. A partial build is
    # not resumable: the existing-artifact gate above requires a fresh copy.
    prepared.write_owned(root, MANIFEST_PATH, manifest_raw.decode('utf-8'), 0o644)
    prepared.write_owned(root, PROFILE_PATH, profile_raw.decode('utf-8'), 0o600)
    prepared.write_owned(root, AUTHORIZED_KEYS, 'restrict ' + value['operator_public_key'] + '\n', 0o644)
    for name, line in ACCOUNT_APPEND.items():
        before = account_before[name]
        root.write(name, (account_bytes[name] + line).decode('ascii'), before['mode'])
        if os.geteuid() == 0:
            os.chown(root.path(name), before['uid'], before['gid'], follow_symlinks=False)
    root.link(ENABLE_PATH, UNIT_TARGET)
    require(prepared.protected_hashes(root, boot) == protected and boot_snapshot(boot) == boot_hash, 'Protected boot/grow bytes changed')
    return {'parent_image_sha256': parent_sha256, 'profile_sha256': sha256(profile_raw),
            'access_runtime_manifest_sha256': sha256(manifest_raw),
            'source_file_sha256': {name: sha256(payloads[name]) for name in SOURCES},
            'recipe_source_commit': inputs['source_commit'], 'recipe_worktree_dirty': inputs['worktree_dirty'],
            'recipe_inputs_sha256': sha256(inputs_raw), 'preserved_parent_file_sha256': preserved,
            'protected_boot_grow_sha256': protected, 'bootfs_snapshot_sha256': boot_hash,
            'account_parent_metadata': account_before,
            'account_file_sha256': {name: {'before': sha256(raw), 'after': sha256(raw + ACCOUNT_APPEND[name])}
                                    for name, raw in account_bytes.items()}}


def verification(root, boot, metadata, *, _owner_uid=0, _owner_gid=0, _app_uid=1000, _app_gid=1000):
    root, boot = (prepared.safe_tree(path) for path in (root, boot))
    profile_raw = read_profile(root.path(PROFILE_PATH), owner_uid=_owner_uid, owner_gid=_owner_gid)
    value = policy.strict_json(profile_raw)
    manifest_raw = read_bytes(root, MANIFEST_PATH, limit=65536)
    manifest = policy.strict_json(manifest_raw)
    expected = {'schema_version': 1, 'kind': 'test-access-runtime', 'application_source_commit': SOURCE_COMMIT,
                'application_manifest_sha256': MANIFEST_SHA256, 'parent_image_sha256': PARENT_IMAGE_SHA256,
                'files': {path: {'sha256': metadata['source_file_sha256'][name], 'mode': f'{mode:04o}'}
                          for name, (path, mode) in PAYLOADS.items()}}
    checks = {
        'exact_prepared_parent': metadata['parent_image_sha256'] == PARENT_IMAGE_SHA256
            and parent_valid(root, boot, owner_uid=_owner_uid, owner_gid=_owner_gid, app_uid=_app_uid, app_gid=_app_gid),
        'private_profile_valid_and_bound': policy.validate_profile(value) and sha256(profile_raw) == metadata['profile_sha256']
            and value['access_runtime_manifest_sha256'] == metadata['access_runtime_manifest_sha256'],
        'profile_private_mode': owned(root.path(PROFILE_DIRECTORY), 0o700, _owner_uid, _owner_gid, directory=True)
            and {path.name for path in root.path(PROFILE_DIRECTORY).iterdir()} == {'profile.json'},
        'enrollment_and_cache_empty_private': all(owned(root.path(path), 0o700, _owner_uid, _owner_gid, directory=True)
            and not any(root.path(path).iterdir()) for path in (STATE_DIRECTORY, CACHE_DIRECTORY)),
        'access_service_enabled_only': only_access_hooks(root, configured=True) and root.path(ENABLE_PATH).is_symlink()
            and os.readlink(root.path(ENABLE_PATH)) == UNIT_TARGET,
        'static_manifest_exact_and_bound': manifest == expected and manifest_raw == policy.canonical(expected)
            and sha256(manifest_raw) == metadata['access_runtime_manifest_sha256']
            and owned(root.path(MANIFEST_PATH), 0o644, _owner_uid, _owner_gid),
        'payload_hashes_match': all(prepared.digest(root, path) == metadata['source_file_sha256'][name]
            for name, (path, _mode) in PAYLOADS.items()),
        'payload_modes_match': all(owned(root.path(path), mode, _owner_uid, _owner_gid) for path, mode in PAYLOADS.values())
            and owned(root.path('usr/local/lib/inkyos'), 0o700, _owner_uid, _owner_gid, directory=True)
            and owned(root.path(SSH_PUBLIC_DIRECTORY), 0o755, _owner_uid, _owner_gid, directory=True),
        'application_helper_vendor_ssh_masked': prepared.masked(root, ('inky-studio.service', 'inky-network.service',
            'ssh.service', 'ssh.socket', 'sshswitch.service')),
        'updates_masked': prepared.masked(root, MASKS), 'wifi_disabled_no_profiles': wifi_off(root),
        'no_precreated_identity_capsule_or_report': no_identity(root, boot),
        'not_booted': root.read('etc/machine-id') == 'uninitialized\n',
        'parent_files_preserved': all(prepared.digest(root, path) == expected_hash
            for path, expected_hash in metadata['preserved_parent_file_sha256'].items()),
        'bootfs_unchanged': boot_snapshot(boot) == metadata['bootfs_snapshot_sha256'],
        'protected_boot_grow_files_preserved': prepared.protected_hashes(root, boot) == metadata['protected_boot_grow_sha256'],
        'operator_account_exact_append_locked_unaged': accounts_match(root, metadata['account_parent_metadata'], metadata['account_file_sha256']),
        'operator_public_key_restricted_readable': read_bytes(root, AUTHORIZED_KEYS)
            == ('restrict ' + value['operator_public_key'] + '\n').encode('ascii')
            and owned(root.path(AUTHORIZED_KEYS), 0o644, _owner_uid, _owner_gid)
            and owned(root.path(SSH_DIRECTORY), 0o755, _owner_uid, _owner_gid, directory=True)
            and {path.name for path in root.path(SSH_DIRECTORY).iterdir()} == {'authorized_keys', 'sshd_config'},
    }
    require(set(checks) == CHECKS and all(flag is True for flag in checks.values()), 'Private access static verification failed')
    return {'schema_version': 1, 'kind': 'test-lan-access', 'scope': 'offline-test-access-configuration',
            'passed': True, 'private_artifact': True, 'bootstrap_action': 'enrollment-then-signed-access',
            'application_started': False, 'no_active_application': True, 'ssh_started': False, 'network_connected': False,
            'ready_for_activation': False, 'hardware_qualified': False, 'release_qualified': False,
            'removed_rootfs_paths': [], 'removed_bootfs_paths': [], 'checks': checks, **metadata}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('rootfs', 'bootfs', 'recipe', 'profile', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--parent-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        require(sys.platform == 'linux' and os.geteuid() == 0
                and Path('/var/lib/inkyos-build/owner').read_text().strip() == 'inkyos-builder-v1', 'Isolated root Linux builder required')
        require(all(path.is_absolute() and path != Path('/') for path in (args.rootfs, args.bootfs, args.recipe, args.profile, args.output)),
                'Absolute private build paths required')
        prepared.safe_tree(args.output.parent)
        require(not args.output.exists() and not args.output.is_symlink()
                and all(path != args.output and path not in args.output.parents for path in (args.rootfs, args.bootfs, args.recipe)),
                'Independent new report required')
        metadata = configure(args.rootfs, args.bootfs, args.recipe, args.profile, args.parent_sha256)
        report = verification(args.rootfs, args.bootfs, metadata)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(policy.canonical(report))
        print('Private TEST access child configured offline; runtime access remains unverified.')
        return 0
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        print('Private TEST access configuration refused.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
