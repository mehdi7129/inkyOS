#!/usr/bin/env python3
"""Prepare a distinct inactive TEST LAN copy of the pinned app prototype.

This static step enables no service, radio, network access or app authority.
The manual read-only preflight never substitutes for reviewed activation.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys


SCRIPT_DIR = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('_inkyos_test_lan_configuration', SCRIPT_DIR / 'configure-rootfs.py')
configuration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(configuration)

SOURCE_COMMIT = '758a2bf7ed099aad41ef35316e53228e797b0b2b'
MANIFEST_SHA256 = '0d587792433d924ad1c4e71af19c2a46279f573791cb690571fa1019e7703551'
REVIEWED_APPLICATIONS = {
    '6a697d134290ced0214fc74b903f4b3c336d70fa': '2424fb9c32234ad7d359799f6b137e98298734023f0039afd1a57fbf265c250f',
    SOURCE_COMMIT: MANIFEST_SHA256,
}
MASKS = ('rpi-eeprom-update.service', 'apt-daily.timer', 'apt-daily.service',
         'apt-daily-upgrade.timer', 'apt-daily-upgrade.service',
         'inky-studio.service', 'inky-network.service', 'ssh.service', 'ssh.socket', 'sshswitch.service')
SOURCES = frozenset(('scripts/test-lan-preflight.py', 'scripts/configure-test-lan-rootfs.py',
                    'scripts/configure-rootfs.py', 'application-manifest.json'))
MARKER_PATH = METADATA_PATH = 'etc/inkyos-test-lan.json'
PENDING_BOOT_ARTIFACTS = ('recovery.', 'pieeprom', 'vl805')
PAYLOADS = {
    'scripts/test-lan-preflight.py': ('usr/local/lib/inkyos/test-lan-preflight.py', 0o555),
    'application-manifest.json': ('usr/local/share/inkyos/inky-studio-manifest-v1.json', 0o444),
}
BOOT_CONFIG_APPEND = '\n\n[all]\nbootloader_update=0\n'
BOOT_APPEND = BOOT_CONFIG_APPEND
EXPECTED_INKYOS_CONFIG = ('# InkyOS system prototype: hardware still to qualify\n'
                          '[all]\ndtparam=i2c_arm=on\ndtparam=spi=on\ndtoverlay=spi0-0cs\n')
PROTECTED_FILES = (
    'boot/cmdline.txt', 'boot/initramfs8', 'boot/initramfs_2712', 'boot/kernel8.img', 'boot/kernel_2712.img',
    'root/etc/fstab', 'root/usr/lib/systemd/system/rpi-resize.service',
    'root/usr/lib/systemd/system/systemd-growfs-root.service',
    'root/usr/share/initramfs-tools/scripts/local-premount/resize_early',
    'root/usr/share/initramfs-tools/scripts/local-bottom/set_partuuid',
)
# Static declarative configuration derived from the exact application pin.
# The existing parent image verifier checks the complete source/venv payload.
STATIC_PARENT_FILES = {
    'usr/lib/systemd/system/inky-studio.service': ('9c3bf0c44fa120ed824b15e65310f26e22ad53ef20a118eddd6f4c8ea1e59a24', 0o644),
    'usr/lib/systemd/system/inky-network.service': ('6fae02fbef586060085882325e43346d18889f5a73a3dfae407d2df95cf547bb', 0o644),
    'etc/systemd/system/inky-studio.service.d/bluetooth.conf': ('50621d3ee8c2fa6b9afb58d174c32dcdbc73d939ead0bd6ad1d84f36f34c263d', 0o644),
    'etc/systemd/system/inky-studio.service.d/10-inkyos-firstboot.conf': ('abe954d0381202ad9f4388256575fa1a63f75814cf7b4c28a50708c624dbddfc', 0o644),
    'etc/systemd/system/inky-network.service.d/10-inkyos-firstboot.conf': ('abe954d0381202ad9f4388256575fa1a63f75814cf7b4c28a50708c624dbddfc', 0o644),
    'usr/local/lib/inky-studio/network-helper.py': ('6e5c00862bff1d02c575b422f2d1e1112cd20f2c9e9141894557a698e2d5f431', 0o555),
    'etc/polkit-1/rules.d/49-inky-network.rules': ('894de12a283581ddbc0f50e5d86edf207ad936f9c456fb43f002ae67001643d3', 0o644),
    'etc/sudoers.d/inky-studio': ('79ea3a78f22dad52f851a982dfa96e370743598dd3b5fe3199473a0a5bbd001a', 0o440),
    'usr/local/bin/inky-studio': ('1abbb94b61281473bad2ea194d58b614aa8dd98128957791379d1ddb89835492', 0o755),
}
CHECKS = frozenset((
    'metadata_matches', 'prepared_inactive_nonfactory', 'application_runtime_masked', 'ssh_masked',
    'updates_masked', 'pending_bootloader_artifacts_absent', 'bootloader_update_disabled_directly',
    'no_diagnostic_or_test_runtime_hooks', 'wifi_remains_disabled_in_networkmanager',
    'no_disable_wifi_overlay', 'not_booted', 'no_generated_app_data', 'payload_hashes_match',
    'payload_modes_match', 'parent_static_files_unchanged', 'protected_boot_grow_files_unchanged',
    'boot_config_delta_matches',
))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def reviewed_application(app):
    if not isinstance(app, dict) or not isinstance(app.get('source_commit'), str):
        return False
    digest = REVIEWED_APPLICATIONS.get(app['source_commit'])
    return digest is not None and app == {
        'source_commit': app['source_commit'], 'manifest_sha256': digest,
        'application_version': '0.5.0-rc.2', 'startup': 'masked-pending-firstboot-contract',
        'release_qualified': False,
    } and app.get('release_qualified') is False


def safe_tree(path):
    path = Path(path).absolute()
    for ancestor in reversed((path, *path.parents)):
        require(stat.S_ISDIR(ancestor.lstat().st_mode), 'Symlink or special tree ancestor refused')
    return configuration.Tree(path)


def absent(tree, relative):
    try:
        path = tree.path(relative)
    except FileNotFoundError:
        return True
    return not (path.exists() or path.is_symlink())


def read_bytes(tree, relative):
    path = tree.path(relative)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'Regular unlinked input file required')
    return path.read_bytes()


def digest(tree, relative):
    return hashlib.sha256(read_bytes(tree, relative)).hexdigest()


def masked(tree, units):
    return all(tree.path('etc/systemd/system/' + unit).is_symlink()
               and os.readlink(tree.path('etc/systemd/system/' + unit)) == '/dev/null' for unit in units)


def update_artifacts_absent(boot):
    return not any(entry.name.casefold().startswith(PENDING_BOOT_ARTIFACTS) for entry in boot.root.iterdir())


def no_runtime_hooks(root, boot):
    return all(absent(root, path) for path in (
        'etc/inkyos-diagnostic.json', 'usr/local/lib/inkyos/sd-diagnostic.py',
        'etc/systemd/system/inkyos-sd-diagnostic.service', 'etc/systemd/system/inkyos-sd-diagnostic.timer',
        'etc/systemd/system/timers.target.wants/inkyos-sd-diagnostic.timer',
        'etc/systemd/system/inkyos-test-lan.service', 'etc/systemd/system/inkyos-test-lan.timer',
    )) and all(absent(boot, path) for path in ('INKYOS-DIAGNOSTIC.txt', 'inkyos-diagnostics'))


def app_data_empty(root, *, app_uid=1000, app_gid=1000):
    for relative, names in (('var/lib/inky-studio', {'photos'}), ('var/lib/inky-studio/photos', set())):
        directory = root.path(relative)
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != app_uid or info.st_gid != app_gid
                or stat.S_IMODE(info.st_mode) != 0o755 or {entry.name for entry in directory.iterdir()} != names):
            return False
    return True


def protected_hashes(root, boot):
    return {name: digest(root if name.startswith('root/') else boot, name.split('/', 1)[1]) for name in PROTECTED_FILES}


def static_parent(root, *, owner_uid=0, owner_gid=0):
    for name, (expected, mode) in STATIC_PARENT_FILES.items():
        info = root.path(name).lstat()
        require(digest(root, name) == expected and stat.S_IMODE(info.st_mode) == mode
                and info.st_uid == owner_uid and info.st_gid == owner_gid, 'Pinned application configuration differs')
    for relative, expected in (('etc/systemd/system/inky-studio.service.d', {'bluetooth.conf', '10-inkyos-firstboot.conf'}),
                               ('etc/systemd/system/inky-network.service.d', {'10-inkyos-firstboot.conf'})):
        directory = root.path(relative)
        require(stat.S_ISDIR(directory.lstat().st_mode) and {item.name for item in directory.iterdir()} == expected,
                'Unreviewed app or helper override present')


def pristine(root, boot, *, owner_uid=0, owner_gid=0, app_uid=1000, app_gid=1000):
    require(root.read('etc/machine-id') == 'uninitialized\n', 'A never-booted original application prototype is required')
    release = json.loads(root.read('etc/inkyos-release.json'))
    require(isinstance(release, dict) and isinstance(release.get('application'), dict), 'Parent application metadata missing')
    app = release['application']
    require(release.get('kind') == 'application-prototype' and release.get('status') == 'not-hardware-qualified'
            and reviewed_application(app),
            'Exact inactive parent application pin required')
    require(root.read('home/inky/inky-studio/server/SOURCE_COMMIT') == app['source_commit'] + '\n', 'Parent source commit differs')
    source_info = root.path('home/inky/inky-studio/server/SOURCE_COMMIT').lstat()
    require(source_info.st_uid == app_uid and source_info.st_gid == app_gid
            and stat.S_IMODE(source_info.st_mode) == 0o644, 'Parent app source pin ownership or mode differs')
    static_parent(root, owner_uid=owner_uid, owner_gid=owner_gid)
    require(masked(root, ('inky-studio.service', 'inky-network.service', 'ssh.service', 'ssh.socket', 'sshswitch.service')),
            'App, helper and SSH must remain masked')
    require(app_data_empty(root, app_uid=app_uid, app_gid=app_gid), 'Private app data must be empty and app-owned')
    require(root.read('var/lib/NetworkManager/NetworkManager.state') == '[main]\nWirelessEnabled=false\n',
            'Pristine disabled NetworkManager radio required')
    require(no_runtime_hooks(root, boot), 'Diagnostic or TEST runtime hook already present')
    for entry in root.path('etc').iterdir():
        if entry.name.casefold().startswith('inkyos-') and entry.name.casefold().endswith('.json'):
            require(entry.name == 'inkyos-release.json', 'Previous or unknown InkyOS variant marker refused')
    for relative in ('var/lib/inkyos/system.json', 'var/lib/inky-network', 'var/lib/systemd/random-seed',
                     'etc/default/crda', 'etc/wpa_supplicant/wpa_supplicant.conf'):
        require(absent(root, relative), 'Runtime identity, authority or country already present')
    for relative in ('etc/NetworkManager/system-connections', 'run/NetworkManager/system-connections'):
        if not absent(root, relative):
            directory = root.path(relative)
            require(stat.S_ISDIR(directory.lstat().st_mode) and not any(directory.iterdir()), 'Network profile already present')
    shadow = [line.split(':') for line in root.read('etc/shadow').splitlines()]
    require(shadow and all(len(row) == 9 and row[1].startswith(('!', '*')) for row in shadow)
            and {'root', 'inky', 'inky-network'} <= {row[0] for row in shadow}, 'Locked image accounts required')
    require(not any(entry.name.startswith('ssh_host_') for entry in root.path('etc/ssh').iterdir()), 'SSH identity already present')
    for name in ('user-data', 'network-config', 'meta-data', 'ssh', 'ssh.txt', 'userconf', 'userconf.txt'):
        require(absent(boot, name), 'Boot credential provisioning refused')
    require(not any(entry.name.casefold().startswith('inkyos-') for entry in boot.root.iterdir()),
            'Previous or unknown boot variant marker refused')
    require(update_artifacts_absent(boot), 'Pending bootloader update artifact refused')
    config = boot.read('config.txt')
    require(boot.read('inkyos.txt') == EXPECTED_INKYOS_CONFIG, 'Unknown parent hardware overlay')
    require('resize' in boot.read('cmdline.txt').split(), 'Pinned first-boot resize hook missing')
    for line in config.splitlines():
        active = line.split('#', 1)[0].strip()
        match = re.match(r'^bootloader_update\s*=\s*(.*?)\s*$', active, re.IGNORECASE)
        require(not match or match.group(1) == '0', 'Conflicting bootloader update configuration')
        require(not re.search(r'(?i)\bdisable-(?:wifi|bt)\b', active), 'Diagnostic radio overlay or disabled Bluetooth refused')
    require(sum(line.split('#', 1)[0].strip() == 'include inkyos.txt' for line in config.splitlines()) == 1,
            'Original parent overlay include required')
    return config, app


def write_owned(tree, relative, content, mode):
    parts = Path(relative).parts
    for length in range(1, len(parts)):
        directory = tree.path('/'.join(parts[:length]))
        try:
            require(stat.S_ISDIR(directory.lstat().st_mode), 'Unsafe configuration parent')
        except FileNotFoundError:
            directory.mkdir(mode=0o755)
            directory.chmod(0o755)
            if os.geteuid() == 0:
                os.chown(directory, 0, 0, follow_symlinks=False)
    tree.write(relative, content, mode)
    if os.geteuid() == 0:
        os.chown(tree.path(relative), 0, 0, follow_symlinks=False)


def expected_metadata(parent_sha256, source_hashes, inputs, inputs_sha256, config, preserved, *, application):
    require(reviewed_application(application), 'Exact reviewed application pair required for metadata')
    return {
        'schema_version': 1, 'kind': 'test-lan-prepared', 'state': 'prepared-inactive', 'status': 'prepared-inactive',
        'source_commit': application['source_commit'], 'manifest_sha256': application['manifest_sha256'],
        'application_manifest_path': '/usr/local/share/inkyos/inky-studio-manifest-v1.json',
        'parent_image_sha256': parent_sha256, 'source_file_sha256': source_hashes,
        'recipe_source_commit': inputs['source_commit'], 'recipe_worktree_dirty': inputs['worktree_dirty'],
        'recipe_inputs_sha256': inputs_sha256, 'application_runtime': 'masked',
        'ready_for_activation': False, 'activation_authorized': False, 'factory_authority': False,
        'hardware_qualified': False, 'release_qualified': False, 'auto_poweroff': False,
        'first_boot_without_lan': False, 'wifi_runtime': 'disabled-pending-local-country-and-lan',
        'privileges_added': False, 'firmware_updates': 'disabled',
        'protected_boot_grow_sha256': preserved,
        'boot_config_delta': {'parent_sha256': hashlib.sha256(config.encode()).hexdigest(),
            'configured_sha256': hashlib.sha256((config.rstrip() + BOOT_CONFIG_APPEND).encode()).hexdigest(),
            'append': BOOT_CONFIG_APPEND},
    }


def configure(root, boot, source, parent_sha256, *, _owner_uid=0, _owner_gid=0, _app_uid=1000, _app_gid=1000):
    require(isinstance(parent_sha256, str) and re.fullmatch(r'[0-9a-f]{64}', parent_sha256), 'Exact parent image SHA-256 required')
    root, boot, source = (safe_tree(path) for path in (root, boot, source))
    trees = (root.root, boot.root, source.root)
    require(all(a != b and a not in b.parents and b not in a.parents for index, a in enumerate(trees) for b in trees[index + 1:]),
            'Image and source trees must be independent')
    config, app = pristine(root, boot, owner_uid=_owner_uid, owner_gid=_owner_gid, app_uid=_app_uid, app_gid=_app_gid)
    preserved = protected_hashes(root, boot)
    payloads = {name: source.read(name) for name in SOURCES}
    require(all(isinstance(raw, str) and raw for raw in payloads.values()), 'Missing or empty recipe input')
    for name in ('configure-test-lan-rootfs.py', 'configure-rootfs.py'):
        require(payloads['scripts/' + name] == (SCRIPT_DIR / name).read_text(), 'Executing configuration differs from recipe')
    hashes = {name: hashlib.sha256(raw.encode()).hexdigest() for name, raw in payloads.items()}
    require(hashes['application-manifest.json'] == app['manifest_sha256'], 'Exact pinned application manifest bytes required')
    inputs_raw = source.read('recipe-inputs.json')
    inputs = json.loads(inputs_raw)
    require(inputs.get('schema_version') == 1 and isinstance(inputs.get('source_commit'), str)
            and re.fullmatch(r'[0-9a-f]{40}', inputs['source_commit']) and isinstance(inputs.get('worktree_dirty'), bool)
            and isinstance(inputs.get('files'), dict) and all(inputs['files'].get(name) == digest for name, digest in hashes.items()),
            'Recipe provenance or source hashes missing or mismatched')
    for relative, _mode in PAYLOADS.values():
        require(absent(root, relative), 'Existing TEST LAN payload refused')
    for unit in MASKS:
        target = root.path('etc/systemd/system/' + unit)
        require(not (target.exists() or target.is_symlink()) or target.is_symlink() and os.readlink(target) == '/dev/null',
                'Unreviewed package or firmware update override')
    metadata = expected_metadata(parent_sha256, hashes, inputs, hashlib.sha256(inputs_raw.encode()).hexdigest(),
                                 config, preserved, application=app)
    for name, (relative, mode) in PAYLOADS.items():
        write_owned(root, relative, payloads[name], mode)
    write_owned(root, MARKER_PATH, json.dumps(metadata, indent=2, sort_keys=True) + '\n', 0o644)
    for unit in MASKS:
        root.link('etc/systemd/system/' + unit, '/dev/null')
    boot.write('config.txt', config.rstrip() + BOOT_CONFIG_APPEND)
    require(protected_hashes(root, boot) == preserved, 'Protected boot/grow bytes changed')
    return metadata


def verification(root, boot, metadata, *, _owner_uid=0, _owner_gid=0, _app_uid=1000, _app_gid=1000):
    root, boot = (safe_tree(path) for path in (root, boot))
    def owned_mode(path, mode):
        info = root.path(path).lstat()
        return (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == mode
                and info.st_uid == _owner_uid and info.st_gid == _owner_gid)
    checks = {
        'metadata_matches': json.loads(root.read(MARKER_PATH)) == metadata and owned_mode(MARKER_PATH, 0o644),
        'prepared_inactive_nonfactory': metadata['state'] == 'prepared-inactive'
            and all(metadata[name] is False for name in ('ready_for_activation', 'activation_authorized', 'factory_authority',
                                                       'hardware_qualified', 'release_qualified', 'auto_poweroff', 'privileges_added')),
        'application_runtime_masked': masked(root, ('inky-studio.service', 'inky-network.service')),
        'ssh_masked': masked(root, ('ssh.service', 'ssh.socket', 'sshswitch.service')),
        'updates_masked': masked(root, MASKS),
        'pending_bootloader_artifacts_absent': update_artifacts_absent(boot),
        'bootloader_update_disabled_directly': boot.read('config.txt').endswith(BOOT_CONFIG_APPEND),
        'no_diagnostic_or_test_runtime_hooks': no_runtime_hooks(root, boot),
        'wifi_remains_disabled_in_networkmanager': root.read('var/lib/NetworkManager/NetworkManager.state') == '[main]\nWirelessEnabled=false\n',
        'no_disable_wifi_overlay': not re.search(r'(?im)^\s*dtoverlay\s*=\s*disable-wifi\b', boot.read('config.txt') + boot.read('inkyos.txt')),
        'not_booted': root.read('etc/machine-id') == 'uninitialized\n',
        'no_generated_app_data': app_data_empty(root, app_uid=_app_uid, app_gid=_app_gid),
        'payload_hashes_match': all(digest(root, path) == metadata['source_file_sha256'][name] for name, (path, _mode) in PAYLOADS.items()),
        'payload_modes_match': all(owned_mode(path, mode) for path, mode in PAYLOADS.values()),
        'parent_static_files_unchanged': all(digest(root, path) == pin for path, (pin, _mode) in STATIC_PARENT_FILES.items()),
        'protected_boot_grow_files_unchanged': protected_hashes(root, boot) == metadata['protected_boot_grow_sha256'],
        'boot_config_delta_matches': digest(boot, 'config.txt') == metadata['boot_config_delta']['configured_sha256'],
    }
    require(set(checks) == CHECKS and all(checks.values()), 'TEST LAN preparation verification failed')
    return {'schema_version': 1, 'kind': 'test-lan-prepared', 'scope': 'offline-test-lan-prepared-configuration',
            'passed': True, 'application_started': False, 'hardware_qualified': False, 'ready_for_activation': False,
            'release_qualified': False, 'marker_sha256': digest(root, MARKER_PATH),
            'metadata_path': MARKER_PATH, 'removed_pending_boot_artifacts': [],
            'parent_image_sha256': metadata['parent_image_sha256'], 'source_file_sha256': metadata['source_file_sha256'],
            'recipe_source_commit': metadata['recipe_source_commit'], 'recipe_worktree_dirty': metadata['recipe_worktree_dirty'],
            'recipe_inputs_sha256': metadata['recipe_inputs_sha256'], 'boot_config_delta': metadata['boot_config_delta'],
            'protected_boot_grow_sha256': metadata['protected_boot_grow_sha256'], 'checks': checks}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--bootfs', type=Path, required=True)
    parser.add_argument('--recipe', type=Path, required=True)
    parser.add_argument('--parent-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('Run as root only through the isolated Linux TEST LAN builder')
    if any(not path.is_absolute() or path == Path('/') for path in (args.rootfs, args.bootfs, args.recipe, args.output)):
        parser.error('Independent absolute build directories required; host root refused')
    try:
        output_parent = safe_tree(args.output.parent)
        require(absent(output_parent, args.output.name), 'Preparation output already exists')
        require(all(path != args.output and path not in args.output.parents for path in (args.rootfs, args.bootfs, args.recipe)),
                'Report must stay outside image and recipe trees')
        metadata = configure(args.rootfs, args.bootfs, args.recipe, args.parent_sha256)
        report = verification(args.rootfs, args.bootfs, metadata)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, 'w') as stream:
            stream.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print('TEST LAN variant prepared and inactive; no target service started.')
        return 0
    except (OSError, ValueError, TypeError, KeyError):
        print('TEST LAN preparation refused; no target service started.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
