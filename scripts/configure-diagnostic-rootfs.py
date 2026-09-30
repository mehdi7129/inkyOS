#!/usr/bin/env python3
"""Opt in a pristine COPY of an application prototype to one boot diagnostic.

Called only by an isolated Linux image builder. This static step starts no
services and creates no report, identity, credential, or network account.
The copied variant powers off after a successful, bounded runtime export.
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
spec = importlib.util.spec_from_file_location('_inkyos_diagnostic_configuration',
                                             SCRIPT_DIR / 'configure-rootfs.py')
configuration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(configuration)

SERVICE = 'inkyos-sd-diagnostic.service'
TIMER = 'inkyos-sd-diagnostic.timer'
MASKED_UNITS = (
    'rpi-eeprom-update.service', 'apt-daily.timer', 'apt-daily.service',
    'apt-daily-upgrade.timer', 'apt-daily-upgrade.service',
)
SOURCE_FILES = (
    'diagnostic/sd-diagnostic.py', 'diagnostic/' + SERVICE, 'diagnostic/' + TIMER,
    'scripts/configure-diagnostic-rootfs.py', 'scripts/configure-rootfs.py',
)
COPY_FILES = {
    'diagnostic/sd-diagnostic.py': ('usr/local/lib/inkyos/sd-diagnostic.py', 0o555),
    'diagnostic/' + SERVICE: ('etc/systemd/system/' + SERVICE, 0o644),
    'diagnostic/' + TIMER: ('etc/systemd/system/' + TIMER, 0o644),
}
REPORT_TEMPLATE = '/boot/firmware/inkyos-diagnostics/boot-<SHA256boot_id>.json'
BOOT_CONFIG_APPEND = '\n\n[all]\nbootloader_update=0\ndtoverlay=disable-wifi\n'
EXPECTED_INKYOS_CONFIG = ('# InkyOS system prototype: hardware still to qualify\n'
                          '[all]\ndtparam=i2c_arm=on\ndtparam=spi=on\ndtoverlay=spi0-0cs\n')
# Package-owned integration scripts in the exact reviewed parent image. They
# contain no network profile; an altered or additional file is refused.
WPA_VENDOR_SCRIPTS = {
    'action_wpa.sh': 'fdfb11ca5fb9231397d25275c5c2d1c3a9b0e091bd103d33946ecf4672b3e85b',
    'functions.sh': 'a9a4e0cfa3827e3cca535c559e3f09c114a063794de3c1c9cc4c201322730014',
    'ifupdown.sh': '9d493c00b36cf074070ac84890390dea850b99108856c25a7e945b46c19664b7',
}
MARKER = (
    'INKYOS EXPERIMENTAL SD DIAGNOSTIC - NOT A RELEASE\n'
    'Application and network helper services remain masked. No SSH account.\n'
    'Wi-Fi is disabled only for this diagnostic variant; Bluetooth stays enabled.\n'
    'After the first-boot resize, a bounded diagnostic runs after 45 seconds.\n'
    'After successful report export the Raspberry Pi powers off automatically.\n'
    'Do not remove power before the Pi has shut down. No automatic reboot.\n'
    'Report: ' + REPORT_TEMPLATE + '\n'
    'This image is not qualified for hardware or personal content.\n'
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_tree(path):
    """Tree checks child parents; additionally reject links above the root."""
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


def pristine(tree, boot):
    require(tree.read('etc/machine-id') == 'uninitialized\n', 'Diagnostic requires a never-booted image copy')
    release = json.loads(tree.read('etc/inkyos-release.json'))
    require(release.get('kind') == 'application-prototype', 'Diagnostic requires the application prototype')
    application = release.get('application')
    require(isinstance(application, dict)
            and application.get('startup') == 'masked-pending-firstboot-contract'
            and application.get('release_qualified') is False,
            'Application must be explicitly inactive and unqualified')
    for unit in ('inky-studio.service', 'inky-network.service', 'ssh.service', 'ssh.socket', 'sshswitch.service'):
        path = tree.path('etc/systemd/system/' + unit)
        require(path.is_symlink() and os.readlink(path) == '/dev/null', 'Application or SSH unit not masked')
    shadow = tree.read('etc/shadow')
    records = [line.split(':') for line in shadow.splitlines()]
    require(all(len(row) == 9 and row[1].startswith(('!', '*')) for row in records),
            'All image account passwords must remain locked')
    require({'root', 'inky', 'inky-network'} <= {row[0] for row in records}, 'Expected locked accounts missing')
    for relative in ('var/lib/inky-studio', 'var/lib/inky-studio/photos'):
        path = tree.path(relative)
        require(stat.S_ISDIR(path.lstat().st_mode), 'App data directory must be real')
        expected = {'photos'} if relative == 'var/lib/inky-studio' else set()
        require({entry.name for entry in path.iterdir()} == expected, 'App runtime data or content already present')
    for relative in ('var/lib/inkyos/system.json', 'var/lib/systemd/random-seed',
                     'var/lib/inky-network', 'etc/inkyos-diagnostic.json'):
        require(absent(tree, relative), 'Runtime state or previous diagnostic present')
    ssh = tree.path('etc/ssh')
    require(not any(entry.name.startswith('ssh_host_') for entry in ssh.iterdir()), 'SSH identity already present')
    for relative in ('etc/NetworkManager/system-connections', 'run/NetworkManager/system-connections'):
        if not absent(tree, relative):
            directory = tree.path(relative)
            require(stat.S_ISDIR(directory.lstat().st_mode), 'Network configuration parent must be real')
            require(not any(directory.iterdir()), 'Network connection configuration already present')
    if not absent(tree, 'etc/wpa_supplicant'):
        directory = tree.path('etc/wpa_supplicant')
        require(stat.S_ISDIR(directory.lstat().st_mode), 'Wireless configuration parent must be real')
        for entry in directory.iterdir():
            require(entry.name in WPA_VENDOR_SCRIPTS, 'Wireless configuration already present')
            content = tree.read('etc/wpa_supplicant/' + entry.name)
            require(hashlib.sha256(content.encode()).hexdigest() == WPA_VENDOR_SCRIPTS[entry.name],
                    'Reviewed vendor wireless script hash mismatch')
    for name in ('user-data', 'network-config', 'meta-data', 'ssh', 'ssh.txt', 'userconf', 'userconf.txt',
                 'inkyos-diagnostics', 'INKYOS-DIAGNOSTIC.txt'):
        require(absent(boot, name), 'Boot provisioning or previous diagnostic present')
    require('resize' in boot.read('cmdline.txt').split(), 'Pinned first-boot resize hook missing')
    for entry in boot.root.iterdir():
        name = entry.name.casefold()
        require(not (name.startswith('recovery.') or name.startswith('pieeprom') or name.startswith('vl805')),
                'Pending bootloader update artifact refused')
    config = boot.read('config.txt')
    require(boot.read('inkyos.txt') == EXPECTED_INKYOS_CONFIG,
            'Unexpected parent hardware overlay; diagnostic policy not reviewed')
    require(sum(line.split('#', 1)[0].strip() == 'include inkyos.txt'
                for line in config.splitlines()) == 1, 'Expected InkyOS parent overlay include missing')
    for line in config.splitlines():
        active = line.split('#', 1)[0].strip()
        match = re.match(r'^bootloader_update\s*=\s*(.*?)\s*$', active, re.IGNORECASE)
        require(not match or match.group(1) == '0', 'Conflicting bootloader_update configuration refused')
    return config


def prepare_parent(tree, relative):
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
    return tree.path(relative)


def write_owned(tree, relative, content, mode):
    path = prepare_parent(tree, relative)
    tree.write(relative, content, mode)
    if os.geteuid() == 0:
        os.chown(path, 0, 0, follow_symlinks=False)


def configure(root, boot, source, parent_sha256):
    require(isinstance(parent_sha256, str) and re.fullmatch(r'[0-9a-f]{64}', parent_sha256),
            'Exact parent image SHA-256 required')
    root, boot, source = (safe_tree(path) for path in (root, boot, source))
    trees = (root.root, boot.root, source.root)
    require(all(a != b and a not in b.parents and b not in a.parents
                for index, a in enumerate(trees) for b in trees[index + 1:]),
            'Root, boot and source trees must be independent')
    config = pristine(root, boot)
    payloads = {}
    for relative in SOURCE_FILES:
        payloads[relative] = source.read(relative)
        require(isinstance(payloads[relative], str) and payloads[relative], 'Diagnostic source missing or empty')
    for name in ('configure-diagnostic-rootfs.py', 'configure-rootfs.py'):
        require(payloads['scripts/' + name] == (SCRIPT_DIR / name).read_text(),
                'Provided configuration source differs from executing recipe')
    inputs_raw = source.read('recipe-inputs.json')
    inputs = json.loads(inputs_raw)
    source_hashes = {name: hashlib.sha256(raw.encode()).hexdigest() for name, raw in payloads.items()}
    require(inputs.get('schema_version') == 1
            and isinstance(inputs.get('source_commit'), str)
            and re.fullmatch(r'[0-9a-f]{40}', inputs['source_commit'])
            and isinstance(inputs.get('worktree_dirty'), bool)
            and isinstance(inputs.get('files'), dict)
            and all(inputs['files'].get(name) == digest for name, digest in source_hashes.items()),
            'Recipe provenance or diagnostic input hashes missing or mismatched')
    for relative, _mode in COPY_FILES.values():
        require(absent(root, relative), 'Diagnostic payload already present')
    link = 'etc/systemd/system/timers.target.wants/' + TIMER
    require(absent(root, link), 'Diagnostic timer already enabled')
    for unit in MASKED_UNITS:
        target = root.path('etc/systemd/system/' + unit)
        require(not (target.exists() or target.is_symlink())
                or target.is_symlink() and os.readlink(target) == '/dev/null',
                'Unexpected firmware or package update override')
    metadata = {
        'schema_version': 1,
        'kind': 'sd-boot-diagnostic',
        'status': 'not-qualified',
        'release_qualified': False,
        'parent_image_sha256': parent_sha256,
        'source_file_sha256': source_hashes,
        'recipe_source_commit': inputs['source_commit'],
        'recipe_worktree_dirty': inputs['worktree_dirty'],
        'recipe_inputs_sha256': hashlib.sha256(inputs_raw.encode()).hexdigest(),
        'application_runtime': 'masked',
        'report_template': REPORT_TEMPLATE,
        'auto_poweroff': True,
        'automatic_reboot': False,
        'firmware_updates': 'disabled',
        'wifi_runtime': 'kernel-disabled-diagnostic-only',
        'bluetooth_runtime': 'system-only',
        'boot_config_delta': {
            'parent_sha256': hashlib.sha256(config.encode()).hexdigest(),
            'configured_sha256': hashlib.sha256((config.rstrip() + BOOT_CONFIG_APPEND).encode()).hexdigest(),
            'append': BOOT_CONFIG_APPEND,
        },
    }
    for source_name, (relative, mode) in COPY_FILES.items():
        write_owned(root, relative, payloads[source_name], mode)
    write_owned(root, 'etc/inkyos-diagnostic.json', json.dumps(metadata, indent=2, sort_keys=True) + '\n', 0o644)
    for unit in MASKED_UNITS:
        root.link('etc/systemd/system/' + unit, '/dev/null')
    prepare_parent(root, link)
    root.link(link, '/etc/systemd/system/' + TIMER)
    boot.write('config.txt', config.rstrip() + BOOT_CONFIG_APPEND)
    boot.write('INKYOS-DIAGNOSTIC.txt', MARKER)
    return metadata


def verification(root, boot, metadata):
    root, boot = (safe_tree(path) for path in (root, boot))
    sources = metadata['source_file_sha256']
    masks = lambda units: all((root.path('etc/systemd/system/' + unit).is_symlink()
                              and os.readlink(root.path('etc/systemd/system/' + unit)) == '/dev/null')
                             for unit in units)
    timer = root.path('etc/systemd/system/timers.target.wants/' + TIMER)
    checks = {
        'application_runtime_masked': masks(('inky-studio.service', 'inky-network.service')),
        'ssh_masked': masks(('ssh.service', 'ssh.socket', 'sshswitch.service')),
        'firmware_and_package_updates_masked': masks(MASKED_UNITS),
        'pending_bootloader_artifacts_absent': not any(entry.name.casefold().startswith(('recovery.', 'pieeprom', 'vl805'))
                                                      for entry in boot.root.iterdir()),
        'bootloader_update_disabled_directly': boot.read('config.txt').endswith(BOOT_CONFIG_APPEND),
        'wifi_disabled_diagnostic_only': boot.read('config.txt').endswith(BOOT_CONFIG_APPEND),
        'boot_config_delta_matches': hashlib.sha256(boot.read('config.txt').encode()).hexdigest()
                                    == metadata['boot_config_delta']['configured_sha256'],
        'timer_enabled': timer.is_symlink() and os.readlink(timer) == '/etc/systemd/system/' + TIMER,
        'payload_hashes_match': all(hashlib.sha256(root.read(relative).encode()).hexdigest() == sources[name]
                                    for name, (relative, _mode) in COPY_FILES.items()),
        'payload_modes_match': all(root.path(relative).stat().st_mode & 0o777 == mode
                                  for relative, mode in COPY_FILES.values()),
        'auto_poweroff_after_success': 'ExecStartPost=/usr/bin/systemctl --no-block poweroff\n'
                                       in root.read('etc/systemd/system/' + SERVICE),
        'metadata_matches': json.loads(root.read('etc/inkyos-diagnostic.json')) == metadata,
        'not_booted': root.read('etc/machine-id') == 'uninitialized\n',
        'resize_hook_preserved': 'resize' in boot.read('cmdline.txt').split(),
        'no_precreated_report': absent(boot, 'inkyos-diagnostics'),
        'diagnostic_marker_matches': boot.read('INKYOS-DIAGNOSTIC.txt') == MARKER,
    }
    require(all(checks.values()), 'Diagnostic overlay verification failed')
    return {'schema_version': 1, 'kind': 'sd-diagnostic-overlay-verification',
            'scope': 'offline-sd-diagnostic-configuration', 'passed': True,
            'application_started': False, 'hardware_qualified': False,
            'parent_image_sha256': metadata['parent_image_sha256'],
            'source_file_sha256': sources, 'boot_config_delta': metadata['boot_config_delta'],
            'recipe_source_commit': metadata['recipe_source_commit'],
            'recipe_worktree_dirty': metadata['recipe_worktree_dirty'],
            'recipe_inputs_sha256': metadata['recipe_inputs_sha256'],
            'release_qualified': False, 'checks': checks}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--bootfs', type=Path, required=True)
    parser.add_argument('--recipe', '--source', dest='source', type=Path, required=True)
    parser.add_argument('--parent-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('Run as root only through the isolated Linux diagnostic image builder')
    if any(not path.is_absolute() or path == Path('/') for path in (args.rootfs, args.bootfs, args.source, args.output)):
        parser.error('Independent absolute build directories required; host root refused')
    try:
        output_parent = safe_tree(args.output.parent)
        require(absent(output_parent, args.output.name), 'Diagnostic verification report already exists')
        require(all(path != args.output and path not in args.output.parents
                    for path in (args.rootfs, args.bootfs, args.source)),
                'Verification output must stay outside image and recipe trees')
        metadata = configure(args.rootfs, args.bootfs, args.source, args.parent_sha256)
        report = verification(args.rootfs, args.bootfs, metadata)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, 'w') as stream:
            stream.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print('Experimental diagnostic variant prepared; no target service started.')
        return 0
    except (OSError, ValueError, TypeError, KeyError):
        print('Diagnostic image configuration refused; no target service started.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
