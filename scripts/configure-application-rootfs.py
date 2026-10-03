#!/usr/bin/env python3
"""Install reviewed static app configuration, with both runtime services masked.

Never source installers, execute application code, start services or create app
identities. Account creation and offline Python installation precede this step.
The declarative extraction is limited to explicitly reviewed source/manifest pairs.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

ROOT = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


configuration = module('_inkyos_configuration', 'configure-rootfs.py')
inspection = module('_inkyos_application_inspection', 'inspect-rootfs.py')
manifest_verifier = module('_inkyos_application_manifest', 'verify-application.py')
APP = 'home/inky/inky-studio'
DATA = 'var/lib/inky-studio'
SOURCE_COMMIT = '758a2bf7ed099aad41ef35316e53228e797b0b2b'
MANIFEST_SHA256 = '0d587792433d924ad1c4e71af19c2a46279f573791cb690571fa1019e7703551'
# Retain the original pair for old exports. Sharing a version or a source alone
# does not authorize a repackaged payload; each manifest is pinned in full.
REVIEWED_APPLICATIONS = {
    '6a697d134290ced0214fc74b903f4b3c336d70fa': '2424fb9c32234ad7d359799f6b137e98298734023f0039afd1a57fbf265c250f',
    SOURCE_COMMIT: MANIFEST_SHA256,
}
SOURCE_HASHES = {
    'install.sh': '541a98b9f3dc220b0dc89162e98affb97be200360ec7ad8e0650960d7d15944d',
    'scripts/install-bluetooth.sh': 'e0f301c97830860bcc1778579d7f4181370fb4cef8d64aeac4c226ab8aeafb69',
    'scripts/inky-studio-launcher': 'cce76b87092a9186085ed1ee422437ee208fa478ba527f863134dcaf1e9a0d4e',
    'scripts/inky-network-helper.py': '6e5c00862bff1d02c575b422f2d1e1112cd20f2c9e9141894557a698e2d5f431',
}
SERVICES = ('inky-studio.service', 'inky-network.service')
STARTUP = 'masked-pending-firstboot-contract'
FIRSTBOOT_DROPIN = '[Unit]\nRequires=inkyos-firstboot.service\nAfter=inkyos-firstboot.service\n'
BACKUPS = ('passwd-', 'shadow-', 'group-', 'gshadow-', 'subuid-', 'subgid-')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load_manifest(path, digest):
    require(manifest_verifier.sha(digest), 'Pinned manifest SHA-256 required')
    raw = manifest_verifier.read_regular(path)
    require(hashlib.sha256(raw).hexdigest() == digest, 'Manifest hash mismatch')
    data = manifest_verifier.validate_manifest(json.loads(raw, object_pairs_hook=manifest_verifier.unique_pairs))
    require(REVIEWED_APPLICATIONS.get(data['source_commit']) == digest,
            'Static integration requires an exact reviewed source/manifest pair')
    return data


def section(source, start, end):
    """Read a unique exact heredoc; no shell expansion or evaluation occurs."""
    require(source.count(start) == 1, 'Installer template start changed')
    remainder = source.split(start, 1)[1]
    require(end in remainder, 'Installer template end changed')
    return remainder.split(end, 1)[0]


def substitute(template, values):
    for key, value in values.items():
        template = template.replace('${' + key + '}', value)
    require('${' not in template, 'Unreviewed installer template substitution')
    return template


def installer_repository(source):
    """Read a literal repository default from the hash-verified installer.

    No shell evaluation or operator-specific default belongs in this recipe.
    The reviewed payload remains the authority for its own update repository.
    """
    declarations = re.findall(r'^REPO_SLUG=.*$', source, re.MULTILINE)
    require(len(declarations) == 1, 'Reviewed installer repository declaration changed')
    match = re.fullmatch(
        r'REPO_SLUG="\$\{INKY_STUDIO_REPO_SLUG:-([A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+)\}"',
        declarations[0])
    require(match is not None, 'Reviewed installer repository declaration changed')
    return match[1]


def expected_files(tree):
    sources = {}
    for name, digest in SOURCE_HASHES.items():
        path = APP + '/' + name
        info = tree.metadata(path)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'Source must be an unlinked regular file')
        content = tree.read(path, 1024 * 1024)
        require(hashlib.sha256(content.encode()).hexdigest() == digest, 'Reviewed installer source hash mismatch')
        sources[name] = content
    install, bluetooth, launcher = (sources[name] for name in
                                    ('install.sh', 'scripts/install-bluetooth.sh', 'scripts/inky-studio-launcher'))
    values = {'RUN_USER': 'inky', 'SERVICE_NAME': 'inky-studio.service',
              'INSTALL_DIR': '/' + APP, 'DATA_DIR': '/' + DATA,
              'REPO_SLUG': installer_repository(install)}
    app_unit = substitute(section(install, 'sudo tee "/etc/systemd/system/${SERVICE_NAME}" >/dev/null <<EOF\n', '\nEOF\n'), values) + '\n'
    sudoers = substitute(section(install, 'cat > "${SUDOERS_TMP}" <<EOF\n', '\nEOF\n'), values).replace('\\`', '`') + '\n'
    network_unit = section(bluetooth, "cat > /etc/systemd/system/inky-network.service <<'UNIT'\n", '\nUNIT\n') + '\n'
    polkit = section(bluetooth, "cat > /etc/polkit-1/rules.d/49-inky-network.rules <<'POLKIT'\n", '\nPOLKIT\n') + '\n'
    dropin = section(bluetooth, "cat > /etc/systemd/system/inky-studio.service.d/bluetooth.conf <<'UNIT'\n", '\nUNIT\n') + '\n'
    stable_launcher = (section(launcher, "  cat <<'HEADER'\n", '\nHEADER\n') + '\n'
                       + f'INKY_DEFAULT_INSTALL_DIR=/{APP}\nINKY_DEFAULT_DATA_DIR=/{DATA}\n'
                       + section(launcher, "  cat <<'BODY'\n", '\nBODY\n') + '\n')
    return {
        'usr/lib/systemd/system/inky-studio.service': (app_unit, 0o644),
        'usr/lib/systemd/system/inky-network.service': (network_unit, 0o644),
        'etc/systemd/system/inky-studio.service.d/bluetooth.conf': (dropin, 0o644),
        'etc/systemd/system/inky-studio.service.d/10-inkyos-firstboot.conf': (FIRSTBOOT_DROPIN, 0o644),
        'etc/systemd/system/inky-network.service.d/10-inkyos-firstboot.conf': (FIRSTBOOT_DROPIN, 0o644),
        'usr/local/lib/inky-studio/network-helper.py': (sources['scripts/inky-network-helper.py'], 0o555),
        'etc/polkit-1/rules.d/49-inky-network.rules': (polkit, 0o644),
        'etc/sudoers.d/inky-studio': (sudoers, 0o440),
        'usr/local/bin/inky-studio': (stable_launcher, 0o755),
    }


def accounts(tree):
    users = [line.split(':') for line in tree.read('etc/passwd', 1024 * 1024).splitlines()]
    groups = [line.split(':') for line in tree.read('etc/group', 1024 * 1024).splitlines()]
    shadow = [line.split(':') for line in tree.read('etc/shadow', 1024 * 1024).splitlines()]
    require(all(len(row) == 7 for row in users) and all(len(row) == 4 for row in groups)
            and all(len(row) == 9 for row in shadow), 'Malformed account database')
    require(len({row[0] for row in users}) == len(users) and len({row[0] for row in groups}) == len(groups)
            and len({row[0] for row in shadow}) == len(shadow), 'Duplicate account records')
    u, g, s = ({row[0]: row for row in records} for records in (users, groups, shadow))
    app, helper, group = u['inky'], u['inky-network'], g['inky-provisioning']
    require(app[2:4] == ['1000', '1000'] and app[5:] == ['/home/inky', '/usr/sbin/nologin'], 'App account mismatch')
    require(sum(row[2] == '1000' for row in users) == 1 and 'pi' not in u, 'App UID must be unique')
    require(helper[2].isdigit() and 0 < int(helper[2]) < 1000 and helper[3] == group[2]
            and helper[5:] == ['/nonexistent', '/usr/sbin/nologin'], 'Helper account mismatch')
    require(sum(row[2] == helper[2] for row in users) == 1 and group[2].isdigit()
            and 0 < int(group[2]) < 1000 and sum(row[2] == group[2] for row in groups) == 1,
            'Helper UID/GID must be unique non-root system IDs')
    require(group[3] == 'inky', 'Provisioning group must include only the app explicitly')
    memberships = lambda account: {row[0] for row in groups if row[2] == account[3] or account[0] in row[3].split(',')}
    require(memberships(helper) == {'inky-provisioning'}, 'Unexpected helper privilege group')
    require({'spi', 'i2c', 'gpio', 'inky-provisioning'} <= memberships(app)
            and not {'sudo', 'admin', 'netdev', 'root'} & memberships(app), 'Unexpected app group privileges')
    require(s['inky'][1].startswith(('!', '*')) and s['inky-network'][1].startswith(('!', '*')),
            'Application accounts must have locked passwords')
    require(s['inky-network'][2] == '0', 'Helper account timestamp must be deterministic')
    return True


def application_metadata(manifest, digest):
    return {'source_commit': manifest['source_commit'], 'application_version': manifest['application_version'],
            'manifest_sha256': digest, 'startup': STARTUP, 'release_qualified': False}


def write_root_configuration(tree, path, content, mode):
    # The enclosing builder uses umask 077. New runtime parent directories must
    # still be traversable; preserve existing vendor directories and their groups.
    parts = PurePosixPath(path).parts
    for length in range(1, len(parts)):
        directory = tree.path('/'.join(parts[:length]))
        try:
            info = directory.lstat()
            require(stat.S_ISDIR(info.st_mode), 'Unsafe configuration parent')
        except FileNotFoundError:
            directory.mkdir(mode=0o755)
            directory.chmod(0o755)
            if os.geteuid() == 0:
                os.chown(directory, 0, 0, follow_symlinks=False)
    tree.write(path, content, mode)
    if os.geteuid() == 0:
        os.chown(tree.path(path), 0, 0, follow_symlinks=False)


def configure(rootfs, manifest_path, digest, *, _app_uid=1000, _app_gid=1000):
    manifest = load_manifest(manifest_path, digest)
    source = inspection.SafeTree(rootfs)
    try:
        files = expected_files(source)
        accounts(source)
        require(source.read(APP + '/server/SOURCE_COMMIT', 256).strip() == manifest['source_commit'], 'App source pin mismatch')
        release = json.loads(source.read('etc/inkyos-release.json', 1024 * 1024))
        require(release['kind'] == 'system-prototype' and release['application'] is None,
                'Application integration requires a fresh system prototype')
        require(release['recipe_inputs']['files']['application-manifest.json'] == digest,
                'Application manifest must be included in recipe inputs')
        require(source.read('etc/machine-id', 256) == 'uninitialized\n', 'Image must not have booted')
    finally:
        source.close()
    tree = configuration.Tree(rootfs)
    for path, (content, mode) in files.items():
        write_root_configuration(tree, path, content, mode)
    for service in SERVICES:
        tree.link('etc/systemd/system/' + service, '/dev/null')
    # Deliberate experimental gate: a future authenticated country contract must
    # precede radio activation. No country is inferred from the build machine.
    tree.write('var/lib/NetworkManager/NetworkManager.state', '[main]\nWirelessEnabled=false\n', 0o600)
    for name in BACKUPS:
        tree.remove('etc/' + name)
    # Match install.sh's empty data directories. Their ownership permits future
    # app startup without creating any identity, password, certificate or photo.
    for relative in (DATA, DATA + '/photos'):
        directory = tree.path(relative)
        require(not directory.exists() and not directory.is_symlink(), 'App data must be absent before integration')
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)
        if os.geteuid() == 0:
            os.chown(directory, _app_uid, _app_gid, follow_symlinks=False)
        require(directory.stat().st_uid == _app_uid and directory.stat().st_gid == _app_gid,
                'Cannot prepare app data ownership')
    release['kind'] = 'application-prototype'
    release['application'] = application_metadata(manifest, digest)
    tree.write('etc/inkyos-release.json', json.dumps(release, indent=2, sort_keys=True) + '\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error('Run only through the isolated Linux image builder')
    try:
        configure(args.rootfs, args.manifest, args.sha256)
        print('Static app integration prepared; runtime services remain masked.')
        return 0
    except (OSError, ValueError, TypeError, KeyError):
        print('Static application configuration failed; no service started.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
