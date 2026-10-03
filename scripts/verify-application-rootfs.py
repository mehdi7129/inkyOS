#!/usr/bin/env python3
"""Verify the inactive application image delta without importing app code."""
import argparse
import configparser
from email.parser import Parser
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tomllib

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('_inkyos_app_configuration', ROOT / 'configure-application-rootfs.py')
configuration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(configuration)
inspection = configuration.inspection
APP = configuration.APP


def missing(tree, path):
    try:
        tree.metadata(path)
        return False
    except FileNotFoundError:
        return True


def readlink(tree, path):
    fd, name = tree._parent(path)
    try:
        return os.readlink(name, dir_fd=fd)
    finally:
        os.close(fd)


def secure_file(tree, path, mode, uid, gid):
    info = tree.metadata(path)
    return (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == uid
            and info.st_gid == gid and stat.S_IMODE(info.st_mode) == mode)


def secure_parents(tree, path, uid, gid):
    for parent in PurePosixPath(path).parents:
        if str(parent) == '.':
            continue
        info = tree.metadata(str(parent))
        if not (stat.S_ISDIR(info.st_mode) and info.st_uid == uid
                and not info.st_mode & 0o022):
            return False
    return True


def empty_or_missing(tree, path, depth=0):
    if missing(tree, path):
        return True
    if depth > 5 or not stat.S_ISDIR(tree.metadata(path).st_mode):
        return False
    entries = tree.entries(path)
    return len(entries) <= 256 and all(stat.S_ISDIR(info.st_mode)
                                      and empty_or_missing(tree, path + '/' + name, depth + 1)
                                      for name, info in entries)


def no_bytecode(tree):
    pending, total = [(APP, 0)], 0
    while pending:
        path, depth = pending.pop()
        if depth > 32:
            return False
        for name, info in tree.entries(path):
            total += 1
            if total > 100000 or name == '__pycache__' or name.endswith(('.pyc', '.pyo')):
                return False
            if stat.S_ISDIR(info.st_mode):
                pending.append((path + '/' + name, depth + 1))
    return True


def no_country(tree):
    # Known system country entry points only: not an exhaustive filesystem scan.
    for path in ('etc/default/crda', 'etc/wpa_supplicant/wpa_supplicant.conf'):
        if not missing(tree, path):
            return False
    for directory in ('etc/modprobe.d', 'etc/NetworkManager/conf.d'):
        if missing(tree, directory):
            continue
        for name, info in tree.entries(directory):
            if not name.endswith('.conf'):
                continue
            if not stat.S_ISREG(info.st_mode):
                return False
            lines = [line.split('#', 1)[0] for line in tree.read(directory + '/' + name, 65536).splitlines()]
            if re.search(r'(?i)\b(?:country|regdom|ieee80211_regdom|regulatory-domain)\s*=', '\n'.join(lines)):
                return False
    return True


def venv_contract(tree, manifest, app_uid, app_gid):
    server = APP + '/server'
    venv = server + '/.venv'
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read_string('[venv]\n' + tree.read(venv + '/pyvenv.cfg', 65536))
    if cfg['venv'].get('include-system-site-packages') != 'false' or not cfg['venv'].get('version', '').startswith('3.13.'):
        return False
    cfg_text = tree.read(venv + '/pyvenv.cfg', 65536)
    if '/var/tmp/' in cfg_text or '/Users/' in cfg_text:
        return False
    executable = venv + '/bin/inky-studio-server'
    info = tree.metadata(executable)
    if not (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == app_uid
            and info.st_gid == app_gid and stat.S_IMODE(info.st_mode) == 0o755):
        return False
    entry = tree.read(executable, 65536)
    if entry.splitlines()[0] != '#!/' + venv + '/bin/python' or 'from inky_web.main import run' not in entry:
        return False
    project = tomllib.loads(tree.read(server + '/pyproject.toml', 65536))['project']
    if project.get('name') != 'inky-studio-server' or project.get('scripts', {}).get('inky-studio-server') != 'inky_web.main:run':
        return False
    # Packaging uses PEP 440 (0.5.0rc2), the manifest uses the release tag form.
    normalized = re.sub(r'-rc\.(\d+)$', r'rc\1', manifest['application_version'])
    if project['version'] != normalized:
        return False
    site = venv + '/lib/python3.13/site-packages'
    candidates = [name for name, info in tree.entries(site)
                  if name.startswith('inky_studio_server-') and name.endswith('.dist-info') and stat.S_ISDIR(info.st_mode)]
    if len(candidates) != 1:
        return False
    metadata = Parser().parsestr(tree.read(site + '/' + candidates[0] + '/METADATA', 1024 * 1024))
    if metadata.get_all('Name') != ['inky-studio-server'] or metadata.get_all('Version') != [normalized]:
        return False
    direct = json.loads(tree.read(site + '/' + candidates[0] + '/direct_url.json', 65536))
    return direct == {'dir_info': {'editable': True}, 'url': 'file:///' + server}


def verify(rootfs, manifest_path, digest, *, _owner_uid=0, _owner_gid=0, _app_uid=1000, _app_gid=1000):
    manifest = configuration.load_manifest(manifest_path, digest)
    checks, files = [], {}

    def check(identifier, callback, requirement):
        try:
            passed = bool(callback())
        except (OSError, ValueError, KeyError, TypeError, IndexError, configparser.Error):
            passed = False
        checks.append({'id': identifier, 'passed': passed, 'requirement': requirement})

    tree = inspection.SafeTree(rootfs)
    try:
        def metadata():
            data = json.loads(tree.read('etc/inkyos-release.json', 1024 * 1024))
            return (type(data.get('schema_version')) is int and data['schema_version'] == 1
                    and data.get('kind') == 'application-prototype'
                    and data.get('status') == 'not-hardware-qualified'
                    and data.get('application') == configuration.application_metadata(manifest, digest)
                    and data['recipe_inputs']['files']['application-manifest.json'] == digest
                    and secure_file(tree, 'etc/inkyos-release.json', 0o644, _owner_uid, _owner_gid))

        check('APPLICATION_METADATA', metadata, 'Pinned inactive application-prototype, unqualified release and manifest recorded in recipe inputs')

        def reviewed():
            files.update(configuration.expected_files(tree, source_commit=manifest['source_commit'], manifest_sha256=digest))
            return True

        check('REVIEWED_INSTALLER_SOURCES', reviewed, 'All declarative installer inputs match the reviewed source hashes; no installer runs')
        check('SOURCE_COMMIT_PIN', lambda: tree.read(APP + '/server/SOURCE_COMMIT', 256).strip() == manifest['source_commit'],
              'Installed SOURCE_COMMIT equals the pinned source')
        check('APPLICATION_ACCOUNTS', lambda: configuration.accounts(tree), 'Locked nologin app and least-privilege nonroot helper accounts')
        for path, (content, mode) in files.items():
            identifier = 'EXACT_' + path.upper().replace('/', '_').replace('.', '_').replace('-', '_')
            check(identifier, lambda p=path, c=content, m=mode: secure_file(tree, p, m, _owner_uid, _owner_gid)
                  and secure_parents(tree, p, _owner_uid, _owner_gid) and tree.read(p, 1024 * 1024) == c,
                  '/' + path + ': exact reviewed content, root ownership and mode')
        for service in configuration.SERVICES:
            check('APP_MASK_' + service, lambda s=service: readlink(tree, 'etc/systemd/system/' + s) == '/dev/null',
                  service + ' is masked pending the firstboot contract')
            check('APP_NOT_ENABLED_' + service, lambda s=service: missing(tree, 'etc/systemd/system/multi-user.target.wants/' + s),
                  service + ' has no enablement link')

        def dropins():
            expected = {'inky-studio.service': {'bluetooth.conf', '10-inkyos-firstboot.conf'},
                        'inky-network.service': {'10-inkyos-firstboot.conf'}}
            for service, names in expected.items():
                if {name for name, _ in tree.entries('etc/systemd/system/' + service + '.d')} != names:
                    return False
                for base in ('usr/lib/systemd/system', 'run/systemd/system'):
                    if not missing(tree, base + '/' + service + '.d'):
                        return False
                if not missing(tree, 'run/systemd/system/' + service):
                    return False
            return True

        check('NO_EXTRA_APP_OVERRIDES', dropins, 'Only reviewed firstboot/Bluetooth dropins; no runtime/vendor override')
        check('WIFI_DISABLED', lambda: tree.read('var/lib/NetworkManager/NetworkManager.state', 4096)
              == '[main]\nWirelessEnabled=false\n' and secure_file(tree, 'var/lib/NetworkManager/NetworkManager.state', 0o600, _owner_uid, _owner_gid),
              'Wi-Fi stays disabled pending an authenticated country contract')
        check('NO_PRESEEDED_COUNTRY', lambda: no_country(tree), 'No country in known supplicant, CRDA, modprobe or NetworkManager configuration entry points')
        check('APP_VENV', lambda: venv_contract(tree, manifest, _app_uid, _app_gid),
              'Private Python 3.13 venv and installed editable metadata/entrypoint target the final app path/version')
        check('NO_PYTHON_BYTECODE', lambda: no_bytecode(tree), 'No generated bytecode or __pycache__ in installed application/venv')
        def data_directories():
            for path in (configuration.DATA, configuration.DATA + '/photos'):
                info = tree.metadata(path)
                if not (stat.S_ISDIR(info.st_mode) and info.st_uid == _app_uid and info.st_gid == _app_gid
                        and stat.S_IMODE(info.st_mode) == 0o755):
                    return False
            return ([name for name, _ in tree.entries(configuration.DATA)] == ['photos']
                    and tree.entries(configuration.DATA + '/photos') == [])

        check('APP_DATA_DIRECTORIES', data_directories, 'Only empty app-owned 0755 data/photos directories are prepared')
        check('NO_APP_RUNTIME_STATE', lambda: all(empty_or_missing(tree, path) for path in
              (configuration.DATA, 'var/lib/inky-network', APP + '/server/data', 'home/inky/.cache',
               'etc/NetworkManager/system-connections', 'run/NetworkManager/system-connections')),
              'No app/helper state, identities, cache or Wi-Fi profiles; only absent/empty directories')
        check('NO_ACCOUNT_BACKUPS', lambda: all(missing(tree, 'etc/' + name) for name in configuration.BACKUPS),
              'No build-created account database backups')
        check('NO_HELPER_HOME', lambda: missing(tree, 'nonexistent'), 'System helper has no home directory')
    finally:
        tree.close()
    failures = [entry['id'] for entry in checks if not entry['passed']]
    return {'schema_version': 1, 'scope': 'offline-application-prototype-contract', 'passed': not failures,
            'qualification': 'not-hardware-qualified', 'manifest_sha256': digest,
            'source_commit': manifest['source_commit'], 'application_version': manifest['application_version'],
            'startup': configuration.STARTUP, 'release_qualified': False,
            'checks': checks, 'failed_checks': failures,
            'expected_file_sha256': {path: hashlib.sha256(content.encode()).hexdigest() for path, (content, _) in files.items()},
            'method': {'image_code_executed': False, 'symlinks_followed': False, 'secret_values_included': False},
            'limitations': ['Static inactive integration only; no proof of factory bootstrap, boot, radio, display or application health.',
                            'Known state and country entry points only; not an exhaustive secret/configuration scan.',
                            'Python metadata is inspected without importing code; dependency installation is verified separately.']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.output.resolve().is_relative_to(args.rootfs.resolve()):
            raise ValueError('Report must be outside the inspected tree')
        report = verify(args.rootfs, args.manifest, args.sha256)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write('\n')
        print(f"Application static verification: {'PASS' if report['passed'] else 'FAIL'} ({len(report['failed_checks'])} failed checks)")
        return 0 if report['passed'] else 1
    except (OSError, ValueError, TypeError, KeyError):
        print('Static application verification failed; no image code executed.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
