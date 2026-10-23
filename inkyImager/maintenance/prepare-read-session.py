#!/usr/bin/env python3
"""Prepare a one-shot, read-only maintenance session after the user inserts SD.

Stage only inventories removable media and writes private request/launcher files.
The generated launcher performs acquisition; it never prepares or runs an update.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shlex
import shutil
import signal
import stat
import subprocess
import time
import uuid


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(4 * 1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def private_file(path, maximum=65536):
    path = Path(path)
    require(path.is_absolute(), 'Chemin privé absolu requis.')
    for part in [path, *path.parents]:
        require(not part.is_symlink(), 'Lien refusé dans le chemin privé.')
    value = path.stat()
    require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_uid == os.getuid()
            and stat.S_IMODE(value.st_mode) in (0o400, 0o600) and value.st_size <= maximum,
            'Fichier de configuration privé requis.')
    return path


def save_new(path, value):
    path = Path(path)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        output.write(json.dumps(value, sort_keys=True, indent=2) + '\n')
        output.flush()
        os.fsync(output.fileno())


def volume_info(path):
    return plistlib.loads(subprocess.check_output(
        ['/usr/sbin/diskutil', 'info', '-plist', str(path)], timeout=30))


def check_container(path, capacity=None):
    container = json.loads(private_file(path).read_text())
    mount, private = Path(container['mount']), Path(container['private'])
    require(private == mount / 'private', 'Dossier de sauvegarde inattendu.')
    info = volume_info(mount)
    require(info.get('FilesystemType') == 'apfs' and info.get('MountPoint') == str(mount)
            and info.get('VolumeUUID') == container['volume_uuid']
            and info.get('GlobalPermissionsEnabled') is True,
            'Le coffre privé doit être monté avec son identité et ses permissions.')
    value = private.stat()
    require(value.st_uid == os.getuid() and stat.S_IMODE(value.st_mode) == 0o700,
            'Dossier de sauvegarde privé requis.')
    physical = volume_info('/Volumes/Elements')
    require(physical.get('VolumeUUID') == container['physical_volume_uuid'],
            'Le Western Digital attendu doit être connecté.')
    if capacity is not None:
        required = 3 * capacity + 2 * 1024**3
        require(shutil.disk_usage(private).free >= required
                and shutil.disk_usage('/Volumes/Elements').free >= required,
                'Espace insuffisant pour sauvegarde, copie de travail et réserve.')
    return container, private


def check_binary(path, expected):
    path = Path(path)
    require(path.is_absolute(), 'Chemin absolu de l’outil natif requis.')
    for part in [path, *path.parents]:
        require(not part.is_symlink(), 'Lien refusé dans le chemin de l’outil natif.')
    value = path.lstat()
    require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1
            and value.st_uid == os.getuid() and os.access(path, os.X_OK)
            and re.fullmatch(r'[0-9a-f]{64}', expected) and digest(path) == expected,
            'L’outil natif a changé ou n’est pas exécutable.')
    subprocess.run(['/usr/bin/codesign', '--verify', '--strict', str(path)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)


def stage(args):
    check_binary(args.binary, args.binary_sha256)
    container, private = check_container(args.container)
    cards = json.loads(subprocess.check_output([str(args.binary), 'list'], timeout=120))
    require(isinstance(cards, list) and len(cards) == 1,
            'Une seule carte SD doit être proposée. Reviens dans Codex pour la sélectionner.')
    card = cards[0]
    require(re.fullmatch(r'disk[0-9]+', card['id']) and isinstance(card['capacity'], int)
            and card['capacity'] > 0 and card['registryID'] > 0,
            'Identité de carte SD invalide.')
    check_container(args.container, card['capacity'])
    session = private / ('sd-sharing-' + uuid.uuid4().hex)
    session.mkdir(mode=0o700)
    request = session / 'acquire-request.json'
    save_new(request, {'schemaVersion': 1, 'ownerUID': os.getuid(),
                       'target': card, 'backupFile': 'sd-backup.img'})
    config = session / 'read-launch.json'
    save_new(config, {'schema_version': 1, 'binary': str(args.binary),
                      'binary_sha256': args.binary_sha256, 'request': str(request),
                      'request_sha256': digest(request), 'container': str(args.container),
                      'container_sha256': digest(args.container), 'session': str(session)})
    launcher = session / 'read.command'
    code = '#!/bin/zsh\nset -eu\nexec /usr/bin/python3 ' + shlex.quote(str(Path(__file__).resolve())) + \
        ' run --config ' + shlex.quote(str(config)) + ' --config-sha256 ' + digest(config) + '\n'
    fd = os.open(str(launcher), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
    with os.fdopen(fd, 'w') as output:
        output.write(code)
        output.flush()
        os.fsync(output.fileno())
    print(json.dumps({'status': 'read_only_launcher_prepared', 'session': str(session),
                      'launcher': str(launcher), 'device': card['id'],
                      'capacity': card['capacity'], 'SD_opened': False}))


def run(args):
    config_path = private_file(args.config)
    require(digest(config_path) == args.config_sha256, 'Le lanceur a changé.')
    config = json.loads(config_path.read_text())
    require(config['schema_version'] == 1, 'Version de lanceur inconnue.')
    check_binary(config['binary'], config['binary_sha256'])
    request = private_file(config['request'])
    require(digest(request) == config['request_sha256'], 'La sélection de carte a changé.')
    require(digest(private_file(config['container'])) == config['container_sha256'], 'Le coffre a changé.')
    value = json.loads(request.read_text())
    _, private = check_container(config['container'], value['target']['capacity'])
    session = Path(config['session'])
    require(session.parent == private and request.parent == session
            and config_path.parent == session and session.stat().st_mode & 0o777 == 0o700,
            'La session de sauvegarde a changé.')
    claim = session / 'read-launch.claim'
    save_new(claim, {'status': 'started', 'operation': 'read_only_acquisition'})
    print('Sauvegarde privée de la carte SD, en lecture seule.\n'
          'Autorise l’accès macOS si demandé. Laisse la carte et le Western Digital branchés.', flush=True)
    child = subprocess.Popen([config['binary'], 'acquire', '--request', str(request)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    previous = None
    phases = {'authorizing-readonly': 'Autorisation macOS', 'acquiring-readonly': 'Copie de la carte',
              'local-readback': 'Vérification de la sauvegarde', 'acquisition-complete': 'Sauvegarde vérifiée'}
    try:
        while child.poll() is None:
            try:
                event = json.loads((session / 'maintenance-progress.json').read_text())
                total, done = event.get('bytesTotal', 0), event.get('bytesDone', 0)
                percent = int(100 * done / total) if total else None
                current = (event.get('phase'), percent)
                if current != previous:
                    label = phases.get(current[0], 'Sauvegarde en cours')
                    print(label + (' : %d %%' % percent if percent is not None else ''), flush=True)
                    previous = current
            except (OSError, ValueError):
                pass
            time.sleep(0.5)
        output, error = child.communicate()
    except KeyboardInterrupt:
        child.send_signal(signal.SIGINT)
        try:
            child.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate()
        raise ValueError('Lecture interrompue. Laisse la carte branchée et reviens dans Codex.')
    require(child.returncode == 0, error.decode('utf8', 'replace')[:4096]
            or 'Sauvegarde non confirmée. Ne relance pas ; reviens dans Codex.')
    result = json.loads(output)
    require(result.get('status') == 'acquisition-complete' and result.get('readbackVerified') is True,
            'La sauvegarde n’a pas pu être confirmée.')
    print('Sauvegarde et relecture locale vérifiées. Aucun flash effectué.\n'
          'Laisse la carte branchée et reviens dans Codex pour la revue.', flush=True)


def main():
    require(os.getuid() >= 500 and os.geteuid() == os.getuid(),
            'Lancer depuis la session utilisateur, sans sudo.')
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    prepare = commands.add_parser('stage')
    prepare.add_argument('--container', type=Path, required=True)
    prepare.add_argument('--binary', type=Path, required=True)
    prepare.add_argument('--binary-sha256', required=True)
    execute = commands.add_parser('run')
    execute.add_argument('--config', type=Path, required=True)
    execute.add_argument('--config-sha256', required=True)
    args = parser.parse_args()
    if args.command == 'stage':
        stage(args)
    else:
        run(args)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, KeyError, TypeError) as error:
        raise SystemExit(str(error))
