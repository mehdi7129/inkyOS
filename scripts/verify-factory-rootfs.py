#!/usr/bin/env python3
"""Inspect only the passive factory layout; never import or execute image code.

Known rootfs state/radio/service entry points only, not full-image validation.
The private ownership arguments are for synthetic filesystem tests only.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat


ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('factory_layout_inspection', ROOT / 'inspect-rootfs.py')
inspection = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inspection)
DATA = 'var/lib/inky-studio'
MARKER = 'etc/inky-studio/factory-v1.json'
PERMISSION = 'var/lib/inkyos/factory-permission'
MODULE_DIR = 'usr/local/lib/inkyos'
WIFI = 'var/lib/NetworkManager/NetworkManager.state'
WIFI_VALUE = b'[main]\nWirelessEnabled=false\n'
MASKS = ('inky-studio.service', 'inky-network.service', 'inky-photo-frame.service')
UNIT_DIRS = ('etc/systemd/system', 'run/systemd/system', 'usr/lib/systemd/system',
             'usr/local/lib/systemd/system')
MODULE_PINS = {
    'factory-authority.py': 'e5b04dd9ad617cf82c5476d2bc81c1ea1295bd3731c363ac4ed6f0ae5aeacb50',
    'factory-credentials-publisher.py': 'ae8d8898315631e4f5ed016fd21c1393073ae611137ece35c8f3fd4f9201bbfe',
    'initialization-receipt.py': '42d2e4ac0b38a3788d41dc4dd85a8df965a5c30fc88dbbfcbd6ed213c3e47de6',
    'initialization-server.py': '946d8bc1823852839058389f59e90b3ae34810b7508aca069c43e40ed6084057',
}
MARKER_VALUE = {'version': 1, 'app_uid': 1000, 'data_dir': '/var/lib/inky-studio'}
PERMISSION_VALUE = {'version': 1, 'operation': 'create-initialization-authority'}
ABSENT = ('var/lib/inky-network', 'var/lib/systemd/random-seed', 'var/lib/urandom/random-seed',
          'var/lib/inkyos-test-enrollment', 'var/lib/inkyos-test-access',
          'run/inkyos-bootstrap', 'etc/default/crda', 'etc/wpa_supplicant/wpa_supplicant.conf')
EMPTY = ('etc/NetworkManager/system-connections', 'run/NetworkManager/system-connections',
         'home/inky/inky-studio/server/data', 'home/inky/.cache', 'home/inky/.ssh', 'root/.ssh')
LIMITATIONS = [
    'Passive offline layout only; no image code, target interpreter, service or command is executed.',
    'Exporter installation/support, full application candidate and full-image provenance are not verified.',
    'Known rootfs identity, state, radio and systemd entry points only; not an exhaustive secret or bootfs audit.',
    'Persistent masks do not qualify a runtime writer barrier or prevent manual application execution.',
    'No boot, runtime, radio, hardware or release qualification; no image recipe is activated.',
    'Configuration requires a private tree without concurrent writers. No rollback: I/O failure may leave partial state. Reserved files or permission state block retries; empty ancestor directories alone can be reused.',
]


def require(value):
    if not value:
        raise ValueError('factory_layout_refused')


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class LayoutTree(inspection.SafeTree):
    def __init__(self, root, uid, gid):
        path = Path(root)
        require(callable(getattr(os, 'listxattr', None)))
        require(path.is_absolute() and path != Path('/') and '..' not in path.parts)
        self.uid, self.gid = uid, gid
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for name in path.parts[1:]:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = child
            self.fd = fd
            self.directory('.')
        except BaseException:
            os.close(fd); raise

    def absent(self, path):
        try:
            self.metadata(path); return False
        except FileNotFoundError:
            return True

    def directory(self, path, *, uid=None, gid=None, mode=None):
        info = self.metadata(path)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == (self.uid if uid is None else uid)
                and info.st_gid == (self.gid if gid is None else gid)
                and not stat.S_IMODE(info.st_mode) & 0o7022
                and (mode is None or stat.S_IMODE(info.st_mode) == mode))
        fd, name = self._parent(path)
        try:
            item = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try: require(not os.listxattr(item))
            finally: os.close(item)
        finally: os.close(fd)

    def parents(self, path):
        self.directory('.')
        for parent in reversed(PurePosixPath(path).parents):
            if str(parent) != '.' and not self.absent(str(parent)):
                self.directory(str(parent))

    def bytes(self, path, *, mode=None, limit=1024 * 1024):
        self.parents(path)
        expected = self.metadata(path)
        require(stat.S_ISREG(expected.st_mode) and expected.st_nlink == 1)
        parent, name = self._parent(path)
        try: fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        finally: os.close(parent)
        try:
            before = os.fstat(fd)
            require(stamp(expected) == stamp(before)
                    and stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and before.st_uid == self.uid and before.st_gid == self.gid
                    and not stat.S_IMODE(before.st_mode) & 0o7022
                    and (mode is None or stat.S_IMODE(before.st_mode) == mode)
                    and 0 <= before.st_size <= limit and not os.listxattr(fd))
            raw = os.read(fd, limit + 1)
            require(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd))
                    == stamp(self.metadata(path)))
            return raw
        finally: os.close(fd)

    def link(self, path):
        self.parents(path)
        info = self.metadata(path)
        require(stat.S_ISLNK(info.st_mode) and info.st_nlink == 1
                and info.st_uid == self.uid and info.st_gid == self.gid)
        parent, name = self._parent(path)
        try: return os.readlink(name, dir_fd=parent)
        finally: os.close(parent)


@contextlib.contextmanager
def tree(rootfs, uid, gid):
    require(type(uid) is int and type(gid) is int and uid >= 0 and gid >= 0)
    value = LayoutTree(rootfs, uid, gid)
    try: yield value
    finally: value.close()


def unused(tree):
    machine_id_mode = stat.S_IMODE(tree.metadata('etc/machine-id').st_mode)
    require(machine_id_mode in (0o444, 0o644))
    require(tree.bytes('etc/machine-id', mode=machine_id_mode, limit=256) == b'uninitialized\n')
    if not tree.absent('var/lib/dbus/machine-id'):
        info = tree.metadata('var/lib/dbus/machine-id')
        if stat.S_ISLNK(info.st_mode):
            require(tree.link('var/lib/dbus/machine-id') == '/etc/machine-id')
        else:
            require(tree.bytes('var/lib/dbus/machine-id', limit=256) in (b'', b'uninitialized\n'))
    if not tree.absent('etc/hostname'):
        require(tree.bytes('etc/hostname', limit=256) == b'inky-unconfigured\n')
    require(all(tree.absent(path) for path in ABSENT))
    for path in EMPTY:
        if not tree.absent(path):
            # State contents are never read, including credentials or Wi-Fi profiles.
            require(stat.S_ISDIR(tree.metadata(path).st_mode) and not tree.entries(path))
    if not tree.absent('etc/ssh'):
        tree.directory('etc/ssh')
        require(not any(name.startswith('ssh_host_') for name, _ in tree.entries('etc/ssh')))
    require(not any(name.startswith('inkyos-test-') for name, _ in tree.entries('etc')))
    users = tree.bytes('etc/passwd', mode=0o644).decode('ascii').splitlines()
    users = [line.split(':') for line in users]
    require(users and all(len(row) == 7 for row in users)
            and len({row[0] for row in users}) == len(users)
            and sum(row[2] == '1000' for row in users) == 1
            and any(row[0] == 'inky' and row[2:4] == ['1000', '1000']
                    and row[5:] == ['/home/inky', '/usr/sbin/nologin'] for row in users)
            and not any(row[0] in {'pi', 'inky-test'} for row in users))


def radio_closed(tree):
    require(tree.bytes(WIFI, mode=0o600, limit=4096) == WIFI_VALUE)
    # Same known country entry points as verify-application-rootfs.no_country.
    # This is deliberately not a general scan of files or network credentials.
    require(tree.absent('etc/default/crda') and tree.absent('etc/wpa_supplicant/wpa_supplicant.conf'))
    for directory in ('etc/modprobe.d', 'etc/NetworkManager/conf.d'):
        if tree.absent(directory):
            continue
        tree.parents(directory); tree.directory(directory)
        entries = tree.entries(directory)
        require(len(entries) <= 256)
        for name, _ in entries:
            if name.endswith('.conf'):
                raw = tree.bytes(directory + '/' + name, limit=65536).decode('utf-8')
                lines = [line.split('#', 1)[0] for line in raw.splitlines()]
                require(not re.search(r'(?i)\b(?:country|regdom|ieee80211_regdom|regulatory-domain)\s*=', '\n'.join(lines)))


def services_closed(tree, *, preparing):
    for unit in MASKS:
        path = 'etc/systemd/system/' + unit
        tree.parents(path)
        require(preparing and tree.absent(path) or tree.link(path) == '/dev/null')
    total = 0
    for base in UNIT_DIRS:
        if tree.absent(base):
            continue
        pending = [(base, 0)]
        while pending:
            directory, depth = pending.pop(); require(depth <= 8)
            tree.directory(directory)
            for name, info in tree.entries(directory):
                total += 1; require(total <= 20000)
                path = directory + '/' + name
                require(name not in {unit + '.d' for unit in MASKS})
                if name in MASKS:
                    allowed_mask = base == directory == 'etc/systemd/system'
                    vendor_file = base == directory and base in {'usr/lib/systemd/system', 'usr/local/lib/systemd/system'}
                    require(allowed_mask or vendor_file and stat.S_ISREG(info.st_mode)
                            and info.st_nlink == 1 and info.st_uid == tree.uid and info.st_gid == tree.gid
                            and not stat.S_IMODE(info.st_mode) & 0o7022)
                if stat.S_ISDIR(info.st_mode):
                    pending.append((path, depth + 1))
                elif stat.S_ISLNK(info.st_mode):
                    target = tree.link(path)
                    require(PurePosixPath(target).name not in MASKS)
                require(name not in {'inkyos-factory.service', 'inkyos-initialization.service'})


def layout(tree, *, preparing, app_uid, app_gid):
    require(type(app_uid) is int and type(app_gid) is int and app_uid >= 0 and app_gid >= 0)
    directories = {'etc/inky-studio': None, 'var/lib/inkyos': None, MODULE_DIR: None}
    for path in (*directories, DATA, PERMISSION):
        tree.parents(path)
    for path in directories:
        if not tree.absent(path): tree.directory(path)
    if not tree.absent(DATA):
        tree.directory(DATA, uid=app_uid, gid=app_gid, mode=0o700)
        require(not tree.entries(DATA))
    else:
        require(preparing)
    expected = {'etc/inky-studio': {'factory-v1.json'}, 'var/lib/inkyos': {'factory-permission'}}
    for path, names in expected.items():
        if not tree.absent(path):
            require({name for name, _ in tree.entries(path)} == (set() if preparing else names))
        else:
            require(preparing)
    for filename, digest in MODULE_PINS.items():
        path = MODULE_DIR + '/' + filename
        if preparing: require(tree.absent(path))
        else: require(hashlib.sha256(tree.bytes(path, mode=0o555)).hexdigest() == digest)
    if preparing:
        require(tree.absent(MARKER) and tree.absent(PERMISSION))
    else:
        tree.directory(PERMISSION, mode=0o700)
        require({name for name, _ in tree.entries(PERMISSION)} == {'lock', 'pending.json'})
        require(tree.bytes(MARKER, mode=0o644) == canonical(MARKER_VALUE))
        require(tree.bytes(PERMISSION + '/lock', mode=0o600) == b'')
        require(tree.bytes(PERMISSION + '/pending.json', mode=0o600) == canonical(PERMISSION_VALUE))


def preflight(rootfs, *, _owner_uid=0, _owner_gid=0, _app_uid=1000, _app_gid=1000):
    with tree(rootfs, _owner_uid, _owner_gid) as source:
        unused(source); radio_closed(source); services_closed(source, preparing=True)
        layout(source, preparing=True, app_uid=_app_uid, app_gid=_app_gid)


def verify(rootfs, *, _owner_uid=0, _owner_gid=0, _app_uid=1000, _app_gid=1000):
    checks = {name: False for name in ('UNUSED_IDENTITY_STATE', 'WIFI_CLOSED', 'SERVICES_MASKED', 'FACTORY_LAYOUT')}
    try:
        with tree(rootfs, _owner_uid, _owner_gid) as source:
            actions = (lambda: unused(source), lambda: radio_closed(source),
                       lambda: services_closed(source, preparing=False),
                       lambda: layout(source, preparing=False, app_uid=_app_uid, app_gid=_app_gid))
            for name, action in zip(checks, actions):
                try: action(); checks[name] = True
                except (OSError, ValueError, KeyError, TypeError): pass
    except (OSError, ValueError, TypeError): pass
    return {'schema_version': 1, 'scope': 'offline-factory-layout', 'passed': all(checks.values()),
            'checks': checks, 'failed_checks': [name for name, passed in checks.items() if not passed],
            'source_sha256': MODULE_PINS.copy(), 'image_code_executed': False, 'services_enabled': False,
            'secret_values_included': False, 'exporter_support_verified': False,
            'full_image_verified': False, 'writer_barrier_qualified': False, 'runtime_qualified': False,
            'hardware_qualified': False, 'limitations': LIMITATIONS.copy()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, required=True)
    args = parser.parse_args(argv)
    result = verify(args.rootfs)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
