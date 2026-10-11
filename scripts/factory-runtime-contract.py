#!/usr/bin/env python3
"""Fixed installed factory contract. No image builder or activation entry point."""
import contextlib
import fcntl
import functools
import grp
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import types

MANIFEST = 'etc/inkyos/factory-runtime-v1.json'
CONTEXT_DIR = 'run/inkyos-factory'
CONTEXT = CONTEXT_DIR + '/context.json'
MODULE_DIR = 'usr/lib/inkyos'
WRITER_PARENTS = MODULE_DIR + '/writer-parents.py'
APP = 'usr/lib/inky-studio'
EXPORTER = 'usr/lib/inkyos/factory-exporter'
SUPPORT = 'etc/inkyos/factory-system-support.json'
HELPER = 'usr/local/lib/inky-studio/network-helper.py'
HELPER_SOURCE = 'scripts/inky-network-helper.py'
IPC = 'usr/local/lib/inkyos/initialization-server.py'
RECEIPT = 'usr/local/lib/inkyos/initialization-receipt.py'
ADMISSION_SHA256 = '915d2a5c0d5d8dd0367dbbb351e70f884a4e4647ef22e6422b1c54032df27884'
MODULES = {'writer-admission.py', 'factory-runtime-contract.py', 'writer-launcher.py'}
WRITER_ENV = {'INKYOS_WRITER_LEASE_FD', 'INKYOS_WRITER_ROLE', 'INKYOS_WRITER_CONTEXT_SHA256'}
HOOKS = (IPC, RECEIPT, 'usr/local/lib/inkyos/factory-authority.py',
         'usr/local/lib/inkyos/factory-credentials-publisher.py')
SUPERVISOR_FILES = {MODULE_DIR + '/factory-supervisor.py': '0555', WRITER_PARENTS: '0555',
                    'usr/lib/systemd/system/inkyos-admission-prepare.service': '0644',
                    'usr/lib/systemd/system/inkyos-factory-supervisor.service': '0644'}
# Exact staging template bytes, independent of a caller's repinned support file.
# The two existing supervisor units participate in the same closed file graph.
UNIT_TEMPLATES = {
    'inky-studio.service': '48f4a5245794ad19fef8e9155a27db814f200eaa99779aefb13be6e6f39350ac',
    'inky-network.service': 'b14c14c8b43e3fec48255dd60ebf539282d9464ab4ddc37e0c7bfb6497f33019',
    'inkyos-initialization.service': '049661642ac18b8efd8c81ef82fefa4cfba2b450b2a4dee8ba1bf573b7bd47c7',
    'inkyos-admission-prepare.service': '8bda5a8691453353345c44bb90e6be1ffd687d888dc823af6746239316baf90e',
    'inkyos-factory-supervisor.service': '26b7cb8a1daf3858ce2f90afc0bb245d1ec6e8efd810c5772c2b13ee36b5c837',
}
UNIT_VENDOR_DIR = 'usr/lib/systemd/system'
WRITER_FILES = {UNIT_VENDOR_DIR + '/' + unit: '0644' for unit in UNIT_TEMPLATES}
# systemd v257.13 path-lookup.c: normal system-manager lookup roots. This is a
# file policy, not an observation of PID1's compiled paths or UNIT_PATH override.
UNIT_LOOKUP_DIRS = (
    'etc/systemd/system.control', 'run/systemd/system.control', 'run/systemd/transient',
    'run/systemd/generator.early', 'etc/systemd/system', 'etc/systemd/system.attached',
    'run/systemd/system', 'run/systemd/system.attached', 'run/systemd/generator',
    'usr/local/lib/systemd/system', UNIT_VENDOR_DIR, 'run/systemd/generator.late',
)
UNIT_EXTENSION_NAMES = {'service'} | {
    stem for unit in UNIT_TEMPLATES
    for stem in (unit, *(unit[:match.end()] + '.service' for match in re.finditer('-', unit)))
}
# load-dropin.c and shared/dropin.c apply type/dash prefixes to dependencies too.
UNIT_ABSENT = {
    directory + '/' + unit for directory in UNIT_LOOKUP_DIRS if directory != UNIT_VENDOR_DIR
    for unit in UNIT_TEMPLATES
} | {
    directory + '/' + stem + '.' + suffix for directory in UNIT_LOOKUP_DIRS
    for stem in UNIT_EXTENSION_NAMES for suffix in ('d', 'wants', 'requires', 'upholds')
}
UNIT_SCAN_LIMIT = 20000
UNIT_SCAN_DEPTH = 8
TEST_SCRIPTS = ('test-enrollment-firstboot', 'test-access-policy', 'test-access-enrollment',
                'test-access-contract', 'test-access-import', 'test-access-connect', 'test-access-boot',
                'test-access-network', 'test-access-wifi-gate', 'test-access-bluetooth', 'test-lan-preflight',
                'test-access-activation-gate', 'test-access-activation', 'test-access-drain',
                'observe-test-panel', 'observe-test-radio')
TEST_ABSENT = {
    'usr/local/share/inkyos/test-access-manifest.json', 'usr/local/share/inkyos/test-access',
    'etc/inkyos-test-ssh', 'etc/inkyos-test-enrollment', 'etc/inkyos-test-lan.json',
    'var/lib/inkyos-test-access', 'var/lib/inkyos-test-enrollment', 'usr/local/lib/inkyos-test-ssh',
    'etc/sudoers.d/inkyos-test-ssh',
    'etc/systemd/system/NetworkManager.service.d/10-inkyos-test-wifi.conf',
    'etc/NetworkManager/conf.d/10-inkyos-test-loopback.conf',
} | {'usr/local/lib/inkyos/' + name + '.py' for name in TEST_SCRIPTS} | {
    prefix + '/inkyos-test-' + name + '.service'
    for prefix in ('usr/lib/systemd/system', 'etc/systemd/system',
                   'etc/systemd/system/multi-user.target.wants')
    for name in ('access', 'ssh', 'activate', 'drain')}
EMPTY_XATTRS = {'status': 'inspected', 'entries': {}}
HASH = re.compile(r'[0-9a-f]{64}\Z')
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')


class Refused(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def require(value, reason='invalid_contract'):
    if not value:
        raise Refused(reason)


def boundary(reason):
    def decorate(function):
        @functools.wraps(function)
        def call(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except Refused:
                raise
            except (OSError, ValueError, TypeError, KeyError, RecursionError):
                raise Refused(reason) from None
        return call
    return decorate


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(Refused('invalid_contract')))


def name(path, root=False):
    require(type(path) is str and len(path) <= 4096 and
            (root and path == '.' or path and not path.startswith('/')
             and all(part not in ('', '.', '..') for part in path.split('/')))
            and not any(ord(char) < 32 or ord(char) == 127 or char == '\\' for char in path))
    return path


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class Tree:
    def __init__(self, root, uid=0, gid=0):
        path = Path(root)
        require(path.is_absolute() and '..' not in path.parts and callable(getattr(os, 'listxattr', None)))
        self.root, self.uid, self.gid = path, uid, gid
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in path.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = child
            self.fd = fd
            self.directory_fd(fd)
        except BaseException:
            os.close(fd); raise

    def __enter__(self): return self
    def __exit__(self, *_): os.close(self.fd)

    def directory_fd(self, fd, mode=None):
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid) == (self.uid, self.gid)
                and not stat.S_IMODE(info.st_mode) & 0o7022 and not os.listxattr(fd)
                and (mode is None or stat.S_IMODE(info.st_mode) == mode), 'invalid_metadata')

    def parent(self, path):
        name(path, root=True)
        fd = os.dup(self.fd)
        try:
            for part in path.split('/')[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = child
                self.directory_fd(fd)
            return fd, path.split('/')[-1]
        except BaseException:
            os.close(fd); raise

    def directory(self, path, mode=None):
        parent, leaf = self.parent(path)
        try: fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        finally: os.close(parent)
        try:
            self.directory_fd(fd, mode)
            return os.fstat(fd), set(os.listdir(fd))
        finally: os.close(fd)

    def read(self, path, mode=None, limit=32 * 1024 * 1024):
        parent, leaf = self.parent(path)
        try:
            before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and (before.st_uid, before.st_gid) == (self.uid, self.gid)
                    and not stat.S_IMODE(before.st_mode) & 0o7022
                    and (mode is None or stat.S_IMODE(before.st_mode) == mode)
                    and 0 <= before.st_size <= limit, 'invalid_metadata')
            fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                require(stamp(before) == stamp(os.fstat(fd)) and not os.listxattr(fd), 'invalid_metadata')
                chunks, remaining = [], limit + 1
                while remaining:
                    part = os.read(fd, min(1024 * 1024, remaining))
                    if not part: break
                    chunks.append(part); remaining -= len(part)
                raw = b''.join(chunks)
                require(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd))
                        == stamp(os.stat(leaf, dir_fd=parent, follow_symlinks=False)), 'invalid_metadata')
                return raw
            finally: os.close(fd)
        finally: os.close(parent)

    def absent(self, path):
        try: parent, leaf = self.parent(path)
        except FileNotFoundError: return True
        try:
            try: os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError: return True
            return False
        finally: os.close(parent)

    def create(self, path, raw, mode):
        parent, leaf = self.parent(path)
        try:
            fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            try:
                if (os.fstat(fd).st_uid, os.fstat(fd).st_gid) != (self.uid, self.gid):
                    os.fchown(fd, self.uid, self.gid)
                view = memoryview(raw)
                while view:
                    count = os.write(fd, view); require(count > 0)
                    view = view[count:]
                os.fchmod(fd, mode); os.fsync(fd)
            finally: os.close(fd)
            os.fsync(parent)
        finally: os.close(parent)


class Contract:
    def __init__(self, manifest, digest, root, uid, gid, boot, mountinfo):
        self.manifest, self.candidate_sha256 = manifest, digest
        self._root, self._uid, self._gid = root, uid, gid
        self._boot, self._mountinfo = boot, mountinfo

    def tree(self): return Tree(self._root, self._uid, self._gid)

    @property
    def context_sha256(self): return context_sha256(self)


@boundary('contract_unavailable')
def load_contract(*, _root=Path('/'), _owner_uid=0, _owner_gid=0, _boot_id=None, _mountinfo=None):
    root = Path(_root)
    require(type(_owner_uid) is int and type(_owner_gid) is int and _owner_uid >= 0 and _owner_gid >= 0)
    require(root != Path('/') or (_owner_uid, _owner_gid, _boot_id, _mountinfo) == (0, 0, None, None))
    with Tree(root, _owner_uid, _owner_gid) as tree:
        raw = tree.read(MANIFEST, 0o644, 16384)
    value = decode(raw)
    require(type(value) is dict and set(value) == {'version', 'studio_commit', 'bundle_manifest_sha256',
            'exporter_manifest_sha256', 'support_manifest_sha256', 'helper_uid', 'provisioning_gid', 'os_module_pins'})
    require(type(value['version']) is int and value['version'] == 1
            and type(value['studio_commit']) is str and re.fullmatch('[0-9a-f]{40}', value['studio_commit']))
    require(all(type(value[key]) is str and HASH.fullmatch(value[key]) for key in
                ('bundle_manifest_sha256', 'exporter_manifest_sha256', 'support_manifest_sha256')))
    require(all(type(value[key]) is int and 1 <= value[key] <= 999 for key in ('helper_uid', 'provisioning_gid')))
    require(type(value['os_module_pins']) is dict and set(value['os_module_pins']) == MODULES
            and all(type(digest) is str and HASH.fullmatch(digest) for digest in value['os_module_pins'].values())
            and value['os_module_pins']['writer-admission.py'] == ADMISSION_SHA256)
    return Contract(value, sha(raw), root, _owner_uid, _owner_gid, _boot_id, _mountinfo)


def unchanged(contract):
    with contract.tree() as tree:
        require(sha(tree.read(MANIFEST, 0o644, 16384)) == contract.candidate_sha256, 'pin_mismatch')


def boot_state(contract, *, writable=False):
    unchanged(contract)
    with contract.tree() as tree:
        info, _ = tree.directory('run', 0o755)
    if contract._boot is None:
        with open('/proc/sys/kernel/random/boot_id', 'rb') as stream: raw = stream.read(129)
        require(raw.endswith(b'\n') and len(raw) <= 128, 'invalid_context')
        boot = raw[:-1].decode('ascii')
    else: boot = contract._boot
    require(type(boot) is str and UUID.fullmatch(boot), 'invalid_context')
    if contract._mountinfo is None:
        with open('/proc/self/mountinfo', 'rb') as stream: raw = stream.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, 'invalid_run')
        mountinfo = raw.decode('ascii')
    else: mountinfo = contract._mountinfo
    require(type(mountinfo) is str and len(mountinfo) <= 1024 * 1024, 'invalid_run')
    mountpoint = str(contract._root / 'run')
    matches = []
    for line in mountinfo.splitlines():
        fields = line.split(); require('-' in fields, 'invalid_run')
        split = fields.index('-')
        require(split >= 6 and len(fields) == split + 4, 'invalid_run')
        decoded = re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), fields[4])
        if decoded == mountpoint: matches.append(fields)
    require(len(matches) == 1, 'invalid_run')
    fields = matches[0]; split = fields.index('-')
    options = set(fields[5].split(','))
    require(fields[split + 1] == 'tmpfs' and fields[3] == '/'
            and len(options & {'ro', 'rw'}) == 1 and (not writable or 'rw' in options)
            and fields[2] == str(os.major(info.st_dev)) + ':' + str(os.minor(info.st_dev)), 'invalid_run')
    return {'version': 1, 'boot_id': boot, 'candidate_sha256': contract.candidate_sha256}


@boundary('invalid_context')
def prepare_boot_context(contract):
    require((os.geteuid(), os.getegid()) == (contract._uid, contract._gid), 'wrong_identity')
    expected = boot_state(contract, writable=True)
    with contract.tree() as tree:
        require(tree.absent(CONTEXT_DIR), 'context_exists')
        require(tree.absent('run/inkyos-admission'), 'context_exists')
        parent, leaf = tree.parent(CONTEXT_DIR)
        try:
            os.mkdir(leaf, 0o755, dir_fd=parent)
            child = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                os.fchmod(child, 0o755)
                if (os.fstat(child).st_uid, os.fstat(child).st_gid) != (contract._uid, contract._gid):
                    os.fchown(child, contract._uid, contract._gid)
            finally: os.close(child)
            os.fsync(parent)
        finally: os.close(parent)
        tree.create(CONTEXT, canonical(expected), 0o644)
    return validate_context(contract)


@boundary('invalid_context')
def validate_context(contract):
    expected = boot_state(contract)
    with contract.tree() as tree:
        _, entries = tree.directory(CONTEXT_DIR, 0o755)
        require(entries == {'context.json'}, 'invalid_context')
        raw = tree.read(CONTEXT, 0o644, 1024)
    require(raw == canonical(expected), 'invalid_context')
    return expected


def context_sha256(contract):
    return sha(canonical(validate_context(contract)))


@boundary('invalid_module')
def import_admission(contract):
    unchanged(contract)
    with contract.tree() as tree:
        tree.directory(MODULE_DIR, 0o755)
        raw = tree.read(MODULE_DIR + '/writer-admission.py', 0o555, 65536)
    require(sha(raw) == contract.manifest['os_module_pins']['writer-admission.py'] == ADMISSION_SHA256,
            'pin_mismatch')
    module = types.ModuleType('inkyos_writer_admission')
    module.__file__ = '/' + MODULE_DIR + '/writer-admission.py'
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


@boundary('invalid_module')
def import_writer_parents(contract):
    """Only the root OS caller imports this required support-pinned module."""
    require((os.geteuid(), os.getegid()) == (contract._uid, contract._gid), 'wrong_identity')
    _, _, _, records = inventories(contract)
    with contract.tree() as tree:
        check_path(tree, WRITER_PARENTS, records)
        raw = tree.read(WRITER_PARENTS, 0o555, 1024 * 1024)
    require(sha(raw) == records[WRITER_PARENTS]['sha256'], 'pin_mismatch')
    module = types.ModuleType('inkyos_writer_parents')
    module.__file__ = '/' + WRITER_PARENTS
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    unchanged(contract)
    return module


@contextlib.contextmanager
def writer_guard(role, *, _contract=None, _identity=None, _environ=None):
    """Own a fresh SH; the caller must drain every writer before leaving it."""
    with contextlib.ExitStack() as stack:
        try:
            require(type(role) is str and role in {'main', 'helper', 'ipc'})
            if _contract is None:
                require(_identity is None and _environ is None)
                contract = load_contract()
            else:
                require(isinstance(_contract, Contract))
                root = _contract._root
                require(root.is_absolute() and root != Path('/') and root == root.resolve(strict=True))
                contract = _contract
            environment = os.environ if _environ is None else _environ
            admission = import_admission(contract)
            lease = stack.enter_context(admission.writer(
                contract._root, _owner_uid=contract._uid, _owner_gid=contract._gid))
            digest = context_sha256(contract)
            verify_role(contract, role, _identity=_identity)
            require(context_sha256(contract) == digest)
            require(all(type(key) is str for key in environment))
            present = {key for key in environment if key.startswith('INKYOS_WRITER_')}
            require(present <= WRITER_ENV)
            if present:
                require(present == WRITER_ENV and environment['INKYOS_WRITER_ROLE'] == role
                        and environment['INKYOS_WRITER_CONTEXT_SHA256'] == digest)
                descriptor = environment['INKYOS_WRITER_LEASE_FD']
                require(type(descriptor) is str and re.fullmatch('[1-9][0-9]{0,9}', descriptor))
                inherited = int(descriptor)
                require(3 <= inherited <= 2147483647 and inherited != lease.fileno()
                        and stamp(os.fstat(inherited)) == stamp(os.fstat(lease.fileno()))
                        and fcntl.fcntl(inherited, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY)
            lease.check()
            require(context_sha256(contract) == digest)
            if present:
                require(stamp(os.fstat(inherited)) == stamp(os.fstat(lease.fileno()))
                        and fcntl.fcntl(inherited, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY)
                os.close(inherited)  # No LOCK_UN: dup/fork may still share this OFD.
                for key in WRITER_ENV:
                    environment.pop(key)
        except Exception:
            raise Refused('writer_admission_refused') from None
        yield lease


SUPPORT_FIELDS = {'schema_version', 'kind', 'base_image_sha256', 'base_lock_sha256',
                  'system_packages_lock_sha256', 'test_access_packages_lock_sha256',
                  'python_version', 'paths', 'trees', 'absent', 'elf_closure_review'}
SUPPORT_TREES = {'usr/lib/python3.13', 'usr/lib/python3/dist-packages',
                 'usr/lib/aarch64-linux-gnu', 'usr/local/lib', 'etc/ld.so.conf.d'}
ABSENCE_GUARDS = {'etc/ld.so.preload', 'lib64', 'usr/bin/Modules', 'usr/bin/lib',
                  'usr/bin/pybuilddir.txt', 'usr/bin/python3.13._pth', 'usr/bin/python3._pth',
                  'usr/bin/pyvenv.cfg', 'usr/lib/lib', 'usr/lib/python313.zip',
                  'usr/local/lib/aarch64-linux-gnu', 'usr/pyvenv.cfg'}
APP_REQUIRED = {HELPER_SOURCE, 'server/.venv/pyvenv.cfg', 'server/.venv/bin/python',
                'server/.venv/lib/python3.13/site-packages/inky_web/main.py'}
EXPORTER_REQUIRED = {'venv/pyvenv.cfg', 'venv/bin/python',
                     'venv/lib/python3.13/site-packages/inky_web/provisioning/factory_credentials.py'}


def record_schema(record):
    require(type(record) is dict and record.get('type') in {'directory', 'file', 'symlink'})
    fields = {'type', 'uid', 'gid', 'mode', 'xattrs'}
    fields |= {'size_bytes', 'sha256'} if record['type'] == 'file' else {'target'} if record['type'] == 'symlink' else set()
    require(set(record) == fields and type(record['uid']) is int and type(record['gid']) is int
            and record['uid'] == record['gid'] == 0 and record['xattrs'] == EMPTY_XATTRS
            and type(record['mode']) is str and re.fullmatch('[0-7]{4}', record['mode']))
    if record['type'] == 'symlink':
        require(record['mode'] == '0777' and type(record['target']) is str and 0 < len(record['target']) <= 4096
                and not any(ord(char) < 32 or ord(char) == 127 for char in record['target']))
    else:
        require(not int(record['mode'], 8) & 0o7022)
    if record['type'] == 'file':
        require(type(record['size_bytes']) is int and 0 <= record['size_bytes'] <= 1024 ** 3
                and type(record['sha256']) is str and HASH.fullmatch(record['sha256']))


def records_schema(records):
    require(type(records) is dict and 0 < len(records) <= 100000
            and type(records.get('.')) is dict and records['.'].get('type') == 'directory')
    for path, record in records.items():
        name(path, root=True); record_schema(record)
        for parent in PurePosixPath(path).parents:
            require(str(parent) in records and records[str(parent)]['type'] == 'directory')


def actual_record(tree, path):
    parent, leaf = tree.parent(path)
    try:
        before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        require((before.st_uid, before.st_gid) == (tree.uid, tree.gid), 'invalid_metadata')
        result = {'uid': 0, 'gid': 0, 'mode': format(stat.S_IMODE(before.st_mode), '04o'), 'xattrs': EMPTY_XATTRS}
        if stat.S_ISLNK(before.st_mode):
            require(before.st_nlink == 1, 'invalid_metadata')
            target = '/proc/self/fd/' + str(parent) + '/' + leaf
            require(not os.listxattr(target, follow_symlinks=False), 'invalid_metadata')
            result.update(type='symlink', target=os.readlink(leaf, dir_fd=parent))
        else:
            require(stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode), 'invalid_metadata')
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if stat.S_ISDIR(before.st_mode): flags |= os.O_DIRECTORY
            else: require(before.st_nlink == 1 and before.st_size <= 1024 ** 3, 'invalid_metadata')
            fd = os.open(leaf, flags, dir_fd=parent)
            try:
                require(stamp(before) == stamp(os.fstat(fd)) and not os.listxattr(fd), 'invalid_metadata')
                if stat.S_ISDIR(before.st_mode): result.update(type='directory')
                else:
                    digest, size = hashlib.sha256(), 0
                    while True:
                        raw = os.read(fd, 1024 * 1024)
                        if not raw: break
                        size += len(raw); require(size <= before.st_size, 'invalid_metadata'); digest.update(raw)
                    require(size == before.st_size, 'invalid_metadata')
                    result.update(type='file', size_bytes=size, sha256=digest.hexdigest())
                require(stamp(before) == stamp(os.fstat(fd)), 'invalid_metadata')
            finally: os.close(fd)
        require(stamp(before) == stamp(os.stat(leaf, dir_fd=parent, follow_symlinks=False)), 'invalid_metadata')
        record_schema(result)
        return result
    finally: os.close(parent)


def resolve(path, records):
    pending, resolved, links = path.split('/'), [], 0
    while pending:
        part = pending.pop(0)
        if part in ('', '.'): continue
        if part == '..':
            require(bool(resolved), 'invalid_candidate'); resolved.pop(); continue
        key = '/'.join(resolved + [part])
        require(key in records, 'invalid_candidate')
        record = records[key]
        if record['type'] == 'symlink':
            links += 1; require(links <= 40, 'invalid_candidate')
            if record['target'].startswith('/'): resolved = []
            pending = record['target'].split('/') + pending
        else:
            require(not pending or record['type'] == 'directory', 'invalid_candidate')
            resolved.append(part)
    return '/'.join(resolved) or '.'


def check_path(tree, path, records):
    require(path in records, 'invalid_candidate')
    for parent in reversed(PurePosixPath(path).parents):
        key = str(parent)
        require(key in records and actual_record(tree, key) == records[key], 'pin_mismatch')
    require(actual_record(tree, path) == records[path], 'pin_mismatch')
    if records[path]['type'] == 'symlink':
        target = resolve(path, records)
        require(target != path, 'invalid_candidate')
        check_path(tree, target, records)


def check_tree(tree, prefix, records, exclude=()):
    pending, seen = ['.'], set()
    while pending:
        relative = pending.pop(); require(len(seen) < 100000, 'invalid_candidate')
        path = prefix if relative == '.' else prefix + '/' + relative
        require(relative in records and actual_record(tree, path) == records[relative], 'pin_mismatch')
        seen.add(relative)
        if records[relative]['type'] == 'directory':
            _, entries = tree.directory(path)
            for item in entries:
                child = item if relative == '.' else relative + '/' + item
                if child not in exclude: pending.append(child)
    require(seen == set(records), 'pin_mismatch')


def inventories(contract):
    unchanged(contract)
    with contract.tree() as tree:
        tree.directory(MODULE_DIR, 0o755)
        for filename, digest in contract.manifest['os_module_pins'].items():
            require(sha(tree.read(MODULE_DIR + '/' + filename, 0o555, 1024 * 1024)) == digest, 'pin_mismatch')
        raw_app = tree.read(APP + '/manifest.json', 0o644)
        raw_exporter = tree.read(EXPORTER + '/manifest.json', 0o644)
        raw_support = tree.read(SUPPORT, 0o644)
    require(all(sha(raw) == contract.manifest[key] for raw, key in
                ((raw_app, 'bundle_manifest_sha256'), (raw_exporter, 'exporter_manifest_sha256'),
                 (raw_support, 'support_manifest_sha256'))), 'pin_mismatch')
    app, exporter, support = map(decode, (raw_app, raw_exporter, raw_support))
    require(type(app) is dict and set(app) == {'schema_version', 'kind', 'studio_commit', 'records'}
            and type(app['schema_version']) is int and app['schema_version'] == 1
            and app['kind'] == 'factory-studio-bundle-manifest' and app['studio_commit'] == contract.manifest['studio_commit'])
    require(type(exporter) is dict and set(exporter) == {'schema_version', 'kind', 'support_manifest_sha256', 'records'}
            and type(exporter['schema_version']) is int and exporter['schema_version'] == 1
            and exporter['kind'] == 'factory-exporter-bundle-manifest'
            and exporter['support_manifest_sha256'] == contract.manifest['support_manifest_sha256'])
    require(type(support) is dict and set(support) == SUPPORT_FIELDS
            and type(support['schema_version']) is int and support['schema_version'] == 1
            and support['kind'] == 'factory-exporter-system-support'
            and re.fullmatch(r'3\.13\.[0-9]+', support['python_version']))
    for field in ('base_image_sha256', 'base_lock_sha256', 'system_packages_lock_sha256', 'test_access_packages_lock_sha256'):
        require(type(support[field]) is str and HASH.fullmatch(support[field]))
    for bundle, required in ((app, APP_REQUIRED), (exporter, EXPORTER_REQUIRED)):
        records_schema(bundle['records'])
        require(required <= set(bundle['records']) and 'manifest.json' not in bundle['records'])
        require(not any(path.endswith(('.pth', '.egg-link')) for path in bundle['records']), 'invalid_candidate')
    require(type(support['paths']) is dict and type(support['trees']) is dict
            and SUPPORT_TREES <= set(support['trees']))
    records = dict(support['paths'])
    for prefix, values in support['trees'].items():
        name(prefix); records_schema(values)
        for path, record in values.items():
            target = prefix if path == '.' else prefix + '/' + path
            require(target not in records)
            records[target] = record
    records_schema(records)
    absent = support['absent']
    require(type(absent) is list and all(type(path) is str for path in absent)
            and len(absent) == len(set(absent)) and TEST_ABSENT | ABSENCE_GUARDS | UNIT_ABSENT <= set(absent))
    for path in absent:
        name(path); require(path not in records)
    require(MANIFEST not in records and SUPPORT not in records)
    require(not any(path.startswith('usr/local/lib/inkyos/test-access-')
                    or 'inkyos-test-' in PurePosixPath(path).name for path in records), 'invalid_candidate')
    review = support['elf_closure_review']
    require(type(review) is dict and set(review) == {'method', 'evidence_sha256', 'roots', 'files', 'search_paths'}
            and type(review['method']) is str and 0 < len(review['method']) <= 4096
            and type(review['evidence_sha256']) is str and HASH.fullmatch(review['evidence_sha256']))
    for key in ('roots', 'files', 'search_paths'):
        require(type(review[key]) is list and 0 < len(review[key]) <= 100000
                and all(type(path) is str for path in review[key]) and len(review[key]) == len(set(review[key])))
        for path in review[key]: name(path)
    for prefix, bundle in ((APP, app), (EXPORTER, exporter)):
        for relative, record in bundle['records'].items():
            path = prefix if relative == '.' else prefix + '/' + relative
            require(path not in records or records[path] == record)
            records[path] = record
    records_schema(records)
    for path in records: resolve(path, records)
    for path in ('usr/bin/python3', 'usr/bin/python3.13', 'etc/ld.so.cache', 'etc/ld.so.conf',
                 HELPER, *HOOKS, *SUPERVISOR_FILES, *WRITER_FILES):
        require(path in records, 'invalid_candidate')
    require(resolve('usr/bin/python3', records) == 'usr/bin/python3.13'
            and records['usr/bin/python3.13']['type'] == 'file', 'invalid_candidate')
    for path in (HELPER, *HOOKS): require(records[path]['type'] == 'file' and records[path]['mode'] == '0555')
    for path, mode in (SUPERVISOR_FILES | WRITER_FILES).items():
        require(path in support['paths'] and records[path]['type'] == 'file' and records[path]['mode'] == mode)
    for filename, digest in contract.manifest['os_module_pins'].items():
        path = MODULE_DIR + '/' + filename
        require(path in support['paths'] and records[path]['type'] == 'file'
                and records[path]['mode'] == '0555' and records[path]['sha256'] == digest)
    require(records[HELPER]['sha256'] == app['records'][HELPER_SOURCE]['sha256'], 'pin_mismatch')
    for path in (APP + '/server/.venv/bin/python', EXPORTER + '/venv/bin/python'):
        require(resolve(path, records) == 'usr/bin/python3.13', 'invalid_candidate')
    require(all(path in records for path in review['files'] + review['roots']))
    require(all(path in records or path in absent for path in review['search_paths']))
    native_prefixes = ('usr/lib/python3.13/', 'usr/lib/python3/dist-packages/',
                       APP + '/', EXPORTER + '/')
    native_roots = {'usr/bin/python3.13'} | {
        path for path, record in records.items()
        if path.startswith(native_prefixes) and path.endswith('.so') and record['type'] == 'file'}
    require(native_roots <= set(review['roots']), 'invalid_candidate')
    return app, exporter, support, records


def check_venv(tree, prefix, version):
    raw = tree.read(prefix + '/pyvenv.cfg', 0o644, 4096)
    expected = ('home = /usr/bin\ninclude-system-site-packages = false\nversion = ' + version +
                '\nexecutable = /usr/bin/python3.13\n').encode()
    require(raw == expected, 'invalid_candidate')


def _unit_entries(fd, budget):
    """Stop at budget + 1 before materializing an unbounded directory listing."""
    result = set()
    with os.scandir(fd) as entries:
        for entry in entries:
            require(len(result) < budget and entry.name not in result, 'invalid_candidate')
            result.add(entry.name)
    return result


def check_unit_files(tree):
    """Closed files only; does not query PID1 or admit a live helper/IPC caller."""
    for unit, digest in UNIT_TEMPLATES.items():
        require(sha(tree.read(UNIT_VENDOR_DIR + '/' + unit, 0o644, 16384)) == digest, 'invalid_candidate')
    for path in UNIT_ABSENT:
        require(tree.absent(path), 'invalid_candidate')
    # The pinned factory base is usr-merged. A legacy split /lib would create an
    # additional lookup root; accept only absence or the identical usr/lib alias.
    if not tree.absent('lib'):
        record = actual_record(tree, 'lib')
        require(record['type'] == 'symlink' and record['target'] in {'usr/lib', '/usr/lib'}, 'invalid_candidate')
    # Catch alternate names and enable/dependency links to a closed unit. Do not
    # follow symlinks or execute/parse unrelated unit payloads. The inventory is
    # bounded, including attached/generated/control roots and nested target wants.
    count = 0
    for base in UNIT_LOOKUP_DIRS:
        if tree.absent(base): continue
        pending = [(base, 0)]
        while pending:
            directory, depth = pending.pop()
            require(depth <= UNIT_SCAN_DEPTH, 'invalid_candidate')
            parent, leaf = tree.parent(directory)
            try:
                fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            finally: os.close(parent)
            try:
                tree.directory_fd(fd)
                before = os.fstat(fd)
                entries = _unit_entries(fd, UNIT_SCAN_LIMIT - count)
                count += len(entries)
                for entry in entries:
                    path = directory + '/' + entry
                    info = os.stat(entry, dir_fd=fd, follow_symlinks=False)
                    if entry in UNIT_TEMPLATES:
                        require(directory == UNIT_VENDOR_DIR and stat.S_ISREG(info.st_mode), 'invalid_candidate')
                    if stat.S_ISDIR(info.st_mode):
                        pending.append((path, depth + 1))
                    elif stat.S_ISLNK(info.st_mode):
                        # systemd follows extension directory links. Refuse such
                        # links even for unrelated units instead of following an
                        # unchecked parent that could hide incoming dependencies.
                        require(not entry.endswith(('.d', '.wants', '.requires', '.upholds')), 'invalid_candidate')
                        target = os.readlink(entry, dir_fd=fd)
                        require(stamp(os.stat(entry, dir_fd=fd, follow_symlinks=False)) == stamp(info), 'invalid_candidate')
                        require(PurePosixPath(target).name not in UNIT_TEMPLATES, 'invalid_candidate')
                require(_unit_entries(fd, len(entries)) == entries
                        and stamp(os.fstat(fd)) == stamp(before), 'invalid_candidate')
            finally: os.close(fd)


@boundary('invalid_candidate')
def verify_candidate(contract):
    require((os.geteuid(), os.getegid()) == (contract._uid, contract._gid), 'wrong_identity')
    app, exporter, support, records = inventories(contract)
    with contract.tree() as tree:
        check_unit_files(tree)
        for prefix, bundle in ((APP, app), (EXPORTER, exporter)):
            check_tree(tree, prefix, bundle['records'], {'manifest.json'})
        for prefix, values in support['trees'].items(): check_tree(tree, prefix, values)
        for path in support['paths']: check_path(tree, path, records)
        for path in support['absent']: require(tree.absent(path), 'invalid_candidate')
        check_venv(tree, APP + '/server/.venv', support['python_version'])
        check_venv(tree, EXPORTER + '/venv', support['python_version'])
    unchanged(contract)


def identity_snapshot():
    names = ('spi', 'i2c', 'gpio', 'inky-provisioning')
    groups = grp.getgrall(); require(len(groups) <= 4096, 'wrong_identity')
    named = {}
    for name in names:
        values = [group.gr_gid for group in groups if group.gr_name == name]
        require(len(values) == 1 and grp.getgrnam(name).gr_gid == values[0]
                and grp.getgrgid(values[0]).gr_name == name, 'wrong_identity')
        named[name] = values[0]
    return {'uids': list(os.getresuid()) if hasattr(os, 'getresuid') else [os.getuid(), os.geteuid()],
            'gids': list(os.getresgid()) if hasattr(os, 'getresgid') else [os.getgid(), os.getegid()],
            'groups': os.getgroups(), 'named_groups': named}


def check_identity(contract, role, identity):
    require(role in {'main', 'helper', 'ipc'}, 'unsupported_role')
    value = identity_snapshot() if identity is None else identity
    require(identity is None or contract._root != Path('/'), 'wrong_identity')
    require(type(value) is dict and set(value) == {'uids', 'gids', 'groups', 'named_groups'}, 'wrong_identity')
    named = value['named_groups']; provisioning = contract.manifest['provisioning_gid']
    require(type(named) is dict and set(named) == {'spi', 'i2c', 'gpio', 'inky-provisioning'}
            and all(type(gid) is int and 1 <= gid <= 999 for gid in named.values())
            and len(set(named.values())) == 4 and named['inky-provisioning'] == provisioning, 'wrong_identity')
    uid, gid = ((1000, 1000) if role == 'main' else
                (contract.manifest['helper_uid'], provisioning) if role == 'helper' else (0, provisioning))
    for key, expected in (('uids', uid), ('gids', gid)):
        require(type(value[key]) is list and 2 <= len(value[key]) <= 3
                and all(type(item) is int and item == expected for item in value[key]), 'wrong_identity')
    require(type(value['groups']) is list and all(type(item) is int and item >= 0 for item in value['groups']), 'wrong_identity')
    actual = set(value['groups']) - {gid}
    expected = set(named.values()) if role == 'main' else set() if role == 'helper' else {0}
    require(actual == expected, 'wrong_identity')


@boundary('invalid_candidate')
def verify_role(contract, role, *, _identity=None):
    check_identity(contract, role, _identity)
    app, exporter, support, records = inventories(contract)
    with contract.tree() as tree:
        check_path(tree, 'usr/bin/python3', records)
        if role == 'main':
            check_tree(tree, APP, app['records'], {'manifest.json'})
            check_venv(tree, APP + '/server/.venv', support['python_version'])
        else:
            check_path(tree, HELPER if role == 'helper' else IPC, records)
            if role == 'helper': check_path(tree, APP + '/' + HELPER_SOURCE, records)
            else: check_path(tree, RECEIPT, records)
    unchanged(contract)
