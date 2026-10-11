#!/usr/bin/python3
"""Closed writer roles; invoke with system Python -I -B -S. Never activates a unit."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

REFUSAL_EXIT = 78
RUNTIME_PATH = '/usr/lib/inkyos/factory-runtime-contract.py'
LAUNCHER_PATH = '/usr/lib/inkyos/writer-launcher.py'
MANIFEST_PATH = '/etc/inkyos/factory-runtime-v1.json'
ARGV = {
    'main': ('/usr/lib/inky-studio/server/.venv/bin/python', '-I', '-B', '-m', 'inky_web.main'),
    'helper': ('/usr/bin/python3', '-I', '-B', '/usr/local/lib/inky-studio/network-helper.py'),
    'ipc': ('/usr/bin/python3', '-I', '-B', '/usr/local/lib/inkyos/initialization-server.py'),
}
runtime = None  # Tests inject a trusted host module only with a synthetic Contract.


class Refused(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def require(value, reason):
    if not value: raise Refused(reason)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'invalid_contract'); result[key] = value
    return result


def bootstrap_read(path, mode, limit):
    """Only fixed public root files, before executing the shared contract module."""
    require(callable(getattr(os, 'listxattr', None)), 'invalid_metadata')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in Path(path).parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent); parent = child
            info = os.fstat(parent)
            require((info.st_uid, info.st_gid) == (0, 0) and not stat.S_IMODE(info.st_mode) & 0o7022
                    and not os.listxattr(parent), 'invalid_metadata')
        leaf = Path(path).name
        before = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and (before.st_uid, before.st_gid) == (0, 0)
                and stat.S_IMODE(before.st_mode) == mode and 0 <= before.st_size <= limit, 'invalid_metadata')
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            require(os.fstat(fd) == before and not os.listxattr(fd), 'invalid_metadata')
            raw = os.read(fd, limit + 1)
            after = os.fstat(fd)
            stable = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                                   info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            require(len(raw) == before.st_size and stable(before) == stable(after)
                    == stable(os.stat(leaf, dir_fd=parent, follow_symlinks=False)), 'invalid_metadata')
            return raw
        finally: os.close(fd)
    finally: os.close(parent)


def installed_runtime():
    require(Path(__file__) == Path(LAUNCHER_PATH), 'not_installed')
    manifest = json.loads(bootstrap_read(MANIFEST_PATH, 0o644, 16384), object_pairs_hook=unique)
    require(type(manifest) is dict and type(manifest.get('os_module_pins')) is dict, 'invalid_contract')
    raw = bootstrap_read(RUNTIME_PATH, 0o555, 1024 * 1024)
    for path, payload in ((RUNTIME_PATH, raw), (LAUNCHER_PATH, bootstrap_read(LAUNCHER_PATH, 0o555, 1024 * 1024))):
        expected = manifest['os_module_pins'].get(Path(path).name)
        require(type(expected) is str and re.fullmatch('[0-9a-f]{64}', expected)
                and hashlib.sha256(payload).hexdigest() == expected, 'pin_mismatch')
    module = types.ModuleType('inkyos_factory_runtime_contract')
    module.__file__ = RUNTIME_PATH
    exec(compile(raw, RUNTIME_PATH, 'exec'), module.__dict__)
    return module


def environment(role, fd, context_digest, inherited):
    value = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
             'INKYOS_WRITER_LEASE_FD': str(fd), 'INKYOS_WRITER_ROLE': role,
             'INKYOS_WRITER_CONTEXT_SHA256': context_digest}
    if role in {'main', 'helper'}:
        value.update(INKY_STUDIO_FACTORY_REQUIRED='1', INKY_STUDIO_DATA_DIR='/var/lib/inky-studio')
    if role == 'main':
        value.update(INKY_STUDIO_DISPLAY_MODE='hardware', INKY_STUDIO_BLUETOOTH='1')
    if role == 'ipc' and 'NOTIFY_SOCKET' in inherited:
        notify = inherited['NOTIFY_SOCKET']
        require(type(notify) is str and len(notify) > 1 and notify[0] in {'/', '@'}
                and len(notify.encode('utf-8')) <= 107
                and not any(ord(char) < 32 or ord(char) == 127 for char in notify), 'invalid_environment')
        value['NOTIFY_SOCKET'] = notify
    return value


def launch(role, *, _contract=None, _execve=None, _identity=None, _environ=None):
    require(role in ARGV, 'unsupported_role')
    admission = None
    try:
        if _contract is None:
            require(_execve is None and _identity is None and _environ is None, 'invalid_override')
            module = installed_runtime()
            contract = module.load_contract()
        else:
            require(runtime is not None and _contract._root != Path('/'), 'invalid_override')
            module, contract = runtime, _contract
        admission = module.import_admission(contract)
        # Never use or convert an inherited FD supplied by the environment.
        with admission.writer(contract._root, _owner_uid=contract._uid, _owner_gid=contract._gid) as lease:
            module.validate_context(contract)
            before = module.context_sha256(contract)
            module.verify_role(contract, role, _identity=_identity)
            require(module.context_sha256(contract) == before, 'invalid_context')
            env = environment(role, lease.fileno(), before, os.environ if _environ is None else _environ)
            lease.check()
            require(module.context_sha256(contract) == before, 'invalid_context')
            os.set_inheritable(lease.fileno(), True)
            try:
                (os.execve if _execve is None else _execve)(ARGV[role][0], list(ARGV[role]), env)
            except OSError:
                raise Refused('exec_failed') from None
            raise Refused('exec_returned')
    except Refused:
        raise
    except Exception as error:
        # The two imported trusted modules expose only fixed reason tokens.
        reason = getattr(error, 'reason', 'contract_refused')
        if not isinstance(reason, str) or not re.fullmatch('[a-z_]{1,64}', reason): reason = 'contract_refused'
        raise Refused(reason) from None


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        require(len(args) == 1 and args[0] in ARGV, 'unsupported_role')
        launch(args[0])
    except Refused as error:
        print('writer_launch_refused:' + error.reason, file=sys.stderr)
        return REFUSAL_EXIT
    return REFUSAL_EXIT


if __name__ == '__main__':
    raise SystemExit(main())
