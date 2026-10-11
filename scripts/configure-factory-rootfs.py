#!/usr/bin/env python3
"""Create a passive factory layout in a private, offline rootfs.

All source and rootfs checks finish before exclusive creation begins. Existing
files are never replaced, and existing directories are never chmod/chowned.
An I/O failure can leave a partial layout. Existing reserved files or permission
state make retries refuse; empty ancestor directories alone can still be reused.
No target code, service, interpreter or system command is executed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('factory_layout_verification', ROOT / 'verify-factory-rootfs.py')
verification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verification)


def sources(source, uid, gid):
    with verification.tree(source, uid, gid) as tree:
        result = {name: tree.bytes('scripts/' + name)
                  for name in verification.MODULE_PINS}
    verification.require(all(hashlib.sha256(raw).hexdigest() == verification.MODULE_PINS[name]
                             for name, raw in result.items()))
    return result


def ownership(fd, uid, gid):
    info = os.fstat(fd)
    if (info.st_uid, info.st_gid) != (uid, gid):
        os.fchown(fd, uid, gid)


def make_directory(tree, path, uid, gid, mode):
    tree.parents(path)
    parent, name = tree._parent(path)
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            ownership(fd, uid, gid)
            os.fchmod(fd, mode)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def create_file(tree, path, raw, mode):
    tree.parents(path)
    parent, name = tree._parent(path)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        ownership(fd, tree.uid, tree.gid)
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            verification.require(count > 0)
            view = view[count:]
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def configure(rootfs, source, *, _owner_uid=0, _owner_gid=0, _app_uid=1000, _app_gid=1000):
    options = dict(_owner_uid=_owner_uid, _owner_gid=_owner_gid,
                   _app_uid=_app_uid, _app_gid=_app_gid)
    payloads = sources(source, _owner_uid, _owner_gid)
    verification.preflight(rootfs, **options)
    files = {verification.MODULE_DIR + '/' + name: (raw, 0o555)
             for name, raw in payloads.items()}
    files.update({verification.MARKER: (verification.canonical(verification.MARKER_VALUE), 0o644),
                  verification.PERMISSION + '/lock': (b'', 0o600),
                  verification.PERMISSION + '/pending.json':
                      (verification.canonical(verification.PERMISSION_VALUE), 0o600)})
    masks = ['etc/systemd/system/' + name for name in verification.MASKS]
    directories = {verification.DATA}
    for path in (*files, *masks, verification.DATA):
        directories.update(str(parent) for parent in PurePosixPath(path).parents if str(parent) != '.')
    private = {verification.DATA, verification.PERMISSION, 'var/lib/inkyos', verification.MODULE_DIR}
    with verification.tree(rootfs, _owner_uid, _owner_gid) as tree:
        # Finish the entire creation plan before the first mutation.
        missing = sorted((path for path in directories if tree.absent(path)), key=lambda path: (path.count('/'), path))
        new_masks = [path for path in masks if tree.absent(path)]
        verification.require(all(tree.absent(path) for path in files))
        for path in missing:
            uid, gid = (_app_uid, _app_gid) if path == verification.DATA else (_owner_uid, _owner_gid)
            make_directory(tree, path, uid, gid, 0o700 if path in private else 0o755)
        for path, (raw, mode) in files.items():
            create_file(tree, path, raw, mode)
        for path in new_masks:
            tree.parents(path)
            parent, name = tree._parent(path)
            try:
                os.symlink('/dev/null', name, dir_fd=parent)
                os.chown(name, _owner_uid, _owner_gid, dir_fd=parent, follow_symlinks=False)
            finally:
                os.close(parent)
    return verification.verify(rootfs, **options)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True, help='Trusted source checkout, with scripts/ beneath it')
    args = parser.parse_args(argv)
    try:
        verification.require(os.geteuid() == 0)
        result = configure(args.rootfs, args.source)
    except (OSError, ValueError, TypeError):
        result = {'schema_version': 1, 'scope': 'offline-factory-layout', 'passed': False,
                  'error': 'factory_layout_refused_or_incomplete', 'image_code_executed': False,
                  'secret_values_included': False, 'limitations': verification.LIMITATIONS.copy()}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
