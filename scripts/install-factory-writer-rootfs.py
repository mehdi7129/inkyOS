#!/usr/bin/env python3
"""Materialize the closed inactive writer mapping in a new offline workspace.

No overwrite, normalization, service action, target import, permission grant or
rollback. Failure retains exclusive creations; use a new workspace, not retry.
"""
import argparse
import importlib.util
import os
from pathlib import Path, PurePosixPath
import sys

_spec = importlib.util.spec_from_file_location(
    '_writer_file_verification', Path(__file__).with_name('verify-factory-writer-rootfs.py'))
verification = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verification)
Refused, require, guards = verification.Refused, verification.require, verification.guards


def _create_parent(environment, path):
    """Create only absent parents; preserve every pre-existing inode/mode."""
    current, relative = environment.root.fd, ''
    for part in path.split('/'):
        relative = part if not relative else relative + '/' + part
        environment.check()
        fd = environment.directory(relative, missing=True)
        if fd is None:
            fd = guards._mkdir(environment.rootfs, current, part)
            held = guards._FdDirectory(environment.rootfs, fd, current, part)
            environment.directories.append(held)
            environment.root_dirs[relative] = held
        current = fd
    environment.check()
    return current


def install_writer(rootfs, input_manifest, input_sha256, sources_dir, bundle_manifest, *, receipt_output):
    environment = None
    try:
        environment = verification.Environment(rootfs, input_manifest, sources_dir,
                                               bundle_manifest, receipt_output)
        value, payload = verification._load_payload(environment, input_sha256)
        verification._preflight(environment, payload, installing=True)
        # The complete read/creation plan is rechecked before the first write.
        require(verification._load_payload(environment, input_sha256) == (value, payload),
                'inputs_changed')
        verification._preflight(environment, payload, installing=True)
        for path, (raw, mode) in sorted(payload.items()):
            parent, name = str(PurePosixPath(path).parent), PurePosixPath(path).name
            fd = _create_parent(environment, parent)
            environment.check()
            guards._write_file(environment.rootfs, fd, name, raw, mode)
        verification._verify_files(environment, payload)
        require(verification._load_payload(environment, input_sha256) == (value, payload),
                'inputs_changed')
        environment.check()
        receipt = verification._receipt(value, input_sha256, payload, 'install')
        raw = verification.canonical(receipt)
        guards._write_file(environment.rootfs, environment.receipt.fd,
                           environment.receipt_name, raw, '0600')
        require(guards._read_file(environment.rootfs, environment.receipt.fd,
                                  environment.receipt_name, verification.LIMIT) == raw,
                'receipt_readback_failed')
        environment.check()
        return receipt
    except Refused:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError, RuntimeError):
        raise Refused('installation_failed') from None
    finally:
        if environment is not None:
            environment.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-sha256', required=True)
    for field in ('rootfs', 'input-manifest', 'sources-dir', 'bundle-manifest', 'receipt'):
        parser.add_argument('--' + field, type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        install_writer(args.rootfs, args.input_manifest, args.input_sha256,
                       args.sources_dir, args.bundle_manifest, receipt_output=args.receipt)
    except Refused as error:
        print('factory_writer_install_refused:' + error.reason, file=sys.stderr)
        return 1
    print('Writer files materialized and read back; no service was started or enabled.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
