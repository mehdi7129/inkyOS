#!/usr/bin/env python3
"""Prepare private operator-signed data locally; never install it or connect.

The context must come from a separately verified enrollment return and the
reviewed access-runtime manifest. This tool does not establish that provenance.
No secret is accepted on the command line. Files, including failed attempts,
remain in the new private output directory; it is never copied to an SD here.
"""
import sys
sys.dont_write_bytecode = True

import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess


SOURCE = Path(__file__).resolve().with_name('test-access-contract.py')
SPEC = importlib.util.spec_from_file_location('_inkyos_access_capsule_contract', SOURCE)
contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract)


class PreparationError(ValueError):
    pass


def require(value):
    if value is not True:
        raise PreparationError('private_input_refused')


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def private_parent(path):
    """Open the complete directory chain without following symlinks."""
    path = Path(path).absolute()
    require('..' not in path.parts and len(path.parts) > 1)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, part in enumerate(path.parts[1:]):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            require(info.st_uid in {0, os.geteuid()})
            # A root-owned sticky temporary ancestor is safe for fixtures;
            # the leaf itself must still be operator-owned and private.
            require(not info.st_mode & 0o022 or
                    info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX))
            if index == len(path.parts) - 2:
                require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
        return fd
    except BaseException:
        os.close(fd)
        raise


def metadata(info, limit):
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600
            and 0 < info.st_size <= limit)


def read_private(path, *, limit=4096):
    path = Path(path).absolute()
    parent = private_parent(path.parent)
    fd = None
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        metadata(before, limit)
        raw = bytearray()
        while len(raw) <= limit:
            block = os.read(fd, min(4096, limit + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        require(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd))
                == stamp(os.stat(path.name, dir_fd=parent, follow_symlinks=False)))
        return bytes(raw)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def inspect_key(path):
    # Only metadata is read here. ssh-keygen alone opens the signing key.
    path = Path(path).absolute()
    parent = private_parent(path.parent)
    try:
        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        metadata(info, 16384)
        return stamp(info)
    finally:
        os.close(parent)


def strict_json(raw):
    def pairs(items):
        value = {}
        for name, item in items:
            require(name not in value)
            value[name] = item
        return value
    def invalid(_value):
        raise PreparationError('private_input_refused')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                      parse_float=invalid, parse_constant=invalid)


def capsule(context, network):
    require(type(context) is dict and set(context) == {
        'schema_version', 'kind', 'bindings', 'operator_public_key'})
    require(type(context['schema_version']) is int and context['schema_version'] == 1
            and context['kind'] == 'verified-test-access-context'
            and type(context['bindings']) is dict)
    require(type(network) is dict and set(network) == {'ssid', 'psk'}
            and type(network['ssid']) is str and type(network['psk']) is str)
    expected = context['bindings']
    value = {'schema_version': 1, 'kind': 'test-access-capsule',
        'purpose': 'operator-ssh-only', 'nonce': expected.get('challenge'),
        'profile_sha256': expected.get('profile_sha256'),
        'host_public_key_sha256': expected.get('host_public_key_sha256'),
        'application_source_commit': expected.get('application_source_commit'),
        'application_manifest_sha256': expected.get('application_manifest_sha256'),
        'access_runtime_manifest_sha256': expected.get('access_runtime_manifest_sha256'),
        'country': 'FR', 'wifi': {'security': 'wpa2-personal', 'band': '2.4GHz',
            'ssid_hex': network['ssid'].encode('utf-8').hex(), 'psk': network['psk']}}
    raw = contract.canonical(value)
    contract.parse_capsule(raw, expected=expected)
    return raw


def write_new(directory, name, raw):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            require(count > 0)
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)


def prepare(context_path, network_path, key_path, output):
    result = {'schema_version': 1, 'kind': 'test-access-capsule-preparation',
        'private_artifact': True, 'prepared': False, 'operator_signature_verified': False,
        'context_provenance_verified': False, 'copied_to_sd': False,
        'connection_authorized': False, 'application_activation_authorized': False,
        'hardware_qualified': False, 'release_qualified': False, 'error': None}
    parent = directory = None
    stage = 'private_inputs'
    try:
        require(os.geteuid() != 0)
        context = strict_json(read_private(context_path))
        network = strict_json(read_private(network_path))
        raw = capsule(context, network)
        key_path = Path(key_path).absolute()
        before = inspect_key(key_path)
        stage = 'new_private_output'
        output = Path(output).absolute()
        parent = private_parent(output.parent)
        os.mkdir(output.name, 0o700, dir_fd=parent)
        directory = private_parent(output)
        write_new(directory, 'INKYACC.JSN', raw)
        stage = 'operator_signature'
        signed = subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-f', str(key_path),
            '-n', contract.NAMESPACE, str(output / 'INKYACC.JSN')],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'SSH_ASKPASS_REQUIRE': 'never'},
            start_new_session=True, timeout=10)
        require(signed.returncode == 0 and inspect_key(key_path) == before)
        # ssh-keygen may use 0644 for a new detached signature; it contains no
        # secret but must meet the private artifact contract before ingestion.
        fd = os.open('INKYACC.JSN.sig', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                    and 0 < info.st_size <= contract.MAX_SIGNATURE)
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        signature = read_private(output / 'INKYACC.JSN.sig', limit=contract.MAX_SIGNATURE)
        stage = 'signature_verification'
        verified = contract.verify_capsule(raw, signature, expected=context['bindings'],
                                           operator_public_key=context['operator_public_key'])
        require(verified.get('passed') is True and verified.get('operator_data_authenticated') is True)
        require(read_private(output / 'INKYACC.JSN') == raw and inspect_key(key_path) == before)
        write_new(directory, 'INKYACC.SIG', signature)
        # Preserve the signer output too. No cleanup of user files is implicit.
        # This receipt describes authentication only, not successful durable
        # preparation. A subsequent filesystem failure cannot contradict it.
        stage = 'private_evidence'
        write_new(directory, 'signature-verification.json', contract.canonical(verified))
        os.fsync(directory)
        os.fsync(parent)
        result.update(prepared=True, operator_signature_verified=True)
    except (Exception, KeyboardInterrupt):
        result.update(prepared=False, operator_signature_verified=False, error=stage + '_refused')
    finally:
        if directory is not None:
            os.close(directory)
        if parent is not None:
            os.close(parent)
    return result


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise PreparationError('invalid_arguments')


def main(argv=None):
    try:
        parser = Parser(description=__doc__, allow_abbrev=False)
        parser.add_argument('--context', required=True, type=Path)
        parser.add_argument('--network', required=True, type=Path)
        parser.add_argument('--operator-key', required=True, type=Path)
        parser.add_argument('--output', required=True, type=Path)
        args = parser.parse_args(argv)
    except PreparationError:
        print('{"error":"invalid_arguments","prepared":false}')
        return 64
    result = prepare(args.context, args.network, args.operator_key, args.output)
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0 if result['prepared'] else 1


if __name__ == '__main__':
    sys.exit(main())
