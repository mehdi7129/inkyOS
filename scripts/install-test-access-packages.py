#!/usr/bin/env python3
"""Install and prove the two locked TEST-only I2C packages, offline.

This is deliberately not a dependency resolver. The independent verifier checks
every changed inventory entry against the locked deb payload or parsed dpkg /
ldconfig state. No application, account, boot or network path is an exception.
"""
import argparse
import base64
import collections
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
LOCK = 'config/test-access-packages.lock.json'
STATUS = 'var/lib/dpkg/status'
CACHE = 'etc/ld.so.cache'
NAMES = ('libi2c0', 'i2c-tools')
STATE_LIMIT = 4 * 1024**2
CHECKS = ('archives_verified', 'dependencies_present', 'i2c_group_present',
          'offline_namespace', 'service_starts_denied', 'udevadm_suppressed',
          'temporary_guards_restored', 'dpkg_audit_clean', 'exact_delta_verified')
POSTINST_SHA = 'ccdffebc8160b7daaa9d75a3e77ed48adf0d8e4c35009130442f121ecba7a779'


class PackageError(ValueError):
    pass


def require(ok, message):
    if ok is not True:
        raise PackageError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def strict_json(raw):
    def pairs(rows):
        out = {}
        for key, value in rows:
            require(key not in out, 'Duplicate JSON field')
            out[key] = value
        return out
    def invalid(_):
        raise PackageError('Non-finite JSON number')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def path_name(value):
    while value.startswith('./'):
        value = value[2:]
    value = value.rstrip('/') or '.'
    require(not value.startswith('/') and '..' not in PurePosixPath(value).parts
            and '\x00' not in value and '\n' not in value, 'Unsafe archive path')
    return value


def ar_members(raw):
    require(raw.startswith(b'!<arch>\n') and len(raw) <= 1024**2, 'Invalid deb archive')
    out, pos = {}, 8
    while pos < len(raw):
        header = raw[pos:pos + 60]
        require(len(header) == 60 and header[58:] == b'`\n', 'Invalid ar header')
        name = header[:16].decode('ascii').strip().rstrip('/')
        size = int(header[48:58])
        require(name in {'debian-binary', 'control.tar.xz', 'data.tar.xz'}
                and name not in out and 0 <= size <= len(raw) - pos - 60, 'Unexpected deb member')
        out[name] = raw[pos + 60:pos + 60 + size]
        pos += 60 + size + size % 2
    require(pos == len(raw) and set(out) == {'debian-binary', 'control.tar.xz', 'data.tar.xz'}
            and out['debian-binary'] == b'2.0\n', 'Unsupported deb format')
    return out


def tar_members(raw):
    out, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:xz') as archive:
        for member in archive:
            name = path_name(member.name)
            require(name not in out and len(out) < 256 and member.uid == member.gid == 0
                    and member.mode in {0o644, 0o755, 0o777}
                    and (member.isfile() or member.isdir() or member.issym()), 'Unexpected tar entry')
            total += member.size
            require(0 <= member.size <= STATE_LIMIT and total <= STATE_LIMIT, 'Oversized deb payload')
            record = {'mode': format(member.mode, '04o'), 'uid': 0, 'gid': 0,
                      'xattrs': {'status': 'inspected', 'entries': {}}}
            data = None
            if member.isfile():
                data = archive.extractfile(member).read(STATE_LIMIT + 1)
                require(len(data) == member.size, 'Short deb member')
                record.update(type='file', size_bytes=len(data), sha256=sha(data))
            elif member.isdir():
                record.update(type='directory')
            else:
                require('/' not in member.linkname and member.linkname not in {'.', '..'}, 'Unsafe deb symlink')
                record.update(type='symlink', target=member.linkname)
            out[name] = (record, data)
    return out


def paragraphs(raw):
    require(len(raw) <= STATE_LIMIT, 'Oversized dpkg state')
    out = {}
    for paragraph in raw.decode('utf-8').strip().split('\n\n'):
        if not paragraph:
            continue
        row, key = {}, None
        for line in paragraph.splitlines():
            if line.startswith((' ', '\t')):
                require(key is not None, 'Invalid control continuation')
                row[key] += '\n' + line
            else:
                require(':' in line, 'Invalid control field')
                key, value = line.split(':', 1)
                require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]*', key) is not None,
                        'Invalid control field')
                require(key not in row, 'Duplicate control field')
                # Debian status commonly emits "Conffiles:" with no inline
                # value, followed by indented file/hash continuations.
                row[key] = value.lstrip(' \t')
        identity = (row.get('Package'), row.get('Architecture'))
        require(all(type(x) is str and x for x in identity) and identity not in out, 'Duplicate package state')
        out[identity] = row
    return out


def reviewed_packages(blobs):
    require(LOCK in blobs and len(blobs[LOCK]) <= 1024**2, 'Package lock missing')
    lock = strict_json(blobs[LOCK])
    require(type(lock.get('version')) is int and lock['version'] == 1 and lock.get('scope') == 'test-access-only'
            and lock.get('architecture') == 'arm64'
            and [p['name'] for p in lock['packages']] == list(NAMES), 'Unexpected package delta')
    result = []
    tools = {'usr/bin/' + x for x in ('ddcmon', 'decode-dimms', 'decode-edid', 'decode-vaio')}
    tools |= {'usr/sbin/' + x for x in ('i2c-stub-from-dump', 'i2cdetect', 'i2cdump', 'i2cget', 'i2cset', 'i2ctransfer')}
    tools |= {'usr/lib/udev/rules.d/60-i2c-tools.rules'}
    tools |= {'usr/share/man/man' + section + '/' + name + '.' + section + '.gz'
              for section, names in [('1', ('decode-dimms', 'decode-vaio')), ('3', ('libi2c',)),
                  ('8', ('i2c-stub-from-dump', 'i2cdetect', 'i2cdump', 'i2cget', 'i2cset', 'i2ctransfer'))]
              for name in names}
    for package in lock['packages']:
        name = package['name']
        require(package['version'] == '4.4-2' and package['architecture'] == 'arm64'
                and package['filename'] == name + '_4.4-2_arm64.deb', 'Unreviewed package version')
        raw = blobs.get('packages/' + package['filename'])
        require(type(raw) is bytes and len(raw) == package['size_bytes']
                and sha(raw) == package['sha256'], 'Package archive hash mismatch')
        members = ar_members(raw)
        control = tar_members(members['control.tar.xz'])
        payload = tar_members(members['data.tar.xz'])
        controls = {'control', 'md5sums', 'shlibs', 'symbols', 'triggers'} if name == 'libi2c0' else {'control', 'md5sums', 'postinst'}
        require(set(control) - {'.'} == controls, 'Unreviewed maintainer script set')
        rows = paragraphs(control['control'][1])
        require(len(rows) == 1 and (name, 'arm64') in rows, 'Deb control identity mismatch')
        fields = rows[(name, 'arm64')]
        require(fields['Version'] == package['version'] and fields.get('Depends', '') == package['depends'], 'Deb control differs from lock')
        if name == 'i2c-tools':
            require(sha(control['postinst'][1]) == POSTINST_SHA, 'Unreviewed i2c maintainer script')
        else:
            require(control['triggers'][1] == b'# Triggers added by dh_makeshlibs/13.24.2\nactivate-noawait ldconfig\n', 'Unreviewed library trigger')
        allowed = {'usr/share/doc/' + name + '/' + x for x in ('changelog.Debian.gz', 'changelog.gz', 'copyright')}
        allowed |= tools if name == 'i2c-tools' else {'usr/lib/aarch64-linux-gnu/libi2c.so.0', 'usr/lib/aarch64-linux-gnu/libi2c.so.0.1.1'}
        require({p for p, (r, _) in payload.items() if r['type'] != 'directory'} == allowed, 'Unexpected package payload path')
        directories = {'.'}
        for path in allowed:
            directories.update(str(parent) for parent in PurePosixPath(path).parents)
        require(set(payload) <= allowed | directories, 'Unexpected payload directory')
        result.append((package, control, payload, fields))
    return result


def unpack_state(value):
    require(type(value) is str and len(value) <= 2 * STATE_LIMIT, 'Oversized encoded package state')
    encoded = base64.b64decode(value, validate=True)
    decoder = zlib.decompressobj()
    raw = decoder.decompress(encoded, STATE_LIMIT + 1)
    require(len(raw) <= STATE_LIMIT and decoder.eof and not decoder.unused_data
            and not decoder.unconsumed_tail, 'Invalid compressed package state')
    return raw


def pack_state(raw):
    require(len(raw) <= STATE_LIMIT, 'Oversized package state')
    return base64.b64encode(zlib.compress(raw, 9)).decode('ascii')


def cache_entries(raw):
    # glibc 2.41 sysdeps/generic/dl-cache.h: new-cache 1.1, LE ARM64.
    require(len(raw) >= 48 and raw[:20] == b'glibc-ld.so.cache1.1', 'Unsupported ldconfig cache')
    count, strings = struct.unpack_from('<II', raw, 20)
    extension = struct.unpack_from('<I', raw, 32)[0]
    start, end = 48 + count * 24, 48 + count * 24 + strings
    require(count <= 10000 and end <= len(raw) and raw[28] in {0, 2}
            and raw[36:48] == bytes(12), 'Invalid ldconfig header')
    def text_at(offset):
        require(start <= offset < end, 'Invalid ldconfig string reference')
        stop = raw.find(b'\0', offset, end)
        require(stop >= offset, 'Unterminated ldconfig string')
        return raw[offset:stop].decode('ascii')
    entries = []
    for index in range(count):
        flags, key, value, osversion, hwcap = struct.unpack_from('<iIIIQ', raw, 48 + 24 * index)
        require(osversion == hwcap == 0, 'Unreviewed ldconfig hwcap metadata')
        entries.append((flags, text_at(key), text_at(value)))
    extensions = []
    if extension:
        require(extension % 4 == 0 and end <= extension <= len(raw) - 8, 'Invalid cache extension')
        magic, count = struct.unpack_from('<II', raw, extension)
        require(magic == ((-358342284) & 0xffffffff) and count <= 4
                and extension + 8 + 16 * count <= len(raw), 'Invalid cache extension directory')
        for index in range(count):
            tag, flags, offset, size = struct.unpack_from('<IIII', raw, extension + 8 + 16 * index)
            require(tag == 0 and flags == 0 and offset >= extension + 8 + 16 * count
                    and size <= 4096 and offset + size <= len(raw), 'Unreviewed cache extension')
            extensions.append((tag, flags, raw[offset:offset + size]))
    return collections.Counter(entries), extensions


def validate_report(report, parent_root, child_root, blobs):
    """Return the proved path set; caller must validate all other overlay changes."""
    require(type(report) is dict and set(report) == {'schema_version', 'scope', 'passed', 'lock_sha256',
            'packages', 'checks', 'changes', 'state_files'}, 'Unexpected package report schema')
    require(type(report['schema_version']) is int and report['schema_version'] == 1
            and report['scope'] == 'test-access-offline-package-delta'
            and report['passed'] is True and report['lock_sha256'] == sha(blobs[LOCK]), 'Invalid package report binding')
    require(type(report['checks']) is dict and set(report['checks']) == set(CHECKS)
            and all(value is True for value in report['checks'].values()), 'Incomplete package checks')
    packages = reviewed_packages(blobs)
    require(report['packages'] == [{key: p[key] for key in ('name', 'version', 'architecture', 'sha256')}
                                   for p, _, _, _ in packages], 'Package report identity mismatch')
    changes, states = report['changes'], report['state_files']
    require(type(changes) is dict and 0 < len(changes) < 128 and type(states) is dict, 'Invalid package changes')
    expected, list_paths = {}, set()
    for package, control, payload, fields in packages:
        for path, (record, _) in payload.items():
            if path in parent_root:
                require(record['type'] == 'directory' and child_root.get(path) == parent_root[path], 'Package payload collision')
            else:
                expected[path] = record
        basename = package['name'] + (':arm64' if fields.get('Multi-Arch') == 'same' else '')
        prefix = 'var/lib/dpkg/info/' + basename
        for name, (record, _) in control.items():
            if name not in {'.', 'control'}:
                expected[prefix + '.' + name] = record
        list_paths.add(prefix + '.list')
    require(set(states) == {STATUS, CACHE} | list_paths, 'Unexpected package state evidence')
    raw_states = {}
    for path, row in states.items():
        require(type(row) is dict and set(row) == {'before', 'after'}, 'Invalid package state pair')
        raw_states[path] = {}
        for side, inventory in (('before', parent_root), ('after', child_root)):
            raw = None if row[side] is None else unpack_state(row[side])
            entry = inventory.get(path)
            require((raw is None and entry is None) or (raw is not None and type(entry) is dict
                    and entry.get('type') == 'file' and entry.get('size_bytes') == len(raw)
                    and entry.get('sha256') == sha(raw)), 'State evidence does not bind inventory')
            raw_states[path][side] = raw
    old_status, new_status = (paragraphs(raw_states[STATUS][side]) for side in ('before', 'after'))
    require(not any('Triggers-Pending' in row or 'Triggers-Awaited' in row for row in new_status.values()),
            'Pending dpkg triggers')
    new_keys = {(name, 'arm64') for name in NAMES}
    require(not (set(old_status) & new_keys) and set(new_status) == set(old_status) | new_keys
            and all(new_status[key] == value for key, value in old_status.items()), 'Unrelated dpkg status change')
    for package, control, payload, fields in packages:
        require(new_status[(package['name'], 'arm64')] == dict(fields, Status='install ok installed'), 'Package not fully configured')
        for dependency in package['required_dependencies_in_base']:
            row = old_status.get((dependency['name'], dependency['architecture']), {})
            require(row.get('Status') == 'install ok installed' and row.get('Version') == dependency['version'], 'Reviewed dependency absent or changed')
        basename = package['name'] + (':arm64' if fields.get('Multi-Arch') == 'same' else '')
        path = 'var/lib/dpkg/info/' + basename + '.list'
        lines = raw_states[path]['after'].decode('utf-8').splitlines()
        require(len(lines) == len(set(lines)) and set(lines) == {'/' + p for p in payload}, 'Dpkg file list differs from deb')
        expected[path] = file_record(raw_states[path]['after'])
    old_cache, old_ext = cache_entries(raw_states[CACHE]['before'])
    new_cache, new_ext = cache_entries(raw_states[CACHE]['after'])
    additions = list((new_cache - old_cache).elements())
    require(not (old_cache - new_cache) and old_ext == new_ext and len(additions) == 1
            and additions[0][0] == 0xa03 and additions[0][1] == 'libi2c.so.0'
            and additions[0][2] in {'/lib/aarch64-linux-gnu/libi2c.so.0', '/usr/lib/aarch64-linux-gnu/libi2c.so.0'}, 'Unrelated ldconfig cache change')
    for path in (STATUS, CACHE):
        before, after = parent_root[path], child_root[path]
        require({k: v for k, v in before.items() if k not in {'sha256', 'size_bytes'}}
                == {k: v for k, v in after.items() if k not in {'sha256', 'size_bytes'}}, 'Package database metadata changed')
        expected[path] = after
    require(set(changes) == set(expected), 'Package change set differs from expected delta')
    for path, record in expected.items():
        require(type(changes[path]) is dict and set(changes[path]) == {'before', 'after'}
                and changes[path] == {'before': parent_root.get(path), 'after': child_root.get(path)}
                and child_root.get(path) == record, 'Package delta differs from filesystem inventory')
        if path not in (STATUS, CACHE):
            require(path not in parent_root, 'Package addition overwrites a parent entry')
    return set(changes)


def file_record(raw, mode='0644'):
    return {'type': 'file', 'mode': mode, 'uid': 0, 'gid': 0, 'size_bytes': len(raw), 'sha256': sha(raw),
            'xattrs': {'status': 'inspected', 'entries': {}}}


def build_report(before, after, blobs, state_before, state_after):
    packages = reviewed_packages(blobs)
    changes = {path: {'before': before.get(path), 'after': after.get(path)}
               for path in sorted(set(before) | set(after)) if before.get(path) != after.get(path)}
    report = {'schema_version': 1, 'scope': 'test-access-offline-package-delta', 'passed': True,
              'lock_sha256': sha(blobs[LOCK]), 'packages': [{k: p[k] for k in ('name', 'version', 'architecture', 'sha256')}
                 for p, _, _, _ in packages], 'checks': {key: True for key in CHECKS}, 'changes': changes,
              'state_files': {path: {side: None if states.get(path) is None else pack_state(states[path])
                   for side, states in (('before', state_before), ('after', state_after))} for path in state_after}}
    validate_report(report, before, after, blobs)
    return report


def read_regular(path, maximum=STATE_LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= maximum, 'Unexpected input file')
        raw = stream.read(maximum + 1)
        require(len(raw) == info.st_size, 'Input file changed')
        return raw


def run_dpkg(rootfs, arguments, log, timeout):
    with log.open('xb') as stream:
        os.chmod(log, 0o600)
        process = subprocess.Popen(['chroot', str(rootfs), '/usr/bin/env', '-i',
            'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL=C', 'DEBIAN_FRONTEND=noninteractive',
            '/usr/bin/dpkg', *arguments], stdin=subprocess.DEVNULL,
            stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            process.wait(timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
    require(process.returncode == 0, 'Offline dpkg command failed')


def install(rootfs, recipe, out):
    rootfs, recipe, out = map(lambda p: Path(p).absolute(), (rootfs, recipe, out))
    require(sys.platform == 'linux' and platform.machine() == 'aarch64' and os.geteuid() == 0, 'Native Linux ARM64 root required')
    require(rootfs != Path('/') and all(p.resolve() == p and p.is_dir() for p in (rootfs, recipe, out))
            and not out.is_relative_to(rootfs) and not recipe.is_relative_to(rootfs), 'Unsafe installer roots')
    interfaces = {line.split(':', 1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]}
    require(os.stat('/proc/self/ns/net').st_ino != os.stat('/proc/1/ns/net').st_ino
            and interfaces == {'lo'}, 'Private offline network namespace required')
    null = (rootfs / 'dev/null').lstat()
    require(stat.S_ISCHR(null.st_mode) and os.major(null.st_rdev) == 1 and os.minor(null.st_rdev) == 3, 'Private /dev/null bind required')
    require(any(line.split(':', 1)[0] == 'i2c' for line in read_regular(rootfs / 'etc/group').decode().splitlines()), 'Existing i2c group required')
    fetch = module('_install_package_fetch', 'fetch-test-access-packages.py')
    lock = fetch.load_lock(recipe / LOCK)
    blobs = {LOCK: read_regular(recipe / LOCK)}
    for package in lock['packages']:
        name = 'packages/' + package['filename']
        blobs[name] = read_regular(recipe / name, 1024**2)
    packages = reviewed_packages(blobs)
    state_before = {path: read_regular(rootfs / path) for path in (STATUS, CACHE)}
    installed = paragraphs(state_before[STATUS])
    require(not any(key[0] in NAMES for key in installed), 'Target packages already present')
    for package, _, _, _ in packages:
        for dependency in package['required_dependencies_in_base']:
            row = installed.get((dependency['name'], dependency['architecture']), {})
            require(row.get('Status') == 'install ok installed' and row.get('Version') == dependency['version'], 'Reviewed dependency mismatch')
    output = out / 'test-access-packages.json'
    require(not output.exists(), 'Package report already exists')
    inventory = module('_install_package_inventory', 'manifest-rootfs.py').inventory
    before = inventory(rootfs)
    # The generic input is disposable. On failure no success report is produced;
    # guards are still restored, but dpkg changes are not rolled back.
    require((rootfs / 'tmp').resolve() == rootfs / 'tmp' and (rootfs / 'tmp').is_dir(), 'Unsafe temporary directory')
    temporary = Path(tempfile.mkdtemp(prefix='inkyos-packages.', dir=rootfs / 'tmp'))
    saved = []
    def preserve(relative, replacement=None, required=False, directory=False):
        target = rootfs / relative
        require(target.parent.is_dir() and target.parent.resolve() == target.parent, 'Unsafe guard parent')
        existed = os.path.lexists(target)
        if existed:
            info = target.lstat()
            require(stat.S_ISDIR(info.st_mode) if directory else
                    stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'Unsafe guard file')
        require(existed or not required, 'Required guard file absent')
        backup = temporary / ('saved-' + str(len(saved)))
        if existed:
            target.rename(backup)
        saved.append((target, backup, existed, directory))
        if directory:
            require(existed, 'Expected man-db cache directory absent')
            target.mkdir(mode=stat.S_IMODE(info.st_mode))
            os.chmod(target, stat.S_IMODE(info.st_mode))
            os.chown(target, info.st_uid, info.st_gid)
        if replacement is not None:
            target.write_bytes(replacement)
            target.chmod(0o755)
    try:
        preserve('usr/bin/udevadm', b'#!/bin/sh\nexit 0\n', required=True)
        preserve('usr/sbin/policy-rc.d', b'#!/bin/sh\nexit 101\n')
        for path in ('var/lib/dpkg/status-old', 'var/log/dpkg.log', 'var/cache/ldconfig/aux-cache'):
            preserve(path)
        preserve('var/cache/man', required=True, directory=True)
        archives = []
        for package, _, _, _ in packages:
            target = temporary / package['filename']
            target.write_bytes(blobs['packages/' + package['filename']])
            target.chmod(0o600)
            archives.append('/' + str(target.relative_to(rootfs)))
        log = out / 'test-access-packages-install.log'
        run_dpkg(rootfs, ['--install', *archives], log, 180)
        audit_log = out / 'test-access-packages-audit.log'
        run_dpkg(rootfs, ['--audit'], audit_log, 30)
        require(read_regular(audit_log) == b'', 'Dpkg audit is not empty')
    finally:
        restoration_errors = []
        for target, backup, existed, directory in reversed(saved):
            try:
                if os.path.lexists(target):
                    if directory:
                        require(stat.S_ISDIR(target.lstat().st_mode), 'Guard directory changed type')
                        shutil.rmtree(target)
                    else:
                        require(stat.S_ISREG(target.lstat().st_mode), 'Guard replacement changed type')
                        target.unlink()
                if existed:
                    backup.rename(target)
            except (OSError, PackageError) as error:
                restoration_errors.append(error)
        require(not restoration_errors, 'Guard restoration failed; preserve disposable build root')
        shutil.rmtree(temporary)
    after = inventory(rootfs)
    state_after = {path: read_regular(rootfs / path) for path in (STATUS, CACHE)}
    for package, _, _, fields in packages:
        basename = package['name'] + (':arm64' if fields.get('Multi-Arch') == 'same' else '')
        path = 'var/lib/dpkg/info/' + basename + '.list'
        state_after[path] = read_regular(rootfs / path)
    report = build_report(before, after, blobs, state_before, state_after)
    with output.open('x') as stream:
        os.chmod(output, 0o600)
        json.dump(report, stream, sort_keys=True, separators=(',', ':'))
        stream.write('\n')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--recipe-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = install(args.rootfs, args.recipe_dir, args.output_dir)
        print(json.dumps({'passed': True, 'packages': 2, 'changed_entries': len(report['changes'])}))
        return 0
    except (PackageError, OSError, ValueError, KeyError, subprocess.SubprocessError):
        print('TEST package installation refused; inspect the private build log', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
