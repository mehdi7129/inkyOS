#!/usr/bin/env python3
"""Prepare a bounded Studio update on a private ext4 COPY, never on a device.

Inputs are pinned artifacts and a native, read-only whole-SD acquisition.
No target program, network request, mount, user-state migration, or SD write.
Python 3.9 compatible. All generated artifacts remain in a private workspace.
"""
import argparse
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import time
import zipfile

BASE = 'b75bf1e7d0ab0a50d14f01527994fc17a3f62e42'
TARGET = '716104b130d34d1973001e78f15e25989d4c2e76'
STUDIO = '/usr/lib/inky-studio'
SITE = 'server/.venv/lib/python3.13/site-packages/'
MEMBERS = {'inky_web/main.py', 'inky_web/photo_access.py', 'inky_web/api/photo_access.py'}
DEBUGFS = Path('/opt/homebrew/opt/e2fsprogs/sbin/debugfs')
FSCK = Path('/opt/homebrew/opt/e2fsprogs/sbin/e2fsck')
TOOL_PINS = {
    'debugfs': '814284f7a5147a0286983fbc1dd64f3969826e5501b03f3fc05225f45287f2c9',
    'e2fsck': 'a14c5f8efe8ccf099e6048efbd5f8aabf3938676b55457e4462b3a6e7461bf9e',
}
SHA = re.compile(r'[0-9a-f]{64}\Z')
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'}
MAX_FILE = 8 * 1024 * 1024
FACTORY = {'/etc/inky-studio/factory-v1.json', '/etc/inkyos/factory-runtime-v1.json',
           '/var/lib/inkyos-factory', '/etc/inkyos-test-enrollment', '/var/lib/inkyos-test-access',
           '/usr/lib/inkyos/factory-main.py'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON key')
            result[key] = value
        return result
    def invalid(_):
        raise ValueError('Non-finite JSON value')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def stamp(path):
    value = Path(path).lstat()
    return tuple(getattr(value, 'st_' + name) for name in
                 ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime_ns', 'ctime_ns'))


def checked_path(path):
    path = Path(path)
    require(path.is_absolute() and str(path) == os.path.abspath(str(path)) and
            not str(path).startswith('/dev/'), 'An absolute regular-file path is required')
    for part in (*reversed(path.parents), path):
        require(not part.is_symlink(), 'Host symlink refused')
    return path


def regular(path, maximum=None, writable=False, public=False):
    path = checked_path(path)
    value = path.lstat()
    require(stat.S_ISREG(value.st_mode) and value.st_uid == os.getuid() and
            value.st_nlink == 1 and stat.S_IMODE(value.st_mode) in
            ((0o600,) if writable else ((0o400, 0o600, 0o644) if public else (0o400, 0o600))),
            'Private owned regular file required')
    require(value.st_size > 0 and (maximum is None or value.st_size <= maximum), 'Input size refused')
    return path


def private_directory(path):
    path = checked_path(path)
    value = path.lstat()
    require(stat.S_ISDIR(value.st_mode) and value.st_uid == os.getuid() and
            stat.S_IMODE(value.st_mode) == 0o700, 'Private owned workspace700 required')
    return path


def read_private(path, maximum=MAX_FILE, public=False):
    path = regular(path, maximum, public=public)
    before = stamp(path)
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) == before[6] and stamp(path) == before, 'Input changed during read')
    return raw


def read_pinned(path, expected, maximum=MAX_FILE, public=False):
    require(type(expected) is str and SHA.fullmatch(expected), 'An explicit SHA256 pin is required')
    raw = read_private(path, maximum, public=public)
    require(sha(raw) == expected, 'Artifact SHA256 differs')
    return raw


def write_private(path, raw):
    path = Path(path)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def hash_file(path):
    path = regular(path)
    before = stamp(path)
    value = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(4 * 1024 * 1024), b''):
            value.update(block)
    require(stamp(path) == before, 'File changed while hashing')
    return value.hexdigest()


def geometry(mbr, capacity):
    require(type(capacity) is int and capacity > 0 and capacity % 512 == 0 and
            len(mbr) == 512 and mbr[510:] == b'\x55\xaa', 'Invalid MBR/capacity')
    parts = []
    for index in range(4):
        raw = mbr[446 + index * 16:462 + index * 16]
        flag, kind = raw[0], raw[4]
        start, count = struct.unpack_from('<II', raw, 8)
        if index > 1:
            require(raw == bytes(16), 'Only the two reviewed MBR partitions are supported')
            continue
        require(flag in (0, 0x80) and kind in ((0x0b, 0x0c) if index == 0 else (0x83,)) and
                start > 0 and count > 0, 'Unexpected partition layout')
        offset, length = start * 512, count * 512
        require(offset + length <= capacity, 'Partition exceeds the acquired medium')
        parts.append((offset, length))
    require(parts[0][0] + parts[0][1] <= parts[1][0], 'Overlapping partitions')
    return {'capacity': capacity, 'bootOffset': parts[0][0], 'bootBytes': parts[0][1],
            'rootOffset': parts[1][0], 'rootBytes': parts[1][1]}


def backup_hashes(path, geo):
    result = {'mbrSHA256': None}
    whole = hashlib.sha256()
    with regular(path).open('rb') as source:
        result['mbrSHA256'] = sha(source.read(512))
        source.seek(0)
        segments = [('prefixSHA256', geo['rootOffset']), ('rootSHA256', geo['rootBytes']),
                    ('suffixSHA256', geo['capacity'] - geo['rootOffset'] - geo['rootBytes'])]
        for name, count in segments:
            digest = hashlib.sha256()
            while count:
                raw = source.read(min(count, 4 * 1024 * 1024))
                require(raw, 'Acquisition ended early')
                digest.update(raw); whole.update(raw); count -= len(raw)
            result[name] = digest.hexdigest()
        require(not source.read(1), 'Acquisition has trailing bytes')
    result['wholeSHA256'] = whole.hexdigest()
    return result


def load_acquisition(workspace, receipt_path, receipt_sha):
    raw = read_pinned(receipt_path, receipt_sha)
    receipt = strict_json(raw)
    require(receipt.get('schemaVersion') == 1 and receipt.get('kind') == 'inkyos-maintenance-acquisition' and
            receipt.get('status') == 'complete' and receipt.get('localReadbackVerified') is True and
            receipt.get('rawOpenedReadOnly') is True and receipt.get('sdWritesIssued') is False,
            'A verified read-only acquisition is required')
    name = receipt.get('backupFile')
    require(type(name) is str and Path(name).name == name and name not in ('', '.', '..'), 'Backup leaf refused')
    backup = regular(workspace / name)
    before = stamp(backup)
    with backup.open('rb') as stream:
        geo = geometry(stream.read(512), before[6])
    require(receipt.get('geometry') == geo and receipt.get('target', {}).get('capacity') == geo['capacity'],
            'Acquisition geometry differs')
    observed = backup_hashes(backup, geo)
    require(receipt.get('hashes') == observed and stamp(backup) == before, 'Acquisition hashes differ')
    return receipt, backup, geo, before


def record_digest(raw):
    return 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b'=').decode()


def csv_rows(raw):
    text = raw.decode('utf-8')
    lines = text.splitlines(keepends=True)
    reader = csv.reader(iter(lines), strict=True)
    records, used, seen = [], 0, set()
    for row in reader:
        require(len(row) == 3 and row[0] and row[0] not in seen, 'Invalid or duplicate RECORD row')
        seen.add(row[0])
        chunk = ''.join(lines[used:reader.line_num]).encode('utf-8')
        records.append((row, chunk)); used = reader.line_num
    require(used == len(lines), 'Unparsed RECORD content')
    return records


def update_record(raw, modules):
    replacements = {item['wheel_member']: item for item in modules}
    remaining = set(replacements)
    output = []
    for row, chunk in csv_rows(raw):
        item = replacements.get(row[0])
        if item is None:
            output.append(chunk)
            continue
        require(row == item['wheel_RECORD_before'], 'Installed RECORD old row differs')
        require(row[0] in remaining, 'Duplicate target RECORD row')
        remaining.remove(row[0])
        newline = '\r\n' if chunk.endswith(b'\r\n') else ('\n' if chunk.endswith(b'\n') else '')
        stream = io.StringIO(newline='')
        csv.writer(stream, lineterminator=newline).writerow(item['wheel_RECORD_after'])
        output.append(stream.getvalue().encode('utf-8'))
    require(not remaining, 'Missing installed RECORD target row')
    return b''.join(output)


def load_package(manifest_path, manifest_sha, wheel_path, wheel_sha, reference_path, reference_sha):
    manifest = strict_json(read_pinned(manifest_path, manifest_sha, public=True))
    reference = strict_json(read_pinned(reference_path, reference_sha, public=True))
    require(manifest.get('base_commit') == BASE and manifest.get('source_commit') == TARGET and
            manifest.get('database_schema_version') == 1 and manifest.get('database_migration') is False and
            reference.get('studio_commit') == BASE and type(reference.get('records')) is dict,
            'Unsupported backend baseline or migration')
    policy = manifest.get('installed_RECORD_policy', {})
    require(policy.get('replace_installed_RECORD_with_wheel_RECORD') is False and
            policy.get('require_observed_three_old_module_hashes_before_change') is True and
            policy.get('update_only_existing_three_module_rows_to_new_sha256_and_size') is True and
            policy.get('preserve_all_other_local_rows_and_extras') is True, 'RECORD policy differs')
    modules = manifest.get('modules')
    require(type(modules) is list and len(modules) == 3 and
            {item.get('wheel_member') for item in modules} == MEMBERS, 'Only the three reviewed modules are allowed')
    for item in modules:
        require(item.get('installed_path_relative_to_studio_root') == SITE + item['wheel_member'], 'Forbidden installed path')
        require(item.get('required_installed_metadata') == {'mode': '0644', 'uid': 0, 'gid': 0,
                'xattrs': {'entries': {}, 'status': 'inspected'}}, 'Module metadata differs')
        for role in ('before', 'after'):
            entry = item.get(role, {})
            require(type(entry.get('sha256')) is str and SHA.fullmatch(entry['sha256']) and
                    type(entry.get('size_bytes')) is int and 0 < entry['size_bytes'] <= MAX_FILE, 'Invalid module pin')
        old = reference['records'].get(SITE + item['wheel_member'], {})
        require(all(old.get(k) == v for k, v in item['before'].items()), 'Delta does not match the frozen baseline')
    wheel_raw = read_pinned(wheel_path, wheel_sha, 64 * 1024 * 1024, public=True)
    payload = {}
    with zipfile.ZipFile(io.BytesIO(wheel_raw)) as archive:
        entries = archive.infolist()
        require(len(entries) < 1000 and len({entry.filename for entry in entries}) == len(entries) and
                sum(entry.file_size for entry in entries) <= 64 * 1024 * 1024, 'Wheel bounds/duplicates refused')
        record_names = [entry.filename for entry in entries if re.fullmatch(r'inky_studio_server-[A-Za-z0-9.+_-]+\.dist-info/RECORD', entry.filename)]
        require(len(record_names) == 1, 'Distribution RECORD not found')
        record_name = record_names[0]
        wheel_rows = {row[0]: row for row, _ in csv_rows(archive.read(record_name))}
        require(set(wheel_rows) == {entry.filename for entry in entries}, 'Wheel RECORD inventory differs')
        for entry in entries:
            name = entry.filename
            require(not entry.is_dir() and str(PurePosixPath(name)) == name and
                    not name.startswith('/') and '..' not in PurePosixPath(name).parts and
                    entry.file_size <= MAX_FILE, 'Wheel member refused')
            data = archive.read(name)
            require(wheel_rows[name] == ([name, '', ''] if name == record_name else
                    [name, record_digest(data), str(len(data))]), 'Wheel RECORD content differs')
            if name in MEMBERS:
                item = next(item for item in modules if item['wheel_member'] == name)
                require(sha(data) == item['after']['sha256'] and len(data) == item['after']['size_bytes'] and
                        item['wheel_RECORD_after'] == wheel_rows[name], 'New module payload differs')
                require(item['wheel_RECORD_before'] == [name, 'sha256=' + base64.urlsafe_b64encode(
                    bytes.fromhex(item['before']['sha256'])).rstrip(b'=').decode(), str(item['before']['size_bytes'])],
                    'Old RECORD row pin differs')
                payload[STUDIO + '/' + SITE + name] = data
            elif name != record_name:
                old = reference['records'].get(SITE + name, {})
                require(old.get('type') == 'file' and old.get('sha256') == sha(data) and
                        old.get('size_bytes') == len(data), 'Unexpected other wheel change')
    return manifest, reference, payload, STUDIO + '/' + SITE + record_name


class Ext4:
    def __init__(self, image):
        self.image = regular(image, writable=True)
        self.binding = stamp(image)[:2]

    def unchanged_identity(self):
        require(stamp(self.image)[:2] == self.binding, 'Copy inode changed')

    def command(self, text, write=False):
        self.unchanged_identity()
        result = subprocess.run([str(DEBUGFS), *(['-w'] if write else []), '-R', text, str(self.image)],
                                env=ENV, capture_output=True, timeout=60)
        errors = result.stderr.splitlines()
        require(result.returncode == 0 and all(line.startswith(b'debugfs ') or not line for line in errors),
                'debugfs refused a copy operation')
        return result.stdout

    def xattr_digest(self, inode):
        listing = self.command('ea_list <{}>'.format(inode))
        if not listing:
            return sha(b'')
        lines = listing.splitlines()
        require(lines and lines[0] == b'Extended attributes:', 'Unrecognized extended-attribute list')
        attributes, names = [], set()
        with tempfile.TemporaryDirectory(prefix='.xattr-', dir=str(self.image.parent)) as directory:
            for line in lines[1:]:
                if not line:
                    continue
                item = re.fullmatch(br'  ([A-Za-z0-9_.:+-]+) \(([0-9]+)\)(?: = .*)?', line)
                require(item is not None, 'Unsupported extended-attribute name/list encoding')
                name, size = item[1].decode('ascii'), int(item[2])
                require(name not in names and len(names) < 1024 and 0 <= size <= MAX_FILE,
                        'Extended-attribute bounds or duplicate refused')
                names.add(name)
                output = Path(directory) / ('value-' + str(len(names)))
                write_private(output, b'')
                require(not any(c in str(output) for c in '\x00\n\r"\\'), 'Unsafe private attribute output path')
                # ea_list truncates or hides long values. Fetch the complete raw
                # value into a private file instead; never log or print it.
                self.command('ea_get -f "{}" <{}> {}'.format(output, inode, name))
                info = output.lstat()
                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
                        stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == size,
                        'Extended-attribute readback differs')
                value = output.read_bytes()
                require(len(value) == size, 'Extended-attribute length changed')
                attributes.append({'name': name, 'size_bytes': size, 'sha256': sha(value)})
        return sha(canonical(sorted(attributes, key=lambda item: item['name'])))

    def metadata(self, inode):
        raw = self.command('stat <{}>'.format(inode))
        text = raw.decode('utf-8')
        first = re.search(r'Inode:\s+(\d+)\s+Type:\s+(.*?)\s+Mode:\s+0([0-7]+)\s+Flags:\s+(0x[0-9a-fA-F]+)', text)
        ids = re.search(r'User:\s+(\d+)\s+Group:\s+(\d+).*?Size:\s+(\d+)', text)
        links = re.search(r'Links:\s+(\d+)', text)
        require(first and ids and links and int(first[1]) == inode, 'Unrecognized inode metadata')
        record = {'inode': inode, 'type': first[2], 'mode': format(int(first[3], 8), '04o'),
                  'uid': int(ids[1]), 'gid': int(ids[2]), 'links': int(links[1]), 'size_bytes': int(ids[3]),
                  'flags': first[4], 'xattrs_sha256': self.xattr_digest(inode)}
        return record, raw

    def stream_hash(self, inode, expected):
        self.unchanged_identity()
        with tempfile.TemporaryFile() as error:
            process = subprocess.Popen([str(DEBUGFS), '-R', 'cat <{}>'.format(inode), str(self.image)],
                                       env=ENV, stdout=subprocess.PIPE, stderr=error)
            digest, count = hashlib.sha256(), 0
            try:
                for raw in iter(lambda: process.stdout.read(4 * 1024 * 1024), b''):
                    count += len(raw); require(count <= expected, 'Inode data exceeds metadata size'); digest.update(raw)
                require(process.wait(timeout=30) == 0 and count == expected, 'Inode data read failed')
            finally:
                process.stdout.close()
                if process.poll() is None:
                    process.kill(); process.wait()
            error.seek(0)
            require(all(line.startswith(b'debugfs ') or not line for line in error.read().splitlines()), 'Inode read reported an error')
        return digest.hexdigest()

    def inventory(self):
        result, cache, pending, seen_dirs = {}, {}, [('/', 2)], set()
        while pending:
            path, inode = pending.pop()
            require(path not in result and len(result) < 300000, 'Filesystem inventory limit/duplicate')
            if inode not in cache:
                record, raw = self.metadata(inode)
                if record['type'] == 'regular':
                    record['sha256'] = self.stream_hash(inode, record['size_bytes'])
                elif record['type'] == 'symlink':
                    fast = re.search(br'Fast link dest: "(.*)"\n?\Z', raw, re.S)
                    if fast:
                        require(len(fast[1]) == record['size_bytes'], 'Fast symlink length differs')
                        record['target_sha256'] = sha(fast[1])
                    else:
                        record['target_sha256'] = self.stream_hash(inode, record['size_bytes'])
                elif record['type'] != 'directory':
                    device = re.search(br'Device major/minor number:\s*([^\n]+)', raw)
                    record['special_identity_sha256'] = sha(device[1] if device else b'')
                cache[inode] = record
            record = dict(cache[inode]); result[path] = record
            if record['type'] == 'directory':
                require(inode not in seen_dirs, 'Directory inode alias refused')
                seen_dirs.add(inode)
                for line in self.command('ls -l -p <{}>'.format(inode)).decode('utf-8').splitlines():
                    if not line:
                        continue
                    fields = line.split('/')
                    require(len(fields) == 8 and fields[0] == fields[-1] == '' and fields[1].isdigit(),
                            'Unrecognized directory entry')
                    if int(fields[1]) == 0:
                        continue  # Unallocated ext4 directory slots are not names.
                    name = fields[5]
                    if name in ('.', '..'):
                        continue
                    require(name and not any(ord(char) < 32 for char in name), 'Unsupported filename encoding')
                    child = (path.rstrip('/') + '/' + name)
                    pending.append((child, int(fields[1])))
        return result

    def read_inode(self, record, maximum=MAX_FILE):
        require(record['type'] == 'regular' and record['size_bytes'] <= maximum, 'Bounded regular payload required')
        raw = self.command('cat <{}>'.format(record['inode']))
        require(len(raw) == record['size_bytes'] and sha(raw) == record['sha256'], 'Inode bytes changed')
        return raw

    def replace(self, path, data, workspace):
        require(path in {STUDIO + '/' + SITE + name for name in MEMBERS} or
                re.fullmatch(re.escape(STUDIO + '/' + SITE) + r'inky_studio_server-[A-Za-z0-9.+_-]+\.dist-info/RECORD', path),
                'Write path outside the four-file allowlist')
        payload = workspace / ('payload-' + sha(data))
        if not payload.exists():
            write_private(payload, data)
        require(not any(c in str(payload) for c in '\x00\n\r"\\'), 'Host payload path cannot be quoted safely')
        self.command('rm ' + path, write=True)
        self.command('write "{}" {}'.format(payload, path), write=True)
        for key, value in [('uid', '0'), ('gid', '0'), ('mode', '0100644')]:
            self.command('set_inode_field {} {} {}'.format(path, key, value), write=True)


def verify_tools():
    for tool in (DEBUGFS, FSCK):
        require(sha(tool.read_bytes()) == TOOL_PINS[tool.name], 'Reviewed filesystem tool changed')


def run_fsck(image, flags, log):
    fd = os.open(str(log), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        process = subprocess.Popen([str(FSCK), *flags, '-E', 'nodiscard', str(image)],
                                   env=ENV, stdout=output, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 1800
        try:
            while process.poll() is None:
                require(time.monotonic() < deadline and os.fstat(output.fileno()).st_size <= 16 * 1024 * 1024,
                        'Filesystem check exceeded its time/log bound')
                time.sleep(0.02)
            require(os.fstat(output.fileno()).st_size <= 16 * 1024 * 1024, 'Filesystem log limit exceeded')
            output.flush(); os.fsync(output.fileno())
            return process.returncode
        finally:
            if process.poll() is None:
                process.kill(); process.wait()


def filesystem_check(image, log, recover=False):
    before = stamp(image)
    with image.open('rb') as stream:
        stream.seek(1024); block = stream.read(1024)
    require(len(block) == 1024 and block[56:58] == b'\x53\xef', 'Candidate is not ext4')
    needs_recovery = bool(struct.unpack_from('<I', block, 96)[0] & 4)
    if needs_recovery:
        require(recover, 'Journal recovery required on the disposable copy')
        code = run_fsck(image, ['-f', '-p'], log / 'fsck-copy-recovery.txt')
        require(code in (0, 1), 'Automatic copy recovery failed; original backup is untouched')
    before = stamp(image)
    code = run_fsck(image, ['-f', '-n'], log / ('fsck-final.txt' if not recover else 'fsck-baseline.txt'))
    require(code == 0 and stamp(image) == before, 'Read-only filesystem check failed or changed copy')
    return needs_recovery


def verify_profile(fs, inventory):
    require(not (set(inventory) & FACTORY), 'Factory/TEST state refused')
    unit_path = '/usr/lib/systemd/system/inky-studio.service'
    require(unit_path in inventory, 'Normal LAN service is absent')
    unit = fs.read_inode(inventory[unit_path]).decode('utf-8')
    required = 'ExecStart=/usr/lib/inky-studio/server/.venv/bin/python3 -I -B -m inky_web.imager_lan'
    require(unit.count('ExecStart=') == 1 and required in unit.splitlines() and
            'User=inky' in unit.splitlines() and 'NoNewPrivileges=yes' in unit.splitlines(), 'Normal LAN unit differs')
    env_path = '/etc/inky-studio/imager.env'
    require(env_path in inventory, 'Normal LAN environment absent')
    env = fs.read_inode(inventory[env_path]).decode('utf-8').splitlines()
    require(set(env) == {'INKY_STUDIO_DATA_DIR="/var/lib/inky-studio"',
            'INKY_STUDIO_DISPLAY_MODE="hardware"',
            'INKY_STUDIO_DISPLAY_PROFILE="ac073-800x480-timed-wait"'}, 'LAN environment differs')


def verify_baseline(inventory, reference, record_path):
    for relative, expected in reference['records'].items():
        path = STUDIO if relative == '.' else STUDIO + '/' + relative
        require(str(PurePosixPath(path)) == path and '..' not in PurePosixPath(path).parts, 'Unsafe reference path')
        actual = inventory.get(path)
        require(actual is not None, 'A frozen installed file is absent')
        kind = {'file': 'regular', 'directory': 'directory', 'symlink': 'symlink'}.get(expected.get('type'))
        require(kind and actual['type'] == kind and all(actual[k] == expected[k] for k in ('mode', 'uid', 'gid')) and
                expected.get('xattrs') == {'entries': {}, 'status': 'inspected'} and actual['xattrs_sha256'] == sha(b''),
                'Frozen installed metadata differs')
        if path != record_path and kind == 'regular':
            require(actual['sha256'] == expected['sha256'] and actual['size_bytes'] == expected['size_bytes'],
                    'Other installed baseline bytes differ')
        if kind == 'symlink':
            require(actual['target_sha256'] == sha(expected['target'].encode()), 'Installed symlink differs')


def apply_to_copy(image, manifest, reference, payload, record_path, log):
    fs = Ext4(image)
    before = fs.inventory()
    verify_profile(fs, before)
    verify_baseline(before, reference, record_path)
    record = before.get(record_path)
    require(record and record['type'] == 'regular' and record['links'] == 1 and record['mode'] == '0644' and
            record['uid'] == record['gid'] == 0 and record['xattrs_sha256'] == sha(b''), 'Installed RECORD metadata differs')
    new_record = update_record(fs.read_inode(record), manifest['modules'])
    for item in manifest['modules']:
        old = before.get(STUDIO + '/' + item['installed_path_relative_to_studio_root'], {})
        require(old.get('type') == 'regular' and old.get('links') == 1 and
                all(old.get(k) == v for k, v in item['before'].items()), 'Observed old module differs')
    replacements = dict(payload); replacements[record_path] = new_record
    require(len(replacements) == 4, 'Four-file update required')
    write_private(log / 'baseline-inventory.json', canonical(before))
    # All old bytes, package metadata, new payloads and RECORD rows are now checked.
    for path, data in sorted(replacements.items()):
        fs.replace(path, data, log)
    fd = os.open(str(image), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    after = fs.inventory()
    require(set(after) == set(before), 'Filesystem names changed outside fixed replacements')
    for path, record in before.items():
        if path in replacements:
            current = after[path]
            require(current['type'] == 'regular' and current['mode'] == '0644' and current['uid'] == current['gid'] == 0 and
                    current['links'] == 1 and current['xattrs_sha256'] == sha(b'') and
                    current['sha256'] == sha(replacements[path]) and current['size_bytes'] == len(replacements[path]),
                    'Written package readback differs')
        elif record['type'] == 'directory':
            # Directory allocation/mtime can change when its child is replaced.
            require(all(record[k] == after[path][k] for k in ('inode', 'type', 'mode', 'uid', 'gid', 'links', 'flags', 'xattrs_sha256')),
                    'Directory identity or permissions changed')
        else:
            require(record == after[path], 'A protected file or installed extra changed')
    write_private(log / 'after-inventory.json', canonical(after))
    return {'logicalEntriesVerified': len(before), 'changedFiles': sorted(replacements),
            'preservationVerified': True, 'installedDeltaVerified': True}


def prepare(workspace, receipt_path, receipt_sha, manifest_path, manifest_sha, wheel_path, wheel_sha,
            reference_path, reference_sha):
    workspace = private_directory(workspace)
    require(Path(receipt_path) == workspace / 'acquisition.json', 'The native acquisition.json receipt is required')
    verify_tools()
    manifest, reference, payload, record_path = load_package(
        manifest_path, manifest_sha, wheel_path, wheel_sha, reference_path, reference_sha)
    receipt, backup, geo, backup_before = load_acquisition(workspace, receipt_path, receipt_sha)
    candidate = workspace / 'root-candidate.img'
    log = workspace / 'preparation'
    require(not candidate.exists() and not log.exists(), 'Preparation already exists; do not replay automatically')
    require(shutil.disk_usage(workspace).free >= geo['rootBytes'] + 1024 ** 3, 'Insufficient space for the private candidate')
    log.mkdir(mode=0o700)
    fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as target, backup.open('rb') as source:
        source.seek(geo['rootOffset']); remaining = geo['rootBytes']; digest = hashlib.sha256()
        while remaining:
            block = source.read(min(remaining, 4 * 1024 * 1024)); require(block, 'Backup partition ended early')
            target.write(block); digest.update(block); remaining -= len(block)
        target.flush(); os.fsync(target.fileno())
    require(digest.hexdigest() == receipt['hashes']['rootSHA256'] and stamp(backup) == backup_before,
            'Partition extraction differs or backup changed')
    recovered = filesystem_check(candidate, log, recover=True)
    result = apply_to_copy(candidate, manifest, reference, payload, record_path, log)
    filesystem_check(candidate, log)
    require(stamp(backup) == backup_before, 'Original backup changed')
    candidate_sha = hash_file(candidate)
    os.chmod(candidate, 0o400)
    approval = {'schemaVersion': 1, 'kind': 'inkyos-maintenance-candidate', 'status': 'complete',
                'acquisitionReceiptSHA256': receipt_sha, 'sourceBackupSHA256': receipt['hashes']['wholeSHA256'],
                'candidateSHA256': candidate_sha, 'candidateBytes': geo['rootBytes'],
                'baselineBackend': BASE, 'targetBackend': TARGET, 'filesystemVerified': True,
                'copyJournalRecovered': recovered, 'manifestSHA256': manifest_sha, 'wheelSHA256': wheel_sha,
                'referenceManifestSHA256': reference_sha, **result}
    approval_raw = canonical(approval)
    write_private(workspace / 'candidate-approval.json', approval_raw)
    request = {'schemaVersion': 1, 'ownerUID': os.getuid(), 'target': receipt['target'],
               'backupFile': receipt['backupFile'], 'candidateFile': candidate.name,
               'candidateSHA256': candidate_sha, 'acquisitionReceiptSHA256': receipt_sha,
               'candidateApprovalFile': 'candidate-approval.json', 'candidateApprovalSHA256': sha(approval_raw)}
    write_private(workspace / 'write-root-request.json', canonical(request))
    return {'status': 'complete', 'candidateSHA256': candidate_sha, 'candidateBytes': geo['rootBytes'],
            'changedFiles': len(result['changedFiles']), 'logicalEntriesVerified': result['logicalEntriesVerified'],
            'copyJournalRecovered': recovered, 'SDOpened': False, 'SDWritesIssued': False,
            'targetProgramsExecuted': False}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', required=True, type=Path)
    parser.add_argument('--receipt', required=True, type=Path)
    parser.add_argument('--receipt-sha256', required=True)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--wheel', required=True, type=Path)
    parser.add_argument('--wheel-sha256', required=True)
    parser.add_argument('--reference-manifest', required=True, type=Path)
    parser.add_argument('--reference-sha256', required=True)
    args = parser.parse_args()
    try:
        result = prepare(args.workspace, args.receipt, args.receipt_sha256, args.manifest, args.manifest_sha256,
                         args.wheel, args.wheel_sha256, args.reference_manifest, args.reference_sha256)
    except Exception as error:
        print(json.dumps({'status': 'REFUSED', 'SDWritesIssued': False, 'error': str(error)}, ensure_ascii=True))
        raise SystemExit(1)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
