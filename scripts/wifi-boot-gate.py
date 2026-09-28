#!/usr/bin/env python3
"""INACTIVE pre-NetworkManager state writer; fixtures only, no runtime CLI.

Candidate future drop-in (NOT installed by this module):
    [Service]
    ExecStartPre=/usr/bin/python3 /usr/local/lib/inkyos/wifi-boot-gate.py
A fixed-root Linux entry point must be reviewed before installing that drop-in.
Do not put this into the hostname firstboot unit: Bluetooth depends on that unit.

Call only while NetworkManager is stopped. NM 1.52.1 reads this file at daemon
startup and defaults WirelessEnabled to true if the file cannot be read. The
function resets the persisted flag on every invocation, including NM restarts;
it does not wait for a country, start NM, call D-Bus or operate rfkill/Bluetooth.
It does NOT prove an already active radio is physically off before NM starts.
No clock/radio/service mutation or bootfs write exists here. A future caller must
fail NM startup on error and preserve BLE availability independently.

Source: https://github.com/NetworkManager/NetworkManager/blob/1.52.1/src/core/nm-config.c
A narrow INI subset preserves untouched lines verbatim without interpolation.
Ambiguous/unrecognized syntax fails closed rather than guessing NM semantics.
Encoding keys are always refused: GLib gives Encoding special first-group
semantics, and this NM state file never needs an encoding declaration.
The fixture root must already contain var/lib/NetworkManager; no directories are
created. The directory lock serializes these writers only, not NetworkManager.
"""
import fcntl
import itertools
import os
from pathlib import Path
import re
import stat

MAX_STATE_BYTES = 64 * 1024
STATE = 'NetworkManager.state'
_counter = itertools.count()
_NAME = re.compile(r'[A-Za-z0-9_.-]+\Z')
_BOOLEANS = {'NetworkingEnabled', 'WirelessEnabled', 'WWANEnabled'}


class GateError(RuntimeError):
    """The persisted Wi-Fi gate was not safely committed; do not start NM."""


def _require(condition, message):
    if not condition:
        raise GateError(message)


def disabled_state(raw):
    """Return bounded UTF-8 INI with exactly one main/WirelessEnabled=false."""
    if raw is None:
        return b'[main]\nWirelessEnabled=false\n'
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_STATE_BYTES, 'Bounded nonempty state required')
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise GateError('State is not UTF-8') from exc
    _require(all(ord(c) >= 32 or c in '\t\r\n' for c in text) and '\x7f' not in text and
             '\r' not in text.replace('\r\n', ''), 'Control character or unsupported line ending')
    pieces = text.split('\n')
    lines = [piece + '\n' for piece in pieces[:-1]] + ([pieces[-1]] if pieces[-1] else [])
    groups = {}; group = None; target = None; main_end = None
    for index, original in enumerate(lines):
        line = original.rstrip('\r\n').strip(' \t')
        if not line or line.startswith('#'):
            continue
        if line.startswith('['):
            _require(line.endswith(']') and _NAME.fullmatch(line[1:-1]), 'Invalid section')
            name = line[1:-1]
            _require(name.casefold() not in groups and (name.casefold() != 'main' or name == 'main'),
                     'Duplicate or ambiguous section')
            if group == 'main':
                main_end = index
            group = name.casefold(); groups[group] = set()
            continue
        _require(group is not None and '=' in line and not original.startswith((' ', '\t')),
                 'Key outside section or unsupported continuation')
        key, value = line.split('=', 1); key = key.strip(' \t'); value = value.strip(' \t')
        _require(_NAME.fullmatch(key) and key.casefold() not in groups[group], 'Duplicate or invalid key')
        # GLib gkeyfile.c 2.84.1 rejects non-UTF-8 Encoding in its first group.
        # NM then falls back to enabled defaults; never preserve this special key.
        _require(key.casefold() != 'encoding', 'Encoding declarations are not permitted')
        groups[group].add(key.casefold())
        if group == 'main' and key.casefold() in {name.casefold() for name in _BOOLEANS}:
            _require(key in _BOOLEANS and value in ('true', 'false'), 'Ambiguous boolean')
        if group == 'main' and key == 'WirelessEnabled':
            target = index
    _require('main' in groups, 'Unique main section required')
    if target is not None:
        lines[target] = 'WirelessEnabled=false\n'
    else:
        position = len(lines) if main_end is None else main_end
        if position and not lines[position - 1].endswith('\n'):
            lines[position - 1] += '\n'
        lines.insert(position, 'WirelessEnabled=false\n')
    result = ''.join(lines).encode('utf-8')
    _require(len(result) <= MAX_STATE_BYTES, 'Resulting state exceeds size limit')
    return result


def _directory(info, owner_uid, *, ancestor=False):
    allowed = {0, owner_uid} if ancestor else {owner_uid}
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid in allowed and not info.st_mode & 0o022,
             'Unsafe directory ownership/type/permissions')


def _open_root(root, owner_uid):
    path = Path(root)
    _require(path.is_absolute() and '..' not in path.parts, 'Absolute canonical fixture root required')
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _directory(os.fstat(fd), owner_uid, ancestor=True)
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            _directory(os.fstat(fd), owner_uid, ancestor=True)
        _directory(os.fstat(fd), owner_uid)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _signature(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _read(directory, owner_uid):
    try:
        fd = os.open(STATE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        return None, None
    try:
        info = os.fstat(fd)
        _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == owner_uid
                 and not info.st_mode & 0o6022 and info.st_size <= MAX_STATE_BYTES,
                 'Unsafe state type/owner/links/permissions/size')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(MAX_STATE_BYTES + 1)
        _require(len(raw) == info.st_size and _signature(info) == _signature(os.fstat(fd)) ==
                 _signature(os.stat(STATE, dir_fd=directory, follow_symlinks=False)), 'State changed during read')
        return raw, stat.S_IMODE(info.st_mode)
    finally:
        os.close(fd)


def set_wireless_disabled(root, *, owner_uid=0, checkpoint=None):
    """Fixture API only. Success commits bytes durably; it never claims radio off."""
    _require(type(owner_uid) is int and owner_uid >= 0, 'Explicit owner UID required')
    checkpoint = checkpoint or (lambda _stage: None)
    directory = temporary_fd = None; temporary = None
    try:
        directory = _open_root(root, owner_uid)
        for part in ('var', 'lib', 'NetworkManager'):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory); directory = child
            _directory(os.fstat(directory), owner_uid)
        fcntl.flock(directory, fcntl.LOCK_EX)
        previous, mode = _read(directory, owner_uid)
        content = disabled_state(previous)
        for _ in range(100):
            name = f'.{STATE}.inkyos-{os.getpid()}-{next(_counter)}'
            try:
                temporary_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                       0o600, dir_fd=directory)
                temporary = name
                break
            except FileExistsError:
                pass
        _require(temporary_fd is not None, 'Cannot allocate exclusive state temporary')
        os.fchmod(temporary_fd, 0o600)
        _require(os.fstat(temporary_fd).st_uid == owner_uid, 'Temporary owner mismatch')
        with os.fdopen(temporary_fd, 'wb', closefd=False) as stream:
            stream.write(content); stream.flush()
        os.fsync(temporary_fd); checkpoint('state:temp_fsynced')
        os.close(temporary_fd); temporary_fd = None
        os.replace(temporary, STATE, src_dir_fd=directory, dst_dir_fd=directory)
        temporary = None; checkpoint('state:replaced')
        os.fsync(directory); checkpoint('state:directory_fsynced')
        return {'scope': 'pre-networkmanager-persisted-wifi-gate', 'wireless_enabled': False,
                'changed': previous != content or mode != 0o600, 'durably_written': True,
                'radio_modified': False, 'clock_modified': False, 'ble_touched': False,
                'hardware_qualified': False}
    except OSError as exc:
        raise GateError('Wi-Fi state commit failed; do not start NetworkManager') from exc
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
        if directory is not None:
            os.close(directory)


if __name__ == '__main__':
    raise SystemExit('Inactive fixture module; no runtime entry point is installed.')
