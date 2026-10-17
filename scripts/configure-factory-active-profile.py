#!/usr/bin/env python3
"""Opt-in offline factory profile; never boot, flash or execute target code.

Stage static controls before inventory. Install a separately pinned runtime
plan only after the real candidate verifier accepts its installed dependencies.
Partial creations remain private evidence, never an exportable image or retry.
"""
import argparse
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location('_active_profile_' + name.replace('-', '_'),
                                                ROOT / 'scripts' / name)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


guards = load('install-factory-studio-bundle-rootfs.py')
planner = load('plan-factory-runtime-manifest.py')
runtime = planner.runtime
require = guards.require
TRIGGER = 'usr/lib/systemd/system/inkyos-factory-start.service'
MARKER = 'etc/inky-studio/factory-v1.json'
PERMISSION = 'var/lib/inkyos/factory-permission'
DROPIN = 'etc/systemd/system/NetworkManager.service.d/20-inkyos-wlan-close.conf'
JOURNAL_DROPIN = 'etc/systemd/journald.conf.d/zz-inkyos-factory-persistent.conf'
MARKER_RAW = runtime.canonical({'version': 1, 'app_uid': 1000,
                              'data_dir': '/var/lib/inky-studio'})
PERMISSION_RAW = runtime.canonical({'version': 1, 'operation': 'create-initialization-authority'})
DROPIN_RAW = b'[Unit]\nRequires=inkyos-wlan-close.service\nAfter=inkyos-wlan-close.service\n'
JOURNAL_DROPIN_RAW = (b'[Journal]\nStorage=persistent\nSplitMode=none\n'
                      b'SystemMaxUse=32M\nSystemMaxFileSize=8M\n')
LINKS = {
    'etc/systemd/system/systemd-rfkill.service': '/dev/null',
    'etc/systemd/system/systemd-rfkill.socket': '/dev/null',
    'etc/systemd/system/multi-user.target.wants/inkyos-factory-start.service': '/' + TRIGGER,
}
BOOT_ABSENT = (
    runtime.MANIFEST, 'run/inkyos-admission', 'run/inkyos-factory',
    'run/inkyos-bootstrap', 'run/inkyos-factory-output', 'run/inky-network',
    'var/lib/inkyos/initialization', 'var/lib/inkyos/system-setup',
)


class Offline:
    """Hold no-follow directory identities in the exclusive private builder."""
    def __init__(self, rootfs):
        self.rootfs = guards._canonical_path(rootfs)
        require(self.rootfs != Path('/'), 'host_root_refused')
        work, trust_from = guards._production_environment(self.rootfs)
        require(re.fullmatch(r'/var/lib/inkyos-build/factory-image\.[A-Za-z0-9]+/root',
                             str(self.rootfs)) is not None or trust_from is not None,
                'private_workspace_required')
        self.held, self.by_name = [], {}
        try:
            for path in (work, self.rootfs):
                directory = guards.Directory(self.rootfs, path, trust_from=trust_from)
                self.held.append(directory)
            require(stat.S_IMODE(os.fstat(self.held[0].fd).st_mode) == 0o700,
                    'private_workspace_required')
            self.by_name['.'] = self.held[-1]
            if trust_from is None:
                with Path('/var/lib/inkyos-build/owner').open('rb') as stream:
                    require(stream.read(257) == b'inkyos-builder-v1\n', 'builder_marker_required')
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        for held in self.held:
            held.check()
            guards._trust(self.rootfs, os.fstat(held.fd))
            require(guards._xattrs(self.rootfs, held.fd) == guards.EMPTY_XATTRS,
                    'untrusted_xattrs')

    def directory(self, relative, *, create=False, mode=0o755):
        current, partial = self.by_name['.'].fd, ''
        for part in PurePosixPath(relative).parts:
            require(part not in ('/', '..'), 'invalid_path')
            partial = part if not partial else partial + '/' + part
            if partial in self.by_name:
                current = self.by_name[partial].fd
                continue
            self.check()
            if guards._missing(current, part):
                if not create:
                    return None
                os.mkdir(part, mode=mode if partial == relative else 0o755, dir_fd=current)
                os.fsync(current)
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            try:
                guards._trust(self.rootfs, os.fstat(fd))
                require(guards._xattrs(self.rootfs, fd) == guards.EMPTY_XATTRS,
                        'untrusted_xattrs')
                held = guards._FdDirectory(self.rootfs, fd, current, part)
            except BaseException:
                os.close(fd)
                raise
            self.held.append(held)
            self.by_name[partial] = held
            current = fd
        self.check()
        return current

    def absent(self, path):
        parent, name = str(PurePosixPath(path).parent), PurePosixPath(path).name
        fd = self.directory(parent)
        return fd is None or guards._missing(fd, name)

    def read(self, path, *, mode=0o644, limit=16384):
        require(type(mode) is int or path == 'etc/machine-id'
                and type(mode) is tuple and mode == (0o444, 0o644), 'input_mode_policy_invalid')
        allowed = mode if type(mode) is tuple else (mode,)
        fd = self.directory(str(PurePosixPath(path).parent))
        require(fd is not None, 'input_missing')
        name = PurePosixPath(path).name
        raw = guards._read_file(self.rootfs, fd, name, limit)
        require(stat.S_IMODE(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode) in allowed,
                'input_mode_invalid')
        return raw

    def write(self, path, raw, mode):
        require(self.absent(path), 'profile_already_exists')
        fd = self.directory(str(PurePosixPath(path).parent), create=True)
        self.check()
        guards._write_file(self.rootfs, fd, PurePosixPath(path).name, raw, mode)
        require(self.read(path, mode=int(mode, 8), limit=max(len(raw), 1)) == raw,
                'profile_readback_failed')

    def link(self, path, target):
        require(self.absent(path), 'profile_already_exists')
        fd = self.directory(str(PurePosixPath(path).parent), create=True)
        os.symlink(target, PurePosixPath(path).name, dir_fd=fd)
        os.fsync(fd)
        require(os.readlink(PurePosixPath(path).name, dir_fd=fd) == target,
                'profile_readback_failed')
        self.check()

    def close(self):
        for held in reversed(self.held):
            held.close()
        self.held = []


@contextmanager
def offline(rootfs):
    environment = Offline(rootfs)
    try:
        yield environment
    finally:
        environment.close()


def stage(rootfs, *, trigger_sha256):
    """Stage the explicit fresh-card permission and boot controls, offline only."""
    require(type(trigger_sha256) is str and runtime.HASH.fullmatch(trigger_sha256), 'pin_required')
    source = ROOT / 'staging/bootstrap/inkyos-factory-start.service'
    raw = guards.planner.exporter.ordinary(source, 16384)
    require(runtime.sha(raw) == trigger_sha256, 'trigger_pin_mismatch')
    with offline(rootfs) as env:
        require(env.read('etc/machine-id', mode=(0o444, 0o644)) == b'uninitialized\n',
                'unbooted_image_required')
        nm = env.read('var/lib/NetworkManager/NetworkManager.state', mode=0o600)
        require(nm == b'[main]\nWirelessEnabled=false\n', 'wifi_not_closed')
        require(all(env.absent(path) for path in (*BOOT_ABSENT, MARKER, PERMISSION,
                                                 DROPIN, JOURNAL_DROPIN, TRIGGER, *LINKS)),
                'profile_or_runtime_state_exists')
        for path in ('etc/NetworkManager/system-connections',
                     'var/lib/NetworkManager/system-connections'):
            fd = env.directory(path)
            require(fd is None or not os.listdir(fd), 'wifi_profiles_present')
        # The state parent is private for authority/journal handling, not a key.
        state = env.directory('var/lib/inkyos', create=True, mode=0o700)
        require(stat.S_IMODE(os.fstat(state).st_mode) == 0o700, 'state_parent_not_private')
        journal = env.directory('var/lib/inkyos/system-setup', create=True, mode=0o700)
        require(stat.S_IMODE(os.fstat(journal).st_mode) == 0o700
                and not os.listdir(journal), 'setup_parent_not_private')
        permission = env.directory(PERMISSION, create=True, mode=0o700)
        require(stat.S_IMODE(os.fstat(permission).st_mode) == 0o700, 'permission_not_private')
        env.write(PERMISSION + '/lock', b'', '0600')
        env.write(PERMISSION + '/pending.json', PERMISSION_RAW, '0600')
        env.write(MARKER, MARKER_RAW, '0644')
        env.write(TRIGGER, raw, '0644')
        env.write(DROPIN, DROPIN_RAW, '0644')
        env.write(JOURNAL_DROPIN, JOURNAL_DROPIN_RAW, '0644')
        for path, target in LINKS.items():
            env.link(path, target)
        require(source.read_bytes() == raw, 'trigger_source_changed')
        env.check()
    return {'scope': 'offline-factory-static-profile', 'passed': True,
            'fresh_permission_staged': True, 'image_code_executed': False,
            'hardware_qualified': False, 'exportable_image': False}


def install_runtime(rootfs, *, plan_file, plan_sha256):
    """Replan from installed bytes; copy only the exact independently pinned plan."""
    require(type(plan_sha256) is str and runtime.HASH.fullmatch(plan_sha256), 'pin_required')
    plan_file = guards._canonical_path(plan_file)
    rootfs = guards._canonical_path(rootfs)
    require(not plan_file.is_relative_to(rootfs), 'plan_overlap')
    raw = guards.planner.exporter.ordinary(plan_file, 16384)
    require(runtime.sha(raw) == plan_sha256, 'plan_pin_mismatch')
    value = runtime.decode(raw)
    require(type(value) is dict, 'invalid_plan')
    with offline(rootfs) as env:
        require(env.read(MARKER) == MARKER_RAW
                and env.read(JOURNAL_DROPIN) == JOURNAL_DROPIN_RAW
                and env.read(PERMISSION + '/lock', mode=0o600) == b''
                and env.read(PERMISSION + '/pending.json', mode=0o600) == PERMISSION_RAW,
                'static_profile_missing')
        require(env.absent(runtime.MANIFEST), 'runtime_manifest_exists')
        planned, receipt = planner.plan(rootfs,
            bundle_sha256=value['bundle_manifest_sha256'],
            exporter_sha256=value['exporter_manifest_sha256'],
            support_sha256=value['support_manifest_sha256'],
            helper_uid=value['helper_uid'], provisioning_gid=value['provisioning_gid'])
        require(planned == raw, 'plan_differs_from_installed_bytes')
        env.write(runtime.MANIFEST, raw, '0644')
        runtime.verify_candidate(runtime.load_contract(_root=rootfs))
        require(plan_file.read_bytes() == raw, 'plan_changed')
        env.check()
    return {**receipt, 'scope': 'offline-factory-runtime-install',
            'runtime_manifest_installed': True, 'passed': True,
            'hardware_qualified': False, 'boot_qualified': False}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('stage-static', 'install-runtime'))
    p.add_argument('--rootfs', required=True, type=Path)
    p.add_argument('--trigger-sha256')
    p.add_argument('--plan-file', type=Path)
    p.add_argument('--plan-sha256')
    a = p.parse_args(argv)
    try:
        if a.operation == 'stage-static':
            require(a.trigger_sha256 is not None and a.plan_file is a.plan_sha256 is None,
                    'wrong_operation_arguments')
            result = stage(a.rootfs, trigger_sha256=a.trigger_sha256)
        else:
            require(a.trigger_sha256 is None and a.plan_file is not None
                    and a.plan_sha256 is not None, 'wrong_operation_arguments')
            result = install_runtime(a.rootfs, plan_file=a.plan_file, plan_sha256=a.plan_sha256)
    except (OSError, ValueError, TypeError, KeyError):
        print(json.dumps({'passed': False, 'error': 'active_profile_refused',
                          'retry_authorized': False}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
