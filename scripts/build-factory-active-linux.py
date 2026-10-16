#!/usr/bin/env python3
"""Private Linux ARM64 factory image composition with an external review checkpoint.

Never run on a device or host root. Only local pinned inputs and a fresh regular
image copy are accepted. Failed work remains private; no partial export receipt.
"""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_ROOTS = {'recipe', 'factory-inputs', 'exporter-inputs', 'packages', 'provenance'}
SNAPSHOT_FILES = {'base.img', 'support-policy.json', 'support-provenance.json'}
INPUT_FIELDS = {'schema_version', 'kind', 'files', 'trigger_sha256', 'readelf'}
REQUIRED_TOOLS = {
    'build-factory-active-linux.py', 'plan-factory-system-support.py', 'manifest-rootfs.py',
    'configure-rootfs.py', 'verify-prototype.py', 'inspect-rootfs.py', 'fetch-base.py',
    'fetch-packages.py', 'fetch-test-access-packages.py', 'install-test-access-packages.py',
    'configure-factory-active-prerequisites.py', 'configure-factory-active-profile.py',
    'plan-factory-runtime-manifest.py', 'factory-runtime-contract.py',
    'install-factory-exporter-rootfs.py', 'verify-factory-exporter-rootfs.py',
    'install-application-rootfs.py', 'inspect-application-archives.py', 'verify-application.py',
}
REVIEW_FIELDS = {'schema_version', 'kind', 'prepared_receipt_sha256', 'proposal_sha256',
                 'support_manifest_sha256', 'exporter_lock_sha256', 'evidence_sha256'}
PRESERVED = ('boot/cmdline.txt', 'boot/initramfs8', 'boot/initramfs_2712', 'boot/kernel8.img',
             'boot/kernel_2712.img', 'root/etc/fstab', 'root/usr/lib/systemd/system/rpi-resize.service',
             'root/usr/lib/systemd/system/systemd-growfs-root.service',
             'root/usr/share/initramfs-tools/scripts/local-premount/resize_early',
             'root/usr/share/initramfs-tools/scripts/local-bottom/set_partuuid')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}
HASH = re.compile(r'[0-9a-f]{64}\Z')


def load(filename):
    spec = importlib.util.spec_from_file_location('_active_image_' + filename.replace('-', '_'),
                                                ROOT / 'scripts' / filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


support_tool = load('plan-factory-system-support.py')
exporter = support_tool.exporter
inventory = exporter.inventory_module
canonical = support_tool.canonical
require = support_tool.require


def digest_file(path):
    exporter.checked_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'regular_single_link_required')
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        inventory._check_stable(before, os.fstat(stream.fileno()))
        inventory._check_stable(before, path.lstat())
        return {'sha256': digest, 'size_bytes': before.st_size}


def json_file(path, pin=None):
    raw = exporter.ordinary(path)
    require(pin is None or type(pin) is str and HASH.fullmatch(pin) and exporter.sha(raw) == pin,
            'json_pin_mismatch')
    return exporter.strict_json(raw)


def write_new(path, value):
    exporter.checked_path(path, missing=True)
    with path.open('xb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())


def trust(path, *, owner=(0, 0), directory=False, private=False):
    exporter.checked_path(path)
    record = exporter.single_record(path)
    exporter.secure_record(record, owner=owner)
    require(not directory or record['type'] == 'directory', 'directory_required')
    require(not private or record['mode'] == '0700', 'private_workspace_required')


def workspace(path):
    require(path.is_absolute() and re.fullmatch(r'/var/lib/inkyos-build/factory-image\.[A-Za-z0-9]+', str(path)),
            'private_workspace_required')
    for parent in (path, *path.parents):
        trust(parent, directory=True, private=parent == path)
    require(sys.platform.startswith('linux') and platform.machine() == 'aarch64'
            and os.geteuid() == os.getegid() == 0, 'root_linux_arm64_required')
    marker = Path('/var/lib/inkyos-build/owner')
    trust(marker)
    require(exporter.ordinary(marker, 256) == b'inkyos-builder-v1\n', 'builder_marker_required')


def private_propagation(mountinfo):
    """Every mount must have private/unbindable propagation, including submounts."""
    rows = mountinfo.splitlines()
    if not rows:
        return False
    seen, root = set(), False
    for row in rows:
        fields = row.split()
        try:
            separator = fields.index('-')
            if (separator < 6 or len(fields) != separator + 4
                    or not fields[0].isdigit() or fields[0] in seen
                    or not fields[3].startswith('/') or not fields[4].startswith('/')
                    or any(field != 'unbindable' for field in fields[6:separator])):
                return False
        except (ValueError, IndexError):
            return False
        seen.add(fields[0])
        root |= fields[4] == '/'
    return root


def private_namespaces():
    return (all(os.readlink('/proc/self/ns/' + name) != os.readlink('/proc/1/ns/' + name)
                for name in ('mnt', 'net', 'uts'))
            and {name for _, name in socket.if_nameindex()} == {'lo'}
            and private_propagation(Path('/proc/self/mountinfo').read_text()))


def current_mounts():
    """Fresh kernel mount observation; decode mountinfo's escaped path fields."""
    raw = Path('/proc/self/mountinfo').read_text()
    require(len(raw) <= 16 * 1024 * 1024, 'mountinfo_limit')
    result = []
    def unescape(value):
        return re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), value)
    for row in raw.splitlines():
        fields = row.split(); separator = fields.index('-')
        require(separator >= 6 and len(fields) == separator + 4, 'invalid_mountinfo')
        require(re.fullmatch(r'[0-9]+:[0-9]+', fields[2]), 'invalid_mount_device')
        result.append({'point': unescape(fields[4]), 'source': unescape(fields[separator + 2]),
                       'device': fields[2], 'type': fields[separator + 1]})
    require(result, 'empty_mountinfo')
    return result


def loop_device_ids(loop):
    result = set()
    for suffix in ('', 'p1', 'p2'):
        try:
            info = os.stat(loop + suffix, follow_symlinks=False)
        except FileNotFoundError:
            require(suffix, 'loop_device_disappeared')
            continue
        require(stat.S_ISBLK(info.st_mode), 'unexpected_loop_device_node')
        result.add(str(os.major(info.st_rdev)) + ':' + str(os.minor(info.st_rdev)))
    return result


@contextmanager
def configuration_umask():
    """Allow declared 0755 rootfs directories; restore caller privacy on failure."""
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


def verify_snapshot(work, pin, *, _owner=(0, 0)):
    """Exact ordinary-file staging. New reports/review/image are outside its roots."""
    trust(work / 'factory-active-inputs.json', owner=_owner)
    value = json_file(work / 'factory-active-inputs.json', pin)
    require(type(value) is dict and set(value) == INPUT_FIELDS and value['schema_version'] == 1
            and type(value['schema_version']) is int and value['kind'] == 'factory-active-image-inputs'
            and type(value['files']) is dict and 0 < len(value['files']) <= 30000
            and type(value['trigger_sha256']) is str and HASH.fullmatch(value['trigger_sha256']), 'invalid_inputs')
    require(type(value['readelf']) is dict and set(value['readelf']) == {'path', 'sha256'}
            and type(value['readelf']['path']) is str and Path(value['readelf']['path']).is_absolute()
            and type(value['readelf']['sha256']) is str and HASH.fullmatch(value['readelf']['sha256']), 'invalid_readelf_input')
    expected = value['files']
    for name, record in expected.items():
        exporter.name(name)
        require(name in SNAPSHOT_FILES or name.split('/')[0] in SNAPSHOT_ROOTS,
                'unsupported_staging_path')
        require(type(record) is dict and set(record) == {'sha256', 'size_bytes'}
                and type(record['sha256']) is str and HASH.fullmatch(record['sha256'])
                and type(record['size_bytes']) is int and 0 <= record['size_bytes'] <= 64 * 1024**3,
                'invalid_file_pin')
    actual = {}
    pending = [work / name for name in sorted(SNAPSHOT_ROOTS | SNAPSHOT_FILES)]
    while pending:
        path = pending.pop()
        trust(path, owner=_owner)
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            pending.extend(path.iterdir())
        else:
            require(stat.S_ISREG(info.st_mode) and len(actual) < 30000, 'invalid_staging_file')
            relative = str(path.relative_to(work))
            require(relative in expected, 'unlisted_staging_file')
            actual[relative] = digest_file(path)
    require(actual == expected, 'staging_snapshot_mismatch')
    require('recipe/scripts/build-factory-active-linux.py' in expected
            and 'recipe/recipe-inputs.json' in expected
            and {'base.img', 'support-policy.json', 'support-provenance.json'} <= set(expected),
            'required_staging_file_missing')
    recipe = json_file(work / 'recipe/recipe-inputs.json')
    require(type(recipe) is dict and type(recipe.get('files')) is dict
            and set(recipe['files']) == {name.removeprefix('recipe/') for name in expected
                                        if name.startswith('recipe/') and name != 'recipe/recipe-inputs.json'}
            and all(expected['recipe/' + name]['sha256'] == digest for name, digest in recipe['files'].items()),
            'recipe_manifest_mismatch')
    return value


def verified_inputs(work, pin):
    value = verify_snapshot(work, pin)
    require(Path(__file__).absolute() == work / 'recipe/scripts/build-factory-active-linux.py',
            'execute_the_pinned_recipe_snapshot')
    assembly = load('factory-assembly-profile.py')
    needed = {'scripts/' + name for name in REQUIRED_TOOLS} | set(assembly.TOOL_FILES)
    needed |= {'config/' + name for name in ('base-image.lock.json', 'system-packages.lock.json',
                                            'test-access-packages.lock.json')}
    needed |= {'overlay/' + name for name in load('configure-rootfs.py').OVERLAY_FILES}
    needed.add('staging/bootstrap/inkyos-factory-start.service')
    require({'recipe/' + name for name in needed} <= set(value['files']), 'incomplete_recipe_snapshot')
    profile = assembly.verify_inputs(work)
    base = load('fetch-packages.py')
    system = base.load_lock(work / 'recipe/config/system-packages.lock.json')
    i2c = load('fetch-test-access-packages.py').load_lock(work / 'recipe/config/test-access-packages.lock.json')
    base.verify_base(system, work / 'recipe/config/base-image.lock.json')
    base.verify_base(i2c, work / 'recipe/config/base-image.lock.json')
    base_lock = base.base.load_lock(work / 'recipe/config/base-image.lock.json')['image']
    require(value['files']['base.img'] == {'sha256': base_lock['extracted_sha256'],
                                         'size_bytes': base_lock['extracted_size_bytes']}, 'base_pin_mismatch')
    for package in system['packages'] + i2c['packages']:
        require(value['files'].get('packages/' + package['filename']) == {
            'sha256': package['sha256'], 'size_bytes': package['size_bytes']}, 'package_pin_mismatch')
    for package in i2c['packages']:
        require(value['files'].get('recipe/packages/' + package['filename'])
                == value['files']['packages/' + package['filename']], 'i2c_installer_snapshot_missing')
    # The lock authenticates package hashes through previously reviewed Debian
    # InRelease provenance. Preserve the exact signed metadata/evidence locally.
    provenance = system['provenance']
    signature = provenance['signature_verification']
    require(signature['performed'] is True and signature['exit_code'] == 0, 'unauthenticated_package_lock')
    for name, metadata in (('InRelease', provenance['inrelease']), ('Packages.xz', provenance['packages_index'])):
        require(value['files'].get('provenance/' + name) == {
            'sha256': metadata['sha256'], 'size_bytes': metadata['size_bytes']}, 'package_provenance_missing')
    require(exporter.sha(exporter.ordinary(work / 'recipe/config/system-packages.lock.json'))
            == i2c['provenance']['reference_lock_sha256'], 'package_provenance_lock_mismatch')
    require(value['files'].get('provenance/Release.verified', {}).get('sha256')
            == i2c['provenance']['authenticated_release_sha256']
            and value['files'].get('provenance/signature-verification.json', {}).get('sha256')
            == i2c['provenance']['signature_verification_record_sha256'], 'package_authentication_evidence_missing')
    return value, profile, system


class Commands:
    def __call__(self, arguments, *, log=None, capture=False):
        require(type(arguments) is list and all(type(arg) is str for arg in arguments), 'invalid_command')
        if log is None:
            process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, env=ENV, start_new_session=True)
            output, _ = self.wait(process)
            return output.decode('utf-8').strip() if capture else None
        with log.open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT,
                                       env=ENV, start_new_session=True)
            self.wait(process)

    @staticmethod
    def wait(process):
        try:
            output = process.communicate(timeout=900)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
        require(process.returncode == 0, 'builder_command_failed:' + str(process.args[0]))
        return output


class MountedImage:
    """Regular private image only. Cleanup never detaches a still-mounted loop."""
    def __init__(self, work, operation, commands, *, _mounts=None):
        self.work, self.operation, self.run = work, operation, commands
        self.loop, self.mounted = None, []
        self.observe = _mounts or current_mounts

    def __enter__(self):
        image = self.work / 'candidate.img'
        trust(image)
        require(image.lstat().st_nlink == 1, 'regular_image_required')
        require(not any(os.path.lexists(self.work / name) for name in ('root', 'boot')), 'old_mountpoint_refused')
        (self.work / 'root').mkdir(mode=0o755); (self.work / 'boot').mkdir(mode=0o755)
        try:
            command = ['losetup', '--find', '--show', '--partscan']
            if self.operation == 'proposal':
                command.append('--read-only')
            selected = self.run(command + ['--', str(image)], capture=True)
            require(re.fullmatch(r'/dev/loop[0-9]+', selected), 'invalid_loop_device')
            self.loop = selected
            association = json.loads(self.run(['losetup', '--json', '--output', 'NAME,BACK-FILE,RO', self.loop], capture=True))
            rows = association['loopdevices']
            require(len(rows) == 1 and rows[0]['name'] == self.loop
                    and rows[0]['back-file'] == str(image)
                    and bool(rows[0]['ro']) == (self.operation == 'proposal'), 'loop_backing_file_mismatch')
            rows = self.run(['lsblk', '--json', '--paths', '--output', 'NAME,TYPE', self.loop], capture=True)
            rows = json.loads(rows)['blockdevices']
            require(len(rows) == 1 and rows[0]['name'] == self.loop and rows[0]['type'] == 'loop'
                    and {(row['name'], row['type']) for row in rows[0]['children']}
                    == {(self.loop + 'p1', 'part'), (self.loop + 'p2', 'part')}, 'unexpected_partition_graph')
            for suffix, filesystem, name in (('p2', 'ext4', 'root'), ('p1', 'vfat', 'boot')):
                device = self.loop + suffix
                require(self.run(['blkid', '-p', '-s', 'TYPE', '-o', 'value', device], capture=True) == filesystem,
                        'unexpected_partition_type')
                options = ('ro,noload,nosuid,nodev,noexec' if filesystem == 'ext4' else 'ro,nosuid,nodev,noexec') \
                    if self.operation == 'proposal' else 'rw,noatime,nosuid,nodev' + (',noexec' if filesystem == 'vfat' else '')
                self.run(['mount', '-t', filesystem, '-o', options, device, str(self.work / name)])
                self.mounted.append(name)
            return self
        except BaseException:
            self.close(); raise

    def device_tree(self):
        self.run(['mount', '-t', 'tmpfs', '-o', 'mode=0755,nosuid,noexec', 'tmpfs', str(self.work / 'root/dev')])
        self.mounted.append('root/dev')
        for name, minor in (('null', 3), ('zero', 5), ('random', 8), ('urandom', 9)):
            self.run(['mknod', '-m', '666', str(self.work / 'root/dev' / name), 'c', '1', str(minor)])

    def associations(self):
        image = self.work / 'candidate.img'
        trust(image)
        raw = self.run(['losetup', '--json', '--list', '--associated', str(image),
                        '--output', 'NAME,BACK-FILE,RO'], capture=True)
        require(len(raw) <= 1024 * 1024, 'loop_association_limit')
        rows = json.loads(raw)['loopdevices']
        require(type(rows) is list and len(rows) <= 1, 'ambiguous_private_image_association')
        for row in rows:
            require(re.fullmatch(r'/dev/loop[0-9]+', row['name'])
                    and row['back-file'] == str(image), 'loop_backing_file_mismatch')
        return rows

    def relevant_mounts(self, observed):
        root, boot = str(self.work / 'root'), str(self.work / 'boot')
        scoped = [row for row in observed if any(row['point'] == parent or row['point'].startswith(parent + '/')
                                                for parent in (root, boot))]
        allowed = {root: ('ext4', self.loop + 'p2' if self.loop else None),
                   boot: ('vfat', self.loop + 'p1' if self.loop else None),
                   root + '/dev': ('tmpfs', 'tmpfs')}
        for row in scoped:
            require(row['point'] in allowed and (row['type'], row['source']) == allowed[row['point']],
                    'unexpected_workspace_mount_preserve_evidence')
        if self.loop:
            devices = loop_device_ids(self.loop)
            for row in observed:
                require(not (re.fullmatch(re.escape(self.loop) + r'(?:p[0-9]+)?', row['source'])
                             or row.get('device') in devices)
                        or row in scoped, 'private_image_mounted_outside_workspace')
        return scoped

    def close(self):
        # Both mount and losetup can apply their effect before output/status is
        # lost. Observe the kernel rather than trusting append-after-command.
        try:
            rows = self.associations()
            self.loop = rows[0]['name'] if rows else None
            scoped = self.relevant_mounts(self.observe())
            names = set(self.mounted) | {str(Path(row['point']).relative_to(self.work)) for row in scoped}
            for name in sorted(names, key=lambda item: (item.count('/'), item), reverse=True):
                try:
                    self.run(['umount', str(self.work / name)])
                except BaseException:
                    # A lost successful umount is recoverable only from a fresh
                    # kernel observation; a still-mounted point blocks detach.
                    remaining = self.relevant_mounts(self.observe())
                    require(not any(row['point'] == str(self.work / name) for row in remaining),
                            'cleanup_unmount_failed')
                if name in self.mounted:
                    self.mounted.remove(name)
            require(not self.relevant_mounts(self.observe()), 'cleanup_mounts_remain')
            rows = self.associations()
            self.loop = rows[0]['name'] if rows else None
            # Recheck every namespace mount, including unexpected locations,
            # immediately before detaching the one exclusive backing file.
            require(not self.relevant_mounts(self.observe()), 'cleanup_mounts_remain')
            if self.loop:
                try:
                    self.run(['losetup', '--detach', self.loop])
                except BaseException:
                    require(not self.associations(), 'cleanup_detach_failed')
                require(not self.associations(), 'cleanup_loop_remains')
                self.loop = None
            for name in ('root', 'boot'):
                if (self.work / name).exists():
                    (self.work / name).rmdir()
        except BaseException as error:
            raise support_tool.Refused('cleanup_incomplete_preserve_private_workspace') from error

    def __exit__(self, *_):
        self.close()

    def freeze_inventory(self, prefix):
        require('root/dev' not in self.mounted, 'temporary_devices_still_mounted')
        for name in ('root', 'boot'):
            self.run(['sync', '-f', str(self.work / name)])
            options = 'remount,ro,noatime,nosuid,nodev' + (',noexec' if name == 'boot' else '')
            self.run(['mount', '-o', options, str(self.work / name)])
        manifest = inventory.build_manifest(self.work / 'root', self.work / 'boot')
        write_new(self.work / (prefix + '-filesystem.json'), manifest)
        for name in ('boot', 'root'):
            self.run(['umount', str(self.work / name)]); self.mounted.remove(name)
        self.run(['e2fsck', '-f', '-n', self.loop + 'p2'], log=self.work / (prefix + '-fsck-ext4.txt'))
        self.run(['fsck.fat', '-n', self.loop + 'p1'], log=self.work / (prefix + '-fsck-fat.txt'))


def preserved(work):
    return {name: digest_file(work / name) for name in PRESERVED}


def target(run, work, command, log):
    run(['chroot', str(work / 'root'), '/usr/bin/env', '-i', 'PATH=' + ENV['PATH'], 'LC_ALL=C',
         'DEBIAN_FRONTEND=noninteractive', 'SOURCE_DATE_EPOCH=1789430400', *command], log=work / log)


def mutate_system(work, inputs, profile, packages, mounted, run):
    root = work / 'root'
    mounted.device_tree()
    policy = root / 'usr/sbin/policy-rc.d'
    require(not os.path.lexists(policy), 'unexpected_policy_rc')
    with policy.open('xb') as stream:
        stream.write(b'#!/bin/sh\nexit 101\n'); os.fchmod(stream.fileno(), 0o755)
    scratch = root / 'var/tmp/inkyos-packages'; scratch.mkdir(mode=0o700)
    for package in packages['packages']:
        source, destination = work / 'packages' / package['filename'], scratch / package['filename']
        with source.open('rb') as src, destination.open('xb') as dst:
            shutil.copyfileobj(src, dst); os.fchmod(dst.fileno(), 0o600)
        target(run, work, ['/usr/bin/dpkg', '--install', '/var/tmp/inkyos-packages/' + package['filename']],
               'system-package-' + package['name'] + '.log')
        destination.unlink()
    scratch.rmdir()
    target(run, work, ['/usr/bin/dpkg', '--audit'], 'system-package-audit.log')
    require(exporter.ordinary(work / 'system-package-audit.log') == b'', 'dpkg_audit_failed')
    # Existing reviewed I2C delta installer; never configure TEST access scripts.
    load('install-test-access-packages.py').install(root, work / 'recipe', work)
    users = (root / 'etc/passwd').read_text().splitlines()
    require(sum(line.split(':')[:3] == ['pi', 'x', '1000'] for line in users) == 1,
            'expected_pi_uid1000')
    for index, command in enumerate((
        ['/usr/sbin/usermod', '--login', 'inky', '--home', '/home/inky', '--move-home', 'pi'],
        ['/usr/sbin/groupmod', '--new-name', 'inky', 'pi'],
        ['/usr/sbin/usermod', '--groups', 'spi,i2c,gpio', '--shell', '/usr/sbin/nologin', '--lock', 'inky'])):
        target(run, work, command, 'account-' + str(index) + '.log')
    with configuration_umask():
        passive = load('factory-passive-profile.py')
        metadata = passive.metadata(profile['input_manifest_sha256'], profile)
        load('configure-rootfs.py').configure(root, work / 'boot', work / 'recipe', factory=metadata)
        load('factory-assembly-profile.py').prepare_rootfs(work)
        prerequisites = load('configure-factory-active-prerequisites.py')
        write_new(work / 'factory-account-prerequisites.json', prerequisites.configure(root, 980, 980))
        write_new(work / 'factory-active-static.json', load('configure-factory-active-profile.py').stage(
            root, trigger_sha256=inputs['trigger_sha256']))
        # The generic configurator's factory argument only controls safe WLAN state.
        # Publish an honest active identity before the support inventory is proposed.
        release_path = root / 'etc/inkyos-release.json'
        release = json_file(release_path)
        require(release['kind'] == 'factory-passive' and release['factory'] == metadata,
                'unexpected_intermediate_release')
        release.update(kind='factory-active', factory={'schema_version': 1, 'kind': 'factory-active-profile',
                       'studio_commit': profile['studio_commit'], 'startup': 'factory-start-trigger',
                       'input_manifest_sha256': exporter.sha(exporter.ordinary(work / 'factory-active-inputs.json'))},
                       runtime_qualified=False, hardware_qualified=False)
        load('configure-rootfs.py').Tree(root).write('etc/inkyos-release.json', canonical(release).decode())
    require(policy.read_bytes() == b'#!/bin/sh\nexit 101\n', 'policy_rc_changed')
    policy.unlink()
    run(['umount', str(root / 'dev')]); mounted.mounted.remove('root/dev')


def generic_static(work, packages):
    tool = load('verify-prototype.py')
    result = tool.verify(work / 'root', work / 'boot', packages)
    adapted = {'RELEASE_METADATA', 'NETWORKMANAGER_GENERIC_STATE', 'EMPTY_VAR_LIB_INKYOS'}
    require(not set(result['failed_checks']) - adapted, 'generic_static_checks_failed:' + ','.join(result['failed_checks']))
    root = work / 'root'
    release = json_file(root / 'etc/inkyos-release.json')
    require(release['kind'] == 'factory-active' and release['hardware_qualified'] is False
            and release['runtime_qualified'] is False, 'active_release_missing')
    tree = tool.inspection.SafeTree(root)
    try:
        require(tool.nm_state_contract(tree, enabled=False), 'wlan_not_closed')
        require(tree.read('etc/machine-id', 256) == 'uninitialized\n', 'runtime_identity_present')
        for path in ('var/lib/inkyos/initialization', 'var/lib/inkyos/system.json',
                     'var/lib/inkyos/system-setup/ready.json'):
            require(tool.missing(tree, path), 'runtime_state_present')
        require(not any(token.startswith('cfg80211.ieee80211_regdom=')
                        for token in (work / 'boot/cmdline.txt').read_text().split()), 'preseeded_country')
    finally:
        tree.close()
    result.update(scope='offline-factory-active-system-contract', passed=True,
                  adapted_checks=sorted(adapted), hardware_qualified=False)
    return result


def prepared_receipt(work, pin, receipt_pin):
    value = json_file(work / 'prepared-receipt.json', receipt_pin)
    require(value.get('kind') == 'factory-active-prepared-image' and value.get('input_manifest_sha256') == pin
            and value.get('exportable_image') is False and value.get('hardware_qualified') is False
            and digest_file(work / 'candidate.img') == value.get('image'), 'prepared_image_mismatch')
    require(digest_file(work / 'prepare-filesystem.json')['sha256'] == value['filesystem_manifest_sha256'],
            'prepared_inventory_mismatch')
    for name, expected in value.get('reports', {}).items():
        exporter.name(name)
        require('/' not in name and digest_file(work / name) == expected, 'prepared_report_mismatch')
    return value


def review_inputs(work, pin, prepared_pin):
    trust(work / 'review', directory=True, private=True)
    for name in ('review.json', 'support.json', 'exporter.lock.json', 'evidence.json'):
        trust(work / 'review' / name)
    review = json_file(work / 'review/review.json', pin)
    require(type(review) is dict and set(review) == REVIEW_FIELDS and review['schema_version'] == 1
            and review['kind'] == 'factory-support-independent-review'
            and review['prepared_receipt_sha256'] == prepared_pin
            and all(type(review[key]) is str and HASH.fullmatch(review[key])
                    for key in REVIEW_FIELDS - {'kind', 'schema_version'}), 'invalid_independent_review')
    proposal = json_file(work / 'support-proposal.json', review['proposal_sha256'])
    support = json_file(work / 'review/support.json', review['support_manifest_sha256'])
    lock = json_file(work / 'review/exporter.lock.json', review['exporter_lock_sha256'])
    initial = json_file(work / 'exporter-inputs/lock.json')
    require({k: v for k, v in support.items() if k != 'elf_closure_review'} == proposal['support_candidate'],
            'review_does_not_match_proposed_inventory')
    require(support['elf_closure_review']['evidence_sha256'] == review['evidence_sha256']
            and digest_file(work / 'review/evidence.json')['sha256'] == review['evidence_sha256'],
            'review_evidence_pin_mismatch')
    require(lock == {**initial, 'support_manifest_sha256': review['support_manifest_sha256']},
            'review_exporter_inputs_changed')
    exporter.load_lock(work / 'review/exporter.lock.json', expected_sha256=review['exporter_lock_sha256'])
    exporter.load_support(lock, work / 'review/support.json')
    return review, lock


def compose(work, operation, *, inputs_sha256, prepared_sha256=None, review_sha256=None, _commands=None):
    workspace(work)
    require(private_namespaces(), 'private_mount_net_uts_namespaces_required')
    run = _commands or Commands()
    inputs, profile, packages = verified_inputs(work, inputs_sha256)
    require(not os.path.lexists(work / 'candidate-receipt.json'), 'candidate_already_finalized')
    if operation == 'prepare':
        require(prepared_sha256 is review_sha256 is None
                and not os.path.lexists(work / 'prepared-receipt.json')
                and not os.path.lexists(work / 'candidate.img'), 'fresh_prepare_required')
        with (work / 'base.img').open('rb') as source, (work / 'candidate.img').open('xb') as target_file:
            os.fchmod(target_file.fileno(), 0o600); shutil.copyfileobj(source, target_file)
            target_file.flush(); os.fsync(target_file.fileno())
        require(digest_file(work / 'candidate.img') == inputs['files']['base.img'], 'base_copy_mismatch')
        with MountedImage(work, operation, run) as mounted:
            initial_preserved = preserved(work)
            mutate_system(work, inputs, profile, packages, mounted, run)
            require(preserved(work) == initial_preserved, 'boot_resize_or_fstab_changed')
            write_new(work / 'prepare-system-verification.json', generic_static(work, packages))
            mounted.freeze_inventory('prepare')
        verified_inputs(work, inputs_sha256)
        receipt = {'schema_version': 1, 'kind': 'factory-active-prepared-image',
                   'input_manifest_sha256': inputs_sha256, 'image': digest_file(work / 'candidate.img'),
                   'filesystem_manifest_sha256': digest_file(work / 'prepare-filesystem.json')['sha256'],
                   'preserved': initial_preserved, 'reports': report_pins(work),
                   'exportable_image': False, 'hardware_qualified': False}
        write_new(work / 'prepared-receipt.json', receipt)
        return receipt
    require(operation in ('proposal', 'finalize') and prepared_sha256 is not None, 'invalid_operation')
    prepared = prepared_receipt(work, inputs_sha256, prepared_sha256)
    require(not os.path.lexists(work / 'finalize-started.json'), 'partial_finalize_cannot_be_retried')
    if operation == 'proposal':
        require(review_sha256 is None and not os.path.lexists(work / 'support-proposal.json'), 'new_proposal_required')
        with MountedImage(work, operation, run):
            require(inventory.build_manifest(work / 'root', work / 'boot') == json_file(work / 'prepare-filesystem.json'),
                    'prepared_filesystems_changed')
            args = {'rootfs': work / 'root', 'policy': work / 'support-policy.json',
                    'provenance': work / 'support-provenance.json',
                    'app_manifest': work / 'factory-inputs/factory-bundle-manifest.json',
                    'exporter_lock': work / 'exporter-inputs/lock.json',
                    'sources_dir': work / 'exporter-inputs/sources', 'wheels_dir': work / 'exporter-inputs/wheels',
                    'readelf': Path(inputs['readelf']['path']), 'readelf_sha256': inputs['readelf']['sha256']}
            for name in ('policy', 'provenance', 'app_manifest', 'exporter_lock'):
                args[name + '_sha256'] = digest_file(args[name])['sha256']
            proposal = support_tool.plan(**args)
        require(digest_file(work / 'candidate.img') == prepared['image'], 'proposal_mutated_image')
        verified_inputs(work, inputs_sha256)
        write_new(work / 'support-proposal.json', proposal)
        return proposal
    require(review_sha256 is not None, 'independent_review_required')
    review, lock = review_inputs(work, review_sha256, prepared_sha256)
    # Persist an explicit no-retry fence before the first writable remount.
    write_new(work / 'finalize-started.json', {'review_sha256': review_sha256, 'prepared_sha256': prepared_sha256})
    with MountedImage(work, operation, run) as mounted:
        require(inventory.build_manifest(work / 'root', work / 'boot') == json_file(work / 'prepare-filesystem.json'),
                'prepared_filesystems_changed')
        root = work / 'root'
        destination = root / support_tool.runtime.SUPPORT
        require(not os.path.lexists(destination), 'support_already_installed')
        destination.parent.mkdir(exist_ok=True, mode=0o755)
        with destination.open('xb') as stream:
            stream.write(exporter.ordinary(work / 'review/support.json')); os.fchmod(stream.fileno(), 0o644)
        mounted.device_tree()
        arguments = SimpleNamespace(rootfs=root, sources_dir=work / 'exporter-inputs/sources',
            wheels_dir=work / 'exporter-inputs/wheels', support_manifest=work / 'review/support.json',
            output=work / 'factory-exporter-installation.json', lock=work / 'review/exporter.lock.json',
            lock_sha256=review['exporter_lock_sha256'])
        load('install-factory-exporter-rootfs.py').install(arguments)
        run(['umount', str(root / 'dev')]); mounted.mounted.remove('root/dev')
        exporter_report = exporter.verify(root, lock, arguments.sources_dir, arguments.wheels_dir, arguments.support_manifest)
        write_new(work / 'factory-exporter-verification.json', exporter_report)
        planner = load('plan-factory-runtime-manifest.py')
        raw, report = planner.plan(root, bundle_sha256=profile['bundle_manifest_sha256'],
            exporter_sha256=exporter_report['bundle_manifest_sha256'],
            support_sha256=review['support_manifest_sha256'], helper_uid=980, provisioning_gid=980)
        plan_file = work / 'factory-runtime-plan.json'
        with plan_file.open('xb') as stream:
            stream.write(raw); os.fchmod(stream.fileno(), 0o600)
        write_new(work / 'factory-runtime-plan-receipt.json', report)
        write_new(work / 'factory-runtime-installation.json', load('configure-factory-active-profile.py').install_runtime(
            root, plan_file=plan_file, plan_sha256=exporter.sha(raw)))
        support_tool.runtime.verify_candidate(support_tool.runtime.load_contract(_root=root))
        require(preserved(work) == prepared['preserved'], 'boot_resize_or_fstab_changed')
        write_new(work / 'finalize-system-verification.json', generic_static(work, packages))
        mounted.freeze_inventory('finalize')
    verified_inputs(work, inputs_sha256)
    review_inputs(work, review_sha256, prepared_sha256)
    receipt = {'schema_version': 1, 'kind': 'factory-active-image-candidate', 'image': digest_file(work / 'candidate.img'),
               'input_manifest_sha256': inputs_sha256, 'prepared_receipt_sha256': prepared_sha256,
               'independent_review_sha256': review_sha256,
               'filesystem_manifest_sha256': digest_file(work / 'finalize-filesystem.json')['sha256'],
               'reports': report_pins(work), 'image_code_executed': True, 'application_code_executed': False,
               'exportable_image': True, 'runtime_file_contract_verified': True,
               'boot_qualified': False, 'hardware_qualified': False, 'release_qualified': False}
    write_new(work / 'candidate-receipt.json', receipt)
    return receipt


def report_pins(work):
    """Bind all completed root-level logs/reports, excluding staged inputs/images."""
    return {path.name: digest_file(path) for path in sorted(work.iterdir())
            if path.is_file() and path.suffix in ('.json', '.txt', '.log')
            and path.name not in SNAPSHOT_FILES | {'candidate-receipt.json'}}


def main(argv=None):
    args_list = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'proposal', 'finalize'))
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--inputs-sha256', required=True)
    parser.add_argument('--prepared-sha256')
    parser.add_argument('--review-sha256')
    args = vars(parser.parse_args(args_list))
    def terminate(_signal, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, terminate)
    try:
        workspace(args['work'])
        if not private_namespaces():
            command = ['unshare', '--mount', '--net', '--uts', '--propagation', 'private', '--',
                       sys.executable, '-I', '-B', '-S', str(Path(__file__).absolute()), *args_list]
            os.execvpe(command[0], command, ENV)
        result = compose(**args)
        print(json.dumps({'kind': result['kind'], 'exportable_image': result.get('exportable_image', False),
                          'hardware_qualified': False}, sort_keys=True))
        return 2 if args['operation'] == 'proposal' and not result['elf_observations']['complete_without_conflicts'] else 0
    except (OSError, ValueError, TypeError, KeyError, inventory.ManifestError, subprocess.SubprocessError) as error:
        print('factory_active_image_refused:' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
