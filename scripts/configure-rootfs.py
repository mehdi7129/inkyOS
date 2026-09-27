#!/usr/bin/env python3
"""Apply the reviewed static delta to a verified, privately mounted base copy.

This command does not create runtime identities or start target services.
Account/package mutations are performed separately by build-image-linux.sh.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat


MASKED_UNITS = (
    'cloud-init-local.service', 'cloud-init-network.service',
    'cloud-config.service', 'cloud-final.service', 'cloud-init.target',
    'userconfig.service', 'systemd-firstboot.service', 'sshswitch.service',
    'ssh.service', 'ssh.socket',
    'regenerate_ssh_host_keys.service', 'sshd-keygen.service',
    'NetworkManager-wait-online.service',
)
NETWORK_UNITS = ('NetworkManager.service', 'avahi-daemon.service', 'bluetooth.service')
OVERLAY_FILES = (
    'usr/local/lib/inkyos/firstboot.py',
    'etc/systemd/system/inkyos-firstboot.service',
)


class Tree:
    """Reject links in all parents; the private build has no concurrent writers."""
    def __init__(self, root):
        self.root = Path(root)
        if self.root.is_symlink() or not self.root.is_dir():
            raise ValueError('Root must be a real directory')

    def path(self, relative, create_parents=False):
        parts = PurePosixPath(relative).parts
        if not parts or '..' in parts or PurePosixPath(relative).is_absolute():
            raise ValueError('Unsafe relative path')
        current = self.root
        for part in parts[:-1]:
            current = current / part
            if create_parents and not current.exists() and not current.is_symlink():
                current.mkdir(mode=0o755)
            info = current.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError('Symlink or special parent refused')
        return current / parts[-1]

    def read(self, relative, absent=None):
        p = self.path(relative)
        try:
            info = p.lstat()
        except FileNotFoundError:
            return absent
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('Expected an unlinked regular configuration file')
        return p.read_text()

    def write(self, relative, content, mode=0o644):
        p = self.path(relative, create_parents=True)
        if p.exists() or p.is_symlink():
            self.read(relative)  # Includes a hard-link check before truncation.
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, 'w') as stream:
            stream.write(content)
            os.fchmod(stream.fileno(), mode)

    def remove(self, relative):
        p = self.path(relative)
        if p.exists() or p.is_symlink():
            self.read(relative)
            p.unlink()

    def link(self, relative, target):
        p = self.path(relative, create_parents=True)
        if p.is_symlink():
            p.unlink()
        elif p.exists():
            raise ValueError('Refusing to replace a real file with a unit link')
        p.symlink_to(target)


def configure(root, boot, recipe):
    root, boot, recipe = Tree(root), Tree(boot), Tree(recipe)
    # Leave the first-boot resize contract untouched, including machine-id.
    if root.read('etc/machine-id') != 'uninitialized\n':
        raise ValueError('Expected a pristine systemd first boot')
    cmdline = boot.read('cmdline.txt')
    if 'resize' not in cmdline.split():
        raise ValueError('Pinned Raspberry Pi first-boot resize hook missing')
    users = [line.split(':') for line in root.read('etc/passwd').splitlines()]
    if (any(len(row) != 7 or row[0] == 'pi' for row in users)
            or sum(row[0] == 'inky' and row[2] == '1000' for row in users) != 1):
        raise ValueError('Account preparation incomplete')
    for relative in OVERLAY_FILES:
        root.write(relative, recipe.read('overlay/' + relative))
    root.link('etc/systemd/system/multi-user.target.wants/inkyos-firstboot.service',
              '/etc/systemd/system/inkyos-firstboot.service')
    for unit in MASKED_UNITS:
        root.link('etc/systemd/system/' + unit, '/dev/null')
    for unit in NETWORK_UNITS:
        root.write('etc/systemd/system/' + unit + '.d/10-inkyos-firstboot.conf',
                   '[Unit]\nRequires=inkyos-firstboot.service\nAfter=inkyos-firstboot.service\n')
    root.write('etc/cloud/cloud-init.disabled', '')
    for name in ('user-data', 'network-config', 'meta-data'):
        boot.remove(name)
    root.remove('etc/ssh/sshd_config.d/rename_user.conf')
    for name in ('subuid', 'subgid'):
        content = root.read('etc/' + name, '')
        root.write('etc/' + name, ''.join(line + '\n' for line in content.splitlines()
                                        if line.split(':', 1)[0] not in ('pi', 'inky')))
    # Backups from usermod/dpkg contain only official generic state but would
    # misleadingly retain the old account or introduce build-time timestamps.
    for name in ('passwd-', 'shadow-', 'group-', 'gshadow-', 'subuid-', 'subgid-'):
        root.remove('etc/' + name)
    root.remove('var/log/dpkg.log')
    root.write('etc/hostname', 'inky-unconfigured\n')
    hosts = root.read('etc/hosts')
    kept = [line for line in hosts.splitlines()
            if not line.split('#', 1)[0].split()[:1] == ['127.0.1.1']]
    root.write('etc/hosts', '\n'.join(kept) + '\n127.0.1.1\tinky-unconfigured\n')
    nm = root.read('var/lib/NetworkManager/NetworkManager.state')
    if 'WirelessEnabled=false' not in nm:
        raise ValueError('Unexpected base NetworkManager state')
    root.write('var/lib/NetworkManager/NetworkManager.state',
               nm.replace('WirelessEnabled=false', 'WirelessEnabled=true'), mode=0o600)
    root.write('etc/modules-load.d/inkyos.conf', 'i2c-dev\n')
    base_config = boot.read('config.txt')
    if 'include inkyos.txt' in base_config:
        raise ValueError('Base already customized')
    boot.write('config.txt', base_config.rstrip() + '\n\n[all]\ninclude inkyos.txt\n')
    boot.write('inkyos.txt', '# InkyOS system prototype: hardware still to qualify\n'
               '[all]\ndtparam=i2c_arm=on\ndtparam=spi=on\ndtoverlay=spi0-0cs\n')
    base = json.loads(recipe.read('config/base-image.lock.json'))
    packages = json.loads(recipe.read('config/system-packages.lock.json'))
    inputs = json.loads(recipe.read('recipe-inputs.json'))
    release = {'schema_version': 1, 'kind': 'system-prototype', 'application': None,
               'status': 'not-hardware-qualified',
               'base_image_sha256': base['image']['extracted_sha256'],
               'packages': [{k: p[k] for k in ('name', 'version', 'architecture', 'sha256')}
                            for p in packages['packages']], 'recipe_inputs': inputs}
    root.write('etc/inkyos-release.json', json.dumps(release, indent=2, sort_keys=True) + '\n')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--rootfs', required=True)
    p.add_argument('--bootfs', required=True)
    p.add_argument('--recipe', required=True)
    a = p.parse_args()
    if os.geteuid() != 0:
        p.error('Run only through the isolated Linux image builder')
    configure(a.rootfs, a.bootfs, a.recipe)


if __name__ == '__main__':
    main()
