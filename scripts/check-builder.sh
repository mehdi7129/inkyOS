#!/usr/bin/env bash
# Exercise Linux capabilities using temporary files inside our dedicated builder.
set -Eeuo pipefail

if [[ $(uname -s) != Linux || $(uname -m) != aarch64 || $EUID != 0 ]]; then
  echo 'Run as root inside the dedicated ARM64 Linux builder.' >&2
  exit 1
fi
if [[ ! -f /var/lib/inkyos-build/owner ]] ||
   [[ $(cat /var/lib/inkyos-build/owner) != inkyos-builder-v1 ]]; then
  echo 'This machine is not marked as the InkyOS builder.' >&2
  exit 1
fi
for tool in losetup mount umount mkfs.ext4 mkfs.vfat chroot python3 busybox; do
  command -v "$tool" >/dev/null || { echo "Missing builder tool: $tool" >&2; exit 1; }
done

scratch=$(mktemp -d /var/tmp/inkyos-preflight.XXXXXXXX)
ext_loop=''
fat_loop=''
cleanup() {
  local status=$?
  trap - EXIT
  if mountpoint -q "$scratch/ext"; then umount "$scratch/ext" || status=1; fi
  if mountpoint -q "$scratch/fat"; then umount "$scratch/fat" || status=1; fi
  if [[ -n $ext_loop ]]; then losetup -d "$ext_loop" || status=1; fi
  if [[ -n $fat_loop ]]; then losetup -d "$fat_loop" || status=1; fi
  if ! mountpoint -q "$scratch/ext" && ! mountpoint -q "$scratch/fat"; then
    rm -rf -- "$scratch"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$scratch/ext" "$scratch/fat" "$scratch/root/bin"
truncate -s 32M "$scratch/ext.img"
truncate -s 8M "$scratch/fat.img"
mkfs.ext4 -q -F "$scratch/ext.img"
mkfs.vfat "$scratch/fat.img" >/dev/null
ext_loop=$(losetup --find --show --read-only "$scratch/ext.img")
fat_loop=$(losetup --find --show --read-only "$scratch/fat.img")
mount -t ext4 -o ro,noload "$ext_loop" "$scratch/ext"
mount -t vfat -o ro "$fat_loop" "$scratch/fat"
[[ $(blockdev --getro "$ext_loop") == 1 && $(blockdev --getro "$fat_loop") == 1 ]]
cp "$(command -v busybox)" "$scratch/root/bin/busybox"
[[ $(chroot "$scratch/root" /bin/busybox uname -m) == aarch64 ]]

python3 - <<'PY'
import json
import platform
import subprocess

packages = ['python3', 'xz-utils', 'util-linux', 'mount', 'e2fsprogs',
            'dosfstools', 'fdisk', 'parted', 'busybox-static', 'rsync']
versions = {}
for name in packages:
    versions[name] = subprocess.check_output(
        ['dpkg-query', '-W', '-f=${Version}', name], text=True).strip()
print(json.dumps({
    'schema_version': 1,
    'scope': 'builder-capabilities-only',
    'machine': platform.machine(),
    'kernel': platform.release(),
    'checks': {'readonly_loop': 'pass', 'ext4_mount': 'pass',
               'fat_mount': 'pass', 'native_arm64_chroot': 'pass'},
    'packages': versions,
    'hardware_qualification': False,
}, indent=2, sort_keys=True))
PY
