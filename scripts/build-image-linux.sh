#!/usr/bin/env bash
# Mutate only the verified prototype.img copy in the dedicated Lima builder.
set -Eeuo pipefail
umask 077
[[ $# == 1 && $(uname -s) == Linux && $(uname -m) == aarch64 && $EUID == 0 ]] || {
  echo 'Usage: sudo bash build-image-linux.sh /var/tmp/inkyos-work/prototype.XXXXXXXX' >&2; exit 2;
}
[[ $(cat /var/lib/inkyos-build/owner) == inkyos-builder-v1 ]] || exit 2
work=$(readlink -e -- "$1")
[[ $work =~ ^/var/tmp/inkyos-work/prototype\.[a-zA-Z0-9]+$ && ! -L $1 ]] || {
  echo 'Only a dedicated prototype work directory is accepted.' >&2; exit 2;
}
# No target command can use the builder network, its mounts or its UTS hostname.
if [[ ${INKYOS_PRIVATE_NAMESPACE:-} != 1 ]]; then
  exec unshare --mount --net --uts --propagation private \
    env INKYOS_PRIVATE_NAMESPACE=1 bash "$0" "$work"
fi
cd "$work"
[[ -f prototype.img && ! -L prototype.img && ! -e root && ! -e boot ]] || exit 2
python3 - <<'PY'
import hashlib,json,os,stat
base=json.load(open('recipe/config/base-image.lock.json'))['image']
info=os.stat('prototype.img',follow_symlinks=False)
assert stat.S_ISREG(info.st_mode) and info.st_nlink==1
assert info.st_size==base['extracted_size_bytes']
with open('prototype.img','rb') as f:
    assert hashlib.file_digest(f,'sha256').hexdigest()==base['extracted_sha256'], 'Base hash mismatch'
lock=json.load(open('recipe/config/system-packages.lock.json'))
assert lock['base_image_sha256']==base['extracted_sha256']
for p in lock['packages']:
    name=p['filename']
    assert '/' not in name and name.endswith('.deb')
    path='packages/'+name
    info=os.stat(path,follow_symlinks=False)
    assert stat.S_ISREG(info.st_mode) and info.st_size==p['size_bytes']
    with open(path,'rb') as f:
        assert hashlib.file_digest(f,'sha256').hexdigest()==p['sha256'], 'Package hash mismatch'
PY
loop=
root_mounted=0
boot_mounted=0
dev_mounted=0
cleanup() {
  local status=$? failed=0
  trap - EXIT INT TERM
  if (( dev_mounted )); then umount "$work/root/dev" && dev_mounted=0 || failed=1; fi
  if (( boot_mounted )); then umount "$work/boot" && boot_mounted=0 || failed=1; fi
  if (( root_mounted && !dev_mounted )); then umount "$work/root" && root_mounted=0 || failed=1; fi
  if [[ -n $loop ]] && (( !root_mounted && !boot_mounted )); then losetup -d "$loop" || failed=1; fi
  if (( !root_mounted && !boot_mounted )); then rmdir "$work/root" "$work/boot" 2>/dev/null || true; fi
  if (( failed )); then echo "Cleanup incomplete in $work; no forced detach attempted." >&2; status=1; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir root boot
loop=$(losetup --find --show --partscan -- prototype.img)
[[ $loop =~ ^/dev/loop[0-9]+$ ]] || exit 1
for attempt in {1..20}; do
  [[ -b ${loop}p1 && -b ${loop}p2 ]] && break
  sleep 0.1
done
[[ $(lsblk -nr -o TYPE "$loop" | wc -l) == 3 ]] || exit 1
[[ $(blkid -p -s TYPE -o value "${loop}p1") == vfat ]] || exit 1
[[ $(blkid -p -s TYPE -o value "${loop}p2") == ext4 ]] || exit 1
mount -t ext4 -o rw,noatime,nosuid,nodev "${loop}p2" root
root_mounted=1
mount -t vfat -o rw,noatime,nosuid,nodev,noexec "${loop}p1" boot
boot_mounted=1
sha256sum boot/cmdline.txt boot/initramfs8 boot/initramfs_2712 boot/kernel8.img boot/kernel_2712.img \
  root/etc/fstab root/usr/lib/systemd/system/rpi-resize.service \
  root/usr/lib/systemd/system/systemd-growfs-root.service \
  root/usr/share/initramfs-tools/scripts/local-premount/resize_early \
  root/usr/share/initramfs-tools/scripts/local-bottom/set_partuuid > boot-preserved.sha256
# Temporary /dev is fabricated; no builder disks/devices are exposed to chroot.
mount -t tmpfs -o mode=0755,nosuid tmpfs root/dev
dev_mounted=1
mknod -m 666 root/dev/null c 1 3
mknod -m 666 root/dev/zero c 1 5
mknod -m 666 root/dev/random c 1 8
mknod -m 666 root/dev/urandom c 1 9
[[ ! -e root/usr/sbin/policy-rc.d && ! -L root/usr/sbin/policy-rc.d ]] || {
  echo 'Unexpected policy-rc.d in the pinned base.' >&2; exit 1;
}
printf '#!/bin/sh\nexit 101\n' > root/usr/sbin/policy-rc.d
chmod 755 root/usr/sbin/policy-rc.d
install -d -m 700 root/var/tmp/inkyos-packages
while IFS= read -r package; do
  install -m 600 "packages/$package" "root/var/tmp/inkyos-packages/$package"
  chroot root /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    DEBIAN_FRONTEND=noninteractive SOURCE_DATE_EPOCH=1789430400 \
    /usr/bin/dpkg --install "/var/tmp/inkyos-packages/$package"
  rm -- "root/var/tmp/inkyos-packages/$package"
done < <(python3 -c 'import json; print("\n".join(p["filename"] for p in json.load(open("recipe/config/system-packages.lock.json"))["packages"]))')
rmdir root/var/tmp/inkyos-packages
chroot root /usr/bin/dpkg --audit > dpkg-audit.txt
[[ ! -s dpkg-audit.txt ]] || { cat dpkg-audit.txt >&2; exit 1; }
# Preserve UID/GID 1000 ownership but remove every inherited supplementary grant.
[[ $(chroot root /usr/bin/id -u pi) == 1000 ]] || exit 1
chroot root /usr/sbin/usermod --login inky --home /home/inky --move-home pi
chroot root /usr/sbin/groupmod --new-name inky pi
chroot root /usr/sbin/usermod --groups spi,i2c,gpio --shell /usr/sbin/nologin --lock inky
chroot root /usr/bin/id inky
python3 recipe/scripts/configure-rootfs.py --rootfs "$work/root" --bootfs "$work/boot" \
  --recipe "$work/recipe"
# Imports only: no D-Bus connection, no daemon or application startup.
chroot root /usr/bin/env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 \
  /usr/bin/python3 -c 'import dbus; print("python3-dbus import OK")'
chroot root /usr/bin/systemd-analyze verify inkyos-firstboot.service \
  NetworkManager.service avahi-daemon.service bluetooth.service rpi-resize.service \
  > systemd-verify.txt 2>&1 || { cat systemd-verify.txt >&2; exit 1; }
rm -- root/usr/sbin/policy-rc.d
python3 recipe/scripts/verify-prototype.py --rootfs "$work/root" --bootfs "$work/boot" \
  --output "$work/qualification-static.json"
sha256sum --check --strict boot-preserved.sha256
umount root/dev
dev_mounted=0
sync -f root
sync -f boot
# Freeze the prepared filesystems before the complete metadata inventory.
mount -o remount,ro,noatime,nosuid,nodev root
mount -o remount,ro,noatime,nosuid,nodev,noexec boot
python3 recipe/scripts/manifest-rootfs.py --rootfs "$work/root" --bootfs "$work/boot" \
  --output "$work/filesystem-manifest.json"
umount boot
boot_mounted=0
umount root
root_mounted=0
e2fsck -fn "${loop}p2" > fsck-ext4.txt 2>&1 || { cat fsck-ext4.txt >&2; exit 1; }
fsck.fat -n "${loop}p1" > fsck-fat.txt 2>&1 || { cat fsck-fat.txt >&2; exit 1; }
# EXIT trap unmounts before the host-side wrapper hashes/exports the image.
echo 'System prototype customized and static gates passed; no Pi boot performed.'
