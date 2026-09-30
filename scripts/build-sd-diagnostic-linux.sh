#!/usr/bin/env bash
# Root inside the marked ARM64 builder only; operates on a new regular image copy.
set -Eeuo pipefail
umask 077
[[ $# == 1 && $(uname -s) == Linux && $(uname -m) == aarch64 && $EUID == 0 ]] || {
  echo 'Usage: sudo bash build-sd-diagnostic-linux.sh /var/tmp/inkyos-work/sd-diagnostic.XXXXXXXX' >&2; exit 2;
}
[[ $(cat /var/lib/inkyos-build/owner) == inkyos-builder-v1 ]] || exit 2
work=$(readlink -e -- "$1")
[[ $work =~ ^/var/tmp/inkyos-work/sd-diagnostic\.[a-zA-Z0-9]{8}$ && ! -L $1 ]] || exit 2
if [[ ${INKYOS_PRIVATE_NAMESPACE:-} != 1 ]]; then
  exec unshare --mount --net --uts --propagation private \
    env INKYOS_PRIVATE_NAMESPACE=1 bash "$0" "$work"
fi
for namespace in mnt net uts; do
  [[ $(readlink "/proc/self/ns/$namespace") != $(readlink "/proc/1/ns/$namespace") ]] || {
    echo 'Private build namespaces were not established.' >&2; exit 2;
  }
done
[[ $(findmnt -n -o PROPAGATION /) == private ]] || exit 2
cd "$work"
[[ -f diagnostic.img && ! -L diagnostic.img && ! -e root && ! -e boot ]] || exit 2
python3 - <<'PY'
import hashlib, json, os, pathlib, stat
work = pathlib.Path('.')
info = work.stat(); assert info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700
interfaces = [line.split(':', 1)[0].strip() for line in pathlib.Path('/proc/net/dev').read_text().splitlines()[2:]]
assert interfaces == ['lo'], 'Build network namespace must expose only loopback'
recipe = json.load(open('recipe/recipe-inputs.json'))
for name, digest in recipe['files'].items():
    relative = pathlib.PurePosixPath(name)
    assert not relative.is_absolute() and '..' not in relative.parts and str(relative) == name
    path = pathlib.Path('recipe') / name
    for parent in path.parents:
        info = parent.lstat(); assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0 and not info.st_mode & 0o022
    with path.open('rb') as stream:
        assert hashlib.file_digest(stream, 'sha256').hexdigest() == digest, 'Recipe hash mismatch'
parent = json.load(open('recipe/parent-manifest.json'))
assert parent['kind'] == 'application-prototype' and parent['hardware_qualified'] is False
assert parent['application']['startup'] == 'masked-pending-firstboot-contract'
image = pathlib.Path('diagnostic.img'); info = image.lstat()
assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0 and not info.st_mode & 0o022
assert info.st_size == parent['image']['size_bytes']
with image.open('rb') as stream:
    assert hashlib.file_digest(stream, 'sha256').hexdigest() == parent['image']['sha256'], 'Parent image hash mismatch'
PY
parent_sha256=$(python3 -c 'import json; print(json.load(open("recipe/parent-manifest.json"))["image"]["sha256"])')
application_sha256=$(python3 -c 'import json; print(json.load(open("recipe/parent-manifest.json"))["application"]["manifest_sha256"])')
loop=
root_mounted=0
boot_mounted=0
cleanup() {
  local status=$? failed=0
  trap - EXIT INT TERM
  if (( boot_mounted )); then umount "$work/boot" && boot_mounted=0 || failed=1; fi
  if (( root_mounted )); then umount "$work/root" && root_mounted=0 || failed=1; fi
  if [[ -n $loop ]] && (( !root_mounted && !boot_mounted )); then losetup -d "$loop" || failed=1; fi
  if (( !root_mounted && !boot_mounted )); then rmdir "$work/root" "$work/boot" 2>/dev/null || true; fi
  if (( failed )); then echo "Cleanup incomplete in $work; no forced detach attempted." >&2; status=1; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir root boot
loop=$(losetup --find --show --partscan -- diagnostic.img)
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
python3 recipe/scripts/configure-diagnostic-rootfs.py --rootfs "$work/root" --bootfs "$work/boot" \
  --recipe "$work/recipe" --parent-sha256 "$parent_sha256" --output "$work/diagnostic-configuration.json"
# Syntax/dependency inspection only. No target service or package installer starts.
chroot root /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  /usr/bin/systemd-analyze verify inkyos-sd-diagnostic.service inkyos-sd-diagnostic.timer \
  > systemd-verify.txt 2>&1 || { cat systemd-verify.txt >&2; exit 1; }
python3 recipe/scripts/verify-prototype.py --rootfs "$work/root" --bootfs "$work/boot" \
  --application-manifest "$work/recipe/application-manifest.json" --application-sha256 "$application_sha256" \
  --output "$work/qualification-static.json"
python3 recipe/scripts/verify-application-rootfs.py --rootfs "$work/root" \
  --manifest "$work/recipe/application-manifest.json" --sha256 "$application_sha256" \
  --output "$work/qualification-application.json"
sha256sum --check --strict boot-preserved.sha256
sync -f root
sync -f boot
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
losetup -d "$loop"
loop=
rmdir root boot
bash recipe/scripts/inspect-image.sh "$work/diagnostic.img" "$work/image-inspection.json"
echo 'Diagnostic image static gates passed; no Pi boot, application start or SD operation performed.'
