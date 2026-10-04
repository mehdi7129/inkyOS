#!/usr/bin/env bash
# Build a PRIVATE access copy; never invoke its firstboot or key generator.
set -Eeuo pipefail
umask 077
[[ $# == 1 && $(uname -s) == Linux && $(uname -m) == aarch64 && $EUID == 0 ]] || exit 2
[[ $(cat /var/lib/inkyos-build/owner) == inkyos-builder-v1 ]] || exit 2
work=$(readlink -e -- "$1")
[[ $work == "$1" && $work =~ ^/var/tmp/inkyos-work/test-access\.[a-zA-Z0-9]{8}$ ]] || exit 2
[[ $(readlink -e -- "$0") == "$work/recipe/scripts/build-test-access-linux.sh" ]] || exit 2
if [[ ${INKYOS_ACCESS_NAMESPACE:-} != 1 ]]; then
  exec unshare --mount --net --uts --propagation private \
    env INKYOS_ACCESS_NAMESPACE=1 bash "$0" "$work"
fi
for namespace in mnt net uts; do
  [[ $(readlink "/proc/self/ns/$namespace") != $(readlink "/proc/1/ns/$namespace") ]] || exit 2
done
[[ $(findmnt -n -o PROPAGATION /) == private ]] || exit 2
cd "$work"
[[ -f test-access.img && ! -L test-access.img && ! -e root && ! -e boot ]] || exit 2
python3 -I - <<'PY'
import hashlib, json, pathlib, stat
work = pathlib.Path('.')
info = work.stat()
assert info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700
interfaces = {line.split(':',1)[0].strip() for line in pathlib.Path('/proc/net/dev').read_text().splitlines()[2:]}
assert interfaces == {'lo'}
recipe = json.loads(pathlib.Path('recipe/recipe-inputs.json').read_text())
for name, digest in recipe['files'].items():
    relative = pathlib.PurePosixPath(name)
    assert not relative.is_absolute() and '..' not in relative.parts and str(relative) == name
    path = pathlib.Path('recipe') / name
    for parent in path.parents:
        info = parent.lstat()
        assert stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == 0
    assert stat.S_IMODE(info.st_mode) == (0o600 if name == 'private-profile.json' else 0o444)
    with path.open('rb') as stream:
        assert hashlib.file_digest(stream,'sha256').hexdigest() == digest
parent = json.loads(pathlib.Path('recipe/parent-manifest.json').read_text())
assert parent['kind'] == 'test-lan-prepared' and parent['no_active_application'] is True
assert parent['hardware_qualified'] is False and parent['release_qualified'] is False and parent['ready_for_activation'] is False
assert parent['image']['sha256'] == '0854663168acf7986d26a473e9116dddeb7d6fbef8226f5d1d96cf190f77e286'
assert (parent['application']['source_commit'],parent['application']['manifest_sha256']) == (
    'c31b13afdc957425571810c46230eaaf52fa5d14','c4183e7304e3ff979450977b36e4a007b30016de68bb23ef121c7ca733cd26a1')
assert parent['application']['startup'] == 'masked-pending-firstboot-contract'
image = pathlib.Path('test-access.img'); info = image.lstat()
assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600
assert info.st_size == parent['image']['size_bytes']
with image.open('rb') as stream:
    assert hashlib.file_digest(stream,'sha256').hexdigest() == parent['image']['sha256']
PY
parent_sha256=$(python3 -I -c 'import json;print(json.load(open("recipe/parent-manifest.json"))["image"]["sha256"])')
application_sha256=$(python3 -I -c 'import json;print(json.load(open("recipe/parent-manifest.json"))["application"]["manifest_sha256"])')
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
  if (( failed )); then echo 'Private access build cleanup incomplete; no forced detach.' >&2; status=1; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir root boot
loop=$(losetup --find --show --partscan -- test-access.img)
[[ $loop =~ ^/dev/loop[0-9]+$ ]] || exit 1
for attempt in {1..20}; do [[ -b ${loop}p1 && -b ${loop}p2 ]] && break; sleep 0.1; done
[[ $(lsblk -nr -o TYPE "$loop" | wc -l) == 3 ]] || exit 1
[[ $(blkid -p -s TYPE -o value "${loop}p1") == vfat && $(blkid -p -s TYPE -o value "${loop}p2") == ext4 ]] || exit 1
mount -t ext4 -o rw,noatime,nosuid,nodev "${loop}p2" root
root_mounted=1
mount -t vfat -o rw,noatime,nosuid,nodev,noexec "${loop}p1" boot
boot_mounted=1
sha256sum boot/cmdline.txt boot/initramfs8 boot/initramfs_2712 boot/kernel8.img boot/kernel_2712.img \
  root/etc/fstab root/usr/lib/systemd/system/rpi-resize.service \
  root/usr/lib/systemd/system/systemd-growfs-root.service \
  root/usr/share/initramfs-tools/scripts/local-premount/resize_early \
  root/usr/share/initramfs-tools/scripts/local-bottom/set_partuuid > boot-preserved.sha256
# Observe all 17 pristine-parent constraints before adding the explicit access hook.
python3 -I - "$work" <<'PY'
import importlib.util,json,pathlib,sys
sys.dont_write_bytecode=True
work=pathlib.Path(sys.argv[1]); source=work/'recipe/scripts/configure-test-lan-rootfs.py'
spec=importlib.util.spec_from_file_location('prepared_contract',source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
metadata=json.loads((work/'root/etc/inkyos-test-lan.json').read_text())
report=module.verification(work/'root',work/'boot',metadata)
assert report['passed'] is True and len(report['checks']) == 17
report['scope']='pristine-parent-before-access-configuration'
(work/'qualification-prepared.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
PY
python3 -I recipe/scripts/configure-test-access-rootfs.py --rootfs "$work/root" --bootfs "$work/boot" \
  --recipe "$work/recipe" --profile "$work/recipe/private-profile.json" --parent-sha256 "$parent_sha256" \
  --output "$work/test-access-configuration.json"
chroot root /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  /usr/bin/systemd-analyze --man=no verify /usr/lib/systemd/system/inky-studio.service \
  /usr/lib/systemd/system/inky-network.service /usr/lib/systemd/system/inkyos-test-access.service \
  /usr/lib/systemd/system/inkyos-test-activate.service /usr/lib/systemd/system/inkyos-test-drain.service \
  /usr/lib/systemd/system/inkyos-test-ssh.service /usr/lib/systemd/system/NetworkManager.service \
  > systemd-verify.txt 2>&1 || { cat systemd-verify.txt >&2; exit 1; }
chroot root /usr/sbin/visudo -c > sudoers-verify.txt 2>&1 || exit 1
python3 -I recipe/scripts/verify-prototype.py --rootfs "$work/root" --bootfs "$work/boot" \
  --application-manifest "$work/recipe/application-manifest.json" --application-sha256 "$application_sha256" \
  --output "$work/qualification-static.json"
python3 -I recipe/scripts/verify-application-rootfs.py --rootfs "$work/root" \
  --manifest "$work/recipe/application-manifest.json" --sha256 "$application_sha256" \
  --output "$work/qualification-application.json"
sha256sum --check --strict boot-preserved.sha256
sync -f root
sync -f boot
mount -o remount,ro,noatime,nosuid,nodev root
mount -o remount,ro,noatime,nosuid,nodev,noexec boot
python3 -I recipe/scripts/manifest-rootfs.py --rootfs "$work/root" --bootfs "$work/boot" \
  --output "$work/filesystem-manifest.json"
umount boot; boot_mounted=0
umount root; root_mounted=0
e2fsck -fn "${loop}p2" > fsck-ext4.txt 2>&1 || { cat fsck-ext4.txt >&2; exit 1; }
fsck.fat -n "${loop}p1" > fsck-fat.txt 2>&1 || { cat fsck-fat.txt >&2; exit 1; }
losetup -d "$loop"; loop=
rmdir root boot
bash recipe/scripts/inspect-image.sh "$work/test-access.img" "$work/image-inspection.json"
echo 'Private access image prepared; no target boot/key generation, network or application activation.'
