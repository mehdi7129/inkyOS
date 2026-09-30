#!/usr/bin/env bash
# Build a PRIVATE enrollment copy; never invoke its firstboot or key generator.
set -Eeuo pipefail
umask 077
[[ $# == 1 && $(uname -s) == Linux && $(uname -m) == aarch64 && $EUID == 0 ]] || exit 2
[[ $(cat /var/lib/inkyos-build/owner) == inkyos-builder-v1 ]] || exit 2
work=$(readlink -e -- "$1")
[[ $work == "$1" && $work =~ ^/var/tmp/inkyos-work/test-enrollment\.[a-zA-Z0-9]{8}$ ]] || exit 2
[[ $(readlink -e -- "$0") == "$work/recipe/scripts/build-test-enrollment-linux.sh" ]] || exit 2
if [[ ${INKYOS_ENROLLMENT_NAMESPACE:-} != 1 ]]; then
  exec unshare --mount --net --uts --propagation private \
    env INKYOS_ENROLLMENT_NAMESPACE=1 bash "$0" "$work"
fi
for namespace in mnt net uts; do
  [[ $(readlink "/proc/self/ns/$namespace") != $(readlink "/proc/1/ns/$namespace") ]] || exit 2
done
[[ $(findmnt -n -o PROPAGATION /) == private ]] || exit 2
cd "$work"
[[ -f test-enrollment.img && ! -L test-enrollment.img && ! -e root && ! -e boot ]] || exit 2
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
assert parent['image']['sha256'] == '4cd9d6fa8183dfb8a7a04c350ab3d3366900264fab2fa0dff90192a7e4cc9a04'
assert (parent['application']['source_commit'],parent['application']['manifest_sha256']) == (
    '758a2bf7ed099aad41ef35316e53228e797b0b2b','0d587792433d924ad1c4e71af19c2a46279f573791cb690571fa1019e7703551')
assert parent['application']['startup'] == 'masked-pending-firstboot-contract'
image = pathlib.Path('test-enrollment.img'); info = image.lstat()
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
  if (( failed )); then echo 'Private enrollment build cleanup incomplete; no forced detach.' >&2; status=1; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir root boot
loop=$(losetup --find --show --partscan -- test-enrollment.img)
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
python3 -I recipe/scripts/configure-test-enrollment-rootfs.py --rootfs "$work/root" --bootfs "$work/boot" \
  --recipe "$work/recipe" --profile "$work/recipe/private-profile.json" --parent-sha256 "$parent_sha256" \
  --output "$work/test-enrollment-configuration.json"
# Check the unchanged PREPARED contract using its actual preserved declaration.
python3 -I - "$work" <<'PY'
import importlib.util,json,pathlib,sys
sys.dont_write_bytecode=True
work=pathlib.Path(sys.argv[1]); source=work/'recipe/scripts/configure-test-lan-rootfs.py'
spec=importlib.util.spec_from_file_location('prepared_contract',source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
metadata=json.loads((work/'root/etc/inkyos-test-lan.json').read_text())
report=module.verification(work/'root',work/'boot',metadata)
assert report['passed'] is True and len(report['checks']) == 17
# ENROLL has one explicit boot action. Do not reuse a broader hook-absence
# label as a claim about this private child; its own gate checks the sole unit.
checks={name:value for name,value in report['checks'].items() if name != 'no_diagnostic_or_test_runtime_hooks'}
assert len(checks) == 16 and all(checks.values())
report={'schema_version':1,'kind':'test-lan-enrollment','scope':'offline-inherited-prepared-constraints',
        'passed':True,'checks':checks,'inherited_prepared_marker_sha256':report['marker_sha256'],
        'enrollment_hook_exception_explicit':True,'application_started':False,
        'no_active_application':True,'hardware_qualified':False,'release_qualified':False,'ready_for_activation':False}
(work/'qualification-prepared.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
PY
chroot root /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  /usr/bin/systemd-analyze verify /usr/lib/systemd/system/inky-studio.service \
  /usr/lib/systemd/system/inky-network.service /usr/lib/systemd/system/inkyos-test-enrollment.service \
  > systemd-verify.txt 2>&1 || { cat systemd-verify.txt >&2; exit 1; }
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
bash recipe/scripts/inspect-image.sh "$work/test-enrollment.img" "$work/image-inspection.json"
echo 'Private enrollment image prepared; no target boot/key generation, network or application activation.'
