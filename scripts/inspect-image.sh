#!/usr/bin/env bash
# Linux isolated VM only. Inspect a regular .img COPY, never a physical device.
# Usage: sudo bash scripts/inspect-image.sh /path/copy.img /tmp/report-new.json
set -Eeuo pipefail
umask 077

usage() {
    printf '%s\n' 'Usage: sudo bash scripts/inspect-image.sh COPY.img NEW_REPORT.json' \
        'Linux isolated VM only; one FAT boot and one ext4 root partition required.' \
        'Uses read-only loop + ro mounts (ext4: noload); never chroots or boots the image.' \
        'The report must be a new file outside the mounted image. No SD/block-device input.'
}
if [[ ${1:-} == --help || ${1:-} == -h ]]; then usage; exit 0; fi
[[ $# == 2 ]] || { usage >&2; exit 2; }
[[ $(uname -s) == Linux && $EUID == 0 ]] || {
    printf '%s\n' 'Run as root inside an isolated Linux VM, never on the Mac or the Pi.' >&2
    exit 2
}
for tool in losetup lsblk blkid blockdev mount umount findmnt mktemp readlink python3; do
    command -v "$tool" >/dev/null || { printf 'Missing tool: %s\n' "$tool" >&2; exit 2; }
done
[[ -f $1 && ! -L $1 && $1 == *.img ]] || {
    printf '%s\n' 'Input must be a regular .img copy, not a symlink or block device.' >&2; exit 2;
}
image=$(readlink -e -- "$1")
output=$(readlink -m -- "$2")
[[ ! -e $2 && ! -L $2 && $image != "$output" ]] || {
    printf '%s\n' 'Report output must not already exist.' >&2; exit 2;
}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
work=$(mktemp -d /tmp/inkyos-inspect.XXXXXXXX)
loop=
boot_mounted=0
root_mounted=0
cleanup() {
    local status=$? failed=0
    trap - EXIT INT TERM
    if (( boot_mounted )); then
        if umount -- "$work/boot"; then boot_mounted=0; else failed=1; fi
    fi
    if (( root_mounted )); then
        if umount -- "$work/root"; then root_mounted=0; else failed=1; fi
    fi
    if [[ -n $loop ]] && (( !boot_mounted && !root_mounted )); then
        losetup --detach "$loop" || failed=1
    fi
    if (( !boot_mounted && !root_mounted )); then
        rmdir -- "$work/boot" "$work/root" "$work" 2>/dev/null || true
    fi
    if (( failed )); then
        printf 'Cleanup incomplete; inspect mount/loop state at %s (%s). No forced detach attempted.\n' "$work" "$loop" >&2
        status=1
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -- "$work/root" "$work/boot"
loop=$(losetup --find --show --read-only --partscan -- "$image")
[[ $loop =~ ^/dev/loop[0-9]+$ && $(blockdev --getro "$loop") == 1 ]] || {
    printf '%s\n' 'Read-only loop verification failed.' >&2; exit 1;
}
# Wait only for the kernel-created partition nodes, never run an image command.
partitions=()
for attempt in {1..20}; do
    inventory=$(lsblk --list --noheadings --paths --output NAME,TYPE "$loop")
    partitions=()
    while read -r node kind; do
        if [[ $kind == part && $node =~ ^${loop}p[0-9]+$ ]]; then partitions+=("$node"); fi
    done <<< "$inventory"
    if (( ${#partitions[@]} == 2 )); then break; fi
    sleep 0.1
done
(( ${#partitions[@]} == 2 )) || { printf '%s\n' 'Expected exactly two image partitions.' >&2; exit 1; }
boot_partition=
root_partition=
for partition in "${partitions[@]}"; do
    [[ $(blockdev --getro "$partition") == 1 ]] || { printf '%s\n' 'Partition is not read-only.' >&2; exit 1; }
    filesystem=$(blkid -p -s TYPE -o value -- "$partition")
    case "$filesystem" in
        vfat) [[ -z $boot_partition ]] || exit 1; boot_partition=$partition ;;
        ext4) [[ -z $root_partition ]] || exit 1; root_partition=$partition ;;
        *) printf 'Unsupported filesystem: %s\n' "$filesystem" >&2; exit 1 ;;
    esac
done
[[ -n $boot_partition && -n $root_partition ]] || { printf '%s\n' 'Expected FAT boot and ext4 root.' >&2; exit 1; }
mount -t ext4 -o ro,noload,nosuid,nodev,noexec -- "$root_partition" "$work/root"
root_mounted=1
mount -t vfat -o ro,nosuid,nodev,noexec -- "$boot_partition" "$work/boot"
boot_mounted=1
for directory in "$work/root" "$work/boot"; do
    options=$(findmnt --noheadings --output OPTIONS --target "$directory")
    [[ ,$options, == *,ro,* ]] || { printf '%s\n' 'Mount is not read-only.' >&2; exit 1; }
done
python3 "$script_dir/inspect-rootfs.py" --rootfs "$work/root" --bootfs "$work/boot" \
    --image "$image" --output "$output"
printf 'Offline report written: %s\n' "$output"
