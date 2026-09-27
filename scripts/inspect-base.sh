#!/usr/bin/env bash
# Host-side orchestration. No physical disk or Raspberry Pi access.
set -Eeuo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"
vm=inkyos-build

owner=$(limactl shell --workdir=/tmp "$vm" cat /var/lib/inkyos-build/owner)
if [[ $owner != inkyos-builder-v1 ]]; then
  echo 'Refusing to use a VM not marked as the InkyOS builder.' >&2
  exit 1
fi
# A direct invocation is safe too: re-verify the cached image before transfer.
python3 scripts/fetch-base.py --extract build/base.img >/dev/null
mkdir -p build
run_dir=$(mktemp -d build/inspection.XXXXXXXX)
guest_dir="/var/tmp/inkyos-work/$(basename "$run_dir")"
limactl shell --workdir=/tmp "$vm" mkdir -p "$guest_dir"
limactl copy scripts/check-builder.sh scripts/inspect-image.sh \
  scripts/inspect-rootfs.py config/base-image.lock.json "$vm:$guest_dir/"
# Every run has its own copy, including when two inspections overlap.
limactl copy build/base.img "$vm:$guest_dir/base.img"
limactl shell --workdir=/tmp "$vm" sudo bash "$guest_dir/check-builder.sh" \
  > "$run_dir/builder.json"
limactl shell --workdir=/tmp "$vm" python3 -c \
  'import hashlib,json,sys
expected=json.load(open(sys.argv[2]))["image"]["extracted_sha256"]
h=hashlib.sha256()
with open(sys.argv[1],"rb") as f:
    for chunk in iter(lambda:f.read(1024*1024),b""):
        h.update(chunk)
if h.hexdigest()!=expected:
    raise SystemExit("Transferred image checksum mismatch")' \
  "$guest_dir/base.img" "$guest_dir/base-image.lock.json"
limactl shell --workdir=/tmp "$vm" sudo bash "$guest_dir/inspect-image.sh" \
  "$guest_dir/base.img" "$guest_dir/base.json"
# Root-created inspection reports contain no credentials; copy via stdout.
limactl shell --workdir=/tmp "$vm" sudo cat "$guest_dir/base.json" \
  > "$run_dir/base.json"
# Inspection completed and its loops were detached; discard only this run's copy.
limactl shell --workdir=/tmp "$vm" rm -- "$guest_dir/base.img"
echo "Reports: $repo/$run_dir"
