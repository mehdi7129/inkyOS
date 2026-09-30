#!/usr/bin/env bash
# Derive a test-lan-prepared copy from an existing verified export; never touch an SD.
set -Eeuo pipefail
umask 077
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"
PYTHON=${PYTHON:-python3}
if [[ ${1:-} == --help || ${1:-} == -h ]]; then
  echo 'Usage: PYTHON=python3.13 bash scripts/build-test-lan.sh PARENT_EXPORT'
  echo 'Requires the running inkyos-build VM. Produces an unqualified test-lan-prepared image only.'
  exit 0
fi
[[ $# == 1 && -d $1 && ! -L $1 ]] || { echo 'An existing masked application-prototype parent export is required.' >&2; exit 2; }
parent=$1
vm=inkyos-build
[[ $(limactl shell --workdir=/tmp "$vm" cat /var/lib/inkyos-build/owner) == inkyos-builder-v1 ]] || exit 2
mkdir -p build
run_dir=$(mktemp -d build/test-lan-prepared.XXXXXXXX)
guest_dir="/var/tmp/inkyos-work/$(basename "$run_dir")"
# Check the parent's image and all prior evidence before deriving any image.
"$PYTHON" -I scripts/verify-artifacts.py "$parent" --output "$run_dir/parent-integrity.json"
"$PYTHON" -I - "$parent" "$run_dir" <<'PY'
import hashlib, importlib.util, io, json, os, pathlib, stat, subprocess, sys, tarfile
parent, out = map(pathlib.Path, sys.argv[1:])
files = [
    'scripts/build-test-lan.sh', 'scripts/build-test-lan-linux.sh',
    'scripts/verify-test-lan.py', 'scripts/verify-artifacts.py',
    'scripts/configure-test-lan-rootfs.py', 'scripts/configure-rootfs.py',
    'scripts/manifest-rootfs.py', 'scripts/inspect-image.sh', 'scripts/inspect-rootfs.py',
    'scripts/verify-prototype.py', 'scripts/verify-application-rootfs.py',
    'scripts/configure-application-rootfs.py', 'scripts/verify-application.py',
    'config/base-image.lock.json', 'config/system-packages.lock.json',
    'scripts/test-lan-preflight.py', 'scripts/verify-sd-diagnostic.py',
]

def read_regular(path, limit=64 * 1024**2):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
            raise ValueError('Snapshot requires bounded, unlinked regular source files')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if len(raw) != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError('Snapshot source changed while reading')
    return raw

parent_raw = read_regular(parent / 'manifest.json')
data = json.loads(parent_raw)
if data['kind'] != 'application-prototype' or data['application']['startup'] != 'masked-pending-firstboot-contract':
    raise ValueError('Only the masked application prototype is an accepted test-lan-prepared parent')
if (data['application']['source_commit'], data['application']['manifest_sha256']) != (
        '758a2bf7ed099aad41ef35316e53228e797b0b2b',
        '0d587792433d924ad1c4e71af19c2a46279f573791cb690571fa1019e7703551'):
    raise ValueError('The current TEST LAN build requires the reviewed panel-metadata candidate')
blobs = {name: read_regular(pathlib.Path(name)) for name in files}
blobs['parent-manifest.json'] = parent_raw
blobs['application-manifest.json'] = read_regular(parent / 'application-manifest.json')
if hashlib.sha256(blobs['application-manifest.json']).hexdigest() != data['application']['manifest_sha256']:
    raise ValueError('Parent application manifest changed')
# The derivative does not silently substitute base/package or application audit inputs.
for name in ('config/base-image.lock.json', 'config/system-packages.lock.json',
             'scripts/configure-application-rootfs.py', 'scripts/verify-application-rootfs.py'):
    if hashlib.sha256(blobs[name]).hexdigest() != data['recipe']['files'][name]:
        raise ValueError('Parent audit input changed; review this derivation before rebuilding')
metadata = {'schema_version': 1,
            'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
            'worktree_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'])),
            'files': {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(blobs.items())}}
encoded = (json.dumps(metadata, indent=2, sort_keys=True) + '\n').encode()
(out / 'recipe-inputs.json').write_bytes(encoded)
(out / 'parent-manifest.json').write_bytes(parent_raw)
(out / 'parent-filesystem-manifest.json').write_bytes(read_regular(parent / 'filesystem-manifest.json'))
(out / 'application-manifest.json').write_bytes(blobs['application-manifest.json'])
(out / 'parent-image-name.txt').write_text(data['image']['filename'] + '\n')
blobs['recipe-inputs.json'] = encoded
with tarfile.open(out / 'recipe.tar', 'w', format=tarfile.USTAR_FORMAT) as archive:
    for name, raw in sorted(blobs.items()):
        member = tarfile.TarInfo('recipe/' + name)
        member.size = len(raw); member.mode = 0o444; member.mtime = 1789430400
        archive.addfile(member, io.BytesIO(raw))
PY
image_name=$(cat "$run_dir/parent-image-name.txt")
[[ $image_name =~ ^[A-Za-z0-9][A-Za-z0-9._-]*\.img$ ]] || exit 2
rm -- "$run_dir/parent-image-name.txt"
limactl shell --workdir=/tmp "$vm" mkdir -m 700 -- "$guest_dir"
limactl copy "$run_dir/recipe.tar" "$vm:$guest_dir/recipe.tar"
limactl copy "$parent/$image_name" "$vm:$guest_dir/test-lan-prepared.img"
limactl shell --workdir=/tmp "$vm" tar -xf "$guest_dir/recipe.tar" -C "$guest_dir"
# Seal the transferred snapshot. There are no linked or personal inputs in it.
limactl shell --workdir=/tmp "$vm" sudo python3 -I - "$guest_dir" <<'PY'
import os, pathlib, re, stat, sys
path = pathlib.Path(sys.argv[1])
assert re.fullmatch(r'/var/tmp/inkyos-work/test-lan-prepared\.[A-Za-z0-9]{8}', str(path))
for entry in [path, *path.rglob('*')]:
    info = entry.lstat()
    assert stat.S_ISDIR(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
    os.chown(entry, 0, 0, follow_symlinks=False)
    # Implicit tar parent directories inherit the guest user's umask. Normalize
    # every entry before a root interpreter reads this sealed snapshot.
    os.chmod(entry, 0o755 if stat.S_ISDIR(info.st_mode) else 0o444, follow_symlinks=False)
os.chmod(path / 'test-lan-prepared.img', 0o600, follow_symlinks=False)
os.chmod(path, 0o700)
PY
limactl shell --workdir=/tmp "$vm" sudo bash "$guest_dir/recipe/scripts/build-test-lan-linux.sh" "$guest_dir" \
  2>&1 | tee "$run_dir/build.log"
for report in test-lan-configuration.json qualification-static.json qualification-application.json \
  filesystem-manifest.json image-inspection.json systemd-verify.txt boot-preserved.sha256 fsck-ext4.txt fsck-fat.txt; do
  limactl shell --workdir=/tmp "$vm" sudo cat "$guest_dir/$report" > "$run_dir/$report"
done
# Read-only access for Lima copy; only root can change the finished guest image.
limactl shell --workdir=/tmp "$vm" sudo chmod 0755 "$guest_dir"
limactl shell --workdir=/tmp "$vm" sudo chmod 0644 "$guest_dir/test-lan-prepared.img"
limactl copy "$vm:$guest_dir/test-lan-prepared.img" "$run_dir/inkyos-test-lan-prepared.img"
"$PYTHON" -I - "$run_dir" <<'PY'
import hashlib, json, pathlib, sys
out = pathlib.Path(sys.argv[1]); image = out / 'inkyos-test-lan-prepared.img'
digest = hashlib.sha256()
with image.open('rb') as stream:
    for block in iter(lambda: stream.read(1024**2), b''): digest.update(block)
parent_raw = (out / 'parent-manifest.json').read_bytes(); parent = json.loads(parent_raw)
names = ['parent-manifest.json', 'parent-filesystem-manifest.json', 'parent-integrity.json', 'recipe.tar', 'test-lan-configuration.json',
         'qualification-static.json', 'qualification-application.json', 'application-manifest.json',
         'filesystem-manifest.json', 'image-inspection.json', 'systemd-verify.txt',
         'boot-preserved.sha256', 'fsck-ext4.txt', 'fsck-fat.txt', 'build.log']
manifest = {'schema_version': 1, 'kind': 'test-lan-prepared', 'hardware_qualified': False,
            'release_qualified': False, 'no_active_application': True, 'ready_for_activation': False, 'application': parent['application'],
            'parent': {'kind': parent['kind'], 'image_sha256': parent['image']['sha256'],
                       'size_bytes': parent['image']['size_bytes'],
                       'manifest_sha256': hashlib.sha256(parent_raw).hexdigest()},
            'image': {'filename': image.name, 'size_bytes': image.stat().st_size, 'sha256': digest.hexdigest()},
            'recipe': json.loads((out / 'recipe-inputs.json').read_text()),
            'reports': {name: hashlib.sha256((out / name).read_bytes()).hexdigest() for name in names}}
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
(out / 'SHA256SUMS').write_text(digest.hexdigest() + '  ' + image.name + '\n')
PY
"$PYTHON" -I scripts/verify-test-lan.py "$run_dir" --output "$run_dir.integrity.json"
# Failed or incomplete builds retain their working image for diagnosis.
limactl shell --workdir=/tmp "$vm" sudo rm -- "$guest_dir/test-lan-prepared.img"
echo "TEST LAN prepared and evidence: $repo/$run_dir"
