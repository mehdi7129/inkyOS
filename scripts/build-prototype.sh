#!/usr/bin/env bash
# Mac-side orchestration: copies only reviewed recipe files and verified inputs.
set -Eeuo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"
vm=inkyos-build
[[ $(limactl shell --workdir=/tmp "$vm" cat /var/lib/inkyos-build/owner) == inkyos-builder-v1 ]] || exit 1
python3 scripts/fetch-base.py --extract build/base.img > /dev/null
python3 scripts/fetch-packages.py --cache-dir cache/packages > /dev/null
mkdir -p build
run_dir=$(mktemp -d build/prototype.XXXXXXXX)
guest_dir="/var/tmp/inkyos-work/$(basename "$run_dir")"
# Whitelist source inputs, never recursively archive the working tree/home.
python3 - "$run_dir" <<'PY'
import hashlib,io,json,pathlib,subprocess,sys,tarfile
files = ['config/base-image.lock.json','config/system-packages.lock.json',
         'scripts/build-prototype.sh','scripts/fetch-base.py','scripts/fetch-packages.py',
         'infra/lima.yaml','Makefile',
         'scripts/build-image-linux.sh','scripts/configure-rootfs.py',
         'scripts/verify-prototype.py','scripts/inspect-rootfs.py',
         'scripts/inspect-image.sh','scripts/check-builder.sh',
         'scripts/manifest-rootfs.py','scripts/smoke-firstboot-linux.sh',
         'overlay/usr/local/lib/inkyos/firstboot.py',
         'overlay/etc/systemd/system/inkyos-firstboot.service']
blobs={name:pathlib.Path(name).read_bytes() for name in files}
metadata={'schema_version':1,
          'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
          'worktree_dirty':bool(subprocess.check_output(['git','status','--porcelain'])),
          'files':{name:hashlib.sha256(data).hexdigest() for name,data in sorted(blobs.items())}}
encoded=(json.dumps(metadata,indent=2,sort_keys=True)+'\n').encode()
out=pathlib.Path(sys.argv[1]); (out/'recipe-inputs.json').write_bytes(encoded)
blobs['recipe-inputs.json']=encoded
with tarfile.open(out/'recipe.tar','w',format=tarfile.USTAR_FORMAT) as archive:
    for name,data in sorted(blobs.items()):
        info=tarfile.TarInfo('recipe/'+name)
        info.size=len(data); info.mode=0o644; info.mtime=1789430400
        archive.addfile(info,io.BytesIO(data))
PY
limactl shell --workdir=/tmp "$vm" mkdir -p "$guest_dir/packages"
limactl copy "$run_dir/recipe.tar" "$vm:$guest_dir/recipe.tar"
limactl shell --workdir=/tmp "$vm" tar -xf "$guest_dir/recipe.tar" -C "$guest_dir"
while IFS= read -r package; do
  limactl copy "cache/packages/$package" "$vm:$guest_dir/packages/$package"
done < <(python3 -c 'import json; print("\n".join(p["filename"] for p in json.load(open("config/system-packages.lock.json"))["packages"]))')
limactl copy build/base.img "$vm:$guest_dir/prototype.img"
limactl shell --workdir=/tmp "$vm" sudo bash "$guest_dir/recipe/scripts/check-builder.sh" > "$run_dir/builder.json"
limactl shell --workdir=/tmp "$vm" sudo bash "$guest_dir/recipe/scripts/smoke-firstboot-linux.sh" > "$run_dir/firstboot-smoke.json"
limactl shell --workdir=/tmp "$vm" sudo bash "$guest_dir/recipe/scripts/build-image-linux.sh" "$guest_dir" \
  2>&1 | tee "$run_dir/build.log"
limactl shell --workdir=/tmp "$vm" sudo bash "$guest_dir/recipe/scripts/inspect-image.sh" \
  "$guest_dir/prototype.img" "$guest_dir/image-inspection.json"
for report in qualification-static.json filesystem-manifest.json image-inspection.json systemd-verify.txt boot-preserved.sha256 fsck-ext4.txt fsck-fat.txt; do
  limactl shell --workdir=/tmp "$vm" sudo cat "$guest_dir/$report" > "$run_dir/$report"
done
limactl copy "$vm:$guest_dir/prototype.img" "$run_dir/inkyos-system-prototype.img"
python3 - "$run_dir" <<'PY'
import hashlib,json,pathlib,sys
out=pathlib.Path(sys.argv[1]); image=out/'inkyos-system-prototype.img'
h=hashlib.sha256()
with image.open('rb') as f:
    for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
report=json.loads((out/'image-inspection.json').read_text())
assert h.hexdigest()==report['image']['sha256'], 'Export hash mismatch'
manifest={'schema_version':1,'kind':'system-prototype','hardware_qualified':False,
          'application':None,'image':{'filename':image.name,'size_bytes':image.stat().st_size,
                                    'sha256':h.hexdigest()},
          'recipe':json.loads((out/'recipe-inputs.json').read_text()),
          'reports':{name:hashlib.sha256((out/name).read_bytes()).hexdigest()
                     for name in ('builder.json','firstboot-smoke.json','qualification-static.json',
                                  'filesystem-manifest.json','image-inspection.json','systemd-verify.txt',
                                  'boot-preserved.sha256','fsck-ext4.txt','fsck-fat.txt')}}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
(out/'SHA256SUMS').write_text(h.hexdigest()+'  '+image.name+'\n')
PY
# Successful export only: preserve failed working copies for diagnosis.
limactl shell --workdir=/tmp "$vm" rm -- "$guest_dir/prototype.img"
echo "Prototype and evidence: $repo/$run_dir"
