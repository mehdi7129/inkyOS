#!/usr/bin/env bash
# Run the local fixture suite unprivileged inside the dedicated ARM64 builder.
set -Eeuo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"
vm=inkyos-build
[[ $(limactl shell --workdir=/tmp "$vm" cat /var/lib/inkyos-build/owner) == inkyos-builder-v1 ]] || exit 1
mkdir -p build
run_dir=$(mktemp -d build/linux-tests.XXXXXXXX)
guest_dir="/var/tmp/inkyos-tests/$(basename "$run_dir")"
python3 - "$run_dir" <<'PY'
import hashlib,io,json,pathlib,subprocess,sys,tarfile
root=pathlib.Path.cwd()
names={'Makefile', 'overlay/usr/local/lib/inkyos/firstboot.py',
       'overlay/etc/systemd/system/inkyos-firstboot.service'}
for pattern in ('scripts/*.py','scripts/*.sh','tests/test_*.py','config/*.json'):
    names.update(str(p) for p in pathlib.Path('.').glob(pattern))
blobs={}
for name in sorted(names):
    path=pathlib.Path(name)
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
        raise SystemExit('Refusing non-regular or external test source')
    blobs[name]=path.read_bytes()
receipt={'schema_version':1,
         'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
         'worktree_dirty':bool(subprocess.check_output(['git','status','--porcelain'])),
         'files':{name:hashlib.sha256(data).hexdigest() for name,data in blobs.items()}}
out=pathlib.Path(sys.argv[1])
(out/'inputs.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
with tarfile.open(out/'suite.tar','w',format=tarfile.USTAR_FORMAT) as archive:
    for name,data in blobs.items():
        info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o644;info.mtime=1789430400
        archive.addfile(info,io.BytesIO(data))
PY
limactl shell --workdir=/tmp "$vm" mkdir -p "$guest_dir"
limactl copy "$run_dir/suite.tar" "$run_dir/inputs.json" "$vm:$guest_dir/"
limactl shell --workdir=/tmp "$vm" tar -xf "$guest_dir/suite.tar" -C "$guest_dir"
# Assert that the executed bytes match the receipt, including new local tests.
limactl shell --workdir="$guest_dir" "$vm" python3 -c \
  'import hashlib,json,pathlib
for name,expected in json.load(open("inputs.json"))["files"].items():
    assert hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()==expected, "Test source hash mismatch"'
status=0
limactl shell --workdir="$guest_dir" "$vm" python3 scripts/run-unit-tests.py \
  --output results.json --log tests.txt || status=$?
# Preserve failure evidence too, then return the actual test status.
limactl copy "$vm:$guest_dir/results.json" "$vm:$guest_dir/tests.txt" "$run_dir/"
python3 - "$run_dir" <<'PY'
import hashlib,json,pathlib,sys
p=pathlib.Path(sys.argv[1]);r=json.loads((p/'results.json').read_text())
assert r['log_sha256']==hashlib.sha256((p/'tests.txt').read_bytes()).hexdigest()
PY
echo "Linux tests and exact inputs: $repo/$run_dir"
exit "$status"
