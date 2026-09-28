#!/usr/bin/env bash
# Real peer UIDs/root receipt, fake time/radio, only in the dedicated Linux VM.
set -Eeuo pipefail
[[ $# == 0 ]] || { echo 'This probe accepts no arguments.' >&2; exit 1; }
umask 077
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"
vm=inkyos-build
[[ $(limactl shell --workdir=/tmp "$vm" cat /var/lib/inkyos-build/owner) == inkyos-builder-v1 ]] || exit 1
mkdir -p build
run_dir=$(mktemp -d build/bootstrap-probe.XXXXXXXX)
python3 - "$run_dir" <<'PY'
import hashlib,json,pathlib,subprocess,sys
out=pathlib.Path(sys.argv[1])
names=('probe-bootstrap-linux.py','bootstrap-system-model.py','initialization-receipt.py')
hashes={}
for name in names:
    path=pathlib.Path('scripts')/name
    if path.is_symlink() or not path.is_file():
        raise SystemExit('Only regular probe sources are accepted')
    data=path.read_bytes()
    if len(data)>1024**2:
        raise SystemExit('Probe source exceeds bound')
    (out/name).write_bytes(data)
    hashes[name]=hashlib.sha256(data).hexdigest()
receipt={'schema_version':1,'scope':'linux-bootstrap-probe-inputs',
         'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
         'worktree_dirty':bool(subprocess.check_output(['git','status','--porcelain'])),
         'files':hashes}
(out/'inputs.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
PY
guest_inputs=
guest_root=
cleanup() {
  if [[ $guest_root =~ ^/var/lib/inkyos-build/bootstrap-sources\.[A-Za-z0-9]+$ ]]; then
    limactl shell --workdir=/tmp "$vm" sudo rm -rf -- "$guest_root"
  fi
  if [[ $guest_inputs =~ ^/var/tmp/inkyos-probe-inputs\.[A-Za-z0-9]+$ ]]; then
    limactl shell --workdir=/tmp "$vm" rm -rf -- "$guest_inputs"
  fi
}
trap cleanup EXIT
guest_inputs=$(limactl shell --workdir=/tmp "$vm" mktemp -d /var/tmp/inkyos-probe-inputs.XXXXXXXX)
[[ $guest_inputs =~ ^/var/tmp/inkyos-probe-inputs\.[A-Za-z0-9]+$ ]] || exit 1
guest_root=$(limactl shell --workdir=/tmp "$vm" sudo mktemp -d /var/lib/inkyos-build/bootstrap-sources.XXXXXXXX)
[[ $guest_root =~ ^/var/lib/inkyos-build/bootstrap-sources\.[A-Za-z0-9]+$ ]] || exit 1
for name in probe-bootstrap-linux.py bootstrap-system-model.py initialization-receipt.py inputs.json; do
  limactl copy "$run_dir/$name" "$vm:$guest_inputs/$name"
  limactl shell --workdir=/tmp "$vm" sudo install -m 0444 "$guest_inputs/$name" "$guest_root/$name"
done
# Verify root-owned immutable-for-clients snapshots before executing as root.
limactl shell --workdir=/tmp "$vm" sudo python3 -I -c '
import hashlib,json,pathlib,stat,sys
root=pathlib.Path(sys.argv[1])
assert root.stat().st_uid==0 and stat.S_IMODE(root.stat().st_mode)==0o700
for name,expected in json.loads((root/"inputs.json").read_text())["files"].items():
    p=root/name;s=p.lstat()
    assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1
    assert stat.S_IMODE(s.st_mode)==0o444
    assert hashlib.sha256(p.read_bytes()).hexdigest()==expected
' "$guest_root"
status=0
limactl shell --workdir=/tmp "$vm" sudo python3 -I "$guest_root/probe-bootstrap-linux.py" \
  > "$run_dir/report.json" || status=$?
if [[ $status == 0 ]]; then
  python3 - "$run_dir" <<'PY'
import hashlib,json,pathlib,sys
p=pathlib.Path(sys.argv[1]);report=json.loads((p/'report.json').read_text())
inputs=json.loads((p/'inputs.json').read_text())
assert report['passed'] and all(check['passed'] for check in report['checks'])
assert report['source_sha256']==inputs['files']
assert report['method']['clock_radio_services_changed'] is False
assert report['method']['receipt_owner_overrides'] is False
names=sorted([*inputs['files'],'inputs.json','report.json'])
(p/'SHA256SUMS').write_text(''.join(hashlib.sha256((p/n).read_bytes()).hexdigest()+'  '+n+'\n' for n in names))
print('Bootstrap Linux probe: '+str(len(report['checks']))+' checks passed')
PY
fi
echo "Probe sources and receipt: $repo/$run_dir"
exit "$status"
