#!/usr/bin/env bash
# Mac orchestration for the inert SSH/PAM bench; never open a physical SD.
set -Eeuo pipefail
umask 077
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"
PYTHON=${PYTHON:-python3}
if [[ ${1:-} == --help && $# == 1 ]]; then
  echo 'Usage: PYTHON=python3.13 bash scripts/probe-test-ssh.sh [--operator-runtime] PARENT_EXPORT'
  echo 'Requires the marked inkyos-build VM; tests only a disposable image copy and inert runner.'
  echo 'Optional operator runtime extension uses production sources; stop mutations remain fixture-only.'
  exit 0
fi
operator_runtime=0
if [[ ${1:-} == --operator-runtime ]]; then
  operator_runtime=1
  shift
fi
[[ $# == 1 && -d $1 && ! -L $1 ]] || exit 2
parent=$1
vm=inkyos-build
[[ $(limactl shell --workdir=/tmp "$vm" cat /var/lib/inkyos-build/owner) == inkyos-builder-v1 ]] || exit 2
mkdir -p build
run_dir=$(mktemp -d build/test-ssh-probe.XXXXXXXX)
guest_dir="/var/tmp/inkyos-work/$(basename "$run_dir")"
"$PYTHON" -I scripts/verify-artifacts.py "$parent" --output "$run_dir/parent-integrity.json"
"$PYTHON" -I - "$parent" "$run_dir" "$operator_runtime" <<'PY'
import ast, hashlib, json, os, pathlib, stat, subprocess, sys
parent, out = map(pathlib.Path, sys.argv[1:3])
operator_mode = sys.argv[3] == '1'
def read(path, limit=64*1024**2):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
            raise ValueError('Bounded regular probe input required')
        raw = stream.read(limit+1); after = os.fstat(stream.fileno())
    if len(raw) != before.st_size or (before.st_size,before.st_mtime_ns,before.st_ctime_ns) != (after.st_size,after.st_mtime_ns,after.st_ctime_ns):
        raise ValueError('Probe source changed while reading')
    return raw
raw = read(parent/'manifest.json'); data = json.loads(raw)
if data['kind'] != 'application-prototype':
    raise ValueError('SSH probe requires an inactive application-prototype parent')
image = data['image']['filename']
if pathlib.PurePosixPath(image).name != image or not image.endswith('.img'):
    raise ValueError('Invalid parent image name')
blobs = {'parent-manifest.json': raw,
         'parent-manifest.sha256': (hashlib.sha256(raw).hexdigest()+'\n').encode(),
         'parent-filesystem-manifest.json': read(parent/'filesystem-manifest.json'),
         'probe-test-ssh-linux.sh': read(pathlib.Path('scripts/probe-test-ssh-linux.sh'))}
operator_names = ('probe-test-operator-runtime.py', 'test-operator-dispatch.py',
                  'test-operator-runner.py', 'test-lan-preflight.py', 'test-enrollment-firstboot.py')
if operator_mode:
    blobs.update({name: read(pathlib.Path('scripts') / name) for name in operator_names})
    blobs['application-manifest.json'] = read(parent / 'application-manifest.json')
    if hashlib.sha256(blobs['application-manifest.json']).hexdigest() != data['application']['manifest_sha256']:
        raise ValueError('Operator probe application manifest differs from parent')
    operator_names += ('application-manifest.json',)
for name, value in blobs.items(): (out/name).write_bytes(value)
names = [*blobs, 'parent-integrity.json']
embedded = blobs['probe-test-ssh-linux.sh'].decode().split("<<'PY_PROBE'\n", 1)[1].rsplit('\nPY_PROBE', 1)[0]
checks_node = next(node for node in ast.parse(embedded).body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'CHECKS' for target in node.targets))
checks = ast.literal_eval(checks_node.value)
if not isinstance(checks, tuple) or len(checks) != 39 or len(set(checks)) != len(checks) or not all(isinstance(x, str) for x in checks):
    raise ValueError('Invalid closed transport checks')
receipt = {'schema_version':1,'scope':'test-ssh-probe-inputs',
           'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
           'worktree_dirty':bool(subprocess.check_output(['git','status','--porcelain'])),
           'files':{name:hashlib.sha256(read(out/name)).hexdigest() for name in names},
           'parent_image':data['image'], 'parent_application':data['application'], 'expected_checks':checks}
if operator_mode:
    tree = ast.parse(blobs['probe-test-operator-runtime.py'].decode())
    node = next(node for node in tree.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == 'CHECKS' for target in node.targets))
    operator_checks = ast.literal_eval(node.value)
    assert type(operator_checks) is tuple and operator_checks and len(set(operator_checks)) == len(operator_checks)
    assert all(type(name) is str for name in operator_checks)
    receipt['expected_operator_checks'] = operator_checks
    receipt['operator_sources'] = {name: hashlib.sha256(blobs[name]).hexdigest() for name in operator_names}
(out/'inputs.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
(out/'parent-image-name.txt').write_text(image+'\n')
PY
image_name=$(cat "$run_dir/parent-image-name.txt")
[[ $image_name =~ ^[A-Za-z0-9][A-Za-z0-9._-]*\.img$ ]] || exit 2
rm -- "$run_dir/parent-image-name.txt"
limactl shell --workdir=/tmp "$vm" mkdir -m 700 -- "$guest_dir"
names=(parent-manifest.json parent-manifest.sha256 parent-filesystem-manifest.json parent-integrity.json probe-test-ssh-linux.sh)
if [[ $operator_runtime == 1 ]]; then
  names+=(probe-test-operator-runtime.py test-operator-dispatch.py test-operator-runner.py test-lan-preflight.py test-enrollment-firstboot.py application-manifest.json)
fi
for name in "${names[@]}"; do
  limactl copy "$run_dir/$name" "$vm:$guest_dir/$name"
done
limactl copy "$parent/$image_name" "$vm:$guest_dir/probe.img"
# Seal source/inputs and check transferred bytes before executing as root.
"$PYTHON" -I - "$run_dir/inputs.json" <<'PY' | limactl shell --workdir=/tmp "$vm" sudo python3 -I -c '
import hashlib,json,os,pathlib,re,stat,sys
data=json.load(sys.stdin); path=pathlib.Path(data["guest_dir"])
assert re.fullmatch(r"/var/tmp/inkyos-work/test-ssh-probe\.[A-Za-z0-9]{8}",str(path))
assert {p.name for p in path.iterdir()}==set(data["files"])|{"probe.img"}
for entry in [path,*path.iterdir()]:
    info=entry.lstat()
    assert stat.S_ISDIR(info.st_mode) if entry==path else stat.S_ISREG(info.st_mode) and info.st_nlink==1
    os.chown(entry,0,0,follow_symlinks=False)
    os.chmod(entry,0o700 if entry==path else 0o600 if entry.name=="probe.img" else 0o444,follow_symlinks=False)
for name,pin in data["files"].items():
    assert hashlib.sha256((path/name).read_bytes()).hexdigest()==pin
'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]); data=json.loads(p.read_text())
data['guest_dir']='/var/tmp/inkyos-work/'+p.parent.name
print(json.dumps(data))
PY
status=0
limactl shell --workdir=/tmp "$vm" sudo bash "$guest_dir/probe-test-ssh-linux.sh" "$guest_dir" || status=$?
limactl shell --workdir=/tmp "$vm" sudo cat "$guest_dir/report.json" > "$run_dir/report.json" || exit 1
"$PYTHON" -I - "$run_dir" "$status" <<'PY_RECEIPT'
import hashlib,json,pathlib,sys

def validate_report(report, inputs, status):
    def require(value):
        if not value:
            raise ValueError('Transport report does not match sealed inputs')
    require(type(status) is int and 0 <= status <= 255)
    require(type(report.get('schema_version')) is int and report['schema_version'] == 1
            and report.get('scope') == 'linux-test-ssh-pam-transport-probe')
    require(report.get('source_sha256') == inputs['files']['probe-test-ssh-linux.sh'])
    require(report.get('activation_stub_only') is True and report.get('application_activated') is False
            and report.get('hardware_qualified') is False and report.get('release_qualified') is False)
    require(report.get('parent') == {
        'manifest_sha256': inputs['files']['parent-manifest.json'],
        'image_sha256': inputs['parent_image']['sha256'],
        'filesystem_manifest_sha256': inputs['files']['parent-filesystem-manifest.json'],
        'application_source_commit': inputs['parent_application']['source_commit'],
        'application_manifest_sha256': inputs['parent_application']['manifest_sha256']})
    checks = report.get('checks')
    require(isinstance(checks, dict) and set(checks) == set(inputs['expected_checks'])
            and all(type(value) is bool for value in checks.values()))
    failed = [name for name in inputs['expected_checks'] if checks[name] is False]
    require(report.get('failed_checks') == failed)
    passed = not failed and report.get('error_stage') is None
    if 'operator_sources' in inputs:
        extra = report.get('operator_runtime')
        if extra is None and report.get('error_stage') is not None:
            require(report.get('passed') is False)
            return False
        require(type(extra) is dict and extra.get('scope') == 'isolated-test-operator-runtime-probe')
        require(extra.get('source_sha256') == inputs['operator_sources'])
        require(extra.get('application_activated') is False and extra.get('stop_mutations_fixture_only') is True
                and extra.get('hardware_qualified') is False and extra.get('release_qualified') is False)
        extra_checks = extra.get('checks')
        require(type(extra_checks) is dict and set(extra_checks) == set(inputs['expected_operator_checks'])
                and all(type(value) is bool for value in extra_checks.values()))
        extra_passed = all(extra_checks.values()) and extra.get('error_stage') is None
        require(extra.get('passed') is extra_passed)
        passed = passed and extra_passed
    else:
        require('operator_runtime' not in report)
    require(type(report.get('passed')) is bool and report['passed'] == passed)
    return passed and status == 0

p=pathlib.Path(sys.argv[1]); report=json.loads((p/'report.json').read_text()); inputs=json.loads((p/'inputs.json').read_text())
status = int(sys.argv[2]); passed = validate_report(report, inputs, status)
(p/'receipt.json').write_text(json.dumps({'schema_version':1,'scope':'local-test-ssh-probe-integrity',
    'passed':passed, 'transport_exit_status':status,'inputs_sha256':hashlib.sha256((p/'inputs.json').read_bytes()).hexdigest(),
    'report_sha256':hashlib.sha256((p/'report.json').read_bytes()).hexdigest(),
    'hardware_qualified':False,'release_qualified':False},indent=2,sort_keys=True)+'\n')
PY_RECEIPT
echo "SSH/PAM probe and closed evidence: $repo/$run_dir"
exit "$status"
