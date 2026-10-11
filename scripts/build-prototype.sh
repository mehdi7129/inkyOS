#!/usr/bin/env bash
# Mac-side orchestration: copies only reviewed recipe files and verified inputs.
set -Eeuo pipefail
umask 077
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"
PYTHON=${PYTHON:-python3}
"$PYTHON" -c 'import sys; sys.exit("Python 3.11+ required; select it with PYTHON.") if sys.version_info < (3, 11) else None'
application_manifest=
application_sha256=
application_assets=
application_mode=0
profile=system
profile_seen=0
factory_manifest=
factory_sha256=
factory_sources=
factory_wheels=
if (( $# )); then
  while (( $# )); do
    [[ $# -ge 2 && -n $2 ]] || { echo 'Every prototype option requires a nonempty value.' >&2; exit 2; }
    case $1 in
      --profile) (( profile_seen == 0 )) || exit 2; profile_seen=1; profile=$2 ;;
      --studio-input-manifest) [[ -z $factory_manifest ]] || exit 2; factory_manifest=$2 ;;
      --studio-input-sha256) [[ -z $factory_sha256 ]] || exit 2; factory_sha256=$2 ;;
      --studio-sources-dir) [[ -z $factory_sources ]] || exit 2; factory_sources=$2 ;;
      --studio-wheels-dir) [[ -z $factory_wheels ]] || exit 2; factory_wheels=$2 ;;
      --application-manifest) [[ -z $application_manifest ]] || exit 2; application_manifest=$2 ;;
      --application-sha256) [[ -z $application_sha256 ]] || exit 2; application_sha256=$2 ;;
      --assets-dir) [[ -z $application_assets ]] || exit 2; application_assets=$2 ;;
      *) echo "Unknown prototype option: $1" >&2; exit 2 ;;
    esac
    shift 2
  done
fi
[[ $profile == system || $profile == factory-passive ]] || { echo 'Unknown build profile.' >&2; exit 2; }
if [[ $profile == factory-passive ]]; then
  [[ -n $factory_manifest && -n $factory_sha256 && -n $factory_sources && -n $factory_wheels &&
     -z $application_manifest && -z $application_sha256 && -z $application_assets ]] || {
    echo 'Factory-passive requires four pinned Studio inputs and forbids legacy application options.' >&2; exit 2;
  }
  [[ $factory_sha256 =~ ^[0-9a-f]{64}$ ]] || { echo 'Factory-passive requires a lowercase SHA-256 pin.' >&2; exit 2; }
else
  [[ -z $factory_manifest && -z $factory_sha256 && -z $factory_sources && -z $factory_wheels ]] || {
    echo 'Studio inputs require the explicit factory-passive profile.' >&2; exit 2;
  }
  if [[ -n $application_manifest || -n $application_sha256 || -n $application_assets ]]; then
    application_mode=1
    [[ -n $application_manifest && -n $application_sha256 && -n $application_assets ]] || {
    echo 'Application prototype requires manifest, reviewed SHA-256 and assets directory.' >&2; exit 2;
    }
  fi
fi
vm=inkyos-build
[[ $(limactl shell --workdir=/tmp "$vm" cat /var/lib/inkyos-build/owner) == inkyos-builder-v1 ]] || exit 1
"$PYTHON" scripts/fetch-base.py --extract build/base.img > /dev/null
"$PYTHON" scripts/fetch-packages.py --cache-dir cache/packages > /dev/null
mkdir -p build
run_dir=$(mktemp -d build/prototype.XXXXXXXX)
guest_dir="/var/tmp/inkyos-work/$(basename "$run_dir")"
if [[ $profile == factory-passive ]]; then
  guest_dir="/var/lib/inkyos-build/factory-image.${run_dir##*.}"
fi
# Whitelist source inputs, never recursively archive the working tree/home.
"$PYTHON" -I -B -S - "$run_dir" "$application_manifest" "$application_sha256" "$application_assets" \
  "$profile" "$factory_manifest" "$factory_sha256" "$factory_sources" "$factory_wheels" <<'PY'
import hashlib,importlib.util,io,json,os,pathlib,shutil,stat,subprocess,sys,tarfile
files = ['config/base-image.lock.json','config/system-packages.lock.json',
         'scripts/build-prototype.sh','scripts/fetch-base.py','scripts/fetch-packages.py',
         'scripts/run-unit-tests.py','scripts/test-linux.sh',
         'infra/lima.yaml','Makefile',
         'scripts/build-image-linux.sh','scripts/configure-rootfs.py',
         'scripts/verify-prototype.py','scripts/inspect-rootfs.py',
         'scripts/verify-artifacts.py','scripts/compare-builds.py',
         'scripts/inspect-image.sh','scripts/check-builder.sh',
         'scripts/manifest-rootfs.py','scripts/smoke-firstboot-linux.sh',
         'overlay/usr/local/lib/inkyos/firstboot.py',
         'overlay/etc/systemd/system/inkyos-firstboot.service']
out=pathlib.Path(sys.argv[1])
application=None
factory=None
factory_inputs=None
if sys.argv[5]=='factory-passive':
    spec=importlib.util.spec_from_file_location('factory_profile','scripts/factory-passive-profile.py')
    factory_tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(factory_tool)
    files += list(factory_tool.TOOL_FILES)
    factory_inputs=out/'factory-inputs'
    factory=factory_tool.stage(*sys.argv[6:10],factory_inputs)
if sys.argv[2]:
    files += ['scripts/verify-application.py','scripts/inspect-application-archives.py',
              'scripts/install-application-rootfs.py','scripts/configure-application-rootfs.py',
              'scripts/verify-application-rootfs.py']
    spec=importlib.util.spec_from_file_location('inspector','scripts/inspect-application-archives.py')
    inspector=importlib.util.module_from_spec(spec);spec.loader.exec_module(inspector)
    manifest=pathlib.Path(sys.argv[2]);pin=sys.argv[3];assets=pathlib.Path(sys.argv[4])
    application=inspector.verifier.verify(manifest,pin,assets)
    # Stage bounded ordinary files, then revalidate the complete snapshot.
    snapshot=out/'application-inputs';snapshot.mkdir(mode=0o700)
    inputs=[(manifest,'application-manifest.json',inspector.verifier.MAX_MANIFEST)]
    inputs += [(assets/a['filename'],a['filename'],a['size_bytes']) for a in application['assets']]
    for source,name,limit in inputs:
        fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream, (snapshot/name).open('xb') as target:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size>limit: raise ValueError('Invalid snapshot source')
            total=0
            while block:=stream.read(1024**2):
                total+=len(block)
                if total>limit: raise ValueError('Snapshot source grew')
                target.write(block)
    inspection=inspector.inspect_application(snapshot/'application-manifest.json',pin,snapshot)
    (out/'application-archives.json').write_text(json.dumps(inspection,indent=2,sort_keys=True)+'\n')
blobs={name:pathlib.Path(name).read_bytes() for name in sorted(set(files))}
if factory:
    blobs['factory-passive.json']=(factory_inputs/'factory-passive.json').read_bytes()
    (out/'factory-passive.json').write_bytes(blobs['factory-passive.json'])
    for name in ('inputs.json','factory-dependencies.json','factory-studio-plan.json','factory-bundle-manifest.json'):
        destination='factory-studio-inputs.json' if name=='inputs.json' else name
        (out/destination).write_bytes((factory_inputs/name).read_bytes())
if application:
    blobs['application-manifest.json']=(snapshot/'application-manifest.json').read_bytes()
    (out/'application-manifest.json').write_bytes(blobs['application-manifest.json'])
metadata={'schema_version':1,
          'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
          'worktree_dirty':bool(subprocess.check_output(['git','status','--porcelain'])),
          'files':{name:hashlib.sha256(data).hexdigest() for name,data in sorted(blobs.items())}}
encoded=(json.dumps(metadata,indent=2,sort_keys=True)+'\n').encode()
(out/'recipe-inputs.json').write_bytes(encoded)
blobs['recipe-inputs.json']=encoded
with tarfile.open(out/'recipe.tar','w',format=tarfile.USTAR_FORMAT) as archive:
    for name,data in sorted(blobs.items()):
        info=tarfile.TarInfo('recipe/'+name)
        info.size=len(data); info.mode=0o644; info.mtime=1789430400
        archive.addfile(info,io.BytesIO(data))
    if factory:
        value=json.loads((factory_inputs/'inputs.json').read_bytes())
        snapshot_names=['inputs.json','factory-passive.json','factory-dependencies.json',
                        'factory-studio-plan.json','factory-bundle-manifest.json']
        snapshot_names += ['sources/'+name for name in value['source_sha256']]
        snapshot_names += ['wheels/'+name for name in value['wheel_sha256']]
        for name in sorted(snapshot_names):
            data=(factory_inputs/name).read_bytes()
            info=tarfile.TarInfo('factory-inputs/'+name)
            info.size=len(data);info.mode=0o600;info.mtime=1789430400
            archive.addfile(info,io.BytesIO(data))
PY
if [[ $profile == factory-passive ]]; then
  # Exclusive root-owned workspace; no user-writable guest upload directory.
  limactl shell --workdir=/tmp "$vm" sudo python3 -I -B -S -c \
    'import os,pathlib,stat,sys; p=pathlib.Path(sys.argv[1]); parents=list(reversed(p.parents)); assert all(stat.S_ISDIR((s:=q.lstat()).st_mode) and (s.st_uid,s.st_gid)==(0,0) and not stat.S_IMODE(s.st_mode)&0o7022 for q in parents); os.mkdir(p,0o700); os.mkdir(p/"packages",0o700)' "$guest_dir"
  limactl shell --workdir=/tmp "$vm" sudo tar --no-same-permissions -xf - -C "$guest_dir" < "$run_dir/recipe.tar"
else
  limactl shell --workdir=/tmp "$vm" mkdir -p "$guest_dir/packages"
  limactl copy "$run_dir/recipe.tar" "$vm:$guest_dir/recipe.tar"
  limactl shell --workdir=/tmp "$vm" tar -xf "$guest_dir/recipe.tar" -C "$guest_dir"
fi
if (( application_mode )); then
  limactl shell --workdir=/tmp "$vm" mkdir "$guest_dir/application-inputs"
  for input in "$run_dir/application-inputs/"*; do
    limactl copy "$input" "$vm:$guest_dir/application-inputs/$(basename "$input")"
  done
fi
while IFS= read -r package; do
  if [[ $profile == factory-passive ]]; then
    limactl shell --workdir=/tmp "$vm" sudo python3 -I -B -S -c \
      'import os,shutil,sys; fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600); f=os.fdopen(fd,"wb"); shutil.copyfileobj(sys.stdin.buffer,f); f.close()' \
      "$guest_dir/packages/$package" < "cache/packages/$package"
  else
    limactl copy "cache/packages/$package" "$vm:$guest_dir/packages/$package"
  fi
done < <("$PYTHON" -c 'import json; print("\n".join(p["filename"] for p in json.load(open("config/system-packages.lock.json"))["packages"]))')
build_options=()
if [[ $profile == factory-passive ]]; then
  limactl shell --workdir=/tmp "$vm" sudo python3 -I -B -S -c \
    'import os,shutil,sys; fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600); f=os.fdopen(fd,"wb"); shutil.copyfileobj(sys.stdin.buffer,f); f.close()' \
    "$guest_dir/prototype.img" < build/base.img
  build_options=(--profile factory-passive)
else
  limactl copy build/base.img "$vm:$guest_dir/prototype.img"
fi
limactl shell --workdir=/tmp "$vm" sudo bash "$guest_dir/recipe/scripts/check-builder.sh" > "$run_dir/builder.json"
limactl shell --workdir=/tmp "$vm" sudo bash "$guest_dir/recipe/scripts/smoke-firstboot-linux.sh" > "$run_dir/firstboot-smoke.json"
limactl shell --workdir=/tmp "$vm" sudo bash "$guest_dir/recipe/scripts/build-image-linux.sh" "$guest_dir" "${build_options[@]}" \
  2>&1 | tee "$run_dir/build.log"
limactl shell --workdir=/tmp "$vm" sudo bash "$guest_dir/recipe/scripts/inspect-image.sh" \
  "$guest_dir/prototype.img" "$guest_dir/image-inspection.json"
for report in qualification-static.json filesystem-manifest.json image-inspection.json systemd-verify.txt boot-preserved.sha256 fsck-ext4.txt fsck-fat.txt; do
  limactl shell --workdir=/tmp "$vm" sudo cat "$guest_dir/$report" > "$run_dir/$report"
done
image_name=inkyos-system-prototype.img
if [[ $profile == factory-passive ]]; then
  image_name=inkyos-factory-passive.img
  for report in factory-studio-installation.json factory-studio-verification.json qualification-factory.json; do
    limactl shell --workdir=/tmp "$vm" sudo cat "$guest_dir/$report" > "$run_dir/$report"
  done
fi
if (( application_mode )); then
  image_name=inkyos-application-prototype.img
  for report in application-installation.json qualification-application.json sudoers-verify.txt; do
    limactl shell --workdir=/tmp "$vm" sudo cat "$guest_dir/$report" > "$run_dir/$report"
  done
  # Logs remain individually inspectable and covered by the export manifest.
  for step in venv dependencies editable pip-check; do
    limactl shell --workdir=/tmp "$vm" sudo cat "$guest_dir/application-installation.logs/$step.txt" \
      </dev/null > "$run_dir/application-install-$step.txt"
  done
fi
if [[ $profile == factory-passive ]]; then
  limactl shell --workdir=/tmp "$vm" sudo cat "$guest_dir/prototype.img" > "$run_dir/$image_name"
else
  limactl copy "$vm:$guest_dir/prototype.img" "$run_dir/$image_name"
fi
"$PYTHON" - "$run_dir" "$image_name" <<'PY'
import hashlib,json,pathlib,sys
out=pathlib.Path(sys.argv[1]); image=out/sys.argv[2]
h=hashlib.sha256()
with image.open('rb') as f:
    for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
report=json.loads((out/'image-inspection.json').read_text())
assert h.hexdigest()==report['image']['sha256'], 'Export hash mismatch'
names=['builder.json','firstboot-smoke.json','qualification-static.json',
       'filesystem-manifest.json','image-inspection.json','systemd-verify.txt',
       'boot-preserved.sha256','fsck-ext4.txt','fsck-fat.txt']
application=None
if (out/'application-manifest.json').exists():
    raw=(out/'application-manifest.json').read_bytes();data=json.loads(raw)
    application={'source_commit':data['source_commit'],'application_version':data['application_version'],
                 'manifest_sha256':hashlib.sha256(raw).hexdigest(),
                 'startup':'masked-pending-firstboot-contract','release_qualified':False}
    names += ['application-manifest.json','application-archives.json','application-installation.json',
              'qualification-application.json','sudoers-verify.txt']
    names += sorted(p.name for p in out.glob('application-install-*.txt'))
manifest={'schema_version':1,'kind':'application-prototype' if application else 'system-prototype','hardware_qualified':False,
          'application':application,'image':{'filename':image.name,'size_bytes':image.stat().st_size,
                                    'sha256':h.hexdigest()},
          'recipe':json.loads((out/'recipe-inputs.json').read_text()),
          'reports':{name:hashlib.sha256((out/name).read_bytes()).hexdigest() for name in names}}
if (out/'factory-passive.json').exists():
    factory=json.loads((out/'factory-passive.json').read_bytes())
    names += ['factory-passive.json','factory-studio-inputs.json','factory-dependencies.json',
              'factory-studio-plan.json','factory-bundle-manifest.json',
              'factory-studio-installation.json','factory-studio-verification.json','qualification-factory.json']
    manifest.update(kind='factory-passive',factory=factory,runtime_qualified=False,
                    reports={name:hashlib.sha256((out/name).read_bytes()).hexdigest() for name in names})
(out/'manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
(out/'SHA256SUMS').write_text(h.hexdigest()+'  '+image.name+'\n')
PY
"$PYTHON" scripts/verify-artifacts.py "$run_dir" --output "$run_dir.integrity.json"
# Successful export only: preserve failed working copies for diagnosis.
if [[ $profile == factory-passive ]]; then
  limactl shell --workdir=/tmp "$vm" sudo rm -- "$guest_dir/prototype.img"
else
  limactl shell --workdir=/tmp "$vm" rm -- "$guest_dir/prototype.img"
fi
echo "Prototype and evidence: $repo/$run_dir"
