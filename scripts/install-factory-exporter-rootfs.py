#!/usr/bin/env python3
"""Prepare the standalone staging exporter in a private disposable ARM64 rootfs.

No image recipe invokes this script. No credentials or application code run.
The reviewed wheels are extracted as UID/GID 1000, without pip or an editable
install. An absent system-support pin refuses before any filesystem mutation.
Failure leaves an unqualified disposable tree for inspection, never a receipt.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import stat
import subprocess
import sys

spec = importlib.util.spec_from_file_location(
    '_factory_exporter_verifier', Path(__file__).with_name('verify-factory-exporter-rootfs.py'))
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
require = verifier.require
checked_path = verifier.checked_path
copy_regular = verifier.application_installer.copy_regular
DESTINATION = Path('/' + verifier.DESTINATION)
SCRATCH = Path('/var/tmp/inkyos-factory-exporter-install')

# This is passed to the already trusted HOST interpreter after unshare. All
# imports, ctypes symbols and definitions are prepared before chroot: no target
# setpriv/env/Python, NSS lookup, dynamic helper or exception hook runs as root.
HOST_LAUNCHER = '''import ctypes,errno,os,sys
class Header(ctypes.Structure):
 _fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
class Data(ctypes.Structure):
 _fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
libc=ctypes.CDLL(None,use_errno=True)
prctl=libc.prctl;prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong];prctl.restype=ctypes.c_int
capget=libc.capget;capget.argtypes=[ctypes.POINTER(Header),ctypes.POINTER(Data)];capget.restype=ctypes.c_int
capset=libc.capset;capset.argtypes=capget.argtypes;capset.restype=ctypes.c_int
# sysconfig computes its user base while importing; HOME avoids pwd/NSS even
# though the build never enables user site-packages or installs into that path.
environment={'HOME':'/home/inky','PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','TZ':'UTC',
 'PYTHONNOUSERSITE':'1','PYTHONDONTWRITEBYTECODE':'1','PYTHONHASHSEED':'0'}
def require(value):
 if not value: raise RuntimeError('launcher_guard')
def control(option,a=0,b=0,c=0,d=0):
 value=prctl(option,a,b,c,d)
 require(value>=0)
 return value
def capabilities():
 header=Header(0x20080522,0);data=(Data*2)()
 require(capget(ctypes.byref(header),data)==0 and header.version==0x20080522)
 return header,data
try:
 require(len(sys.argv)>=3 and os.getresuid()==(0,0,0))
 root=sys.argv[1];command=sys.argv[2:]
 prefixes=('/var/lib/inkyos-build/factory-exporter.','/var/lib/inkyos-build/factory-image.')
 matches=[prefix for prefix in prefixes if root.startswith(prefix)];suffix='/root'
 require(len(matches)==1 and root.endswith(suffix))
 token=root[len(matches[0]):-len(suffix)]
 require(token.isascii() and token.isalnum())
 require(command[0]=='/usr/bin/python3.13')
 # Keep effective CHROOT/SETUID/SETGID until their numeric syscalls finish,
 # but remove all routes for capabilities to survive or return after exec.
 control(28,0);require(control(27)==0)  # SET/GET_SECUREBITS, including KEEP_CAPS=0
 control(38,1);require(control(39)==1)  # SET/GET_NO_NEW_PRIVS
 control(47,4)  # PR_CAP_AMBIENT_CLEAR_ALL
 known=[]
 for capability in range(65):
  ctypes.set_errno(0);value=prctl(23,capability,0,0,0)  # PR_CAPBSET_READ
  if value<0:
   require(ctypes.get_errno()==errno.EINVAL and capability>0)
   break
  require(value in (0,1) and capability<64)
  known.append(capability);control(24,capability)  # PR_CAPBSET_DROP
 else: raise RuntimeError('unsupported_capability_range')
 header,data=capabilities()
 for item in data: item.inheritable=0
 require(capset(ctypes.byref(header),data)==0)
 os.chroot(root);os.chdir('/')
 os.setgroups([]);os.setresgid(1000,1000,1000);os.setresuid(1000,1000,1000)
 require(os.getresuid()==(1000,1000,1000) and os.getresgid()==(1000,1000,1000) and os.getgroups()==[])
 header,data=capabilities()
 require(all(item.effective==item.permitted==item.inheritable==0 for item in data))
 require(control(27)==0 and control(39)==1)
 for capability in known:
  require(control(23,capability)==0 and control(47,1,capability)==0)
 os.execve(command[0],command,environment)
 raise RuntimeError('exec_returned')
except BaseException:
 # Especially after chroot, never use traceback/print/logging/sys.exit: an
 # exception hook or lazy import must not consult the target tree under root.
 try: os.write(2,b'factory_exporter_launcher_failed\\n')
 except BaseException: pass
 os._exit(127)
'''

# Root prepares and validates immutable input snapshots. This trusted extraction
# driver is executed only after chroot + numeric UID/GID drop, never by root.
EXTRACT = '''import hashlib,json,os,zipfile
from pathlib import Path
assert os.getresuid()==(1000,1000,1000) and os.getresgid()==(1000,1000,1000) and os.getgroups()==[]
stage=Path('/var/tmp/inkyos-factory-exporter-install')
site=Path('/usr/lib/inkyos/factory-exporter/venv/lib/python3.13/site-packages')
lock=json.loads((stage/'inputs/lock.json').read_bytes())
def put(name,raw):
 assert not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/'))
 target=site/name; target.parent.mkdir(parents=True,exist_ok=True)
 with target.open('xb') as out: out.write(raw)
 target.chmod(0o644)
for filename,pin in lock['wheel_sha256'].items():
 wheel=stage/'inputs/wheels'/filename
 assert hashlib.sha256(wheel.read_bytes()).hexdigest()==pin
 with zipfile.ZipFile(wheel) as archive:
  for member in archive.infolist():
   if not member.is_dir(): put(member.filename,archive.read(member))
for name,pin in lock['source_sha256'].items():
 raw=(stage/'inputs/sources'/name).read_bytes()
 assert hashlib.sha256(raw).hexdigest()==pin
 put(name,raw)
'''


def guard_destinations(rootfs):
    checked_path(rootfs)
    require(rootfs != Path('/'), 'Host root is never an installation target')
    for path in (rootfs / DESTINATION.relative_to('/'), rootfs / SCRATCH.relative_to('/')):
        if path.parent == rootfs / 'usr/lib/inkyos' and not os.path.lexists(path.parent):
            checked_path(path.parent.parent)
        else:
            checked_path(path.parent)
        require(not os.path.lexists(path), 'Exporter destination or scratch already exists')


def check_workspace(rootfs):
    require(verifier.re.fullmatch(r'/var/lib/inkyos-build/factory-(?:exporter|image)\.[A-Za-z0-9]+/root',
                                 str(rootfs)), 'Dedicated disposable exporter path required')
    checked_path(rootfs)
    work = rootfs.parent
    for path in (work, *work.parents):
        record = verifier.single_record(path)
        require(record['type'] == 'directory', 'Build workspace directory required')
        verifier.secure_record(record)
        if path == work:
            require(record['mode'] == '0700', 'Private root-owned build workspace required')
    return work


def check_environment(rootfs, sources, wheels, support, output):
    require(sys.platform.startswith('linux') and platform.machine() == 'aarch64'
            and os.geteuid() == 0, 'Dedicated root Linux ARM64 builder required')
    work = check_workspace(rootfs)
    marker = checked_path(Path('/var/lib/inkyos-build/owner'))
    verifier.secure_record(verifier.single_record(marker))
    require(verifier.ordinary(marker, 256) == b'inkyos-builder-v1\n', 'Dedicated builder marker required')
    require(os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net') and
            sorted(name for _, name in socket.if_nameindex()) == ['lo'],
            'Private network namespace with only loopback required')
    require(os.readlink('/proc/self/ns/mnt') != os.readlink('/proc/1/ns/mnt'),
            'Private mount namespace required')
    guard_destinations(rootfs)
    require(os.path.ismount(rootfs), 'Mounted disposable rootfs required')
    mounts = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    rows = [fields for fields in mounts if fields[4] == str(rootfs)]
    require(len(rows) == 1, 'Unique rootfs mount required')
    row = rows[0]; split = row.index('-')
    require(row[split + 1] == 'ext4' and verifier.re.fullmatch(r'/dev/loop\d+p2', row[split + 2])
            and {'rw', 'nosuid', 'nodev'} <= set(row[5].split(',')),
            'Writable nosuid/nodev regular-image loop partition required')
    for path in (sources, wheels, support):
        checked_path(path)
        require(path.is_relative_to(work) and not path.is_relative_to(rootfs),
                'Inputs must be outside rootfs in the private exporter workspace')
    checked_path(output, missing=True)
    require(output.parent == work and not os.path.lexists(output), 'New report outside rootfs required')
    for path in (rootfs, rootfs / 'usr', rootfs / 'usr/lib', rootfs / 'usr/lib/inkyos'):
        if path != rootfs / 'usr/lib/inkyos' or os.path.lexists(path):
            verifier.secure_record(verifier.single_record(path))


def host_interpreter():
    """The same trusted host Python, never a program discovered in the image."""
    executable = Path(sys.executable)
    require(executable.is_absolute(), 'Absolute host Python interpreter required')
    executable = executable.resolve(strict=True)
    checked_path(executable)
    for path in (executable, *executable.parents):
        verifier.secure_record(verifier.single_record(path))
    require(stat.S_ISREG(executable.stat().st_mode) and executable.stat().st_mode & 0o111,
            'Regular executable host interpreter required')
    return str(executable)


def child_command(rootfs, command):
    # PID namespace init exit waits for namespace children to be killed/reaped;
    # the unshare supervisor itself is always waited before any freeze/chown.
    return ['/usr/bin/unshare', '--pid', '--ipc', '--fork', '--kill-child=KILL',
            host_interpreter(), '-I', '-B', '-S', '-c', HOST_LAUNCHER, str(rootfs), *command]


def install_steps():
    return [
        ('venv', ['/usr/bin/python3.13', '-I', '-B', '-S', '-m', 'venv', '--without-pip',
                  '--without-scm-ignore-files', '--symlinks', str(DESTINATION / 'venv')]),
        ('payload', ['/usr/bin/python3.13', '-I', '-B', '-S', str(SCRATCH / 'extract.py')]),
    ]


def run_step(rootfs, command, log, timeout=120):
    with log.open('xb') as out:
        process = subprocess.Popen(child_command(rootfs, command), cwd=rootfs,
                                   env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'},
                                   stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                   start_new_session=True,
                                   preexec_fn=verifier.application_installer.child_limits)
        try:
            code = process.wait(timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
    require(code == 0, 'Unprivileged exporter build step failed')


def snapshot_inputs(lock, sources, wheels, scratch):
    inputs = scratch / 'inputs'; inputs.mkdir(mode=0o755)
    for label, source, pins in (('sources', sources, lock['source_sha256']),
                                ('wheels', wheels, lock['wheel_sha256'])):
        target = inputs / label; target.mkdir(mode=0o755)
        for name in pins:
            destination = target / name
            destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            copy_regular(source / name, destination, verifier.LIMIT)
            destination.chmod(0o644)
    (inputs / 'lock.json').write_text(json.dumps(lock, sort_keys=True) + '\n')
    (inputs / 'lock.json').chmod(0o644)
    (scratch / 'extract.py').write_text(EXTRACT)
    (scratch / 'extract.py').chmod(0o644)
    return inputs


def finish_tree(bundle, expected, manifest_raw, version):
    """Only a fixed venv scaffold normalization; unknown entries fail closed."""
    # No child or candidate has executed since its waited PID namespace ended.
    actual = verifier.inventory_module.inventory(bundle)
    for record in actual.values():
        verifier.secure_record(record, owner=(1000, 1000))
    # Activation is unused by the immutable absolute argv. Remove only these
    # known non-importable outputs, refusing links, hardlinks and extra files.
    for leaf in ('activate', 'activate.csh', 'activate.fish', 'Activate.ps1'):
        path = bundle / 'venv/bin' / leaf
        record = actual.get('venv/bin/' + leaf, {})
        require(record.get('type') == 'file', 'Expected venv activation scaffold absent')
        path.unlink()
    cfg = bundle / 'venv/pyvenv.cfg'
    require(actual.get('venv/pyvenv.cfg', {}).get('type') == 'file', 'Venv configuration absent')
    cfg.write_bytes(verifier.configuration(version)); cfg.chmod(0o644)
    before_freeze = verifier.inventory_module.inventory(bundle)
    # Compare bytes/types/modes BEFORE ownership changes. No observed hashes are
    # promoted into the expected map, and no unknown imports are normalized away.
    owned_expected = {path: dict(record, uid=1000, gid=1000)
                      for path, record in expected.items() if path != 'manifest.json'}
    require(before_freeze == owned_expected, 'Unexpected venv or dependency payload before freeze')
    # A child-created manifest is already an unexpected entry above. Publish
    # only the precomputed bytes, never overwrite an observed manifest.
    require(verifier.file_record(manifest_raw) == expected['manifest.json'], 'Expected manifest mismatch')
    with (bundle / 'manifest.json').open('xb') as stream:
        stream.write(manifest_raw)
    (bundle / 'manifest.json').chmod(0o644)
    os.chown(bundle / 'manifest.json', 1000, 1000)
    before_freeze = verifier.inventory_module.inventory(bundle)
    require(before_freeze == {path: dict(record, uid=1000, gid=1000) for path, record in expected.items()},
            'Unexpected entry during manifest publication')
    for path in sorted(before_freeze, key=lambda value: value.count('/'), reverse=True):
        target = bundle if path == '.' else bundle / path
        os.chown(target, 0, 0, follow_symlinks=False)
    require(verifier.inventory_module.inventory(bundle) == expected, 'Root-owned freeze verification failed')
    return expected


def install(args):
    lock = verifier.load_lock()
    # This is intentionally the first gate: null/unreviewed support performs no
    # mkdir, snapshot, chown, subprocess, rootfs mutation or success report.
    verifier.require_support_pin(lock)
    support, records = verifier.load_support(lock, args.support_manifest)
    check_environment(args.rootfs, args.sources_dir, args.wheels_dir, args.support_manifest, args.output)
    payload = verifier.expected_payload(lock, args.sources_dir, args.wheels_dir)
    expected = verifier.expected_bundle(payload, support['python_version'], lock['support_manifest_sha256'])
    manifest_raw = verifier.bundle_manifest(expected, lock['support_manifest_sha256'])
    native = {verifier.DESTINATION + '/' + verifier.SITE + '/' + path
              for path, raw in payload.items() if raw.startswith(b'\x7fELF')}
    require(native <= set(support['elf_closure_review']['roots']), 'Native wheel ELF review missing')
    verifier.verify_support(args.rootfs, support, records)
    os.umask(0o022)
    logs = args.output.with_name(args.output.name + '.logs'); logs.mkdir(mode=0o700)
    scratch = args.rootfs / SCRATCH.relative_to('/'); scratch.mkdir(mode=0o755)
    inputs = snapshot_inputs(lock, args.sources_dir, args.wheels_dir, scratch)
    require(verifier.expected_payload(lock, inputs / 'sources', inputs / 'wheels') == payload,
            'Input snapshot differs from reviewed payload')
    bundle = args.rootfs / DESTINATION.relative_to('/')
    if not os.path.lexists(bundle.parent):
        bundle.parent.mkdir(mode=0o755)
    bundle.mkdir(mode=0o755)
    os.chown(bundle, 1000, 1000)
    for label, command in install_steps():
        run_step(args.rootfs, command, logs / (label + '.txt'))
    finish_tree(bundle, expected, manifest_raw, support['python_version'])
    # Verify support again after all unprivileged build steps, before admitting
    # any successful staging report. The sources and wheels remain external.
    report = verifier.verify(args.rootfs, lock, inputs / 'sources', inputs / 'wheels', args.support_manifest)
    require(shutil.rmtree.avoids_symlink_attacks, 'Safe scratch removal unavailable')
    shutil.rmtree(scratch)
    report.update(scope='staging-factory-exporter-install', build_uid=1000, build_gid=1000,
                  bundle_manifest_sha256=expected['manifest.json']['sha256'],
                  image_code_executed=True, pip_executed=False,
                  application_code_executed=False, image_recipe_changed=False,
                  scratch_removed=True, all_build_children_waited=True)
    with args.output.open('x', encoding='utf-8') as out:
        json.dump(report, out, indent=2, sort_keys=True); out.write('\n')
    return report


def main(argv=None):
    signal.signal(signal.SIGTERM, verifier.application_installer.stop)
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ('rootfs', 'sources-dir', 'wheels-dir', 'support-manifest', 'output'):
        parser.add_argument('--' + field, type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        install(args)
        print('Staging exporter installed and statically verified; runtime remains inactive.')
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError,
            verifier.zipfile.BadZipFile, verifier.inventory_module.ManifestError):
        print('Staging exporter installation refused; no qualified artifact or success receipt.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
