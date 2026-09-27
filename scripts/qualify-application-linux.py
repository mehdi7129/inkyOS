#!/usr/bin/env python3
"""Install and smoke a pinned application in a disposable ARM64 VM workspace.

Never used by the image builder. The candidate supplies its own qualification
script. This bench runs candidate/build code as nobody without network and
records a VM software result, not hardware or final-image qualification.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import signal
import stat
import subprocess
import tarfile
import zipfile

_spec = importlib.util.spec_from_file_location('archive_inspector',Path(__file__).with_name('inspect-application-archives.py'))
inspector = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(inspector)


def sha(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        while data:=stream.read(1024**2): digest.update(data)
    return digest.hexdigest()


def stop(signum, frame):
    raise KeyboardInterrupt


def child_limits():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_FSIZE,(64*1024**2,64*1024**2))


def copy_regular(source, target, limit):
    fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>limit:
            raise ValueError('Snapshot requires a bounded ordinary file')
        total=0
        with target.open('xb') as output:
            while block:=stream.read(1024**2):
                total+=len(block)
                if total>limit: raise ValueError('Snapshot source exceeds limit')
                output.write(block)
    return target


def run(command, cwd, env, log, timeout=300):
    """One unprivileged process group with kernel-enforced network isolation."""
    prefix=['unshare','--net','--uts','--ipc','--fork','setpriv','--reuid=65534',
            '--regid=65534','--clear-groups','--no-new-privs']
    with log.open('xb') as output:
        process=subprocess.Popen(prefix+command,cwd=cwd,env=env,stdout=output,
                                 stderr=subprocess.STDOUT,start_new_session=True,preexec_fn=child_limits)
        try:
            return process.wait(timeout=timeout)
        except BaseException:
            try: os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait()
            raise


def ordinary_member(name, directory):
    # Independent extraction guard, in addition to the full inert scanner.
    return inspector.safe_name(name,directory,inspector.DEFAULT_LIMITS)


def extract_inputs(data, assets, root):
    application=root/'application'; wheelhouse=root/'wheelhouse'
    application.mkdir();wheelhouse.mkdir()
    by_role={a['role']:assets/a['filename'] for a in data['assets']}
    with tarfile.open(by_role['application'],'r:gz') as archive:
        for member in archive:
            if not (member.isfile() or member.isdir()): raise ValueError('Ordinary tar members required')
            name=ordinary_member(member.name,member.isdir());target=application/name
            if member.isdir(): target.mkdir(parents=True,exist_ok=True)
            else:
                target.parent.mkdir(parents=True,exist_ok=True)
                with target.open('xb') as out, archive.extractfile(member) as source: shutil.copyfileobj(source,out,1024**2)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
    with zipfile.ZipFile(by_role['wheelhouse']) as archive:
        for member in archive.infolist():
            name=ordinary_member(member.filename,member.is_dir());target=wheelhouse/name
            if member.is_dir(): target.mkdir(parents=True,exist_ok=True)
            else:
                target.parent.mkdir(parents=True,exist_ok=True)
                with target.open('xb') as out,archive.open(member) as source: shutil.copyfileobj(source,out,1024**2)
    lock=root/'requirements.lock';shutil.copyfile(by_role['python_lock'],lock)
    # Require a simple exact registry lock: no directives, links or local paths.
    text=lock.read_text().replace('\\\n',' ')
    import re
    for line in text.splitlines():
        line=line.strip()
        if line and not line.startswith('#') and not re.fullmatch(
                r'[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9][A-Za-z0-9.!+_-]*(?:\s+--hash=sha256:[0-9a-f]{64})+',line):
            raise ValueError('Only exact package versions and SHA-256 hashes accepted in bench lock')
    if os.path.lexists(application/'server/.venv'):
        raise ValueError('Candidate must not contain a pre-existing venv')
    return application,wheelhouse,lock


def main():
    signal.signal(signal.SIGTERM,stop)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',type=Path,required=True);p.add_argument('--sha256',required=True)
    p.add_argument('--assets-dir',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    if (platform.system()!='Linux' or platform.machine()!='aarch64' or os.geteuid()!=0
            or Path('/var/lib/inkyos-build/owner').read_text().strip()!='inkyos-builder-v1'):
        raise SystemExit('Dedicated root ARM64 builder required')
    if platform.python_version()!='3.13.5': raise SystemExit('Python 3.13.5 required')
    for path in (args.assets_dir,args.manifest,args.output):
        if path.is_symlink() or not path.resolve().is_relative_to('/var/tmp/inkyos-application-tests'):
            raise SystemExit('All paths must stay within the disposable application bench')
    data=inspector.verifier.verify(args.manifest,args.sha256,args.assets_dir)
    os.umask(0o022);args.output.mkdir(mode=0o755)
    # Snapshot into a root-only directory, then revalidate before extraction.
    snapshot=args.output/'inputs';snapshot.mkdir(mode=0o700)
    manifest=copy_regular(args.manifest,snapshot/'manifest.json',inspector.verifier.MAX_MANIFEST)
    for asset in data['assets']:
        copy_regular(args.assets_dir/asset['filename'],snapshot/asset['filename'],asset['size_bytes'])
    inspection=inspector.inspect_application(manifest,args.sha256,snapshot)
    work=args.output/'work';work.mkdir(mode=0o755)
    application,wheelhouse,lock=extract_inputs(data,snapshot,work)
    venv=application/'server/.venv'
    source_smoke=application/'scripts/qualify_offline_runtime.py'
    if not source_smoke.is_file(): raise ValueError('Candidate must supply its versioned qualification script')
    smoke=copy_regular(source_smoke,args.output/'qualification.py',1024**2)
    smoke_hash=sha(smoke)
    # Source/editable/venv need application ownership. Other inputs stay root-owned.
    for path in [application,*application.rglob('*')]:
        if path.is_symlink() or not (path.is_dir() or stat.S_ISREG(path.stat().st_mode)):
            raise ValueError('Unexpected extracted file type')
        os.chown(path,65534,65534)
    temp=work/'tmp';temp.mkdir(mode=0o700);os.chown(temp,65534,65534)
    env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','TZ':'UTC','PYTHONNOUSERSITE':'1',
         'PYTHONHASHSEED':'0','PIP_CONFIG_FILE':'/dev/null','TMPDIR':str(temp)}
    python=str(venv/'bin/python')
    pip=[python,'-m','pip','--isolated','--disable-pip-version-check','--no-cache-dir']
    steps=[('venv',['/usr/bin/python3','-m','venv',str(venv)]),
           ('dependencies',pip+['install','--no-index','--only-binary=:all:','--require-hashes',
                                '--find-links',str(wheelhouse),'-r',str(lock)]),
           ('editable',pip+['install','--no-index','--no-deps','--no-build-isolation',
                            '--no-compile','-e',str(application/'server')+'[pi]']),
           ('pip-check',pip+['check']),
           ('runtime-smoke',[python,str(smoke)])]
    report={'schema_version':1,'scope':'disposable-vm-offline-application-software',
            'manifest_sha256':args.sha256,'source_commit':data['source_commit'],
            'application_version':data['application_version'],'python':platform.python_version(),
            'architecture':platform.machine(),'glibc':platform.libc_ver(),'build_uid':65534,
            'recipe_sha256':sha(Path(__file__)),'candidate_smoke_sha256':smoke_hash,
            'image_modified':False,'hardware_qualified':False,'release_qualified':False,
            'archive_inspection':inspection,'steps':[],'passed':False,
            'inputs_snapshotted_root_only':True,'qualification_script_root_owned':True,
            'builder_packages':subprocess.check_output(['dpkg-query','-W','-f=${Package}=${Version}\n'],text=True).splitlines(),
            'limits':['Builder VM, not the exact Raspberry Pi image rootfs or kernel.',
                      'Candidate code executes only in the disposable unprivileged software bench.',
                      'No service boot, application lifespan, GPIO/SPI, BLE or real radio test.']}
    for name,command in steps:
        log=args.output/(name+'.txt')
        if sha(smoke)!=smoke_hash: raise ValueError('Qualification program changed')
        try:
            code=run(command,application,env,log)
        except subprocess.TimeoutExpired:
            code=124
        except KeyboardInterrupt:
            code=130
        if sha(smoke)!=smoke_hash: raise ValueError('Qualification program changed')
        report['steps'].append({'name':name,'exit_code':code,'log_sha256':sha(log)})
        if code: break
    if len(report['steps'])==len(steps) and all(s['exit_code']==0 for s in report['steps']):
        if (args.output/'runtime-smoke.txt').stat().st_size>1024**2:
            raise ValueError('Runtime report exceeds limit')
        result=json.loads((args.output/'runtime-smoke.txt').read_text())
        if (result.get('passed') is not True or result.get('hardware_qualified') is not False
                or result.get('application_version') != data['application_version']
                or result.get('application_lifespan_entered') is not False or result.get('data_created') is not False
                or result.get('network_interfaces')!=['lo']):
            raise ValueError('Runtime result does not satisfy software-bench contract')
        report['runtime_smoke']=result;report['passed']=True
    (args.output/'results.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'passed':report['passed'],'steps':report['steps']},indent=2))
    return 0 if report['passed'] else 1


if __name__=='__main__':
    raise SystemExit(main())
