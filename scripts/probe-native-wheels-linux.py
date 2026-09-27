#!/usr/bin/env python3
"""Experimental native wheel builds in the dedicated Linux VM, never a Pi image.

Only the two audited immutable source distributions are accepted. Runs their
build backends as nobody, without network or privilege escalation. No wheel or
application import/install is performed. Output is research, not release input.
"""
import argparse
import base64
import csv
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import resource
import signal
import stat
import subprocess
import tarfile
import zipfile

SOURCES = {
    'RPi.GPIO-0.7.1.tar.gz': (29090, 'cd61c4b03c37b62bba4a5acfea9862749c33c618e0295e7e90aa4713fb373b70'),
    'spidev-3.8.tar.gz': (13893, '2bc02fb8c6312d519ebf1f4331067427c0921d3f77b8bcaf05189a2e8b8382c0'),
}
EPOCH = '1789430400'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract_audited(raw, destination):
    """Copy only bounded, ordinary entries from already pinned tiny sdists."""
    records, names, roots = [], set(), set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        total = 0
        for member in archive:
            name = member.name.rstrip('/') if member.isdir() else member.name
            path = PurePosixPath(name)
            if (not name or path.is_absolute() or '..' in path.parts or str(path) != name
                    or '\\' in name or name in names or member.mode & 0o7000
                    or not (member.isfile() or member.isdir())):
                raise ValueError('Invalid source archive member')
            names.add(name); roots.add(path.parts[0]); total += member.size
            if len(names) > 1000 or member.size > 1024 * 1024 or total > 5 * 1024 * 1024:
                raise ValueError('Source archive exceeds research limits')
            content = archive.extractfile(member).read() if member.isfile() else None
            records.append((path, content))
    if len(roots) != 1:
        raise ValueError('Source must have one root')
    # No source code runs until the entire archive has passed the check.
    destination.mkdir()
    for path, content in records:
        target = destination / str(path)
        if content is None:
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(content)
    return destination / roots.pop()



def verify_wheel(wheel, source_name):
    expected = {'RPi.GPIO-0.7.1.tar.gz': 'rpi_gpio-0.7.1',
                'spidev-3.8.tar.gz': 'spidev-3.8'}[source_name]
    info = wheel.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_size > 64*1024**2
            or wheel.name != expected + '-cp313-cp313-linux_aarch64.whl'):
        raise ValueError('Expected ordinary native wheel with exact name/tag')
    native, contents, total = [], {}, 0
    with zipfile.ZipFile(wheel) as archive:
        if len(archive.infolist()) > 256:
            raise ValueError('Too many wheel members')
        for entry in archive.infolist():
            path = PurePosixPath(entry.filename)
            total += entry.file_size
            if (path.is_absolute() or '..' in path.parts or str(path) != entry.filename
                    or entry.filename in contents or entry.is_dir()
                    or stat.S_ISLNK(entry.external_attr >> 16) or entry.flag_bits & 1
                    or entry.file_size > 8*1024**2 or total > 32*1024**2
                    or entry.compress_type not in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED)):
                raise ValueError('Invalid or oversized wheel member')
            data = archive.read(entry)  # bounded size above; validates CRC
            contents[entry.filename] = data
            if entry.filename.endswith('.so'):
                if (data[:6] != b'\x7fELF\x02\x01' or len(data) < 64
                        or int.from_bytes(data[18:20],'little') != 183):
                    raise ValueError('Expected ELF64 little-endian AArch64')
                native.append({'filename':entry.filename,'sha256':hashlib.sha256(data).hexdigest(),
                               'size_bytes':len(data),'elf_machine':'AArch64'})
    dist = expected + '.dist-info/'
    wheel_metadata = contents[dist+'WHEEL'].decode('utf-8').splitlines()
    if (not native or [x for x in wheel_metadata if x.startswith('Tag:')] !=
            ['Tag: cp313-cp313-linux_aarch64'] or 'Root-Is-Purelib: false' not in wheel_metadata
            or dist+'METADATA' not in contents):
        raise ValueError('Native wheel metadata/object required')
    rows = list(csv.reader(io.StringIO(contents[dist+'RECORD'].decode('utf-8'))))
    seen = set()
    for row in rows:
        if len(row) != 3 or row[0] in seen or row[0] not in contents:
            raise ValueError('Invalid wheel RECORD')
        name, encoded, size = row; seen.add(name)
        if name == dist+'RECORD':
            if encoded or size: raise ValueError('Invalid self RECORD')
        else:
            expected_hash = base64.urlsafe_b64encode(hashlib.sha256(contents[name]).digest()).decode().rstrip('=')
            if encoded != 'sha256='+expected_hash or size != str(len(contents[name])):
                raise ValueError('Wheel RECORD hash/size mismatch')
    if seen != set(contents): raise ValueError('Incomplete wheel RECORD')
    return {'filename':wheel.name,'size_bytes':info.st_size,'sha256':digest(wheel),
            'native_objects':native}


def build_limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
    resource.setrlimit(resource.RLIMIT_FSIZE, (256 * 1024 ** 2, 256 * 1024 ** 2))


def main():
    def terminate(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,terminate)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if (platform.system() != 'Linux' or platform.machine() != 'aarch64' or os.geteuid() != 0
            or Path('/var/lib/inkyos-build/owner').read_text().strip() != 'inkyos-builder-v1'):
        raise SystemExit('Dedicated root ARM64 builder required')
    if platform.python_version() != '3.13.5':
        raise SystemExit('This research targets Python 3.13.5 exactly')
    for p in (args.inputs, args.output):
        if p.is_symlink() or not p.resolve().is_relative_to('/var/tmp/inkyos-native-wheels'):
            raise SystemExit('Research paths must stay inside the dedicated VM directory')
    inputs = {}
    for name, (size, expected) in SOURCES.items():
        path = args.inputs / name
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode) or path.stat().st_size != size:
            raise SystemExit('Invalid source input')
        raw = path.read_bytes()
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != expected:
            raise SystemExit('Source hash mismatch')
        inputs[name] = raw
    args.output.mkdir(mode=0o755)  # exclusive; previous evidence never overwritten
    os.umask(0o022)
    report = {
        'schema_version': 1, 'scope': 'experimental-native-wheel-compilation',
        'python': platform.python_version(), 'architecture': platform.machine(),
        'glibc': platform.libc_ver(), 'source_date_epoch': EPOCH,
        'build_packages': {name: importlib.metadata.version(name) for name in ['pip','setuptools','wheel']},
        'compiler': subprocess.check_output(['gcc','--version'],text=True).splitlines()[0],
        'builder_packages': subprocess.check_output(['dpkg-query','-W','-f=${Package}=${Version}\n'],text=True).splitlines(),
        'recipe_sha256': digest(Path(__file__)),
        'network_namespace': 'isolated', 'build_uid': 65534,
        'application_executed': False, 'libraries_imported': False,
        'hardware_qualified': False, 'release_qualified': False, 'builds': [],
    }
    for name, raw in inputs.items():
        job = args.output / name.removesuffix('.tar.gz')
        job.mkdir(mode=0o755)
        source = extract_audited(raw, job/'source')
        for path in [job, *job.rglob('*')]:
            os.chmod(path, 0o755 if path.is_dir() else 0o644)
            os.chown(path, 65534, 65534)
        for part in ('tmp','wheels'):
            (job/part).mkdir(mode=0o700); os.chown(job/part,65534,65534)
        env = {'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','TZ':'UTC',
               'SOURCE_DATE_EPOCH':EPOCH, 'PYTHONHASHSEED':'0', 'PYTHONNOUSERSITE':'1',
               'PIP_CONFIG_FILE':'/dev/null','TMPDIR':str(job/'tmp'),
               'CFLAGS':f'-g0 -ffile-prefix-map={job}=/build/native-wheel',
               'CXXFLAGS':f'-g0 -ffile-prefix-map={job}=/build/native-wheel'}
        command = ['unshare','--net','--uts','--ipc','--fork',
                   'setpriv','--reuid=65534','--regid=65534','--clear-groups','--no-new-privs',
                   '/usr/bin/python3','-m','pip','--disable-pip-version-check',
                   'wheel','--use-pep517','--no-index','--no-deps','--no-build-isolation',
                   '--no-cache-dir','--wheel-dir',str(job/'wheels'),'.']
        log = job/'build.txt'
        with log.open('xb') as stream:
            process = subprocess.Popen(command,cwd=source,env=env,stdout=stream,
                                       stderr=subprocess.STDOUT,preexec_fn=build_limits,
                                       start_new_session=True)
            try:
                code = process.wait(timeout=180)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL)
                process.wait()
                code = 124
            except BaseException:
                os.killpg(process.pid,signal.SIGKILL)
                process.wait()
                raise
        record = {'source':name,'source_sha256':hashlib.sha256(raw).hexdigest(),
                  'exit_code':code,'log_sha256':digest(log),'wheels':[]}
        for wheel in sorted((job/'wheels').glob('*.whl')):
            record['wheels'].append(verify_wheel(wheel,name))
        report['builds'].append(record)
    report['passed'] = all(b['exit_code']==0 and len(b['wheels'])==1 for b in report['builds'])
    (args.output/'results.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'passed':report['passed'],'builds':report['builds']},indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
