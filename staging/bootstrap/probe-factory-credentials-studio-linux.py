#!/usr/bin/env python3
"""Opt-in private builder fixture: real pinned serializer, never application startup.

The private controller prepares an isolated venv offline as UID 1000 and starts
this probe in a transient network namespace with TasksMax=2. Only the publisher's
documented synthetic-root seam is used: the fixed interpreter path is replaced
with the fixture interpreter. No production path, hook or authority is installed.
Credential bytes stay in two private guest fixture directories and in memory.
"""
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import types
import zipfile


STUDIO_COMMIT = 'cf17a0514989023143798570a8ae47739b829301'
PUBLISHER_SHA256 = '82c071dd2ab841c91464a680e9757a469dbf5f2d105f68999c18a387b70bb222'
STUDIO_PINS = {
    'inky_web/__init__.py': 'eb46584f68f555f175241641fc930408af7747bc7d45c997216dad6df2be88cc',
    'inky_web/provisioning/__init__.py': 'fa80434eb14bdd643937dedfc52f345a517f856335428bd9b047bcb24be0645f',
    'inky_web/provisioning/factory_credentials.py': '55b3f5b11c5ebad60ae2a65cf9006dd7d1cb2ce2777fc3d5511ea0d72aa6715b',
    'inky_web/auth.py': '758a867cb1d6c769befdfb0178841e81d2a7d47b0395f4eb54b90a6f2ab7803d',
}
WHEELS = {
    'annotated_doc-0.0.5-py3-none-any.whl': '117bac03a25ede5df5440e855b32d556049ca169ead221505badf432fed4b101',
    'annotated_types-0.8.0-py3-none-any.whl': 'f072f4d804ea359e4eaf198b1af7a8b0943881a87f31bb764f8bf219bb9419e0',
    'anyio-4.15.1-py3-none-any.whl': '6152fdbbf9a77fdec97731721bebf7c4c44f7c29b424b0065826173efc7ed101',
    'fastapi-0.141.1-py3-none-any.whl': 'bfb91aa2d334c61cb35ba9a116fc123b3d3df31640b801cf57a7a78ec3f603b3',
    'idna-3.20-py3-none-any.whl': 'ab7ae7122974553370f0bdb919e1a960b2cd1bc1ef0276416d896db81c14582c',
    'pydantic-2.13.5-py3-none-any.whl': '346a034f080da3755d8e9cb5e00e8b07de1d39e4f6e2c87d8ab7cafa0b269a73',
    'pydantic_core-2.46.5-cp313-cp313-manylinux_2_17_aarch64.manylinux2014_aarch64.whl': '193375f3548919d3f0b60936ca113ada3e38f264f91b9b8e0508efaad57be931',
    'starlette-1.7.0-py3-none-any.whl': '67f8e99895493dd2911a03f11314af6ceebeae4e704bb9f43dfc6a9db151c93e',
    'typing_extensions-4.16.0-py3-none-any.whl': '481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8',
    'typing_inspection-0.4.4-py3-none-any.whl': '65b8397ba37ccbce054456aaccddfc91e6e3083c92824df348d96ca832f3f147',
}


def require(value):
    if not value:
        raise ValueError('fixture_failed')


def ordinary(path, *, uid, mode=None, limit=8_000_000):
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in {0, 1000}
                and not stat.S_IMODE(info.st_mode) & 0o022)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid == uid and 0 <= before.st_size <= limit)
        if mode is not None:
            require(stat.S_IMODE(before.st_mode) == mode)
        chunks = []
        left = limit + 1
        while left:
            chunk = os.read(fd, min(left, 65536))
            if not chunk:
                break
            chunks.append(chunk); left -= len(chunk)
        raw = b''.join(chunks)
        def stamp(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        require(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd))
                == stamp(path.lstat()))
        return raw
    finally:
        os.close(fd)


def verify_material(stage):
    site = stage / 'venv/lib/python3.13/site-packages'
    require('include-system-site-packages = false' in
            ordinary(stage / 'venv/pyvenv.cfg', uid=1000).decode())
    require({p.name for p in (stage / 'wheels').iterdir()} == set(WHEELS))
    checked = 0
    for filename, pin in WHEELS.items():
        path = stage / 'wheels' / filename
        require(hashlib.sha256(ordinary(path, uid=0)).hexdigest() == pin)
        with zipfile.ZipFile(path) as wheel:
            for item in wheel.infolist():
                name = Path(item.filename)
                require(not name.is_absolute() and '..' not in name.parts
                        and not any(p.endswith('.data') for p in name.parts))
                if item.is_dir() or item.filename.endswith('.dist-info/RECORD'):
                    continue  # pip rewrites RECORD; every wheel payload is compared below.
                require(ordinary(site / name, uid=1000) == wheel.read(item))
                checked += 1
    for name, pin in STUDIO_PINS.items():
        require(hashlib.sha256(ordinary(stage / 'studio-source' / name, uid=0)).hexdigest() == pin)
        require(hashlib.sha256(ordinary(site / name, uid=1000)).hexdigest() == pin)
    expected_packages = {name.split('-')[0].replace('_', '-') for name in WHEELS} | {'pip'}
    installed = {d.metadata['Name'].lower().replace('_', '-')
                 for d in importlib.metadata.distributions(path=[str(site)])}
    require(installed == expected_packages)
    return checked


VALIDATE = '''import json,os,sys
from pathlib import Path
try:
 from inky_web import auth
 path=Path(sys.argv[1]);raw=path.read_bytes()
 assert 1<len(raw)<=8192 and raw.endswith(b'\\n') and raw.count(b'\\n')==1
 record=json.loads(raw)
 assert type(record) is dict and record.get('version')==2
 credentials=auth._parse_record(path,record)
 password=credentials.bootstrap_password
 assert type(password) is str and len(password)==16 and all(c in auth.PASSWORD_ALPHABET for c in password)
 assert credentials.verify(password)
 wrong=('a' if password[0]!='a' else 'b')+password[1:]
 assert not credentials.verify(wrong)
 assert os.getresuid()==(1000,1000,1000) and os.getresgid()==(1000,1000,1000) and os.getgroups()==[]
 print(json.dumps({'status':'PASS','record_v2_valid':True,'password_verifies':True,'different_password_refused':True,'unprivileged_identity_verified':True}))
except BaseException:
 print(json.dumps({'status':'FAIL'}));sys.exit(1)
'''


def main():
    report = {'schema_version': 1, 'scope': 'real-studio-serializer-private-fixture',
              'status': 'FAIL', 'checks': {}, 'studio_commit': STUDIO_COMMIT,
              'source_sha256': STUDIO_PINS, 'publisher_sha256': PUBLISHER_SHA256,
              'wheel_sha256': WHEELS, 'application_startup_qualified': False,
              'production_paths_qualified': False, 'factory_barrier_qualified': False,
              'hardware_qualified': False, 'credential_bytes_exported': False,
              'phase': 'guard'}
    try:
        require(sys.argv[1:] == ['--run'] and sys.platform == 'linux'
                and platform.machine() == 'aarch64' and os.geteuid() == 0)
        stage = Path(__file__).resolve().parents[2]
        require(stage.parent == Path('/var/lib/inkyos-build')
                and stage.name.startswith('serializer-review.'))
        require(ordinary(stage.parent / 'owner', uid=0) == b'inkyos-builder-v1\n')
        interfaces = {line.split(':', 1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines() if ':' in line}
        initial_namespace = ordinary(stage / 'initial-network-namespace.txt', uid=0).decode().strip()
        require(initial_namespace.startswith('net:[') and initial_namespace.endswith(']')
                and interfaces == {'lo'} and os.readlink('/proc/self/ns/net') != initial_namespace)
        report['checks']['private_network_namespace'] = True
        report['phase'] = 'material'
        payload_count = verify_material(stage)
        raw = ordinary(stage / 'scripts/factory-credentials-publisher.py', uid=0)
        require(hashlib.sha256(raw).hexdigest() == PUBLISHER_SHA256)
        publisher = types.ModuleType('pinned_publisher')
        exec(compile(raw, '<pinned-publisher>', 'exec'), publisher.__dict__)
        require('inky_web' not in sys.modules)
        interpreter = str(stage / 'venv/bin/python')
        calls = []
        def spawn(argv, **options):
            require(argv == publisher.ARGV and options['user'] == options['group'] == 1000
                    and options['extra_groups'] == [] and options['cwd'] == '/'
                    and options['shell'] is False and options['env'] == publisher.ENV)
            calls.append(True)
            return subprocess.Popen((interpreter, *argv[1:]), **options)
        observations = []
        for name in ('first', 'second'):
            report['phase'] = name + '_publication'
            root = stage / 'fixtures' / name
            credentials = root / publisher.DATA / publisher.NAME
            require(publisher.publish(_root=root, _spawn=spawn) == {'status': 'published'})
            raw = ordinary(credentials, uid=1000, mode=0o600, limit=8192)
            require(credentials.stat().st_gid == 1000)
            report['phase'] = name + '_validation'
            result = subprocess.run([interpreter, '-I', '-B', '-c', VALIDATE, str(credentials)],
                                    cwd='/', env=dict(publisher.ENV), user=1000, group=1000,
                                    extra_groups=[], close_fds=True, start_new_session=True,
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=20, check=False)
            require(result.returncode == 0 and len(result.stdout) < 4096)
            require(json.loads(result.stdout) == {'status': 'PASS', 'record_v2_valid': True,
                    'password_verifies': True, 'different_password_refused': True,
                    'unprivileged_identity_verified': True})
            before = credentials.stat()
            report['phase'] = name + '_replacement_refusal'
            count = len(calls)
            try:
                publisher.publish(_root=root, _spawn=spawn)
                raise AssertionError('replacement accepted')
            except publisher.PublisherError as error:
                require(error.code == 'data_unavailable')
            require(len(calls) == count and ordinary(credentials, uid=1000, mode=0o600) == raw
                    and credentials.stat().st_ino == before.st_ino)
            observations.append(raw)
        require(len(calls) == 2)
        report['checks'].update(two_publications_validated_by_studio=True,
                                effective_real_saved_uid_gid_1000_and_empty_groups=True,
                                existing_credentials_refused_before_spawn=True,
                                exact_private_publication_preserved=True,
                                app_code_never_imported_by_root=True)
        report['independent_outputs_differ_observed'] = observations[0] != observations[1]
        require(report['independent_outputs_differ_observed'])  # Observation only, not an entropy proof.
        report['phase'] = 'material_readback'
        require('inky_web' not in sys.modules and verify_material(stage) == payload_count)
        report['checks']['pinned_sources_and_wheel_payloads_unchanged'] = True
        report['wheel_payload_files_verified'] = payload_count
        report['serializer_invocations'] = len(calls)
        report['status'] = 'PASS'
        report['phase'] = 'complete'
    except BaseException:
        report['status'] = 'FAIL'
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
