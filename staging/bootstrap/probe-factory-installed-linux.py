#!/usr/bin/env python3
"""Opt-in installed factory composition fixture; never an image recipe.

The controller supplies an already prepared, globally visible RO loop rootfs.
This probe never mounts an image, alters that rootfs, or starts app/helper units.
Only private fixtures are written. The real hook invokes the installed exporter;
its opaque credential bytes stay in the builder and never enter the report.
"""
import argparse
import configparser
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import time


ROOT = Path(__file__).resolve().parents[2]
BUILDER = Path('/var/lib/inkyos-build')
MODULES = ('factory-authority.py', 'factory-credentials-publisher.py', 'initialization-receipt.py')
OBSERVER_NAME = 'factory-installed-observer.py'
CASES = ('fresh', 'restart', 'consumed_no_authority', 'no_permission')
HOOK_RESULTS = {
    'fresh': {'status': 'created', 'authority_status': 'authorized'},
    'restart': {'status': 'existing', 'authority_status': 'authorized'},
    'consumed_no_authority': {'status': 'refused', 'error': 'recovery_required'},
    'no_permission': {'status': 'refused', 'error': 'permission_unavailable'},
}
SOURCE_PINS = {
    'config/factory-exporter.lock.json': '3738c252a1a7b9291f87fdaa3dde82705010e2c216b8a79784e6ff10fdfef853',
    'config/base-image.lock.json': 'b8dfe442703d1b2063f7006a28353427aa526858c31a2d9f73f4090dc86add18',
    'config/system-packages.lock.json': '85769aa6a159a6fba2ab0054d66ee4a31056e5cea9177380730954c83862abb2',
    'config/test-access-packages.lock.json': 'af97a2b51e5cd49f1d6520a39569c27fb8d90ea6cb812f285dcd5be5a36e6752',
    'staging/bootstrap/probe-factory-service-linux.py': '2e1cb8d8aaa5f05fd9127381c5175f4218eff89e1fd80ad0d01ee2606db17cc1',
    'staging/bootstrap/inkyos-factory-fixture.service': '69eed59cac22e76d0e152f02a0568672f47e1f898c017199e060367da36d6d3f',
    'scripts/verify-factory-exporter-rootfs.py': '3e77e24f682455efacd9cfdad35e651c5ee071af81e23dcc0f9ef25e7d47bcce',
    'scripts/manifest-rootfs.py': '54c7a05347a20c8bcd32ba84892b8a210bed72f4e962cf5c1809fa5765ba0fd0',
    'scripts/install-application-rootfs.py': 'f58b2cbac8dfda473f643f4a6c016270f6bfdbc22e08ebe7e4641a2fb6c92695',
    'scripts/inspect-application-archives.py': '42317ec6ea9385e81dfafe55e5350071fb037717af28c72e5ebeff0ec3601746',
    'scripts/verify-application.py': '57fea361a8ae2a87723805bcf678af374916d273d06f1ea7cdd93844de788d5d',
    'scripts/factory-authority.py': 'e5b04dd9ad617cf82c5476d2bc81c1ea1295bd3731c363ac4ed6f0ae5aeacb50',
    'scripts/factory-credentials-publisher.py': 'ae8d8898315631e4f5ed016fd21c1393073ae611137ece35c8f3fd4f9201bbfe',
    'scripts/initialization-receipt.py': '42d2e4ac0b38a3788d41dc4dd85a8df965a5c30fc88dbbfcbd6ed213c3e47de6',
}
EMPTY_XATTRS = {'status': 'inspected', 'entries': {}}
UNIT_RE = re.compile(r'inkyos-factory-probe-installed-[a-f0-9]{8}-(?:fresh|restart|consumed_no_authority|no_permission|validate)\.service')
HASH_RE = re.compile('[a-f0-9]{64}')
PRE_PHASES = ('arguments', 'manifest', 'identity', 'capabilities', 'isolation',
              'binds', 'mount_flags', 'critical_mounts', 'inventory_helper',
              'local_inventory', 'bundle_inventory', 'cgroup', 'receipt')


class PreRefusal(ValueError):
    def __init__(self, phase):
        self.phase = phase
        super().__init__('installed_pre_refused')


def require(value):
    if not value:
        raise ValueError('installed_fixture_check_failed')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')


def closed_json(raw, limit):
    require(isinstance(raw, bytes) and 0 < len(raw) <= limit and raw.isascii())
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result); result[key] = value
        return result
    def invalid(_):
        raise ValueError('installed_fixture_check_failed')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def validate_hook_output(raw, case):
    require(case in HOOK_RESULTS and raw.endswith(b'\n') and raw.count(b'\n') == 1)
    require(closed_json(raw, 512) == HOOK_RESULTS[case])
    return HOOK_RESULTS[case].copy()


def validate_pre_receipt(raw, unit):
    require(UNIT_RE.fullmatch(unit))
    expected = {'schema_version': 1, 'scope': 'exec-start-pre-only',
                'control_group': '/system.slice/' + unit, 'checks_passed': True}
    value = closed_json(raw, 512)
    if isinstance(value, dict) and value.get('checks_passed') is False:
        failure_phase = value.get('failure_phase')
        require(type(failure_phase) is str and failure_phase in PRE_PHASES
                and value == {**expected, 'checks_passed': False, 'failure_phase': failure_phase}
                and type(value['schema_version']) is int)
        raise PreRefusal(failure_phase)
    require(value == expected and type(value['schema_version']) is int
            and type(value['checks_passed']) is bool)
    return value['control_group']


def guard_path(path):
    """Trusted builder inputs only, including every ancestor and Linux ACLs."""
    require(path.is_absolute() and '..' not in path.parts)
    for entry in reversed((path, *path.parents)):
        info = entry.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == info.st_gid == 0
                and not stat.S_IMODE(info.st_mode) & 0o7022
                and os.listxattr(entry, follow_symlinks=False) == [])
        require(stat.S_ISDIR(info.st_mode) or entry == path and stat.S_ISREG(info.st_mode)
                and info.st_nlink == 1)


def regular(path, maximum=1024 * 1024, *, uid=0, mode=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid == before.st_gid == uid
                and not stat.S_IMODE(before.st_mode) & 0o7022
                and (mode is None or stat.S_IMODE(before.st_mode) == mode)
                and 0 <= before.st_size <= maximum)
        raw = os.read(fd, maximum + 1)
        require(len(raw) == before.st_size and signature(before) == signature(os.fstat(fd))
                == signature(path.lstat()))
        return raw
    finally:
        os.close(fd)


def signature(info):
    # Reads may legitimately update atime; identity, content and metadata may not.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def write_exact(service, path, raw, mode=0o600):
    service.write_new(path, raw, mode)
    os.chmod(path, mode, follow_symlinks=False)


def load_dependencies():
    material = {}
    for relative, digest in SOURCE_PINS.items():
        path = ROOT / relative; guard_path(path)
        raw = regular(path); require(sha(raw) == digest); material[relative] = raw
    def load(name, relative):
        spec = importlib.util.spec_from_file_location(name, ROOT / relative)
        module = importlib.util.module_from_spec(spec)
        exec(compile(material[relative], str(ROOT / relative), 'exec'), module.__dict__)
        return module
    service = load('installed_fixture_service', 'staging/bootstrap/probe-factory-service-linux.py')
    verifier = load('installed_fixture_verifier', 'scripts/verify-factory-exporter-rootfs.py')
    return service, verifier, material


def mount_rows(raw):
    rows = []
    for line in raw.splitlines():
        fields = line.split(); split = fields.index('-')
        require(len(fields) > split + 3)
        rows.append({'target': fields[4], 'options': set(fields[5].split(',')),
                     'root': fields[3], 'type': fields[split + 1], 'source': fields[split + 2]})
    return rows


def guard_rootfs(rootfs, expected_image_sha, verifier):
    require(re.fullmatch(r'/var/lib/inkyos-build/factory-installed\.[A-Za-z0-9]+/root', str(rootfs))
            and HASH_RE.fullmatch(expected_image_sha))
    guard_path(rootfs)
    require(stat.S_IMODE(rootfs.parent.stat().st_mode) == 0o700)
    # PID1 must resolve exactly the same prepared global mount. No mount is made here.
    require(os.readlink('/proc/self/ns/mnt') == os.readlink('/proc/1/ns/mnt'))
    rows = [row for row in mount_rows(Path('/proc/self/mountinfo').read_text())
            if row['target'] == str(rootfs)]
    require(len(rows) == 1)
    row = rows[0]
    require(row['type'] == 'ext4' and row['root'] == '/' and
            {'ro', 'nosuid', 'nodev'} <= row['options'] and 'noexec' not in row['options'])
    device = re.fullmatch(r'/dev/(loop[0-9]+)p2', row['source']); require(device)
    image = rootfs.parent / 'image.img'; guard_path(image)
    require(stat.S_IMODE(image.stat().st_mode) == 0o600)
    block = Path('/sys/block') / device[1]
    require((block / 'ro').read_text().strip() == '1'
            and (block / 'loop/backing_file').read_text().strip() == str(image))
    before = image.stat()
    with image.open('rb') as stream:
        require(hashlib.file_digest(stream, 'sha256').hexdigest() == expected_image_sha)
    require(signature(before) == signature(image.stat()))
    # These empty mountpoints are the only preparation requested from the controller.
    for relative, mode in (('etc/inky-studio', '0755'), ('var/lib/inkyos', '0700')):
        path = rootfs / relative
        record = verifier.single_record(path); verifier.secure_record(record)
        require(record['type'] == 'directory' and record['mode'] == mode and not list(path.iterdir()))


def expected_local_tree(support, additions):
    require(set(additions) == set(MODULES) | {OBSERVER_NAME})
    expected = copy.deepcopy(support['trees']['usr/local/lib'])
    require(expected['inkyos'] == {'type': 'directory', 'uid': 0, 'gid': 0,
                                   'mode': '0700', 'xattrs': EMPTY_XATTRS})
    for name, raw in additions.items():
        require('/' not in name and isinstance(raw, bytes) and raw)
        path = 'inkyos/' + name; require(path not in expected)
        expected[path] = {'type': 'file', 'uid': 0, 'gid': 0, 'mode': '0555',
                          'size_bytes': len(raw), 'sha256': sha(raw), 'xattrs': copy.deepcopy(EMPTY_XATTRS)}
    return expected


def hook_command():
    return ['/usr/bin/python3.13', '-I', '-B', '-S', '/usr/local/lib/inkyos/factory-authority.py']


STUDIO_RESULT = {'status': 'PASS', 'record_v2_valid': True, 'password_verifies': True,
                 'different_password_refused': True, 'unprivileged_identity_verified': True}
VALIDATE = r'''import json,os,stat
from pathlib import Path
try:
 assert os.getresuid()==(1000,1000,1000) and os.getresgid()==(1000,1000,1000) and os.getgroups()==[]
 status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
 assert all(int(status[k].strip(),16)==0 for k in ('CapEff','CapPrm','CapInh','CapAmb')) and status['NoNewPrivs'].strip()=='1'
 from inky_web import auth
 path=Path('/var/lib/inky-studio/credentials.json')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd);assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==info.st_gid==1000 and stat.S_IMODE(info.st_mode)==0o600 and 1<info.st_size<=8192
  raw=os.read(fd,8193);assert len(raw)==info.st_size
 finally:os.close(fd)
 assert raw.endswith(b'\n') and raw.count(b'\n')==1
 record=json.loads(raw);assert type(record) is dict and record.get('version')==2
 credentials=auth._parse_record(path,record);password=credentials.bootstrap_password
 assert type(password) is str and len(password)==16 and all(c in auth.PASSWORD_ALPHABET for c in password)
 assert credentials.verify(password)
 wrong=('a' if password[0]!='a' else 'b')+password[1:];assert not credentials.verify(wrong)
 print(json.dumps({'status':'PASS','record_v2_valid':True,'password_verifies':True,'different_password_refused':True,'unprivileged_identity_verified':True}))
except BaseException:os._exit(1)
'''


def validation_command():
    # This separate validation unit never wraps the real hook. Its first app
    # import is after numeric identity drop and an exec with no effective caps.
    target = ['/usr/lib/inkyos/factory-exporter/venv/bin/python', '-I', '-B', '-c', VALIDATE]
    environment = {'HOME': '/home/inky', 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
    launcher = '''import os
try:
 assert os.getresuid()==(0,0,0) and os.getresgid()==(0,0,0)
 os.setgroups([]);os.setresgid(1000,1000,1000);os.setresuid(1000,1000,1000)
 assert os.getresuid()==(1000,1000,1000) and os.getresgid()==(1000,1000,1000) and os.getgroups()==[]
 fd=os.open('/proc/self/status',os.O_RDONLY)
 try:raw=os.read(fd,65536)
 finally:os.close(fd)
 status=dict(line.split(b':',1) for line in raw.splitlines() if b':' in line)
 assert all(int(status[k].strip(),16)==0 for k in (b'CapEff',b'CapPrm',b'CapInh',b'CapAmb')) and status[b'NoNewPrivs'].strip()==b'1'
 os.execve(TARGET[0],TARGET,ENVIRONMENT)
except BaseException:os._exit(1)
'''.replace('TARGET', repr(target)).replace('ENVIRONMENT', repr(environment))
    return ['/usr/bin/python3.13', '-I', '-B', '-S', '-c', launcher]


def validate_studio_output(raw):
    require(raw.endswith(b'\n') and raw.count(b'\n') == 1)
    value = closed_json(raw, 512)
    require(value == STUDIO_RESULT and all(type(value[key]) is bool
            for key in STUDIO_RESULT if key != 'status'))
    return STUDIO_RESULT.copy()


def unit_properties(base, rootfs, state, data, marker, modules, unit, manifest_sha, hook_output):
    require(UNIT_RE.fullmatch(unit) and HASH_RE.fullmatch(manifest_sha))
    for path in (rootfs, state, data, marker, modules, hook_output):
        require(re.fullmatch(r'/[A-Za-z0-9_./-]+', str(path)) and '..' not in path.parts)
    props = dict(base)
    require(props.pop('ExecStart') == '/usr/bin/false' and props['TasksMax'] == '2'
            and 'User' not in props and props['Restart'] == 'no')
    props.update(RootDirectory=str(rootfs), WorkingDirectory='/', MountAPIVFS='yes',
                 BindLogSockets='no', TimeoutStartSec='40s', TimeoutStopSec='1s',
                 LimitFSIZE='8192', LimitCORE='0', StandardInput='null', StandardError='null',
                 StandardOutput='append:' + str(hook_output),
                 BindPaths=f'{state}:/var/lib/inkyos:norbind {data}:/var/lib/inky-studio:norbind',
                 BindReadOnlyPaths=f'{marker}:/etc/inky-studio:norbind {modules}:/usr/local/lib/inkyos:norbind',
                 Environment='HOME=/home/inky PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 '
                             'INKY_STUDIO_FACTORY_REQUIRED=1 INKY_STUDIO_DATA_DIR=/var/lib/inky-studio',
                 UnsetEnvironment='LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG LD_PROFILE LD_ORIGIN_PATH '
                                  'GLIBC_TUNABLES GCONV_PATH LOCPATH PYTHONPATH PYTHONHOME PYTHONUSERBASE '
                                  'OPENSSL_CONF OPENSSL_CONF_INCLUDE OPENSSL_MODULES OPENSSL_ENGINES',
                 ExecStartPre='/usr/bin/python3.13 -I -B -S /usr/local/lib/inkyos/' + OBSERVER_NAME +
                              ' ' + unit + ' ' + manifest_sha)
    return props


def wait_unit(service, unit, timeout=50):
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic(); require(remaining > 0)
        fields = (*service.PROPERTIES, 'ExecMainStatus', 'ExecMainCode')
        raw = service.command(['/usr/bin/systemctl', 'show', unit, '--property=' + ','.join(fields)],
                              timeout=min(5, remaining))
        observed = dict(line.split('=', 1) for line in raw.decode().splitlines())
        if observed['ActiveState'] == 'failed' or observed['SubState'] == 'exited':
            return observed
        time.sleep(min(.03, max(0, deadline - time.monotonic())))


def stop_all(service, attempted):
    ok = True
    for unit, group in attempted:
        try:
            service.stop_unit(unit, group)
        except BaseException:
            ok = False
    return ok


# Only ExecStartPre runs this observer, never the app or a wrapper around the hook.
# Every diagnostic is closed; stdout is reserved for the hook's tiny JSON result.
OBSERVER = r'''import hashlib,json,os,re,stat,sys,types
from pathlib import Path
phases=PRE_PHASES_LITERAL
phase='arguments';out=None
def require(value):
 if not value: raise ValueError('pre_guard')
def signature(info):
 return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
def read(path,limit):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd);require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==info.st_gid==0 and info.st_size<=limit)
  raw=os.read(fd,limit+1);require(len(raw)==info.st_size and signature(info)==signature(os.fstat(fd))==signature(os.lstat(path)));return raw
 finally:os.close(fd)
def emit(value):
 raw=(json.dumps(value,sort_keys=True)+'\n').encode('ascii');require(len(raw)<=512 and out is not None)
 fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:require(os.write(fd,raw)==len(raw));os.fsync(fd)
 finally:os.close(fd)
def critical_mounts(raw,root_device):
 expected={'/etc/inky-studio':0,'/usr/local/lib/inkyos':0,'/usr/lib/modules':0}
 for line in raw.splitlines():
  fields=line.split();target=fields[4]
  if target in ('/usr','/etc','/lib') or target.startswith(('/usr/','/etc/','/lib/')):
   require(target in expected);expected[target]+=1
   if target=='/usr/lib/modules':
    # systemd v257.13 ProtectKernelModules masks this exact path with an empty
    # inaccessible node, then remounts it read-only and noexec (namespace.c).
    require({'ro','noexec'}<=set(fields[5].split(',')))
    info=os.lstat(target)
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode)==0 and info.st_uid==info.st_gid==0 and info.st_dev!=root_device)
    require(os.statvfs(target).f_flag & os.ST_RDONLY and not os.listdir(target))
 require(all(count==1 for count in expected.values()))
try:
 unit,pin=sys.argv[1:]
 require(re.fullmatch(r'inkyos-factory-probe-installed-[a-f0-9]{8}-(fresh|restart|consumed_no_authority|no_permission|validate)\.service',unit))
 out='/var/lib/inkyos/observations/'+unit+'.json'
 phase='manifest';raw=read('/etc/inky-studio/bench-expected.json',1048576)
 require(hashlib.sha256(raw).hexdigest()==pin);expected=json.loads(raw)
 phase='identity'
 require(unit==expected['unit'] and os.getresuid()==(0,0,0) and os.getresgid()==(0,0,0))
 phase='capabilities'
 status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
 require(all(int(status[k].strip(),16)==0xe3 for k in ('CapEff','CapPrm','CapBnd')) and all(int(status[k].strip(),16)==0 for k in ('CapInh','CapAmb')) and status['NoNewPrivs'].strip()=='1')
 phase='isolation'
 require(os.readlink('/proc/self/ns/net')!=expected['host_net'] and os.stat('/dev').st_dev!=expected['host_dev'])
 require(not list(Path('/dev').glob('spidev*')))
 phase='binds'
 root=os.stat('/');require([root.st_dev,root.st_ino]==expected['root_identity'])
 for path,identity in expected['bind_identities'].items():
  info=os.stat(path);require([info.st_dev,info.st_ino]==identity)
 phase='mount_flags'
 for path in ('/','/usr/lib/python3.13','/usr/lib/aarch64-linux-gnu','/usr/local/lib/inkyos','/usr/lib/inkyos/factory-exporter','/etc/inky-studio'):
  require(os.statvfs(path).f_flag & os.ST_RDONLY)
 for path in ('/var/lib/inkyos','/var/lib/inky-studio'):
  require(not os.statvfs(path).f_flag & os.ST_RDONLY)
 phase='critical_mounts';critical_mounts(Path('/proc/self/mountinfo').read_text(),root.st_dev)
 phase='inventory_helper'
 helper=read('/etc/inky-studio/manifest-rootfs.py',65536)
 require(hashlib.sha256(helper).hexdigest()==expected['inventory_sha256'])
 module=types.ModuleType('pinned_bench_inventory');exec(compile(helper,'<pinned-inventory>','exec'),module.__dict__)
 phase='local_inventory';require(module.inventory(Path('/usr/local/lib'))==expected['local_tree'])
 phase='bundle_inventory';require(module.inventory(Path('/usr/lib/inkyos/factory-exporter'))==expected['bundle_tree'])
 phase='cgroup'
 lines=Path('/proc/self/cgroup').read_text().splitlines();require(len(lines)==1 and lines[0].startswith('0::'))
 group=lines[0][3:];require(group=='/system.slice/'+unit)
 cg=Path('/sys/fs/cgroup')/group.lstrip('/')
 require((cg/'pids.max').read_text().strip()=='2')
 require(dict(line.split() for line in (cg/'cgroup.events').read_text().splitlines())['populated']=='1')
 phase='receipt'
 emit({'schema_version':1,'scope':'exec-start-pre-only','control_group':group,'checks_passed':True})
except BaseException:
 try:
  emit({'schema_version':1,'scope':'exec-start-pre-only','control_group':'/system.slice/'+unit,'checks_passed':False,'failure_phase':phase})
 except BaseException:pass
 # A fixed exit code still identifies the phase if the private receipt cannot
 # be written. Never export exception text, a traceback, credentials or hashes.
 os._exit(64+phases.index(phase))
'''.replace('PRE_PHASES_LITERAL', repr(PRE_PHASES)).encode('ascii')


def new_directory(path, uid=0):
    path.mkdir(mode=0o700); os.chmod(path, 0o700); os.chown(path, uid, uid)


def prepare_case(work, case, service, fresh=None):
    require(case in CASES and case != 'restart')
    path = work / case; new_directory(path)
    state = path / 'state'; data = path / 'data'
    new_directory(state); new_directory(data, 1000)
    new_directory(state / 'observations')
    if case != 'no_permission':
        permission = state / 'factory-permission'; new_directory(permission)
        write_exact(service, permission / 'lock', b'')
        filename = 'pending.json' if case == 'fresh' else 'consumed.json'
        write_exact(service, permission / filename,
                          encode({'version': 1, 'operation': 'create-initialization-authority'}))
    if case == 'consumed_no_authority':
        require(fresh is not None)
        raw = regular(fresh / 'data/credentials.json', 8192, uid=1000, mode=0o600)
        write_exact(service, data / 'credentials.json', raw)
        os.chown(data / 'credentials.json', 1000, 1000)
    return path


def private_snapshot(state, data):
    """Comparison stays in memory; credential bytes/digests never enter reports."""
    result = {}
    for root in (state / 'factory-permission', state / 'initialization', data):
        if not root.exists():
            result[str(root)] = None; continue
        for path in (root, *sorted(root.rglob('*'))):
            info = path.lstat()
            require(not stat.S_ISLNK(info.st_mode))
            record = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                      info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            if stat.S_ISREG(info.st_mode):
                record += (regular(path, 8192, uid=info.st_uid, mode=0o600),)
            else:
                require(stat.S_ISDIR(info.st_mode))
            result[str(path)] = record
    return result


def inspect_authority(material, state):
    relative = 'scripts/initialization-receipt.py'
    spec = importlib.util.spec_from_file_location('installed_receipt_inspection', ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    exec(compile(material[relative], str(ROOT / relative), 'exec'), module.__dict__)
    require(module.inspect(state / 'initialization') == {'status': 'authorized'})


def execute_unit(service, base, args, work, modules, state, data, name, phase,
                 local_tree, bundle_tree, material, attempted):
    require(phase in (*CASES, 'validate'))
    unit = name + '-' + phase + '.service'; group = service.group_path('/system.slice/' + unit)
    marker = work / ('marker-' + phase); new_directory(marker)
    write_exact(service, marker / 'factory-v1.json', encode({'version': 1, 'app_uid': 1000,
                                                          'data_dir': '/var/lib/inky-studio'}), 0o644)
    write_exact(service, marker / 'manifest-rootfs.py', material['scripts/manifest-rootfs.py'], 0o444)
    bindings = {'/var/lib/inkyos': state, '/var/lib/inky-studio': data,
                '/etc/inky-studio': marker, '/usr/local/lib/inkyos': modules}
    expected = {'unit': unit, 'local_tree': local_tree, 'bundle_tree': bundle_tree,
                'root_identity': [args.rootfs.stat().st_dev, args.rootfs.stat().st_ino],
                'bind_identities': {key: [value.stat().st_dev, value.stat().st_ino]
                                    for key, value in bindings.items()},
                'inventory_sha256': SOURCE_PINS['scripts/manifest-rootfs.py'],
                'host_net': os.readlink('/proc/self/ns/net'), 'host_dev': os.stat('/dev').st_dev}
    manifest = encode(expected); write_exact(service, marker / 'bench-expected.json', manifest, 0o444)
    output = work / ('hook-' + phase + '.stdout'); write_exact(service, output, b'')
    properties = unit_properties(base, args.rootfs, state, data, marker, modules, unit, sha(manifest), output)
    require(service.command(['/usr/bin/systemctl', 'show', unit, '--property=LoadState', '--value']).strip() == b'not-found')
    attempted.append((unit, group))
    command = validation_command() if phase == 'validate' else hook_command()
    service.command(['/usr/bin/systemd-run', '--quiet', '--no-block', '--unit=' + unit] +
                    ['--property=' + key + '=' + value for key, value in properties.items()] + command)
    observed = wait_unit(service, unit)
    started = regular(state / 'observations' / (unit + '.json'), 512, mode=0o600)
    require(service.group_path(validate_pre_receipt(started, unit)) == group
            and observed['ControlGroup'] in {'', '/system.slice/' + unit})
    expected_status = '0' if phase in {'fresh', 'restart', 'validate'} else '1'
    require(observed['ExecMainCode'] == '1' and observed['ExecMainStatus'] == expected_status
            and observed['Result'] == ('success' if expected_status == '0' else 'exit-code')
            and observed['TasksMax'] == observed['EffectiveTasksMax'] == '2')
    for field, expected_value in {'Type': 'oneshot', 'KillMode': 'control-group', 'Delegate': 'no',
            'NoNewPrivileges': 'yes', 'PrivateDevices': 'yes', 'PrivateNetwork': 'yes',
            'ProtectSystem': 'strict', 'ProtectHome': 'read-only', 'ProtectControlGroups': 'yes'}.items():
        require(observed[field] == expected_value)
    raw = regular(output, 512, mode=0o600)
    result = validate_studio_output(raw) if phase == 'validate' else validate_hook_output(raw, phase)
    service.stop_unit(unit, group)
    return result


def run(args):
    report = {'schema_version': 1, 'scope': 'installed-factory-composition-staging',
              'status': 'FAIL', 'phase': 'guard', 'cases': [], 'completed_case_count': 0,
              'studio_validation': None, 'all_units_stopped': False,
              'pre_failure_phase': None,
              'target_execution_attempted': False,
              'pre_observation_is_start_observation': False, 'credential_bytes_exported': False,
              'writer_barrier_qualified': False, 'application_candidate_complete': False,
              'image_recipe_activated': False, 'hardware_qualified': False}
    attempted = []; service = None
    try:
        require(args.installed_composition and sys.platform == 'linux' and platform.machine() == 'aarch64'
                and os.geteuid() == 0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode)
        require(re.fullmatch('[a-f0-9]{8}', args.fixture_token))
        service, verifier, material = load_dependencies()
        parent = service.trusted_builder(); os.close(parent)
        guard_rootfs(args.rootfs, args.prepared_image_sha256, verifier)
        for path in (args.sources_dir, args.wheels_dir, args.support_manifest):
            guard_path(path)
            require(path.is_relative_to(BUILDER) and not path.is_relative_to(args.rootfs))
        lock = verifier.load_lock()
        require(lock == closed_json(material['config/factory-exporter.lock.json'], 1024 * 1024))
        support, _ = verifier.load_support(lock, args.support_manifest)
        baseline = verifier.verify(args.rootfs, lock, args.sources_dir, args.wheels_dir, args.support_manifest)
        payload = verifier.expected_payload(lock, args.sources_dir, args.wheels_dir)
        bundle_tree = verifier.expected_bundle(payload, support['python_version'], lock['support_manifest_sha256'])
        additions = {name: material['scripts/' + name] for name in MODULES}
        additions[OBSERVER_NAME] = OBSERVER
        local_tree = expected_local_tree(support, additions)
        config = configparser.ConfigParser(interpolation=None); config.optionxform = str
        config.read_string(material['staging/bootstrap/inkyos-factory-fixture.service'].decode())
        base = dict(config['Service'])
        require(base['CapabilityBoundingSet'].split() == list(service.CAPS))
        name = 'inkyos-factory-probe-installed-' + args.fixture_token
        work = BUILDER / name; new_directory(work)
        modules = work / 'modules'; new_directory(modules)
        # The base subtree has only ordinary pinned entries; reject anything else.
        original = support['trees']['usr/local/lib']
        for relative, record in original.items():
            if not relative.startswith('inkyos/'):
                continue
            leaf = relative[len('inkyos/'):]
            require('/' not in leaf and record['type'] == 'file')
            raw = verifier.ordinary(args.rootfs / 'usr/local/lib' / relative)
            require(sha(raw) == record['sha256'])
            write_exact(service, modules / leaf, raw, int(record['mode'], 8))
        for filename, raw in additions.items():
            write_exact(service, modules / filename, raw, 0o555)
        expected_modules = {'.': local_tree['inkyos'], **{
            key[len('inkyos/'):]: value for key, value in local_tree.items() if key.startswith('inkyos/')}}
        require(verifier.inventory_module.inventory(modules) == expected_modules)
        report.update(source_sha256=SOURCE_PINS, observer_sha256=sha(OBSERVER),
                      fixture_token=args.fixture_token, validator_sha256=sha(VALIDATE.encode('ascii')),
                      prepared_image_sha256=args.prepared_image_sha256,
                      bundle_manifest_sha256=baseline['bundle_manifest_sha256'],
                      support_manifest_sha256=baseline['support_manifest_sha256'])
        fresh = None
        for case in CASES:
            report['phase'] = case
            path = fresh if case == 'restart' else prepare_case(work, case, service, fresh)
            if case == 'fresh': fresh = path
            state, data = path / 'state', path / 'data'
            before = private_snapshot(state, data)
            result = execute_unit(service, base, args, work, modules, state, data, name, case,
                                  local_tree, bundle_tree, material, attempted)
            after = private_snapshot(state, data)
            if case == 'fresh':
                require(set(data.iterdir()) == {data / 'credentials.json'})
                regular(data / 'credentials.json', 8192, uid=1000, mode=0o600)
                require(set((state / 'factory-permission').iterdir()) == {
                    state / 'factory-permission/lock', state / 'factory-permission/consumed.json'})
                inspect_authority(material, state)
                report['phase'] = 'validate'
                validation_before = private_snapshot(state, data)
                report['studio_validation'] = execute_unit(
                    service, base, args, work, modules, state, data, name, 'validate',
                    local_tree, bundle_tree, material, attempted)
                require(validation_before == private_snapshot(state, data))
            else:
                require(before == after)
            report['cases'].append({'case': case, 'hook_result': result, 'pre_checks_passed': True,
                                    'private_state_expected': True, 'cgroup_empty_after_stop': True})
            report['completed_case_count'] = len(report['cases'])
        report['phase'] = 'readback'
        verifier.verify(args.rootfs, lock, args.sources_dir, args.wheels_dir, args.support_manifest)
        require(verifier.inventory_module.inventory(modules) == expected_modules)
        require([case['case'] for case in report['cases']] == list(CASES)
                and report['completed_case_count'] == 4 and report['studio_validation'] == STUDIO_RESULT)
        report['status'] = 'PASS'; report['phase'] = 'complete'
    except PreRefusal as error:
        report['status'] = 'FAIL'; report['pre_failure_phase'] = error.phase
    except BaseException:
        report['status'] = 'FAIL'
    finally:
        report['target_execution_attempted'] = bool(attempted)
        report['all_units_stopped'] = bool(attempted) and service is not None and stop_all(service, attempted)
        if not report['all_units_stopped']:
            report['status'] = 'FAIL'
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installed-composition', action='store_true', required=True)
    for name in ('rootfs', 'sources-dir', 'wheels-dir', 'support-manifest'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--prepared-image-sha256', required=True)
    parser.add_argument('--fixture-token', required=True)
    args = parser.parse_args(argv)
    report = run(args)
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
