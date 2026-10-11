#!/usr/bin/env python3
"""Cross-repository fixture: actual Studio IPC client against the staged OS unit.

Explicit builder-VM use only. Place the eight pinned Studio files under
./studio-client/ beside this script, then run with --run as root in the marked
builder. No Studio startup, account modification, radio or production install.
The existing native probe supplies the service, synthetic authority, assertions
and cleanup. Only its fixture request generator is replaced by the actual
Studio client. The returned Python result is normalized for that harness; it
is not a captured wire frame. The client verifies the real peer and wire/EOF.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import select
import signal
import stat
import sys
import time

STUDIO_COMMIT = 'da966c6bb6bbb74fae70e20044ff16282d99ef43'
NATIVE_PROBE_SHA = 'defcb99434c8f000a473de2f2c326f6055dc95345a879a385824398c62fbe379'
STUDIO_PINS = {
    'inky_web/__init__.py': 'eb46584f68f555f175241641fc930408af7747bc7d45c997216dad6df2be88cc',
    'inky_web/provisioning/__init__.py': 'fa80434eb14bdd643937dedfc52f345a517f856335428bd9b047bcb24be0645f',
    'inky_web/provisioning/initialization_ipc.py': 'ed39708d17d150511ae2bf4db4008c65e3d954760ccfcb2bf70e703cbcd4389a',
    'inky_web/provisioning/first_boot.py': 'b71f8d634db039340d402305c3894bd8e441264b672ca869d8313b4a18e4cd41',
    'inky_web/provisioning/identity.py': '22fdbd6cda126fc46e6ea26bba77e0ac26d3d3cc6730db97fb5b463e0a2a1e71',
    'inky_web/provisioning/factory.py': '26665699c4ce594b0654c0979e67adafc296febb8b56d9608c54c379b1efe02b',
    'inky_web/provisioning/bootstrap_identity.py': '85b8105eb851b9bc0138d5ddcefface6bb57d0f4369c999982ad100d5fb1c9c4',
    'inky_web/provisioning/ownership.py': '8cda6bf806f066470fe8137b23ab43d6357650917cfeaed815d765938e68a867',
}


def require(value):
    if not value:
        raise ValueError('cross fixture check failed')


def pinned(path, digest):
    def stable(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and before.st_nlink == 1 and not before.st_mode & 0o022
                and 0 < before.st_size <= 65536)
        raw = os.read(fd, 65537)
        require(len(raw) == before.st_size and hashlib.sha256(raw).hexdigest() == digest)
        require(stable(before) == stable(os.fstat(fd)) == stable(path.lstat()))
        return raw
    finally:
        os.close(fd)


def client_request(native, ipc, path, uid, *, begin=False, timeout=4):
    """Drop real process credentials before using the unmodified client."""
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            for name in os.listdir('/proc/self/fd'):
                fd = int(name)
                if fd not in {0, 1, 2, write_fd}:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            os.setgroups([native.GID]); os.setgid(native.GID); os.setuid(uid)
            require(os.getuid() == os.geteuid() == uid and os.getgid() == native.GID)
            client = ipc.InitializationIPCClient(str(path))
            try:
                result = (client.begin_initialization(native.INTENT) if begin
                          else client.inspect_initialization())
                value = {'v': 1, 'id': native.ID, 'ok': True, 'result': result}
            except ipc.InitializationIPCError as error:
                if error.code == 'forbidden':
                    require(error.uncertain is False)
                if error.code == 'initialization_uncertain':
                    require(begin and error.begin_submitted and error.uncertain)
                value = {'v': 1, 'id': native.ID, 'ok': False, 'error': error.code}
            os.write(write_fd, json.dumps(value).encode())
            os.close(write_fd)
            os._exit(0)
        except BaseException:
            os._exit(2)
    os.close(write_fd)
    raw = b''; deadline = time.monotonic() + timeout + .5
    try:
        while True:
            remaining = deadline - time.monotonic(); require(remaining > 0)
            ready, _, _ = select.select([read_fd], [], [], remaining); require(bool(ready))
            block = os.read(read_fd, 4097 - len(raw))
            if not block:
                break
            raw += block; require(len(raw) <= 4096)
        while True:
            child, status = os.waitpid(pid, os.WNOHANG)
            if child:
                pid = None; require(status == 0); break
            require(time.monotonic() < deadline); time.sleep(.01)
        return json.loads(raw)
    finally:
        os.close(read_fd)
        if pid is not None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            # This fixture admits no second call while an old client is alive.
            deadline = time.monotonic() + 1
            while os.waitpid(pid, os.WNOHANG)[0] == 0:
                require(time.monotonic() < deadline); time.sleep(.01)


def main():
    report = {'schema_version': 1, 'scope': 'initialization-studio-native-cross-fixture',
              'status': 'FAIL', 'hardware_qualified': False, 'image_qualified': False,
              'application_startup_qualified': False, 'studio_commit': STUDIO_COMMIT}
    try:
        require(sys.argv[1:] == ['--run'] and sys.platform == 'linux' and os.geteuid() == 0)
        base = Path(__file__).absolute().parent
        probe = base / 'probe-initialization-linux.py'
        pinned(probe, NATIVE_PROBE_SHA)
        source = base / 'studio-client'
        require({str(p.relative_to(source)) for p in source.rglob('*') if not p.is_dir()} == set(STUDIO_PINS))
        for relative, digest in STUDIO_PINS.items():
            pinned(source / relative, digest)
        require(not any(name == 'inky_web' or name.startswith('inky_web.') for name in sys.modules))
        sys.path.insert(0, str(source))
        from inky_web.provisioning import initialization_ipc as ipc
        import cryptography
        require(Path(ipc.__file__) == source / 'inky_web/provisioning/initialization_ipc.py')
        spec = importlib.util.spec_from_file_location('native_probe', probe)
        native = importlib.util.module_from_spec(spec); spec.loader.exec_module(native)
        native.request = lambda path, uid, **kw: client_request(native, ipc, path, uid, **kw)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = native.main()
        observation = json.loads(output.getvalue())
        report.update(native=observation, source_sha256=STUDIO_PINS,
                      native_probe_sha256=NATIVE_PROBE_SHA,
                      cryptography_version=cryptography.__version__,
                      actual_client_unmodified=True, actual_peer_credentials=True,
                      normalized_result_not_wire_capture=True,
                      client_uids=[0, 1001, 1000], client_group=native.GID,
                      response_loss_injected=False)
        require(code == 0 and observation['status'] == 'PASS' and observation['unit_stopped'] is True
                and len(observation['checks']) == 8 and all(observation['checks'].values()))
        report['status'] = 'PASS'
    except Exception:
        report['status'] = 'FAIL'
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
