"""Inactive fixed app-interpreter composition of the separately pinned Phase A.

No CLI options, ASGI app import, helper injection or normal-mode fallback. Its
future launcher/support installation is a separate, unqualified image change.
"""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import types

SELF = '/usr/lib/inkyos/factory-main.py'
GRAPH = '/usr/lib/inkyos/writer-graph.py'
RUNTIME = '/usr/lib/inkyos/factory-runtime-contract.py'
MANIFEST = '/etc/inkyos/factory-runtime-v1.json'
DATA = Path('/var/lib/inky-studio')
APP_PYTHON = '/usr/lib/inky-studio/server/.venv/bin/python'
REFUSAL_EXIT = 78


class Refused(ValueError):
    pass


def require(value):
    if not value: raise Refused('factory_main_refused')


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def read_fixed(path, mode, limit):
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in Path(path).parts[1:-1]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent); parent = fd
            info = os.fstat(parent)
            require((info.st_uid, info.st_gid) == (0, 0) and not stat.S_IMODE(info.st_mode) & 0o7022
                    and not os.listxattr(parent))
        name = Path(path).name
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == mode
                and (info.st_uid, info.st_gid) == (0, 0) and info.st_nlink == 1
                and 0 <= info.st_size <= limit)
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
        try:
            stable = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                                    value.st_gid, value.st_nlink, value.st_size,
                                    value.st_mtime_ns, value.st_ctime_ns)
            require(stable(os.fstat(fd)) == stable(info) and not os.listxattr(fd))
            raw = os.read(fd, limit + 1)
            require(len(raw) == info.st_size and stable(os.fstat(fd)) == stable(info)
                    and stable(os.stat(name, dir_fd=parent, follow_symlinks=False)) == stable(info))
            return raw
        finally: os.close(fd)
    finally: os.close(parent)


def installed_proof():
    require(Path(__file__) == Path(SELF) and sys.argv == [SELF]
            and sys.executable == APP_PYTHON and sys.flags.isolated
            and sys.dont_write_bytecode)
    value = json.loads(read_fixed(MANIFEST, 0o644, 16384), object_pairs_hook=unique)
    require(type(value) is dict and type(value.get('os_module_pins')) is dict
            and set(value['os_module_pins']) == {'writer-admission.py', 'factory-runtime-contract.py',
                                               'writer-launcher.py'})
    raw = read_fixed(RUNTIME, 0o555, 1024 * 1024)
    digest = value['os_module_pins']['factory-runtime-contract.py']
    require(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest)
            and hashlib.sha256(raw).hexdigest() == digest)
    runtime = types.ModuleType('inkyos_factory_runtime_contract')
    runtime.__file__ = RUNTIME
    exec(compile(raw, RUNTIME, 'exec'), runtime.__dict__)
    contract = runtime.load_contract()
    _, _, support, records = runtime.inventories(contract)
    with contract.tree() as tree:
        for path in (SELF[1:], GRAPH[1:]):
            require(path in support['paths'] and path in records
                    and records[path]['type'] == 'file' and records[path]['mode'] == '0555')
            runtime.check_path(tree, path, records)
        raw_graph = tree.read(GRAPH[1:], 0o555, 1024 * 1024)
        require(hashlib.sha256(raw_graph).hexdigest() == records[GRAPH[1:]]['sha256'])
    graph = types.ModuleType('inkyos_writer_graph')
    graph.__file__ = GRAPH
    exec(compile(raw_graph, GRAPH, 'exec'), graph.__dict__)
    return graph.open_main()


def load_components():
    # Only reached after graph binding; no inky_web.main/global ASGI construction.
    from inky_web.provisioning.factory_phase_a import serve_factory_phase_a
    from inky_web.provisioning.bootstrap_runtime import BootstrapRuntime
    from inky_web.inky.display import DisplayController
    return serve_factory_phase_a, DisplayController, BootstrapRuntime


def install_signals(loop, shutdown):
    installed = []
    try:
        for number in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(number, shutdown)
            installed.append(number)
    except BaseException:
        for number in installed: loop.remove_signal_handler(number)
        raise
    return lambda: [loop.remove_signal_handler(number) for number in installed]


async def run_phase_a(*, _root=None, _proof=None, _components=None, _signals=None):
    if _root is None:
        require(_proof is None and _components is None and _signals is None)
        proof, components, signals = None, load_components, install_signals
    else:
        root = Path(_root)
        require(root.is_absolute() and root != Path('/') and root == root.resolve(strict=True)
                and _proof is not None and callable(_components) and callable(_signals))
        proof, components, signals = _proof, _components, _signals
    stop_requested = asyncio.Event()
    loop = asyncio.get_running_loop()
    remove = None
    cancelled = False

    def shutdown():
        if proof is not None:
            proof.invalidate('shutdown_requested')
        stop_requested.set()

    try:
        # Suppress default fatal signals before any SH acquisition or query.
        # During synchronous binding asyncio can defer the callback, but its
        # registered handler already prevents exit without owned cleanup.
        remove = signals(loop, shutdown)
        require(callable(remove))
        if stop_requested.is_set(): raise Refused('shutdown_requested')
        if proof is None: proof = installed_proof()
        proof.__enter__()
        if stop_requested.is_set(): raise Refused('shutdown_requested')
        proof.start_monitor(loop, stop_requested)
        serve, display, bootstrap = components()
        require(callable(serve) and callable(display) and callable(bootstrap))
        require(proof.check() is None)
        # Studio owns its additional fresh SH and every submitted operation/drain.
        await serve(DATA, stop_requested=stop_requested,
                    display_factory=lambda: display(mode='hardware'),
                    runtime_factory=lambda result, controller, verify_epoch:
                        bootstrap(result, verify_epoch, controller, DATA),
                    admission_check=proof.check,
                    initialization_peer_guard=proof.initialization_guard)
        raise Refused('phase_a_returned')
    finally:
        # This also handles an uncertain __enter__ failure: that object may own SH.
        # An unknown cleanup never becomes process exit/quiescence. Only cleanup
        # of already owned observations is retried; no rebind or app restart.
        while proof is not None:
            try:
                proof.close()
                break
            except asyncio.CancelledError:
                cancelled = True
            except BaseException:
                try: await asyncio.sleep(0.05)
                except asyncio.CancelledError: cancelled = True
        if remove is not None: remove()
        if cancelled: raise asyncio.CancelledError


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    try:
        require(arguments == [])
        asyncio.run(run_phase_a())
    except Exception:
        print('factory_main_refused', file=sys.stderr)
        return REFUSAL_EXIT
    return REFUSAL_EXIT


if __name__ == '__main__':
    raise SystemExit(main())
