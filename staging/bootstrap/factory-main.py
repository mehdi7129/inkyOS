"""Fixed admitted factory/normal composition of the pinned Studio continuation.

This module starts no unit and imports no application code before graph binding.
Its closed offline installation is separate from image/runtime qualification.
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
# Public literal refusals from OS 5087d19 graph/runtime and Studio 87c082 runtime.
DIAGNOSTIC_REASONS = frozenset({
    'admission_changed', 'boot_changed', 'candidate_changed', 'command_closure_missing',
    'context_changed', 'context_exists', 'context_inventory_limit', 'contract_unavailable',
    'graph_invalid', 'graph_refused', 'graph_reused', 'identity_changed',
    'inactive_launch_contract', 'invalid_candidate', 'invalid_context', 'invalid_contract',
    'invalid_metadata', 'invalid_module', 'invalid_override', 'invalid_run', 'manager_reply_shape',
    'missing_invocation', 'missing_mainpid', 'module_changed', 'module_metadata',
    'monitor_not_drained', 'monitor_state', 'not_installed', 'not_mainpid',
    'observation_not_drained', 'observation_not_quiescent', 'observation_not_reaped',
    'observation_timeout', 'peer_closed', 'peer_credentials_shape', 'peer_mapping_changed',
    'peer_not_drained', 'peer_not_mainpid', 'peer_pidfd_shape', 'peer_wrong_identity',
    'pid_view_changed', 'pid_view_unconfirmed', 'pidfd_unavailable', 'pin_mismatch',
    'property_shape', 'query_failed', 'reply_shape', 'reply_too_large',
    'resource_close_unconfirmed', 'run_mount_changed', 'runtime_pin_mismatch', 'runtime_pin_shape',
    'setup_privileges', 'source_baseline', 'source_changed', 'source_check_result',
    'source_depth_limit', 'source_inventory_incomplete', 'source_inventory_limit',
    'source_metadata', 'source_parent_not_directory', 'source_path', 'source_plan',
    'source_prepare_result', 'source_root_missing', 'source_xattrs', 'state_binding_changed',
    'stop_propagation', 'studio_candidate_mismatch', 'support_pin_missing', 'unit_configuration',
    'unit_dependencies', 'unit_execstart', 'unit_job_shape', 'unit_not_running', 'unit_policy',
    'unsupported_query', 'unsupported_role', 'unsupported_unit', 'writer_admission_refused',
    'writer_changed', 'writer_dead', 'writer_mapping_changed', 'wrong_identity',
})
DIAGNOSTIC_CODES = frozenset({
    'factory_runtime_refused', 'factory_runtime_uncertain', 'factory_runtime_pending',
})


class Refused(ValueError):
    pass


def public_diagnostic(error):
    # Pinned exceptions store these public fields as instance data. Never invoke
    # reason/code properties or format exception text, args or unknown fields.
    try:
        attributes = BaseException.__getattribute__(error, '__dict__')
    except Exception:
        return 'factory_main_refused'
    if type(attributes) is dict:
        for field, allowed in (('reason', DIAGNOSTIC_REASONS), ('code', DIAGNOSTIC_CODES)):
            value = attributes.get(field)
            if type(value) is str and value in allowed:
                return 'factory_main_refused:' + value
    return 'factory_main_refused'


def public_graph_diagnostic(proof):
    # Read only native instance data, including when a fixture shadows __dict__.
    # Never invoke a reason/__dict__ property or format a graph object's text.
    try:
        kind = type(proof)
        descriptor = type.__getattribute__(kind, '__dict__').get('__dict__')
        if type(descriptor) is not types.GetSetDescriptorType:
            return None
        attributes = descriptor.__get__(proof, kind)
        if type(attributes) is dict:
            reason = attributes.get('reason')
            if type(reason) is str and reason in DIAGNOSTIC_REASONS:
                return 'factory_main_graph_refused:' + reason
    except Exception:
        pass
    return None


def public_timeout_diagnostic(proof):
    # Fixed tuple schema shared with writer-graph: origin, phase, step,
    # request/acquire/failure monotonic ms, wait/hold/total ms, budget ms.
    # Do not invoke properties, formatting hooks or arbitrary numeric objects.
    try:
        descriptor = type.__getattribute__(type(proof), '__dict__').get('__dict__')
        if type(descriptor) is not types.GetSetDescriptorType:
            return None
        attributes = descriptor.__get__(proof, type(proof))
        if type(attributes) is not dict or type(attributes.get('reason')) is not str:
            return None
        if attributes['reason'] != 'observation_timeout':
            return None
        value = attributes.get('_timeout_observation')
        if type(value) is not tuple or len(value) != 10:
            return None
        if not all(type(item) is int and 0 <= item <= 2**53 - 1 for item in value):
            return None
        origin, phase, step, requested, acquired, failed, wait, hold, total, budget = value
        if origin not in {1, 2, 3} or phase not in {1, 2, 3, 4, 5}:
            return None
        if step not in ({0} if phase in {1, 2, 3} else {1, 2, 3} if phase == 4 else set(range(1, 11))):
            return None
        if not (requested <= failed and 0 < budget <= 180000
                and max(wait, hold, total) <= 2**31 - 1 and total >= budget - 1
                and abs(total - (failed - requested)) <= 1 and abs(total - wait - hold) <= 1):
            return None
        if phase == 1:
            if acquired != 0 or hold != 0 or wait != total: return None
        elif not (requested <= acquired <= failed and abs(wait - acquired + requested) <= 1
                  and abs(hold - failed + acquired) <= 1):
            return None
        return 'factory_main_observation_timeout:' + json.dumps(value, separators=(',', ':'))
    except BaseException:
        return None


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
    from inky_web.provisioning.factory_continuation import FactoryContinuationRuntime
    from inky_web.provisioning.system_setup_ipc import SystemSetupClient
    from inky_web.provisioning.network import NetworkClient
    from inky_web.inky.display import DisplayController
    return serve_factory_phase_a, DisplayController, FactoryContinuationRuntime, SystemSetupClient, NetworkClient


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
        print('factory_main_phase:graph_binding', file=sys.stderr, flush=True)
        if proof is None: proof = installed_proof()
        proof.__enter__()
        if stop_requested.is_set(): raise Refused('shutdown_requested')
        print('factory_main_phase:graph_bound', file=sys.stderr, flush=True)
        proof.start_monitor(loop, stop_requested)
        print('factory_main_phase:components_loading', file=sys.stderr, flush=True)
        serve, display, bootstrap, setup_client, network_client = components()
        print('factory_main_phase:components_loaded', file=sys.stderr, flush=True)
        require(callable(serve) and callable(display) and callable(bootstrap))
        require(proof.check() is None)
        # Studio owns its additional fresh SH and every submitted operation/drain.
        print('factory_main_phase:phase_a_enter', file=sys.stderr, flush=True)
        await serve(DATA, stop_requested=stop_requested,
                    display_factory=lambda: display(mode='hardware'),
                    runtime_factory=lambda result, controller, verify_epoch:
                        bootstrap(result, verify_epoch, controller, DATA / "provisioning",
                                  system_setup=setup_client(peer_guard=proof.setup_guard),
                                  network=network_client(peer_guard=proof.network_guard)),
                    admission_check=proof.check,
                    initialization_peer_guard=proof.initialization_guard)
        raise Refused('phase_a_returned')
    except BaseException:
        # Studio may replace a graph refusal with its own fixed runtime code.
        # Observe the public graph reason before close changes graph state.
        try:
            diagnostic = public_graph_diagnostic(proof)
            if diagnostic is not None:
                print(diagnostic, file=sys.stderr, flush=True)
        except Exception:
            pass  # Diagnostic output must not replace the original exception.
        try:
            diagnostic = public_timeout_diagnostic(proof)
            if diagnostic is not None:
                print(diagnostic, file=sys.stderr, flush=True)
        except BaseException:
            pass  # Optional measurements never change refusal or owned cleanup.
        raise
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
    except Exception as error:
        print(public_diagnostic(error), file=sys.stderr)
        return REFUSAL_EXIT
    return REFUSAL_EXIT


if __name__ == '__main__':
    raise SystemExit(main())
