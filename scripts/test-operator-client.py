#!/usr/bin/env python3
"""Restricted Mac client for a separately verified private TEST SD return.

Only context.json and known_hosts select the device. Python never reads the
private identity: ssh-keygen derives its public key, then ssh authenticates.
Metadata/content rechecks do not exclude a concurrent privileged local writer.
A client timeout does not establish cancellation of a remote systemd worker.
"""
import sys
sys.dont_write_bytecode = True

import argparse
import base64
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import selectors
import subprocess
import time


SOURCE = Path(__file__).resolve().with_name('prepare-test-access-capsule.py')
SPEC = importlib.util.spec_from_file_location('_inkyos_client_private_io', SOURCE)
private = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(private)
ACTIVATION_SPEC = importlib.util.spec_from_file_location('_inkyos_client_activation_projection',
    Path(__file__).resolve().with_name('test-access-activation.py'))
activation = importlib.util.module_from_spec(ACTIVATION_SPEC)
ACTIVATION_SPEC.loader.exec_module(activation)
OPERATIONS = {'preflight', 'status', 'activate', 'stop'}
TIMEOUT, OUTPUT_LIMIT = 50.0, 32768
ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C', 'SSH_ASKPASS_REQUIRE': 'never'}
HEX_BINDINGS = {'profile_sha256', 'challenge', 'host_public_key_sha256', 'application_source_commit',
                'application_manifest_sha256', 'access_runtime_manifest_sha256'}
RUNNER_FIELDS = {'schema_version', 'kind', 'operation', 'passed', 'status', 'error', 'live_evidence',
                 'preflight', 'stop', 'activation', 'lifecycle_status', 'activation_authorized',
                 'hardware_qualified', 'release_qualified', 'limits'}
BOOL_FIELDS = {'passed', 'live_evidence', 'request_accepted', 'helper_started', 'helper_verified',
    'application_started', 'application_active_observed', 'physical_refresh_verified', 'activation_authorized',
    'hardware_qualified', 'release_qualified', 'request_present', 'request_created', 'job_acknowledged',
    'permit_invalidated', 'application_stop_acknowledged', 'application_inactive', 'application_masked',
    'helper_stop_acknowledged', 'helper_inactive', 'helper_masked', 'bindings_unchanged', 'poweroff_requested',
    'stop_acknowledged', 'mask_acknowledged', 'inactive_and_persistently_masked'}
FALSE_FIELDS = {'physical_refresh_verified', 'activation_authorized', 'hardware_qualified', 'release_qualified'}
ENUMS = {
    'kind': {'test-operator-result', 'test-access-activation-result', 'test-access-drain-enqueue',
        'test-access-drain-observation', 'test-access-drain-status', 'test-access-lifecycle-status', 'test-lan-preflight'},
    'operation': OPERATIONS,
    'status': {'PASS', 'BLOCKED', 'QUEUED', 'EXISTING', 'ABSENT', 'REQUESTED', 'OBSERVED'},
    'phase': {'idle', 'queued', 'gating', 'preparing', 'helper-start-requested', 'helper-ready', 'app-start-requested',
        'active', 'failed', 'blocked', 'accepted', 'waiting-activation', 'stopping-application', 'waiting-application',
        'stopping-helper', 'waiting-helper', 'ready-for-poweroff', 'poweroff-requested'},
    'observation_source': {'live-system', 'fixture'},
}
REMOTE_ERRORS = {
    'invalid_request', 'target_unverified', 'caller_unverified', 'binding_invalid', 'operation_busy',
    'preflight_unavailable', 'preflight_blocked', 'activation_unavailable', 'stop_incomplete', 'state_changed',
    'stop_requires_inactive_runtime', 'lifecycle_unavailable', 'lifecycle_failed', 'observations_unavailable',
    'activation_invalid_request', 'activation_binding_invalid', 'activation_already_admitted',
    'activation_drain_requested', 'activation_queue_failed', 'activation_busy', 'activation_gate_failed',
    'activation_units_invalid', 'activation_helper_failed', 'activation_app_failed', 'activation_utc_stale',
    'activation_permit_invalid', 'activation_state_changed', 'activation_interrupted', 'activation_failed',
    'invalid_arguments', 'request_invalid', 'existing_drain', 'unsafe_unit', 'permit_invalid',
    'stop_submission_unconfirmed', 'unit_observation_unavailable', 'unit_state_unexpected', 'mask_unconfirmed',
    'status_write_failed', 'poweroff_unconfirmed', 'worker_submission_unconfirmed', 'status_invalid', 'drain_failed',
}
PREFLIGHT_CHECKS = {'prepared_profile', 'exact_payload_pin', 'operator_access_confirmed', 'firstboot_success',
    'app_stopped_and_masked', 'helper_stopped_and_masked', 'networkmanager_manages_connected_wlan0',
    'country_operator_confirmed', 'country_global_matches', 'country_phy_matches', 'utc_synchronized',
    'independent_reference_recent', 'utc_matches_independent_reference', 'bluez_running', 'hci0_powered',
    'bluetooth_unblocked', 'system_packages_present', 'application_hardware_metadata_present',
    'service_accounts_and_groups', 'spi_i2c_gpio_nodes', 'application_state_virgin', 'helper_state_virgin',
    'panel_inventory_supplied_and_valid', 'panel_runtime_evidence_verified'}
LOCAL_ERRORS = {'invalid_arguments', 'private_input_refused', 'context_invalid', 'known_hosts_invalid',
    'identity_unverified', 'local_state_changed', 'utc_unavailable', 'client_timeout_unconfirmed',
    'output_excessive_unconfirmed', 'transport_unconfirmed', 'remote_response_invalid', 'interrupted_unconfirmed'}


class ClientError(ValueError):
    pass


def require(value, error):
    if value is not True:
        raise ClientError(error)


def safe_path(value):
    path = Path(value).absolute()
    text = str(path)
    # OpenSSH expands percent/env tokens in filenames. One quoted known-hosts
    # pathname permits ordinary spaces but no expansion or config delimiters.
    require(len(text.encode()) <= 4096 and '..' not in path.parts
            and all(ord(char) >= 32 and ord(char) != 127 and char not in '\\"\'%$' for char in text),
            'private_input_refused')
    return path


def public_key(value):
    try:
        private.contract._public_key(value)
        return base64.b64decode(value.split(' ')[1], validate=True)
    except Exception:
        raise ClientError('context_invalid') from None


def load_context(directory):
    directory = safe_path(directory)
    fd = private.private_parent(directory)
    os.close(fd)
    raw = private.read_private(directory / 'context.json')
    known = private.read_private(directory / 'known_hosts', limit=512)
    value = private.strict_json(raw)
    require(type(value) is dict and set(value) == {'schema_version', 'kind', 'bindings', 'operator_public_key'}
            and type(value['schema_version']) is int and value['schema_version'] == 1
            and value['kind'] == 'verified-test-access-context'
            and type(value['bindings']) is dict and set(value['bindings']) == HEX_BINDINGS
            and raw == private.contract.canonical(value), 'context_invalid')
    for name, item in value['bindings'].items():
        size = 40 if name == 'application_source_commit' else 64
        require(type(item) is str and re.fullmatch('[0-9a-f]{' + str(size) + '}', item) is not None
                and item != '0' * size, 'context_invalid')
    public_key(value['operator_public_key'])
    matched = re.fullmatch(rb'\[(inky-[0-9a-f]{32}\.local)\]:2222 (ssh-ed25519 [A-Za-z0-9+/]{68})\n', known)
    require(matched is not None, 'known_hosts_invalid')
    host_key = public_key(matched[2].decode('ascii'))
    require(hashlib.sha256(host_key).hexdigest() == value['bindings']['host_public_key_sha256'], 'known_hosts_invalid')
    return value, matched[1].decode('ascii'), raw, known


def bounded(argv, payload, *, timeout, limit):
    """Bound pipes and elapsed time. Kill only this local command client."""
    child = None
    selector = selectors.DefaultSelector()
    try:
        require(timeout > 0, 'client_timeout_unconfirmed')
        child = subprocess.Popen(argv, stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd='/', env=ENV,
            close_fds=True, start_new_session=True)
        os.set_blocking(child.stdout.fileno(), False)
        selector.register(child.stdout, selectors.EVENT_READ)
        if payload is not None:
            os.set_blocking(child.stdin.fileno(), False)
            selector.register(child.stdin, selectors.EVENT_WRITE)
        deadline, offset, output = time.monotonic() + timeout, 0, bytearray()
        while selector.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'client_timeout_unconfirmed')
            for key, events in selector.select(remaining):
                if events & selectors.EVENT_WRITE:
                    count = os.write(key.fd, payload[offset:])
                    require(count > 0, 'transport_unconfirmed')
                    offset += count
                    if offset == len(payload):
                        selector.unregister(key.fileobj)
                        child.stdin.close()  # Closed JSON input followed by EOF.
                else:
                    block = os.read(key.fd, min(4096, limit + 1 - len(output)))
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(block)
                        require(len(output) <= limit, 'output_excessive_unconfirmed')
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'client_timeout_unconfirmed')
        try:
            code = child.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise ClientError('client_timeout_unconfirmed') from None
        return code, bytes(output)
    finally:
        selector.close()
        if child is not None:
            if child.poll() is None:
                try:
                    child.kill()
                except OSError:
                    pass
                try:
                    child.wait(timeout=0.2)
                except subprocess.TimeoutExpired:
                    pass
            for stream in (child.stdin, child.stdout):
                if stream is not None:
                    stream.close()


def ssh_arguments(directory, identity, host, operation):
    options = (
        'BatchMode=yes', 'IdentitiesOnly=yes', 'IdentityAgent=none', 'CertificateFile=none',
        'StrictHostKeyChecking=yes', 'UserKnownHostsFile="' + str(directory / 'known_hosts') + '"',
        'GlobalKnownHostsFile=/dev/null', 'ClearAllForwardings=yes', 'RequestTTY=no',
        'ControlMaster=no', 'ControlPath=none', 'ControlPersist=no', 'ForwardAgent=no', 'ForwardX11=no',
        'PermitLocalCommand=no', 'ProxyCommand=none', 'ProxyJump=none', 'UpdateHostKeys=no',
        'VerifyHostKeyDNS=no', 'CheckHostIP=no', 'HostKeyAlgorithms=ssh-ed25519',
        'PubkeyAcceptedAlgorithms=ssh-ed25519', 'PreferredAuthentications=publickey',
        'PasswordAuthentication=no', 'KbdInteractiveAuthentication=no', 'NumberOfPasswordPrompts=0',
        'ConnectTimeout=10', 'ConnectionAttempts=1', 'LogLevel=ERROR',
    )
    argv = ['/usr/bin/ssh', '-F', '/dev/null', '-p', '2222', '-l', 'inky-test', '-i', str(identity)]
    for option in options:
        argv.extend(('-o', option))
    return tuple(argv + ['--', host, operation])


def projection(value, *, depth=0):
    """Never forward remote prose, paths, unknown keys or arbitrary strings."""
    require(type(value) is dict and depth <= 5, 'remote_response_invalid')
    output = {}
    for key, item in value.items():
        if key in BOOL_FIELDS:
            require(type(item) is bool and (key not in FALSE_FIELDS or item is False), 'remote_response_invalid')
            output[key] = item
        elif key in ENUMS:
            require(type(item) is str and item in ENUMS[key], 'remote_response_invalid')
            output[key] = item
        elif key == 'error':
            require(item is None or type(item) is str and item in REMOTE_ERRORS, 'remote_response_invalid')
            output[key] = item
        elif key == 'schema_version':
            require(type(item) is int and item == 1, 'remote_response_invalid')
            output[key] = item
        elif key in {'activation', 'drain', 'preflight', 'stop', 'lifecycle_status'}:
            output[key] = None if item is None else projection(item, depth=depth + 1)
        elif key == 'assessment':
            try:
                output[key] = None if item is None else activation.assessment_projection(item)
            except (activation.ActivationError, TypeError, KeyError):
                raise ClientError('remote_response_invalid') from None
        elif key == 'checks':
            require(type(item) is dict and set(item) == PREFLIGHT_CHECKS, 'remote_response_invalid')
            checks = {}
            for name, row in item.items():
                require(type(row) is dict and type(row.get('passed')) is bool, 'remote_response_invalid')
                checks[name] = row['passed']
            output[key] = checks
        elif key == 'units':
            require(type(item) is dict and set(item) == {'inky-studio.service', 'inky-network.service'}, 'remote_response_invalid')
            output[key] = {name: projection(row, depth=depth + 1) for name, row in item.items()}
        # All other fields, including producer limits/prose, are discarded.
    return output


def response(raw, operation, code):
    require(type(raw) is bytes and 0 < len(raw) <= OUTPUT_LIMIT and type(code) is int and code in {0, 1, 64},
            'remote_response_invalid')
    try:
        value = private.strict_json(raw)
    except Exception:
        raise ClientError('remote_response_invalid') from None
    require(type(value) is dict and set(value) == RUNNER_FIELDS and value.get('kind') == 'test-operator-result'
            and value.get('operation') == operation and type(value.get('passed')) is bool
            and value['status'] == ('PASS' if value['passed'] else 'BLOCKED')
            and value['passed'] == (code == 0), 'remote_response_invalid')
    if value['passed']:
        field, kind = {'preflight': ('preflight', 'test-lan-preflight'),
            'activate': ('activation', 'test-access-activation-result'),
            'status': ('lifecycle_status', 'test-access-lifecycle-status'),
            'stop': ('stop', 'test-access-drain-enqueue')}[operation]
        item = value[field]
        require(type(item) is dict and (item.get('kind') == kind or operation == 'stop'
                and set(item) == {'permit_invalidated', 'units', 'bindings_unchanged', 'poweroff_requested'}),
                'remote_response_invalid')
    return projection(value)


def operate(directory, identity, operation, *, confirm_test_refresh=False, invoke=bounded,
            wall_clock=time.time, monotonic=time.monotonic):
    result = {'schema_version': 1, 'kind': 'test-operator-client-result', 'operation': None,
        'passed': False, 'status': 'BLOCKED', 'error': None, 'ssh_attempted': False,
        'response_verified': False, 'remote': None, 'remote_worker_cancelled': False,
        'context_provenance_verified': False, 'hardware_qualified': False, 'release_qualified': False}
    stage = 'inputs'
    deadline = monotonic() + TIMEOUT
    try:
        require(type(operation) is str and operation in OPERATIONS and type(confirm_test_refresh) is bool
                and confirm_test_refresh == (operation == 'activate'), 'invalid_arguments')
        result['operation'] = operation
        require(os.geteuid() != 0, 'private_input_refused')
        directory, identity = safe_path(directory), safe_path(identity)
        context, host, context_raw, known_raw = load_context(directory)
        key_stamp = private.inspect_key(identity)  # Metadata only; never read_private(identity).
        def unchanged():
            require(private.inspect_key(identity) == key_stamp
                    and private.read_private(directory / 'context.json') == context_raw
                    and private.read_private(directory / 'known_hosts', limit=512) == known_raw, 'local_state_changed')
        stage = 'identity'
        code, raw = invoke(('/usr/bin/ssh-keygen', '-y', '-f', str(identity)), None,
                           timeout=min(10.0, deadline - monotonic()), limit=1024)
        require(type(code) is int and code == 0 and type(raw) is bytes and len(raw) <= 1024, 'identity_unverified')
        match = re.fullmatch(rb'(ssh-ed25519 [A-Za-z0-9+/]{68})(?: [^\r\n]*)?\n', raw)
        require(match is not None and match[1].decode('ascii') == context['operator_public_key'], 'identity_unverified')
        unchanged()
        request = {'schema_version': 1}
        if operation in {'preflight', 'activate'}:
            now = wall_clock()
            require(type(now) in {int, float} and math.isfinite(now) and 1767225600 <= now <= 2524608000, 'utc_unavailable')
            request.update(utc_reference=int(now), utc_reference_age=0, utc_reference_source='independent-device')
        if operation == 'activate':
            request['confirm_test_refresh'] = True
        payload = private.contract.canonical(request)
        stage = 'ssh'
        remaining = deadline - monotonic()
        require(remaining > 0, 'client_timeout_unconfirmed')
        result['ssh_attempted'] = True
        code, raw = invoke(ssh_arguments(directory, identity, host, operation), payload,
                           timeout=remaining, limit=OUTPUT_LIMIT)
        unchanged()
        require(type(code) is int and code in {0, 1, 64}, 'transport_unconfirmed')
        result['remote'] = response(raw, operation, code)
        result.update(response_verified=True, passed=result['remote']['passed'],
                      status=result['remote']['status'], error=result['remote']['error'])
        return (0 if result['passed'] else 1), result
    except (Exception, KeyboardInterrupt) as error:
        if isinstance(error, KeyboardInterrupt):
            reason = 'interrupted_unconfirmed'
        elif type(error) is ClientError and str(error) in LOCAL_ERRORS:
            reason = str(error)
        else:
            reason = {'inputs': 'private_input_refused', 'identity': 'identity_unverified',
                      'ssh': 'transport_unconfirmed'}[stage]
        result.update(error=reason, status='UNCONFIRMED' if result['ssh_attempted'] else 'BLOCKED')
        return (124 if reason == 'client_timeout_unconfirmed' and result['ssh_attempted'] else 1), result


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ClientError('invalid_arguments')


def main(argv=None):
    parser = Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--context-directory', required=True, type=Path)
    parser.add_argument('--identity', required=True, type=Path)
    parser.add_argument('--confirm-test-refresh', action='store_true')
    parser.add_argument('operation', choices=sorted(OPERATIONS))
    try:
        args = parser.parse_args(argv)
    except ClientError:
        print('{"error":"invalid_arguments","passed":false}')
        return 64
    code, result = operate(args.context_directory, args.identity, args.operation,
                           confirm_test_refresh=args.confirm_test_refresh)
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return code


if __name__ == '__main__':
    sys.exit(main())
