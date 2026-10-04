#!/usr/bin/python3 -I
"""One explicit TEST refresh admission per boot, run by an independent worker.

Only local fixture adapters may simulate the algorithm. The native path binds
the installed access manifest, checks the live gate, and consumes short-lived
permits in systemd ExecCondition. Failure never kills or cleans application
state: a refresh may already own SPI and must be drained separately.
"""
import sys
sys.dont_write_bytecode = True

import contextlib
import fcntl
import hashlib
import json
import math
import os
import re
import signal
import socket
import stat
import struct
import time

BASE = '/usr/local/lib/inkyos/'
SELF = BASE + 'test-access-activation.py'
BOOT = BASE + 'test-access-boot.py'
GATE = BASE + 'test-access-activation-gate.py'
LEGACY = BASE + 'test-enrollment-firstboot.py'
LEGACY_SHA256 = '081bac2c04d4e72a6e74a365664b72941fa4d1e84d1ccc32cf0dc25d9e8a337a'
MANIFEST = '/usr/local/share/inkyos/test-access-manifest.json'
PROFILE = '/etc/inkyos-test-enrollment/profile.json'
DIRECTORY = '/run/inkyos-test-operator'
REQUEST, STATUS, PERMIT, DRAIN = 'activation-request.json', 'activation-status.json', 'activation-permit.json', 'drain-request.json'
WORKER = 'inkyos-test-activate.service'
UNITS = {'helper': 'inky-network.service', 'app': 'inky-studio.service'}
TEMPLATES = {role: '/usr/local/share/inkyos/test-access/' + unit.removesuffix('.service') + '.conf'
             for role, unit in UNITS.items()}
DROPINS = {role: '/run/systemd/system/' + unit + '.d/10-inkyos-test-access.conf' for role, unit in UNITS.items()}
UTC_FIELDS = {'schema_version', 'utc_reference', 'utc_reference_age', 'utc_reference_source'}
REQUEST_FIELDS = UTC_FIELDS | {'confirm_test_refresh'}
BINDING_FIELDS = {'boot_id', 'profile_sha256', 'access_runtime_manifest_sha256'}
PHASES = {'idle', 'queued', 'gating', 'preparing', 'helper-start-requested', 'helper-ready',
          'app-start-requested', 'active', 'failed', 'blocked'}
ERRORS = {'activation_invalid_request', 'activation_binding_invalid', 'activation_already_admitted',
          'activation_drain_requested', 'activation_queue_failed', 'activation_busy', 'activation_gate_failed',
          'activation_units_invalid', 'activation_helper_failed', 'activation_app_failed', 'activation_utc_stale',
          'activation_permit_invalid', 'activation_state_changed', 'activation_interrupted', 'activation_failed'}
BOOL_FIELDS = {'passed', 'request_accepted', 'helper_started', 'helper_verified', 'application_started',
               'application_active_observed', 'physical_refresh_verified', 'hardware_qualified', 'release_qualified'}
REPORT_FIELDS = {'schema_version', 'kind', 'phase', 'error', 'assessment'} | BOOL_FIELDS
GATE_CHECKS = {
    'target_verified', 'sources_and_enrollment_bound', 'cache_authenticated', 'operator_country_confirmed',
    'bindings_unchanged_before', 'connection_verified_before', 'application_templates_verified',
    'historical_provenance_valid', 'historical_required_checks_passed', 'inactive_runtime_before_panel',
    'panel_exact_test_tuple', 'radio_mapping_consistent', 'radio_test_policy_verified',
    'bindings_unchanged_after', 'connection_verified_after', 'inactive_runtime_after',
    'application_templates_unchanged', 'independent_reference_still_recent',
}
HISTORICAL_CHECKS = {
    'prepared_profile', 'exact_payload_pin', 'operator_access_confirmed', 'firstboot_success',
    'app_stopped_and_masked', 'helper_stopped_and_masked', 'networkmanager_manages_connected_wlan0',
    'country_operator_confirmed', 'country_global_matches', 'country_phy_matches', 'utc_synchronized',
    'independent_reference_recent', 'utc_matches_independent_reference', 'bluez_running', 'hci0_powered',
    'bluetooth_unblocked', 'system_packages_present', 'application_hardware_metadata_present',
    'service_accounts_and_groups', 'spi_i2c_gpio_nodes', 'application_state_virgin', 'helper_state_virgin',
    'panel_inventory_supplied_and_valid', 'panel_runtime_evidence_verified',
}
RADIO_CHECKS = {'firmware_country_fr', 'firmware_ccode_fr', 'kernel_global_fr', 'phy_label_reviewed', 'channels_test_fr'}
ASSESSMENT_ERRORS = {'invalid_request', 'target_unverified', 'sources_invalid', 'cache_invalid',
    'country_unconfirmed', 'state_changed', 'connection_unconfirmed', 'templates_unconfirmed',
    'historical_invalid', 'historical_blocked', 'inactive_runtime_required', 'panel_unconfirmed',
    'radio_unconfirmed', 'reference_expired', 'runtime_timeout', 'assessment_unavailable', 'invalid_arguments'}
ASSESSMENT_CHECKS = {'gate_checks': GATE_CHECKS, 'historical_checks': HISTORICAL_CHECKS, 'radio_checks': RADIO_CHECKS}
PERMIT_TTL_NS = 30_000_000_000


class ActivationError(ValueError):
    pass


def require(value, error='activation_binding_invalid'):
    if value is not True:
        raise ActivationError(error)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def valid_request(value):
    return (type(value) is dict and set(value) == REQUEST_FIELDS
            and type(value['schema_version']) is int and value['schema_version'] == 1
            and value['confirm_test_refresh'] is True
            and type(value['utc_reference']) is int and 1767225600 <= value['utc_reference'] <= 2524608000
            and type(value['utc_reference_age']) is int and 0 <= value['utc_reference_age'] <= 60
            and type(value['utc_reference_source']) is str and value['utc_reference_source'] in {'independent-device', 'gnss'})


def result(phase='blocked', error=None, **values):
    return {'schema_version': 1, 'kind': 'test-access-activation-result', 'phase': phase, 'error': error, 'assessment': None,
            **dict.fromkeys(BOOL_FIELDS, False), **values}


def assessment_projection(value, *, from_gate=False):
    require(type(value) is dict and value.get('error') in ASSESSMENT_ERRORS | {None})
    if not from_gate:
        require(set(value) == set(ASSESSMENT_CHECKS) | {'error'})
    result = {'error': value['error']}
    for field, names in ASSESSMENT_CHECKS.items():
        rows = value.get(field)
        require(type(rows) is dict)
        if from_gate and field == 'historical_checks':
            require(set(rows) in (set(), names))
            require(all(type(row) is dict and type(row.get('passed')) is bool for row in rows.values()))
            rows = {name: rows[name]['passed'] if name in rows else False for name in names}
        require(set(rows) == names and all(type(flag) is bool for flag in rows.values()))
        result[field] = dict(rows)
    return result


def status_projection(value):
    require(type(value) is dict and set(value) == REPORT_FIELDS
            and type(value['schema_version']) is int and value['schema_version'] == 1
            and value['kind'] == 'test-access-activation-result' and value['phase'] in PHASES
            and value['error'] in ERRORS | {None} and all(type(value[k]) is bool for k in BOOL_FIELDS)
            and all(value[k] is False for k in ('physical_refresh_verified', 'hardware_qualified', 'release_qualified')))
    require(not value['application_active_observed'] or value['application_started'] and value['helper_verified'])
    projected = dict(value)
    if value['assessment'] is not None:
        projected['assessment'] = assessment_projection(value['assessment'])
    return projected


def bootstrap():
    directory, source = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW), None
    try:
        for part in LEGACY.strip('/').split('/')[:-1]:
            info = os.fstat(directory)
            require(info.st_uid == 0 and not info.st_mode & 0o022)
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory); directory = child
        info = os.fstat(directory)
        require(info.st_uid == 0 and not info.st_mode & 0o022)
        name = LEGACY.rsplit('/', 1)[1]
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        before = os.fstat(source)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == 0o555 and 0 < before.st_size <= 65536)
        raw = os.read(source, 65537)
        stamp = lambda v: (v.st_dev, v.st_ino, v.st_mode, v.st_uid, v.st_nlink, v.st_size, v.st_mtime_ns, v.st_ctime_ns)
        require(len(raw) == before.st_size and digest(raw) == LEGACY_SHA256
                and stamp(before) == stamp(os.fstat(source)) == stamp(os.stat(name, dir_fd=directory, follow_symlinks=False)))
    finally:
        if source is not None: os.close(source)
        os.close(directory)
    namespace = {'__name__': 'activation_legacy', '__file__': LEGACY}
    exec(compile(raw, LEGACY, 'exec'), namespace)
    return namespace


class Store:
    """Private runtime I/O; caller owns operation.lock for every mutation."""
    def __init__(self, lib, files, directory, binding):
        self.lib, self.files, self.directory, self.binding = lib, files, directory, binding

    def read(self, name):
        raw = self.files.read(DIRECTORY + '/' + name, mode=0o600, private=True, limit=8192)
        value = self.lib['strict_json'](raw)
        require(raw == canonical(value), 'activation_state_changed')
        return value

    def exists(self, name):
        try: os.stat(name, dir_fd=self.directory, follow_symlinks=False)
        except FileNotFoundError: return False
        return True

    def put(self, name, value, *, replace=False):
        previous = None
        if replace:
            self.read(name)
            previous = os.stat(name, dir_fd=self.directory, follow_symlinks=False)
            self.lib['_metadata'](previous, mode=0o600)
        raw = canonical(value)
        self.lib['write_atomic'](self.directory, name, raw,
                                replace_stamp=None if previous is None else self.lib['_stamp'](previous))
        require(self.files.read(DIRECTORY + '/' + name, mode=0o600, private=True, limit=8192) == raw,
                'activation_state_changed')

    def clear_permit(self):
        try:
            info = os.stat(PERMIT, dir_fd=self.directory, follow_symlinks=False)
        except FileNotFoundError:
            return True
        self.lib['_metadata'](info, mode=0o600)
        os.unlink(PERMIT, dir_fd=self.directory)
        os.fsync(self.directory)
        return True

    def no_drain(self):
        require(not self.exists(DRAIN), 'activation_drain_requested')
        return True

    def request(self):
        value = self.read(REQUEST)
        require(type(value) is dict and set(value) == BINDING_FIELDS | {'schema_version', 'kind', 'submitted_monotonic_ns', 'request'}
                and type(value['schema_version']) is int and value['schema_version'] == 1
                and value['kind'] == 'test-access-activation-request' and valid_request(value['request'])
                and all(value[k] == self.binding[k] for k in BINDING_FIELDS)
                and type(value['submitted_monotonic_ns']) is int and 0 < value['submitted_monotonic_ns'] <= time.monotonic_ns())
        return value

    def report(self, request):
        value = self.read(STATUS)
        require(type(value) is dict and set(value) == {'schema_version', 'kind', 'request_sha256', 'report'}
                and type(value['schema_version']) is int and value['schema_version'] == 1
                and value['kind'] == 'test-access-activation-status' and value['request_sha256'] == digest(canonical(request)))
        return status_projection(value['report'])

    def publish(self, request, report):
        self.put(STATUS, {'schema_version': 1, 'kind': 'test-access-activation-status',
                 'request_sha256': digest(canonical(request)), 'report': status_projection(report)}, replace=self.exists(STATUS))


def binding(files, profile_raw, manifest_raw):
    boot_id = files.read('/proc/sys/kernel/random/boot_id', limit=64).decode('ascii').strip()
    require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot_id) is not None)
    return {'boot_id': boot_id, 'profile_sha256': digest(profile_raw), 'access_runtime_manifest_sha256': digest(manifest_raw)}


def borrowed(operator):
    require(operator.unchanged() is True and operator.profile.get('schema_version') == 2)
    profile_raw, manifest_raw = operator.snapshot[PROFILE][0], operator.snapshot[MANIFEST][0]
    require(operator.profile['access_runtime_manifest_sha256'] == digest(manifest_raw))
    return Store(operator.runtime, operator.files, operator.directory, binding(operator.files, profile_raw, manifest_raw))


def enqueue(request, operator_adapter):
    report = result()
    store = record = None
    try:
        require(valid_request(request), 'activation_invalid_request')
        store = borrowed(operator_adapter)
        store.no_drain()
        require(not any(store.exists(name) for name in (REQUEST, STATUS, PERMIT)), 'activation_already_admitted')
        record = {'schema_version': 1, 'kind': 'test-access-activation-request', **store.binding,
                  'submitted_monotonic_ns': time.monotonic_ns(), 'request': dict(request)}
        store.put(REQUEST, record)
        report.update(phase='queued', request_accepted=True)
        store.publish(record, report)
        require(operator_adapter.unchanged() is True, 'activation_state_changed')
        store.no_drain()
        require(store.lib['command'](('/usr/bin/systemctl', '--no-block', 'start', WORKER), timeout=3, limit=4096) == (0, b''),
                'activation_queue_failed')
        report['passed'] = True
        store.publish(record, report)
        return 0, report
    except Exception as error:
        report.update(phase='failed', passed=False, error=str(error) if type(error) is ActivationError and str(error) in ERRORS else 'activation_failed')
        if store is not None and record is not None and report['request_accepted']:
            try: store.publish(record, report)
            except Exception: pass
        return 1, report


def status(operator_adapter):
    try:
        store = borrowed(operator_adapter)
        if not store.exists(REQUEST):
            require(not store.exists(STATUS) and not store.exists(PERMIT))
            return 0, result('idle', passed=True)
        return 0, store.report(store.request())
    except Exception:
        return 1, result(error='activation_binding_invalid')


class NativeAdapter:
    def __init__(self):
        self.boot = self.store = None
        self.activation_fd = self.directory = None

    def bind(self):
        lib = bootstrap()
        files = lib['Files']()
        try:
            raw = files.read(MANIFEST, mode=0o644, limit=65536)
            manifest = lib['strict_json'](raw)
            sources = {}
            for path in (SELF, BOOT, GATE):
                data = files.read(path, mode=0o555, limit=65536)
                require(manifest['files'].get(path[1:]) == {'sha256': digest(data), 'mode': '0555'})
                sources[path] = data
        finally:
            files.close()
        namespace = {'__name__': 'activation_boot', '__file__': BOOT}
        exec(compile(sources[BOOT], BOOT, 'exec'), namespace)
        self.boot = namespace['NativeAdapter']()
        require(self.boot.bind() == 'enrolled' and self.boot.manifest_raw == raw)
        require(all(self.boot.sources.get(path) == data for path, data in sources.items()))
        self.lib, self.files = self.boot.lib, self.boot.files
        self.directory = self.files.directory(DIRECTORY, private=True)
        self.store = Store(self.lib, self.files, self.directory, binding(self.files, self.boot.profile_raw, raw))
        self.gate = {'__name__': 'activation_gate', '__file__': GATE}
        exec(compile(sources[GATE], GATE, 'exec'), self.gate)
        self.app_snapshot = {}
        for path, (pin, mode) in {**self.gate['APP_FILES'],
                self.gate['APP_MANIFEST']: (self.gate['APP_MANIFEST_SHA256'], 0o444)}.items():
            data = self.files.read(path, mode=mode, limit=65536)
            require(digest(data) == pin)
            self.app_snapshot[path] = (data, mode)
        self.deadline = time.monotonic() + 100
        return True

    def acquire(self):
        self.activation_fd = os.open('activation.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                                     0o600, dir_fd=self.directory)
        self.lib['_metadata'](os.fstat(self.activation_fd), mode=0o600)
        try: fcntl.flock(self.activation_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise ActivationError('activation_busy') from None
        return True

    @contextlib.contextmanager
    def operation(self):
        fd = os.open('operation.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.directory)
        try:
            self.lib['_metadata'](os.fstat(fd), mode=0o600)
            until = time.monotonic() + 3
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    require(time.monotonic() < until, 'activation_busy')
                    time.sleep(0.025)
            yield
        finally:
            os.close(fd)

    def unchanged(self):
        return (self.boot.unchanged() is True
                and binding(self.files, self.boot.profile_raw, self.boot.manifest_raw) == self.store.binding
                and all(self.files.read(path, mode=mode, limit=65536) == raw
                        for path, (raw, mode) in self.app_snapshot.items()))

    def request(self): return self.store.request()
    def report(self, request): return self.store.report(request)
    def publish(self, request, report): self.store.publish(request, report)
    def no_drain(self): return self.store.no_drain()
    def invalidate(self): return self.store.clear_permit()

    def elapsed(self, request):
        elapsed = (time.monotonic_ns() - request['submitted_monotonic_ns']) / 1e9
        require(0 <= elapsed <= 100, 'activation_utc_stale')
        return elapsed

    def assess(self, request):
        query = {k: request['request'][k] for k in UTC_FIELDS}
        query['utc_reference_age'] += math.ceil(self.elapsed(request))
        observed = self.gate['assess'](self.gate['NativeAdapter'](), query)
        self.assessment = assessment_projection(observed, from_gate=True)
        return (type(observed) is dict and observed.get('passed') is True
                and observed.get('ready_for_test_activation') is True and observed.get('live_evidence') is True
                and observed.get('error') is None and observed.get('test_profile') == 'ac073-800x480')

    def command(self, argv, timeout=3):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, 'activation_failed')
        return self.lib['command'](tuple(argv), timeout=min(remaining, timeout), limit=16384)

    def prepare_units(self):
        self.no_boot_links()
        for role, unit in UNITS.items():
            self.no_drain()
            self.no_runtime_unit(unit)
            raw = self.boot.sources.get(TEMPLATES[role])
            require(type(raw) is bytes, 'activation_units_invalid')
            parent = self.files.directory('/run/systemd/system')
            try:
                name = unit + '.d'
                try: os.mkdir(name, 0o755, dir_fd=parent)
                except FileExistsError: pass
                os.fsync(parent)
            finally: os.close(parent)
            directory = self.files.directory('/run/systemd/system/' + name)
            try:
                require(not os.listdir(directory), 'activation_units_invalid')
                self.lib['write_atomic'](directory, '10-inkyos-test-access.conf', raw, mode=0o644)
            finally: os.close(directory)
            require(self.files.read(DROPINS[role], mode=0o644, limit=4096) == raw, 'activation_units_invalid')
            parent = self.files.directory('/etc/systemd/system')
            try:
                info = os.stat(unit, dir_fd=parent, follow_symlinks=False)
                require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and os.readlink(unit, dir_fd=parent) == '/dev/null',
                        'activation_units_invalid')
            finally: os.close(parent)
            self.no_drain()
            self.no_runtime_unit(unit)
            self.no_boot_links()
            require(self.command(('/usr/bin/systemctl', 'unmask', unit)) == (0, b''), 'activation_units_invalid')
        self.no_drain()
        require(self.command(('/usr/bin/systemctl', 'daemon-reload'), timeout=5) == (0, b''), 'activation_units_invalid')
        return all(self.effective(role) for role in UNITS)

    def no_runtime_unit(self, unit):
        directory = self.files.directory('/run/systemd/system')
        try:
            try: os.stat(unit, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError: return True
            raise ActivationError('activation_units_invalid')
        finally: os.close(directory)

    def no_boot_links(self):
        # Enabling links can be hidden while masked and become effective at
        # reboot. Inspect fixed unit search directories without following links.
        for path in ('/etc/systemd/system', '/run/systemd/system', '/usr/lib/systemd/system'):
            directory = self.files.directory(path)
            try:
                for name in os.listdir(directory):
                    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode):
                        target = os.readlink(name, dir_fd=directory).rsplit('/', 1)[-1]
                        require(target not in UNITS.values(), 'activation_units_invalid')
                    if not name.endswith(('.wants', '.requires', '.upholds')):
                        continue
                    child = self.files.directory(path + '/' + name)
                    try:
                        for link in os.listdir(child):
                            require(link not in UNITS.values(), 'activation_units_invalid')
                            row = os.stat(link, dir_fd=child, follow_symlinks=False)
                            if stat.S_ISLNK(row.st_mode):
                                target = os.readlink(link, dir_fd=child).rsplit('/', 1)[-1]
                                require(target not in UNITS.values(), 'activation_units_invalid')
                    finally: os.close(child)
            finally: os.close(directory)
        return True

    def properties(self, unit, names):
        response = self.command(('/usr/bin/systemctl', '--no-pager', 'show', unit, '--property=' + ','.join(names)))
        require(response is not None and response[0] == 0, 'activation_units_invalid')
        rows = [row.split('=', 1) for row in response[1].decode('ascii').splitlines()]
        require(all(len(row) == 2 for row in rows) and len(rows) == len(names) and {r[0] for r in rows} == set(names),
                'activation_units_invalid')
        return dict(rows)

    def effective(self, role):
        self.no_runtime_unit(UNITS[role])
        self.no_boot_links()
        value = self.properties(UNITS[role], ('LoadState', 'UnitFileState', 'Restart', 'KillSignal', 'KillMode',
                                'TimeoutStopUSec', 'SendSIGKILL', 'ExecCondition', 'DropInPaths', 'Environment', 'FragmentPath'))
        condition = value['ExecCondition']
        command = '/usr/bin/python3 -I ' + SELF + ' --consume-' + role + '-permit'
        valid = (value['LoadState'] == 'loaded' and value['UnitFileState'] in {'static', 'disabled'}
                 and value['FragmentPath'] == '/usr/lib/systemd/system/' + UNITS[role]
                 and value['Restart'] == 'no' and value['KillSignal'] == '15' and value['KillMode'] == 'mixed'
                 and value['TimeoutStopUSec'] == 'infinity' and value['SendSIGKILL'] == 'no'
                 and condition.count('path=') == 1 and 'path=/usr/bin/python3 ;' in condition
                 and ('argv[]=' + command + ' ;') in condition and 'ignore_errors=no' in condition
                 and set(value['DropInPaths'].split()) == {DROPINS[role],
                    '/etc/systemd/system/' + UNITS[role] + '.d/10-inkyos-firstboot.conf'}
                    | ({'/etc/systemd/system/inky-studio.service.d/bluetooth.conf'} if role == 'app' else set())
                 and self.files.read(DROPINS[role], mode=0o644, limit=4096) == self.boot.sources[TEMPLATES[role]])
        if role == 'app':
            import shlex
            environment = shlex.split(value['Environment'])
            valid = valid and all(environment.count(item) == 1 for item in (
                'INKY_STUDIO_DISPLAY_MODE=hardware', 'INKY_STUDIO_DISPLAY_PROFILE=ac073-800x480'))
        return valid

    def permit(self, request, *, helper_verified=False):
        if helper_verified:
            value = self.read_permit(request)
            require(value['helper_pending'] is False and value['app_pending'] is True, 'activation_permit_invalid')
            value['helper_verified'] = True
            self.store.put(PERMIT, value, replace=True)
        else:
            self.store.put(PERMIT, {'schema_version': 1, 'kind': 'test-access-activation-permit', **self.store.binding,
                'request_sha256': digest(canonical(request)), 'expires_monotonic_ns': time.monotonic_ns() + PERMIT_TTL_NS,
                'helper_pending': True, 'app_pending': True, 'helper_verified': False})
        return True

    def read_permit(self, request):
        value = self.store.read(PERMIT)
        require(type(value) is dict and set(value) == BINDING_FIELDS | {'schema_version', 'kind', 'request_sha256',
                'expires_monotonic_ns', 'helper_pending', 'app_pending', 'helper_verified'}
                and type(value['schema_version']) is int and value['schema_version'] == 1
                and value['kind'] == 'test-access-activation-permit' and all(value[k] == self.store.binding[k] for k in BINDING_FIELDS)
                and value['request_sha256'] == digest(canonical(request))
                and type(value['expires_monotonic_ns']) is int and time.monotonic_ns() < value['expires_monotonic_ns'] <= time.monotonic_ns() + PERMIT_TTL_NS
                and all(type(value[k]) is bool for k in ('helper_pending', 'app_pending', 'helper_verified')),
                'activation_permit_invalid')
        return value

    def take_permit(self, role, request):
        require(role in UNITS, 'activation_permit_invalid')
        value = self.read_permit(request)
        if role == 'helper':
            require(value['helper_pending'] and value['app_pending'] and not value['helper_verified'], 'activation_permit_invalid')
            value['helper_pending'] = False
            self.store.put(PERMIT, value, replace=True)
        else:
            require(not value['helper_pending'] and value['app_pending'] and value['helper_verified'], 'activation_permit_invalid')
            require(self.fresh_utc(request), 'activation_utc_stale')
            self.store.clear_permit()
        return True

    def start(self, role):
        require(self.unchanged(), 'activation_state_changed')
        require(self.effective(role), 'activation_units_invalid')
        return self.command(('/usr/bin/systemctl', '--no-block', 'start', UNITS[role])) == (0, b'')

    def active(self, role):
        value = self.properties(UNITS[role], ('ActiveState', 'SubState', 'MainPID'))
        return (value['ActiveState'] == 'active' and value['SubState'] == 'running'
                and re.fullmatch(r'[1-9][0-9]{0,9}', value['MainPID']) is not None)

    def health(self):
        path = '/run/inky-network/control.sock'
        import pwd, grp
        uid, gid = pwd.getpwnam('inky-network').pw_uid, grp.getgrnam('inky-provisioning').gr_gid
        parent = self.files.directory('/run')
        directory = None
        try:
            directory = os.open('inky-network', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            runtime = os.fstat(directory)
            require(stat.S_ISDIR(runtime.st_mode) and runtime.st_uid == uid and runtime.st_gid == gid
                    and stat.S_IMODE(runtime.st_mode) == 0o750, 'activation_helper_failed')
            before = os.stat('control.sock', dir_fd=directory, follow_symlinks=False)
            require(stat.S_ISSOCK(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o660, 'activation_helper_failed')
            state = self.properties(UNITS['helper'], ('ActiveState', 'SubState', 'MainPID', 'User', 'Group'))
            require(before.st_uid == uid and before.st_gid == gid and state['User'] == 'inky-network'
                    and state['Group'] == 'inky-provisioning' and state['ActiveState'] == 'active'
                    and state['SubState'] == 'running', 'activation_helper_failed')
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(2)
                deadline = min(self.deadline, time.monotonic() + 2)
                connection.connect(path)
                pid, peer_uid, peer_gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                require(str(pid) == state['MainPID'] and peer_uid == uid and peer_gid == gid, 'activation_helper_failed')
                connection.sendall(b'{"op":"health"}\n')
                raw = bytearray()
                while len(raw) <= 16384:
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, 'activation_helper_failed')
                    connection.settimeout(remaining)
                    block = connection.recv(min(4096, 16385 - len(raw)))
                    if not block: break
                    raw.extend(block)
                require(bytes(raw) == b'{"ok":true,"result":{"ready":true,"protocol":1}}\n', 'activation_helper_failed')
            after = os.stat('control.sock', dir_fd=directory, follow_symlinks=False)
            require(self.lib['_stamp'](before) == self.lib['_stamp'](after), 'activation_helper_failed')
            require(self.lib['_stamp'](runtime) == self.lib['_stamp'](os.fstat(directory))
                    == self.lib['_stamp'](os.stat('inky-network', dir_fd=parent, follow_symlinks=False)),
                    'activation_helper_failed')
            return True
        finally:
            if directory is not None: os.close(directory)
            os.close(parent)

    def wait_ready(self, role):
        deadline = min(self.deadline, time.monotonic() + (20 if role == 'helper' else 15))
        while time.monotonic() < deadline:
            self.no_drain()
            require(self.unchanged(), 'activation_state_changed')
            if self.active(role):
                if role == 'app': return True
                try:
                    if self.health(): return True
                except (FileNotFoundError, ConnectionRefusedError, socket.timeout):
                    pass  # ActiveState can precede the helper socket creation.
            time.sleep(0.1)
        return False

    def fresh_utc(self, request):
        query = {k: request['request'][k] for k in UTC_FIELDS}
        preflight = {'__name__': 'activation_preflight_clock', '__file__': BASE + 'test-lan-preflight.py'}
        exec(compile(self.boot.sources[preflight['__file__']], preflight['__file__'], 'exec'), preflight)
        return (self.command(preflight['COMMANDS']['utc_sync'], timeout=2) == (0, b'v b true\n')
                and self.gate['reference_current'](query, elapsed=self.elapsed(request)) is True)

    def close(self):
        failed = False
        for fd in (self.activation_fd, self.directory):
            if fd is not None:
                try: os.close(fd)
                except OSError: failed = True
        if self.boot is not None:
            try: self.boot.close()
            except Exception: failed = True
        if failed: raise ActivationError('activation_failed')


def activate(adapter):
    report, request, claimed = result(), None, False
    try:
        require(adapter.bind() is True)
        require(adapter.acquire() is True, 'activation_busy')
        with adapter.operation():
            adapter.no_drain()
            request = adapter.request()
            previous = adapter.report(request)
            require(previous['phase'] == 'queued', 'activation_already_admitted')
            claimed = True
            report.update(phase='gating', request_accepted=True)
            adapter.publish(request, report)
        ready = adapter.assess(request)
        observed = getattr(adapter, 'assessment', None)
        if observed is not None:
            report['assessment'] = assessment_projection(observed)
        require(ready is True, 'activation_gate_failed')
        with adapter.operation():
            adapter.no_drain()
            require(adapter.unchanged() is True, 'activation_state_changed')
            report['phase'] = 'preparing'; adapter.publish(request, report)
            require(adapter.prepare_units() is True, 'activation_units_invalid')
            adapter.no_drain()
            require(adapter.permit(request) is True, 'activation_permit_invalid')
            adapter.no_drain()
            require(adapter.start('helper') is True, 'activation_helper_failed')
            report['phase'] = 'helper-start-requested'; adapter.publish(request, report)
        require(adapter.wait_ready('helper') is True, 'activation_helper_failed')
        with adapter.operation():
            adapter.no_drain()
            require(adapter.unchanged() is True, 'activation_state_changed')
            report.update(phase='helper-ready', helper_started=True, helper_verified=True)
            adapter.publish(request, report)
            require(adapter.fresh_utc(request) is True, 'activation_utc_stale')
            adapter.no_drain()
            require(adapter.permit(request, helper_verified=True) is True, 'activation_permit_invalid')
            adapter.no_drain()
            require(adapter.start('app') is True, 'activation_app_failed')
            report['phase'] = 'app-start-requested'; adapter.publish(request, report)
        require(adapter.wait_ready('app') is True, 'activation_app_failed')
        with adapter.operation():
            adapter.no_drain()
            require(adapter.unchanged() is True, 'activation_state_changed')
            adapter.invalidate()
            report.update(phase='active', passed=True, application_started=True, application_active_observed=True)
            adapter.publish(request, report)
        return 0, report
    except (Exception, KeyboardInterrupt) as error:
        report.update(passed=False, phase='failed', error=str(error) if type(error) is ActivationError and str(error) in ERRORS else 'activation_failed')
        if claimed:
            try:
                with adapter.operation():
                    adapter.invalidate()
                    if request is not None: adapter.publish(request, report)
            except Exception: pass
        return 1, report
    finally:
        try: adapter.close()
        except Exception:
            report.update(passed=False, phase='failed', error='activation_failed')
            return 1, report


def consume(adapter, role):
    try:
        require(role in {'helper', 'app'}, 'activation_permit_invalid')
        require(adapter.bind() is True)
        with adapter.operation():
            adapter.no_drain()
            request = adapter.request()
            require(adapter.unchanged() is True, 'activation_state_changed')
            require(adapter.take_permit(role, request) is True, 'activation_permit_invalid')
        return 0
    except Exception:
        return 1
    finally:
        try: adapter.close()
        except Exception: return 1


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args == ['--activate']:
        def interrupted(_signal, _frame): raise ActivationError('activation_interrupted')
        signal.signal(signal.SIGTERM, interrupted)
        code, report = activate(NativeAdapter())
        print(json.dumps(report, sort_keys=True, separators=(',', ':')))
        return code
    if args in (['--consume-app-permit'], ['--consume-helper-permit']):
        return consume(NativeAdapter(), 'app' if args[0] == '--consume-app-permit' else 'helper')
    return 2


if __name__ == '__main__':
    sys.exit(main())
