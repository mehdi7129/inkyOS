#!/usr/bin/python3 -I
"""Ephemeral, initial TEST activation assessment; never activate anything.

The historical preflight stays unchanged. Three unavailable historical checks
have explicit TEST replacements, separately reported. Only this gate's exact
native adapter can report readiness; fixtures, EEPROM declarations and kernel
country observations do not qualify hardware. No permit is written. A caller
must hold the activation lifecycle lock and consume readiness immediately in memory.
"""
import sys
sys.dont_write_bytecode = True

import hashlib
import json
import math
import os
import platform
import re
import select
import signal
import stat
import struct
import time


BASE = '/usr/local/lib/inkyos/'
SELF = BASE + 'test-access-activation-gate.py'
LEGACY = BASE + 'test-enrollment-firstboot.py'
CONNECT = BASE + 'test-access-connect.py'
PREFLIGHT = BASE + 'test-lan-preflight.py'
PANEL = BASE + 'observe-test-panel.py'
MANIFEST = '/usr/local/share/inkyos/test-access-manifest.json'
APP_MANIFEST = '/usr/local/share/inkyos/inky-studio-manifest-v1.json'
MARKER = '/etc/inkyos-test-lan.json'
LEGACY_SHA256 = '081bac2c04d4e72a6e74a365664b72941fa4d1e84d1ccc32cf0dc25d9e8a337a'
PREFLIGHT_SHA256 = '9cda15bfeaef8ed5bc7c0a2d0b71f470a1411d13dda4e2043f800e9ca37e5fba'
PANEL_SHA256 = '6fc6b93e30beeb6c03a3867efeb88cfe30ed7e1fe58f2ea6e5c35db9a4c29164'
SOURCE = 'c31b13afdc957425571810c46230eaaf52fa5d14'
APP_MANIFEST_SHA256 = 'c4183e7304e3ff979450977b36e4a007b30016de68bb23ef121c7ca733cd26a1'
PARENT = 'dcc451dc927eeb5ba202ca480005351a7516c13bc057f6946e4023efea91a595'
PROFILE = 'ac073-800x480'
BUDGET = 45.0
REQUEST_FIELDS = {'schema_version', 'utc_reference', 'utc_reference_age', 'utc_reference_source'}
HISTORICAL_CHECKS = (
    'prepared_profile', 'exact_payload_pin', 'operator_access_confirmed', 'firstboot_success',
    'app_stopped_and_masked', 'helper_stopped_and_masked', 'networkmanager_manages_connected_wlan0',
    'country_operator_confirmed', 'country_global_matches', 'country_phy_matches', 'utc_synchronized',
    'independent_reference_recent', 'utc_matches_independent_reference', 'bluez_running', 'hci0_powered',
    'bluetooth_unblocked', 'system_packages_present', 'application_hardware_metadata_present',
    'service_accounts_and_groups', 'spi_i2c_gpio_nodes', 'application_state_virgin', 'helper_state_virgin',
    'panel_inventory_supplied_and_valid', 'panel_runtime_evidence_verified',
)
REPLACED_CHECKS = ('country_phy_matches', 'panel_inventory_supplied_and_valid', 'panel_runtime_evidence_verified')
RADIO_CHECKS = ('firmware_country_fr', 'firmware_ccode_fr', 'kernel_global_fr', 'phy_label_reviewed', 'channels_test_fr')
CHECKS = (
    'target_verified', 'sources_and_enrollment_bound', 'cache_authenticated', 'operator_country_confirmed',
    'bindings_unchanged_before', 'connection_verified_before', 'application_templates_verified',
    'historical_provenance_valid', 'historical_required_checks_passed', 'inactive_runtime_before_panel',
    'panel_exact_test_tuple', 'radio_mapping_consistent', 'radio_test_policy_verified',
    'bindings_unchanged_after', 'connection_verified_after', 'inactive_runtime_after',
    'application_templates_unchanged', 'independent_reference_still_recent',
)
APP_FILES = {
    '/usr/lib/systemd/system/inky-studio.service': ('c9d7e4c16ec08c3b5e51af584a2ed1d70f66ebd3dcfd1d9e42d2d5abd751aef8', 0o644),
    '/usr/lib/systemd/system/inky-network.service': ('6fae02fbef586060085882325e43346d18889f5a73a3dfae407d2df95cf547bb', 0o644),
    '/etc/systemd/system/inky-studio.service.d/bluetooth.conf': ('50621d3ee8c2fa6b9afb58d174c32dcdbc73d939ead0bd6ad1d84f36f34c263d', 0o644),
    '/etc/systemd/system/inky-studio.service.d/10-inkyos-firstboot.conf': ('abe954d0381202ad9f4388256575fa1a63f75814cf7b4c28a50708c624dbddfc', 0o644),
    '/etc/systemd/system/inky-network.service.d/10-inkyos-firstboot.conf': ('abe954d0381202ad9f4388256575fa1a63f75814cf7b4c28a50708c624dbddfc', 0o644),
}
DROPIN_NAMES = {
    '/etc/systemd/system/inky-studio.service.d': {'bluetooth.conf', '10-inkyos-firstboot.conf'},
    '/etc/systemd/system/inky-network.service.d': {'10-inkyos-firstboot.conf'},
    **{prefix + '/' + unit + '.d': set() for prefix in ('/run/systemd/system', '/usr/lib/systemd/system')
       for unit in ('inky-studio.service', 'inky-network.service')},
}
ERRORS = {'invalid_request', 'target_unverified', 'sources_invalid', 'cache_invalid',
          'country_unconfirmed', 'state_changed', 'connection_unconfirmed', 'templates_unconfirmed',
          'historical_invalid', 'historical_blocked', 'inactive_runtime_required', 'panel_unconfirmed',
          'radio_unconfirmed', 'reference_expired', 'runtime_timeout', 'assessment_unavailable', 'invalid_arguments'}


class GateError(ValueError):
    pass


def require(value, error):
    if value is not True:
        raise GateError(error)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def validate_request(value):
    return (type(value) is dict and set(value) == REQUEST_FIELDS
        and type(value['schema_version']) is int and value['schema_version'] == 1
        and type(value['utc_reference']) is int and 1767225600 <= value['utc_reference'] <= 2524608000
        and type(value['utc_reference_age']) is int and 0 <= value['utc_reference_age'] <= 60
        and type(value['utc_reference_source']) is str and value['utc_reference_source'] in {'independent-device', 'gnss'})


def reference_current(request, elapsed=0):
    """Fresh independent-reference comparison only; does not re-observe NTP."""
    if (not validate_request(request) or type(elapsed) not in {int, float}
            or not math.isfinite(elapsed) or elapsed < 0):
        return False
    age = request['utc_reference_age'] + elapsed
    current = time.time()
    return (type(current) in {int, float} and math.isfinite(current)
            and 0 <= age <= 60 and abs(current - (request['utc_reference'] + age)) <= 30)


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'invalid_request')
            value[key] = item
        return value
    def invalid(_value):
        raise GateError('invalid_request')
    require(type(raw) is bytes and 0 < len(raw) <= 4096, 'invalid_request')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)


def bootstrap():
    """Only the immutable root-owned safe reader is executed before binding."""
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    source = None
    try:
        for part in LEGACY.strip('/').split('/')[:-1]:
            info = os.fstat(directory)
            require(info.st_uid == 0 and not info.st_mode & 0o022, 'sources_invalid')
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.fstat(directory)
        require(info.st_uid == 0 and not info.st_mode & 0o022, 'sources_invalid')
        name = LEGACY.rsplit('/', 1)[1]
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        before = os.fstat(source)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_gid == 0
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o555
                and 0 < before.st_size <= 65536, 'sources_invalid')
        raw = os.read(source, 65537)
        stamp = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
                             item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        require(len(raw) == before.st_size and digest(raw) == LEGACY_SHA256
                and stamp(before) == stamp(os.fstat(source))
                == stamp(os.stat(name, dir_fd=directory, follow_symlinks=False)), 'sources_invalid')
    finally:
        if source is not None:
            os.close(source)
        os.close(directory)
    return load(raw, LEGACY)


def load(raw, path):
    value = {'__name__': 'inkyos_activation_gate_dependency', '__file__': path}
    exec(compile(raw, path, 'exec'), value)
    return value


class NativeAdapter:
    def __init__(self):
        self.connection = None
        self.snapshot = {}

    def target(self):
        if not (sys.platform.startswith('linux') and platform.machine() == 'aarch64'
                and sys.byteorder == 'little' and os.getuid() == os.geteuid() == 0):
            return False
        self.lib = bootstrap()
        files = self.lib['Files']()
        try:
            return files.read(self.lib['MODEL_PATH'], limit=128) == self.lib['PI_MODEL']
        finally:
            files.close()

    def bind(self):
        files = self.lib['Files']()
        try:
            raw = files.read(MANIFEST, mode=0o644, limit=65536)
            manifest = self.lib['strict_json'](raw)
            require(type(manifest) is dict and set(manifest) == {'schema_version', 'kind',
                'application_source_commit', 'application_manifest_sha256', 'parent_image_sha256', 'files'}
                and type(manifest['schema_version']) is int and manifest['schema_version'] == 1
                and manifest['kind'] == 'test-access-runtime'
                and (manifest['application_source_commit'], manifest['application_manifest_sha256'], manifest['parent_image_sha256'])
                    == (SOURCE, APP_MANIFEST_SHA256, PARENT) and type(manifest['files']) is dict, 'sources_invalid')
            sources = {}
            for path in (SELF, CONNECT, PREFLIGHT, PANEL):
                data = files.read(path, mode=0o555, limit=65536)
                require(manifest['files'].get(path[1:]) == {'sha256': digest(data), 'mode': '0555'}, 'sources_invalid')
                sources[path] = data
            require(digest(sources[PREFLIGHT]) == PREFLIGHT_SHA256 and digest(sources[PANEL]) == PANEL_SHA256,
                    'sources_invalid')
        finally:
            files.close()
        self.connect = load(sources[CONNECT], CONNECT)
        self.connection = self.connect['NativeAdapter']()
        self.connection.deadline = self.connection.work_deadline = self.deadline
        require(self.connection.target() is True and self.connection.bind() is True, 'sources_invalid')
        auth = self.connection.auth
        require(auth.snapshot[MANIFEST][0] == raw and all(auth.snapshot[path][0] == data
                    for path, data in sources.items()), 'state_changed')
        self.preflight_module = load(sources[PREFLIGHT], PREFLIGHT)
        self.panel_module = load(sources[PANEL], PANEL)
        require(tuple(self.preflight_module['CHECKS']) == HISTORICAL_CHECKS, 'sources_invalid')
        return True

    def authenticate_cache(self):
        return self.connection.authenticate_cache()

    def country_confirmed(self):
        # Authentication has parsed the signed capsule with exact country FR.
        profile = self.lib['strict_json'](self.connection.auth.snapshot[self.connection.importer['PROFILE']][0])
        return profile['country_requested'] == 'FR'

    def unchanged(self):
        return (self.connection.unchanged() is True and self.connection.country.unchanged() is True
                and all(self.connection.auth.files.read(path, mode=mode, limit=65536) == raw
                        for path, (raw, mode) in self.snapshot.items()))

    def connected(self):
        return (self.connection.auth.files.read(self.connect['PROFILE'], mode=0o600, limit=4096) == self.connection.network
                and self.connection.profiles_closed() is True and self.connection.profile_restricted() is True
                and self.connection.connected() is True)

    def templates(self):
        files = self.connection.auth.files
        for path, (pin, mode) in {**APP_FILES, APP_MANIFEST: (APP_MANIFEST_SHA256, 0o444)}.items():
            raw = files.read(path, mode=mode, limit=65536)
            if digest(raw) != pin or path in self.snapshot and self.snapshot[path] != (raw, mode):
                return False
            self.snapshot[path] = (raw, mode)
        marker_raw = files.read(MARKER, mode=0o644, limit=65536)
        marker = self.lib['strict_json'](marker_raw)
        if (type(marker) is not dict or marker.get('source_commit') != SOURCE
                or marker.get('manifest_sha256') != APP_MANIFEST_SHA256
                or marker.get('state') != 'prepared-inactive'
                or MARKER in self.snapshot and self.snapshot[MARKER] != (marker_raw, 0o644)):
            return False
        self.snapshot[MARKER] = (marker_raw, 0o644)
        for path, expected in DROPIN_NAMES.items():
            try:
                directory = files.directory(path)
            except FileNotFoundError:
                if expected:
                    return False
                continue
            try:
                if set(os.listdir(directory)) != expected:
                    return False
            finally:
                os.close(directory)
        # A runtime unit could be hidden by the current persistent mask and
        # take precedence over the verified vendor file once unmasked.
        try:
            directory = files.directory('/run/systemd/system')
        except FileNotFoundError:
            return True
        try:
            for unit in ('inky-studio.service', 'inky-network.service'):
                try:
                    os.stat(unit, dir_fd=directory, follow_symlinks=False)
                    return False
                except FileNotFoundError:
                    pass
        finally:
            os.close(directory)
        return True

    def preflight(self, request):
        module = self.preflight_module
        return module['preflight'](module['LiveAdapter'](), live=True, operator_access_confirmed=True,
            country='FR', country_confirmed=True, panel_inventory=None,
            **{key: request[key] for key in REQUEST_FIELDS - {'schema_version'}})

    def inactive(self):
        self.connection.country.deadline = self.deadline
        return self.connection.country.prepared()

    def panel(self):
        # Keep the old catalogue untouched: its parse_eeprom rejects colour 4.
        # Only the fixed pointer/read transaction is reused, not a driver import.
        raw = self.panel_module['ProductionAdapter']().sample()
        require(type(raw) is bytes and len(raw) == 29, 'panel_unconfirmed')
        width, height, color, _pcb, variant, _timestamp = struct.unpack('<HHBBB22p', raw)
        return {'width': width, 'height': height, 'color_code': color, 'display_variant': variant}

    def radio(self):
        country = self.connection.country
        country.deadline = self.deadline
        before = country.mapping()
        index, firmware, kernel, channels = country.observe()
        after = country.mapping()
        return {'mapping_consistent': (type(before) is int and type(index) is int and type(after) is int
                    and 0 <= before <= 255 and before == index == after),
                'checks': self.connection.country_module['evaluate'](firmware, kernel, channels)}

    def reference_current(self, request, elapsed):
        return reference_current(request, elapsed)

    def close(self):
        if self.connection is not None:
            self.connection.close()


def historical_projection(value, *, native):
    fields = {'schema_version', 'kind', 'live_selected', 'scope', 'checks', 'passed', 'activation_authorized',
              'live_evidence', 'observation_source', 'hardware_qualified', 'release_qualified', 'limitations', 'error'}
    require(type(value) is dict and set(value) == fields and type(value['schema_version']) is int
        and value['schema_version'] == 1 and value['kind'] == 'test-lan-preflight'
        and value['scope'] == 'test_lan_preconditions_only' and value['live_selected'] is True
        and type(value['passed']) is bool and type(value['live_evidence']) is bool
        and value['activation_authorized'] is value['hardware_qualified'] is value['release_qualified'] is False
        and value['observation_source'] == ('live-system' if native else 'fixture')
        and value['live_evidence'] is native and value['error'] in {None, 'observations_unavailable'}
        and type(value['checks']) is dict and set(value['checks']) == set(HISTORICAL_CHECKS), 'historical_invalid')
    checks = {}
    for name, row in value['checks'].items():
        require(type(row) is dict and set(row) == {'passed', 'status', 'reason'} and type(row['passed']) is bool
            and row['status'] == ('PASS' if row['passed'] else 'BLOCKED')
            and (row['reason'] is None if row['passed'] else row['reason'] in {
                'precondition_unverified', 'panel_runtime_observation_pending',
                'existing_or_unsafe_state_requires_explicit_review'}), 'historical_invalid')
        checks[name] = dict(row)
    require(value['passed'] is all(row['passed'] for row in checks.values()), 'historical_invalid')
    return checks


def empty_result():
    return {'schema_version': 1, 'kind': 'test-access-activation-assessment', 'scope': 'initial-test-only',
        'passed': False, 'live_evidence': False, 'ready_for_test_activation': False, 'error': None,
        'gate_checks': dict.fromkeys(CHECKS, False), 'historical_checks': {}, 'historical_preflight_passed': False,
        'historical_replaced_checks': list(REPLACED_CHECKS), 'radio_checks': dict.fromkeys(RADIO_CHECKS, False),
        'test_profile': PROFILE, 'panel': None, 'permit_written': False, 'application_started': False,
        'helper_started': False, 'activation_authorized': False, 'hardware_qualified': False,
        'release_qualified': False, 'firmware_tuple_qualified': False,
        'limits': ['Readiness is ephemeral and only for the first TEST activation with virgin application/helper data.',
                   'The historical preflight and its three replaced checks are preserved without asserting a historical PASS.',
                   'EEPROM 800x480/colour4/variant20 selects an explicit TEST candidate; the unsigned declaration is not physical qualification.',
                   'FR/FR firmware and FR or 99 PHY labels plus kernel channel limits are a TEST policy, not RF certification.',
                   'The EEPROM transaction positions its read pointer; no EEPROM contents or display pixels are written.',
                   'Snapshots and cache locking cannot exclude unrelated privileged changes.',
                   'Read deadlines cannot interrupt kernel-blocked filesystem I/O; an I2C child may remain pending after timeout.',
                   'No country setter, Wi-Fi toggle, clock update, service activation, profile or permit write is performed.']}


def assess(adapter, request):
    result = empty_result()
    native = type(adapter) is NativeAdapter
    started = time.monotonic()
    try:
        require(validate_request(request), 'invalid_request')
        adapter.deadline = started + BUDGET
        def within(operation):
            require(time.monotonic() < adapter.deadline, 'runtime_timeout')
            value = operation()
            require(time.monotonic() < adapter.deadline, 'runtime_timeout')
            return value
        def checked(name, operation, error):
            require(within(operation) is True, error)
            result['gate_checks'][name] = True
        for name, operation, error in (
            ('target_verified', adapter.target, 'target_unverified'),
            ('sources_and_enrollment_bound', adapter.bind, 'sources_invalid'),
            ('cache_authenticated', adapter.authenticate_cache, 'cache_invalid'),
            ('operator_country_confirmed', adapter.country_confirmed, 'country_unconfirmed'),
            ('bindings_unchanged_before', adapter.unchanged, 'state_changed'),
            ('connection_verified_before', adapter.connected, 'connection_unconfirmed'),
            ('application_templates_verified', adapter.templates, 'templates_unconfirmed'),
        ):
            checked(name, operation, error)
        aged = dict(request, utc_reference_age=request['utc_reference_age'] + math.ceil(time.monotonic() - started))
        require(validate_request(aged), 'reference_expired')
        historical = within(lambda: adapter.preflight(aged))
        result['historical_checks'] = historical_projection(historical, native=native)
        result['historical_preflight_passed'] = historical['passed']
        result['gate_checks']['historical_provenance_valid'] = True
        checked('historical_required_checks_passed', lambda: all(row['passed'] for name, row in
            result['historical_checks'].items() if name not in REPLACED_CHECKS), 'historical_blocked')
        checked('inactive_runtime_before_panel', adapter.inactive, 'inactive_runtime_required')
        panel = within(adapter.panel)
        valid_panel = (type(panel) is dict and set(panel) == {'width', 'height', 'color_code', 'display_variant'}
            and all(type(value) is int for value in panel.values())
            and panel == {'width': 800, 'height': 480, 'color_code': 4, 'display_variant': 20})
        checked('panel_exact_test_tuple', lambda: valid_panel, 'panel_unconfirmed')
        result['panel'] = dict(panel)
        radio = within(adapter.radio)
        require(type(radio) is dict and set(radio) == {'mapping_consistent', 'checks'}
                and type(radio['mapping_consistent']) is bool and type(radio['checks']) is dict
                and set(radio['checks']) == set(RADIO_CHECKS)
                and all(type(value) is bool for value in radio['checks'].values()), 'radio_unconfirmed')
        result['radio_checks'] = dict(radio['checks'])
        checked('radio_mapping_consistent', lambda: radio['mapping_consistent'], 'radio_unconfirmed')
        checked('radio_test_policy_verified', lambda: all(radio['checks'].values()), 'radio_unconfirmed')
        for name, operation, error in (
            ('bindings_unchanged_after', adapter.unchanged, 'state_changed'),
            ('connection_verified_after', adapter.connected, 'connection_unconfirmed'),
            ('inactive_runtime_after', adapter.inactive, 'inactive_runtime_required'),
            ('application_templates_unchanged', adapter.templates, 'templates_unconfirmed'),
            ('independent_reference_still_recent', lambda: adapter.reference_current(request, time.monotonic() - started), 'reference_expired'),
        ):
            checked(name, operation, error)
        result.update(passed=True, live_evidence=native, ready_for_test_activation=native)
    except Exception as error:
        result['error'] = str(error) if type(error) is GateError and str(error) in ERRORS else 'assessment_unavailable'
    finally:
        try:
            adapter.close()
        except Exception:
            result.update(passed=False, live_evidence=False, ready_for_test_activation=False, error='assessment_unavailable')
    return result


def receive(fd):
    deadline, raw = time.monotonic() + 5.0, bytearray()
    while True:
        remaining = deadline - time.monotonic()
        require(remaining > 0 and bool(select.select([fd], [], [], remaining)[0]), 'invalid_request')
        chunk = os.read(fd, min(1024, 4097 - len(raw)))
        if not chunk:
            return bytes(raw)
        raw.extend(chunk)
        require(len(raw) <= 4096, 'invalid_request')


def main(argv=None):
    result = empty_result()
    old_handler = None
    try:
        require((sys.argv[1:] if argv is None else argv) == [], 'invalid_arguments')
        request = strict_json(receive(sys.stdin.fileno()))
        def timeout(_number, _frame):
            raise GateError('runtime_timeout')
        old_handler = signal.signal(signal.SIGALRM, timeout)
        signal.setitimer(signal.ITIMER_REAL, BUDGET)
        result = assess(NativeAdapter(), request)
    except Exception as error:
        result['error'] = str(error) if type(error) is GateError and str(error) in ERRORS else 'invalid_request'
    finally:
        if old_handler is not None:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old_handler)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['ready_for_test_activation'] else 1


if __name__ == '__main__':
    sys.exit(main())
