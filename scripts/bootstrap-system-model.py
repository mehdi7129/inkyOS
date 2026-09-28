#!/usr/bin/env python3
"""INERT experimental model; neither BLE nor network-helper-v1 wire contract.

No CLI, service, socket, process, clock syscall, radio operation or persistence
implementation exists here. All adapter methods are injected test doubles.
Numeric caller UID is only a model input: a production SO_PEERCRED adapter does
not exist. Production also needs a process-shared lock, durable root-owned state
outside bootfs, reviewed time authorization/bounds, and a regulatory verifier
that checks the actual radio. This object's lock serializes threads only.

Requests are bounded JSON bytes with exact fields. Trusted time bounds and
country allowlist/verifiers are explicit; no country or UTC default is inferred.
Country processing closes the gate before pending -> apply -> observe -> confirmed.
Adapter success alone never acknowledges a country: a trusted verifier must
accept its observation, confirmed persistence must succeed, and Wi-Fi must still
be disabled. The returned gate is permission to proceed, NOT a radio enable call.
An authorized, syntactically valid operation's execution failure closes the gate
(including an unsupported country). Identity/parser refusal changes no state.
BLE is never touched. Initialization is an optional third INTERNAL model
operation, restricted to a distinct application UID. It invokes one injected
begin callback and preserves newly_consumed/already_consumed verbatim; a retry
never authorizes DB recreation. It never creates authorization or changes the
Wi-Fi gate, even on callback failure. Once invoked, callback errors or invalid
results raise InitializationUncertain: same-intent consultation/recovery only,
never a new intent or DB recreation. Interruptions remain interruptions.
Callbacks/verifiers must not reenter handle()/inspect() under the non-reentrant
lock. No BLE/helper-v1 contract is changed.

Fake adapter methods: set_time(int)->True, observe_time()->int,
close_wifi_gate()->True, wifi_status()->{disabled,trial,connected:bool},
persist_country(dict)->True, apply_country(str)->True, observe_country()->object.
Persistence True represents a durable write in the model only. Observations are
opaque trusted fixture values, not a proposed production response schema.
"""
import copy
import json
import threading
import uuid

MAX_REQUEST_BYTES = 256
MAX_UID = 2**32 - 2


class InitializationUncertain(RuntimeError):
    """The callback may have consumed authorization; recover without a new grant."""


class Refused(ValueError):
    """Malformed, unauthorized, unsafe or unconfirmed model operation."""


def _require(condition, message):
    if not condition:
        raise Refused(message)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, 'Duplicate JSON key')
        result[key] = value
    return result


def _not_integer(value):
    raise Refused('Only integer numeric JSON values are accepted')


def _country_code(value):
    return (type(value) is str and len(value) == 2 and
            all('A' <= character <= 'Z' for character in value) and value != 'EU')


def _canonical_uuid(value):
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def parse_request(raw):
    """Parse internal fixture operations; accept no paths, argv or extras."""
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_REQUEST_BYTES, 'Bounded JSON bytes required')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                           parse_float=_not_integer, parse_constant=_not_integer)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Refused('Malformed JSON request') from exc
    _require(type(value) is dict and type(value.get('operation')) is str, 'Operation object required')
    operation = value['operation']
    if operation == 'time':
        _require(set(value) == {'operation', 'unix_seconds'} and
                 type(value['unix_seconds']) is int, 'Exact integer time request required')
    elif operation == 'country':
        _require(set(value) == {'operation', 'country_code'} and
                 _country_code(value['country_code']), 'Exact ASCII country request required')
    elif operation == 'begin_initialization':
        _require(set(value) == {'operation', 'intent'} and _canonical_uuid(value['intent']),
                 'Exact canonical initialization intent required')
    else:
        raise Refused('Unknown internal operation')
    return value


class BootstrapSystemModel:
    """Thread-serialized fixture state. Construction never calls an adapter."""
    def __init__(self, *, helper_uid, time_bounds, country_allowlist,
                 time_verifier, regulatory_verifier, adapter,
                 application_uid=None, begin_initialization=None):
        _require(type(helper_uid) is int and 0 < helper_uid <= MAX_UID, 'Nonroot helper UID required')
        _require(type(time_bounds) is tuple and len(time_bounds) == 2 and
                 all(type(value) is int for value in time_bounds) and
                 0 <= time_bounds[0] <= time_bounds[1] <= 2**63 - 1,
                 'Explicit ordered trusted integer time bounds required')
        _require(type(country_allowlist) in (set, frozenset) and country_allowlist and
                 all(_country_code(code) for code in country_allowlist),
                 'Explicit trusted country allowlist required')
        _require(callable(time_verifier) and callable(regulatory_verifier), 'Trusted verifiers required')
        _require((application_uid is None and begin_initialization is None) or
                 (type(application_uid) is int and 0 < application_uid <= MAX_UID and
                  application_uid != helper_uid and callable(begin_initialization)),
                 'Initialization requires a distinct nonroot application UID and callback')
        self._application_uid = application_uid
        self._begin_initialization = begin_initialization
        self._helper_uid = helper_uid
        self._time_bounds = time_bounds
        self._countries = frozenset(country_allowlist)
        self._time_verifier = time_verifier
        self._regulatory_verifier = regulatory_verifier
        self._adapter = adapter
        self._lock = threading.Lock()
        self._gate_open = False
        self._requested_country = None
        self._persisted_country = None
        self._observed_country = None
        self._requested_time = None
        self._observed_time = None
        self._time_confirmed = False

    def _snapshot(self):
        return copy.deepcopy({
            'experimental_model': True, 'hardware_qualified': False,
            'wifi_gate_open': self._gate_open,
            'country': {'requested': self._requested_country,
                        'persisted': self._persisted_country,
                        'observed': self._observed_country},
            'time': {'requested': self._requested_time, 'observed': self._observed_time,
                     'confirmed': self._time_confirmed},
        })

    def inspect(self):
        """Return fixture state without invoking any adapter or hardware."""
        with self._lock:
            return self._snapshot()

    def handle(self, raw, *, caller_uid):
        with self._lock:
            # Authentication and syntax errors are side-effect free. An invalid
            # caller/request must not revoke another operation's confirmed gate.
            _require(type(caller_uid) is int and caller_uid in (self._helper_uid, self._application_uid),
                     'Configured nonroot caller UID required')
            request = parse_request(raw)
            if request['operation'] == 'begin_initialization':
                _require(self._begin_initialization is not None, 'Initialization operation not configured')
                _require(caller_uid == self._application_uid, 'Application UID required for initialization')
                result = self._begin(request['intent'])
                return {'acknowledged': True, 'operation': 'begin_initialization',
                        'initialization': result, **self._snapshot()}
            _require(caller_uid == self._helper_uid, 'Helper UID required for time/country')
            try:
                if request['operation'] == 'time':
                    self._set_time(request['unix_seconds'])
                else:
                    self._set_country(request['country_code'])
                return {'acknowledged': True, 'operation': request['operation'], **self._snapshot()}
            except BaseException:
                self._gate_open = False
                raise

    def _begin(self, intent):
        try:
            result = self._begin_initialization(intent)  # Exactly once; no retry on uncertainty.
            _require(type(result) is dict and set(result) == {'status', 'intent', 'receipt'} and
                     type(result['status']) is str and result['status'] in ('newly_consumed', 'already_consumed') and
                     type(result['intent']) is str and result['intent'] == intent,
                     'Invalid initialization callback result')
            receipt = result['receipt']
            _require(type(receipt) is dict and set(receipt) == {'receipt_id', 'digest'} and
                     _canonical_uuid(receipt['receipt_id']) and type(receipt['digest']) is str and
                     len(receipt['digest']) == 64 and all(c in '0123456789abcdef' for c in receipt['digest']),
                     'Invalid initialization receipt binding')
            return {'status': result['status'], 'intent': intent, 'receipt': dict(receipt)}
        except Exception as exc:
            raise InitializationUncertain('Initialization may be consumed; same-intent recovery only') from exc

    def _set_time(self, requested):
        low, high = self._time_bounds
        _require(low <= requested <= high, 'Time outside explicit trusted bounds')
        self._requested_time = requested
        self._observed_time = None
        self._time_confirmed = False
        _require(self._adapter.set_time(requested) is True, 'Time setter failed')
        observed = self._adapter.observe_time()
        self._observed_time = observed
        _require(type(observed) is int and low <= observed <= high and
                 self._time_verifier(requested, observed) is True, 'Time observation unconfirmed')
        self._time_confirmed = True

    def _wifi_status(self, *, disabled):
        status = self._adapter.wifi_status()
        _require(type(status) is dict and set(status) == {'disabled', 'trial', 'connected'} and
                 all(type(value) is bool for value in status.values()), 'Explicit Wi-Fi status required')
        _require(not status['trial'] and not status['connected'], 'Country change conflicts with Wi-Fi activity')
        if disabled:
            _require(status['disabled'], 'Wi-Fi must remain disabled during country confirmation')

    def _persist(self, status, code):
        record = {'status': status, 'country_code': code}
        _require(self._adapter.persist_country(dict(record)) is True, 'Country persistence failed')
        self._persisted_country = record

    def _set_country(self, code):
        _require(code in self._countries, 'Country absent from trusted allowlist')
        self._gate_open = False
        self._requested_country = code
        self._observed_country = None
        # Check activity first: this operation must not disconnect a trial or
        # active connection. Closing the model gate never touches BLE.
        self._wifi_status(disabled=False)
        _require(self._adapter.close_wifi_gate() is True, 'Wi-Fi gate closure failed')
        self._wifi_status(disabled=True)
        self._persist('pending', code)
        self._wifi_status(disabled=True)
        _require(self._adapter.apply_country(code) is True, 'Country apply failed')
        self._wifi_status(disabled=True)
        observed = self._adapter.observe_country()
        self._observed_country = copy.deepcopy(observed)
        _require(self._regulatory_verifier(code, observed) is True, 'Regulatory observation unconfirmed')
        self._wifi_status(disabled=True)
        self._persist('confirmed', code)
        self._wifi_status(disabled=True)
        self._gate_open = True
