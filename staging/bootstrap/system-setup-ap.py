"""Bounded FR prototype AP lifecycle, serialized by Setup.effects externally.

The controller owns one identity for one workflow and observed service invocation.
It does not retry an uncertain activation. Only verified status or targeted stop
can reconcile its opaque native record. A stopped AP can reuse that same identity
until the original BOOTTIME deadline; expiry never creates factory authority.

Secrets exist in memory and in successful IPC results only. This module performs
no logging, filesystem I/O, radio effects or locking of its own. The service is
Restart=no, and its native AP is bound to the persistent D-Bus client lifetime.
"""

import copy
import re
import secrets
import uuid


POLICY = {
    "schema_version": 1,
    "country": "FR",
    "interface": "wlan0",
    "channel": 6,
    "host": "192.168.4.1",
    "prefix": 24,
    "port": 9443,
    "ttl_seconds": 1800,
    "ssid_prefix": "Inky-",
}
WORKFLOW_KEYS = frozenset(
    {
        "initialization_intent",
        "initialization_receipt_digest",
        "frame_id",
        "spki_sha256",
    }
)
CONTEXT_KEYS = frozenset(
    {"boot_id", "candidate_sha256", "context_sha256", "main_invocation_id"}
)
RESULT_KEYS = frozenset(
    {
        "state", "boot_id", "ap_id", "country", "interface", "ssid",
        "passphrase", "host", "port", "expires_boottime_ns",
    }
)
MAX_BOOTTIME = 2**63 - 1
REASONS = frozenset(
    {
        "unavailable", "invalid_request", "conflict", "forbidden", "expired",
        "not_found", "session_closed", "reconciliation_required", "policy_invalid",
        "invalid_clock", "random_unavailable", "closed", "ap_unavailable",
        "ap_ownership_changed", "country_unconfirmed", "ap_timeout",
        "ap_effect_uncertain", "network_unconfirmed", "source_changed",
        "writer_guard_failed", "radio_unconfirmed", "ap_profile_changed",
        "ap_inventory_changed", "nm_owner_changed", "timeout",
    }
)


def _uuid(value):
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def _hex(value, length):
    return type(value) is str and re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is not None


def _safe_record(record):
    """A diagnostic record never exposes arbitrary adapter values or credentials."""
    if type(record) is not dict:
        return None
    result = {}
    for key in ("ap_id", "profile_uuid", "boot_id"):
        if _uuid(record.get(key)):
            result[key] = record[key]
    for key, collection in (("active_path", "ActiveConnection"), ("profile_path", "Settings"), ("device_path", "Devices")):
        value = record.get(key)
        pattern = r"/org/freedesktop/NetworkManager/" + collection + r"/[0-9]{1,10}"
        if type(value) is str and re.fullmatch(pattern, value):
            result[key] = value
    value = record.get("nm_unique_owner")
    if type(value) is str and re.fullmatch(r":[0-9]+\.[0-9]+", value):
        result["nm_unique_owner"] = value
    return result or None


class APError(ValueError):
    def __init__(self, reason="unavailable", *, record=None, owned_record=None, reconciliation=False):
        self.reason = reason if type(reason) is str and reason in REASONS else "unavailable"
        self.record = _safe_record(record)
        self.owned_record = owned_record
        self.reconciliation = bool(reconciliation)
        super().__init__(self.reason)

    def __repr__(self):
        return "APError(" + repr(self.reason) + ")"


def _require(condition, reason="unavailable"):
    if not condition:
        raise APError(reason)


def validate_policy(value):
    """This is one explicit FR prototype policy, not arbitrary radio settings."""
    _require(type(value) is dict and set(value) == set(POLICY), "policy_invalid")
    _require(all(type(value[key]) is type(expected) and value[key] == expected for key, expected in POLICY.items()), "policy_invalid")
    return value.copy()


def _binding(workflow, context):
    _require(type(workflow) is dict and set(workflow) == WORKFLOW_KEYS, "invalid_request")
    _require(type(context) is dict and set(context) == CONTEXT_KEYS, "invalid_request")
    _require(_uuid(workflow["initialization_intent"]) and _uuid(workflow["frame_id"]) and _hex(workflow["initialization_receipt_digest"], 64) and _hex(workflow["spki_sha256"], 64), "invalid_request")
    _require(_uuid(context["boot_id"]) and _hex(context["candidate_sha256"], 64) and _hex(context["context_sha256"], 64) and _hex(context["main_invocation_id"], 32), "invalid_request")
    return workflow.copy(), context.copy()


class Controller:
    def __init__(self, adapter, policy, *, boottime_ns, random=None):
        self.adapter = adapter
        self.policy = validate_policy(policy)
        _require(callable(boottime_ns), "invalid_request")
        _require(random is None or callable(random), "invalid_request")
        self._clock = boottime_ns
        self._random = secrets.token_bytes if random is None else random
        self._workflow = self._context = self._config = self._record = None
        self._state = "stopped"
        self._uncertain = self._closed = self._generation_failed = False
        self._clock_invalid = False
        self._last_now = None

    def __repr__(self):
        return "Controller(state=" + repr(self._state) + ", has_started=" + repr(self.has_started) + ")"

    @property
    def has_started(self):
        return self._config is not None

    @property
    def record_active(self):
        return self._record is not None and self._state == "active" and not self._uncertain

    def _now(self):
        _require(not self._clock_invalid, "invalid_clock")
        try:
            value = self._clock()
        except Exception:
            self._clock_invalid = True
            if self._config is not None:
                self._state = "expired"
            raise APError("invalid_clock") from None
        if not (type(value) is int and 0 <= value <= MAX_BOOTTIME and (self._last_now is None or value >= self._last_now)):
            self._clock_invalid = True
            if self._config is not None:
                self._state = "expired"
            raise APError("invalid_clock")
        self._last_now = value
        return value

    def _admit(self, workflow, context, check, *, allow_closed=False):
        _require(callable(check), "invalid_request")
        check()
        _require(allow_closed or not self._closed, "closed")
        current = _binding(workflow, context)
        if self._workflow is not None:
            _require(current == (self._workflow, self._context), "conflict")
        return current

    def _generate(self, binding, now):
        _require(not self._generation_failed, "random_unavailable")
        self._workflow, self._context = binding
        # A broken entropy source must not turn repeated calls into generation
        # attempts. No native effect is admitted until all bytes are validated.
        self._generation_failed = True
        try:
            raw = [self._random(count) for count in (4, 12, 16)]
            _require(all(type(value) is bytes and len(value) == count for value, count in zip(raw, (4, 12, 16))), "random_unavailable")
            deadline = now + self.policy["ttl_seconds"] * 10**9
            _require(deadline <= MAX_BOOTTIME, "invalid_clock")
            self._config = {
                "boot_id": self._context["boot_id"],
                "ap_id": str(uuid.UUID(bytes=raw[2], version=4)),
                "country": self.policy["country"],
                "interface": self.policy["interface"],
                "ssid": self.policy["ssid_prefix"] + raw[0].hex(),
                "passphrase": raw[1].hex(),
                "host": self.policy["host"],
                "prefix": self.policy["prefix"],
                "port": self.policy["port"],
                "channel": self.policy["channel"],
                "expires_boottime_ns": deadline,
            }
        except APError:
            raise
        except Exception:
            raise APError("random_unavailable") from None
        self._generation_failed = False

    def _result(self):
        result = {key: self._config[key] for key in RESULT_KEYS if key != "state"}
        result["state"] = self._state
        return result

    def _failure(self, error, *, effect=False):
        owned = getattr(error, "owned_record", None)
        if owned is None:
            owned = getattr(error, "record", None)
        if owned is None:
            owned = getattr(self.adapter, "owned_record", None)
        if self._record is None and owned is not None:
            self._record = owned
        if effect or self._record is not None:
            self._uncertain = True
        return APError(
            getattr(error, "reason", "unavailable"),
            record=self._record,
            owned_record=self._record,
            reconciliation=self._uncertain,
        )

    def _stop_owned(self, check):
        if self._record is not None:
            try:
                check()
                self.adapter.stop(self._record, check)
                check()
            except Exception as error:
                raise self._failure(error, effect=True) from None
            self._record = None
        # A native start timeout can carry no record. NativeAP must reconcile
        # its pending call before stop returns, even when no path was received.
        elif self._uncertain:
            try:
                check()
                self.adapter.stop(None, check)
                check()
            except Exception as error:
                raise self._failure(error, effect=True) from None
        self._uncertain = False

    def _expire(self, now, check):
        if self._config is not None and now >= self._config["expires_boottime_ns"]:
            self._state = "expired"
            self._stop_owned(check)
            return True
        return self._state == "expired"

    def _verify(self, check):
        _require(self._record is not None, "reconciliation_required" if self._uncertain else "ap_unavailable")
        try:
            observation = self.adapter.verify(self._record, check)
            check()
            _require(type(observation) is dict and observation.get("active") is True and observation.get("state") == "active", "ap_unavailable")
            for key in ("ap_id", "country", "interface", "host", "prefix", "port", "channel"):
                _require(type(observation.get(key)) is type(self._config[key]) and observation[key] == self._config[key], "ap_ownership_changed")
        except Exception as error:
            raise self._failure(error) from None
        self._uncertain = False
        self._state = "active"

    def reserve(self, workflow, context, check):
        """Reserve one identity/deadline before the caller prepares any radio.

        This is strictly a RAM operation: even expiry of an already owned AP
        only seals admission here. The externally serialized expiry/stop path
        must drain that record, and can never use reserve to replay activation.
        No credential is returned before native readiness has been verified.
        """
        binding = self._admit(workflow, context, check)
        now = self._now()
        if self._config is None:
            self._generate(binding, now)
        check()
        now = self._now()
        if now >= self._config["expires_boottime_ns"]:
            self._state = "expired"
        _require(self._state != "expired", "expired")
        _require(not self._uncertain, "reconciliation_required")

    def start(self, workflow, context, check):
        binding = self._admit(workflow, context, check)
        now = self._now()
        if self._config is None:
            self._generate(binding, now)
        _require(not self._expire(now, check), "expired")
        _require(not self._uncertain, "reconciliation_required")
        if self._record is None:
            try:
                check()
                record = self.adapter.start(copy.deepcopy(self._config), check)
                self._record = record
                _require(record is not None, "ap_effect_uncertain")
                check()
            except Exception as error:
                raise self._failure(error, effect=True) from None
        self._verify(check)
        _require(not self._expire(self._now(), check), "expired")
        return self._result()

    def status(self, workflow, context, check):
        self._admit(workflow, context, check)
        _require(self._config is not None, "not_found")
        if not self._expire(self._now(), check):
            if self._record is not None:
                self._verify(check)
            else:
                _require(not self._uncertain, "reconciliation_required")
            self._expire(self._now(), check)
        return self._result()

    def verify_active(self, workflow, context, check):
        value = self.status(workflow, context, check)
        _require(value["state"] == "active", "expired" if value["state"] == "expired" else "ap_unavailable")
        return value

    def apply_evidence(self, workflow, context, proof, check):
        self.verify_active(workflow, context, check)
        try:
            value = self.adapter.apply_evidence(self._record, context.copy(), proof, check)
            check()
            _require(type(value) is dict and set(value) == {"gate", "country", "radio"}, "unavailable")
            _require(not self._expire(self._now(), check), "expired")
            return copy.deepcopy(value)
        except Exception as error:
            raise self._failure(error) from None

    def stop(self, workflow, context, check):
        self._admit(workflow, context, check)
        _require(self._config is not None, "not_found")
        expired = self._state == "expired" or self._clock_invalid
        if not expired:
            try:
                expired = self._now() >= self._config["expires_boottime_ns"]
            except APError:
                # A broken clock must not prevent targeted cleanup. Its sticky
                # invalidation prevents any later activation on this instance.
                expired = True
        self._stop_owned(check)
        self._state = "expired" if expired else "stopped"
        return self._result()

    def expire_owned(self, check):
        _require(callable(check), "invalid_request")
        check()
        if self._config is not None:
            if self._clock_invalid:
                self._state = "expired"
                self._stop_owned(check)
                return True
            return self._expire(self._now(), check)
        return False

    def close(self, check):
        _require(callable(check), "invalid_request")
        check()
        self._stop_owned(check)
        self._closed = True
        if self._state != "expired":
            self._state = "stopped"
        try:
            self.adapter.close(check)
        except Exception:
            raise APError("unavailable") from None
