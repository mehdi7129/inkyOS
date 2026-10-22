#!/usr/bin/python3.13
"""Pinned factory system setup; stdlib only, never imports application code.

Production entry has no flags or dependency injection. Fixtures require a
canonical non-/ root. Status reads never authorize/repeat a native effect.
"""

import copy
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import select
import signal
import socket
import stat
import sys
import threading
import time
import types
import uuid

SELF = "/usr/lib/inkyos/system-setup.py"
CONTRACT = "/usr/lib/inkyos/system-setup-contract.json"
NATIVE = "/usr/lib/inkyos/system-setup-native.py"
AP = "/usr/lib/inkyos/system-setup-ap.py"
AP_NATIVE = "/usr/lib/inkyos/system-setup-ap-native.py"
AP_POLICY = "/usr/lib/inkyos/softap-region.json"
GRAPH = "/usr/lib/inkyos/writer-graph.py"
POLICY = "/usr/lib/inkyos/time-policy.py"
STATE = "/var/lib/inkyos/system-setup"
SOCKET = "/run/inkyos-system-setup/control.sock"
POLICY_SHA = "68bde4a4ff166b4b2f945bc8dbf8664750cee4f43e3315d8b3e624075a5c7148"
CONTRACT_SHA = "e76001c8593f85eeacbf0e45b904301bc0afae129ba02ec3a5ee848b686dbddd"
LIMIT = 1024 * 1024


class Refused(ValueError):
    def __init__(self, reason="unavailable"):
        self.reason = reason
        super().__init__(reason)


def require(value, reason="unavailable"):
    if not value:
        raise Refused(reason)


def canonical(value):
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sealed(value):
    return {**value, "record_sha256": digest(value)}


def stable(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def verify_seal(value):
    require(
        type(value) is dict
        and value.get("record_sha256")
        == digest({key: item for key, item in value.items() if key != "record_sha256"})
    )


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "invalid_request")
        result[key] = value
    return result


def integer(token):
    require(re.fullmatch(r"0|-?[1-9][0-9]*", token) is not None, "invalid_request")
    return int(token)


def bad_number(_):
    raise Refused("invalid_request")


def decode(raw, limit=8192):
    require(
        type(raw) is bytes
        and 0 < len(raw) <= limit
        and raw.endswith(b"\n")
        and b"\n" not in raw[:-1],
        "invalid_request",
    )
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique,
            parse_int=integer,
            parse_float=bad_number,
            parse_constant=bad_number,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise Refused("invalid_request") from None


class Schema:
    """Only the closed vocabulary used by the frozen reviewed contract."""

    def __init__(self, value):
        self.value = value

    def check(self, value, schema):
        if "$ref" in schema:
            require(schema["$ref"].startswith("#/$defs/"), "invalid_request")
            return self.check(value, self.value["$defs"][schema["$ref"].split("/")[-1]])
        if "oneOf" in schema:
            matches = 0
            for option in schema["oneOf"]:
                try:
                    self.check(value, option)
                    matches += 1
                except Refused:
                    pass
            require(matches == 1, "invalid_request")
            return
        if "const" in schema:
            require(
                type(value) is type(schema["const"]) and value == schema["const"],
                "invalid_request",
            )
        if "enum" in schema:
            require(
                any(
                    type(value) is type(item) and value == item
                    for item in schema["enum"]
                ),
                "invalid_request",
            )
        kind = schema.get("type")
        if kind:
            require(
                type(value)
                is {
                    "object": dict,
                    "array": list,
                    "string": str,
                    "integer": int,
                    "null": type(None),
                    "boolean": bool,
                }[kind],
                "invalid_request",
            )
        if kind == "object":
            require(
                set(value) == set(schema["properties"]) == set(schema["required"])
                and schema["additionalProperties"] is False,
                "invalid_request",
            )
            for key, item in value.items():
                self.check(item, schema["properties"][key])
        elif kind == "string":
            if "pattern" in schema:
                require(
                    re.fullmatch(schema["pattern"], value) is not None,
                    "invalid_request",
                )
            if schema.get("format") == "ipv4":
                try:
                    require(
                        str(ipaddress.IPv4Address(value)) == value, "invalid_request"
                    )
                except ipaddress.AddressValueError:
                    raise Refused("invalid_request") from None
        elif kind == "integer":
            for key, test in (
                ("minimum", lambda a, b: a >= b),
                ("maximum", lambda a, b: a <= b),
                ("exclusiveMaximum", lambda a, b: a < b),
            ):
                if key in schema:
                    require(test(value, schema[key]), "invalid_request")
        elif kind == "array":
            require(
                schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", 1024),
                "invalid_request",
            )
            if schema.get("uniqueItems"):
                require(
                    len({canonical(item) for item in value}) == len(value),
                    "invalid_request",
                )
            for item in value:
                self.check(item, schema["items"])

    def named(self, value, name):
        self.check(value, self.value["$defs"][name])
        return value

    def request(self, raw):
        value = decode(raw)
        require(
            type(value) is dict
            and type(value.get("op")) is str
            and value["op"] in self.value["request_schemas"],
            "invalid_request",
        )
        self.check(value, self.value["request_schemas"][value["op"]])
        return value


class Journal:
    """One bounded root-owned workflow; atomic file, process lock held throughout."""

    def __init__(self, directory, schema, *, _root=None):
        if _root is None:
            require(
                str(directory) == STATE
                and sys.platform == "linux"
                and os.geteuid() == 0
            )
            self.uid = self.gid = 0
        else:
            root = Path(_root)
            require(
                root.is_absolute()
                and root != Path("/")
                and root == root.resolve(strict=True)
                and Path(directory).is_relative_to(root)
            )
            self.uid, self.gid = os.geteuid(), os.getegid()
        self.schema, self.lock = schema, threading.RLock()
        self.parent = self.fd = None
        self.directory = Path(directory)
        # Every production ancestor is root-owned and opened without symlinks.
        # Fixture trust starts at its explicit canonical non-/ root.
        base = Path("/") if _root is None else Path(_root)
        self.parent = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for part in self.directory.relative_to(base).parts:
            info = os.fstat(self.parent)
            require(
                (info.st_uid, info.st_gid) == (self.uid, self.gid)
                and not stat.S_IMODE(info.st_mode) & 0o7022
                and not os.listxattr(self.parent)
            )
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.parent
            )
            os.close(self.parent)
            self.parent = child
        self._metadata(self.parent, 0o700, directory=True)
        self.parent_identity = (
            os.fstat(self.parent).st_dev,
            os.fstat(self.parent).st_ino,
        )
        self.fd = os.open(
            "lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
            dir_fd=self.parent,
        )
        self._metadata(self.fd, 0o600)
        require(os.fstat(self.fd).st_size == 0)
        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        entries = set(os.listdir(self.parent))
        require(entries <= {"lock", "journal.json"})
        self.data = {
            "version": 1,
            "workflow": None,
            "challenges": [],
            "operations": [],
            "completion": None,
            "completions": [],
            "network_head": None,
        }
        if "journal.json" in entries:
            fd = os.open(
                "journal.json",
                os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
                dir_fd=self.parent,
            )
            try:
                self._metadata(fd, 0o600)
                before = os.fstat(fd)
                raw = os.read(fd, LIMIT + 1)
                require(
                    before.st_size == len(raw) <= LIMIT
                    and stable(os.fstat(fd)) == stable(before)
                )
                self.data = decode(raw, LIMIT)
                require(canonical(self.data) == raw)
                self.validate()
            finally:
                os.close(fd)
        # An interrupted effect is never replayed. Recovery is a new owner op.
        changed = False
        for operation in self.data["operations"]:
            if operation["state"] == "pending":
                operation["state"] = "uncertain"
                changed = True
        if changed:
            self.save()

    def _metadata(self, fd, mode, directory=False):
        info = os.fstat(fd)
        require(
            (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
            == (self.uid, self.gid, mode)
            and (directory or info.st_nlink == 1)
            and not os.listxattr(fd)
        )

    def validate(self):
        data = self.data
        require(
            type(data) is dict
            and set(data)
            == {
                "version",
                "workflow",
                "challenges",
                "operations",
                "completion",
                "completions",
                "network_head",
            }
            and type(data["version"]) is int
            and data["version"] == 1
        )
        if data["workflow"] is not None:
            self.schema.named(data["workflow"], "Workflow")
        require(
            type(data["challenges"]) is list
            and type(data["operations"]) is list
            and len(data["operations"]) <= 64
            and len(data["challenges"]) <= 64
        )
        ids, sessions = set(), set()
        for challenge in data["challenges"]:
            self.schema.named(challenge, "Challenge")
            require(
                challenge["operation_id"] not in ids
                and challenge["binding"]["session_id"] not in sessions
            )
            ids.add(challenge["operation_id"])
            sessions.add(challenge["binding"]["session_id"])
            require(workflow(challenge["binding"]) == data["workflow"])
        operations = set()
        for operation in data["operations"]:
            self.schema.named(operation, "Operation")
            require(
                operation["operation_id"] in ids
                and operation["operation_id"] not in operations
                and workflow(operation["binding"]) == data["workflow"]
            )
            operations.add(operation["operation_id"])
            if operation["receipt"] is not None:
                receipt = operation["receipt"]
                verify_seal(receipt)
                require(
                    receipt["binding"] == operation["binding"]
                    and receipt["operation_id"] == operation["operation_id"]
                    and receipt["request_sha256"] == operation["request_sha256"]
                    and operation["state"] in {"effects_completed", "superseded"}
                )
        require(type(data["completions"]) is list and len(data["completions"]) <= 64)
        completed_ids, completed_operations = set(), set()
        initial_publication = None
        for completion in data["completions"]:
            self.schema.named(completion, "Completion")
            verify_seal(completion)
            require(
                completion["workflow"] == data["workflow"]
                and completion["operation_id"] in operations
                and completion["completion_id"] not in completed_ids
                and completion["operation_id"] not in completed_operations
            )
            completed_ids.add(completion["completion_id"])
            completed_operations.add(completion["operation_id"])
            operation = self.operation(completion["operation_id"])
            require(
                operation["receipt"] is not None
                and completion["effect_receipt_sha256"]
                == operation["receipt"]["record_sha256"]
            )
            if initial_publication is None:
                initial_publication = completion["publication"]
            require(completion["publication"] == initial_publication)
        require(
            data["completion"]
            == (data["completions"][-1] if data["completions"] else None)
        )
        if data["network_head"] is not None:
            head = self.schema.named(data["network_head"], "NetworkHead")
            verify_seal(head)
            require(
                data["completion"] is not None
                and head["completion_id"] == data["completion"]["completion_id"]
                and head["country"] == data["completion"]["country"]
            )

    def check(self):
        self._metadata(self.parent, 0o700, directory=True)
        info = self.directory.lstat()
        require(
            (info.st_dev, info.st_ino) == self.parent_identity
            and stat.S_ISDIR(info.st_mode)
        )
        self._metadata(self.fd, 0o600)
        require(
            stable(os.fstat(self.fd))
            == stable(os.stat("lock", dir_fd=self.parent, follow_symlinks=False))
            and set(os.listdir(self.parent)) <= {"lock", "journal.json"}
        )

    def save(self):
        with self.lock:
            self.check()
            self.validate()
            raw = canonical(self.data)
            require(len(raw) <= LIMIT)
            name = "pending-" + secrets.token_hex(16)
            fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=self.parent,
            )
            try:
                self._metadata(fd, 0o600)
                view = memoryview(raw)
                while view:
                    view = view[os.write(fd, view) :]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(
                name, "journal.json", src_dir_fd=self.parent, dst_dir_fd=self.parent
            )
            os.fsync(self.parent)
            fd = os.open(
                "journal.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.parent
            )
            try:
                self._metadata(fd, 0o600)
                require(os.read(fd, LIMIT + 1) == raw)
            finally:
                os.close(fd)

    def operation(self, identifier):
        return next(
            (
                item
                for item in self.data["operations"]
                if item["operation_id"] == identifier
            ),
            None,
        )

    def challenge(self, identifier):
        return next(
            (
                item
                for item in self.data["challenges"]
                if item["operation_id"] == identifier
            ),
            None,
        )

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.parent is not None:
            os.close(self.parent)
            self.parent = None


def workflow(binding):
    return {
        key: binding[key]
        for key in (
            "initialization_intent",
            "initialization_receipt_digest",
            "frame_id",
            "spki_sha256",
        )
    }


class Session:
    def __init__(self, connection, proof, stopping=None):
        self.connection, self.proof, self.binding = connection, proof, None
        self.stopping = stopping

    def check(self):
        require(self.stopping is None or not self.stopping.is_set(), "session_closed")
        self.proof.check()
        require(self.stopping is None or not self.stopping.is_set(), "session_closed")
        readable, _, _ = select.select([self.connection], [], [], 0)
        if readable:
            require(
                self.connection.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT) != b"",
                "session_closed",
            )

    def read_check(self):
        """Continuity during bounded readbacks, never admission for an effect.

        Full Graph.check still runs at operation boundaries and immediately
        before/after each native effect. Read-only D-Bus/polling steps only need
        the live connection/stopping flag and the already owned graph state.
        Graph's lock makes the ACTIVE observation atomic with invalidation.
        """
        require(self.stopping is None or not self.stopping.is_set(), "session_closed")
        with self.proof._lock:
            require(self.proof.state == "ACTIVE", "session_closed")
        readable, _, _ = select.select([self.connection], [], [], 0)
        if readable:
            require(
                self.connection.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT) != b"",
                "session_closed",
            )
        require(self.stopping is None or not self.stopping.is_set(), "session_closed")
        with self.proof._lock:
            require(self.proof.state == "ACTIVE", "session_closed")


class Setup:
    def __init__(
        self, journal, native, policy, schema, *, ap_controller=None, _root=None
    ):
        if _root is None:
            require(
                Path(__file__) == Path(SELF)
                and type(native).__name__ == "Native"
                and ap_controller is not None
            )
        else:
            root = Path(_root)
            require(
                root.is_absolute()
                and root != Path("/")
                and root == root.resolve(strict=True)
            )
        self.journal, self.native, self.policy, self.schema = (
            journal,
            native,
            policy,
            schema,
        )
        self.ap = ap_controller
        self.ap_radio_prepared = False
        self.effects = threading.Lock()
        self.live_country = self.live_radio = self.live_clock = None

    def context(self, session):
        return session.proof.observed_context()

    def checked_workflow(self, value):
        self.native.consumed(value)
        existing = self.journal.data["workflow"]
        require(existing is None or existing == value, "conflict")

    def _ap_check(self, session, *, deadline=None):
        def budget():
            if deadline is not None:
                require(self.native.boottime() < deadline, "effect_uncertain")

        def check():
            session.check()
            self.journal.check()
            budget()

        def read_check():
            # Fixtures/other callbacks without the narrow seam stay strict.
            reader = getattr(session, "read_check", None)
            if not callable(reader):
                return check()
            reader()
            self.journal.check()
            budget()

        check.read_check = read_check
        return check

    def ap_request(self, session, op, args):
        """Secrets cross only an already attested per-peer main_guard connection.

        Start/status are transport recovery only and require the real consumed
        workflow plus current observed main context even after adoption. They
        grant no ownership, publication or factory claim authority. Stop after
        adoption requires a current matching owner/claim/epoch binding.
        """
        require(self.ap is not None, "unavailable")
        value = args["workflow"]
        require(self.effects.acquire(blocking=False), "conflict")
        try:
            check = self._ap_check(session)
            check()
            with self.journal.lock:
                self.checked_workflow(value)
                if op == "setup.ap.stop" and self.journal.data["challenges"]:
                    # Start/status expose a transport only: the admitted main
                    # still authenticates the existing owner over that channel.
                    # Explicit stop after adoption remains current-owner bound.
                    first = self.journal.data["challenges"][0]["binding"]
                    require(
                        session.binding is not None
                        and workflow(session.binding) == value
                        and all(
                            session.binding[key] == first[key]
                            for key in ("owner_id", "claim_request_id")
                        )
                        and session.binding["credential_epoch"]
                        == self.journal.data["challenges"][-1]["binding"]["credential_epoch"],
                        "forbidden",
                    )
            check()
            context = self.context(session)
            initial = op == "setup.ap.start" and not self.ap_radio_prepared
            if initial:
                # Validate sticky BOOTTIME/entropy and reserve the one AP
                # identity before any native clock/country/radio effect.
                self.ap.reserve(value, context, check)
                # Only a fresh consumed factory workflow may cross the boot
                # WLAN gate. The region is pinned FR prototype policy, not a
                # default supplied by the phone. Only an independently
                # root-approved, currently inactive station profile is allowed.
                gate = self.native.gate(context)
                self.schema.named(gate, "Gate")
                self.native.inventory(session.proof)
                check()
                self.ap.adapter.preflight(check)
                check()
                try:
                    country = self.native.country("FR", check)
                    self.schema.named(country, "Country")
                    check()
                    self.native.inventory(session.proof)
                    check()
                    radio = self.native.enable_wlan(country, check)
                    self.schema.named(radio, "Radio")
                    check()
                    result = self.ap.start(value, context, check)
                    self.schema.named(result, "APState")
                    check()
                    self.ap_radio_prepared = True
                    return result
                except BaseException:
                    self._close_initial_ap(value, context, session.proof)
                    raise
            result = getattr(self.ap, op.rsplit(".", 1)[-1])(
                value, context, check
            )
            self.schema.named(result, "APState")
            check()
            return result
        finally:
            self.effects.release()

    def _close_initial_ap(self, value, context, proof):
        # Retain the lease until targeted AP cleanup and positive observation.
        # Enabling WLAN can auto-connect an approved saved station before the
        # AP activation. Preserve that proven LAN instead of cutting it down.
        while True:
            try:
                if self.ap.has_started:
                    self.ap.stop(value, context, self.journal.check)
                try:
                    self.ap.adapter.preflight(self.journal.check)
                except Exception:
                    observation = self.native.network_latest(proof)
                    self.schema.named(observation, "NetworkObservation")
                    self.native.check_network(observation, ready=True)
                    return
                self.native.close_wlan()
                return
            except Exception:
                # Unknown activity or cleanup stays owned and is never turned
                # into an authorization to disconnect somebody else's link.
                time.sleep(0.05)

    def expire_ap(self):
        # The process-wide writer_guard remains owned. Expiry admits no new
        # effect: only targeted cleanup of an already owned AP is allowed.
        if self.ap is not None and self.effects.acquire(blocking=False):
            try:
                self.ap.expire_owned(self.journal.check)
            finally:
                self.effects.release()

    def close_ap(self):
        # A failed/blocked close must retain the writer lease until readback.
        if self.ap is not None:
            with self.effects:
                while True:
                    try:
                        self.ap.close(self.journal.check)
                        break
                    except Exception:
                        time.sleep(0.05)

    def _ap_evidence(self, session, check):
        require(self.ap is not None, "unavailable")
        evidence = self.ap.apply_evidence(
            workflow(session.binding), self.context(session), session.proof, check
        )
        require(type(evidence) is dict and set(evidence) == {"gate", "country", "radio"})
        for key, name in (("gate", "Gate"), ("country", "Country"), ("radio", "Radio")):
            self.schema.named(evidence[key], name)
        require(evidence["country"]["requested_country"] == "FR", "country_unconfirmed")
        return evidence

    def live(self, session):
        context = self.context(session)
        country, radio = self.live_country, self.live_radio
        closed = False
        try:
            if country and radio:
                country, radio = self.native.observe_live(country, radio)
                self.schema.named(country, "Country")
                self.schema.named(radio, "Radio")
            else:
                closed = self.native.closed(context)
        except Exception:
            country = radio = None
        network = None
        try:
            if radio:
                network = self.native.network_latest(session.proof)
                self.schema.named(network, "NetworkObservation")
                self.native.check_network(network, ready=False)
        except Exception:
            network = None
        origin = self.native.origin() if radio else None
        return {
            **{
                key: context[key]
                for key in ("boot_id", "candidate_sha256", "context_sha256")
            },
            "readiness": (
                "network_ready"
                if network
                and network["ipv4"]
                and network["active_profile_uuid"] == network["profile_uuid"]
                else "country_radio_ready"
                if radio
                else "wlan_closed"
                if closed
                else "unavailable"
            ),
            "clock_status": "owner_asserted_current_boot"
            if self.live_clock
            else "not_attested_current_boot",
            "country_receipt_sha256": digest(country) if country else None,
            "radio_receipt_sha256": digest(radio) if radio else None,
            "https_origin": origin,
            "origin_status": "avahi_current" if origin else "unavailable",
            "network": network,
        }

    def snapshot(self, session, value):
        self.checked_workflow(value)
        with self.journal.lock:
            data = copy.deepcopy(self.journal.data)
        latest = data["challenges"][-1]["operation_id"] if data["challenges"] else None
        operation = next(
            (item for item in data["operations"] if item["operation_id"] == latest),
            None,
        )
        return {
            "workflow": value,
            "state": "completed"
            if data["completion"]
            and operation
            and data["completion"]["operation_id"] == operation["operation_id"]
            else operation["state"]
            if operation
            else "challenged"
            if latest
            else "not_started",
            "latest_operation_id": latest,
            "operation": operation,
            "completion": data["completion"],
            "live": self.live(session),
            "network_head": data["network_head"],
        }

    def handle(self, session, request):
        session.check()
        self.journal.check()
        op, args = request["op"], request["args"]
        if op in {"setup.ap.start", "setup.ap.status", "setup.ap.stop"}:
            return self.ap_request(session, op, args)
        if op == "setup.open":
            require(session.binding is None, "conflict")
            self.checked_workflow(workflow(args["binding"]))
            with self.journal.lock:
                if self.journal.data["challenges"]:
                    first = self.journal.data["challenges"][0]["binding"]
                    require(
                        all(
                            args["binding"][key] == first[key]
                            for key in ("owner_id", "claim_request_id")
                        ),
                        "forbidden",
                    )
            session.binding = {**args["binding"], **self.context(session)}
            return {"binding": session.binding}
        if op == "setup.inspect":
            return self.snapshot(session, args["workflow"])
        if op == "setup.status":
            with self.journal.lock:
                operation = copy.deepcopy(self.journal.operation(args["operation_id"]))
                require(operation is not None, "not_found")
                completion, head = (
                    copy.deepcopy(self.journal.data["completion"]),
                    copy.deepcopy(self.journal.data["network_head"]),
                )
            return {
                "operation": operation,
                "completion": completion,
                "live": self.live(session),
                "network_head": head,
            }
        if op == "setup.resume":
            return self.resume(session, args["completion_id"])
        require(session.binding is not None, "forbidden")
        self.checked_workflow(workflow(session.binding))
        if op == "setup.challenge":
            return self.challenge(session, args)
        if op == "setup.apply":
            return self.apply(session, args)
        if op == "setup.complete":
            return self.complete(session, args)
        raise Refused("invalid_request")

    def challenge(self, session, args):
        session.check()
        require(self.effects.acquire(blocking=False), "conflict")
        try:
            with self.journal.lock:
                old = self.journal.challenge(args["operation_id"])
                if old:
                    require(
                        old["binding"] == session.binding
                        and old["supersedes_operation_id"]
                        == args["supersedes_operation_id"],
                        "conflict",
                    )
                    return copy.deepcopy(old)
                require(len(self.journal.data["challenges"]) < 64, "ledger_full")
                require(
                    not any(
                        item["binding"]["session_id"] == session.binding["session_id"]
                        for item in self.journal.data["challenges"]
                    ),
                    "conflict",
                )
                operations = self.journal.data["operations"]
                if operations:
                    previous = operations[-1]
                    require(
                        args["supersedes_operation_id"] == previous["operation_id"]
                        and previous["state"] in {"uncertain", "effects_completed"},
                        "conflict",
                    )
                    if self.ap is not None and self.ap.has_started:
                        # Recovery of AP setup preserves only a currently
                        # verified owned AP; it never reopens RF implicitly.
                        self._ap_evidence(session, self._ap_check(session))
                    else:
                        self.native.close_wlan()
                    self.live_country = self.live_radio = self.live_clock = None
                else:
                    require(args["supersedes_operation_id"] is None, "conflict")
                issued = self.native.boottime()
                value = {
                    **args,
                    "challenge_id": str(uuid.uuid4()),
                    "nonce": secrets.token_hex(32),
                    "issued_boottime_ns": issued,
                    "expires_boottime_ns": issued + 30_000_000_000,
                    "binding": session.binding,
                }
                self.journal.data["workflow"] = workflow(session.binding)
                self.journal.data["challenges"].append(value)
                self.journal.save()
                return copy.deepcopy(value)
        finally:
            self.effects.release()

    def apply(self, session, args):
        material = {
            "workflow": workflow(session.binding),
            **{
                key: session.binding[key]
                for key in ("owner_id", "claim_request_id", "credential_epoch")
            },
            **args,
        }
        request_hash = digest(material)
        with self.journal.lock:
            previous = self.journal.operation(args["operation_id"])
            if previous:
                require(previous["request_sha256"] == request_hash, "conflict")
                return copy.deepcopy(previous)
        require(self.effects.acquire(blocking=False), "conflict")
        admitted = False
        ap_mode = self.ap is not None and self.ap.has_started
        ap_context = ap_workflow = None
        try:
            with self.journal.lock:
                challenge = self.journal.challenge(args["operation_id"])
                require(
                    challenge
                    and challenge["binding"] == session.binding
                    and all(
                        challenge[key] == args[key]
                        for key in ("challenge_id", "nonce", "supersedes_operation_id")
                    ),
                    "conflict",
                )
                require(
                    self.policy.challenge_fresh(
                        challenge["issued_boottime_ns"], self.native.boottime()
                    ),
                    "challenge_expired",
                )
                require(len(self.journal.data["operations"]) < 64, "ledger_full")
                session.check()
                if ap_mode:
                    # Capture the original cleanup binding while admission is
                    # live; cleanup must not need a now disconnected peer.
                    ap_context = self.context(session)
                    ap_workflow = workflow(session.binding)
                    require(args["country"] == "FR", "country_unconfirmed")
                    evidence = self._ap_evidence(session, self._ap_check(session))
                    gate = evidence["gate"]
                else:
                    gate = self.native.gate(self.context(session))
                operation = {
                    "operation_id": args["operation_id"],
                    "state": "pending",
                    "request_sha256": request_hash,
                    "binding": session.binding,
                    "supersedes_operation_id": args["supersedes_operation_id"],
                    "receipt": None,
                }
                self.journal.data["operations"].append(operation)
                self.journal.save()  # Before the first effect.
                admitted = True
            deadline = self.native.boottime() + 45_000_000_000

            def check():
                session.check()
                require(self.native.boottime() < deadline, "effect_uncertain")

            if ap_mode:
                check = self._ap_check(session, deadline=deadline)
            check()
            clock = self.native.clock(args["utc_seconds"], self.policy)
            check()
            if ap_mode:
                # FR was explicitly prepared by the pinned prototype policy
                # before advertising the AP. Reattest the exact owned AP and
                # radio instead of toggling WLAN beneath the phone connection.
                evidence = self._ap_evidence(session, check)
                require(evidence["gate"] == gate, "effect_uncertain")
                country, radio = evidence["country"], evidence["radio"]
            else:
                self.native.inventory(session.proof)
                check()
                country = self.native.country(args["country"], check)
                check()
                self.native.inventory(session.proof)
                check()
                radio = self.native.enable_wlan(country, check)
            check()
            receipt = sealed(
                {
                    "schema_version": 1,
                    "operation_id": args["operation_id"],
                    "request_sha256": request_hash,
                    "binding": session.binding,
                    "gate": gate,
                    "clock": clock,
                    "country": country,
                    "radio": radio,
                }
            )
            with self.journal.lock:
                operation.update(state="effects_completed", receipt=receipt)
                if args["supersedes_operation_id"]:
                    old = self.journal.operation(args["supersedes_operation_id"])
                    require(old is not None)
                    old["state"] = "superseded"
                self.journal.save()
                self.live_clock, self.live_country, self.live_radio = (
                    clock,
                    country,
                    radio,
                )
                return copy.deepcopy(operation)
        except BaseException:
            if admitted:
                # Cleanup remains owned. A failed/blocked cleanup cannot release SH.
                while True:
                    try:
                        if ap_mode:
                            # Close only the owned AP. Never globally disable a
                            # station transaction that may have taken over.
                            self.ap.stop(
                                ap_workflow, ap_context, self.journal.check,
                            )
                        else:
                            self.native.close_wlan()
                        break
                    except Exception:
                        time.sleep(0.05)
                self.live_country = self.live_radio = self.live_clock = None
                with self.journal.lock:
                    operation.update(state="uncertain", receipt=None)
                    self.journal.save()
            raise
        finally:
            self.effects.release()

    def _network_head(self, completion, observation):
        previous = self.journal.data["network_head"]
        return sealed(
            {
                "completion_id": completion["completion_id"],
                "revision": 1 if previous is None else previous["revision"] + 1,
                "profile_uuid": observation["profile_uuid"],
                "network_transaction_id": observation["id"],
                "owner_id": observation["owner_id"],
                "country": completion["country"],
                "source_observation_sha256": observation["observation_sha256"],
                "updated_boot_id": observation["boot_id"],
            }
        )

    def complete(self, session, args):
        session.check()
        require(self.effects.acquire(blocking=False), "conflict")
        try:
            with self.journal.lock:
                operation = self.journal.operation(args["operation_id"])
                require(
                    operation
                    and operation["state"] in {"effects_completed", "superseded"}
                    and operation["receipt"],
                    "effect_uncertain",
                )
                require(
                    workflow(operation["binding"]) == workflow(session.binding)
                    and all(
                        operation["binding"][key] == session.binding[key]
                        for key in ("owner_id", "claim_request_id", "credential_epoch")
                    ),
                    "conflict",
                )
                publication = args["publication"]
                require(
                    all(
                        publication[key] == session.binding[key]
                        for key in ("frame_id", "spki_sha256")
                    ),
                    "publication_conflict",
                )
                initial = self.journal.operation(
                    publication["initial_setup_operation_id"]
                )
                require(
                    initial is not None
                    and initial["receipt"] is not None
                    and initial["state"] in {"effects_completed", "superseded"}
                    and workflow(initial["binding"]) == workflow(session.binding),
                    "publication_conflict",
                )
                for existing in self.journal.data["completions"]:
                    if existing["operation_id"] == args["operation_id"]:
                        require(
                            existing["publication"] == publication
                            and existing["initial_network_transaction_id"]
                            == args["network_transaction_id"],
                            "conflict",
                        )
                        return copy.deepcopy(existing)
                historical = self.journal.data["completion"]
                require(
                    historical is None or historical["publication"] == publication,
                    "publication_conflict",
                )
                require(len(self.journal.data["completions"]) < 64, "ledger_full")
                require(
                    self.journal.data["operations"][-1]["operation_id"]
                    == args["operation_id"],
                    "conflict",
                )
                # No historical receipt becomes a new current native grant.
                require(
                    operation["binding"]["boot_id"] == self.context(session)["boot_id"]
                    and self.live_radio,
                    "effect_uncertain",
                )
            observation = self.native.network_exact(
                args["network_transaction_id"],
                session.binding["owner_id"],
                session.proof,
            )
            self.schema.named(observation, "NetworkObservation")
            self.native.check_network(observation, ready=True)
            session.check()
            completion = sealed(
                {
                    "completion_id": str(uuid.uuid4()),
                    "workflow": workflow(session.binding),
                    **{
                        key: session.binding[key]
                        for key in ("owner_id", "claim_request_id", "credential_epoch")
                    },
                    "operation_id": args["operation_id"],
                    "effect_receipt_sha256": operation["receipt"]["record_sha256"],
                    "publication": publication,
                    "initial_profile_uuid": observation["profile_uuid"],
                    "initial_network_transaction_id": observation["id"],
                    "country": operation["receipt"]["country"]["requested_country"],
                    "created_boot_id": self.context(session)["boot_id"],
                }
            )
            with self.journal.lock:
                self.journal.data["completion"] = completion
                self.journal.data["completions"].append(completion)
                self.journal.data["network_head"] = self._network_head(
                    completion, observation
                )
                self.journal.save()
            return copy.deepcopy(completion)
        finally:
            self.effects.release()

    def resume(self, session, identifier):
        session.check()
        require(self.effects.acquire(blocking=False), "conflict")
        try:
            with self.journal.lock:
                completion = copy.deepcopy(self.journal.data["completion"])
                require(
                    completion and completion["completion_id"] == identifier,
                    "not_found",
                )
            self.checked_workflow(completion["workflow"])
            if self.live_radio:
                return {
                    "completion": completion,
                    "live": self.live(session),
                    "network_head": copy.deepcopy(self.journal.data["network_head"]),
                }
            self.native.gate(self.context(session))
            try:
                observation = self.native.network_latest(session.proof)
                self.schema.named(observation, "NetworkObservation")
                self.native.check_network(observation, ready=False)
                self.native.inventory(session.proof)
                session.check()
                country = self.native.country(completion["country"], session.check)
                session.check()
                self.native.inventory(session.proof)
                session.check()
                radio = self.native.enable_wlan(country, session.check)
                session.check()
                self.live_country, self.live_radio, self.live_clock = (
                    country,
                    radio,
                    None,
                )
                # A new network is accepted only from the actual latest committed helper record.
                with self.journal.lock:
                    self.journal.data["network_head"] = self._network_head(
                        completion, observation
                    )
                    self.journal.save()
            except Exception:
                while True:
                    try:
                        self.native.close_wlan()
                        break
                    except Exception:
                        time.sleep(0.05)
                self.live_country = self.live_radio = self.live_clock = None
            return {
                "completion": completion,
                "live": self.live(session),
                "network_head": copy.deepcopy(self.journal.data["network_head"]),
            }
        finally:
            self.effects.release()


def load_pinned(graph, path, *, expected=None, json_data=False):
    runtime, contract = graph.runtime, graph.contract
    _, _, support, records = runtime.inventories(contract)
    relative = path[1:]
    require(relative in support["paths"] and relative in records)
    with contract.tree() as tree:
        runtime.check_path(tree, relative, records)
        raw = tree.read(relative, 0o444 if json_data else 0o555, LIMIT)
    if expected:
        require(hashlib.sha256(raw).hexdigest() == expected)
    if json_data:
        return json.loads(raw, object_pairs_hook=unique)
    module = types.ModuleType("inkyos_" + Path(path).stem.replace("-", "_"))
    module.__file__ = path
    exec(compile(raw, path, "exec"), module.__dict__)
    return module


def verify_socket_parent(runtime, contract):
    relative = "run/inkyos-system-setup"
    with contract.tree() as tree:
        raw = tree.read("run/inkyos-writer-parents/parents.json", 0o644, 4096)
        receipt = json.loads(raw, object_pairs_hook=unique)
    current = runtime.validate_context(contract)
    require(
        all(
            receipt[key] == current[key]
            for key in ("version", "boot_id", "candidate_sha256")
        )
    )
    fd = os.open("/" + relative, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        expected = {
            "dev": info.st_dev,
            "ino": info.st_ino,
            "uid": 0,
            "gid": contract.manifest["provisioning_gid"],
            "mode": "0750",
        }
        require(
            receipt["parents"][relative] == expected
            and info.st_uid == 0
            and info.st_gid == expected["gid"]
            and stat.S_IMODE(info.st_mode) == 0o750
            and not os.listxattr(fd)
            and os.listdir(fd) == []
        )
    finally:
        os.close(fd)


def notify_ready():
    address = os.environ.pop("NOTIFY_SOCKET", None)
    require(
        type(address) is str
        and 1 < len(address.encode("utf-8")) <= 107
        and address[0] in "/@"
        and not any(ord(char) < 32 or ord(char) == 127 for char in address)
    )
    if address[0] == "@":
        address = "\0" + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notification:
        notification.settimeout(2)
        require(notification.sendto(b"READY=1", address) == len(b"READY=1"))


def serve(journal, setup, schema, graph_module, stopping):
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connections = set()
    threads = set()
    lock = threading.Lock()
    # Runtime parent is already provisioned by trusted prepare-boot, never adopted here.
    require(not Path(SOCKET).exists())
    listener.bind(SOCKET)
    import grp

    os.chown(SOCKET, -1, grp.getgrnam("inky-provisioning").gr_gid)
    os.chmod(SOCKET, 0o660)
    listener.listen(8)
    listener.settimeout(0.25)
    notify_ready()

    def client(connection):
        proof = graph_module.open_setup()
        try:
            with proof:
                with proof.main_guard(connection):
                    session = Session(connection, proof, stopping)
                    stream = connection.makefile("rb")
                    try:
                        while not stopping.is_set():
                            raw = stream.readline(8193)
                            if not raw:
                                break
                            request = None
                            try:
                                request = schema.request(raw)
                                result = setup.handle(session, request)
                                reply = {
                                    "v": 1,
                                    "id": request["id"],
                                    "ok": True,
                                    "result": result,
                                }
                                schema.check(
                                    reply,
                                    schema.value["success_response_schemas"][
                                        request["op"]
                                    ],
                                )
                            except Exception as error:
                                reason = getattr(error, "reason", "unavailable")
                                if (
                                    reason
                                    not in schema.value["error_response_schema"][
                                        "properties"
                                    ]["error"]["enum"]
                                ):
                                    reason = "unavailable"
                                reply = {
                                    "v": 1,
                                    "id": request["id"] if request else None,
                                    "ok": False,
                                    "error": reason,
                                }
                            encoded = canonical(reply)
                            require(len(encoded) <= 16384)
                            connection.sendall(encoded)
                            if request is None:
                                break
                    finally:
                        stream.close()
        except Exception:
            pass
        finally:
            connection.close()
            while proof.state != "CLOSED":
                try:
                    proof.close()
                except Exception:
                    time.sleep(0.05)
            with lock:
                threads.discard(threading.current_thread())
                connections.discard(connection)

    try:
        while not stopping.is_set():
            setup.expire_ap()
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            with lock:
                if len(threads) >= 8:
                    connection.close()
                    continue
                thread = threading.Thread(
                    target=client, args=(connection,), daemon=False
                )
                threads.add(thread)
                connections.add(connection)
                thread.start()
    finally:
        listener.close()
        with lock:
            for connection in connections:
                try:
                    connection.shutdown(socket.SHUT_RD)
                except OSError:
                    pass
        # Shut read admission without cancelling already admitted effects.
        while True:
            with lock:
                owned = tuple(threads)
            if not owned:
                break
            for thread in owned:
                thread.join(0.1)


def read_fixed(path, mode, limit):
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in Path(path).parts[1:-1]:
            fd = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
            )
            os.close(parent)
            parent = fd
            info = os.fstat(parent)
            require(
                (info.st_uid, info.st_gid) == (0, 0)
                and not stat.S_IMODE(info.st_mode) & 0o7022
                and not os.listxattr(parent)
            )
        name = Path(path).name
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(
            stat.S_ISREG(info.st_mode)
            and stat.S_IMODE(info.st_mode) == mode
            and (info.st_uid, info.st_gid) == (0, 0)
            and info.st_nlink == 1
            and 0 <= info.st_size <= limit
        )
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
        try:
            stable = lambda value: (
                value.st_dev,
                value.st_ino,
                value.st_mode,
                value.st_uid,
                value.st_gid,
                value.st_nlink,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )
            require(stable(os.fstat(fd)) == stable(info) and not os.listxattr(fd))
            raw = os.read(fd, limit + 1)
            require(
                len(raw) == info.st_size
                and stable(os.fstat(fd)) == stable(info)
                and stable(os.stat(name, dir_fd=parent, follow_symlinks=False))
                == stable(info)
            )
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def main():
    require(
        Path(__file__) == Path(SELF)
        and sys.argv == [SELF]
        and sys.platform == "linux"
        and sys.flags.isolated
        and sys.dont_write_bytecode
        and os.geteuid() == 0
    )
    # Bootstrap trust is identical to graph's pinned installed runtime bootstrap.
    # Read the runtime from the launcher's already verified root-only support graph.
    launcher_path = "/usr/lib/inkyos/writer-launcher.py"
    namespace = {"__file__": launcher_path, "__name__": "inkyos_setup_launcher"}
    # Bootstrap reader is loaded from the exact pinned three-module manifest.
    manifest = json.loads(
        read_fixed("/etc/inkyos/factory-runtime-v1.json", 0o644, 16384),
        object_pairs_hook=unique,
    )
    launcher_raw = read_fixed(launcher_path, 0o555, LIMIT)
    require(
        hashlib.sha256(launcher_raw).hexdigest()
        == manifest["os_module_pins"]["writer-launcher.py"]
    )
    exec(compile(launcher_raw, launcher_path, "exec"), namespace)
    runtime = namespace["installed_runtime"]()
    contract = runtime.load_contract()
    sources = types.SimpleNamespace(runtime=runtime, contract=contract)
    graph_module = load_pinned(sources, GRAPH)
    schema = Schema(
        load_pinned(sources, CONTRACT, expected=CONTRACT_SHA, json_data=True)
    )
    policy = load_pinned(sources, POLICY, expected=POLICY_SHA)
    native_module = load_pinned(sources, NATIVE)
    ap_module = load_pinned(sources, AP)
    ap_native_module = load_pinned(sources, AP_NATIVE)
    ap_policy = load_pinned(sources, AP_POLICY, json_data=True)
    stopping = threading.Event()
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, lambda *_: stopping.set())
    # Fresh admission held even before main exists; graph binding is per incoming peer.
    with runtime.writer_guard("setup"):
        journal = Journal(STATE, schema)
        setup = None
        try:
            native = native_module.Native(runtime, contract)
            ap_native = ap_native_module.NativeAP(native)
            ap_controller = ap_module.Controller(
                ap_native, ap_policy, boottime_ns=native.boottime
            )
            setup = Setup(journal, native, policy, schema, ap_controller=ap_controller)
            verify_socket_parent(runtime, contract)
            serve(journal, setup, schema, graph_module, stopping)
        finally:
            if setup is not None:
                setup.close_ap()
            journal.close()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit(78) from None
