#!/usr/bin/env python3
"""Inactive internal numeric helpers for the bootstrap UTC prototype.

These functions receive numbers only. They read no clock, perform no syscall,
and supply no admission or permission to a setter. Validated numbers do not
prove their CLOCK_BOOTTIME origin, a common timebase, owner authority, independent
UTC, or the current time. The returned error interval is an arithmetic result,
not a privileged receipt. No wire or installed interface is defined here.
"""
from __future__ import annotations


_MIN_UTC_SECONDS = 1_767_225_600
_MAX_UTC_SECONDS = 4_102_444_800
_NANOSECONDS_PER_SECOND = 1_000_000_000
_CHALLENGE_TTL_NS = 30_000_000_000
_READBACK_TOLERANCE_NS = 2_000_000_000


def _integer(value: int) -> int:
    if type(value) is not int:
        raise ValueError("An exact integer is required")
    return value


def _monotonic_integer(value: int) -> int:
    value = _integer(value)
    if value < 0:
        raise ValueError("A nonnegative monotonic observation is required")
    return value


def utc_nanoseconds(utc_seconds: int) -> int:
    """Convert the bounded assertion exactly, without transport compensation."""
    value = _integer(utc_seconds)
    if not _MIN_UTC_SECONDS <= value < _MAX_UTC_SECONDS:
        raise ValueError("UTC assertion is outside the prototype range")
    return value * _NANOSECONDS_PER_SECOND


def challenge_fresh(created_ns: int, observed_ns: int) -> bool:
    """Check elapsed numbers; creation provenance and one-use state are external.

    Equality with the expiry instant is expired. An observation before creation
    is not fresh. Neither a retry nor receipt arrival changes the creation value.
    """
    created = _monotonic_integer(created_ns)
    observed = _monotonic_integer(observed_ns)
    return created <= observed < created + _CHALLENGE_TTL_NS


def readback_error_interval(utc_seconds: int, realtime_ns: int, *,
                            e0: int, e1: int, r0: int, r1: int) -> tuple[int, int]:
    """Return possible error bounds from ordered, supplied observations only.

    e0/e1 enclose the proposed effect; r0/r1 enclose the readback. Arithmetic
    cannot prove that either event occurred or that observations share BOOTTIME.
    The readback remains distinct from the unchanged UTC assertion.
    """
    requested = utc_nanoseconds(utc_seconds)
    realtime = _integer(realtime_ns)
    bounds = tuple(_monotonic_integer(value) for value in (e0, e1, r0, r1))
    effect_start, effect_end, read_start, read_end = bounds
    if not effect_start <= effect_end <= read_start <= read_end:
        raise ValueError("Observation bounds are out of order")
    return (realtime - requested - (read_end - effect_start),
            realtime - requested - (read_start - effect_end))


def readback_within_tolerance(utc_seconds: int, realtime_ns: int, *,
                              e0: int, e1: int, r0: int, r1: int) -> bool:
    """Require the entire numeric error interval within inclusive +/-2 seconds.

    True is not clock freshness, independent UTC, effect success, or admission.
    Invalid numeric inputs raise ValueError; valid inconclusive bounds are False.
    """
    lower, upper = readback_error_interval(
        utc_seconds, realtime_ns, e0=e0, e1=e1, r0=r0, r1=r1,
    )
    return -_READBACK_TOLERANCE_NS <= lower and upper <= _READBACK_TOLERANCE_NS
