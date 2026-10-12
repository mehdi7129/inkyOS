"""Pure numeric fixtures; no clock, syscall, journal, or admission is exercised."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "bootstrap_time_policy_fixture", ROOT / "staging/bootstrap/time-policy.py",
)
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)


class IntegerSubclass(int):
    pass


BAD_INTEGERS = (True, False, 1.0, "1", b"1", None, IntegerSubclass(1))
UTC = 1_767_225_600
REQUESTED_NS = 1_767_225_600_000_000_000


class UTCAssertionTests(unittest.TestCase):
    def test_lower_bound_converts_exactly(self):
        self.assertEqual(policy.utc_nanoseconds(1_767_225_600),
                         1_767_225_600_000_000_000)

    def test_last_supported_second_converts_exactly(self):
        self.assertEqual(policy.utc_nanoseconds(4_102_444_799),
                         4_102_444_799_000_000_000)

    def test_range_is_half_open(self):
        for value in (1_767_225_599, 4_102_444_800, -(1 << 100), 1 << 100):
            with self.subTest(value=value), self.assertRaises(ValueError):
                policy.utc_nanoseconds(value)

    def test_conversion_rejects_coercible_and_subclass_types(self):
        for value in BAD_INTEGERS:
            with self.subTest(kind=type(value).__name__, value=value):
                with self.assertRaises(ValueError):
                    policy.utc_nanoseconds(value)


class ChallengeFreshnessTests(unittest.TestCase):
    def test_creation_and_last_nanosecond_are_fresh(self):
        self.assertTrue(policy.challenge_fresh(17, 17))
        self.assertTrue(policy.challenge_fresh(17, 30_000_000_016))

    def test_exact_deadline_and_later_are_expired(self):
        self.assertFalse(policy.challenge_fresh(17, 30_000_000_017))
        self.assertFalse(policy.challenge_fresh(17, 30_000_000_018))

    def test_receipt_delay_cannot_extend_creation_deadline(self):
        # A response arriving after twenty seconds still has only ten left.
        self.assertTrue(policy.challenge_fresh(100, 29_000_000_100))
        self.assertFalse(policy.challenge_fresh(100, 31_000_000_100))

    def test_elapsed_suspension_is_not_removed_from_supplied_numbers(self):
        self.assertFalse(policy.challenge_fresh(100, 60_000_000_100))

    def test_observation_before_creation_is_not_fresh(self):
        self.assertFalse(policy.challenge_fresh(100, 99))

    def test_both_observations_require_exact_nonnegative_integers(self):
        for position in (0, 1):
            for value in (*BAD_INTEGERS, -1):
                inputs = [10, 20]
                inputs[position] = value
                with self.subTest(position=position, kind=type(value).__name__, value=value):
                    with self.assertRaises(ValueError):
                        policy.challenge_fresh(*inputs)

    def test_large_monotonic_origin_preserves_single_nanosecond_boundary(self):
        origin = 1 << 100
        self.assertTrue(policy.challenge_fresh(origin, origin + 29_999_999_999))
        self.assertFalse(policy.challenge_fresh(origin, origin + 30_000_000_000))


class ReadbackTests(unittest.TestCase):
    def interval(self, realtime_ns, *, e0=10, e1=20, r0=30, r1=40):
        return policy.readback_error_interval(
            UTC, realtime_ns, e0=e0, e1=e1, r0=r0, r1=r1,
        )

    def within(self, realtime_ns, *, e0=10, e1=20, r0=30, r1=40):
        return policy.readback_within_tolerance(
            UTC, realtime_ns, e0=e0, e1=e1, r0=r0, r1=r1,
        )

    def test_error_interval_accounts_for_both_unknown_event_instants(self):
        self.assertEqual(self.interval(REQUESTED_NS + 220,
                                       e0=1_000, e1=1_010, r0=1_200, r1=1_250),
                         (-30, 30))

    def test_equal_bounds_are_valid_and_tolerance_edges_are_inclusive(self):
        for offset in (-2_000_000_000, 2_000_000_000):
            with self.subTest(offset=offset):
                self.assertTrue(self.within(REQUESTED_NS + offset,
                                            e0=50, e1=50, r0=50, r1=50))

    def test_upper_interval_edge_has_no_one_nanosecond_extra_margin(self):
        self.assertEqual(self.interval(REQUESTED_NS + 2_000_000_010),
                         (1_999_999_980, 2_000_000_000))
        self.assertTrue(self.within(REQUESTED_NS + 2_000_000_010))
        self.assertFalse(self.within(REQUESTED_NS + 2_000_000_011))

    def test_lower_interval_edge_has_no_one_nanosecond_extra_margin(self):
        self.assertEqual(self.interval(REQUESTED_NS - 1_999_999_970),
                         (-2_000_000_000, -1_999_999_980))
        self.assertTrue(self.within(REQUESTED_NS - 1_999_999_970))
        self.assertFalse(self.within(REQUESTED_NS - 1_999_999_971))

    def test_overlapping_interval_is_insufficient(self):
        self.assertEqual(self.interval(REQUESTED_NS + 1_000_000_000,
                                       e0=0, e1=0, r0=0, r1=4_000_000_000),
                         (-3_000_000_000, 1_000_000_000))
        self.assertFalse(self.within(REQUESTED_NS + 1_000_000_000,
                                     e0=0, e1=0, r0=0, r1=4_000_000_000))

    def test_interval_enclosing_the_whole_tolerance_is_inconclusive(self):
        self.assertFalse(self.within(REQUESTED_NS + 3_000_000_000,
                                     e0=0, e1=0, r0=0, r1=6_000_000_000))

    def test_each_adjacent_order_violation_refuses(self):
        for bounds in ((20, 10, 30, 40), (10, 30, 20, 40), (10, 20, 40, 30)):
            with self.subTest(bounds=bounds), self.assertRaises(ValueError):
                self.interval(REQUESTED_NS, **dict(zip(("e0", "e1", "r0", "r1"), bounds)))

    def test_readback_and_bounds_reject_coercion_and_negative_monotonic(self):
        for field in ("realtime_ns", "e0", "e1", "r0", "r1"):
            invalid = BAD_INTEGERS if field == "realtime_ns" else (*BAD_INTEGERS, -1)
            for value in invalid:
                values = dict(realtime_ns=REQUESTED_NS, e0=10, e1=20, r0=30, r1=40)
                values[field] = value
                with self.subTest(field=field, kind=type(value).__name__, value=value):
                    with self.assertRaises(ValueError):
                        policy.readback_error_interval(UTC, **values)

    def test_readback_does_not_bypass_utc_assertion_validation(self):
        for assertion in (*BAD_INTEGERS, 1_767_225_599, 4_102_444_800):
            with self.subTest(assertion=assertion), self.assertRaises(ValueError):
                policy.readback_within_tolerance(
                    assertion, REQUESTED_NS, e0=10, e1=20, r0=30, r1=40,
                )

    def test_single_nanosecond_error_survives_large_origins(self):
        origin = 1 << 100
        self.assertEqual(self.interval(REQUESTED_NS + 1,
                                       e0=origin, e1=origin, r0=origin, r1=origin),
                         (1, 1))
        self.assertEqual(self.interval(REQUESTED_NS - 1,
                                       e0=origin, e1=origin, r0=origin, r1=origin),
                         (-1, -1))

    def test_large_common_origin_cancels_without_float_rounding(self):
        origin = 1 << 100
        self.assertEqual(self.interval(REQUESTED_NS + 1_000,
                                       e0=origin, e1=origin + 10,
                                       r0=origin + 1_000, r1=origin + 1_010),
                         (-10, 10))

    def test_elapsed_time_is_observed_without_changing_the_assertion(self):
        self.assertEqual(self.interval(REQUESTED_NS + 1_000_000_000,
                                       e0=0, e1=1, r0=999_999_999, r1=1_000_000_000),
                         (0, 2))

    def test_negative_civil_readback_is_an_out_of_tolerance_observation(self):
        self.assertFalse(self.within(-1))


if __name__ == "__main__":
    unittest.main()
