"""Pure fixtures for additional observer detail; no hardware or service access."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


detail = module("observer_detail_tests", ROOT / "scripts/detail-enrollment-observers.py")
panel = module("observer_detail_panel_tests", ROOT / "scripts/observe-test-panel.py")
radio = module("observer_detail_radio_tests", ROOT / "scripts/observe-test-radio.py")
V1_BYTES = (ROOT / "scripts/diagnose-enrollment-observers.py").read_bytes()


def firmware():
    country = struct.pack("<4si4s", b"FR\0\0", 1, b"FR\0\0") + bytes(8)
    return struct.pack("<HHH", 6, 1, 20) + bytes(2) + struct.pack("<HH", 24, 2) + country


def sample():
    return {"wiphy_index": 3, "firmware": firmware(),
            "regulatory": b"global\ncountry FR: DFS-ETSI\nphy#3 (custom)\ncountry 99: DFS-UNSET\n",
            "channels": b"Wiphy phy3\n\t\t* 2412 MHz [1] (20.0 dBm)\n"}


class ObserverDetailTests(unittest.TestCase):
    def test_v1_pin_required_before_compile_and_namespace_only_names_change(self):
        with patch("builtins.exec") as execute:
            with self.assertRaisesRegex(detail.DetailError, "v1_pin_invalid"):
                detail.compile_v1(V1_BYTES + b"\n")
            execute.assert_not_called()
        v1 = detail.compile_v1(V1_BYTES)
        self.assertEqual(v1["REPORT"], detail.REPORT)
        self.assertEqual(v1["CLAIM"], detail.CLAIM)
        self.assertEqual((ROOT / "scripts/diagnose-enrollment-observers.py").read_bytes(), V1_BYTES)
        self.assertIn("inkyos-test-enrollment.service", v1["MASKED"])

    def test_eeprom_exports_only_four_integers_and_boolean_never_pcb_or_timestamp(self):
        raw = struct.pack("<HHBBB22p", 600, 400, 6, 123, 26, b"SECRET_TIMESTAMP")
        result = detail.panel_detail(vars(panel), lambda: raw)
        self.assertEqual(result, {"error": "eeprom_unreviewed", "data": {"width": 600, "height": 400,
            "color_code": 6, "display_variant": 26, "reviewed_catalogue_match": False}})
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertNotIn("123", json.dumps(result))
        reviewed = struct.pack("<HHBBB22p", 600, 400, 6, 0, 25, b"IGNORED")
        reviewed_result = detail.panel_detail(vars(panel), lambda: reviewed)
        self.assertTrue(reviewed_result["data"]["reviewed_catalogue_match"])
        self.assertIsNone(reviewed_result["error"])

    def test_eeprom_failure_is_enum_only_and_no_catalogue_guess(self):
        result = detail.panel_detail(vars(panel), lambda: b"SECRET")
        self.assertEqual(result, {"error": "eeprom_invalid", "data": None})
        def failure():
            raise OSError("PRIVATE_PATH SECRET")
        self.assertEqual(detail.panel_detail(vars(panel), failure),
                         {"error": "observation_unavailable", "data": None})

    def test_global_only_regulatory_keeps_independent_firmware_and_channels(self):
        values = sample()
        values["regulatory"] = b"global\ncountry 00: DFS-UNSET\n"
        calls = []
        result = detail.radio_detail(vars(radio), lambda: calls.append(True) or values)
        self.assertEqual(calls, [True])
        self.assertEqual(result["firmware"]["data"], {"country_abbrev": "FR", "ccode": "FR", "revision": 1})
        self.assertEqual(result["regulatory"]["error"], "kernel_observation_invalid")
        self.assertEqual(result["regulatory"]["structure"]["global_header_count"], 1)
        self.assertEqual(result["regulatory"]["structure"]["mapped_phy_header_count"], 0)
        self.assertEqual(result["regulatory"]["structure"]["global_country"], "00")
        self.assertIsNotNone(result["channels"]["data"])
        self.assertFalse(result["firmware_tuple_qualified"])

    def test_channel_failure_keeps_kernel_and_drops_unknown_text(self):
        values = sample()
        values["channels"] = b"Wiphy phy3\n * 2412 MHz [1] (20.0 dBm) (no IR, SECRET_FLAG)\n"
        result = detail.radio_detail(vars(radio), lambda: values)
        self.assertIsNotNone(result["regulatory"]["data"])
        self.assertEqual(result["channels"]["error"], "kernel_observation_invalid")
        structure = result["channels"]["structure"]
        self.assertEqual(structure["unknown_flag_count"], 1)
        self.assertEqual(structure["known_flag_counts"]["no_ir"], 1)
        self.assertNotIn("SECRET", json.dumps(result))

    def test_invalid_firmware_does_not_discard_valid_kernel_or_channels(self):
        values = sample()
        values["firmware"] = b"SECRET"
        result = detail.radio_detail(vars(radio), lambda: values)
        self.assertEqual(result["firmware"]["error"], "firmware_response_invalid")
        self.assertIsNotNone(result["regulatory"]["data"])
        self.assertIsNotNone(result["channels"]["data"])
        self.assertNotIn("SECRET", json.dumps(result))

    def test_regulatory_summary_distinguishes_bad_headers_and_duplicate_country(self):
        raw = (b"country US: DFS-FCC\nglobal\ncountry FR: DFS-ETSI\ncountry FR: DFS-ETSI\n"
               b"phy#3 (SECRET_HEADER)\ncountry SECRET: SECRET\nphy#4 (self-managed)\ncountry 00: DFS-UNSET\n")
        result = detail.regulatory_structure(raw, 3)
        self.assertEqual(result["country_without_section_count"], 2)
        self.assertEqual(result["duplicate_country_count"], 1)
        self.assertEqual(result["malformed_country_count"], 1)
        self.assertEqual(result["malformed_phy_header_count"], 1)
        self.assertEqual(result["other_phy_header_count"], 1)
        self.assertEqual(result["mapped_phy_header_style"], "unrecognized")
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertNotIn("phy#", json.dumps(result))

    def test_channel_summary_counts_disabled_and_rejected_shapes_without_raw_ids(self):
        raw = (b"Wiphy phy3\nWiphy PRIVATE_IDENTIFIER\n"
               b" * 2412 MHz [1] (disabled)\n * 2412 MHz [2] (50.0 dBm) (no IR, no IR) (SECRET)\n"
               b" * 2417 MHz [2] (disabled) (passive scan)\n * 2422.5 MHz [3] (20.0 dBm)\n")
        result = detail.channel_structure(raw, 3)
        self.assertEqual(result["wiphy_header_count"], 2)
        self.assertEqual(result["mapped_header_count"], 1)
        self.assertEqual(result["disabled_rows"], 2)
        self.assertEqual(result["enabled_rows"], 1)
        self.assertEqual(result["duplicate_frequency_count"], 1)
        self.assertEqual(result["channel_frequency_mismatch_count"], 1)
        self.assertEqual(result["power_out_of_range_count"], 1)
        self.assertEqual(result["duplicate_flag_count"], 1)
        self.assertEqual(result["unknown_flag_count"], 1)
        self.assertEqual(result["multiple_flag_groups_count"], 1)
        self.assertEqual(result["disabled_with_flags_count"], 1)
        self.assertEqual(result["noninteger_frequency_count"], 1)
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertNotIn("SECRET", json.dumps(result))

    def test_garbage_and_oversized_numbers_do_not_escape_or_leak(self):
        for raw in (b"\xffSECRET", b"x" * (detail.MAX_OUTPUT + 1), None):
            for summary in (detail.regulatory_structure, detail.channel_structure):
                result = summary(raw, 3)
                self.assertFalse(result["input_valid"])
                self.assertNotIn("SECRET", json.dumps(result))
        huge = b" * " + b"9" * 5000 + b" MHz [1] (20.0 dBm)\n"
        self.assertEqual(detail.channel_structure(huge, 3)["noninteger_frequency_count"], 1)
        huge_channel = b" * 2412 MHz [" + b"9" * 5000 + b"] (20.0 dBm)\n"
        self.assertEqual(detail.channel_structure(huge_channel, 3)["channel_frequency_mismatch_count"], 1)

    def test_zero_khz_offset_structure_matches_integer_rows_without_rounding(self):
        raw = (b"Wiphy phy3\n\t* 2412.0 MHz [1] (20.0 dBm)\n"
               b"\t* 2472.0 MHz [13] (disabled)\n\t* 2484.0 MHz [14] (disabled)\n")
        expected = detail.channel_structure(raw.replace(b".0 MHz", b" MHz"), 3)
        observed = detail.channel_structure(raw, 3)
        self.assertEqual(observed, expected)
        self.assertEqual(observed["noninteger_frequency_count"], 0)
        self.assertEqual(observed["rows_2_4ghz_count"], 3)
        self.assertEqual(observed["enabled_rows"], 1)
        self.assertEqual(observed["disabled_rows"], 2)
        duplicate = raw + b"\t* 2412 MHz [1] (20.0 dBm)\n"
        self.assertEqual(detail.channel_structure(duplicate, 3)["duplicate_frequency_count"], 1)

    def test_structure_rejects_nonzero_offsets_and_malformed_frequency_tokens(self):
        tokens = (b"2412.1", b"2412.100", b"2412.00", b"2412.", b"2412.0.0", b"+2412",
                  b"-2412", b"2412e0", b"02412", b" 2412", b"2412 ", b"4294967296", b"NaN")
        for token in tokens:
            raw = b"Wiphy phy3\n\t* " + token + b" MHz [1] (20.0 dBm)\n"
            with self.subTest(token=token):
                result = detail.channel_structure(raw, 3)
                self.assertEqual(result["noninteger_frequency_count"], 1)
                self.assertEqual(result["rows_2_4ghz_count"], 0)
        malformed = b"Wiphy phy3\n\t* 2412.0MHz [1] (20.0 dBm)\n"
        self.assertEqual(detail.channel_structure(malformed, 3)["noninteger_frequency_count"], 1)

    def test_structure_ignores_source_faithful_ht_capability_prose(self):
        frequency = b"Wiphy phy3\n\tFrequencies:\n\t\t* 2412.0 MHz [1] (20.0 dBm)\n"
        capabilities = (b"\tHT Capability overrides:\n"
                        b"\t\t * short GI for 20 MHz\n\t\t * short GI for 40 MHz\n")
        result = detail.channel_structure(frequency + capabilities, 3)
        self.assertEqual(result, detail.channel_structure(frequency, 3))
        self.assertEqual(result["noninteger_frequency_count"], 0)
        self.assertEqual(result["rows_2_4ghz_count"], 1)

    def test_replay_uses_new_names_and_preserves_v1_artifacts(self):
        v1 = detail.compile_v1(V1_BYTES)
        names = (detail.REPORT, "." + detail.REPORT + ".tmp", detail.CLAIM, "." + detail.CLAIM + ".tmp")
        for name in names:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                old = Path(tmp) / "inkyos-observer-diag.json"
                old.write_bytes(b"preserve old report")
                (Path(tmp) / name).write_bytes(b"preserve detail")
                adapter = v1["NativeAdapter"].__new__(v1["NativeAdapter"])
                adapter.files = SimpleNamespace(directory=lambda *a, **k: os.open(tmp, os.O_RDONLY), close=lambda: None)
                adapter.runtime, adapter.boot = {}, None
                try:
                    with self.assertRaisesRegex(v1["DiagnosticError"], "existing_diagnostic"):
                        adapter.fresh()
                    self.assertEqual(old.read_bytes(), b"preserve old report")
                    self.assertEqual((Path(tmp) / name).read_bytes(), b"preserve detail")
                finally:
                    adapter.close()

    def test_attached_detail_preserves_every_service_guard_and_decorates_before_write(self):
        v1 = detail.compile_v1(V1_BYTES)
        adapter = v1["NativeAdapter"].__new__(v1["NativeAdapter"])
        saved = []
        adapter.report = lambda result: saved.append(copy.deepcopy(result))
        guarded_methods = {name: getattr(adapter, name).__func__ for name in (
            "environment", "fresh", "pin_sources", "enrollment", "identity", "inactive_guards",
            "start_firstboot", "firstboot_success", "unchanged", "close")}
        self.assertIs(detail.attach_details(v1, adapter), adapter)
        for name, method in guarded_methods.items():
            self.assertIs(getattr(adapter, name).__func__, method)
        result = {"kind": "enrollment-observer-diagnostic", "limits": [], "activation_authorized": False}
        adapter.report(result)
        self.assertEqual(saved[0]["kind"], detail.KIND)
        self.assertEqual(saved[0]["v1_source_sha256"], detail.V1_SHA256)
        self.assertFalse(saved[0]["activation_authorized"])

    def test_cli_has_no_alternate_root_or_command_and_never_echoes_secrets(self):
        with patch.object(detail, "load_v1") as load:
            for args in (["--root", "PRIVATE_PATH"], ["--command", "SECRET"]):
                output = io.StringIO()
                with patch("sys.stdout", output):
                    self.assertEqual(detail.main(args), 1)
                self.assertEqual(json.loads(output.getvalue())["error"], "invalid_arguments")
                self.assertNotIn("SECRET", output.getvalue())
                self.assertNotIn("PRIVATE_PATH", output.getvalue())
            load.assert_not_called()


if __name__ == "__main__":
    unittest.main()
