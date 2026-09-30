"""Synthetic local snapshots only; no physical report, SD or Pi accessed."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/compare-sd-reports.py"
spec = importlib.util.spec_from_file_location("inkyos_compare_sd_reports", SCRIPT)
compare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare)


def digest(label):
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def report(*, card="a", boot="one"):
    hostname_hash = digest("hostname-" + card)
    return {
        "schema_version": 1,
        "boot_id_sha256": digest("boot-" + boot),
        "hardware": {key: {"status": "missing"} for key in (
            "kernel", "architecture", "model", "uptime_seconds", "memory",
            "temperature_millicelsius", "throttling")},
        "filesystems": {key: {"status": "read_error"} for key in ("root", "boot")},
        "identity": {
            "machine_id": {"status": "ok", "sha256": digest("machine-" + card)},
            "hostname": {"status": "ok", "sha256": hostname_hash},
            "kernel_hostname": {"status": "ok", "sha256": hostname_hash},
            "firstboot_state": {"status": "ok", "version": 1, "hostname_sha256": hostname_hash},
            "coherence": {"status": "ok", "state_matches_hostname": True,
                          "state_matches_kernel": True, "state_matches_hosts": True},
            "hosts_file": {"status": "ok"},
        },
        "services": {"inkyos-firstboot.service": {
            "status": "ok", "ActiveState": "active", "SubState": "exited",
            "Result": "success", "ExecMainStatus": 0, "LoadState": "loaded",
            "UnitFileState": "enabled",
        }},
    }


class CompareReportsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="PRIVATE_REPORT_DIRECTORY-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.left = self.write("PRIVATE_LEFT.json", report())
        self.right = self.write("PRIVATE_RIGHT.json", report(boot="two"))

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        return path

    def invoke(self, mode="same-card", left=None, right=None, *, arguments=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        args = arguments if arguments is not None else ["--mode", mode, str(left or self.left), str(right or self.right)]
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = compare.main(args)
        self.assertEqual(stderr.getvalue(), "")
        value = json.loads(stdout.getvalue())
        self.assertNotIn(str(self.root), stdout.getvalue())
        self.assertNotIn("PRIVATE_", stdout.getvalue())
        self.assertFalse(value["hardware_qualified"])
        self.assertFalse(value["release_qualified"])
        self.assertEqual(value["schema_version"], 1)
        self.assertEqual(value["scope"], "identity_comparison_only")
        self.assertEqual(value["limitations"], list(compare.LIMITATIONS))
        self.assertTrue(all(type(check) is bool for check in value["checks"].values()))
        self.assertTrue(all(type(check) is bool for check in value["comparisons"].values()))
        return code, value, stdout.getvalue()

    def test_same_card_different_boots_passes_and_only_artifact_hashes_are_exported(self):
        code, value, output = self.invoke()
        self.assertEqual(code, 0)
        self.assertTrue(value["passed"])
        self.assertTrue(all(value["checks"].values()))
        self.assertTrue(all(value["comparisons"].values()))
        expected = [hashlib.sha256(path.read_bytes()).hexdigest() for path in (self.left, self.right)]
        self.assertEqual(value["input_artifact_sha256"], expected)
        for snapshot in (report(), report(boot="two")):
            self.assertNotIn(snapshot["boot_id_sha256"], output)
            for key in ("machine_id", "hostname", "kernel_hostname"):
                self.assertNotIn(snapshot["identity"][key]["sha256"], output)
            self.assertNotIn(snapshot["identity"]["firstboot_state"]["hostname_sha256"], output)
        self.assertIsNone(value["error"])

    def test_different_cards_distinct_machine_and_hostname_passes(self):
        self.write(self.right.name, report(card="b", boot="two"))
        code, value, _output = self.invoke("different-cards")
        self.assertEqual(code, 0)
        self.assertTrue(value["passed"])
        self.assertTrue(all(value["checks"].values()))
        self.assertFalse(any(value["comparisons"].values()))

    def test_same_card_machine_regeneration_or_coherent_hostname_regeneration_fails(self):
        changes = (lambda value: value["identity"]["machine_id"].update(sha256=digest("regenerated-machine")),
                   lambda value: value.update(identity=report(card="b")["identity"]))
        for change in changes:
            with self.subTest(change=change):
                value = report(boot="two")
                change(value)
                self.write(self.right.name, value)
                code, output, _text = self.invoke()
                self.assertEqual(code, 1)
                self.assertFalse(output["passed"])

    def test_different_cards_clone_of_either_machine_or_hostname_fails(self):
        for field in ("machine", "hostname"):
            with self.subTest(field=field):
                value = report(card="b", boot="two")
                if field == "machine":
                    value["identity"]["machine_id"] = report()["identity"]["machine_id"]
                else:
                    for key in ("hostname", "kernel_hostname", "firstboot_state"):
                        value["identity"][key] = report()["identity"][key]
                self.write(self.right.name, value)
                code, output, _text = self.invoke("different-cards")
                self.assertEqual(code, 1)
                self.assertFalse(output["passed"])

    def test_copied_boot_id_fails_even_with_distinct_artifacts_or_distinct_cards(self):
        for mode, card in (("same-card", "a"), ("different-cards", "b")):
            with self.subTest(mode=mode):
                value = report(card=card, boot="one")
                value["hardware"]["uptime_seconds"] = {"status": "ok", "value": 999}
                self.write(self.right.name, value)
                code, output, _text = self.invoke(mode)
                self.assertEqual(code, 1)
                self.assertFalse(output["checks"]["distinct_boots"])
                self.assertFalse(output["passed"])
                self.assertNotEqual(*output["input_artifact_sha256"])
        code, output, _text = self.invoke(left=self.left, right=self.left)
        self.assertEqual(code, 1)
        self.assertEqual(*output["input_artifact_sha256"])

    def test_hostname_kernel_state_divergence_and_contradictory_assertions_fail(self):
        for field, assertion in (("hostname", "state_matches_hostname"),
                                 ("kernel_hostname", "state_matches_kernel")):
            for reported_match in (True, False):
                with self.subTest(field=field, reported_match=reported_match):
                    value = report(boot="two")
                    value["identity"][field]["sha256"] = digest("divergence")
                    value["identity"]["coherence"][assertion] = reported_match
                    self.write(self.right.name, value)
                    code, output, _text = self.invoke()
                    self.assertEqual(code, 1)
                    self.assertFalse(output["checks"]["right_hashes_coherent"])
                    self.assertEqual(output["checks"]["right_coherence_assertions_consistent"], not reported_match)
        value = report(boot="two")
        value["identity"]["coherence"]["state_matches_hostname"] = False
        self.write(self.right.name, value)
        code, output, _text = self.invoke()
        self.assertEqual(code, 1)
        self.assertFalse(output["checks"]["right_coherence_assertions_consistent"])

    def test_hosts_unreadable_or_reported_host_mismatch_fails(self):
        for field, metric in (("hosts_file", {"status": "missing"}),
                              ("coherence", {"status": "unavailable"})):
            value = report(boot="two")
            value["identity"][field] = metric
            self.write(self.right.name, value)
            code, output, _text = self.invoke()
            self.assertEqual(code, 1)
            self.assertFalse(output["passed"])
        value = report(boot="two")
        value["identity"]["coherence"]["state_matches_hosts"] = False
        self.write(self.right.name, value)
        code, output, _text = self.invoke()
        self.assertEqual(code, 1)
        self.assertFalse(output["checks"]["right_reported_coherent"])

    def test_missing_invalid_identity_metrics_are_failures_not_equal_absences(self):
        for field in ("machine_id", "hostname", "kernel_hostname", "firstboot_state"):
            value = report(boot="two")
            value["identity"][field] = {"status": "invalid"}
            self.write(self.right.name, value)
            code, output, _text = self.invoke("different-cards")
            self.assertEqual(code, 1)
            self.assertFalse(output["checks"]["right_identity_ready"])
            self.assertFalse(output["checks"]["expected_machine_id_relationship"])

    def test_bad_or_unexecuted_firstboot_service_fails(self):
        updates = ({"Result": "exit-code", "ExecMainStatus": 1},
                   {"ActiveState": "failed", "SubState": "failed"},
                   {"ActiveState": "inactive", "SubState": "dead"},
                   {"LoadState": "masked"})
        for update in updates:
            with self.subTest(update=update):
                value = report(boot="two")
                value["services"]["inkyos-firstboot.service"].update(update)
                self.write(self.right.name, value)
                code, output, _text = self.invoke()
                self.assertEqual(code, 1)
                self.assertFalse(output["checks"]["right_firstboot_success"])
        value["services"]["inkyos-firstboot.service"] = {"status": "missing"}
        self.write(self.right.name, value)
        self.assertEqual(self.invoke()[0], 1)

    def test_schema_boolean_integer_types_hashes_unknown_keys_and_service_enum_are_invalid(self):
        changes = (
            lambda value: value.update(schema_version=True),
            lambda value: value.update(schema_version=2),
            lambda value: value.update(boot_id_sha256="A" * 64),
            lambda value: value.update(boot_id_sha256="0" * 63),
            lambda value: value.update(hardware=True),
            lambda value: value.update(filesystems=[]),
            lambda value: value.update(PRIVATE_RAW_ID="PRIVATE_SECRET"),
            lambda value: value["identity"]["firstboot_state"].update(version=True),
            lambda value: value["identity"]["machine_id"].update(sha256=10),
            lambda value: value["identity"]["hostname"].update(status=True),
            lambda value: value["identity"]["coherence"].update(state_matches_hosts=1),
            lambda value: value["identity"]["hosts_file"].update(PRIVATE_KEY="PRIVATE_SECRET"),
            lambda value: value["services"]["inkyos-firstboot.service"].update(ExecMainStatus=True),
            lambda value: value["services"]["inkyos-firstboot.service"].update(ExecMainStatus=0.0),
            lambda value: value["services"]["inkyos-firstboot.service"].update(ActiveState="PRIVATE_SECRET"),
            lambda value: value["services"].pop("inkyos-firstboot.service"),
        )
        for change in changes:
            with self.subTest(change=change):
                value = report(boot="two")
                change(value)
                self.write(self.right.name, value)
                code, output, text = self.invoke()
                self.assertEqual(code, 2)
                self.assertEqual(output["error"], "invalid_schema")
                self.assertFalse(output["passed"])
                self.assertNotIn("PRIVATE_SECRET", text)

    def test_duplicate_keys_nonfinite_numbers_invalid_encoding_and_malformed_json_are_invalid(self):
        serialized = json.dumps(report(boot="two"))
        duplicate = serialized.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1', 1)
        nested_duplicate = serialized.replace('"version": 1', '"version": 1, "version": 1', 1)
        for content in (duplicate.encode(), nested_duplicate.encode(), b"{PRIVATE_SECRET", b"\xffPRIVATE_SECRET",
                        serialized.replace('"hardware": {', '"hardware": {"bad": NaN,', 1).encode(),
                        serialized.replace('"hardware": {', '"hardware": {"bad": Infinity,', 1).encode(),
                        serialized.replace('"hardware": {', '"hardware": {"bad": -Infinity,', 1).encode(),
                        serialized.replace('"hardware": {', '"hardware": {"bad": 1e309,', 1).encode(),
                        serialized.replace('"hardware": {', '"hardware": {"bad": -1e309,', 1).encode()):
            with self.subTest(content=content[:40]):
                self.right.write_bytes(content)
                code, output, text = self.invoke()
                self.assertEqual(code, 2)
                self.assertEqual(output["error"], "invalid_json")
                self.assertNotIn("PRIVATE_SECRET", text)

    def test_symlinks_hardlinks_fifo_directory_and_missing_inputs_are_refused(self):
        targets = []
        symlink = self.root / "PRIVATE_SYMLINK"
        symlink.symlink_to(self.right)
        targets.append(symlink)
        hardlink = self.root / "PRIVATE_HARDLINK"
        os.link(self.right, hardlink)
        targets.append(hardlink)
        fifo = self.root / "PRIVATE_FIFO"
        os.mkfifo(fifo)
        targets.extend((fifo, self.root, self.root / "PRIVATE_MISSING"))
        for target in targets:
            with self.subTest(target=target.name):
                code, output, _text = self.invoke(right=target)
                self.assertEqual(code, 2)
                self.assertIn(output["error"], {"unsafe_input", "input_unavailable"})

    def test_bound_exact_size_is_readable_and_oversized_input_is_refused(self):
        raw = self.right.read_bytes()
        self.right.write_bytes(raw + b" " * (compare.MAX_REPORT_BYTES - len(raw)))
        self.assertEqual(self.invoke()[0], 0)
        with self.right.open("ab") as stream:
            stream.write(b" ")
        code, output, _text = self.invoke()
        self.assertEqual(code, 2)
        self.assertEqual(output["error"], "input_too_large")

    def test_content_modified_during_read_is_detected(self):
        original = os.read
        changed = False
        def mutate(fd, count):
            nonlocal changed
            chunk = original(fd, count)
            if not changed:
                changed = True
                with self.right.open("ab") as stream:
                    stream.write(b" ")
            return chunk
        with mock.patch.object(compare.os, "read", side_effect=mutate):
            with self.assertRaisesRegex(compare.InputError, "^input_changed$"):
                compare.read_report(self.right)

    def test_path_replaced_during_read_is_detected(self):
        alternate = self.write("PRIVATE_ALTERNATE.json", report(boot="three"))
        original = os.read
        changed = False
        def replace(fd, count):
            nonlocal changed
            chunk = original(fd, count)
            if not changed:
                changed = True
                os.replace(alternate, self.right)
            return chunk
        with mock.patch.object(compare.os, "read", side_effect=replace):
            with self.assertRaisesRegex(compare.InputError, "^input_changed$"):
                compare.read_report(self.right)

    def test_unknown_cli_arguments_and_bad_modes_return_json_without_argument_paths(self):
        argument_sets = ([], ["--mode", "PRIVATE_MODE", str(self.left), str(self.right)],
                         ["--mode", "same-card", str(self.left), str(self.right), "--PRIVATE_SECRET"],
                         ["--mode", "same-card", str(self.left)],
                         ["--m", "same-card", str(self.left), str(self.right)])
        for arguments in argument_sets:
            code, output, _text = self.invoke(arguments=arguments)
            self.assertEqual(code, 2)
            self.assertEqual(output["error"], "invalid_arguments")

    def test_invalid_api_path_with_embedded_nul_has_fixed_json_error_without_traceback(self):
        path = str(self.root / "PRIVATE_SECRET\x00REPORT.json")
        code, output, _text = self.invoke(right=path)
        self.assertEqual(code, 2)
        self.assertEqual(output["error"], "input_unavailable")
        with self.assertRaisesRegex(compare.InputError, "^input_unavailable$"):
            compare.read_report(path)

    def test_actual_cli_has_only_one_json_stdout_line_for_pass_fail_and_errors(self):
        for args, expected in ((["--mode", "same-card", str(self.left), str(self.right)], 0),
                               (["--mode", "same-card", str(self.left), str(self.left)], 1),
                               (["--mode", "same-card", str(self.left), str(self.root / "PRIVATE_MISSING")], 2),
                               (["--PRIVATE_RAW_PATH=" + str(self.root)], 2)):
            result = subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, expected)
            self.assertEqual(result.stderr, "")
            self.assertEqual(len(result.stdout.splitlines()), 1)
            self.assertEqual(json.loads(result.stdout)["hardware_qualified"], False)
            self.assertNotIn("PRIVATE_", result.stdout)

    def test_inputs_are_never_modified_by_comparison(self):
        before = {path: path.read_bytes() for path in (self.left, self.right)}
        self.invoke()
        self.assertEqual(before, {path: path.read_bytes() for path in (self.left, self.right)})
        self.assertEqual(set(self.root.iterdir()), {self.left, self.right})


if __name__ == "__main__":
    unittest.main()
