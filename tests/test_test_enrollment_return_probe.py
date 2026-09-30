"""Closed negative report fixtures only: no image, mount, VM or key access."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/probe-test-enrollment-return-linux.sh'
CONTROLLER = ROOT / 'scripts/verify-test-enrollment-return.py'


def driver():
    raw = SCRIPT.read_text().split("<<'PY_RETURN'\n", 1)[1].rsplit('\nPY_RETURN', 1)[0]
    namespace = {'__name__': 'inert_negative_return_probe'}
    exec(compile(raw, str(SCRIPT), 'exec'), namespace)
    return namespace


def negative(probe, contract):
    return dict(schema_version=1, kind='test-enrollment-return-comparison',
        scope='offline-readonly-enrollment-consistency', status='FAIL', passed=False,
        observation_source='native-read-only', native_readonly_evidence=True,
        error='return_incomplete', checks={name: index < 4 for index, name in enumerate(contract['CHECKS'])},
        limits=contract['LIMITS'], **{key: False for key in probe['FALSE_FIELDS']})


class ReturnProbeTests(unittest.TestCase):
    def test_help_and_missing_arguments_do_not_touch_images_or_devices(self):
        output = subprocess.run(['/bin/bash', str(SCRIPT), '--help'], capture_output=True, text=True, timeout=3)
        self.assertEqual(output.returncode, 0)
        self.assertIn('mounts READ ONLY', output.stdout)
        self.assertIn('No standalone profile/client key', output.stdout)
        output = subprocess.run(['/bin/bash', str(SCRIPT)], capture_output=True, text=True, timeout=3)
        self.assertEqual(output.returncode, 2)
        self.assertEqual(output.stdout, '')

    def test_closed_ingress_names_have_nine_sources_nineteen_export_files_and_no_key(self):
        probe = driver()
        self.assertEqual(len(probe['SOURCES']), 9)
        self.assertEqual(len(probe['REPORTS']), 16)
        self.assertEqual(len(probe['EXPORT']), 19)
        self.assertEqual(len(probe['INPUT_FILES']), 29)
        self.assertEqual(probe['INPUT_FILES'], {probe['PROBE']} | {'sources/' + name for name in probe['SOURCES']}
                         | {'expected/' + name for name in probe['EXPORT']})
        self.assertFalse(any('client_ed25519' in name or 'private-profile' in name or 'ssh_host' in name
                             for name in probe['INPUT_FILES']))

    def test_sources_closure_imports_real_controller_definitions_without_extra_files(self):
        probe = driver()
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            for name in probe['SOURCES']:
                (folder / name).write_bytes((ROOT / 'scripts' / name).read_bytes())
            spec = importlib.util.spec_from_file_location('inert_copied_return_controller', folder / CONTROLLER.name)
            module = importlib.util.module_from_spec(spec)
            previous = sys.dont_write_bytecode
            try:
                sys.dont_write_bytecode = True
                spec.loader.exec_module(module)
            finally:
                sys.dont_write_bytecode = previous
            self.assertEqual(module.CHECKS[:4], probe['FIRST_CHECKS'])
            self.assertEqual(set(module.export_contract.REQUIRED_REPORTS), probe['REPORTS'])
            self.assertEqual({path.name for path in folder.iterdir()}, probe['SOURCES'])

    def test_contract_ast_is_closed_and_does_not_execute_controller_body(self):
        probe = driver()
        raw = CONTROLLER.read_bytes()
        contract = probe['controller_contract'](raw + b'\nraise AssertionError("MUST NOT EXECUTE")\n')
        self.assertEqual(contract['CHECKS'][:4], probe['FIRST_CHECKS'])
        self.assertEqual(len(contract['CHECKS']), 21)
        for bad in (raw + b'\nCHECKS = ()\n', raw.replace(b'CHECKS = (', b'IGNORED_CHECKS = (')):
            with self.assertRaises(ValueError):
                probe['controller_contract'](bad)

    def test_only_exit_one_with_four_proven_checks_accepts_the_expected_negative(self):
        probe = driver()
        contract = probe['controller_contract'](CONTROLLER.read_bytes())
        value = negative(probe, contract)
        result = probe['validate_result'](1, json.dumps(value).encode(), contract)
        self.assertFalse(result['passed'])
        self.assertTrue(result['native_readonly_evidence'])
        self.assertEqual(sum(result['checks'].values()), 4)
        self.assertTrue(all(result[key] is False for key in probe['FALSE_FIELDS']))

    def test_status_schema_authority_count_and_boolean_contradictions_are_rejected(self):
        probe = driver()
        contract = probe['controller_contract'](CONTROLLER.read_bytes())
        original = negative(probe, contract)
        cases = [{key: value} for key, value in (
            ('schema_version', True), ('passed', True), ('passed', 0), ('status', 'PASS'), ('error', None),
            ('native_readonly_evidence', False), ('native_readonly_evidence', 1),
            ('observation_source', 'fixture'), ('PRIVATE_EXTRA', 'PRIVATE_DATA'), ('limits', []))]
        cases += [{key: True} for key in probe['FALSE_FIELDS']]
        cases += [{key: 0} for key in probe['FALSE_FIELDS']]
        for index, name in enumerate(contract['CHECKS']):
            checks = copy.deepcopy(original['checks'])
            checks[name] = not checks[name]
            cases.append({'checks': checks})
            checks = copy.deepcopy(original['checks'])
            checks[name] = int(checks[name])
            cases.append({'checks': checks})
        for change in cases:
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    probe['validate_result'](1, json.dumps(dict(original, **change)).encode(), contract)
        for code in (0, 2, 255, True):
            with self.assertRaises(ValueError):
                probe['validate_result'](code, json.dumps(original).encode(), contract)
        raw = json.dumps(original).encode()
        for bad in (b'{"schema_version":1,' + raw[1:], b'PRIVATE_RAW_LOG', b'x' * 65537):
            with self.assertRaises(ValueError):
                probe['validate_result'](1, bad, contract)


if __name__ == '__main__':
    unittest.main()
