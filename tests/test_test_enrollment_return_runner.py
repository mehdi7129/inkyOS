"""Inert read-only runner tests: no device, VM, image or private key access."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/check-test-enrollment-return-linux.sh'
CONTROLLER = ROOT / 'scripts/verify-test-enrollment-return.py'


def driver():
    raw = SCRIPT.read_text().split("<<'PY_RETURN'\n", 1)[1].rsplit('\nPY_RETURN', 1)[0]
    namespace = {'__name__': 'inert_return_runner'}
    exec(compile(raw, str(SCRIPT), 'exec'), namespace)
    return namespace


def outcome(runner, contract, code):
    return dict(schema_version=1, kind='test-enrollment-return-comparison',
        scope='offline-readonly-enrollment-consistency', status=('PASS', 'FAIL', 'INVALID')[code],
        passed=code == 0, observation_source='native-read-only', native_readonly_evidence=code != 2,
        error=(None, 'return_incomplete', 'invalid_input')[code],
        checks={name: code == 0 or code == 1 and index < 4 for index, name in enumerate(contract['CHECKS'])},
        limits=contract['LIMITS'], **{key: False for key in runner['FALSE_FIELDS']})


class ReturnRunnerTests(unittest.TestCase):
    def test_help_and_missing_arguments_are_inert(self):
        result = subprocess.run(['/bin/bash', str(SCRIPT), '--help'], capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0)
        self.assertIn('RETURNED_SIZE RETURNED_SHA256', result.stdout)
        self.assertIn('READ ONLY', result.stdout)
        result = subprocess.run(['/bin/bash', str(SCRIPT)], capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b'')

    def test_sealed_input_layout_has_only_required_closure_and_private_container(self):
        runner = driver()
        self.assertEqual(len(runner['SOURCES']), 9)
        self.assertEqual(len(runner['EXPORT']), 19)
        self.assertEqual(len(runner['INPUT_FILES']), 30)
        self.assertIn('returned.img', runner['INPUT_FILES'])
        self.assertFalse(any('client_ed25519' in name or 'ssh_host' in name or 'profile.json' in name
                             for name in runner['INPUT_FILES']))

    def test_result_accepts_positive_negative_and_invalid_without_reclassifying_them(self):
        runner = driver()
        contract = runner['controller_contract'](CONTROLLER.read_bytes())
        for code in (0, 1, 2):
            original = outcome(runner, contract, code)
            self.assertEqual(runner['validate_result'](code, json.dumps(original).encode(), contract), original)

    def test_result_refuses_secret_fields_authority_type_confusion_and_mismatched_exit(self):
        runner = driver()
        contract = runner['controller_contract'](CONTROLLER.read_bytes())
        for code in (0, 1, 2):
            original = outcome(runner, contract, code)
            cases = [{'private_key': 'DO NOT EMIT'}, {'schema_version': True}, {'status': 'UNKNOWN'},
                     {'passed': int(code == 0)}, {'native_readonly_evidence': 1}, {'limits': []},
                     {'observation_source': 'fixture'}, {'error': 'RAW_SECRET'}]
            cases += [{name: True} for name in runner['FALSE_FIELDS']]
            cases += [{name: 0} for name in runner['FALSE_FIELDS']]
            bad_checks = copy.deepcopy(original['checks'])
            bad_checks[contract['CHECKS'][0]] = int(bad_checks[contract['CHECKS'][0]])
            cases.append({'checks': bad_checks})
            for change in cases:
                with self.subTest(code=code, change=change), self.assertRaises(ValueError):
                    runner['validate_result'](code, json.dumps(dict(original, **change)).encode(), contract)
            for incorrect in ({0, 1, 2, 255, -15} - {code}):
                with self.assertRaises(ValueError):
                    runner['validate_result'](incorrect, json.dumps(original).encode(), contract)
        raw = json.dumps(outcome(runner, contract, 0)).encode()
        for invalid in (b'{"schema_version":1,' + raw[1:], b'RAW SECRET', b'x' * 65537):
            with self.assertRaises(ValueError):
                runner['validate_result'](0, invalid, contract)

    def test_cleanup_inspects_attempted_mount_and_detaches_even_when_attach_output_was_lost(self):
        runner = driver()
        calls, mounts, loops = [], {'/root', '/boot'}, ['/dev/loop7']
        def command(*args, **kwargs):
            calls.append(args)
            self.assertEqual(kwargs.get('timeout'), 3)
            if args[0] == 'findmnt':
                return subprocess.CompletedProcess(args, 0 if args[-1] in mounts else 1, b'')
            if args[0] == 'umount':
                mounts.remove(args[1])
            elif args[:2] == ('losetup', '-d'):
                loops.remove(args[2])
            return subprocess.CompletedProcess(args, 0, b'')
        runner['command'] = command
        runner['associated'] = lambda _image, **_kwargs: list(loops)
        self.assertEqual(runner['cleanup'](['/root', '/boot'], Path('/returned.img')), (True, True))
        self.assertEqual([call[1] for call in calls if call[0] == 'umount'], ['/boot', '/root'])
        self.assertEqual(loops, [])

    def test_cleanup_preserves_loop_on_unmount_failure_and_reports_detach_failure(self):
        runner = driver()
        detaches = []
        def command(*args, **kwargs):
            if args[0] == 'umount':
                raise TimeoutError('synthetic failure')
            if args[:2] == ('losetup', '-d'):
                detaches.append(args[2])
            return subprocess.CompletedProcess(args, 0, b'')
        runner['command'] = command
        runner['associated'] = lambda _image, **_kwargs: ['/dev/loop7']
        self.assertEqual(runner['cleanup'](['/root'], Path('/returned.img')), (False, False))
        self.assertEqual(detaches, [])
        self.assertEqual(runner['cleanup']([], Path('/returned.img')), (True, False))

    def test_associated_device_list_refuses_non_loop_duplicate_or_unbounded_output(self):
        runner = driver()
        for raw in (b'/dev/sda\n', b'/dev/loop1\n/dev/loop1\n',
                    '\n'.join('/dev/loop' + str(i) for i in range(17)).encode()):
            runner['command'] = lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, raw)
            with self.assertRaises(ValueError):
                runner['associated'](Path('/returned.img'))

    def test_paths_and_symlinks_fail_before_mount_or_private_file_read(self):
        runner = driver()
        with self.assertRaises(ValueError):
            runner['ancestors'](Path('relative'))
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'target').write_bytes(b'not private data')
            (base / 'link').symlink_to(base / 'target')
            with self.assertRaises(OSError):
                runner['read_file'](base / 'link', 0o600)
            with self.assertRaises(ValueError):
                runner['ancestors'](base / 'link')
        runner['ancestors'] = lambda *_args: self.fail('invalid size must fail before filesystem access')
        for size in (0, -1, runner['IMAGE_SIZE'] - 512, runner['IMAGE_SIZE'] + 1, 33 * 1024**3):
            with self.assertRaises(ValueError):
                runner['main'](Path('/no-access'), 'a' * 64, size, 'b' * 64)


if __name__ == '__main__':
    unittest.main()
