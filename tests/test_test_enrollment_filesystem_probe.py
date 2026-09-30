"""Inert probe tests: no root, mounts, loop devices, VM or runtime execution."""
import ast
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/probe-test-enrollment-filesystem-linux.sh'
SOURCE = ROOT / 'scripts/test-enrollment-firstboot.py'


def driver():
    shell = SCRIPT.read_text()
    raw = shell.split("<<'PY_FILESYSTEM'\n", 1)[1].rsplit('\nPY_FILESYSTEM', 1)[0]
    namespace = {'__name__': 'inert_probe_test'}
    exec(compile(raw, str(SCRIPT), 'exec'), namespace)
    return namespace


class FilesystemProbeTests(unittest.TestCase):
    def test_help_and_invalid_arguments_do_not_run_a_native_probe(self):
        help_result = subprocess.run(['/bin/bash', str(SCRIPT), '--help'], capture_output=True, text=True, timeout=3)
        self.assertEqual(help_result.returncode, 0)
        self.assertIn('RUNTIME_SHA256', help_result.stdout)
        self.assertIn('ext4 32 MiB and FAT32 64 MiB regular images', help_result.stdout)
        result = subprocess.run(['/bin/bash', str(SCRIPT)], capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('Traceback', result.stderr)

    def test_ast_extracts_only_reviewed_helpers_without_module_or_runtime_execution(self):
        probe = driver()
        raw = SOURCE.read_bytes() + b'\nraise AssertionError("TOP LEVEL MUST NOT RUN")\n'
        namespace = probe['helpers'](raw)
        self.assertEqual(set(namespace) - {'__builtins__', 'os', 'stat', 'ctypes', 're'}, set(probe['HELPERS']))
        self.assertNotIn('NativeAdapter', namespace)
        self.assertNotIn('enroll', namespace)
        self.assertNotIn('subprocess', namespace)

    def test_extractor_refuses_missing_duplicate_and_decorated_helpers(self):
        probe = driver()
        raw = SOURCE.read_bytes()
        for altered in (raw.replace(b'def mount_is_fat(', b'def omitted('),
                        raw + b'\ndef _stamp(info): return None\n',
                        raw.replace(b'def _stamp(', b'@staticmethod\ndef _stamp(')):
            with self.assertRaises(ValueError):
                probe['helpers'](altered)

    def test_portable_orchestration_exercises_helpers_and_preserves_synthetic_partial(self):
        probe = driver()
        ns = probe['helpers'](SOURCE.read_bytes())
        # Test orchestration on macOS; production never installs this shim.
        def no_replace(fd, old, new):
            try:
                os.stat(new, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                os.rename(old, new, src_dir_fd=fd, dst_dir_fd=fd)
            else:
                raise ns['EnrollmentError']('existing_artifact')
        ns['rename_noreplace'] = no_replace
        ns['write_atomic'].__kwdefaults__['rename'] = no_replace
        ns['write_atomic'].__kwdefaults__['owner'] = os.getuid()
        with tempfile.TemporaryDirectory() as directory:
            passed = set()
            probe['exercise'](ns, Path(directory), False, passed)
            self.assertEqual(passed, {name for name in probe['CHECKS'] if name.startswith('ext4_')})
            self.assertEqual((Path(directory) / '.partial.json.tmp').read_bytes(), b'SYNTHETIC ENROLLMENT FILESYSTEM FIXTURE\n')
            self.assertEqual((Path(directory) / 'published.json').read_bytes(), b'FOREIGN STATE')

    def test_probe_detects_accidental_replace_and_does_not_mark_refusal_passed(self):
        probe = driver()
        ns = probe['helpers'](SOURCE.read_bytes())
        def replacing(fd, name, raw, **_kwargs):
            stream = os.open(name, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600, dir_fd=fd)
            try:
                os.write(stream, raw)
                ns['os'].fsync(stream)
            finally:
                os.close(stream)
            ns['os'].fsync(fd)
        ns['write_atomic'] = replacing
        with tempfile.TemporaryDirectory() as directory:
            passed = set()
            with self.assertRaisesRegex(ValueError, 'unexpected_success'):
                probe['exercise'](ns, Path(directory), False, passed)
            self.assertEqual(passed, {'ext4_publish_fsync'})

    def test_check_ids_are_closed_and_no_runtime_entrypoint_is_in_extracted_ast(self):
        probe = driver()
        self.assertEqual(len(probe['CHECKS']), 17)
        self.assertEqual(len(set(probe['CHECKS'])), 17)
        source = ast.parse(SOURCE.read_bytes())
        helpers = [node for node in source.body if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name in probe['HELPERS']]
        forbidden = {'subprocess', 'Popen', 'system', 'key', 'keygen', 'enroll', 'poweroff', 'NativeAdapter'}
        self.assertFalse({node.id for item in helpers for node in ast.walk(item) if isinstance(node, ast.Name)} & forbidden)


if __name__ == '__main__':
    unittest.main()
