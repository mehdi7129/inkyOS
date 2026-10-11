"""Private build diagnostics never become command output or public reports."""
import contextlib
import importlib.util
import io
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('access_build_log_fixture',
    ROOT / 'scripts/build-test-access.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class BuildLogTests(unittest.TestCase):
    def test_failed_build_preserves_both_streams_only_in_new_private_log(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'native-build.log'
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                with self.assertRaises(builder.ClosedError):
                    builder.invoke([sys.executable, '-I', '-c',
                        'import sys; print("PRIVATE_STDOUT"); '
                        'print("PRIVATE_STDERR", file=sys.stderr); sys.exit(7)'],
                        destination=log, merge_stderr=True)
            self.assertEqual(output.getvalue(), '')
            self.assertEqual(set(log.read_text().splitlines()), {'PRIVATE_STDOUT', 'PRIVATE_STDERR'})
            self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)
            original = log.read_bytes()
            with self.assertRaises(FileExistsError):
                builder.invoke([sys.executable, '-I', '-c', 'print("replacement")'],
                               destination=log, merge_stderr=True)
            self.assertEqual(log.read_bytes(), original)

    def test_diagnostics_cannot_be_merged_into_public_capture(self):
        with self.assertRaises(builder.ClosedError):
            builder.invoke([sys.executable, '-I', '-c', 'print("PRIVATE")'],
                           capture=True, merge_stderr=True)


if __name__ == '__main__':
    unittest.main()
