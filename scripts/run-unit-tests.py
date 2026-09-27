#!/usr/bin/env python3
"""Run this checkout's fixtures and preserve a small machine-readable receipt."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import unittest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--log', type=Path, required=True)
    args = parser.parse_args()
    if os.path.lexists(args.output) or os.path.lexists(args.log):
        parser.error('Outputs must be new files')
    root = Path(__file__).resolve().parents[1]
    suite = unittest.defaultTestLoader.discover(str(root / 'tests'))
    with args.log.open('x', encoding='utf-8') as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
        scripts = sorted((root / 'scripts').glob('*.sh'))
        shell_passed = True
        for script in scripts:
            try:
                checked = subprocess.run(['bash', '-n', str(script)], stdout=stream, stderr=stream)
                shell_passed = checked.returncode == 0 and shell_passed
            except OSError:
                stream.write('Shell syntax checker unavailable.\n')
                shell_passed = False
        stream.write(f'Shell syntax: {len(scripts)} scripts, passed={shell_passed}\n')
    passed = result.wasSuccessful() and shell_passed
    receipt = {'schema_version': 1, 'scope': 'software-fixtures-only',
               'passed': passed, 'tests': result.testsRun,
               'python_fixtures_passed': result.wasSuccessful(),
               'shell_syntax': {'scripts_checked': len(scripts), 'passed': shell_passed},
               'failures': len(result.failures), 'errors': len(result.errors),
               'skipped': len(result.skipped), 'python': platform.python_version(),
               'system': platform.system(), 'architecture': platform.machine(),
               'log_sha256': hashlib.sha256(args.log.read_bytes()).hexdigest(),
               'hardware_qualified': False}
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(receipt, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(f"Software fixtures: {result.testsRun} tests, "
          f"{len(result.failures)} failures, {len(result.errors)} errors, "
          f"{len(result.skipped)} skipped")
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
