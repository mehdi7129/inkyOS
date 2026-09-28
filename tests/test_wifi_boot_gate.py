"""Inactive Wi-Fi gate fixtures: no services, radios, clock or real NM state."""
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'wifi_boot_gate', Path(__file__).parents[1] / 'scripts/wifi-boot-gate.py')
gate = importlib.util.module_from_spec(spec); spec.loader.exec_module(gate)


class SimulatedCrash(RuntimeError):
    pass


class WifiBootGateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='.inkyos-wifi-gate-test-', dir=Path.home().resolve())
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.root.chmod(0o700)
        self.directory = self.root / 'var/lib/NetworkManager'
        self.directory.mkdir(parents=True, mode=0o755)
        for path in (self.root / 'var', self.root / 'var/lib', self.directory):
            path.chmod(0o755)
        self.state = self.directory / 'NetworkManager.state'
        self.write(b'[main]\nWirelessEnabled=true\n')

    def write(self, value, mode=0o600):
        self.state.write_bytes(value); self.state.chmod(mode)

    def run_gate(self, **kwargs):
        return gate.set_wireless_disabled(self.root, owner_uid=os.geteuid(), **kwargs)

    def test_enabled_state_closed_with_private_durable_output(self):
        self.state.chmod(0o644); checkpoints = []
        result = self.run_gate(checkpoint=checkpoints.append)
        self.assertEqual(self.state.read_bytes(), b'[main]\nWirelessEnabled=false\n')
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o600)
        self.assertEqual(self.state.stat().st_uid, os.geteuid())
        self.assertEqual(checkpoints, ['state:temp_fsynced', 'state:replaced', 'state:directory_fsynced'])
        self.assertTrue(result['changed']); self.assertTrue(result['durably_written'])
        for flag in ('wireless_enabled', 'radio_modified', 'clock_modified', 'ble_touched', 'hardware_qualified'):
            self.assertFalse(result[flag])

    def test_restart_and_identical_repeat_both_commit_durably(self):
        self.run_gate(); checks = []
        result = self.run_gate(checkpoint=checks.append)
        self.assertFalse(result['changed']); self.assertEqual(len(checks), 3)
        self.write(b'[main]\nNetworkingEnabled=true\nWirelessEnabled=true\nWWANEnabled=false\n')
        self.run_gate()
        self.assertIn(b'WirelessEnabled=false\n', self.state.read_bytes())
        self.assertIn(b'NetworkingEnabled=true\n', self.state.read_bytes())
        self.assertIn(b'WWANEnabled=false\n', self.state.read_bytes())

    def test_missing_state_is_created_but_missing_directory_is_not(self):
        self.state.unlink(); self.run_gate()
        self.assertEqual(self.state.read_bytes(), b'[main]\nWirelessEnabled=false\n')
        self.state.unlink(); self.directory.rmdir()
        with self.assertRaises(gate.GateError):
            self.run_gate()
        self.assertFalse(self.directory.exists())

    def test_unknown_sections_values_and_other_booleans_are_preserved_verbatim(self):
        before = (b'# retained\r\n[main]\r\nNetworkingEnabled=false\r\nWirelessEnabled = true\r\n'
                  b'WWANEnabled=true\r\nUnknown = literal%value\\n\r\n[extra]\r\nFoo=bar\r\n')
        self.write(before)
        self.run_gate()
        self.assertEqual(self.state.read_bytes(), before.replace(b'WirelessEnabled = true\r\n',
                                                                b'WirelessEnabled=false\n'))

    def test_missing_wireless_key_inserted_in_main_not_last_section(self):
        before = b'[main]\nNetworkingEnabled=true\n[other]\nWirelessEnabled=untouched'
        self.write(before); self.run_gate()
        self.assertEqual(self.state.read_bytes(),
                         b'[main]\nNetworkingEnabled=true\nWirelessEnabled=false\n[other]\nWirelessEnabled=untouched')
        self.write(b'[main]\nNetworkingEnabled=false'); self.run_gate()
        self.assertEqual(self.state.read_bytes(), b'[main]\nNetworkingEnabled=false\nWirelessEnabled=false\n')

    def test_duplicates_conflicts_and_malformed_files_are_refused_unchanged(self):
        cases = [b'', b'no section', b'[other]\nFoo=bar\n',
                 b'[main]\nWirelessEnabled=true\nWirelessEnabled=false\n',
                 b'[main]\nWirelessEnabled=true\nwirelessenabled=false\n',
                 b'[main]\nWirelessEnabled=true\n[main]\nFoo=bar\n',
                 b'[MAIN]\nWirelessEnabled=true\n', b'[main]\nWirelessEnabled=1\n',
                 b'[main]\nNetworkingEnabled=maybe\n', b'[main]\nFoo=1\nFoo=2\n',
                 b'[main]\nFoo=1\n continuation\n', b'[main]\nWirelessEnabled=true # inline\n',
                 b'[main] # suffix\nWirelessEnabled=true\n', b'[main]\nFoo=\xff\n',
                 b'[main]\nFoo=bar\x00\n', b'[main]\rWirelessEnabled=true\r',
                 '[main]\nWirelessEnabled=true\u2028'.encode()]
        for value in cases:
            with self.subTest(value=value):
                self.write(value)
                with self.assertRaises(gate.GateError):
                    self.run_gate()
                self.assertEqual(self.state.read_bytes(), value)
                self.assertEqual(list(self.directory.iterdir()), [self.state])

    def test_encoding_key_is_refused_in_every_group_without_rewriting(self):
        for key in ('Encoding', 'encoding', 'ENCODING', 'EnCoDiNg'):
            for encoding in ('ISO-8859-1', 'UTF-8'):
                layouts = [f'[main]\n{key}={encoding}\nWirelessEnabled=true\n',
                           f'[extra]\n{key}={encoding}\n[main]\nWirelessEnabled=true\n',
                           f'[main]\nWirelessEnabled=true\n[extra]\n{key}={encoding}\n']
                for text in layouts:
                    with self.subTest(text=text):
                        value = text.encode(); self.write(value)
                        with self.assertRaisesRegex(gate.GateError, 'Encoding declarations'):
                            self.run_gate()
                        self.assertEqual(self.state.read_bytes(), value)
                        self.assertEqual(list(self.directory.iterdir()), [self.state])

    def test_unicode_line_separator_in_unknown_value_is_preserved_not_reparsed(self):
        value = '[main]\nWirelessEnabled=true\nOpaque=A\u2028[main]\u0085B\n'.encode()
        self.write(value); self.run_gate()
        self.assertEqual(self.state.read_bytes(), value.replace(b'WirelessEnabled=true', b'WirelessEnabled=false'))

    def test_unicode_separators_cannot_hide_absent_real_wireless_key(self):
        for separator in ('\u0085', '\u2028', '\u2029'):
            with self.subTest(separator=separator):
                value = ('[main]\nCustom=value' + separator + 'WirelessEnabled=true\n').encode()
                self.write(value); self.run_gate()
                self.assertEqual(self.state.read_bytes(), value + b'WirelessEnabled=false\n')

    def test_non_ascii_whitespace_in_ini_syntax_is_refused(self):
        for text in ('[main]\u00a0\nWirelessEnabled=true\n',
                     '\u00a0[main]\nWirelessEnabled=true\n',
                     '[main]\nWirelessEnabled\u00a0=true\n',
                     '[main]\nWirelessEnabled=true\u00a0\n'):
            with self.subTest(text=text):
                value = text.encode(); self.write(value)
                with self.assertRaises(gate.GateError):
                    self.run_gate()
                self.assertEqual(self.state.read_bytes(), value)

    def test_oversize_source_or_result_refused_without_changes(self):
        too_large = b'[main]\nFoo=' + b'a' * gate.MAX_STATE_BYTES
        self.write(too_large)
        with self.assertRaises(gate.GateError):
            self.run_gate()
        self.assertEqual(self.state.read_bytes(), too_large)
        full = b'[main]\nFoo=' + b'a' * (gate.MAX_STATE_BYTES - len(b'[main]\nFoo='))
        self.write(full)
        with self.assertRaises(gate.GateError):
            self.run_gate()
        self.assertEqual(self.state.read_bytes(), full)

    def test_symlink_hardlink_fifo_and_writable_state_refused(self):
        outside = self.root / 'outside'; outside.write_bytes(b'keep'); outside.chmod(0o600)
        self.state.unlink(); self.state.symlink_to(outside)
        with self.assertRaises(gate.GateError):
            self.run_gate()
        self.state.unlink(); os.link(outside, self.state)
        with self.assertRaises(gate.GateError):
            self.run_gate()
        self.state.unlink(); os.mkfifo(self.state, 0o600)
        with self.assertRaises(gate.GateError):
            self.run_gate()
        self.state.unlink(); self.write(b'[main]\nWirelessEnabled=true\n', mode=0o666)
        with self.assertRaises(gate.GateError):
            self.run_gate()
        self.assertEqual(outside.read_bytes(), b'keep')

    def test_unsafe_root_parent_and_internal_directories_refused(self):
        alias = self.root.parent / (self.root.name + '-alias')
        alias.symlink_to(self.root); self.addCleanup(alias.unlink)
        with self.assertRaises(gate.GateError):
            gate.set_wireless_disabled(alias, owner_uid=os.geteuid())
        with self.assertRaises(gate.GateError):
            gate.set_wireless_disabled(alias / 'var', owner_uid=os.geteuid())
        self.directory.chmod(0o777)
        with self.assertRaises(gate.GateError):
            self.run_gate()
        self.directory.chmod(0o755)
        self.directory.rename(self.directory.with_name('saved'))
        self.directory.symlink_to(self.directory.with_name('saved'))
        with self.assertRaises(gate.GateError):
            self.run_gate()
        with self.assertRaises(gate.GateError):
            gate.set_wireless_disabled(self.root, owner_uid=os.geteuid() + 1)

    def test_simulated_crash_boundaries_leave_only_old_or_complete_new_state(self):
        original = b'[main]\nWirelessEnabled=true\n'
        for stage in ('state:temp_fsynced', 'state:replaced', 'state:directory_fsynced'):
            with self.subTest(stage=stage):
                self.write(original)
                def crash(current):
                    if current == stage:
                        raise SimulatedCrash
                with self.assertRaises(SimulatedCrash):
                    self.run_gate(checkpoint=crash)
                expected = original if stage == 'state:temp_fsynced' else b'[main]\nWirelessEnabled=false\n'
                self.assertEqual(self.state.read_bytes(), expected)
                self.assertEqual(list(self.directory.iterdir()), [self.state])
                self.assertTrue(self.run_gate()['durably_written'])

    def test_fsync_failures_do_not_report_success_and_retry_recommits(self):
        original_fsync = gate.os.fsync
        for fail_at in (1, 2):
            with self.subTest(fail_at=fail_at):
                self.write(b'[main]\nWirelessEnabled=true\n'); calls = []
                def fsync(fd):
                    calls.append(fd)
                    if len(calls) == fail_at:
                        raise OSError('injected fsync failure')
                    return original_fsync(fd)
                with patch.object(gate.os, 'fsync', fsync), self.assertRaises(gate.GateError):
                    self.run_gate()
                self.assertIn(self.state.read_bytes(), (b'[main]\nWirelessEnabled=true\n',
                                                       b'[main]\nWirelessEnabled=false\n'))
                self.assertTrue(self.run_gate()['durably_written'])

    @unittest.skipUnless(sys.platform.startswith('linux'), 'GLib parser oracle requires Linux')
    def test_linux_glib_reads_actual_false_without_missing_key_error(self):
        import ctypes
        import ctypes.util
        library = ctypes.util.find_library('glib-2.0')
        if not library:
            self.skipTest('Installed GLib library unavailable')
        try:
            glib = ctypes.CDLL(library)
        except OSError:
            self.skipTest('Installed GLib library cannot be loaded')
        # Official ABI: docs.gtk.org/glib/method.KeyFile.load_from_data.html
        # and docs.gtk.org/glib/method.KeyFile.get_boolean.html. gboolean is int;
        # false alone is insufficient because an absent key also returns false.
        error_pointer = ctypes.POINTER(ctypes.c_void_p)
        glib.g_key_file_new.argtypes = []; glib.g_key_file_new.restype = ctypes.c_void_p
        glib.g_key_file_free.argtypes = [ctypes.c_void_p]; glib.g_key_file_free.restype = None
        glib.g_error_free.argtypes = [ctypes.c_void_p]; glib.g_error_free.restype = None
        glib.g_key_file_load_from_data.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                                  ctypes.c_size_t, ctypes.c_int, error_pointer]
        glib.g_key_file_load_from_data.restype = ctypes.c_int
        glib.g_key_file_get_boolean.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                                ctypes.c_char_p, error_pointer]
        glib.g_key_file_get_boolean.restype = ctypes.c_int
        # Negative control from GLib 2.84.1 gkeyfile.c: merely forcing the
        # boolean to false cannot repair a first-group Encoding load failure.
        counterexample = b'[main]\nEncoding=ISO-8859-1\nWirelessEnabled=false\n'
        key_file = glib.g_key_file_new(); self.assertTrue(key_file)
        error = ctypes.c_void_p()
        try:
            loaded = glib.g_key_file_load_from_data(key_file, counterexample, len(counterexample), 0,
                                                    ctypes.byref(error))
            self.assertEqual(loaded, 0, 'Expected GLib Encoding load failure')
            self.assertIsNotNone(error.value, 'Encoding failure must carry GError')
        finally:
            if error.value is not None:
                glib.g_error_free(error)
            glib.g_key_file_free(key_file)
        with self.assertRaisesRegex(gate.GateError, 'Encoding declarations'):
            gate.disabled_state(counterexample)
        cases = {
            'enabled': b'[main]\nWirelessEnabled=true\n',
            'already-disabled': b'[main]\nWirelessEnabled=false\n',
            'missing-file': None,
            'missing-key': b'[main]\nNetworkingEnabled=true\n',
            'extra-section': b'[main]\nWirelessEnabled=true\n[other]\nWirelessEnabled=true\n',
            'crlf': b'[main]\r\nNetworkingEnabled=true\r\nWirelessEnabled = true\r\nWWANEnabled=false\r\n',
        }
        for separator in ('\u0085', '\u2028', '\u2029'):
            cases[f'embedded-{ord(separator):x}'] = (
                '[main]\nCustom=value' + separator + 'WirelessEnabled=true\n').encode()
        for name, raw in cases.items():
            with self.subTest(case=name):
                payload = gate.disabled_state(raw)
                key_file = glib.g_key_file_new(); self.assertTrue(key_file)
                error = ctypes.c_void_p()
                try:
                    loaded = glib.g_key_file_load_from_data(key_file, payload, len(payload), 0,
                                                            ctypes.byref(error))
                    self.assertNotEqual(loaded, 0, 'GLib rejected gate output')
                    self.assertIsNone(error.value, 'GLib load returned GError')
                    enabled = glib.g_key_file_get_boolean(key_file, b'main', b'WirelessEnabled',
                                                          ctypes.byref(error))
                    self.assertIsNone(error.value, 'False must represent a present valid key, not GError')
                    self.assertEqual(enabled, 0, 'GLib still considers Wi-Fi enabled')
                finally:
                    if error.value is not None:
                        glib.g_error_free(error)
                    glib.g_key_file_free(key_file)

    def test_direct_execution_refuses_inactive_entry_without_touching_fixture(self):
        before = self.state.read_bytes()
        script = Path(__file__).parents[1] / 'scripts/wifi-boot-gate.py'
        for arguments in ([], ['--root', str(self.root)]):
            with self.subTest(arguments=arguments):
                result = subprocess.run([sys.executable, str(script), *arguments], cwd=self.root,
                                        capture_output=True, text=True, timeout=5,
                                        env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertEqual(result.stderr, 'Inactive fixture module; no runtime entry point is installed.\n')
                self.assertEqual(self.state.read_bytes(), before)
                self.assertEqual(list(self.directory.iterdir()), [self.state])

    def test_ble_country_boot_and_identity_files_are_untouched(self):
        sentinels = {'var/lib/bluetooth/fixture': b'BLE', 'var/lib/inkyos/country.json': b'country',
                     'boot/firmware/cmdline.txt': b'resize', 'etc/machine-id': b'identity'}
        for relative, content in sentinels.items():
            path = self.root / relative; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        self.run_gate()
        for relative, content in sentinels.items():
            self.assertEqual((self.root / relative).read_bytes(), content)


if __name__ == '__main__':
    unittest.main()
