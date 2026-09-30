import copy
import errno
import hashlib
import importlib.util
import os
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    'flash_sd', Path(__file__).resolve().parents[1] / 'scripts/flash-sd-macos.py')
flash = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flash)


class FlashTests(unittest.TestCase):
    def setUp(self):
        self.media = {'DeviceIdentifier': 'disk6', 'DeviceNode': '/dev/disk6',
                      'WholeDisk': True, 'VirtualOrPhysical': 'Physical',
                      'BusProtocol': 'Secure Digital', 'Removable': True,
                      'Ejectable': True, 'Writable': True, 'OSInternalMedia': False,
                      'IOKitSize': 128000000000}
        self.registry = {'BSD Name': 'disk6', 'Whole': True, 'Removable': True,
                         'Ejectable': True, 'Size': 128000000000,
                         'IORegistryEntryID': 4294970729}
        self.expected = {'device': 'disk6', 'capacity_bytes': 128000000000,
                         'registry_id': 4294970729}

    def command(self, argv):
        if argv[0].endswith('diskutil'):
            return plistlib.dumps(self.media)
        return plistlib.dumps([{'IORegistryEntryChildren': [self.registry]}])

    def test_builtin_sd_is_accepted_without_allowing_system_disk(self):
        self.media['Internal'] = True
        self.assertEqual(flash.media_record('disk6', self.command), self.expected)
        self.media.update(Removable=False, OSInternalMedia=True)
        with self.assertRaises(flash.Refused):
            flash.media_record('disk6', self.command)

    def test_targets_must_be_whole_real_writable_removable_sd(self):
        variants = [('WholeDisk', False), ('BusProtocol', 'Disk Image'),
                    ('VirtualOrPhysical', 'Virtual'), ('Writable', False),
                    ('Ejectable', False), ('DeviceIdentifier', 'disk0'),
                    ('DeviceNode', '/dev/disk0'), ('IOKitSize', 127)]
        for key, value in variants:
            with self.subTest(key=key):
                original = self.media
                self.media = copy.deepcopy(original)
                self.media[key] = value
                with self.assertRaises(flash.Refused):
                    flash.media_record('disk6', self.command)
                self.media = original
        for device in ('disk6s1', '/dev/disk6', 'disk6;true', 'disk-1'):
            with self.assertRaises(flash.Refused):
                flash.media_record(device, self.command)

    def test_live_media_identity_rejects_reinsertion_even_at_same_capacity(self):
        observed = dict(self.expected, registry_id=self.expected['registry_id'] + 1)
        with self.assertRaises(flash.Refused):
            flash.require_same(observed, self.expected)

    def test_registry_duplicate_and_non_whole_media_are_rejected(self):
        with self.assertRaises(flash.Refused):
            flash.media_record('disk6', lambda argv: plistlib.dumps(self.media)
                               if argv[0].endswith('diskutil') else
                               plistlib.dumps([self.registry, self.registry]))
        self.registry['Whole'] = False
        with self.assertRaises(flash.Refused):
            flash.media_record('disk6', self.command)

    def test_image_hash_pin_and_symlink_are_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'image'
            source.write_bytes(b'fixture bytes')
            pin = hashlib.sha256(source.read_bytes()).hexdigest()
            fd, info = flash.open_image(str(source), pin)
            try:
                self.assertEqual(os.read(fd, info.st_size), b'fixture bytes')
                # Size changes are deterministic even when a filesystem's
                # timestamp resolution groups two immediate writes together.
                source.write_bytes(b'changed fixture bytes')
                with self.assertRaises(flash.Refused):
                    flash.require_unchanged(fd, info)
            finally:
                os.close(fd)
            with self.assertRaises(flash.Refused):
                flash.open_image(str(source), pin)
            link = Path(tmp) / 'link'
            link.symlink_to(source)
            with self.assertRaises(OSError):
                flash.open_image(str(link), pin)

    def test_default_preflight_never_unmounts_or_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'image'
            source.write_bytes(b'fixture bytes')
            pin = hashlib.sha256(source.read_bytes()).hexdigest()
            with patch.object(flash.platform, 'system', return_value='Darwin'), \
                    patch.object(flash, 'media_record', return_value=self.expected), \
                    patch.object(flash, 'run') as command:
                report = flash.flash(str(source), pin, self.expected)
                command.assert_not_called()
                self.assertFalse(report['card_written'])
                self.assertFalse(report['readback_verified'])

    def test_image_too_large_is_rejected_before_any_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'image'
            source.write_bytes(b'fixture bytes')
            pin = hashlib.sha256(source.read_bytes()).hexdigest()
            selected = dict(self.expected, capacity_bytes=2)
            with patch.object(flash.platform, 'system', return_value='Darwin'), \
                    patch.object(flash, 'media_record', return_value=selected), \
                    patch.object(flash, 'run') as command:
                with self.assertRaises(flash.Refused):
                    flash.flash(str(source), pin, selected, write=True)
                command.assert_not_called()

    def test_partial_writes_and_readback_verify_exact_prefix(self):
        with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as target:
            payload = b'abc' * 1000
            source.write(payload)
            source.seek(0)
            write = os.write
            with patch.object(flash.os, 'write', side_effect=lambda fd, block: write(fd, block[:17])):
                observed = flash.write_image(source.fileno(), target.fileno(), len(payload))
            expected = hashlib.sha256(payload).hexdigest()
            self.assertEqual(observed, expected)
            self.assertEqual(flash.readback(target.fileno(), len(payload)), expected)
            target.seek(0)
            target.write(b'different')
            target.flush()
            self.assertNotEqual(flash.readback(target.fileno(), len(payload)), expected)

    def test_early_eof_is_rejected_for_source_and_readback(self):
        with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as target:
            source.write(b'abc')
            source.seek(0)
            with self.assertRaises(flash.Refused):
                flash.write_image(source.fileno(), target.fileno(), 4)
            with self.assertRaises(flash.Refused):
                flash.readback(target.fileno(), 4)

    def test_exclusive_raw_device_lock_is_required_before_write(self):
        with patch.object(flash.os, 'O_EXLOCK', 0x20, create=True):
            flags = flash.raw_device_flags()
            self.assertEqual(flags & 0x20, 0x20)
            self.assertEqual(flags & os.O_NONBLOCK, os.O_NONBLOCK)
        with patch.object(flash.os, 'O_EXLOCK', None, create=True):
            with self.assertRaises(flash.Refused):
                flash.raw_device_flags()

    def test_driver_cache_sync_is_required_even_if_raw_fsync_unsupported(self):
        with patch.object(flash.os, 'fsync', side_effect=OSError(errno.EINVAL, 'fixture')), \
                patch.object(flash, 'run') as command, \
                patch.object(flash.fcntl, 'ioctl') as ioctl:
            flash.flush_card(42)
            command.assert_called_once_with(['/bin/sync'])
            ioctl.assert_called_once_with(42, 0x20006416)
        with patch.object(flash.os, 'fsync'), patch.object(flash, 'run'), \
                patch.object(flash.fcntl, 'ioctl', side_effect=OSError(errno.ENOTTY, 'fixture')):
            with self.assertRaises(OSError):
                flash.flush_card(42)


if __name__ == '__main__':
    unittest.main()
