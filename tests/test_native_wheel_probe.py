import base64
import csv
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('native_probe', Path(__file__).parents[1]/'scripts/probe-native-wheels-linux.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class NativeWheelChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.wheel = self.root/'spidev-3.8-cp313-cp313-linux_aarch64.whl'

    def fixture(self, *, pure=False, tag='cp313-cp313-linux_aarch64', bad_record=False, machine=183):
        elf = bytearray(64); elf[:6] = b'\x7fELF\x02\x01'; elf[18:20] = machine.to_bytes(2,'little')
        prefix = 'spidev-3.8.dist-info/'
        files = {prefix+'WHEEL':f'Wheel-Version: 1.0\nRoot-Is-Purelib: {str(pure).lower()}\nTag: {tag}\n'.encode(),
                 prefix+'METADATA':b'Name: spidev\nVersion: 3.8\n'}
        if not pure: files['spidev.cpython-313-aarch64-linux-gnu.so'] = bytes(elf)
        rows = io.StringIO(); writer = csv.writer(rows)
        for name,data in files.items():
            hashed = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')
            writer.writerow([name,'sha256='+('0'*len(hashed) if bad_record else hashed),str(len(data))])
        writer.writerow([prefix+'RECORD','','']); files[prefix+'RECORD'] = rows.getvalue().encode()
        with zipfile.ZipFile(self.wheel,'w') as archive:
            for name,data in files.items(): archive.writestr(name,data)

    def test_native_headers_and_record_are_required(self):
        self.fixture()
        result = probe.verify_wheel(self.wheel,'spidev-3.8.tar.gz')
        self.assertEqual(result['native_objects'][0]['elf_machine'],'AArch64')
        for kwargs in ({'pure':True},{'tag':'py3-none-any'},{'bad_record':True},{'machine':62}):
            with self.subTest(kwargs=kwargs):
                self.fixture(**kwargs)
                with self.assertRaises(ValueError): probe.verify_wheel(self.wheel,'spidev-3.8.tar.gz')

    def test_nonregular_wheel_does_not_open_fifo_or_follow_symlink(self):
        if hasattr(os,'mkfifo'):
            os.mkfifo(self.wheel)
            with self.assertRaises(ValueError): probe.verify_wheel(self.wheel,'spidev-3.8.tar.gz')
            self.wheel.unlink()
        target = self.root/'target'; target.write_bytes(b'not a wheel'); self.wheel.symlink_to(target)
        with self.assertRaises(ValueError): probe.verify_wheel(self.wheel,'spidev-3.8.tar.gz')

    def test_extra_or_duplicate_members_rejected(self):
        self.fixture()
        with zipfile.ZipFile(self.wheel,'a') as archive: archive.writestr('../escape',b'bad')
        with self.assertRaises(ValueError): probe.verify_wheel(self.wheel,'spidev-3.8.tar.gz')
        self.fixture()
        with zipfile.ZipFile(self.wheel,'a') as archive: archive.writestr('unrecorded.py',b'bad')
        with self.assertRaises(ValueError): probe.verify_wheel(self.wheel,'spidev-3.8.tar.gz')

    def test_expanding_member_refused_before_reading_it(self):
        with zipfile.ZipFile(self.wheel,'w',compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('oversized',b'0'*(8*1024**2+1))
        with self.assertRaises(ValueError): probe.verify_wheel(self.wheel,'spidev-3.8.tar.gz')

    def test_wrong_filename_tag_rejected(self):
        self.fixture()
        other = self.wheel.with_name('spidev-3.8-py3-none-any.whl'); self.wheel.rename(other)
        with self.assertRaises(ValueError): probe.verify_wheel(other,'spidev-3.8.tar.gz')
