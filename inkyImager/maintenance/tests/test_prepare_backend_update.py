import base64
import copy
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).resolve().parents[1] / 'prepare-backend-update.py'
SPEC = importlib.util.spec_from_file_location('maintenance_editor', SCRIPT)
editor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(editor)
MKE2FS = '/opt/homebrew/opt/e2fsprogs/sbin/mke2fs'
DIST = 'inky_studio_server-0.5.0rc2.dist-info/'


def csv_bytes(rows):
    out = io.StringIO(newline='')
    csv.writer(out, lineterminator='\n').writerows(rows)
    return out.getvalue().encode()


class Fixture:
    def __init__(self, root):
        self.root = root
        self.host = root / 'host'
        self.host.mkdir(mode=0o700)
        self.site = editor.STUDIO + '/' + editor.SITE
        self.old = {name: ('old:' + name + '\n').encode() for name in sorted(editor.MEMBERS)}
        self.new = {name: ('new reviewed:' + name + '\n').encode() for name in sorted(editor.MEMBERS)}
        meta = b'Metadata-Version: 2.1\nName: inky-studio-server\nVersion: 0.5.0rc2\n'
        self.record_name = DIST + 'RECORD'
        self.record_path = self.site + self.record_name
        old_rows = [[name, editor.record_digest(data), str(len(data))] for name, data in sorted(self.old.items())]
        old_rows += [[DIST + 'METADATA', editor.record_digest(meta), str(len(meta))], [self.record_name, '', '']]
        self.extra = b'custom-extra,"sha256=local-extra",42\r\n' + b'"INSTALLER",,\n'
        self.old_record = csv_bytes(old_rows) + self.extra
        files = {self.site + name: data for name, data in self.old.items()}
        files.update({
            self.record_path: self.old_record,
            self.site + DIST + 'METADATA': meta,
            self.site + 'some_dependency/core.py': b'untouched dependency\n',
            self.site + 'inky_web/__pycache__/legacy.pyc': b'local cached bytes\n',
            '/var/lib/inky-studio/photos/keep.jpg': b'fixture photo bytes, no real image',
            '/var/lib/inky-studio/inky_studio.db': b'fixture database, not a real credential store',
            '/var/lib/inky-studio/photo-access/access.sqlite3': b'fixture photo sessions',
            '/var/lib/inky-studio/provisioning/identity.json': b'{"fixture":"identity"}\n',
            '/var/lib/inky-studio/provisioning/tls/key.pem': b'NOT A REAL KEY\n',
            '/var/lib/inky-studio/credentials.json': b'{"fixture":"credential"}\n',
            '/etc/NetworkManager/system-connections/inky-home.nmconnection': b'fixture network only\n',
            '/var/lib/inkyos/imager-network.json': b'{"fixture":"network-receipt"}\n',
            '/etc/hostname': b'inky-fixture\n', '/etc/machine-id': b'fixture-machine-id\n',
            '/usr/lib/systemd/system/inky-studio.service': (
                b'[Service]\nUser=inky\nNoNewPrivileges=yes\n'
                b'ExecStart=/usr/lib/inky-studio/server/.venv/bin/python3 -I -B -m inky_web.imager_lan\n'),
            '/etc/inky-studio/imager.env': (
                b'INKY_STUDIO_DATA_DIR="/var/lib/inky-studio"\nINKY_STUDIO_DISPLAY_MODE="hardware"\n'
                b'INKY_STUDIO_DISPLAY_PROFILE="ac073-800x480-timed-wait"\n'),
        })
        for name, data in files.items():
            path = self.host / name.lstrip('/')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data); path.chmod(0o644)
        for directory, dirs, children in os.walk(self.host):
            Path(directory).chmod(0o755)
        (self.host / 'etc/fixture-short-link').symlink_to('../var/lib/inky-studio/credentials.json')
        (self.host / 'etc/fixture-long-link').symlink_to('/' + 'a' * 100)
        self.image = root / 'fixture.img'
        with self.image.open('wb') as stream:
            stream.truncate(32 * 1024 * 1024)
        self.image.chmod(0o600)
        subprocess.run([MKE2FS, '-q', '-t', 'ext4', '-F', '-d', str(self.host), str(self.image)],
                       check=True, capture_output=True)
        commands = []
        for name in files:
            if name.startswith(editor.STUDIO + '/'):
                commands += ['set_inode_field {} uid 0'.format(name), 'set_inode_field {} gid 0'.format(name)]
        # The baseline root is root-owned too; user data remains deliberately UID501.
        commands += ['set_inode_field {} uid 0'.format(editor.STUDIO),
                     'set_inode_field {} gid 0'.format(editor.STUDIO), 'mknod fixture-device c 1 3']
        commands_file = root / 'fixture-commands'
        commands_file.write_text('\n'.join(commands) + '\n')
        subprocess.run([str(editor.DEBUGFS), '-w', '-f', str(commands_file), str(self.image)],
                       check=True, capture_output=True)
        self.manifest = {'base_commit': editor.BASE, 'source_commit': editor.TARGET,
                         'database_schema_version': 1, 'database_migration': False,
                         'installed_RECORD_policy': {
                             'replace_installed_RECORD_with_wheel_RECORD': False,
                             'require_observed_three_old_module_hashes_before_change': True,
                             'update_only_existing_three_module_rows_to_new_sha256_and_size': True,
                             'preserve_all_other_local_rows_and_extras': True}, 'modules': []}
        for name in sorted(self.old):
            self.manifest['modules'].append({
                'installed_path_relative_to_studio_root': editor.SITE + name, 'wheel_member': name,
                'before': {'sha256': editor.sha(self.old[name]), 'size_bytes': len(self.old[name])},
                'after': {'sha256': editor.sha(self.new[name]), 'size_bytes': len(self.new[name])},
                'wheel_RECORD_before': [name, editor.record_digest(self.old[name]), str(len(self.old[name]))],
                'wheel_RECORD_after': [name, editor.record_digest(self.new[name]), str(len(self.new[name]))],
                'required_installed_metadata': {'mode': '0644', 'uid': 0, 'gid': 0,
                                                'xattrs': {'entries': {}, 'status': 'inspected'}}})
        self.reference = {'studio_commit': editor.BASE, 'records': {}}
        frozen = {editor.STUDIO: None}
        frozen.update({self.site + key: value for key, value in self.old.items()})
        frozen.update({self.record_path: csv_bytes(old_rows), self.site + DIST + 'METADATA': meta,
                       self.site + 'some_dependency/core.py': files[self.site + 'some_dependency/core.py']})
        for name, data in frozen.items():
            relative = '.' if name == editor.STUDIO else name[len(editor.STUDIO) + 1:]
            record = {'type': 'directory' if data is None else 'file', 'mode': '0755' if data is None else '0644',
                      'uid': 0, 'gid': 0, 'xattrs': {'entries': {}, 'status': 'inspected'}}
            if data is not None:
                record.update(sha256=editor.sha(data), size_bytes=len(data))
            self.reference['records'][relative] = record
        self.payload = {self.site + name: value for name, value in self.new.items()}
        self.manifest_path = root / 'delta.json'
        self.reference_path = root / 'reference.json'
        editor.write_private(self.manifest_path, editor.canonical(self.manifest))
        editor.write_private(self.reference_path, editor.canonical(self.reference))
        self.wheel = root / 'fixture.whl'
        members = dict(self.new); members[DIST + 'METADATA'] = meta
        new_rows = [[name, editor.record_digest(data), str(len(data))] for name, data in sorted(members.items())]
        new_rows.append([self.record_name, '', ''])
        members[self.record_name] = csv_bytes(new_rows)
        with zipfile.ZipFile(self.wheel, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, raw in members.items():
                archive.writestr(name, raw)
        self.wheel.chmod(0o600)

    def load(self):
        return editor.load_package(self.manifest_path, editor.hash_file(self.manifest_path), self.wheel,
                                   editor.hash_file(self.wheel), self.reference_path, editor.hash_file(self.reference_path))

    def log(self, name):
        path = self.root / name
        path.mkdir(mode=0o700)
        return path

    def acquisition(self, workspace):
        capacity = 2 * 1024 * 1024 + self.image.stat().st_size + 512
        mbr = bytearray(512)
        mbr[510:] = b'\x55\xaa'
        for index, kind, start, count in [(0, 0x0c, 2048, 2048), (1, 0x83, 4096, self.image.stat().st_size // 512)]:
            at = 446 + index * 16; mbr[at + 4] = kind; struct.pack_into('<II', mbr, at + 8, start, count)
        backup = workspace / 'sd-backup.img'
        with backup.open('wb') as stream:
            stream.write(mbr); stream.write(b'B' * (2 * 1024 * 1024 - 512))
            with self.image.open('rb') as source:
                shutil.copyfileobj(source, stream)
            stream.write(b'S' * 512)
        backup.chmod(0o600)
        geo = editor.geometry(bytes(mbr), capacity)
        receipt = {'schemaVersion': 1, 'kind': 'inkyos-maintenance-acquisition', 'operationID': 'fixture',
                   'status': 'complete', 'target': {'id': 'disk999999', 'name': 'fixture only',
                   'capacity': capacity, 'registryID': 123}, 'backupFile': backup.name, 'geometry': geo,
                   'hashes': editor.backup_hashes(backup, geo), 'localReadbackVerified': True,
                   'rawOpenedReadOnly': True, 'sdWritesIssued': False, 'limits': []}
        path = workspace / 'acquisition.json'
        editor.write_private(path, editor.canonical(receipt))
        return backup, path, editor.hash_file(path)


class RecordTests(unittest.TestCase):
    def test_only_three_rows_change_with_local_bytes_preserved(self):
        modules = [{'wheel_member': key, 'wheel_RECORD_before': [key, 'old', '1'],
                    'wheel_RECORD_after': [key, 'new', '2']} for key in ('a', 'b', 'c')]
        raw = b'a,old,1\r\n"INSTALLER",,\n"b",old,1\nc,old,1\n"local,extra",,\r\n'
        result = editor.update_record(raw, modules)
        self.assertEqual(result, b'a,new,2\r\n"INSTALLER",,\nb,new,2\nc,new,2\n"local,extra",,\r\n')

    def test_duplicate_or_missing_target_refused(self):
        module = [{'wheel_member': 'a', 'wheel_RECORD_before': ['a', 'old', '1'],
                   'wheel_RECORD_after': ['a', 'new', '2']}]
        for raw in (b'a,old,1\na,old,1\n', b'other,,\n', b'a,wrong,1\n'):
            with self.assertRaises(ValueError):
                editor.update_record(raw, module)


@unittest.skipUnless(Path(MKE2FS).is_file() and editor.DEBUGFS.is_file() and editor.FSCK.is_file(),
                     'Reviewed local e2fsprogs tools required for regular-file fixtures')
class Ext4Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='inky-maintenance-test-', dir='/private/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = Fixture(self.root)

    def test_full_prepare_preserves_source_and_user_state(self):
        workspace = self.root / 'workspace'; workspace.mkdir(mode=0o700)
        backup, receipt, receipt_sha = self.fixture.acquisition(workspace)
        source_hash = editor.hash_file(backup)
        result = editor.prepare(workspace, receipt, receipt_sha, self.fixture.manifest_path,
                                editor.hash_file(self.fixture.manifest_path), self.fixture.wheel,
                                editor.hash_file(self.fixture.wheel), self.fixture.reference_path,
                                editor.hash_file(self.fixture.reference_path))
        self.assertEqual(result['changedFiles'], 4)
        self.assertFalse(result['SDWritesIssued'])
        self.assertEqual(editor.hash_file(backup), source_hash)
        candidate = workspace / 'root-candidate.img'
        self.assertEqual(stat.S_IMODE(candidate.stat().st_mode), 0o400)
        approval = json.loads((workspace / 'candidate-approval.json').read_text())
        self.assertTrue(approval['preservationVerified'])
        request = json.loads((workspace / 'write-root-request.json').read_text())
        self.assertEqual(request['candidateApprovalSHA256'], editor.hash_file(workspace / 'candidate-approval.json'))
        before = json.loads((workspace / 'preparation/baseline-inventory.json').read_text())
        after = json.loads((workspace / 'preparation/after-inventory.json').read_text())
        for name in before:
            if name.startswith(('/var/', '/etc/')):
                self.assertEqual(before[name], after[name], name)

    def test_old_hash_mismatch_refuses_before_modification(self):
        manifest, reference, payload, record_path = self.fixture.load()
        reference['records'][editor.SITE + 'inky_web/main.py']['sha256'] = '0' * 64
        before = editor.hash_file(self.fixture.image)
        with self.assertRaisesRegex(ValueError, 'baseline bytes'):
            editor.apply_to_copy(self.fixture.image, manifest, reference, payload, record_path, self.fixture.log('hash-refusal'))
        self.assertEqual(editor.hash_file(self.fixture.image), before)

    def test_duplicate_installed_record_refuses_before_modification(self):
        manifest, reference, payload, record_path = self.fixture.load()
        fs = editor.Ext4(self.fixture.image)
        duplicated = self.fixture.old_record + csv_bytes([manifest['modules'][0]['wheel_RECORD_before']])
        fs.replace(record_path, duplicated, self.fixture.log('seed-record'))
        before = editor.hash_file(self.fixture.image)
        with self.assertRaisesRegex(ValueError, 'duplicate RECORD'):
            editor.apply_to_copy(self.fixture.image, manifest, reference, payload, record_path, self.fixture.log('record-refusal'))
        self.assertEqual(editor.hash_file(self.fixture.image), before)

    def test_forbidden_delta_path_refused(self):
        manifest = copy.deepcopy(self.fixture.manifest)
        manifest['modules'][0]['installed_path_relative_to_studio_root'] = '../../etc/machine-id'
        self.fixture.manifest_path.write_bytes(editor.canonical(manifest))
        with self.assertRaises(ValueError):
            self.fixture.load()

    def test_protected_file_corruption_detected(self):
        manifest, reference, payload, record_path = self.fixture.load()
        original = editor.Ext4.replace
        changed = [False]
        def faulty(fs, path, data, workspace):
            original(fs, path, data, workspace)
            if not changed[0]:
                changed[0] = True
                fs.command('set_inode_field /etc/hostname uid 1000', write=True)
        with patch.object(editor.Ext4, 'replace', faulty):
            with self.assertRaisesRegex(ValueError, 'protected file'):
                editor.apply_to_copy(self.fixture.image, manifest, reference, payload, record_path, self.fixture.log('corruption'))

    def test_geometry_and_acquisition_pin_refused(self):
        workspace = self.root / 'workspace'; workspace.mkdir(mode=0o700)
        backup, receipt, receipt_sha = self.fixture.acquisition(workspace)
        with backup.open('r+b') as stream:
            stream.seek(100); stream.write(b'changed')
        with self.assertRaises(ValueError):
            editor.load_acquisition(workspace, receipt, receipt_sha)
        with self.assertRaises(ValueError):
            editor.geometry(bytes(512), backup.stat().st_size)

    def test_journal_recovery_happens_only_on_candidate(self):
        editor.Ext4(self.fixture.image).command('feature needs_recovery', write=True)
        workspace = self.root / 'journal-workspace'; workspace.mkdir(mode=0o700)
        backup, receipt, receipt_sha = self.fixture.acquisition(workspace)
        original = editor.hash_file(backup)
        result = editor.prepare(workspace, receipt, receipt_sha, self.fixture.manifest_path,
                                editor.hash_file(self.fixture.manifest_path), self.fixture.wheel,
                                editor.hash_file(self.fixture.wheel), self.fixture.reference_path,
                                editor.hash_file(self.fixture.reference_path))
        self.assertTrue(result['copyJournalRecovered'])
        self.assertEqual(editor.hash_file(backup), original)
        self.assertTrue((workspace / 'preparation/fsck-copy-recovery.txt').is_file())

    def seed_xattr(self, fs, target, name, value):
        path = self.root / 'xattr-fixture-value'
        path.write_bytes(value); path.chmod(0o600)
        fs.command('ea_set -f "{}" {} {}'.format(path, target, name), write=True)

    def test_long_xattr_complete_value_changes_digest_despite_identical_listing(self):
        fs = editor.Ext4(self.fixture.image)
        inode = fs.inventory()['/etc/hostname']['inode']
        for size in (64, 128):
            with self.subTest(size=size):
                self.seed_xattr(fs, '/etc/hostname', 'user.example', b'A' * size)
                listing = fs.command('ea_list /etc/hostname')
                before = fs.xattr_digest(inode)
                self.seed_xattr(fs, '/etc/hostname', 'user.example', b'A' * (size - 1) + b'B')
                self.assertEqual(fs.command('ea_list /etc/hostname'), listing)
                self.assertNotEqual(fs.xattr_digest(inode), before)
        self.assertEqual(list(self.root.glob('.xattr-*')), [])

    def test_long_xattrs_are_preserved_without_values_in_inventory(self):
        manifest, reference, payload, record_path = self.fixture.load()
        fs = editor.Ext4(self.fixture.image)
        self.seed_xattr(fs, '/etc/hostname', 'user.example64', b'A' * 64)
        self.seed_xattr(fs, '/var/lib/inky-studio/credentials.json', 'user.example128', b'C' * 128)
        before = fs.inventory()
        log = self.fixture.log('xattr-preservation')
        result = editor.apply_to_copy(self.fixture.image, manifest, reference, payload, record_path, log)
        self.assertTrue(result['preservationVerified'])
        after = fs.inventory()
        for path in ('/etc/hostname', '/var/lib/inky-studio/credentials.json'):
            self.assertEqual(before[path]['xattrs_sha256'], after[path]['xattrs_sha256'])
        for file in log.glob('*inventory.json'):
            self.assertNotIn(b'A' * 64, file.read_bytes())
            self.assertNotIn(b'C' * 128, file.read_bytes())

    def test_same_length_long_xattr_corruption_is_detected(self):
        manifest, reference, payload, record_path = self.fixture.load()
        fs = editor.Ext4(self.fixture.image)
        self.seed_xattr(fs, '/etc/hostname', 'user.example', b'A' * 128)
        original = editor.Ext4.replace
        changed = [False]
        def faulty(instance, path, data, workspace):
            original(instance, path, data, workspace)
            if not changed[0]:
                changed[0] = True
                self.seed_xattr(instance, '/etc/hostname', 'user.example', b'A' * 127 + b'B')
        with patch.object(editor.Ext4, 'replace', faulty):
            with self.assertRaisesRegex(ValueError, 'protected file'):
                editor.apply_to_copy(self.fixture.image, manifest, reference, payload, record_path,
                                     self.fixture.log('xattr-corruption'))


if __name__ == '__main__':
    unittest.main()
