import importlib.util
import io
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location(
    'application_installer', Path(__file__).parents[1] / 'scripts/install-application-rootfs.py')
installer = importlib.util.module_from_spec(spec); spec.loader.exec_module(installer)


class ApplicationRootfsInstallerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.assets = self.root / 'assets'; self.assets.mkdir()

    def bundle(self, members=None, lock=None, zip_entry=None):
        with tarfile.open(self.assets / 'app.tar.gz', 'w:gz') as archive:
            for entry in members or [('server/pyproject.toml', b'[project]\n')]:
                if isinstance(entry, tarfile.TarInfo):
                    archive.addfile(entry)
                else:
                    name, content = entry
                    info = tarfile.TarInfo(name); info.size = len(content)
                    archive.addfile(info, io.BytesIO(content))
        with zipfile.ZipFile(self.assets / 'wheels.zip', 'w') as archive:
            archive.writestr(zip_entry or 'fixture.whl', b'fixture')
        (self.assets / 'app.lock').write_text(
            lock if lock is not None else 'fixture==1.0 --hash=sha256:' + 'a' * 64 + '\n')
        return {'assets': [{'role': role, 'filename': name} for role, name in [
            ('application', 'app.tar.gz'), ('wheelhouse', 'wheels.zip'), ('python_lock', 'app.lock')]]}

    def extract(self, data, suffix=''):
        scratch = self.root / ('scratch' + suffix); scratch.mkdir()
        return installer.extract_inputs(data, self.assets, self.root / ('application' + suffix), scratch)

    def test_source_extracts_only_ordinary_flat_files_and_normalizes_mode(self):
        data = self.bundle()
        self.extract(data)
        source = self.root / 'application/server/pyproject.toml'
        self.assertEqual(source.read_bytes(), b'[project]\n')
        self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o644)

    def test_tar_symlink_hardlink_traversal_and_venv_are_rejected(self):
        bad_entries = []
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            info = tarfile.TarInfo('server/link'); info.type = kind; info.linkname = '/etc/passwd'
            bad_entries.append(info)
        bad_entries += [('../escape', b'bad'), ('server/.venv/bin/python', b'bad')]
        for index, entry in enumerate(bad_entries):
            with self.subTest(entry=entry):
                data = self.bundle([entry])
                with self.assertRaises(ValueError):
                    self.extract(data, str(index))
        self.assertFalse((self.root / 'escape').exists())

    def test_existing_destination_is_never_reused(self):
        data = self.bundle(); (self.root / 'application').mkdir()
        (self.root / 'application/sentinel').write_text('keep')
        with self.assertRaises(FileExistsError):
            self.extract(data)
        self.assertEqual((self.root / 'application/sentinel').read_text(), 'keep')

    def test_zip_symlink_and_duplicate_tar_collision_are_rejected(self):
        info = zipfile.ZipInfo('fixture.whl'); info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaisesRegex(ValueError, 'Ordinary zip'):
            self.extract(self.bundle(zip_entry=info))
        with self.assertRaisesRegex(ValueError, 'Duplicate archive path'):
            self.extract(self.bundle([('server/file', b'a'), ('server/file', b'b')]), '2')

    def test_lock_rejects_remote_local_options_duplicate_and_empty(self):
        cases = ['--index-url https://invalid.example', 'thing @ file:///tmp/foreign',
                 '-e ../project', 'thing>=1.0', '',
                 'Thing==1.0 --hash=sha256:' + 'a' * 64 + '\nthing==1.0 --hash=sha256:' + 'b' * 64]
        lock = self.root / 'requirements.lock'
        for value in cases:
            with self.subTest(value=value):
                lock.write_text(value)
                with self.assertRaises(ValueError):
                    installer.validate_lock(lock)
        lock.write_text('# comment\nthing==1.0 \\\n --hash=sha256:' + 'a' * 64 + '\n')
        installer.validate_lock(lock)

    def test_snapshot_rejects_fifo_hardlink_symlink_and_oversize(self):
        source = self.root / 'source'; target = self.root / 'copy'
        os.mkfifo(source)
        with self.assertRaises(ValueError):
            installer.copy_regular(source, target, 8)
        source.unlink(); source.write_bytes(b'bytes'); os.link(source, self.root / 'hardlink')
        with self.assertRaises(ValueError):
            installer.copy_regular(source, target, 8)
        source.unlink(); source.symlink_to(self.root / 'hardlink')
        with self.assertRaises(OSError):
            installer.copy_regular(source, target, 8)
        source.unlink(); source.write_bytes(b'ninebytes')
        with self.assertRaises(ValueError):
            installer.copy_regular(source, target, 8)
        self.assertFalse(target.exists())

    def test_paths_reject_symlinked_parents_and_hardlinked_leaf(self):
        link = self.root / 'link'; link.symlink_to(self.assets)
        with self.assertRaisesRegex(ValueError, 'Symlink'):
            installer.checked_path(link / 'new', missing=True)
        source = self.root / 'file'; source.write_text('content')
        os.link(source, self.root / 'duplicate')
        with self.assertRaisesRegex(ValueError, 'single-link'):
            installer.checked_path(source)
        self.assertEqual(installer.checked_path(self.root / 'new', missing=True), self.root / 'new')

    def test_candidate_commands_drop_privilege_use_final_paths_and_no_network_installs(self):
        steps = dict(installer.install_steps())
        self.assertEqual(set(steps), {'venv', 'dependencies', 'editable', 'pip-check'})
        self.assertEqual(steps['venv'][-1], '/home/inky/inky-studio/server/.venv')
        for name in ('dependencies', 'editable'):
            self.assertIn('--no-index', steps[name]); self.assertIn('--no-compile', steps[name])
            self.assertIn('--no-cache-dir', steps[name])
        self.assertIn('--require-hashes', steps['dependencies'])
        self.assertIn('--only-binary=:all:', steps['dependencies'])
        self.assertIn('--no-build-isolation', steps['editable'])
        self.assertIn('--no-deps', steps['editable'])
        command = installer.child_command(Path('/fixture/root'), steps['editable'])
        self.assertEqual(command[:5], ['/usr/bin/unshare', '--pid', '--ipc', '--fork', '--kill-child=KILL'])
        self.assertEqual(command[5:8], ['/usr/sbin/chroot', '/fixture/root', '/usr/bin/setpriv'])
        for argument in ('--reuid=1000', '--regid=1000', '--clear-groups', '--no-new-privs',
                         'PYTHONDONTWRITEBYTECODE=1', 'PIP_CONFIG_FILE=/dev/null'):
            self.assertIn(argument, command)
        self.assertLess(command.index('--no-new-privs'), command.index('/usr/bin/env'))
        self.assertEqual(command[command.index('/usr/bin/env') + 1], '-i')
        self.assertFalse(any('runtime' in part or 'install.sh' in part for part in command))

    def application_owner(self):
        original = Path.lstat
        def lstat(path, *args, **kwargs):
            values = list(original(path, *args, **kwargs)); values[4] = 1000; values[5] = 1000
            return os.stat_result(values)
        return patch.object(Path, 'lstat', lstat)

    def test_bytecode_removed_without_following_venv_interpreter_links(self):
        app = self.root / 'application'; (app / 'server/.venv/bin').mkdir(parents=True)
        (app / 'server/.venv/bin/python3').symlink_to('/usr/bin/python3')
        cache = app / 'server/__pycache__'; cache.mkdir(); (cache / 'module.pyc').write_bytes(b'bytecode')
        (app / 'server/module.py').write_text('value = 1\n')
        with self.application_owner():
            report = installer.finish_tree(app)
        self.assertEqual(report['removed_bytecode_files'], 1)
        self.assertFalse(cache.exists())
        self.assertTrue((app / 'server/.venv/bin/python3').is_symlink())
        self.assertEqual(report['files'], 1)

    def test_delivered_foreign_link_and_hardlink_fail_closed(self):
        app = self.root / 'application'; app.mkdir()
        outside = self.root / 'outside.pyc'; outside.write_bytes(b'keep')
        (app / 'bad.pyc').symlink_to(outside)
        with self.application_owner(), self.assertRaisesRegex(ValueError, 'Unexpected delivered symlink'):
            installer.finish_tree(app)
        self.assertEqual(outside.read_bytes(), b'keep')
        (app / 'bad.pyc').unlink(); os.link(outside, app / 'bad.pyc')
        with self.application_owner(), self.assertRaisesRegex(ValueError, 'hardlink'):
            installer.finish_tree(app)
        self.assertEqual(outside.read_bytes(), b'keep')


if __name__ == '__main__':
    unittest.main()
