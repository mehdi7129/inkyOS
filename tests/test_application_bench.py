import importlib.util
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

spec=importlib.util.spec_from_file_location('application_bench',Path(__file__).parents[1]/'scripts/qualify-application-linux.py')
bench=importlib.util.module_from_spec(spec);spec.loader.exec_module(bench)


class ApplicationBenchTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        self.assets=self.root/'assets';self.assets.mkdir()

    def bundle(self, extra=None, lock=None):
        with tarfile.open(self.assets/'app.tar.gz','w:gz') as archive:
            for name,content in {'server/pyproject.toml':b'[project]\n',**(extra or {})}.items():
                info=tarfile.TarInfo(name);info.size=len(content);archive.addfile(info,io.BytesIO(content))
        with zipfile.ZipFile(self.assets/'wheels.zip','w') as archive: archive.writestr('fixture.whl',b'fixture')
        (self.assets/'app.lock').write_text(lock if lock is not None else 'fixture==1.0 --hash=sha256:'+'a'*64+'\n')
        return {'assets':[{'role':r,'filename':f} for r,f in [('application','app.tar.gz'),('wheelhouse','wheels.zip'),('python_lock','app.lock')]]}

    def test_existing_venv_is_rejected_before_any_execution(self):
        data=self.bundle({'server/.venv/lib/leftover.py':b'old dependency'})
        work=self.root/'work';work.mkdir()
        with self.assertRaisesRegex(ValueError,'pre-existing venv'):bench.extract_inputs(data,self.assets,work)

    def test_extraction_rejects_parent_path_even_without_prior_inspection(self):
        data=self.bundle({'../outside':b'bad'});work=self.root/'work';work.mkdir()
        with self.assertRaises(ValueError):bench.extract_inputs(data,self.assets,work)
        self.assertFalse((self.root/'outside').exists())

    def test_lock_cannot_inject_remote_or_local_requirements(self):
        for index,line in enumerate(['--index-url https://invalid.example','fixture @ file:///tmp/foreign','-e ../project','fixture>=1.0']):
            with self.subTest(line=line):
                data=self.bundle(lock=line);work=self.root/f'work-{index}';work.mkdir()
                with self.assertRaisesRegex(ValueError,'exact package'):bench.extract_inputs(data,self.assets,work)

    def test_snapshot_rejects_fifo_symlink_and_oversize(self):
        source=self.root/'source';target=self.root/'copy'
        if hasattr(os,'mkfifo'):
            os.mkfifo(source)
            with self.assertRaises(ValueError):bench.copy_regular(source,target,8)
            source.unlink()
        source.symlink_to(self.assets)
        with self.assertRaises(OSError):bench.copy_regular(source,target,8)
        source.unlink();source.write_bytes(b'ninebytes')
        with self.assertRaises(ValueError):bench.copy_regular(source,target,8)
        self.assertFalse(target.exists())

    def test_snapshot_stays_independent_of_later_source_edits(self):
        source=self.root/'source';source.write_bytes(b'original');target=self.root/'copy'
        bench.copy_regular(source,target,8);source.write_bytes(b'modified')
        self.assertEqual(target.read_bytes(),b'original')
        with self.assertRaises(FileExistsError):bench.copy_regular(source,target,8)
