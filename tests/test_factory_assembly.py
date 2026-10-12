"""Inactive assembly regressions; inert wheels, mocked APIs, no VM or image.

Recipe source bytes are copied as data. Mocked composition proves sequencing,
not production Linux ownership, installation, namespaces or target execution.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    spec = importlib.util.spec_from_file_location('_assembly_fixture_' + path.stem.replace('-', '_'), path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


profile = load(ROOT / 'scripts/factory-assembly-profile.py')
dependencies = load(ROOT / 'tests/test_factory_studio_dependencies.py')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def host_caller(args):
    # Even a failed regression may not contact a real builder.
    with tempfile.TemporaryDirectory(prefix='inkyos-assembly-cli-deny-') as temporary:
        command=Path(temporary)/'limactl'
        command.write_text('#!/bin/sh\nprintf "unexpected builder access\\n" >&2\nexit 99\n')
        command.chmod(0o755)
        return subprocess.run(['bash',str(ROOT/'scripts/build-prototype.sh'),*args],
            env={**os.environ,'PYTHON':sys.executable,'PATH':temporary+os.pathsep+os.environ['PATH']},
            capture_output=True,text=True,timeout=10)


class Fixture:
    def __init__(self):
        self.f = dependencies.FactoryStudioDependencyTests()
        self.f.setUp()
        self.base = self.f.base
        self.f.inputs['studio_commit'] = profile.writer.STUDIO_COMMIT
        self.pin = self.f.write_inputs()
        self.bundle_raw, self.plan = profile.planner.plan(self.f.input_file, self.pin, self.f.sources, self.f.wheels)
        self.bundle = self.base / 'expected-bundle.json'; self.bundle.write_bytes(self.bundle_raw)
        self.os_sources = self.base / 'os-sources'; self.os_sources.mkdir()
        self.source_bytes = {}
        for name in profile.SOURCE_FILES:
            raw = (ROOT / name).read_bytes(); self.source_bytes[name] = raw
            target = self.os_sources / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
        self.writer_value = {'schema_version':1, 'kind':'factory-writer-file-inputs',
            'os_commit':'d'*40, 'studio_commit':profile.writer.STUDIO_COMMIT,
            'os_source_sha256':{name:sha(raw) for name,raw in self.source_bytes.items()},
            'studio_bundle_manifest_sha256':sha(self.bundle_raw),
            'helper_source_sha256':json.loads(self.bundle_raw)['records'][profile.writer.HELPER_SOURCE]['sha256']}
        self.writer_path = self.base / 'writer-inputs.json'
        self.writer_pin = self.write_writer()
        self.work = self.base / 'work'; self.work.mkdir(mode=0o700)
        self.output = self.work / 'factory-inputs'

    def write_writer(self):
        raw = profile.canonical(self.writer_value); self.writer_path.write_bytes(raw)
        self.writer_pin = sha(raw)
        return self.writer_pin

    def args(self):
        return (self.f.input_file,self.pin,self.f.sources,self.f.wheels,self.bundle,
                self.writer_path,self.writer_pin,self.os_sources)

    def stage(self):
        return profile.stage(*self.args(),self.output)

    def close(self):
        self.f.doCleanups()


class AssemblyInputTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture(); self.addCleanup(self.f.close)

    def test_snapshot_is_exact_and_reverified_without_candidate_import(self):
        value = self.f.stage()
        self.assertEqual(profile.verify_inputs(self.f.work),value)
        self.assertEqual((self.f.output/'writer-inputs.json').read_bytes(),self.f.writer_path.read_bytes())
        self.assertEqual(set(str(path.relative_to(self.f.output/'writer-sources'))
                             for path in (self.f.output/'writer-sources').rglob('*') if path.is_file()),set(profile.SOURCE_FILES))
        self.assertFalse((self.f.work/'root').exists())
        self.assertTrue(all(flag is False for flag in value['qualification'].values()))

    def test_recipe_whitelist_works_without_checkout_or_site_packages(self):
        self.f.stage()
        recipe = self.f.work/'recipe'; recipe.mkdir()
        for name in profile.TOOL_FILES:
            target=recipe/name; target.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(ROOT/name,target)
        script=('import importlib.util,pathlib,sys; p=pathlib.Path(sys.argv[1]); '
                's=importlib.util.spec_from_file_location("assembly",p/"recipe/scripts/factory-assembly-profile.py"); '
                'm=importlib.util.module_from_spec(s); s.loader.exec_module(m); m.verify_inputs(p)')
        result=subprocess.run([sys.executable,'-I','-B','-S','-c',script,str(self.f.work)],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_wrong_external_pins_refuse_before_snapshot_creation(self):
        for index in (1,6):
            args=list(self.f.args()); args[index]='0'*64
            with self.subTest(index=index),self.assertRaises(ValueError): profile.stage(*args,self.f.output)
            self.assertFalse(self.f.output.exists())

    def test_changed_expected_bundle_refuses_before_snapshot_creation(self):
        self.f.bundle.write_bytes(self.f.bundle_raw+b' ')
        with self.assertRaises(ValueError): self.f.stage()
        self.assertFalse(self.f.output.exists())

    def test_old_graph_pin_extra_source_and_changed_source_refuse_before_write(self):
        name='staging/bootstrap/writer-graph.py'
        original=self.f.writer_value['os_source_sha256'][name]
        self.f.writer_value['os_source_sha256'][name]='c'*64; self.f.write_writer()
        with self.assertRaises(ValueError): self.f.stage()
        self.f.writer_value['os_source_sha256'][name]=original; self.f.write_writer()
        extra=self.f.os_sources/'unpinned.txt'; extra.write_bytes(b'no copy')
        with self.assertRaises(ValueError): self.f.stage()
        extra.unlink(); (self.f.os_sources/name).write_bytes(b'changed source')
        with self.assertRaises(ValueError): self.f.stage()
        self.assertFalse(self.f.output.exists())

    def test_changed_staged_source_is_refused_on_readback(self):
        self.f.stage(); (self.f.output/'writer-sources/scripts/writer-launcher.py').write_bytes(b'changed')
        with self.assertRaises(ValueError): profile.verify_inputs(self.f.work)

    def test_profile_cannot_promote_any_active_qualification(self):
        value=self.f.stage()
        for name in profile.QUALIFICATIONS:
            changed=copy.deepcopy(value); changed['qualification'][name]=True
            with self.subTest(name=name),self.assertRaises(ValueError): profile.validate_metadata(changed)

    def test_four_production_api_calls_are_ordered_after_readonly_preflight(self):
        self.f.stage(); actions=[]
        environment=SimpleNamespace(check=lambda:actions.append('check'),close=lambda:actions.append('close'))
        def operation(name):
            def run(*args,**kwargs): actions.append(name); return {'inert':True}
            return run
        bundle=SimpleNamespace(install_bundle=operation('install_bundle'),verify_bundle=operation('verify_bundle'))
        installer=SimpleNamespace(install_writer=operation('install_writer'))
        with patch.object(profile.writer,'Environment',return_value=environment), \
             patch.object(profile.writer,'_preflight',side_effect=lambda *a,**kw:actions.append('preflight')), \
             patch.object(profile.writer,'verify_writer',side_effect=operation('verify_writer')), \
             patch.object(profile,'module',side_effect=lambda name:bundle if name=='install-factory-studio-bundle-rootfs.py' else installer):
            profile.prepare_rootfs(self.f.work)
        self.assertEqual(actions,['preflight','install_bundle','verify_bundle','preflight','install_writer','verify_writer','check','close'])

    def test_base_guard_refusal_precedes_first_bundle_api_and_closes(self):
        self.f.stage(); actions=[]
        environment=SimpleNamespace(close=lambda:actions.append('close'))
        with patch.object(profile.writer,'Environment',return_value=environment), \
             patch.object(profile.writer,'_preflight',side_effect=ValueError('incompatible base')), \
             patch.object(profile,'module',side_effect=AssertionError('installation started')):
            with self.assertRaises(ValueError): profile.prepare_rootfs(self.f.work)
        self.assertEqual(actions,['close'])

    def test_existing_receipt_refuses_before_root_environment(self):
        self.f.stage(); (self.f.work/profile.OUTPUT_REPORTS[-1]).write_bytes(b'inert existing')
        with patch.object(profile.writer,'Environment',side_effect=AssertionError('root inspected')):
            with self.assertRaises(ValueError): profile.prepare_rootfs(self.f.work)

    def test_bundle_readback_failure_stops_without_writer_retry_or_positive_receipt(self):
        self.f.stage(); actions=[]
        environment=SimpleNamespace(close=lambda:actions.append('close'))
        bundle=SimpleNamespace(install_bundle=lambda *a,**kw:actions.append('install_bundle'),
                               verify_bundle=lambda *a,**kw:(_ for _ in ()).throw(ValueError('readback failed')))
        with patch.object(profile.writer,'Environment',return_value=environment), \
             patch.object(profile.writer,'_preflight',return_value=None), \
             patch.object(profile,'module',return_value=bundle):
            with self.assertRaises(ValueError): profile.prepare_rootfs(self.f.work)
        self.assertEqual(actions,['install_bundle','close'])
        self.assertFalse(any((self.f.work/name).exists() for name in profile.OUTPUT_REPORTS))


class AssemblyCallerTests(unittest.TestCase):
    def test_incompatible_profiles_refuse_before_builder_access(self):
        cases=(['--writer-input-manifest','fixture'],
               ['--profile','factory-passive','--writer-sources-dir','fixture'],
               ['--profile','factory-assembly'],
               ['--profile','factory-assembly','--application-manifest','legacy'],
               ['--profile','factory-assembly','--profile','system'])
        for args in cases:
            with self.subTest(args=args):
                result=host_caller(args)
                self.assertEqual(result.returncode,2,result.stderr)

    def test_wrong_pin_through_real_host_caller_refuses_before_vm_or_fetch(self):
        f=Fixture(); self.addCleanup(f.close)
        fields=('studio-input-manifest','studio-input-sha256','studio-sources-dir','studio-wheels-dir',
                'studio-bundle-manifest','writer-input-manifest','writer-input-sha256','writer-sources-dir')
        values=list(f.args()); values[6]='0'*64
        args=['--profile','factory-assembly']
        for field,value in zip(fields,values): args += ['--'+field,str(value)]
        result=host_caller(args)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Writer inputs differ from reviewed assembly pins',result.stderr)
        self.assertNotIn('limactl',result.stderr)
        self.assertNotIn('unexpected builder access',result.stderr)


if __name__=='__main__':
    unittest.main()
