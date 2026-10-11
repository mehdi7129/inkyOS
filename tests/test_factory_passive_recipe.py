"""Inactive recipe integration fixtures; no real inputs, image, VM or SD used."""
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
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    spec = importlib.util.spec_from_file_location('_passive_fixture_' + path.stem.replace('-', '_'), path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


profile = load(ROOT / 'scripts/factory-passive-profile.py')
prototype = load(ROOT / 'tests/test_verify_prototype.py')
configuration = load(ROOT / 'tests/test_configure_rootfs.py')
dependencies = load(ROOT / 'tests/test_factory_studio_dependencies.py')
exports = load(ROOT / 'tests/test_verify_artifacts.py')
layout = load(ROOT / 'scripts/configure-factory-rootfs.py')


def inert_profile():
    return {'schema_version': 1, 'kind': 'factory-passive-profile', 'studio_commit': 'a' * 40,
            'input_manifest_sha256': 'b' * 64, 'bundle_manifest_sha256': 'c' * 64,
            'startup': 'masked', 'runtime_qualified': False, 'hardware_qualified': False}


class PassiveParsingTests(unittest.TestCase):
    def test_invalid_or_mixed_options_refuse_before_builder_access(self):
        cases = [(['--profile', 'unknown'], 'Unknown build profile'),
                 (['--profile', 'factory-passive'], 'requires four pinned Studio inputs'),
                 (['--studio-input-manifest', 'fixture'], 'require the explicit factory-passive'),
                 (['--profile', 'system', '--profile', 'system'], ''),
                 (['--profile', 'factory-passive', '--studio-input-manifest', 'fixture',
                   '--studio-input-sha256', 'b' * 64, '--studio-sources-dir', 'fixture',
                   '--studio-wheels-dir', 'fixture', '--application-manifest', 'legacy'], 'forbids legacy'),
                 (['--application-manifest', 'fixture'], 'requires manifest')]
        for args, message in cases:
            with self.subTest(args=args):
                result = subprocess.run(['bash', str(ROOT / 'scripts/build-prototype.sh'), *args],
                                        env={**os.environ, 'PYTHON': sys.executable}, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(message, result.stderr)

    def test_unknown_linux_profile_refuses_before_platform_or_work_access(self):
        result = subprocess.run(['bash', str(ROOT / 'scripts/build-image-linux.sh'),
                                 '/must-not-open', '--profile', 'unknown'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('Unknown or incomplete build profile', result.stderr)

    def test_metadata_is_explicit_and_never_qualified(self):
        self.assertEqual(profile.validate_metadata(inert_profile()), inert_profile())
        for key, value in (('runtime_qualified', True), ('hardware_qualified', True),
                           ('startup', 'ready'), ('schema_version', True), ('kind', 'system-prototype')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                profile.validate_metadata({**inert_profile(), key: value})
        with self.assertRaises(ValueError): profile.validate_metadata({**inert_profile(), 'extra': True})

    def test_guard_rejects_host_root_before_inspection_or_mutation(self):
        with patch.object(Path, 'lstat', side_effect=AssertionError('host path inspected')):
            with self.assertRaises(ValueError): profile.guard_work(Path('/'))

    def test_configuration_factory_keeps_exact_wifi_closed_and_kind_separate(self):
        fixture = configuration.ConfigureRootfsTests()
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        configuration.configure_rootfs.configure(fixture.root, fixture.boot, fixture.recipe, factory=inert_profile())
        self.assertEqual((fixture.root / 'var/lib/NetworkManager/NetworkManager.state').read_bytes(),
                         b'[main]\nWirelessEnabled=false\n')
        release = json.loads((fixture.root / 'etc/inkyos-release.json').read_bytes())
        self.assertEqual(release['kind'], 'factory-passive')
        self.assertIsNone(release['application'])
        self.assertEqual(release['factory'], inert_profile())
        self.assertIs(release['runtime_qualified'], False)


class PassiveStagingTests(unittest.TestCase):
    def setUp(self):
        fixture = dependencies.FactoryStudioDependencyTests()
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.pin = fixture.write_inputs()
        self.work = fixture.base / 'work'; self.work.mkdir(mode=0o700)
        self.output = self.work / 'factory-inputs'

    def stage(self):
        f = self.fixture
        return profile.stage(f.input_file, self.pin, f.sources, f.wheels, self.output)

    def test_exact_inert_snapshot_is_reverified_without_candidate_import(self):
        result = self.stage()
        self.assertEqual(profile.verify_inputs(self.work), result)
        self.assertEqual((self.output / 'inputs.json').read_bytes(), self.fixture.input_file.read_bytes())
        for field, subdir in (('source_sha256', 'sources'), ('wheel_sha256', 'wheels')):
            actual = {str(p.relative_to(self.output / subdir)) for p in (self.output / subdir).rglob('*') if p.is_file()}
            self.assertEqual(actual, set(self.fixture.inputs[field]))
        self.assertIs(result['runtime_qualified'], False)
        self.assertFalse((self.work / 'root').exists())

    def test_transitive_whitelist_is_sufficient_without_checkout_or_site_packages(self):
        self.stage()
        recipe = self.work / 'recipe'; recipe.mkdir()
        for name in set(profile.TOOL_FILES) | {'scripts/manifest-rootfs.py', 'scripts/inspect-rootfs.py'}:
            target = recipe / name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        script = ('import importlib.util,pathlib,sys; p=pathlib.Path(sys.argv[1]); '
                  's=importlib.util.spec_from_file_location("passive",p/"recipe/scripts/factory-passive-profile.py"); '
                  'm=importlib.util.module_from_spec(s); s.loader.exec_module(m); m.verify_inputs(p)')
        result = subprocess.run([sys.executable, '-I', '-B', '-S', '-c', script, str(self.work)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_pin_refusal_precedes_snapshot_creation(self):
        self.pin = '0' * 64
        with self.assertRaises(ValueError): self.stage()
        self.assertFalse(self.output.exists())

    def test_aggregate_staging_bound_refuses_before_snapshot_creation(self):
        with patch.object(profile, 'MAX_TRANSFER_BYTES', 1):
            with self.assertRaises(ValueError): self.stage()
        self.assertFalse(self.output.exists())

    def test_extra_unpinned_source_refuses_before_snapshot_creation(self):
        (self.fixture.sources / 'private.txt').write_bytes(b'never copy this unpinned fixture')
        with self.assertRaises(ValueError): self.stage()
        self.assertFalse(self.output.exists())

    def test_symlink_source_refuses_before_snapshot_creation(self):
        helper = self.fixture.sources / 'scripts/inky-network-helper.py'
        raw = helper.read_bytes(); helper.unlink()
        external = self.fixture.base / 'outside-helper.py'; external.write_bytes(raw)
        helper.symlink_to(external)
        with self.assertRaises(ValueError): self.stage()
        self.assertFalse(self.output.exists())

    def test_metadata_wrong_target_refuses_before_snapshot_creation(self):
        self.fixture.inputs['python_version'] = '3.13.4'
        self.pin = self.fixture.write_inputs()
        with self.assertRaises(ValueError): self.stage()
        self.assertFalse(self.output.exists())

    def test_metadata_missing_runtime_dependency_refuses_before_snapshot_creation(self):
        self.fixture.inputs['wheel_sha256'].pop('foundation-1.5-py3-none-any.whl')
        (self.fixture.wheels / 'foundation-1.5-py3-none-any.whl').unlink()
        self.pin = self.fixture.write_inputs()
        with self.assertRaises(ValueError): self.stage()
        self.assertFalse(self.output.exists())

    def test_changed_staged_receipt_refuses_readback(self):
        self.stage()
        (self.output / 'factory-studio-plan.json').write_bytes(b'{}\n')
        with self.assertRaises(ValueError): profile.verify_inputs(self.work)

    def test_changed_staged_helper_refuses_readback(self):
        self.stage()
        (self.output / 'sources/scripts/inky-network-helper.py').write_bytes(b'changed fixture')
        with self.assertRaises(ValueError): profile.verify_inputs(self.work)

    def test_profile_pin_disagrees_with_expected_bundle_refuses(self):
        self.stage()
        path = self.output / 'factory-passive.json'
        value = json.loads(path.read_bytes()); value['bundle_manifest_sha256'] = '0' * 64
        path.write_bytes(profile.canonical(value))
        with self.assertRaises(ValueError): profile.verify_inputs(self.work)


class PassiveRootfsTests(unittest.TestCase):
    def setUp(self):
        if sys.platform != 'linux':
            xattrs = patch.object(os, 'listxattr', create=True, return_value=[])
            xattrs.start(); self.addCleanup(xattrs.stop)
        self.f = prototype.VerifyPrototypeTests()
        self.f.setUp(); self.addCleanup(self.f.doCleanups)
        self.f.root = self.f.root.resolve()
        self.f.boot = self.f.boot.resolve()
        self.options = dict(_owner_uid=os.geteuid(), _owner_gid=os.getegid(),
                            _app_uid=os.geteuid(), _app_gid=os.getegid())
        self.pin = inert_profile()
        self.f.put('var/lib/NetworkManager/NetworkManager.state', '[main]\nWirelessEnabled=false\n', 0o600)
        self.f.put('etc/inkyos-release.json', json.dumps({'schema_version': 1, 'kind': 'factory-passive',
                   'application': None, 'factory': self.pin, 'runtime_qualified': False, 'hardware_qualified': False}))
        layout.configure(self.f.root, ROOT, **self.options)

    def report(self):
        return prototype.verify.verify(self.f.root, self.f.boot, self.f.lock, factory=self.pin, **self.options)

    def test_precise_pending_permission_passes_in_separate_scope(self):
        report = self.report()
        self.assertTrue(report['passed'], report['failed_checks'])
        self.assertEqual(report['scope'], 'offline-factory-passive-contract')
        self.assertIn('EMPTY_VAR_LIB_INKYOS', {c['id'] for c in report['checks']})
        self.assertIs(report['method']['image_code_executed'], False)
        self.assertFalse(self.f.report()['passed'])

    def test_nonvirgin_data_refuses(self):
        self.f.put('var/lib/inky-studio/credentials.json', 'inert private fixture')
        self.assertIn('FACTORY_PASSIVE_LAYOUT', self.report()['failed_checks'])

    def test_permission_replacement_refuses(self):
        self.f.put('var/lib/inkyos/factory-permission/pending.json', '{}', 0o600)
        failures = self.report()['failed_checks']
        self.assertIn('EMPTY_VAR_LIB_INKYOS', failures)
        self.assertIn('FACTORY_PASSIVE_LAYOUT', failures)

    def test_wifi_enabled_or_preseeded_country_refuses(self):
        self.f.put('var/lib/NetworkManager/NetworkManager.state', '[main]\nWirelessEnabled=true\n', 0o600)
        self.assertIn('NETWORKMANAGER_GENERIC_STATE', self.report()['failed_checks'])
        self.f.put('var/lib/NetworkManager/NetworkManager.state', '[main]\nWirelessEnabled=false\n', 0o600)
        self.f.put('cmdline.txt', 'rootwait resize cfg80211.ieee80211_regdom=FR\n', boot=True)
        self.assertIn('BOOT_NO_COUNTRY', self.report()['failed_checks'])

    def test_app_service_unmask_refuses(self):
        path = self.f.root / 'etc/systemd/system/inky-studio.service'; path.unlink()
        path.write_text('[Service]\nExecStart=/usr/lib/inky-studio/server/.venv/bin/python -m inky_web.main\n')
        self.assertIn('FACTORY_PASSIVE_LAYOUT', self.report()['failed_checks'])

    def test_changed_factory_module_pin_refuses(self):
        path = self.f.root / 'usr/local/lib/inkyos/factory-authority.py'
        path.chmod(0o644); path.write_bytes(b'raise AssertionError("never execute tampered hook")\n'); path.chmod(0o555)
        self.assertIn('FACTORY_PASSIVE_LAYOUT', self.report()['failed_checks'])

    def test_factory_runtime_manifest_or_enabled_alias_refuses(self):
        self.f.put('etc/inkyos/factory-runtime-v1.json', '{}')
        self.assertIn('FACTORY_RUNTIME_ABSENT', self.report()['failed_checks'])
        (self.f.root / 'etc/inkyos/factory-runtime-v1.json').unlink()
        self.f.link('etc/systemd/system/multi-user.target.wants/aliased.service',
                    '/usr/lib/systemd/system/inkyos-factory-supervisor.service')
        self.assertIn('FACTORY_RUNTIME_ABSENT', self.report()['failed_checks'])

    def test_legacy_application_and_factory_are_incompatible(self):
        with self.assertRaises(ValueError):
            prototype.verify.verify(self.f.root, self.f.boot, self.f.lock, factory=self.pin,
                                    application={'fixture': True}, **self.options)


class PassiveArtifactTests(unittest.TestCase):
    # This class deliberately reuses staging setup, not a real candidate/image.
    def setUp(self):
        PassiveStagingTests.setUp(self)
        self.pin_value = PassiveStagingTests.stage(self)
        self.export = self.fixture.base / 'export'
        build = exports.default_build()
        build.update(kind='factory-passive', factory=self.pin_value, runtime_qualified=False)
        build['recipe']['files'] = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in profile.TOOL_FILES}
        build['recipe']['files']['factory-passive.json'] = hashlib.sha256(profile.canonical(self.pin_value)).hexdigest()
        fs = exports.default_filesystem(2)
        bundle = json.loads((self.output / 'factory-bundle-manifest.json').read_bytes())
        expected = bundle['records'].copy()
        raw = (self.output / 'factory-bundle-manifest.json').read_bytes()
        expected['manifest.json'] = {'type': 'file', 'mode': '0644', 'uid': 0, 'gid': 0,
                                    'size_bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                                    'xattrs': {'status': 'inspected', 'entries': {}}}
        fs['rootfs'].update({'usr/lib/inky-studio' + ('' if p == '.' else '/' + p): r for p, r in expected.items()})
        exports.save_export(self.export, build=build, filesystem=fs)
        gate = json.loads((self.export / 'qualification-static.json').read_bytes())
        gate['scope'] = 'offline-factory-passive-contract'
        gate['checks'] += [{'id': name, 'passed': True} for name in sorted(exports.artifacts.FACTORY_CHECKS)]
        exports.rehash_report(self.export, 'qualification-static.json', gate)
        for name in ('factory-passive.json', 'factory-dependencies.json', 'factory-studio-plan.json', 'factory-bundle-manifest.json'):
            exports.rehash_report(self.export, name, (self.output / name).read_bytes())
        exports.rehash_report(self.export, 'factory-studio-inputs.json', (self.output / 'inputs.json').read_bytes())
        plan = json.loads((self.output / 'factory-studio-plan.json').read_bytes())
        installer = load(ROOT / 'scripts/install-factory-studio-bundle-rootfs.py')
        for name, operation in (('factory-studio-installation.json', 'install'), ('factory-studio-verification.json', 'verify')):
            exports.rehash_report(self.export, name, installer._receipt(plan, operation=operation))
        source = {name: build['recipe']['files']['scripts/' + name] for name in layout.verification.MODULE_PINS}
        result = {'schema_version': 1, 'scope': 'offline-factory-layout', 'passed': True, 'failed_checks': [],
                  'checks': dict.fromkeys(('UNUSED_IDENTITY_STATE', 'WIFI_CLOSED', 'SERVICES_MASKED', 'FACTORY_LAYOUT'), True),
                  'source_sha256': source}
        result.update(dict.fromkeys(('image_code_executed', 'services_enabled', 'secret_values_included',
                                     'exporter_support_verified', 'full_image_verified', 'writer_barrier_qualified',
                                     'runtime_qualified', 'hardware_qualified'), False))
        exports.rehash_report(self.export, 'qualification-factory.json', result)

    def test_export_factory_is_distinct_and_inactive(self):
        result = exports.artifacts.load_export(self.export)
        self.assertEqual(result['manifest']['kind'], 'factory-passive')
        self.assertIs(result['report']['runtime_qualified'], False)
        self.assertEqual(result['report']['startup'], 'masked')

    def test_export_refuses_missing_factory_gate(self):
        gate = json.loads((self.export / 'qualification-static.json').read_bytes())
        gate['checks'] = [c for c in gate['checks'] if c['id'] != 'FACTORY_PASSIVE_LAYOUT']
        exports.rehash_report(self.export, 'qualification-static.json', gate)
        with self.assertRaises(exports.artifacts.ArtifactError): exports.artifacts.load_export(self.export)

    def test_export_refuses_runtime_qualification(self):
        value = json.loads((self.export / 'factory-studio-verification.json').read_bytes())
        value['runtime_qualified'] = True
        exports.rehash_report(self.export, 'factory-studio-verification.json', value)
        with self.assertRaises(exports.artifacts.ArtifactError): exports.artifacts.load_export(self.export)

    def test_export_refuses_metadata_target_mismatch(self):
        value = json.loads((self.export / 'factory-dependencies.json').read_bytes())
        value['target']['python_version'] = '3.13.4'
        exports.rehash_report(self.export, 'factory-dependencies.json', value)
        with self.assertRaises(exports.artifacts.ArtifactError): exports.artifacts.load_export(self.export)

    def test_export_refuses_bundle_inventory_tamper(self):
        value = json.loads((self.export / 'filesystem-manifest.json').read_bytes())
        value['rootfs']['usr/lib/inky-studio/server/.venv/bin/python3.13']['target'] = '/tmp/private-python'
        exports.rehash_report(self.export, 'filesystem-manifest.json', value)
        with self.assertRaises(exports.artifacts.ArtifactError): exports.artifacts.load_export(self.export)

    def test_export_refuses_legacy_relabel_and_mixed_evidence(self):
        path = self.export / 'manifest.json'
        value = json.loads(path.read_bytes())
        value['kind'] = 'system-prototype'
        path.write_text(json.dumps(value))
        with self.assertRaises(exports.artifacts.ArtifactError): exports.artifacts.load_export(self.export)
        value['kind'] = 'factory-passive'
        path.write_text(json.dumps(value))
        exports.rehash_report(self.export, 'application-manifest.json', b'{}')
        with self.assertRaises(exports.artifacts.ArtifactError): exports.artifacts.load_export(self.export)

    def test_export_refuses_nonobject_factory_report(self):
        exports.rehash_report(self.export, 'factory-studio-verification.json', b'[]')
        with self.assertRaises(exports.artifacts.ArtifactError): exports.artifacts.load_export(self.export)


if __name__ == '__main__':
    unittest.main()
