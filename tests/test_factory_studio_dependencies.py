"""Metadata-only dependency closure through the real isolated CLI.

All wheels and sources are independently generated inert fixtures. No candidate
package, pip, network, image, VM, or host site package is imported by these tests.
"""
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = 'scripts/verify-factory-studio-dependencies.py'
LOCK = 'config/factory-studio-dependency-tooling.lock.json'
TOOLING = 'vendor/build-tooling/packaging-26.3-py3-none-any.whl'
REPO_INPUTS = (SCRIPT, LOCK, TOOLING, 'scripts/plan-factory-studio-bundle.py',
               'scripts/verify-factory-exporter-rootfs.py', 'scripts/manifest-rootfs.py',
               'scripts/install-application-rootfs.py', 'scripts/inspect-application-archives.py',
               'scripts/verify-application.py')
APP = 'inky_studio'
APP_VERSION = '0.3.0rc2'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def wheel_bytes(distribution, version, metadata, *, app=False, record_transform=None):
    """Produce a ZIP with independent exact RECORD hashes and no executable work."""
    dist = f'{distribution}-{version}.dist-info'
    # Distinct payload paths let normalized duplicate distributions reach the
    # metadata check instead of being rejected first as cross-wheel collisions.
    module = 'inky_web' if app else 'fixture_' + sha((distribution + version).encode())[:16]
    files = {
        module + '/__init__.py': b'raise AssertionError("candidate package imported")\n',
        dist + '/METADATA': metadata,
        dist + '/WHEEL': b'Wheel-Version: 1.0\nGenerator: inert-fixture\nTag: py3-none-any\n',
    }
    if app:
        files['inky_web/main.py'] = b'raise AssertionError("candidate app executed")\n'
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, lineterminator='\n')
    for name, raw in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b'=').decode()
        writer.writerow((name, 'sha256=' + digest, str(len(raw))))
    writer.writerow((dist + '/RECORD', '', ''))
    record = stream.getvalue().encode()
    files[dist + '/RECORD'] = record if record_transform is None else record_transform(record)
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, raw in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, raw)
    return output.getvalue()


class FactoryStudioDependencyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='inkyos-dependencies-',
                                                dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.sources = self.base / 'sources'
        self.wheels = self.base / 'wheels'
        self.output = self.base / 'outputs/receipt.json'
        self.input_file = self.base / 'inputs.json'
        for directory in (self.sources, self.wheels, self.output.parent):
            directory.mkdir(mode=0o755)
            directory.chmod(0o755)
        sources = {
            'scripts/inky-network-helper.py': b'raise AssertionError("helper executed")\n',
            'client/dist/index.html': b'<!doctype html><title>Inert dependency fixture</title>\n',
        }
        for name, raw in sources.items():
            self.write(self.sources / name, raw)
        self.inputs = {
            'schema_version': 1, 'kind': 'factory-studio-bundle-inputs',
            'studio_commit': 'a' * 40, 'python_version': '3.13.5',
            'app_wheel': f'{APP}-{APP_VERSION}-py3-none-any.whl',
            'source_sha256': {name: sha(raw) for name, raw in sources.items()},
            'wheel_sha256': {},
        }
        self.add_app(('foundation>=1',))
        self.add_wheel('foundation', '1.5')

    def write(self, path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        for parent in (path.parent, *path.parent.parents):
            if parent == self.base:
                break
            parent.chmod(0o755)
        path.write_bytes(raw)
        path.chmod(0o644)

    def write_inputs(self):
        raw = canonical(self.inputs)
        self.write(self.input_file, raw)
        return sha(raw)

    def add_wheel(self, distribution, version='1.0', *, requires=(), extras=(),
                  requires_python=None, metadata=None, record_transform=None, app=False,
                  metadata_version='2.3', dynamic=()):
        if metadata is None:
            lines = ['Metadata-Version: ' + metadata_version, 'Name: ' + distribution, 'Version: ' + version]
            lines.extend('Dynamic: ' + field for field in dynamic)
            if requires_python is not None:
                lines.append('Requires-Python: ' + requires_python)
            lines.extend('Provides-Extra: ' + extra for extra in extras)
            lines.extend('Requires-Dist: ' + requirement for requirement in requires)
            metadata = ('\n'.join(lines) + '\n').encode()
        filename = f'{distribution}-{version}-py3-none-any.whl'
        raw = wheel_bytes(distribution, version, metadata, app=app, record_transform=record_transform)
        self.write(self.wheels / filename, raw)
        self.inputs['wheel_sha256'][filename] = sha(raw)
        self.write_inputs()
        return filename

    def add_app(self, requires=(), *, extras=('pi',), **kwargs):
        return self.add_wheel(APP, APP_VERSION, requires=requires, extras=extras, app=True, **kwargs)

    def remove_wheel(self, filename):
        (self.wheels / filename).unlink()
        del self.inputs['wheel_sha256'][filename]
        self.write_inputs()

    def snapshot(self):
        result = {}
        for path in (self.base, *sorted(self.base.rglob('*'))):
            info = path.lstat()
            value = (info.st_mode, info.st_uid, info.st_gid, info.st_nlink, info.st_ino, info.st_dev)
            if stat.S_ISREG(info.st_mode):
                value += (path.read_bytes(),)
            elif stat.S_ISLNK(info.st_mode):
                value += (os.readlink(path),)
            result[str(path.relative_to(self.base))] = value
        return result

    def run_cli(self, *, repository=ROOT, receipt=None, input_sha256=None, environment=None,
                bootstrap=None):
        prefix = [sys.executable, '-I', '-B', '-S']
        if bootstrap is not None:
            prefix.extend(('-c', bootstrap))
        return subprocess.run(
            [*prefix, str(repository / SCRIPT),
             '--input-manifest', str(self.input_file),
             '--input-sha256', input_sha256 or sha(self.input_file.read_bytes()),
             '--sources-dir', str(self.sources), '--wheels-dir', str(self.wheels),
             '--receipt', str(self.output if receipt is None else receipt)],
            cwd=self.base, env=environment, capture_output=True, timeout=20)

    def succeeds(self, **kwargs):
        result = self.run_cli(**kwargs)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertEqual(result.stderr, b'')
        output = kwargs.get('receipt', self.output)
        raw = output.read_bytes()
        value = json.loads(raw)
        self.assertEqual(raw, canonical(value))
        self.assertFalse(value['candidate_code_executed'])
        self.assertFalse(value['application_candidate_qualified'])
        return value

    def refused(self, *, reason=None, **kwargs):
        before = self.snapshot()
        result = self.run_cli(**kwargs)
        self.assertEqual(result.returncode, 1, result.stderr.decode(errors='replace'))
        self.assertEqual(result.stdout, b'')
        self.assertRegex(result.stderr, rb'\Afactory_studio_dependencies_refused:[a-z_]{1,64}\n\Z')
        if reason is not None:
            self.assertEqual(result.stderr, ('factory_studio_dependencies_refused:' + reason + '\n').encode())
        self.assertEqual(self.snapshot(), before)

    def hosted_repository(self):
        target = self.base / 'hosted-repository'
        for name in REPO_INPUTS:
            self.write(target / name, (ROOT / name).read_bytes())
        return target

    def test_pinned_root_rc_and_exact_stable_metadata_receipt(self):
        value = self.succeeds()
        self.assertEqual(value, {
            'schema_version': 1, 'scope': 'factory-studio-dependency-metadata-only',
            'input_manifest_sha256': sha(self.input_file.read_bytes()),
            'studio_commit': 'a' * 40,
            'target': {'architecture': 'arm64', 'python_version': '3.13.5', 'debian_release': 'trixie'},
            'root_distribution': 'inky-studio', 'root_extras': ['pi'],
            'reached_distributions': ['foundation', 'inky-studio'],
            'activated_extras': {'foundation': [], 'inky-studio': ['pi']},
            'wheel_count': 2, 'tooling_sha256': sha((ROOT / TOOLING).read_bytes()),
            'candidate_code_executed': False, 'application_candidate_qualified': False,
        })
        second = self.output.with_name('second.json')
        self.assertEqual(self.succeeds(receipt=second), value)

    def test_pi_extra_transitive_uvicorn_standard_and_qrcode_pil_union(self):
        self.add_app(('foundation>=1', 'uvicorn[standard]>=0.30; extra == "pi"',
                      'qrcode[pil]>=8; extra == "pi"'))
        self.add_wheel('foundation', '1.5', requires=('uvicorn[tls]>=0.30',))
        self.add_wheel('uvicorn', '0.35', extras=('standard', 'tls'),
                       requires=('base_dep>=1; extra == ""',
                                 'uvloop>=0.20; extra == "standard"',
                                 'tls_dep>=1; extra == "tls"'))
        self.add_wheel('qrcode', '8.1', extras=('pil',),
                       requires=('pillow>=10; extra == "pil"',))
        self.add_wheel('uvloop', '0.21')
        self.add_wheel('pillow', '11.0')
        self.add_wheel('base_dep')
        self.add_wheel('tls_dep')
        value = self.succeeds()
        self.assertEqual(value['reached_distributions'],
                         ['base-dep', 'foundation', 'inky-studio', 'pillow', 'qrcode',
                          'tls-dep', 'uvicorn', 'uvloop'])
        self.assertEqual(value['activated_extras']['uvicorn'], ['standard', 'tls'])
        self.assertEqual(value['activated_extras']['qrcode'], ['pil'])

    def test_cycles_and_late_extra_activation_are_independent_of_wheel_order(self):
        self.add_app(('foundation>=1', 'zeta[fast]>=1'))
        self.add_wheel('foundation', '1.5', extras=('feature',),
                       requires=('zeta>=1', 'leaf>=1; extra == "feature"'))
        self.add_wheel('zeta', extras=('fast',),
                       requires=('foundation[feature]>=1; extra == "fast"',))
        self.add_wheel('leaf')
        first = self.succeeds()
        payloads = [(path.name, path.read_bytes()) for path in sorted(self.wheels.iterdir())]
        for name, _ in payloads:
            (self.wheels / name).unlink()
        for name, raw in reversed(payloads):
            self.write(self.wheels / name, raw)
        second = self.succeeds(receipt=self.output.with_name('reverse.json'))
        self.assertEqual(first, second)
        self.assertEqual(first['activated_extras']['foundation'], ['feature'])
        self.assertEqual(first['reached_distributions'], ['foundation', 'inky-studio', 'leaf', 'zeta'])

    def test_target_markers_use_pinned_linux_arm64_cpython_not_host(self):
        condition = ('python_version == "3.13" and python_full_version == "3.13.5" '
                     'and sys_platform == "linux" and os_name == "posix" '
                     'and platform_machine == "aarch64" '
                     'and platform_system == "Linux" '
                     'and implementation_name == "cpython" '
                     'and platform_python_implementation == "CPython" '
                     'and implementation_version == "3.13.5"')
        self.add_app(('foundation>=1; ' + condition,
                      'windows_only>=1; sys_platform == "win32"'))
        self.assertEqual(self.succeeds()['reached_distributions'], ['foundation', 'inky-studio'])

    def test_missing_dependency_refuses_without_receipt(self):
        self.add_app(('absent>=1',))
        self.refused(reason='missing_dependency')

    def test_superfluous_wheel_refuses_without_receipt(self):
        self.add_wheel('unrequested')
        self.refused(reason='extra_wheels')

    def test_active_constraint_rejects_installed_version(self):
        self.add_app(('foundation>=2,<3',))
        self.refused()

    def test_all_reachable_constraints_are_enforced(self):
        self.add_app(('foundation>=1', 'other>=1'))
        self.add_wheel('other', requires=('foundation<1.5',))
        self.refused()

    def test_requires_python_must_include_exact_target_patch(self):
        self.add_wheel('foundation', '1.5', requires_python='>=3.13.6')
        self.refused()

    def test_root_requires_python_is_checked(self):
        self.add_app(('foundation>=1',), requires_python='<3.13')
        self.refused()

    def test_invalid_requires_python_and_requirement_syntax_refuse(self):
        self.add_wheel('foundation', '1.5', requires_python='not-a-specifier')
        self.refused()
        self.add_wheel('foundation', '1.5', requires=('bad requirement ???',))
        self.refused()

    def test_active_and_inactive_urls_are_always_refused(self):
        for requirement in ('foundation @ https://invalid.example/dep.whl',
                            'foundation @ file:///not-read.whl ; python_version < "3"',
                            'absent @ https://invalid.example/a.whl ; extra == "not-requested"'):
            with self.subTest(requirement=requirement):
                self.add_app((requirement,))
                self.refused(reason='url_dependency')

    def test_duplicate_normalized_distribution_refuses(self):
        self.add_app(('foundation>=1', 'dupe-name>=1'))
        self.add_wheel('dupe_name')
        self.add_wheel('dupe.name', '2.0')
        self.refused(reason='duplicate_distribution')

    def test_duplicate_normalized_provides_extra_refuses(self):
        self.add_wheel('foundation', '1.5', extras=('pdf-render', 'PDF_render'))
        self.refused()

    def test_root_pi_extra_is_required(self):
        self.add_app(('foundation>=1',), extras=())
        self.refused()

    def test_unknown_requested_dependency_extra_refuses(self):
        self.add_app(('foundation[absent]>=1',))
        self.refused()

    def test_dynamic_requires_dist_keeps_dependency_and_version_checks(self):
        self.add_wheel('foundation', '1.5', requires=('leaf>=1',), dynamic=('Requires-Dist',))
        self.add_wheel('leaf')
        receipt = self.succeeds(receipt=self.output.parent / 'valid.json')
        self.assertEqual(receipt['reached_distributions'], ['foundation', 'inky-studio', 'leaf'])
        self.add_wheel('foundation', '1.5', requires=('leaf>=2',), dynamic=('Requires-Dist',))
        self.refused(reason='dependency_version')
        self.add_wheel('foundation', '1.5', requires=('missing>=1',), dynamic=('Requires-Dist',))
        self.refused(reason='missing_dependency')

    def test_dynamic_requires_python_still_checks_fixed_target(self):
        self.add_wheel('foundation', '1.5', requires_python='>=3.13,<3.14', dynamic=('requires-python',))
        self.succeeds(receipt=self.output.parent / 'valid.json')
        self.add_wheel('foundation', '1.5', requires_python='<3.13', dynamic=('requires-python',))
        self.refused(reason='requires_python')

    def test_dynamic_provides_extra_still_activates_transitive_requirements(self):
        self.add_app(('foundation[render]>=1',), dynamic=('Provides-Extra', 'Requires-Dist'))
        self.add_wheel('foundation', '1.5', extras=('render',),
                       requires=('leaf>=1; extra == "render"',),
                       dynamic=('Provides-Extra', 'Requires-Dist'))
        self.add_wheel('leaf')
        receipt = self.succeeds(receipt=self.output.parent / 'valid.json')
        self.assertEqual(receipt['activated_extras']['foundation'], ['render'])
        self.assertIn('leaf', receipt['reached_distributions'])
        self.add_wheel('foundation', '1.5', extras=(), dynamic=('Provides-Extra',))
        self.refused(reason='unknown_extra')

    def test_dynamic_identity_fields_are_refused_case_insensitively(self):
        for field in ('Name', 'nAmE', 'Version', 'vErSiOn', 'Metadata-Version', 'mEtAdAtA-vErSiOn'):
            with self.subTest(field=field):
                self.add_wheel('foundation', '1.5', dynamic=(field,))
                self.refused(reason='dynamic_metadata')

    def test_dynamic_is_refused_before_metadata_2_2(self):
        for version in ('1.0', '1.2', '2.1'):
            with self.subTest(version=version):
                self.add_wheel('foundation', '1.5', metadata_version=version, dynamic=('Summary',))
                self.refused(reason='dynamic_metadata')

    def test_dynamic_metadata_version_comparison_is_numeric(self):
        for version in ('2.2', '2.4', '2.10'):
            with self.subTest(version=version):
                self.add_wheel('foundation', '1.5', metadata_version=version, dynamic=('Summary',))
                self.succeeds(receipt=self.output.parent / (version + '.json'))

    def test_unknown_marker_variables_even_on_inactive_edges_refuse(self):
        for variable in ('platform_release', 'platform_version', 'extras', 'dependency_groups'):
            with self.subTest(variable=variable):
                self.add_app(('foundation>=1; python_version < "3" and ' + variable + ' == "pi"',))
                self.refused(reason='unknown_marker_variable')

    def test_mixed_quoted_literals_cannot_hide_kernel_marker_variables(self):
        markers = ('python_version == "3.13\'" and platform_release == \'fixture\'',
                   'python_version == \'3.13"\' and platform_version == "fixture"',
                   'os_name == \'x"y\' or platform_version == \'z"w\'')
        for marker in markers:
            with self.subTest(marker=marker):
                self.add_app(('foundation>=1; ' + marker,))
                self.refused(reason='unknown_marker_variable')

    def test_kernel_variable_spelling_inside_quoted_literal_is_allowed(self):
        self.add_app(('foundation>=1; os_name != \'platform_version"x\'',))
        self.assertEqual(self.succeeds()['reached_distributions'], ['foundation', 'inky-studio'])

    def test_transitive_prerelease_without_explicit_permission_refuses(self):
        for version in ('2.0rc1', '2.0.dev1'):
            with self.subTest(version=version):
                name = self.add_wheel('preview', version)
                self.add_app(('foundation>=1', 'preview>=1'))
                self.refused()
                self.remove_wheel(name)

    def test_transitive_prerelease_explicitly_allowed_by_edge_passes(self):
        self.add_app(('foundation>=1', 'preview>=2.0rc1,<3'))
        self.add_wheel('preview', '2.0rc2')
        self.assertIn('preview', self.succeeds()['reached_distributions'])

    def test_each_edge_must_explicitly_allow_transitive_prerelease(self):
        self.add_app(('foundation>=1', 'preview>=2.0rc1'))
        self.add_wheel('preview', '2.0rc2')
        self.add_wheel('foundation', '1.5', requires=('preview>=1',))
        self.refused()

    def test_prerelease_permission_does_not_override_another_constraint(self):
        self.add_app(('foundation>=1', 'preview>=2.0rc1'))
        self.add_wheel('preview', '2.0rc2')
        self.add_wheel('foundation', '1.5', requires=('preview<2.0rc2',))
        self.refused()

    def test_input_pin_mismatch_refuses_without_receipt(self):
        self.refused(input_sha256='0' * 64)

    def test_changed_source_or_wheel_bytes_refuse_without_receipt(self):
        source = self.sources / 'client/dist/index.html'
        original = source.read_bytes()
        self.write(source, original + b'changed')
        self.refused()
        self.write(source, original)
        wheel = self.wheels / 'foundation-1.5-py3-none-any.whl'
        self.write(wheel, wheel.read_bytes() + b'changed')
        self.refused()

    def test_invalid_record_refuses_even_when_wheel_pin_is_updated(self):
        self.add_wheel('foundation', '1.5', record_transform=lambda raw: raw.replace(b'sha256=', b'sha512=', 1))
        self.refused()

    def test_existing_receipt_is_preserved(self):
        self.write(self.output, b'existing receipt must remain byte-identical\n')
        self.refused()

    def test_ambient_pythonpath_and_working_directory_packages_are_ignored(self):
        poison = b'raise AssertionError("ambient packaging or site hook imported")\n'
        self.write(self.base / 'packaging/__init__.py', poison)
        self.write(self.base / 'sitecustomize.py', poison)
        environment = dict(os.environ, PYTHONPATH=str(self.base), PYTHONHOME=str(self.base / 'absent'))
        self.assertEqual(self.succeeds(environment=environment)['wheel_count'], 2)
        self.assertFalse(list(self.base.rglob('__pycache__')))

    def test_preloaded_packaging_namespace_is_refused_by_real_cli(self):
        bootstrap = ('import runpy, sys, types\n'
                     'sys.modules["packaging"] = types.ModuleType("packaging")\n'
                     'sys.argv = sys.argv[1:]\n'
                     'runpy.run_path(sys.argv[0], run_name="__main__")\n')
        self.refused(bootstrap=bootstrap, reason='ambient_packaging')

    def test_tooling_cleans_up_exceptions_and_active_never_looks_up_host(self):
        # Every assertion runs before the child exits: process teardown cannot
        # provide the namespace or private-directory cleanup being tested.
        code = r'''
import importlib.util
from pathlib import Path
import sys
import zipimport

spec = importlib.util.spec_from_file_location('dependency_context_fixture', sys.argv[1])
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)

def forbidden_host_lookup(*args, **kwargs):
    raise AssertionError('host marker environment queried')

for exception_type in (RuntimeError, KeyboardInterrupt, SystemExit):
    expected = exception_type('inert context exception')
    try:
        with verifier.tooling() as api:
            snapshot = Path(sys.modules['packaging'].__file__.split('/packaging/', 1)[0])
            private_directory = snapshot.parent
            assert snapshot.is_file() and private_directory.is_dir()
            api['markers'].default_environment = forbidden_host_lookup
            requirement = api['requirements'].Requirement(
                'foundation>=1; sys_platform == "linux" and platform_machine == "aarch64" '
                'and python_full_version == "3.13.5" and extra == "pi"')
            assert verifier.active(requirement, {'pi'}, api)
            assert not verifier.active(requirement, set(), api)
            raise expected
    except BaseException as observed:
        assert observed is expected, (exception_type.__name__, repr(observed))
    else:
        raise AssertionError('context swallowed caller exception')
    assert not any(name == 'packaging' or name.startswith('packaging.') for name in sys.modules)
    assert not snapshot.exists() and not private_directory.exists()
    assert str(snapshot) not in zipimport._zip_directory_cache
    assert not any(key == str(snapshot) or key.startswith(str(snapshot) + '/')
                   for key in sys.path_importer_cache)
print('cleanup-and-fixed-target-verified')
'''
        before = self.snapshot()
        result = subprocess.run([sys.executable, '-I', '-B', '-S', '-c', code, str(ROOT / SCRIPT)],
                                cwd=self.base, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertEqual(result.stdout, b'cleanup-and-fixed-target-verified\n')
        self.assertEqual(result.stderr, b'')
        self.assertEqual(self.snapshot(), before)

    def test_hosted_tooling_wheel_tampering_refuses(self):
        repository = self.hosted_repository()
        path = repository / TOOLING
        raw = path.read_bytes()
        self.write(path, bytes((raw[0] ^ 1,)) + raw[1:])
        self.refused(repository=repository, reason='invalid_tooling')

    def test_hosted_tooling_lock_tampering_refuses(self):
        repository = self.hosted_repository()
        original = json.loads((repository / LOCK).read_bytes())
        for key, value in (('schema_version', True), ('sha256', '0' * 64), ('version', '26.2')):
            with self.subTest(field=key):
                self.write(repository / LOCK, canonical({**original, key: value}))
                self.refused(repository=repository, reason='invalid_tooling')

    def test_hosted_cli_ignores_adjacent_packaging_shadow(self):
        repository = self.hosted_repository()
        self.write(repository / 'scripts/packaging/__init__.py',
                   b'raise AssertionError("adjacent packaging shadow imported")\n')
        self.assertEqual(self.succeeds(repository=repository)['wheel_count'], 2)


if __name__ == '__main__':
    unittest.main()
