"""Synthetic readonly return trees; never a mounted device or native evidence.

Output-writer tests replace only filesystem ownership/target gates to exercise
regular temporary files. They do not call a native comparison or issue context
for a real device. The target private-key placeholder is never opened.
"""
import base64
import contextlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


controller = load('access_return_fixture_controller', 'scripts/verify-test-access-return.py')
seed = load('access_return_fixture_export', 'tests/test_test_access_export.py')
policy = controller.policy


def put(root, relative, raw, mode=0o644):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    for parent in (path.parent, *path.parent.parents):
        if parent == root:
            break
        parent.chmod(0o755)
    if path.exists():
        path.chmod(0o600)
    path.write_bytes(raw)
    path.chmod(mode)
    return path


class FixtureAdapter(controller.NativeAdapter):
    def __init__(self, root, boot, export, context_output=None):
        super().__init__(root, boot, export, context_output)
        self.mount_result = dict.fromkeys(controller.legacy.CHECKS[:2], True)

    def environment(self):
        return True

    def open(self):
        for path, fat, private in zip(self.paths, (False, True, False), (False, False, True)):
            self.trees.append(controller.ReadTree(path, owner=os.geteuid(), group=os.getegid(),
                fat=fat, private=private, _fixture=True))
        self.root, self.boot, self.export = self.trees

    def mounts(self):
        return self.mount_result


class AccessReturnTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root, self.boot, self.export, self.outputs = (self.base / name
            for name in ('root', 'boot', 'expected', 'outputs'))
        for path in (self.root, self.boot, self.export, self.outputs):
            path.mkdir(mode=0o700)
            path.chmod(0o700)
        captured = []
        function = seed.seed.verify.overlay.expected_metadata
        def capture(*args, **kwargs):
            result = function(*args, **kwargs)
            captured.append(result)
            return result
        with mock.patch.object(seed.seed.verify.overlay, 'expected_metadata', side_effect=capture):
            self.manifest, self.blobs = seed.fixture(self.export)
        self.marker = policy.canonical(captured[0])
        for path in self.export.iterdir():
            path.chmod(0o600)
        self.profile_raw = self.blobs['private-profile.json']
        self.profile = policy.strict_json(self.profile_raw)
        self.profile_hash = controller.digest(self.profile_raw)
        wire = policy.public_key(self.profile['operator_public_key'])
        self.host = 'ssh-ed25519 ' + base64.b64encode(wire[:-32] + b'h' * 32).decode()
        self.state = {'schema_version': 1, 'kind': 'test-lan-enrollment-state', 'state': 'enrolled',
            'profile_sha256': self.profile_hash, 'application_activation_authorized': False}
        self.system = {'version': 1, 'hostname': 'inky-' + 'a' * 32}
        self.report = {'schema_version': 2, 'kind': 'test-lan-enrollment-report', 'state': 'enrolled',
            'challenge': self.profile['challenge'], 'application_source_commit': policy.SOURCE,
            'application_manifest_sha256': policy.MANIFEST_HASH, 'parent_image_sha256': policy.PARENT_IMAGE_SHA256,
            'profile_sha256': self.profile_hash, 'host_public_key': self.host,
            'host_public_key_sha256': controller.digest(policy.public_key(self.host)),
            'runtime_source_sha256': controller.digest(self.blobs['scripts/test-access-enrollment.py']),
            'access_runtime_manifest_sha256': self.profile['access_runtime_manifest_sha256'],
            'observations': {kind: {'status': 'blocked', 'live_evidence': False, 'data': None}
                             for kind in ('panel', 'radio')},
            'live_evidence': True, **dict.fromkeys(policy.FALSE_FIELDS, False)}
        for relative, raw, mode in (
            (controller.PROFILE, self.profile_raw, 0o600),
            (controller.STATE, policy.canonical(self.state), 0o600),
            (controller.PUBLIC_KEY, (self.host + ' inkyos-test-host\n').encode(), 0o644),
            (controller.PRIVATE_KEY, b'SYNTHETIC_PRIVATE_PLACEHOLDER_NEVER_OPENED', 0o600),
            (controller.MANIFEST, self.blobs['test-access-manifest.json'], 0o644),
            (controller.SYSTEM, json.dumps(self.system, separators=(',', ':')).encode() + b'\n', 0o600),
            (controller.HOSTNAME, (self.system['hostname'] + '\n').encode(), 0o644),
            (controller.APPLICATION_MANIFEST, self.blobs['application-manifest.json'], 0o444),
            (controller.MARKER, self.marker, 0o644),
        ):
            put(self.root, relative, raw, mode)
        for name, (relative, mode) in controller.export_contract.overlay.PAYLOADS.items():
            put(self.root, relative, self.blobs[name], mode)
        (self.root / controller.CACHE).mkdir(parents=True, mode=0o700)
        self.private_modes()
        self.write_report()

    def private_modes(self):
        for name in (str(Path(controller.PROFILE).parent), str(Path(controller.STATE).parent),
                     str(Path(controller.SYSTEM).parent), controller.CACHE):
            (self.root / name).chmod(0o700)

    def write_report(self):
        put(self.boot, controller.REPORT, policy.canonical(self.report))

    def adapter(self, output=None):
        return FixtureAdapter(self.root, self.boot, self.export, output)

    def check(self, code=0, adapter=None):
        result, actual = controller.compare(adapter or self.adapter())
        self.assertEqual(actual, code, result)
        return result

    def test_complete_fixture_passes_only_local_consistency_without_private_output(self):
        result = self.check()
        self.assertEqual(len(result['checks']), 35)
        self.assertTrue(all(result['checks'].values()))
        self.assertEqual(result['observation_source'], 'fixture')
        for key in ('native_readonly_evidence', 'authenticity_verified', 'runtime_execution_attested',
                    'image_sha256_verified', 'shutdown_observed', 'hardware_qualified', 'release_qualified',
                    'application_activation_authorized', 'ssh_access_enabled', 'context_written'):
            self.assertIs(result[key], False)
        self.assertEqual(result['private_output_files_written'], 0)
        output = json.dumps(result)
        for secret in (self.profile['challenge'], self.profile['operator_public_key'], self.host,
                       self.profile_hash, self.system['hostname'], str(self.base), 'SYNTHETIC_PRIVATE'):
            self.assertNotIn(secret, output)

    def test_private_key_and_image_are_stat_only_and_target_bytes_never_execute(self):
        original = os.open
        def guarded(path, *args, **kwargs):
            self.assertNotIn(os.fspath(path), ('ssh_host_ed25519_key', 'inkyos-test-access.img'))
            return original(path, *args, **kwargs)
        with mock.patch.object(os, 'open', side_effect=guarded), \
                mock.patch('subprocess.Popen', side_effect=AssertionError('No child processes')):
            self.check()

    def test_v1_report_or_profile_cannot_be_accepted(self):
        self.report['schema_version'] = 1
        self.write_report()
        self.check(2)
        self.report['schema_version'] = 2
        self.write_report()
        changed = dict(self.profile, schema_version=1)
        (self.root / controller.PROFILE).write_bytes(policy.canonical(changed))
        self.check(2)

    def test_report_pins_nonce_and_manifest_binding_must_match_ext4(self):
        for key in ('challenge', 'profile_sha256', 'application_source_commit',
                    'application_manifest_sha256', 'parent_image_sha256', 'access_runtime_manifest_sha256'):
            with self.subTest(key=key):
                saved = self.report[key]
                self.report[key] = 'b' * len(saved)
                self.write_report()
                self.check(1)
                self.report[key] = saved
        self.write_report()

    def test_pending_review_required_wrong_hash_or_noncanonical_state_fails(self):
        path = self.root / controller.STATE
        for state in ('pending', 'review-required'):
            path.write_bytes(policy.canonical(dict(self.state, state=state)))
            self.assertFalse(self.check(1)['checks']['state_enrolled'])
        path.write_bytes(policy.canonical(dict(self.state, profile_sha256='b' * 64)))
        self.assertFalse(self.check(1)['checks']['state_profile_binding'])
        path.write_bytes(json.dumps(self.state).encode())
        self.assertFalse(self.check(1)['checks']['state_canonical'])

    def test_all_static_payloads_are_rehashed_with_installed_metadata(self):
        for name, (relative, mode) in controller.export_contract.overlay.PAYLOADS.items():
            with self.subTest(path=relative):
                path = self.root / relative
                path.chmod(0o600)
                path.write_bytes(b'raise AssertionError("TARGET_NOT_EXECUTED")\n')
                path.chmod(mode)
                self.assertFalse(self.check(1)['checks']['installed_payloads_binding'])
                path.chmod(0o600)
                path.write_bytes(self.blobs[name])
                path.chmod(mode)

    def test_manifest_cannot_redirect_reads_to_untrusted_paths(self):
        manifest = policy.strict_json(self.blobs['test-access-manifest.json'])
        manifest['files']['../../PRIVATE_DO_NOT_OPEN'] = {'mode': '0600', 'sha256': 'b' * 64}
        (self.root / controller.MANIFEST).write_bytes(policy.canonical(manifest))
        original = os.open
        def guarded(path, *args, **kwargs):
            self.assertNotIn('PRIVATE_DO_NOT_OPEN', os.fspath(path))
            return original(path, *args, **kwargs)
        with mock.patch.object(os, 'open', side_effect=guarded):
            self.assertFalse(self.check(1)['checks']['access_manifest_matches_expected_bytes'])

    def test_application_metadata_files_match_exact_validated_inventory(self):
        for relative in controller.APPLICATION_FILES:
            with self.subTest(path=relative):
                path = self.root / relative
                original, mode = path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
                path.chmod(0o600)
                path.write_bytes(b'{}\n')
                path.chmod(mode)
                self.assertFalse(self.check(1)['checks']['application_installed_binding'])
                path.chmod(0o600)
                path.write_bytes(original)
                path.chmod(mode)

    def test_system_identity_and_hostname_are_strict_and_never_echoed(self):
        path = self.root / controller.SYSTEM
        for value in ({'version': True, 'hostname': self.system['hostname']},
                      {'version': 1, 'hostname': 'inky-INVALID\n[attacker]:2222'},
                      dict(self.system, private='DO_NOT_ECHO')):
            path.write_bytes(policy.canonical(value))
            result = self.check(1)
            self.assertFalse(result['checks']['system_identity_schema'])
            self.assertNotIn('DO_NOT_ECHO', json.dumps(result))
        path.write_bytes(policy.canonical(self.system))
        (self.root / controller.HOSTNAME).write_bytes(b'inky-' + b'b' * 32 + b'\n')
        self.assertFalse(self.check(1)['checks']['system_hostname_binding'])

    def test_public_key_wire_report_and_comment_are_strict(self):
        public = self.root / controller.PUBLIC_KEY
        original = public.read_bytes()
        for raw in (b'ssh-ed25519 AAAA\n', original.replace(b'inkyos-test-host', b'other'),
                    original + b'PRIVATE_TRAILER\n'):
            public.write_bytes(raw)
            self.check(2)
        public.write_bytes(original)
        self.report['host_public_key_sha256'] = 'b' * 64
        self.write_report()
        self.assertFalse(self.check(1)['checks']['host_public_binding'])

    def test_missing_file_or_partial_private_directory_never_passes(self):
        state = self.root / controller.STATE
        state.unlink()
        self.assertEqual(self.check(1)['error'], 'return_incomplete')
        state.write_bytes(policy.canonical(self.state)); state.chmod(0o600)
        partial = state.with_name('.state.json.tmp')
        partial.write_bytes(b'PRIVATE_UNREAD'); partial.chmod(0o600)
        self.assertFalse(self.check(1)['checks']['no_partial_artifacts'])

    def test_existing_access_cache_capsule_or_operator_config_blocks_context(self):
        for root, name in ((self.root, controller.CACHE + '/state.json'),
                           (self.root, 'etc/inkyos-test-operator.json'), (self.boot, 'iNkYaCc.JsN')):
            with self.subTest(path=name):
                path = root / name
                path.write_bytes(b'PRIVATE_UNREAD'); path.chmod(0o600)
                self.assertFalse(self.check(1)['checks']['access_not_started'])
                path.unlink()

    def test_unsafe_mount_refuses_before_any_private_or_expected_read(self):
        adapter = self.adapter()
        adapter.mount_result[controller.CHECKS[0]] = False
        adapter.expected = mock.Mock(side_effect=AssertionError('No export reads'))
        adapter.returned = mock.Mock(side_effect=AssertionError('No target reads'))
        self.assertEqual(self.check(1, adapter)['error'], 'readonly_mount_required')
        adapter.expected.assert_not_called(); adapter.returned.assert_not_called()

    def test_symlink_writable_metadata_and_changed_reads_refused(self):
        path = self.root / controller.PROFILE
        raw = path.read_bytes()
        path.chmod(0o644)
        self.check(2)
        path.unlink()
        other = self.base / 'outside-profile'; other.write_bytes(raw); other.chmod(0o600)
        path.symlink_to(other)
        self.check(2)
        path.unlink(); path.write_bytes(raw); path.chmod(0o600)
        adapter = self.adapter()
        adapter.stable = lambda: False
        self.assertFalse(self.check(1, adapter)['checks']['reads_stable'])

    def test_duplicate_float_bool_version_extra_field_and_live_claim_refused(self):
        path = self.boot / controller.REPORT
        for raw in (b'{"schema_version":2,"schema_version":2}', b'{"value":1.5}', b'{"value":NaN}',
                    policy.canonical(dict(self.report, schema_version=True)),
                    policy.canonical(dict(self.report, hardware_qualified=True)),
                    policy.canonical(dict(self.report, private='DO_NOT_ECHO'))):
            path.write_bytes(raw)
            self.check(2)
        self.report['live_evidence'] = False
        self.write_report()
        self.assertFalse(self.check(1)['checks']['public_report_live_claim'])

    def test_export_report_tamper_and_image_size_mismatch_fail_without_image_read(self):
        path = self.export / 'test-access-configuration.json'
        saved = path.read_bytes()
        path.write_bytes(saved + b' ')
        self.check(2)
        path.write_bytes(saved)
        image = self.export / self.manifest['image']['filename']
        image.write_bytes(b'wrong-size')
        self.check(2)

    def test_fixture_cannot_issue_context_or_known_hosts_even_after_all_checks_pass(self):
        output = self.outputs / 'new'
        result = self.check(2, self.adapter(str(output)))
        self.assertTrue(all(result['checks'].values()))
        self.assertFalse(result['native_readonly_evidence'])
        self.assertFalse(result['context_written'])
        self.assertFalse(output.exists())

    def test_output_failure_is_not_a_successful_comparison_or_context_receipt(self):
        adapter = self.adapter(str(self.outputs / 'unused'))
        # Simulate an output I/O failure only; no context is ever issued by this
        # fixture. The success checks must not override an output failure.
        with mock.patch.object(controller, '_write_context', side_effect=OSError('PRIVATE_FAILURE')):
            result = self.check(2, adapter)
        self.assertTrue(all(result['checks'].values()))
        self.assertFalse(result['passed'])
        self.assertFalse(result['context_written'])
        self.assertEqual(result['private_output_files_written'], 0)
        self.assertEqual(result['error'], 'context_output_refused')
        self.assertNotIn('PRIVATE_FAILURE', json.dumps(result))

    def context(self):
        return controller._context(self.profile, self.profile_hash,
            controller.digest(policy.public_key(self.host)), self.profile['access_runtime_manifest_sha256'])

    @contextlib.contextmanager
    def writer_fixture(self, output):
        """Filesystem-only seam. No native compare or live-evidence output."""
        adapter = controller.NativeAdapter(str(self.root), str(self.boot), str(self.export), str(output))
        adapter.environment = lambda: True
        adapter.stable = mock.Mock(return_value=True)
        # All synthetic trees are regular directories on one test filesystem.
        # Native use instead forbids an output device shared with either image.
        adapter.output_device_allowed = lambda _parent: True
        tree, metadata = controller.ReadTree, controller.legacy.metadata
        def own_tree(path, **kwargs):
            return tree(path, owner=os.geteuid(), group=os.getegid(), _fixture=True, **kwargs)
        def own_metadata(info, _owner, _group, **kwargs):
            return metadata(info, os.geteuid(), os.getegid(), **kwargs)
        with mock.patch.object(controller, 'ReadTree', side_effect=own_tree), \
                mock.patch.object(controller.legacy, 'metadata', side_effect=own_metadata):
            yield adapter

    def known_hosts(self):
        return ('[' + self.system['hostname'] + '.local]:2222 ' + self.host + '\n').encode()

    def test_private_output_writer_modes_exact_two_files_and_capsule_schema(self):
        output = self.outputs / 'new'
        with self.writer_fixture(output) as adapter:
            controller._write_context(adapter, self.context(), self.known_hosts())
            self.assertEqual(adapter.stable.call_count, 2)
        self.assertEqual(set(x.name for x in output.iterdir()), {'context.json', 'known_hosts'})
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        for path in output.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual((output / 'known_hosts').read_bytes(), self.known_hosts())
        context = json.loads((output / 'context.json').read_bytes())
        self.assertEqual(context, self.context())
        preparer = load('access_return_context_consumer_fixture', 'scripts/prepare-test-access-capsule.py')
        capsule = preparer.capsule(context, {'ssid': 'Synthetic TEST', 'psk': 'fake-fixture-secret'})
        self.assertEqual(preparer.contract.parse_capsule(capsule, expected=context['bindings'])['nonce'],
                         self.profile['challenge'])

    def test_existing_output_alias_or_unsafe_parent_never_overwritten(self):
        output = self.outputs / 'existing'; output.mkdir(mode=0o700)
        preserved = output / 'preserved'; preserved.write_bytes(b'KEEP')
        with self.writer_fixture(output) as adapter, self.assertRaises(FileExistsError):
            controller._write_context(adapter, self.context(), self.known_hosts())
        self.assertEqual(preserved.read_bytes(), b'KEEP')
        for bad in (self.export / 'nested', self.root, self.base):
            with self.writer_fixture(bad) as adapter, self.assertRaises(ValueError):
                controller._write_context(adapter, self.context(), self.known_hosts())
        self.outputs.chmod(0o755)
        with self.writer_fixture(self.outputs / 'no') as adapter, self.assertRaises(ValueError):
            controller._write_context(adapter, self.context(), self.known_hosts())

    def test_output_same_image_filesystem_or_unknown_device_never_creates_directory(self):
        adapter = self.adapter()
        adapter.open()
        try:
            parent = controller.ReadTree(str(self.outputs), owner=os.geteuid(), group=os.getegid(),
                                         private=True, _fixture=True)
            try:
                self.assertIs(adapter.output_device_allowed(parent), False)
            finally:
                parent.close()
        finally:
            adapter.close()
        for allowed in (False, None, 1):
            output = self.outputs / 'refused'
            with self.writer_fixture(output) as writer:
                writer.output_device_allowed = lambda _parent: allowed
                with self.assertRaises(ValueError):
                    controller._write_context(writer, self.context(), self.known_hosts())
            self.assertFalse(output.exists())

    def test_second_file_failure_preserves_partial_output_without_false_commit(self):
        output = self.outputs / 'partial'
        original = os.open
        def refuse_second(path, *args, **kwargs):
            if os.fspath(path) == 'known_hosts':
                raise OSError('synthetic disk failure')
            return original(path, *args, **kwargs)
        with self.writer_fixture(output) as adapter, mock.patch.object(os, 'open', side_effect=refuse_second):
            with self.assertRaises(OSError):
                controller._write_context(adapter, self.context(), self.known_hosts())
        self.assertTrue((output / 'context.json').exists())
        self.assertFalse((output / 'known_hosts').exists())

    def test_final_output_readback_refuses_changed_first_file_after_second_creation(self):
        output = self.outputs / 'changed-between-writes'
        original = os.open
        corrupted = b'CORRUPTED_SYNTHETIC_CONTEXT\n'
        def alter_first(path, flags, *args, **kwargs):
            if os.fspath(path) == 'known_hosts' and flags & os.O_CREAT:
                (output / 'context.json').write_bytes(corrupted)
            return original(path, flags, *args, **kwargs)
        with self.writer_fixture(output) as adapter, mock.patch.object(os, 'open', side_effect=alter_first):
            with self.assertRaises(ValueError):
                controller._write_context(adapter, self.context(), self.known_hosts())
        # Own partial artifacts are retained for review; no repair or success.
        self.assertEqual(set(item.name for item in output.iterdir()), {'context.json', 'known_hosts'})
        self.assertEqual((output / 'context.json').read_bytes(), corrupted)
        self.assertEqual((output / 'known_hosts').read_bytes(), self.known_hosts())

    def test_close_failure_after_passing_comparison_is_closed_and_hides_detail(self):
        adapter = self.adapter()
        close = adapter.close
        def failed_close():
            close()
            raise OSError('PRIVATE_CLOSE_FAILURE')
        adapter.close = failed_close
        result = self.check(2, adapter)
        self.assertTrue(all(result['checks'].values()))
        self.assertIs(result['passed'], False)
        self.assertEqual(result['status'], 'INVALID')
        self.assertEqual(result['error'], 'readonly_cleanup_failed')
        self.assertFalse(result['context_written'])
        self.assertEqual(result['private_output_files_written'], 0)
        self.assertNotIn('PRIVATE_CLOSE_FAILURE', json.dumps(result))

    def test_native_close_attempts_every_tree_even_after_one_failure(self):
        adapter = controller.NativeAdapter('/unused/root', '/unused/boot', '/unused/expected')
        calls = []
        def tree(name, failed=False):
            value = mock.Mock()
            def close():
                calls.append(name)
                if failed:
                    raise OSError('PRIVATE_TREE_FAILURE')
            value.close = close
            return value
        adapter.trees = [tree('root'), tree('boot', failed=True), tree('export')]
        with self.assertRaises(OSError):
            adapter.close()
        self.assertEqual(calls, ['export', 'boot', 'root'])

    def test_cli_rejects_unknown_arguments_without_echoing_them(self):
        import io
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = controller.main(['--fixture-root', 'PRIVATE_PATH'])
        self.assertEqual(code, 2)
        self.assertNotIn('PRIVATE_PATH', output.getvalue())


if __name__ == '__main__':
    unittest.main()
