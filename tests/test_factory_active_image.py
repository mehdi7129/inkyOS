"""Source recipe tests: real snapshot hashes, simulated commands, no mounts/target code."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('factory_active_image_test', ROOT / 'scripts/build-factory-active-linux.py')
builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)


class Files(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='factory-image-test-', dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(temp.cleanup)
        self.work = Path(temp.name); self.work.chmod(0o700)
        attributes = patch.object(builder.inventory, '_xattrs', return_value=builder.exporter.EMPTY_XATTRS)
        attributes.start(); self.addCleanup(attributes.stop)

    def write(self, path, raw=b'fixture\n', mode=0o600):
        path = self.work / path; path.parent.mkdir(parents=True, exist_ok=True)
        for parent in path.parents:
            if parent == self.work:
                break
            parent.chmod(0o755)
        path.write_bytes(raw); path.chmod(mode)
        return path

    def json(self, path, value):
        return self.write(path, builder.canonical(value))

    def pin(self, path):
        return builder.digest_file(self.work / path)['sha256']


class SnapshotTests(Files):
    def setUp(self):
        super().setUp()
        for name in builder.SNAPSHOT_ROOTS:
            (self.work / name).mkdir(mode=0o755)
        for name in builder.SNAPSHOT_FILES:
            self.write(name)
        self.write('recipe/scripts/build-factory-active-linux.py')
        self.write('factory-inputs/inputs.json')
        self.json('recipe/recipe-inputs.json', {'files': {
            'scripts/build-factory-active-linux.py': self.pin('recipe/scripts/build-factory-active-linux.py')}})
        files = {}
        for path in self.work.rglob('*'):
            if path.is_file():
                files[str(path.relative_to(self.work))] = builder.digest_file(path)
        self.inputs = {'schema_version': 1, 'kind': 'factory-active-image-inputs', 'files': files,
                       'trigger_sha256': 'a' * 64, 'readelf': {'path': '/usr/bin/readelf', 'sha256': 'b' * 64}}
        self.repin()

    def repin(self):
        self.json('factory-active-inputs.json', self.inputs)
        self.input_pin = self.pin('factory-active-inputs.json')

    def verify(self):
        return builder.verify_snapshot(self.work, self.input_pin, _owner=(os.geteuid(), os.getegid()))

    def test_exact_snapshot_round_trip(self):
        self.assertEqual(self.verify(), self.inputs)

    def test_wrong_hash_extra_missing_or_hardlinked_file_refuses(self):
        target = self.work / 'base.img'
        original = target.read_bytes(); target.write_bytes(b'changed')
        with self.assertRaises(ValueError): self.verify()
        target.write_bytes(original)
        extra = self.write('packages/extra.deb')
        with self.assertRaises(ValueError): self.verify()
        extra.unlink()
        os.link(target, self.work / 'packages/hardlink.deb')
        with self.assertRaises(ValueError): self.verify()

    def test_escape_absolute_or_unknown_staging_path_refuses(self):
        for name in ('../outside', '/etc/passwd', 'candidate.img', 'review/support.json'):
            with self.subTest(name=name):
                value = copy.deepcopy(self.inputs)
                value['files'][name] = {'sha256': 'c' * 64, 'size_bytes': 1}
                self.inputs = value; self.repin()
                with self.assertRaises(ValueError): self.verify()

    def test_symlink_source_and_group_writable_file_refuse(self):
        target = self.work / 'base.img'; target.unlink(); target.symlink_to('/etc/passwd')
        with self.assertRaises(ValueError): self.verify()
        target.unlink(); target.write_bytes(b'fixture\n'); target.chmod(0o666)
        with self.assertRaises(ValueError): self.verify()

    def test_recipe_manifest_covers_every_recipe_file(self):
        self.write('recipe/scripts/unlisted.py')
        self.inputs['files']['recipe/scripts/unlisted.py'] = builder.digest_file(self.work / 'recipe/scripts/unlisted.py')
        self.repin()
        with self.assertRaisesRegex(ValueError, 'recipe_manifest_mismatch'): self.verify()

    def test_explicit_manifest_pin_and_duplicate_json_are_required(self):
        self.input_pin = '0' * 64
        with self.assertRaises(ValueError): self.verify()
        self.write('factory-active-inputs.json', b'{"schema_version":1,"schema_version":1}')
        self.input_pin = self.pin('factory-active-inputs.json')
        with self.assertRaises(ValueError): self.verify()


class FakeCommands:
    def __init__(self, work, readonly=False):
        self.work, self.readonly, self.calls = work, readonly, []
        self.fail_umount = False

    def __call__(self, command, *, capture=False, log=None):
        self.calls.append(command)
        if command[:2] == ['losetup', '--find']:
            return '/dev/loop17'
        if command[:2] == ['losetup', '--json']:
            return json.dumps({'loopdevices': [{'name': '/dev/loop17', 'back-file': str(self.work / 'candidate.img'),
                                               'ro': self.readonly}]})
        if command[0] == 'lsblk':
            return json.dumps({'blockdevices': [{'name': '/dev/loop17', 'type': 'loop', 'children': [
                {'name': '/dev/loop17p1', 'type': 'part'}, {'name': '/dev/loop17p2', 'type': 'part'}]}]})
        if command[0] == 'blkid':
            return 'vfat' if command[-1].endswith('p1') else 'ext4'
        if command[0] == 'umount' and self.fail_umount:
            raise ValueError('simulated busy mount')
        if log:
            log.write_bytes(b'clean\n')


class MountTests(Files):
    def setUp(self):
        super().setUp(); self.write('candidate.img')
        owner = os.geteuid(), os.getegid()
        original = builder.trust
        seam = patch.object(builder, 'trust', side_effect=lambda path, **kwargs: original(path, **{**kwargs, 'owner': owner}))
        seam.start(); self.addCleanup(seam.stop)

    def test_proposal_loop_and_mounts_are_readonly_without_journal_replay(self):
        run = FakeCommands(self.work, readonly=True)
        with builder.MountedImage(self.work, 'proposal', run):
            pass
        self.assertIn('--read-only', run.calls[0])
        mounts = [call for call in run.calls if call[0] == 'mount']
        self.assertEqual(len(mounts), 2)
        self.assertIn('ro,noload,nosuid,nodev,noexec', mounts[0])
        self.assertFalse(any(call[0] == 'chroot' for call in run.calls))
        self.assertEqual(run.calls[-1], ['losetup', '--detach', '/dev/loop17'])
        self.assertFalse((self.work / 'root').exists())

    def test_failed_unmount_never_forces_detach(self):
        run = FakeCommands(self.work)
        mounted = builder.MountedImage(self.work, 'prepare', run).__enter__()
        run.fail_umount = True
        with self.assertRaisesRegex(ValueError, 'cleanup_incomplete'):
            mounted.close()
        self.assertFalse(any(call[:2] == ['losetup', '--detach'] for call in run.calls))
        self.assertTrue((self.work / 'root').exists())

    def test_readonly_inventory_precedes_fsck_and_detach(self):
        run = FakeCommands(self.work)
        with builder.MountedImage(self.work, 'prepare', run) as mounted:
            mounted.freeze_inventory('fixture')
        root_remount = next(i for i, call in enumerate(run.calls) if call[:2] == ['mount', '-o'])
        fsck = next(i for i, call in enumerate(run.calls) if call[0] == 'e2fsck')
        self.assertLess(root_remount, fsck)
        self.assertEqual(run.calls[-1], ['losetup', '--detach', '/dev/loop17'])
        self.assertTrue((self.work / 'fixture-filesystem.json').exists())

    def test_private_dev_exposes_exactly_four_synthetic_devices(self):
        run = FakeCommands(self.work)
        with builder.MountedImage(self.work, 'prepare', run) as mounted:
            mounted.device_tree()
        calls = [call for call in run.calls if call[0] == 'mknod']
        self.assertEqual([(Path(call[3]).name, call[-2:]) for call in calls], [
            ('null', ['1', '3']), ('zero', ['1', '5']), ('random', ['1', '8']), ('urandom', ['1', '9'])])
        self.assertFalse(any('bind' in part for call in run.calls for part in call))

    def test_invalid_losetup_result_is_not_detached_as_a_device(self):
        run = Mock(return_value='/dev/sda')
        with self.assertRaisesRegex(ValueError, 'invalid_loop'):
            builder.MountedImage(self.work, 'prepare', run).__enter__()
        self.assertFalse(any(call.args[0][:2] == ['losetup', '--detach'] for call in run.call_args_list))


class CheckpointTests(Files):
    def prepared(self):
        self.write('candidate.img', b'prepared image')
        self.json('prepare-filesystem.json', {'rootfs': {}, 'bootfs': {}})
        value = {'schema_version': 1, 'kind': 'factory-active-prepared-image',
                 'input_manifest_sha256': 'a' * 64, 'image': builder.digest_file(self.work / 'candidate.img'),
                 'filesystem_manifest_sha256': self.pin('prepare-filesystem.json'),
                 'exportable_image': False, 'hardware_qualified': False, 'preserved': {}}
        self.json('prepared-receipt.json', value)
        return self.pin('prepared-receipt.json')

    def test_prepared_checkpoint_binds_image_and_inventory(self):
        pin = self.prepared()
        self.assertFalse(builder.prepared_receipt(self.work, 'a' * 64, pin)['exportable_image'])
        self.write('candidate.img', b'mutated')
        with self.assertRaisesRegex(ValueError, 'prepared_image_mismatch'):
            builder.prepared_receipt(self.work, 'a' * 64, pin)

    def test_fresh_hash_of_altered_receipt_does_not_bypass_inputs(self):
        pin = self.prepared()
        with self.assertRaises(ValueError):
            builder.prepared_receipt(self.work, 'b' * 64, pin)

    def test_review_references_real_prepared_proposal_inventory_and_evidence(self):
        owner = os.geteuid(), os.getegid()
        original = builder.trust
        with patch.object(builder, 'trust', side_effect=lambda path, **kwargs: original(path, **{**kwargs, 'owner': owner})), \
             patch.object(builder.exporter, 'load_lock') as load_lock, patch.object(builder.exporter, 'load_support') as load_support:
            self.json('exporter-inputs/lock.json', {'source_sha256': {'fixture.py': 'a' * 64}})
            support = {'kind': 'factory-exporter-system-support', 'paths': {}}
            self.json('support-proposal.json', {'support_candidate': support})
            self.json('review/evidence.json', {'independent_observations': ['fixture']})
            evidence_pin = self.pin('review/evidence.json')
            self.json('review/support.json', {**support, 'elf_closure_review': {'evidence_sha256': evidence_pin}})
            support_pin = self.pin('review/support.json')
            self.json('review/exporter.lock.json', {'source_sha256': {'fixture.py': 'a' * 64}, 'support_manifest_sha256': support_pin})
            review = {'schema_version': 1, 'kind': 'factory-support-independent-review',
                      'prepared_receipt_sha256': 'e' * 64, 'proposal_sha256': self.pin('support-proposal.json'),
                      'support_manifest_sha256': support_pin, 'exporter_lock_sha256': self.pin('review/exporter.lock.json'),
                      'evidence_sha256': evidence_pin}
            self.json('review/review.json', review); (self.work / 'review').chmod(0o700)
            review_pin = self.pin('review/review.json')
            actual, _ = builder.review_inputs(self.work, review_pin, 'e' * 64)
            self.assertEqual(actual, review)
            load_lock.assert_called_once(); load_support.assert_called_once()
            self.write('review/evidence.json', b'changed')
            (self.work / 'review').chmod(0o700)
            with self.assertRaisesRegex(ValueError, 'review_evidence_pin_mismatch'):
                builder.review_inputs(self.work, review_pin, 'e' * 64)
            self.assertFalse((self.work / 'candidate-receipt.json').exists())

    def test_compose_checks_hash_before_remount_and_preserves_failed_candidate(self):
        pin = self.prepared(); self.write('candidate.img', b'altered before proposal')
        with patch.object(builder, 'workspace'), patch.object(builder, 'private_namespaces', return_value=True), \
             patch.object(builder, 'verified_inputs', return_value=({}, {}, {})), patch.object(builder, 'MountedImage') as mounting:
            with self.assertRaises(ValueError):
                builder.compose(self.work, 'proposal', inputs_sha256='a' * 64, prepared_sha256=pin)
            mounting.assert_not_called()
            self.assertFalse((self.work / 'support-proposal.json').exists())

    def test_prepare_failure_leaves_no_export_or_prepared_receipt(self):
        self.write('base.img', b'base')
        inputs = {'files': {'base.img': builder.digest_file(self.work / 'base.img')}}
        with patch.object(builder, 'workspace'), patch.object(builder, 'private_namespaces', return_value=True), \
             patch.object(builder, 'verified_inputs', return_value=(inputs, {}, {})), \
             patch.object(builder, 'MountedImage'), patch.object(builder, 'preserved', return_value={}), \
             patch.object(builder, 'mutate_system', side_effect=ValueError('package failure')):
            with self.assertRaisesRegex(ValueError, 'package failure'):
                builder.compose(self.work, 'prepare', inputs_sha256='a' * 64)
        self.assertTrue((self.work / 'candidate.img').exists())
        self.assertFalse((self.work / 'prepared-receipt.json').exists())
        self.assertFalse((self.work / 'candidate-receipt.json').exists())

    def test_partial_finalize_fence_disallows_retry(self):
        pin = self.prepared(); self.json('finalize-started.json', {'fixture': True})
        with patch.object(builder, 'workspace'), patch.object(builder, 'private_namespaces', return_value=True), \
             patch.object(builder, 'verified_inputs', return_value=({}, {}, {})), patch.object(builder, 'MountedImage') as mounting:
            with self.assertRaisesRegex(ValueError, 'partial_finalize_cannot_be_retried'):
                builder.compose(self.work, 'finalize', inputs_sha256='a' * 64, prepared_sha256=pin, review_sha256='f' * 64)
            mounting.assert_not_called()

    def test_workspace_rejects_host_paths_before_commands(self):
        for path in (Path('/'), Path('/var/lib/inkyos-build'), Path('/dev/sda'), self.work):
            with self.subTest(path=path), self.assertRaises(ValueError):
                builder.workspace(path)

    def test_prepare_orders_bundle_before_parents_and_stage_then_records_active_release(self):
        self.write('root/etc/passwd', b'pi:x:1000:1000::/home/pi:/bin/bash\n')
        (self.work / 'root/usr/sbin').mkdir(parents=True)
        (self.work / 'root/var/tmp').mkdir(parents=True)
        self.write('packages/fixture.deb')
        self.json('factory-active-inputs.json', {'fixture': True})
        calls = []
        metadata = {'kind': 'factory-passive-profile'}
        tree = builder.load('configure-rootfs.py').Tree
        def configure(root, boot, recipe, *, factory):
            calls.append('configure')
            self.json('root/etc/inkyos-release.json', {'kind': 'factory-passive', 'factory': factory})
        modules = {
            'install-test-access-packages.py': SimpleNamespace(install=lambda *args: calls.append('i2c')),
            'factory-passive-profile.py': SimpleNamespace(metadata=lambda *args: metadata),
            'configure-rootfs.py': SimpleNamespace(configure=configure, Tree=tree),
            'factory-assembly-profile.py': SimpleNamespace(prepare_rootfs=lambda *args: calls.append('assembly')),
            'configure-factory-active-prerequisites.py': SimpleNamespace(configure=lambda *args: calls.append('parents') or {}),
            'configure-factory-active-profile.py': SimpleNamespace(stage=lambda *args, **kwargs: calls.append('stage') or {}),
        }
        def target(run, work, command, log):
            calls.append(command[0])
            if '--audit' in command:
                self.write(log, b'')
        mounted = SimpleNamespace(device_tree=lambda: calls.append('private-dev'), mounted=['root/dev'])
        run = Mock()
        with patch.object(builder, 'load', side_effect=modules.__getitem__), patch.object(builder, 'target', side_effect=target):
            builder.mutate_system(self.work, {'trigger_sha256': 'a' * 64},
                {'input_manifest_sha256': 'b' * 64, 'studio_commit': 'c' * 40},
                {'packages': [{'filename': 'fixture.deb', 'name': 'fixture'}]}, mounted, run)
        self.assertLess(calls.index('i2c'), calls.index('configure'))
        self.assertLess(calls.index('configure'), calls.index('assembly'))
        self.assertLess(calls.index('assembly'), calls.index('parents'))
        self.assertLess(calls.index('parents'), calls.index('stage'))
        release = builder.json_file(self.work / 'root/etc/inkyos-release.json')
        self.assertEqual(release['kind'], 'factory-active')
        self.assertEqual(release['factory']['kind'], 'factory-active-profile')
        self.assertFalse((self.work / 'root/usr/sbin/policy-rc.d').exists())
        self.assertFalse(any('app' in call or 'systemctl' in call for call in calls))


if __name__ == '__main__':
    unittest.main()
