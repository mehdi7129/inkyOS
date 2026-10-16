"""Fresh-card controls only, with held synthetic roots and no service execution."""
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('active_profile_test',
    ROOT / 'scripts/configure-factory-active-profile.py')
profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profile)


class ProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='factory-profile-',
                                                dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name); self.base.chmod(0o700)
        self.root = self.base / 'root'; self.root.mkdir(mode=0o755)
        self.write('etc/machine-id', b'uninitialized\n')
        self.write('var/lib/NetworkManager/NetworkManager.state',
                   b'[main]\nWirelessEnabled=false\n', 0o600)
        self.pin = profile.runtime.sha((ROOT / 'staging/bootstrap/inkyos-factory-start.service').read_bytes())
        self.patches = [
            patch.object(profile.guards, '_production_environment', self.environment),
            patch.object(profile.guards, '_owner_ids', self.owner),
        ]
        if not sys.platform.startswith('linux'):
            self.patches.append(patch.object(profile.guards, '_xattrs', self.xattrs))
        for item in self.patches:
            item.start(); self.addCleanup(item.stop)

    def environment(self, root):
        profile.require(root == self.root and root != Path('/'), 'fixture_root_refused')
        return self.base, self.base

    def owner(self, root):
        profile.require(root == self.root and root != Path('/'), 'fixture_root_refused')
        return os.geteuid(), os.getegid()

    def xattrs(self, root, *args, **kwargs):
        profile.require(root == self.root and root != Path('/'), 'fixture_root_refused')
        return profile.guards.EMPTY_XATTRS

    def write(self, name, raw, mode=0o644):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw); path.chmod(mode)

    def snapshot(self):
        result = {}
        for path in [self.root, *sorted(self.root.rglob('*'))]:
            info = path.lstat()
            record = [info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink]
            if stat.S_ISREG(info.st_mode):
                record.append(path.read_bytes())
            elif stat.S_ISLNK(info.st_mode):
                record.append(os.readlink(path))
            result[str(path.relative_to(self.root))] = record
        return result

    def stage(self):
        return profile.stage(self.root, trigger_sha256=self.pin)

    def test_fresh_profile_has_no_credentials_or_runtime_and_closes_wlan(self):
        result = self.stage()
        self.assertTrue(result['fresh_permission_staged'])
        self.assertFalse(result['image_code_executed'])
        self.assertFalse(result['exportable_image'])
        permission = self.root / profile.PERMISSION
        self.assertEqual(set(p.name for p in permission.iterdir()), {'lock', 'pending.json'})
        self.assertEqual((permission / 'lock').read_bytes(), b'')
        self.assertEqual(stat.S_IMODE(permission.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((permission / 'pending.json').stat().st_mode), 0o600)
        journal = self.root / 'var/lib/inkyos/system-setup'
        self.assertEqual(list(journal.iterdir()), [])
        self.assertEqual(stat.S_IMODE(journal.stat().st_mode), 0o700)
        for name, target in profile.LINKS.items():
            self.assertEqual(os.readlink(self.root / name), target)
        self.assertEqual((self.root / profile.DROPIN).read_bytes(), profile.DROPIN_RAW)
        self.assertFalse((self.root / profile.runtime.MANIFEST).exists())
        self.assertFalse((self.root / 'var/lib/inky-studio').exists())
        self.assertFalse((self.root / 'var/lib/inkyos/initialization').exists())

    def test_repeat_refuses_and_preserves_permission_inode(self):
        self.stage(); before = self.snapshot()
        with self.assertRaises(ValueError):
            self.stage()
        self.assertEqual(self.snapshot(), before)

    def test_official_readonly_machine_id_preserves_mode_inode_and_bytes(self):
        path = self.root / 'etc/machine-id'; path.chmod(0o444)
        before = path.lstat(), path.read_bytes()
        self.assertTrue(self.stage()['passed'])
        after = path.lstat(), path.read_bytes()
        self.assertEqual(after[0].st_ino, before[0].st_ino)
        self.assertEqual(after[0].st_mode, before[0].st_mode)
        self.assertEqual(stat.S_IMODE(after[0].st_mode), 0o444)
        self.assertEqual(after[1], before[1])

    def test_machine_id_modes_outside_explicit_official_pair_refuse_without_write(self):
        path = self.root / 'etc/machine-id'
        for mode in (0o400, 0o440, 0o600, 0o640, 0o664, 0o666, 0o755):
            path.chmod(mode); before = self.snapshot()
            with self.subTest(mode=oct(mode)), self.assertRaises(ValueError):
                self.stage()
            self.assertEqual(self.snapshot(), before)

    def test_machine_id_mode_exception_does_not_relax_networkmanager_state(self):
        self.write('etc/machine-id', b'uninitialized\n', 0o444)
        path = self.root / 'var/lib/NetworkManager/NetworkManager.state'; path.chmod(0o644)
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'input_mode_invalid'):
            self.stage()
        self.assertEqual(self.snapshot(), before)

    def test_mode_pair_is_explicit_and_available_only_for_machine_id(self):
        with profile.offline(self.root) as env:
            for path, modes in (('var/lib/NetworkManager/NetworkManager.state', (0o444, 0o644)),
                                ('etc/machine-id', (0o444, 0o600))):
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'input_mode_policy_invalid'):
                    env.read(path, mode=modes)

    def test_existing_state_parent_must_already_be_private_and_is_not_chmodded(self):
        path = self.root / 'var/lib/inkyos'; path.mkdir(mode=0o755)
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'state_parent_not_private'):
            self.stage()
        self.assertEqual(self.snapshot(), before)
        path.chmod(0o700); inode = path.stat().st_ino
        self.assertTrue(self.stage()['passed'])
        self.assertEqual(path.stat().st_ino, inode)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)

    def test_pin_mismatch_does_not_write(self):
        before = self.snapshot()
        with self.assertRaises(ValueError):
            profile.stage(self.root, trigger_sha256='0' * 64)
        self.assertEqual(self.snapshot(), before)

    def test_booted_or_wifi_enabled_image_refuses_without_write(self):
        for name, raw, mode in (
            ('etc/machine-id', b'0' * 32 + b'\n', 0o644),
            ('var/lib/NetworkManager/NetworkManager.state', b'[main]\nWirelessEnabled=true\n', 0o600),
        ):
            path = self.root / name; original = path.read_bytes()
            self.write(name, raw, mode); before = self.snapshot()
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.stage()
            self.assertEqual(self.snapshot(), before)
            self.write(name, original, mode)

    def test_network_credentials_block_profile(self):
        self.write('etc/NetworkManager/system-connections/private.nmconnection', b'private', 0o600)
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.stage()
        self.assertEqual(self.snapshot(), before)

    def test_existing_journal_or_authority_blocks_profile(self):
        for path in ('var/lib/inkyos/system-setup', 'var/lib/inkyos/initialization'):
            target = self.root / path; target.mkdir(parents=True, mode=0o700)
            before = self.snapshot()
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.stage()
            self.assertEqual(self.snapshot(), before)
            target.rmdir()

    def test_symlink_parent_cannot_write_outside(self):
        outside = self.base / 'outside'; outside.mkdir()
        (self.root / 'etc/systemd').symlink_to(outside, target_is_directory=True)
        before = self.snapshot()
        with self.assertRaises((ValueError, OSError)):
            self.stage()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(list(outside.iterdir()), [])

    def test_partial_failure_retains_evidence_and_refuses_retry(self):
        original = profile.Offline.write
        def fail(env, path, *args):
            if path == profile.TRIGGER:
                raise OSError('injected storage failure')
            return original(env, path, *args)
        with patch.object(profile.Offline, 'write', fail), self.assertRaises(OSError):
            self.stage()
        self.assertTrue((self.root / profile.PERMISSION / 'pending.json').is_file())
        self.assertFalse((self.root / profile.TRIGGER).exists())
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.stage()
        self.assertEqual(self.snapshot(), before)

    def test_runtime_is_not_installed_when_full_candidate_plan_refuses(self):
        self.stage()
        value = dict(bundle_manifest_sha256='a' * 64, exporter_manifest_sha256='b' * 64,
                     support_manifest_sha256='c' * 64, helper_uid=980, provisioning_gid=980)
        raw = profile.runtime.canonical(value)
        plan = self.base / 'runtime-plan.json'; plan.write_bytes(raw)
        before = self.snapshot()
        with patch.object(profile.planner, 'plan', side_effect=ValueError('invalid candidate')) as planner:
            with self.assertRaises(ValueError):
                profile.install_runtime(self.root, plan_file=plan, plan_sha256=profile.runtime.sha(raw))
            planner.assert_called_once()
        self.assertEqual(self.snapshot(), before)

    def test_runtime_plan_pin_is_required_before_installed_mutation(self):
        self.stage(); before = self.snapshot()
        plan = self.base / 'runtime-plan.json'; plan.write_bytes(b'{}\n')
        with self.assertRaises(ValueError):
            profile.install_runtime(self.root, plan_file=plan, plan_sha256='0' * 64)
        self.assertEqual(self.snapshot(), before)

    def test_host_root_refused_even_with_fixture_seams(self):
        with self.assertRaises(ValueError):
            profile.stage(Path('/'), trigger_sha256=self.pin)


if __name__ == '__main__':
    unittest.main()
