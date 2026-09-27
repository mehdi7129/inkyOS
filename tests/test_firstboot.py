"""System first-boot fixtures only: no host hostname, entropy or services changed."""

import importlib.util
import fcntl
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "overlay/usr/local/lib/inkyos/firstboot.py"
spec = importlib.util.spec_from_file_location("inkyos_firstboot", SCRIPT)
firstboot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(firstboot)


class SimulatedPowerLoss(RuntimeError):
    pass


class FirstBootTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.make_root("root")
        self.runtime_names = []

    def make_root(self, name):
        root = self.base / name
        # Model the image permissions explicitly, independent of the builder's
        # default umask (Lima's development user commonly uses 0002).
        for directory in (root, root / "etc", root / "var", root / "var/lib"):
            directory.mkdir(mode=0o755)
        (root / "etc/hostname").write_text("raspberrypi\n")
        (root / "etc/hosts").write_text("127.0.0.1 localhost\n::1 localhost ip6-localhost\n127.0.1.1 raspberrypi\n192.0.2.1 retained-host # retained comment\n")
        (root / "etc/machine-id").write_text("systemd-owned-sentinel\n")
        for name in ("hostname", "hosts", "machine-id"):
            (root / "etc" / name).chmod(0o644)
        return root

    def run_firstboot(self, root=None, entropy=None, checkpoint=None):
        return firstboot.initialize_system(root or self.root,
                                          entropy=entropy or (lambda size: b"\x10" * size),
                                          set_runtime_hostname=self.runtime_names.append,
                                          owner_uid=os.getuid(), checkpoint=checkpoint)

    def state(self, root=None):
        return json.loads(((root or self.root) / "var/lib/inkyos/system.json").read_text())

    def test_two_roots_get_distinct_identities_and_private_state(self):
        other = self.make_root("other")
        one = self.run_firstboot()
        two = self.run_firstboot(other, entropy=lambda size: b"\x20" * size)
        self.assertNotEqual(one["hostname"], two["hostname"])
        self.assertRegex(one["hostname"], r"^inky-[0-9a-f]{32}$")
        self.assertEqual(self.state(), {"version": 1, "hostname": one["hostname"]})
        self.assertEqual((self.root / "var/lib/inkyos").stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.root / "var/lib/inkyos/system.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root / "etc/hostname").stat().st_mode & 0o777, 0o644)
        self.assertEqual((self.root / "etc/hosts").stat().st_mode & 0o777, 0o644)
        self.assertEqual((self.root / "etc/machine-id").read_text(), "systemd-owned-sentinel\n")
        self.assertFalse((self.root / "var/lib/inky-studio").exists())

    def test_reboot_preserves_identity_and_does_not_rewrite_files(self):
        initial = self.run_firstboot()
        paths = ("var/lib/inkyos/system.json", "etc/hostname", "etc/hosts")
        before = {name: (self.root / name).stat().st_ino for name in paths}
        def no_entropy(_size):
            self.fail("Existing identity must not request entropy")
        again = self.run_firstboot(entropy=no_entropy)
        self.assertEqual(initial["hostname"], again["hostname"])
        self.assertFalse(again["created"])
        self.assertEqual(before, {name: (self.root / name).stat().st_ino for name in paths})
        hosts = (self.root / "etc/hosts").read_text()
        self.assertEqual(hosts.count("127.0.1.1"), 1)
        self.assertIn("192.0.2.1 retained-host # retained comment", hosts)
        self.assertNotIn("raspberrypi", hosts)

    def test_power_loss_at_each_write_recovers_from_durable_state(self):
        stages = [f"{name}:{step}" for name in ("system.json", "hostname", "hosts")
                  for step in ("temp_fsynced", "replaced", "directory_fsynced")]
        stages.append("runtime_hostname:applied")
        for index, stage in enumerate(stages):
            with self.subTest(stage=stage):
                root = self.make_root(f"crash-{index}")
                def cut_power(current):
                    if current == stage:
                        raise SimulatedPowerLoss(stage)
                with self.assertRaises(SimulatedPowerLoss):
                    self.run_firstboot(root, checkpoint=cut_power)
                state_file = root / "var/lib/inkyos/system.json"
                committed = json.loads(state_file.read_text()) if state_file.exists() else None
                if committed is None:
                    # No external configuration can use an uncommitted identity.
                    self.assertEqual((root / "etc/hostname").read_text(), "raspberrypi\n")
                def resumed_entropy(size):
                    if committed:
                        self.fail("Committed identity must survive every subsequent interruption")
                    return b"\x30" * size
                resumed = self.run_firstboot(root, entropy=resumed_entropy)
                if committed:
                    self.assertEqual(resumed["hostname"], committed["hostname"])
                self.assertEqual((root / "etc/hostname").read_text(), resumed["hostname"] + "\n")
                self.assertIn(resumed["hostname"], (root / "etc/hosts").read_text())
                self.assertEqual(self.runtime_names[-1], resumed["hostname"])

    def test_corrupt_existing_state_fails_without_regeneration_or_system_writes(self):
        state_dir = self.root / "var/lib/inkyos"
        state_dir.mkdir(mode=0o700)
        state = state_dir / "system.json"
        corruptions = ("", "{broken", "{}", '{"version":2,"hostname":"inky-' + "10" * 16 + '"}',
                       '{"version":true,"hostname":"inky-' + "10" * 16 + '"}',
                       '{"version":1,"hostname":"unsafe hostname"}',
                       '{"version":1,"version":1,"hostname":"inky-' + "10" * 16 + '"}')
        for content in corruptions:
            with self.subTest(content=content):
                state.write_text(content)
                state.chmod(0o600)
                with self.assertRaises(firstboot.FirstBootError):
                    self.run_firstboot(entropy=lambda _size: self.fail("No regeneration allowed"))
                self.assertEqual(state.read_text(), content)
                self.assertEqual((self.root / "etc/hostname").read_text(), "raspberrypi\n")
                self.assertEqual(self.runtime_names, [])

    def test_symlink_targets_cannot_escape_fixture(self):
        outside = self.base / "outside"
        outside.write_text("HOST_SENTINEL\n")
        for index, target in enumerate(("etc/hostname", "etc/hosts", "var/lib/inkyos/system.json")):
            with self.subTest(target=target):
                root = self.make_root(f"symlink-{index}")
                item = root / target
                item.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                if item.exists():
                    item.unlink()
                item.symlink_to(outside)
                with self.assertRaises(firstboot.FirstBootError):
                    self.run_firstboot(root)
                self.assertEqual(outside.read_text(), "HOST_SENTINEL\n")
                self.assertTrue(item.is_symlink())

    def test_writable_system_directory_or_private_state_is_refused(self):
        (self.root / "etc").chmod(0o777)
        with self.assertRaises(firstboot.FirstBootError):
            self.run_firstboot()
        self.assertFalse((self.root / "var/lib/inkyos/system.json").exists())
        (self.root / "etc").chmod(0o755)
        self.run_firstboot()
        (self.root / "var/lib/inkyos/system.json").chmod(0o644)
        with self.assertRaises(firstboot.FirstBootError):
            self.run_firstboot()

    def test_parent_directory_symlink_is_refused(self):
        other = self.make_root("outside-root")
        (self.root / "var/lib").rmdir()
        (self.root / "var/lib").symlink_to(other / "var/lib", target_is_directory=True)
        with self.assertRaises(firstboot.FirstBootError):
            self.run_firstboot()
        self.assertFalse((other / "var/lib/inkyos").exists())

    def test_hard_linked_system_file_is_refused(self):
        outside = self.base / "hardlink-target"
        outside.write_text("HOST_SENTINEL\n")
        (self.root / "etc/hostname").unlink()
        os.link(outside, self.root / "etc/hostname")
        with self.assertRaises(firstboot.FirstBootError):
            self.run_firstboot()
        self.assertEqual(outside.read_text(), "HOST_SENTINEL\n")
        self.assertFalse((self.root / "var/lib/inkyos/system.json").exists())

    def test_concurrent_firstboot_is_refused(self):
        self.run_firstboot()
        before = self.state()
        with (self.root / "var/lib/inkyos/.firstboot.lock").open("r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(firstboot.FirstBootError):
                self.run_firstboot()
        self.assertEqual(self.state(), before)

    def test_cli_has_no_alternate_root_option(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--root", str(self.root)],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrecognized arguments", result.stderr)
        self.assertFalse((self.root / "var/lib/inkyos/system.json").exists())


if __name__ == "__main__":
    unittest.main()
