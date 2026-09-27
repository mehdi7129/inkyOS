"""Offline fixture tests; no mounts, sudo, image runtime or network required."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "inspect-rootfs.py"
spec = importlib.util.spec_from_file_location("inspect_rootfs", SCRIPT)
inspector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inspector)


class InspectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "root"
        self.boot = self.base / "boot"
        self.root.mkdir()
        self.boot.mkdir()

    def write(self, path, content, mode=0o644):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        target.chmod(mode)
        return target

    def report(self):
        return inspector.inspect(self.root, self.boot)

    def test_shadow_contents_and_state_contents_never_leak(self):
        self.write("etc/passwd", "root:x:0:0:root:/root:/bin/bash\npi:x:1000:1000::/home/pi:/bin/bash\n")
        self.write("etc/shadow", "root:!:20000:0:99999:7:::\npi:$y$PASSWORD_SENTINEL:20000:0:99999:7:::\n", 0o600)
        self.write("etc/NetworkManager/system-connections/PRIVATE_SSID", "psk=NETWORK_SECRET")
        self.write("var/lib/inky-studio/PRIVATE_PHOTO_NAME", "PHOTO_CONTENT")
        self.write("etc/ssh/ssh_host_ed25519_key", "PRIVATE_KEY_CONTENT", 0o600)
        (self.boot / "userconf.txt").write_text("pi:BOOT_PASSWORD_HASH")
        report = self.report()
        encoded = json.dumps(report)
        for secret in ("PASSWORD_SENTINEL", "PRIVATE_SSID", "NETWORK_SECRET", "PRIVATE_PHOTO_NAME",
                       "PHOTO_CONTENT", "PRIVATE_KEY_CONTENT", "BOOT_PASSWORD_HASH"):
            self.assertNotIn(secret, encoded)
        self.assertEqual(report["accounts"]["accounts"][0]["password_state"], "locked")
        self.assertEqual(report["accounts"]["accounts"][1]["password_state"], "password_set")
        self.assertIn("PRESEEDED_SSH_HOST_KEY", {risk["code"] for risk in report["risks"]})

    def test_machine_id_is_detected_but_never_serialized(self):
        identity = "f079408335574ed3b6f99b9308b67b55"
        self.write("etc/machine-id", identity + "\n")
        report = self.report()
        self.assertEqual(report["identities"]["machine_id"]["etc/machine-id"]["state"],
                         "populated_valid_format")
        self.assertNotIn(identity, json.dumps(report))
        self.assertIn("PRESEEDED_MACHINE_ID", {risk["code"] for risk in report["risks"]})

    def test_empty_and_uninitialized_ids_are_not_preseeded(self):
        for content, state in (("", "empty"), ("uninitialized\n", "uninitialized")):
            with self.subTest(content=content):
                self.write("etc/machine-id", content)
                report = self.report()
                self.assertEqual(report["identities"]["machine_id"]["etc/machine-id"]["state"], state)
                self.assertNotIn("PRESEEDED_MACHINE_ID", {risk["code"] for risk in report["risks"]})

    def test_zero_id_is_not_valid(self):
        self.write("etc/machine-id", "0" * 32)
        self.assertEqual(self.report()["identities"]["machine_id"]["etc/machine-id"]["state"],
                         "populated_invalid_format")

    def test_random_seed_is_metadata_only(self):
        seed = "RANDOM_SEED_CONTENT_SENTINEL"
        self.write("var/lib/systemd/random-seed", seed, 0o600)
        self.write("var/lib/urandom/random-seed", "", 0o600)
        report = self.report()
        states = report["identities"]["random_seeds"]
        self.assertEqual(states["/var/lib/systemd/random-seed"]["size_bytes"], len(seed))
        self.assertEqual(states["/var/lib/urandom/random-seed"]["size_bytes"], 0)
        self.assertNotIn(seed, json.dumps(report))
        self.assertEqual(sum(risk["code"] == "PRESEEDED_RANDOM_SEED" for risk in report["risks"]), 1)

    def test_absolute_and_parent_symlinks_never_escape_root(self):
        host = self.base / "host"
        host.mkdir()
        (host / "status").write_text("Package: HOST_SENTINEL\nStatus: install ok installed\nVersion: 1\nArchitecture: arm64\n")
        self.write("usr/lib/os-release", "ID=fixture\nVERSION_ID=13\n")
        (self.root / "etc").mkdir()
        (self.root / "etc/os-release").symlink_to(host / "status")
        (self.root / "etc/shadow").symlink_to(host / "status")
        (self.root / "var/lib").mkdir(parents=True)
        (self.root / "var/lib/dpkg").symlink_to(host, target_is_directory=True)
        report = self.report()
        self.assertEqual(report["os"]["fields"]["ID"], "fixture")
        self.assertFalse(report["packages"]["available"])
        self.assertFalse(report["accounts"]["shadow_readable"])
        self.assertNotIn("HOST_SENTINEL", json.dumps(report))
        tree = inspector.SafeTree(self.root)
        try:
            with self.assertRaises(inspector.UnsafePath):
                tree.read("../host/status")
        finally:
            tree.close()

    def test_fifo_is_not_read(self):
        (self.root / "etc").mkdir()
        os.mkfifo(self.root / "etc/shadow")
        self.assertFalse(self.report()["accounts"]["shadow_readable"])

    def test_packages_architecture_kernel_and_enabled_units(self):
        self.write("var/lib/dpkg/status", "Package: linux-image-rpi-v8\nStatus: install ok installed\nVersion: 6.12.47-1+rpt1\nArchitecture: arm64\n\nPackage: deleted\nStatus: deinstall ok config-files\nVersion: 1\nArchitecture: all\n")
        self.write("usr/lib/systemd/system/NetworkManager.service", "[Service]\nExecStart=/bin/true\n")
        enabled = self.root / "etc/systemd/system/multi-user.target.wants"
        enabled.mkdir(parents=True)
        (enabled / "NetworkManager.service").symlink_to("/usr/lib/systemd/system/NetworkManager.service")
        (self.root / "usr/lib/modules/6.12.47+rpt-rpi-v8").mkdir(parents=True)
        report = self.report()
        self.assertEqual(report["architectures"], ["arm64"])
        self.assertEqual(report["packages"]["count"], 1)
        self.assertEqual(report["kernel"]["module_directories"], ["6.12.47+rpt-rpi-v8"])
        self.assertTrue(report["services"]["NetworkManager.service"]["enablement_link_present"])
        self.assertEqual(report["qualification"], "not-qualified")

    def test_modern_cloud_init_units_and_fat_metadata_note(self):
        units = ("cloud-init-local.service", "cloud-init-network.service",
                 "cloud-config.service", "cloud-final.service", "cloud-init.target")
        enabled = self.root / "etc/systemd/system/multi-user.target.wants"
        enabled.mkdir(parents=True)
        for unit in units:
            self.write(f"usr/lib/systemd/system/{unit}", "[Unit]\nDescription=Fixture\n")
            (enabled / unit).symlink_to(f"/usr/lib/systemd/system/{unit}")
        report = self.report()
        for unit in units:
            self.assertTrue(report["services"][unit]["unit_present"])
            self.assertTrue(report["services"][unit]["enablement_link_present"])
        self.assertIn("not stored Unix permissions", report["boot"]["metadata_note"])

    def test_cli_refuses_output_replacement_and_image_tree_output(self):
        output = self.base / "report.json"
        command = [sys.executable, str(SCRIPT), "--rootfs", str(self.root),
                   "--bootfs", str(self.boot), "--output", str(output)]
        first = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        content = output.read_bytes()
        second = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(second.returncode, 0)
        self.assertEqual(content, output.read_bytes())
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        command[-1] = str(self.root / "forbidden-report.json")
        self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
        self.assertFalse((self.root / "forbidden-report.json").exists())


if __name__ == "__main__":
    unittest.main()
