"""Static recipe fixtures; no mounts, root privileges, chroot or image runtime."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[1]
SCRIPT = REPOSITORY / "scripts/configure-rootfs.py"
spec = importlib.util.spec_from_file_location("configure_rootfs", SCRIPT)
configure_rootfs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(configure_rootfs)


class ConfigureRootfsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "root"
        self.boot = self.base / "boot"
        self.recipe = self.base / "recipe"
        for path in (self.root, self.boot, self.recipe):
            path.mkdir()
        root_files = {
            "etc/machine-id": "uninitialized\n",
            "etc/passwd": "root:x:0:0:root:/root:/bin/bash\ninky:x:1000:1000::/home/inky:/bin/bash\n",
            "etc/shadow": "root:*:20000:0:99999:7:::\ninky:!:20000:0:99999:7:::\n",
            "etc/hostname": "raspberrypi\n",
            "etc/hosts": "127.0.0.1 localhost\n::1 localhost ip6-localhost\n127.0.1.1 raspberrypi\n192.0.2.1 preserved-host\n",
            "etc/subuid": "pi:100000:65536\ninky:100000:65536\nfixture:200000:65536\n",
            "etc/subgid": "pi:100000:65536\ninky:100000:65536\nfixture:200000:65536\n",
            "etc/ssh/sshd_config.d/rename_user.conf": "# generic upstream first-boot configuration\n",
            "etc/passwd-": "pi:x:1000:1000::/home/pi:/bin/bash\n",
            "etc/shadow-": "pi:!:20000:0:99999:7:::\n",
            "var/log/dpkg.log": "fixture package preparation log\n",
            "var/lib/NetworkManager/NetworkManager.state": "[main]\nNetworkingEnabled=true\nWirelessEnabled=false\nWWANEnabled=true\n",
        }
        for name, content in root_files.items():
            self.write(self.root, name, content)
        self.cmdline = "console=tty1 root=PARTUUID=fixture-02 rootfstype=ext4 rootwait resize\n"
        self.write(self.boot, "cmdline.txt", self.cmdline)
        self.write(self.boot, "config.txt", "# pinned base fixture\nauto_initramfs=1\n[all]\n")
        for name in ("user-data", "network-config", "meta-data"):
            self.write(self.boot, name, "# generic provisioning fixture\n")
        for relative in configure_rootfs.OVERLAY_FILES:
            source = REPOSITORY / "overlay" / relative
            destination = self.recipe / "overlay" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        # Use actual local locks; no network or package execution is involved.
        (self.recipe / "config").mkdir()
        for name in ("base-image.lock.json", "system-packages.lock.json"):
            shutil.copyfile(REPOSITORY / "config" / name, self.recipe / "config" / name)
        self.write(self.recipe, "recipe-inputs.json", json.dumps({"fixture": True, "files": {}}))

    def write(self, root, relative, content):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def configure(self):
        configure_rootfs.configure(self.root, self.boot, self.recipe)

    def test_static_bootstrap_preserves_resize_and_creates_no_runtime_identity(self):
        before_machine_id = (self.root / "etc/machine-id").read_bytes()
        before_shadow = (self.root / "etc/shadow").read_bytes()
        self.configure()
        self.assertEqual((self.root / "etc/machine-id").read_bytes(), before_machine_id)
        self.assertEqual((self.boot / "cmdline.txt").read_text(), self.cmdline)
        self.assertEqual((self.root / "etc/shadow").read_bytes(), before_shadow)
        self.assertEqual((self.root / "etc/hostname").read_text(), "inky-unconfigured\n")
        self.assertIn("192.0.2.1 preserved-host", (self.root / "etc/hosts").read_text())
        for path in ("var/lib/inkyos/system.json", "var/lib/inky-studio", "var/lib/inky-network",
                     "home/inky/inky-studio", "var/lib/systemd/random-seed"):
            self.assertFalse((self.root / path).exists(), path)
        self.assertEqual(list((self.root / "etc/ssh").glob("ssh_host_*")), [])
        release = json.loads((self.root / "etc/inkyos-release.json").read_text())
        self.assertIsNone(release["application"])
        self.assertEqual(release["kind"], "system-prototype")
        self.assertEqual(release["status"], "not-hardware-qualified")
        lock = json.loads((self.recipe / "config/base-image.lock.json").read_text())
        self.assertEqual(release["base_image_sha256"], lock["image"]["extracted_sha256"])
        self.assertFalse((self.root / "etc/passwd-").exists())
        self.assertFalse((self.root / "etc/shadow-").exists())
        for name in ("user-data", "network-config", "meta-data"):
            self.assertFalse((self.boot / name).exists())

    def test_only_reviewed_overlay_payload_is_copied_with_safe_modes(self):
        extra = "usr/local/lib/inkyos/unreviewed-payload.py"
        self.write(self.recipe, "overlay/" + extra, "UNREVIEWED_PAYLOAD_SENTINEL\n")
        self.write(self.recipe, "overlay/etc/ssh/ssh_host_ed25519_key", "PRIVATE_KEY_SENTINEL\n")
        self.configure()
        for relative in configure_rootfs.OVERLAY_FILES:
            target = self.root / relative
            self.assertEqual(target.read_bytes(), (self.recipe / "overlay" / relative).read_bytes())
            self.assertEqual(target.stat().st_mode & 0o777, 0o644)
        self.assertFalse((self.root / extra).exists())
        self.assertFalse((self.root / "etc/ssh/ssh_host_ed25519_key").exists())
        self.assertEqual((self.root / "var/lib/NetworkManager/NetworkManager.state").stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root / "etc/inkyos-release.json").stat().st_mode & 0o777, 0o644)
        self.assertEqual((self.root / "etc/hostname").stat().st_mode & 0o777, 0o644)

    def test_competing_firstboot_and_ssh_are_masked_network_requires_hostname(self):
        self.configure()
        for unit in ("systemd-firstboot.service", "sshswitch.service", "userconfig.service",
                     "ssh.service", "ssh.socket", "cloud-init-local.service", "cloud-init-network.service"):
            path = self.root / "etc/systemd/system" / unit
            self.assertTrue(path.is_symlink(), unit)
            self.assertEqual(os.readlink(path), "/dev/null", unit)
        for unit in ("NetworkManager.service", "avahi-daemon.service", "bluetooth.service"):
            dropin = self.root / "etc/systemd/system" / (unit + ".d/10-inkyos-firstboot.conf")
            content = dropin.read_text()
            self.assertIn("Requires=inkyos-firstboot.service", content)
            self.assertIn("After=inkyos-firstboot.service", content)
        self.assertTrue((self.root / "etc/systemd/system/multi-user.target.wants/inkyos-firstboot.service").is_symlink())
        self.assertFalse((self.root / "etc/systemd/system/rpi-resize.service").is_symlink())
        self.assertFalse((self.root / "etc/systemd/system/systemd-growfs-root.service").is_symlink())

    def test_preseeded_machine_id_is_rejected_before_overlay_install(self):
        identifier = "102030405060708090a0b0c0d0e0f001\n"
        self.write(self.root, "etc/machine-id", identifier)
        with self.assertRaises(ValueError):
            self.configure()
        self.assertEqual((self.root / "etc/machine-id").read_text(), identifier)
        self.assertEqual((self.boot / "cmdline.txt").read_text(), self.cmdline)
        self.assertFalse((self.root / "usr/local/lib/inkyos/firstboot.py").exists())

    def test_missing_real_resize_token_is_rejected_before_overlay_install(self):
        content = "console=tty1 rootwait pretend=resize\n"
        self.write(self.boot, "cmdline.txt", content)
        with self.assertRaises(ValueError):
            self.configure()
        self.assertEqual((self.boot / "cmdline.txt").read_text(), content)
        self.assertFalse((self.root / "usr/local/lib/inkyos/firstboot.py").exists())

    def test_account_preparation_guard_rejects_pi_first_line_and_invalid_inky(self):
        root_row = "root:x:0:0:root:/root:/bin/bash\n"
        inky_row = "inky:x:1000:1000::/home/inky:/bin/bash\n"
        cases = {
            "pi_first_line": "pi:x:1000:1000::/home/pi:/bin/bash\n" + root_row + inky_row,
            "inky_missing": root_row,
            "inky_duplicated": root_row + inky_row + inky_row,
            "inky_wrong_uid": root_row + "inky:x:1001:1000::/home/inky:/bin/bash\n",
            "inky_malformed": root_row + "inky:x:1000:1000:/home/inky:/bin/bash\n",
        }
        for name, passwd in cases.items():
            with self.subTest(case=name):
                self.write(self.root, "etc/passwd", passwd)
                with self.assertRaises(ValueError):
                    self.configure()
                self.assertEqual((self.root / "etc/passwd").read_text(), passwd)
                self.assertFalse((self.root / "usr/local/lib/inkyos/firstboot.py").exists())

    def test_parent_symlink_cannot_redirect_overlay_write(self):
        outside = self.base / "outside"
        outside.mkdir()
        sentinel = outside / "sentinel"
        sentinel.write_text("HOST_SENTINEL\n")
        (self.root / "usr").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.configure()
        self.assertEqual(sentinel.read_text(), "HOST_SENTINEL\n")
        self.assertEqual(sorted(path.name for path in outside.iterdir()), ["sentinel"])

    def test_leaf_symlink_cannot_truncate_host_configuration(self):
        sentinel = self.base / "host-hostname"
        sentinel.write_text("HOST_SENTINEL\n")
        (self.root / "etc/hostname").unlink()
        (self.root / "etc/hostname").symlink_to(sentinel)
        with self.assertRaises(ValueError):
            self.configure()
        self.assertEqual(sentinel.read_text(), "HOST_SENTINEL\n")
        self.assertTrue((self.root / "etc/hostname").is_symlink())

    def test_hardlink_cannot_truncate_host_configuration(self):
        sentinel = self.base / "host-hostname"
        sentinel.write_text("HOST_SENTINEL\n")
        (self.root / "etc/hostname").unlink()
        os.link(sentinel, self.root / "etc/hostname")
        with self.assertRaises(ValueError):
            self.configure()
        self.assertEqual(sentinel.read_text(), "HOST_SENTINEL\n")
        self.assertEqual((self.root / "etc/hostname").read_text(), "HOST_SENTINEL\n")

    def test_overlay_source_symlink_cannot_import_host_payload(self):
        sentinel = self.base / "host-payload"
        sentinel.write_text("HOST_PAYLOAD_SENTINEL\n")
        overlay = self.recipe / "overlay/usr/local/lib/inkyos/firstboot.py"
        overlay.unlink()
        overlay.symlink_to(sentinel)
        with self.assertRaises(ValueError):
            self.configure()
        self.assertFalse((self.root / "usr/local/lib/inkyos/firstboot.py").exists())
        self.assertEqual(sentinel.read_text(), "HOST_PAYLOAD_SENTINEL\n")

    def test_boot_provisioning_symlink_is_not_followed_or_deleted(self):
        sentinel = self.base / "host-user-data"
        sentinel.write_text("HOST_PROVISIONING_SENTINEL\n")
        (self.boot / "user-data").unlink()
        (self.boot / "user-data").symlink_to(sentinel)
        with self.assertRaises(ValueError):
            self.configure()
        self.assertTrue((self.boot / "user-data").is_symlink())
        self.assertEqual(sentinel.read_text(), "HOST_PROVISIONING_SENTINEL\n")


if __name__ == "__main__":
    unittest.main()
