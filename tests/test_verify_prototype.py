"""Synthetic rootfs contract checks; no image scripts, services or private data run."""

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("verify_prototype", Path(__file__).resolve().parents[1] / "scripts/verify-prototype.py")
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)


class VerifyPrototypeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.root = self.base / "root"
        self.boot = self.base / "boot"
        self.root.mkdir()
        self.boot.mkdir()
        self.lock = {"packages": [{"name": "python3-dbus", "version": "1.4.0-1", "architecture": "arm64"}]}
        self.lock_path = self.base / "packages.json"
        self.lock_path.write_text(json.dumps(self.lock))
        self.put("etc/inkyos-release.json", json.dumps({"schema_version": 1, "kind": "system-prototype", "application": None}))
        self.put("usr/local/lib/inkyos/firstboot.py", "raise RuntimeError('IMAGE CODE MUST NEVER RUN')\n")
        self.put("etc/systemd/system/inkyos-firstboot.service", "[Service]\nType=oneshot\nUser=root\nExecStart=/usr/bin/python3 /usr/local/lib/inkyos/firstboot.py\n")
        self.link("etc/systemd/system/multi-user.target.wants/inkyos-firstboot.service", "/etc/systemd/system/inkyos-firstboot.service")
        self.put("etc/machine-id", "uninitialized\n")
        self.put("etc/hostname", "inky-unconfigured\n")
        self.put("etc/passwd", "root:x:0:0:root:/root:/bin/bash\ninky:x:1000:1000::/home/inky:/usr/sbin/nologin\n")
        self.put("etc/shadow", "root:*:1:0:99999:7:::\ninky:!:1:0:99999:7:::\n", 0o600)
        self.put("etc/group", "root:x:0:\ninky:x:1000:\nspi:x:997:inky\ni2c:x:998:inky\ngpio:x:999:inky\nsudo:x:27:\nadmin:x:28:\nnetdev:x:29:\n")
        self.put("var/lib/NetworkManager/NetworkManager.state", "[main]\nWirelessEnabled=true\n", 0o600)
        for unit in verify.MASKS:
            self.link("etc/systemd/system/" + unit, "/dev/null")
        self.put("etc/cloud/cloud-init.disabled", "")
        self.put("cmdline.txt", "console=tty1 root=PARTUUID=00000000-02 rootwait resize\n", boot=True)
        self.put("config.txt", "[all]\ninclude inkyos.txt\n", boot=True)
        self.put("inkyos.txt", "[all]\ndtparam=i2c_arm=on\ndtparam=spi=on\ndtoverlay=spi0-0cs\n", boot=True)
        self.put("etc/modules-load.d/inkyos.conf", "i2c-dev\n")
        for unit in ("rpi-resize.service", "systemd-growfs-root.service"):
            self.put("usr/lib/systemd/system/" + unit, "[Unit]\nDescription=fixture grow service\n")
        self.link("etc/systemd/system/sysinit.target.wants/rpi-resize.service", "/usr/lib/systemd/system/rpi-resize.service")
        for unit in verify.ORDERED_SERVICES:
            self.put("etc/systemd/system/" + unit + ".d/10-inkyos-firstboot.conf", "[Unit]\nRequires=inkyos-firstboot.service\nAfter=inkyos-firstboot.service\n")
        self.put("var/lib/dpkg/status", "Package: python3-dbus\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1.4.0-1\n\n")

    def put(self, name, content, mode=0o644, boot=False):
        path = (self.boot if boot else self.root) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(mode)
        return path

    def link(self, name, target):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)

    def report(self):
        return verify.verify(self.root, self.boot, self.lock, _owner_uid=os.getuid())

    def assert_failed(self, identifier):
        report = self.report()
        self.assertFalse(report["passed"])
        self.assertIn(identifier, report["failed_checks"])
        return report

    def test_valid_fixture_passes_without_executing_script(self):
        report = self.report()
        self.assertTrue(report["passed"], report["failed_checks"])
        self.assertFalse(report["method"]["image_code_executed"])

    def test_application_mode_is_explicit_and_keeps_wifi_disabled(self):
        application = {'source_commit': 'a' * 40, 'application_version': '0.5.0-rc.2',
                       'manifest_sha256': 'b' * 64, 'startup': 'masked-pending-firstboot-contract',
                       'release_qualified': False}
        self.put('etc/inkyos-release.json', json.dumps({'schema_version': 1,
                 'kind': 'application-prototype', 'application': application}))
        self.put('var/lib/NetworkManager/NetworkManager.state', '[main]\nWirelessEnabled=false\n', 0o600)
        self.assertFalse(self.report()['passed'])
        report = verify.verify(self.root, self.boot, self.lock, application=application, _owner_uid=os.getuid())
        self.assertTrue(report['passed'], report['failed_checks'])
        self.put('var/lib/NetworkManager/NetworkManager.state', '[main]\nWirelessEnabled=true\n', 0o600)
        report = verify.verify(self.root, self.boot, self.lock, application=application, _owner_uid=os.getuid())
        self.assertIn('NETWORKMANAGER_GENERIC_STATE', report['failed_checks'])

    def test_missing_metadata_and_wrong_prototype_type_fail(self):
        path = self.root / "etc/inkyos-release.json"
        for contents in ["{}", '{"schema_version":true,"kind":"system-prototype","application":null}',
                         '{"schema_version":1,"kind":"system-prototype","application":{"release":"unqualified"}}']:
            path.write_text(contents)
            self.assert_failed("RELEASE_METADATA")
        path.unlink()
        self.assert_failed("RELEASE_METADATA")

    def test_missing_firstboot_and_writable_script_fail(self):
        path = self.root / "usr/local/lib/inkyos/firstboot.py"
        path.chmod(0o666)
        self.assert_failed("SECURE_USR_LOCAL_LIB_INKYOS_FIRSTBOOT.PY")
        path.unlink()
        self.assert_failed("SECURE_USR_LOCAL_LIB_INKYOS_FIRSTBOOT.PY")

    def test_mask_must_be_exact_null_symlink(self):
        path = self.root / "etc/systemd/system/ssh.service"
        path.unlink()
        path.write_text("/dev/null\n")
        self.assert_failed("MASK_ssh.service")
        path.unlink()
        path.symlink_to("/outside/SECRET_DESTINATION")
        report = self.assert_failed("MASK_ssh.service")
        self.assertNotIn("SECRET_DESTINATION", json.dumps(report))

    def test_network_dependency_requires_both_after_and_requires(self):
        path = "etc/systemd/system/NetworkManager.service.d/10-inkyos-firstboot.conf"
        self.put(path, "[Unit]\nRequires=inkyos-firstboot.service\nAfter=inkyos-firstboot.service\nRequires=\n")
        self.assert_failed("FIRSTBOOT_ORDER_NetworkManager.service")

    def test_wifi_state_and_profile_values_are_not_disclosed(self):
        self.put("var/lib/NetworkManager/NetworkManager.state", "[main]\nWirelessEnabled=false\n")
        self.assert_failed("NETWORKMANAGER_GENERIC_STATE")
        self.put("etc/NetworkManager/system-connections/SECRET_WIFI_PROFILE", "psk=VERY_PRIVATE_PASSWORD\n")
        report = self.assert_failed("EMPTY_ETC_NETWORKMANAGER_SYSTEM-CONNECTIONS")
        self.assertNotIn("SECRET_WIFI_PROFILE", json.dumps(report))
        self.assertNotIn("VERY_PRIVATE_PASSWORD", json.dumps(report))

    def test_preseeded_identities_and_application_state_fail_without_disclosure(self):
        self.put("etc/machine-id", "0123456789abcdef0123456789abcdef\n")
        self.put("var/lib/systemd/random-seed", "VERY_PRIVATE_SEED")
        self.put("var/lib/inkyos/system.json", '{"hostname":"PRIVATE_HOSTNAME"}')
        self.put("var/lib/inky-studio/db.sqlite", "PRIVATE_PHOTOS")
        self.put("etc/ssh/ssh_host_ed25519_key", "PRIVATE_SSH_KEY")
        report = self.report()
        for identifier in ("MACHINE_ID_UNINITIALIZED", "ABSENT_VAR_LIB_SYSTEMD_RANDOM-SEED", "ABSENT_VAR_LIB_INKYOS_SYSTEM.JSON", "EMPTY_VAR_LIB_INKY-STUDIO", "NO_SSH_HOST_KEYS"):
            self.assertIn(identifier, report["failed_checks"])
        self.assertNotIn("PRIVATE_", json.dumps(report))
        self.assertNotIn("0123456789abcdef", json.dumps(report))

    def test_wrong_account_shell_unlocked_password_and_privileged_groups_fail(self):
        passwd = (self.root / "etc/passwd").read_text()
        for contents in [passwd.replace("1000:1000", "1001:1000"), passwd.replace("/usr/sbin/nologin", "/bin/bash"), passwd + "pi:x:1001:1001::/home/pi:/bin/bash\n"]:
            self.put("etc/passwd", contents)
            self.assert_failed("INKY_ACCOUNT")
        self.put("etc/passwd", passwd)
        shadow = (self.root / "etc/shadow").read_text()
        self.put("etc/shadow", shadow.replace("inky:!:", "inky:PRIVATE_HASH:"))
        report = self.assert_failed("INKY_ACCOUNT")
        self.assertNotIn("PRIVATE_HASH", json.dumps(report))
        self.put("etc/shadow", shadow)
        self.put("etc/group", (self.root / "etc/group").read_text().replace("sudo:x:27:", "sudo:x:27:inky"))
        self.assert_failed("INKY_ACCOUNT")

    def test_boot_resize_interfaces_and_provisioning_are_checked(self):
        self.put("cmdline.txt", "rootwait\n", boot=True)
        self.put("inkyos.txt", "[pi5]\ndtparam=i2c_arm=on\ndtparam=spi=on\n", boot=True)
        self.put("user-data", "PRIVATE_CLOUD_CONFIG", boot=True)
        report = self.report()
        self.assertTrue({"BOOT_RESIZE", "BOOT_INTERFACES", "BOOT_ABSENT_user-data"} <= set(report["failed_checks"]))
        self.assertNotIn("PRIVATE_CLOUD_CONFIG", json.dumps(report))

    def test_locked_package_must_be_configured_at_exact_version(self):
        self.put("var/lib/dpkg/status", "Package: python3-dbus\nStatus: install ok unpacked\nArchitecture: arm64\nVersion: 1.4.0-1\n\n")
        self.assert_failed("LOCKED_SYSTEM_PACKAGES")
        self.put("var/lib/dpkg/status", "Package: python3-dbus\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1.3.2-5\n\n")
        self.assert_failed("LOCKED_SYSTEM_PACKAGES")

    def test_parent_symlink_is_not_followed(self):
        path = self.root / "var/lib/inky-studio"
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "PRIVATE_FILE").write_text("PRIVATE_CONTENT")
        path.symlink_to(outside, target_is_directory=True)
        report = self.assert_failed("EMPTY_VAR_LIB_INKY-STUDIO")
        self.assertNotIn("PRIVATE_FILE", json.dumps(report))
        self.assertEqual((outside / "PRIVATE_FILE").read_text(), "PRIVATE_CONTENT")

    def test_cli_writes_new_report_and_refuses_existing_or_inside_tree(self):
        output = self.base / "report.json"
        args = ["--rootfs", str(self.root), "--bootfs", str(self.boot), "--packages-lock", str(self.lock_path), "--output", str(output)]
        original = verify.verify
        with patch.object(verify, "verify", side_effect=lambda root, boot, lock, **kw: original(root, boot, lock, _owner_uid=os.getuid(), **kw)), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(verify.main(args), 0)
            before = output.read_bytes()
            self.assertEqual(verify.main(args), 1)
            self.assertEqual(output.read_bytes(), before)
            inside = self.root / "report.json"
            self.assertEqual(verify.main(args[:-1] + [str(inside)]), 1)
            self.assertFalse(inside.exists())
        self.assertTrue(json.loads(before)["passed"])

    def test_cli_loads_explicit_pinned_application_manifest(self):
        source = '6a697d134290ced0214fc74b903f4b3c336d70fa'
        data = {'schema_version': 1, 'application_version': '0.5.0-rc.2', 'source_commit': source,
                'assets': [{'role': role, 'filename': role + suffix, 'size_bytes': 1, 'sha256': 'a' * 64}
                           for role, suffix in (('application', '.tar.gz'), ('wheelhouse', '.zip'), ('python_lock', '.lock'))],
                'compatibility': {'architecture': 'arm64', 'python_minor': '3.13', 'debian_release': 'trixie',
                                  **{key: 'git:' + source + '#contracts/' + key for key in
                                     ('http_contract', 'ble_contract', 'network_helper_contract')}},
                'qualification': {'evidence': []}}
        manifest = self.base/'application.json'
        manifest.write_text(json.dumps(data))
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        application = {'source_commit': source, 'application_version': data['application_version'],
                       'manifest_sha256': digest, 'startup': 'masked-pending-firstboot-contract', 'release_qualified': False}
        self.put('etc/inkyos-release.json', json.dumps({'schema_version': 1,
                 'kind': 'application-prototype', 'application': application}))
        self.put('var/lib/NetworkManager/NetworkManager.state', '[main]\nWirelessEnabled=false\n', 0o600)
        args = ['--rootfs', str(self.root), '--bootfs', str(self.boot), '--packages-lock', str(self.lock_path),
                '--output', str(self.base/'app-report.json'), '--application-manifest', str(manifest),
                '--application-sha256', digest]
        original = verify.verify
        with patch.object(verify, 'verify', side_effect=lambda *a, **kw: original(*a, _owner_uid=os.getuid(), **kw)), redirect_stdout(io.StringIO()):
            self.assertEqual(verify.main(args), 0)


if __name__ == "__main__":
    unittest.main()
