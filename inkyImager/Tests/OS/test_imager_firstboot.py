import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[2] / "OS"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SOURCE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


boot = load("imager_boot_tests", "imager-firstboot.py")
profile = load("imager_profile_tests", "configure-imager-rootfs.py")


class Fixture:
    def __init__(self, root):
        self.root = root
        self.events = []
        self.radio_calls = 0
        for name in ("boot/firmware", "etc/NetworkManager/system-connections", "etc/modprobe.d", "var/lib/inkyos"):
            (root / name).mkdir(parents=True, mode=0o755, exist_ok=True)
        (root / "var/lib/inkyos").chmod(0o700)

    def put(self, name, raw, mode=0o644):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(mode)
        return path

    def capsule(self, *, ssid="IEEE", password="password", country="FR"):
        return self.put(boot.CAPSULE, json.dumps({"schema_version": 1, "wifi": {
            "ssid": ssid, "password": password, "country": country}}, ensure_ascii=False).encode())

    def radio(self):
        self.radio_calls += 1

    def run(self, checkpoint=None, radio=None):
        return boot.configure(self.root, owner_uid=os.getuid(), radio=radio or self.radio,
                              checkpoint=checkpoint or self.events.append)


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.fixture = Fixture(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_success_uses_wpa_vector_private_profile_and_deletes_only_after_commit(self):
        capsule = self.fixture.capsule()
        result = self.fixture.run()
        network = (self.root / boot.PROFILE).read_bytes()
        self.assertEqual(result, {"status": "configured", "reused": False, "country": "FR"})
        self.assertIn(b"ssid=73;69;69;69;\n", network)
        self.assertIn(b"psk=f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e\n", network)
        self.assertIn(b"autoconnect=true\n", network)
        self.assertNotIn(b"password", network)
        self.assertFalse(capsule.exists())
        self.assertEqual(self.fixture.events, ["profile_committed", "country_committed", "state_committed",
                                               "radio_configured", "capsule_removed"])
        for name in (boot.PROFILE, boot.STATE):
            self.assertEqual(stat.S_IMODE((self.root / name).stat().st_mode), 0o600)
        state = json.loads((self.root / boot.STATE).read_text())
        self.assertEqual(state["profile_sha256"], hashlib.sha256(network).hexdigest())
        self.assertNotIn("IEEE", (self.root / boot.STATE).read_text())
        self.assertEqual(self.fixture.radio_calls, 1)

    def test_unicode_ssid_whitespace_and_injection_characters_are_bytes_not_ini(self):
        ssid = " Café\n[evil]; "
        password = 'a";\\$bcd123'
        self.fixture.capsule(ssid=ssid, password=password)
        self.fixture.run()
        raw = (self.root / boot.PROFILE).read_bytes()
        self.assertIn(("ssid=" + ";".join(map(str, ssid.encode())) + ";\n").encode(), raw)
        self.assertNotIn(b"[evil]", raw)
        self.assertNotIn(password.encode(), raw)
        self.assertEqual(raw.count(b"psk="), 1)

    def test_64_hex_psk_is_preserved_canonically(self):
        self.fixture.capsule(password="AB" * 32)
        self.fixture.run()
        self.assertIn(("psk=" + "ab" * 32 + "\n").encode(), (self.root / boot.PROFILE).read_bytes())

    def test_reboot_has_no_capsule_and_preserves_profile_inode_and_bytes(self):
        self.fixture.capsule()
        self.fixture.run()
        path = self.root / boot.PROFILE
        before = (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes())
        self.assertTrue(self.fixture.run()["reused"])
        self.assertEqual(before, (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes()))
        self.assertEqual(self.fixture.radio_calls, 2)

    def test_interruption_after_each_durable_commit_is_resumable(self):
        for stage in ("profile_committed", "country_committed", "state_committed", "radio_configured"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                fixture = Fixture(root)
                capsule = fixture.capsule()
                def interrupt(value):
                    if value == stage:
                        raise RuntimeError("fixture_power_loss")
                with self.assertRaises(RuntimeError):
                    fixture.run(checkpoint=interrupt)
                self.assertTrue(capsule.exists())
                self.assertEqual(fixture.run()["status"], "configured")
                self.assertFalse(capsule.exists())

    def test_radio_failure_keeps_capsule_and_committed_profile_for_retry(self):
        capsule = self.fixture.capsule()
        def fail():
            raise boot.ImportProblem("radio_setup_failed")
        with self.assertRaisesRegex(boot.ImportProblem, "radio_setup_failed"):
            self.fixture.run(radio=fail)
        self.assertTrue(capsule.exists())
        self.assertTrue((self.root / boot.STATE).exists())
        self.assertTrue(self.fixture.run()["reused"])
        self.assertFalse(capsule.exists())

    def test_missing_capsule_does_not_create_profile_or_marker(self):
        with self.assertRaisesRegex(boot.ImportProblem, "network_configuration_missing"):
            self.fixture.run()
        self.assertFalse((self.root / boot.PROFILE).exists())
        self.assertFalse((self.root / boot.STATE).exists())
        self.assertEqual(self.fixture.radio_calls, 0)

    def test_bad_schema_limits_country_password_and_nul_are_refused(self):
        values = [
            {"ssid": "", "password": "password", "country": "FR"},
            {"ssid": "é" * 17, "password": "password", "country": "FR"},
            {"ssid": "bad\0ssid", "password": "password", "country": "FR"},
            {"ssid": "SSID", "password": "short", "country": "FR"},
            {"ssid": "SSID", "password": "motdepässé", "country": "FR"},
            {"ssid": "SSID", "password": "password\n", "country": "FR"},
            {"ssid": "SSID", "password": "password", "country": "US"},
        ]
        for wifi in values:
            with self.subTest(wifi=wifi):
                raw = json.dumps({"schema_version": 1, "wifi": wifi}).encode()
                with self.assertRaises(boot.ImportProblem):
                    boot.network_profile(raw)
        for raw in (b'{"schema_version":true,"wifi":{}}',
                    b'{"schema_version":1,"schema_version":1,"wifi":{}}', b"x" * 4097):
            with self.assertRaises(boot.ImportProblem):
                boot.network_profile(raw)

    def test_maximum_unicode_ssid_is_accepted_without_normalization(self):
        self.fixture.capsule(ssid="é" * 16)
        self.fixture.run()
        self.assertIn(b"ssid=" + b"195;169;" * 16 + b"\n", (self.root / boot.PROFILE).read_bytes())

    def test_symlink_capsule_and_public_secret_profile_are_refused(self):
        target = self.fixture.put("secret", b"secret")
        (self.root / boot.CAPSULE).symlink_to(target)
        with self.assertRaises(boot.ImportProblem):
            self.fixture.run()
        self.assertEqual(target.read_bytes(), b"secret")
        (self.root / boot.CAPSULE).unlink()
        self.fixture.capsule()
        self.fixture.put(boot.PROFILE, b"secret", 0o644)
        with self.assertRaises(boot.ImportProblem):
            self.fixture.run()

    def test_changed_capsule_is_not_deleted_and_changed_profile_is_not_overwritten(self):
        capsule = self.fixture.capsule()
        def alter(stage):
            if stage == "state_committed":
                capsule.write_bytes(b"changed")
        with self.assertRaisesRegex(boot.ImportProblem, "configuration_changed"):
            self.fixture.run(checkpoint=alter)
        self.assertEqual(capsule.read_bytes(), b"changed")
        profile_path = self.root / boot.PROFILE
        profile_path.write_bytes(b"foreign")
        with self.assertRaisesRegex(boot.ImportProblem, "configuration_conflict"):
            self.fixture.run()
        self.assertEqual(profile_path.read_bytes(), b"foreign")


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        target = self.root / "var/lib/NetworkManager/NetworkManager.state"
        target.parent.mkdir(parents=True)
        target.write_text("[main]\nWirelessEnabled=true\n")
        self.boot = self.root / "test-offline-boot"
        self.boot.mkdir()
        self.recipe = Path(__file__).resolve().parents[3]

    def tearDown(self):
        self.temp.cleanup()

    def configure(self, **changes):
        values = {"rootfs": self.root, "bootfs": self.boot, "recipe": self.recipe, "source": SOURCE,
                  "backend_exec_start": "/usr/lib/inky-studio/server/.venv/bin/python3 -I -B -m inky_web.imager_lan",
                  "backend_environment": {"INKY_STUDIO_DATA_DIR": "/var/lib/inky-studio"}}
        values.update(changes)
        return profile.configure(**values)

    def test_normal_profile_binds_real_entrypoint_and_orders_wifi_before_nm(self):
        self.configure()
        raw = (self.root / "usr/lib/systemd/system/inky-studio.service").read_text()
        self.assertNotIn("@BACKEND_", raw)
        self.assertIn("inky_web.imager_lan", raw)
        self.assertIn("Requires=inkyos-imager-firstboot.service", raw)
        for name in ("systemd-rfkill.service", "systemd-rfkill.socket", "bluetooth.service"):
            self.assertEqual(os.readlink(self.root / "etc/systemd/system" / name), "/dev/null")
        for name in ("inky-studio.service", "inkyos-imager-firstboot.service"):
            self.assertTrue((self.root / "etc/systemd/system/multi-user.target.wants" / name).is_symlink())
        self.assertEqual(stat.S_IMODE((self.root / "usr/local/lib/inkyos/imager-firstboot.py").stat().st_mode), 0o555)
        self.assertEqual((self.boot / ".metadata_never_index").read_bytes(), b"")

    def test_factory_image_is_refused_instead_of_repaired(self):
        bad = self.root / "etc/inky-studio/factory-v1.json"
        bad.parent.mkdir(parents=True)
        bad.write_text("{}")
        with self.assertRaisesRegex(ValueError, "Factory/test"):
            self.configure()

    def test_environment_and_exec_cannot_inject_units_or_reenable_factory(self):
        for env in ({"INKY_STUDIO_DATA_DIR": "x\nInjected=yes"}, {"INKY_STUDIO_FACTORY_REQUIRED": "1"}):
            with self.subTest(env=env), self.assertRaises(ValueError):
                profile.render_environment(env)
        for command in ("/bin/sh -c evil", "/usr/lib/inky-studio/server/.venv/bin/python3 -I -B -m inky_web.main\nExecStart=/bin/sh"):
            with self.subTest(command=command), self.assertRaises(ValueError):
                self.configure(backend_exec_start=command)


if __name__ == "__main__":
    unittest.main()
