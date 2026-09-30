"""Offline redaction/path/durability fixtures; no host device or services used."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "diagnostic/sd-diagnostic.py"
spec = importlib.util.spec_from_file_location("inkyos_sd_diagnostic", SCRIPT)
diagnostic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostic)
BOOT_ID = "abcdef01-2345-4678-9234-567890abcdef"
HOSTNAME = "inky-" + "10" * 16
MACHINE_ID = "ab" * 16


class SimulatedPowerLoss(RuntimeError):
    pass


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "root"
        self.root.mkdir(mode=0o755)
        self.commands = []
        self.put("etc/machine-id", MACHINE_ID + "\n")
        self.put("etc/hostname", HOSTNAME + "\n")
        self.put("etc/hosts", "127.0.0.1 localhost\n127.0.1.1 " + HOSTNAME + " # fixture\n192.0.2.55 PERSONAL_NAME # PRIVATE_CONTACT\n")
        self.put("var/lib/inkyos/system.json", json.dumps({"version": 1, "hostname": HOSTNAME}), mode=0o600)
        (self.root / "var/lib/inkyos").chmod(0o700)
        self.put("proc/sys/kernel/hostname", HOSTNAME + "\n")
        self.put("proc/sys/kernel/random/boot_id", BOOT_ID + "\n")
        self.put("proc/uptime", "42.75 151.33\n")
        self.put("proc/meminfo", "MemTotal:      524288 kB\nMemAvailable: 262144 kB\nPrivateInfo: NEVER_EXPORT_THIS\n")
        self.put("sys/firmware/devicetree/base/model", "Raspberry Pi Zero 2 W Rev 1.0\0")
        self.put("sys/devices/virtual/thermal/thermal_zone0/temp", "48000\n")
        (self.root / "boot/firmware").mkdir(mode=0o755, parents=True)
        (self.root / "boot").chmod(0o755)
        self.put("proc/123/mountinfo", self.mountinfo())
        # Never read these sources. Place sentinels in the fixture to catch an
        # accidental expansion of the report's approved source list.
        self.put("sys/firmware/devicetree/base/serial-number", "PRIVATE_SERIAL\0")
        self.put("etc/NetworkManager/system-connections/private.nmconnection", "SSID=PRIVATE_WIFI\npassword=PRIVATE_PASSWORD\n")
        self.put("var/log/journal/private-log", "PRIVATE_JOURNAL QR_PRIVATE_KEY PRIVATE_PHOTO\n")
        self.adapters = diagnostic.Adapters(
            command=self.command,
            uname=lambda: SimpleNamespace(release="6.12.75+rpt-rpi-v8", machine="aarch64", nodename="PERSONAL_HOST", version="PERSONAL_DATE"),
            statvfs=lambda _fd: SimpleNamespace(f_frsize=4096, f_blocks=1024, f_bavail=512),
            process_id=123,
            mount_id=lambda fd: 1 if os.fstat(fd).st_ino == self.root.stat().st_ino else 2,
        )

    def put(self, path, content, *, mode=0o644):
        item = self.root / path
        item.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        for parent in item.parents:
            if parent == self.root:
                break
            # Existing private firstboot directory is explicitly reset after
            # fixture setup; all other directories model system ownership.
            parent.chmod(0o755)
        item.write_text(content)
        item.chmod(mode)
        return item

    def mountinfo(self, *, fs="vfat", options="rw", device=None, point="/boot/firmware"):
        dev = (self.root / "boot/firmware").stat().st_dev
        major, minor = (os.major(dev), os.minor(dev)) if device is None else device
        return (f"1 0 {os.major(dev)}:{os.minor(dev)} / / rw - ext4 /dev/mmcblk0p2 rw\n"
                f"2 1 {major}:{minor} / {point} {options} - {fs} /dev/mmcblk0p1 rw\n")

    def command(self, argv, *, timeout, limit):
        self.commands.append((argv, timeout, limit))
        if argv == ("/usr/bin/vcgencmd", "get_throttled"):
            return {"status": "ok"}, "throttled=0x50005\n"
        self.assertEqual(argv[:3], ("/usr/bin/systemctl", "--no-pager", "show"))
        self.assertIn(argv[3], diagnostic.UNITS)
        values = {"ActiveState": "inactive", "SubState": "dead", "Result": "success",
                  "ExecMainStatus": "0", "LoadState": "loaded", "UnitFileState": "masked"}
        properties = argv[4].removeprefix("--property=").split(",")
        return {"status": "ok"}, "".join(f"{key}={values[key]}\n" for key in properties)

    def export(self):
        return diagnostic.export_report(self.root, owner_uid=os.getuid(), adapters=self.adapters)

    @property
    def output(self):
        return self.root / "boot/firmware/inkyos-diagnostics"

    def expected_filename(self, boot_id=BOOT_ID):
        return "boot-" + hashlib.sha256(boot_id.encode("ascii")).hexdigest() + ".json"

    def test_report_whitelist_and_identity_coherence_without_raw_identifiers(self):
        result = self.export()
        self.assertEqual(result["filename"], self.expected_filename())
        saved = (self.output / result["filename"]).read_bytes()
        report = json.loads(saved)
        self.assertEqual(report, result["report"])
        self.assertEqual(set(report), {"schema_version", "boot_id_sha256", "hardware", "identity", "filesystems", "services"})
        for sentinel in (BOOT_ID, HOSTNAME, MACHINE_ID, "PERSONAL_NAME", "PRIVATE_CONTACT", "192.0.2.55",
                         "NEVER_EXPORT_THIS", "PRIVATE_SERIAL", "PRIVATE_WIFI", "PRIVATE_PASSWORD", "PRIVATE_JOURNAL",
                         "QR_PRIVATE_KEY", "PRIVATE_PHOTO", "PERSONAL_HOST", "PERSONAL_DATE"):
            self.assertNotIn(sentinel.encode(), saved)
        self.assertEqual(report["hardware"]["model"], {"status": "ok", "value": "Raspberry Pi Zero 2 W"})
        self.assertEqual(report["hardware"]["uptime_seconds"], {"status": "ok", "value": 42})
        self.assertEqual(report["hardware"]["memory"]["total_bytes"], 524288 * 1024)
        self.assertEqual(report["hardware"]["temperature_millicelsius"]["value"], 48000)
        self.assertEqual(report["hardware"]["throttling"], {"status": "ok", "value": 0x50005})
        self.assertEqual(report["identity"]["hostname"]["sha256"], hashlib.sha256(HOSTNAME.encode()).hexdigest())
        self.assertEqual(report["identity"]["coherence"], {"status": "ok", "state_matches_hostname": True,
                         "state_matches_kernel": True, "state_matches_hosts": True})
        self.assertEqual(report["filesystems"]["root"]["device"], "mmc")
        self.assertEqual(report["filesystems"]["boot"]["type"], "vfat")
        self.assertEqual(set(report["services"]), set(diagnostic.UNITS))
        self.assertIsNone(report["services"]["apt-daily.timer"]["ExecMainStatus"])
        self.assertIsNone(report["services"]["apt-daily.timer"]["Result"])
        self.assertTrue(all(timeout == 2.0 and limit <= 4096 for _, timeout, limit in self.commands))

    def test_same_boot_replaces_one_report_new_boot_creates_new_report_only(self):
        before = {str(path.relative_to(self.root)): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        one = self.export()
        self.put("proc/uptime", "99.90 188.20\n")
        two = self.export()
        self.assertEqual(one["filename"], two["filename"])
        self.assertEqual(len(list(self.output.glob("*.json"))), 1)
        other = "abcdef01-2345-4678-9234-567890abcdee"
        self.put("proc/sys/kernel/random/boot_id", other + "\n")
        three = self.export()
        self.assertEqual(three["filename"], self.expected_filename(other))
        self.assertEqual(len(list(self.output.glob("*.json"))), 2)
        for path, content in before.items():
            if path not in {"proc/uptime", "proc/sys/kernel/random/boot_id"}:
                self.assertEqual((self.root / path).read_bytes(), content)
        self.assertFalse(list(self.output.glob(".*")))

    def test_directory_without_real_vfat_mount_readonly_and_mismatched_device_are_refused(self):
        for content in (self.mountinfo(fs="ext4"), self.mountinfo(point="/boot"),
                        self.mountinfo(options="ro"), self.mountinfo(device=(999, 999)),
                        "malformed SECRET_RAW_MOUNTINFO\n", self.mountinfo() + self.mountinfo()):
            with self.subTest(content=content):
                self.put("proc/123/mountinfo", content)
                with self.assertRaises(diagnostic.DiagnosticError) as caught:
                    self.export()
                self.assertNotIn("SECRET", str(caught.exception))
                self.assertFalse(self.output.exists())

    def test_missing_mountinfo_and_invalid_boot_identity_fail_before_output_creation(self):
        mount = self.root / "proc/123/mountinfo"
        mount.unlink()
        with self.assertRaisesRegex(diagnostic.DiagnosticError, "^boot_mount_unavailable$"):
            self.export()
        self.put("proc/123/mountinfo", self.mountinfo())
        for value in ("", "PERSONAL_SERIAL", BOOT_ID.upper(), BOOT_ID + "\n\n", "00000000-0000-0000-0000-000000000000"):
            self.put("proc/sys/kernel/random/boot_id", value)
            with self.assertRaisesRegex(diagnostic.DiagnosticError, "^boot_identity_unavailable$"):
                self.export()
            self.assertFalse(self.output.exists())

    def test_fd_mount_id_selects_visible_mount_when_systemd_stacks_mountpoints(self):
        original = self.mountinfo()
        dev = (self.root / "boot/firmware").stat().st_dev
        hidden = f"3 1 {os.major(dev)}:{os.minor(dev)} / /boot/firmware rw - ext4 /dev/mmcblk0p2 rw\n"
        self.put("proc/123/mountinfo", original + hidden)
        self.assertEqual(self.export()["report"]["filesystems"]["boot"]["type"], "vfat")
        self.adapters.mount_id = lambda fd: 1 if os.fstat(fd).st_ino == self.root.stat().st_ino else 3
        with self.assertRaisesRegex(diagnostic.DiagnosticError, "^boot_mount_refused$"):
            self.export()

    def test_fdinfo_requires_one_canonical_mount_id_without_echoing_other_fields(self):
        files = diagnostic.Files(self.root, os.getuid())
        self.addCleanup(files.close)
        self.adapters.mount_id = None
        for content in ("pos:\t0\nflags:\t0100000\nmnt_id:\t1\nino:\tPRIVATE_SERIAL\n",):
            self.put(f"proc/123/fdinfo/{files.root}", content)
            self.assertEqual(diagnostic._fd_mount_id(files, self.adapters, files.root), 1)
        for content in ("PRIVATE_SERIAL", "mnt_id:\t0\n", "mnt_id:\t1\nmnt_id:\t1\n",
                        "mnt_id:\t4294967296\n", "mnt_id:\tPRIVATE_SERIAL\n", "mnt_id:\t" + "1" * 5000):
            with self.subTest(content=content[:80]):
                self.put(f"proc/123/fdinfo/{files.root}", content)
                with self.assertRaises(diagnostic.DiagnosticError) as caught:
                    diagnostic._fd_mount_id(files, self.adapters, files.root)
                self.assertNotIn("PRIVATE_SERIAL", str(caught.exception))

    def test_firstboot_missing_invalid_duplicate_schema_does_not_block_report(self):
        state = self.root / "var/lib/inkyos/system.json"
        state.unlink()
        self.assertEqual(self.export()["report"]["identity"]["firstboot_state"], {"status": "missing"})
        for content in ("{PERSONAL_SECRET", "{}", '{"version":true,"hostname":"' + HOSTNAME + '"}',
                        '{"version":1,"version":1,"hostname":"' + HOSTNAME + '"}',
                        '{"version":1,"hostname":"PERSONAL_HOST"}',
                        '{"version":1,"hostname":"' + HOSTNAME + '","serial":"PRIVATE_SERIAL"}'):
            with self.subTest(content=content):
                self.put("var/lib/inkyos/system.json", content, mode=0o600)
                (self.root / "var/lib/inkyos").chmod(0o700)
                report = self.export()["report"]
                self.assertEqual(report["identity"]["firstboot_state"], {"status": "invalid"})
                self.assertEqual(report["identity"]["coherence"], {"status": "unavailable"})
                self.assertNotIn("PRIVATE_SERIAL", json.dumps(report))
                self.assertEqual(state.read_text(), content)

    def test_hostname_coherence_detects_each_divergence_without_identifiers(self):
        other = "inky-" + "20" * 16
        for path, content, check in (
            ("etc/hostname", other + "\n", "state_matches_hostname"),
            ("proc/sys/kernel/hostname", other + "\n", "state_matches_kernel"),
            ("etc/hosts", "127.0.1.1 " + other + "\n", "state_matches_hosts"),
        ):
            with self.subTest(path=path):
                item = self.root / path
                before = item.read_text()
                self.put(path, content)
                report = self.export()["report"]
                self.assertFalse(report["identity"]["coherence"][check])
                self.assertNotIn(other, json.dumps(report))
                self.put(path, before)

    def test_invalid_identifiers_are_not_hashed_or_echoed(self):
        for path, label in (("etc/machine-id", "machine_id"), ("etc/hostname", "hostname"),
                            ("proc/sys/kernel/hostname", "kernel_hostname")):
            self.put(path, "PERSONAL_NAME_SECRET\n")
            report = self.export()["report"]
            self.assertEqual(report["identity"][label], {"status": "invalid"})
            self.assertNotIn("PERSONAL_NAME_SECRET", json.dumps(report))
        self.put("etc/machine-id", "0" * 32 + "\n")
        self.assertEqual(self.export()["report"]["identity"]["machine_id"], {"status": "invalid"})

    def test_all_inputs_refuse_symlinks_hardlinks_and_special_files(self):
        outside = self.base / "outside"
        outside.write_text("PRIVATE_SENTINEL\n")
        paths = (("etc/machine-id", ("identity", "machine_id")),
                 ("var/lib/inkyos/system.json", ("identity", "firstboot_state")),
                 ("sys/firmware/devicetree/base/model", ("hardware", "model")),
                 ("proc/meminfo", ("hardware", "memory")))
        for path, keys in paths:
            item = self.root / path
            before = item.read_bytes()
            mode = item.stat().st_mode & 0o777
            for kind in ("symlink", "hardlink", "fifo"):
                with self.subTest(path=path, kind=kind):
                    item.unlink()
                    if kind == "symlink":
                        item.symlink_to(outside)
                    elif kind == "hardlink":
                        os.link(outside, item)
                    else:
                        os.mkfifo(item)
                    report = self.export()["report"]
                    self.assertEqual(report[keys[0]][keys[1]], {"status": "unsafe_path"})
                    self.assertNotIn("PRIVATE_SENTINEL", json.dumps(report))
                    self.assertEqual(outside.read_text(), "PRIVATE_SENTINEL\n")
                    item.unlink()
                    item.write_bytes(before)
                    item.chmod(mode)

    def test_input_parent_symlink_and_writable_parent_are_not_followed(self):
        etc = self.root / "etc"
        real = self.root / "real-etc"
        etc.rename(real)
        etc.symlink_to(real, target_is_directory=True)
        report = self.export()["report"]
        self.assertEqual(report["identity"]["hostname"], {"status": "read_error"})
        self.assertEqual(report["identity"]["coherence"], {"status": "unavailable"})
        etc.unlink()
        real.rename(etc)
        etc.chmod(0o777)
        self.assertEqual(self.export()["report"]["identity"]["hostname"], {"status": "unsafe_path"})

    def test_output_directory_and_report_target_refuse_symlinks_hardlinks_and_specials(self):
        outside = self.base / "outside-dir"
        outside.mkdir()
        self.output.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(diagnostic.DiagnosticError):
            self.export()
        self.assertFalse(list(outside.iterdir()))
        self.output.unlink()
        self.output.mkdir()
        target = self.output / self.expected_filename()
        sentinel = outside / "sentinel"
        sentinel.write_text("PRIVATE_SENTINEL\n")
        for kind in ("symlink", "hardlink", "fifo", "directory"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    target.symlink_to(sentinel)
                elif kind == "hardlink":
                    os.link(sentinel, target)
                elif kind == "fifo":
                    os.mkfifo(target)
                else:
                    target.mkdir()
                with self.assertRaisesRegex(diagnostic.DiagnosticError, "^report_write_failed$"):
                    self.export()
                self.assertEqual(sentinel.read_text(), "PRIVATE_SENTINEL\n")
                target.rmdir() if kind == "directory" else target.unlink()
                self.assertFalse(list(self.output.iterdir()))

    def test_boot_directory_symlink_is_refused(self):
        boot = self.root / "boot/firmware"
        boot.rmdir()
        outside = self.base / "outside"
        outside.mkdir()
        boot.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(diagnostic.DiagnosticError):
            self.export()
        self.assertFalse(list(outside.iterdir()))

    def test_input_sizes_and_arbitrary_metrics_emit_fixed_errors(self):
        self.put("proc/meminfo", "PRIVATE_SENTINEL" * 2000)
        self.put("sys/devices/virtual/thermal/thermal_zone0/temp", "SERIAL_SECRET")
        self.put("sys/firmware/devicetree/base/model", "Raspberry Pi Zero 2 W Rev 1.0 PRIVATE_NAME\0")
        self.put("proc/uptime", "PERSONAL_DATE")
        self.adapters.uname = lambda: SimpleNamespace(release="6.12.75+PERSONAL_SECRET", machine="PERSONAL_ARCH")
        report = self.export()["report"]
        self.assertEqual(report["hardware"]["memory"], {"status": "too_large"})
        for metric in ("temperature_millicelsius", "model", "uptime_seconds", "kernel", "architecture"):
            self.assertEqual(report["hardware"][metric], {"status": "invalid"})
        self.assertNotIn("PERSONAL", json.dumps(report))
        self.assertNotIn("SECRET", json.dumps(report))

    def test_services_and_throttling_timeout_unknown_properties_and_raw_output_are_redacted(self):
        original = self.adapters.command
        for state, content, expected in (({"status": "timeout"}, "SECRET_TIMEOUT", "timeout"),
                                         ({"status": "exception PRIVATE_NAME"}, "SECRET_ERROR", "command_error"),
                                         ({"status": "ok"}, "ActiveState=PRIVATE_NAME\n", "invalid"),
                                         ({"status": "ok"}, "SECRET_OVERSIZE" * 1000, "invalid")):
            with self.subTest(expected=expected):
                self.adapters.command = lambda _argv, **_kw: (state, content)
                report = self.export()["report"]
                self.assertEqual(report["services"]["NetworkManager.service"], {"status": expected})
                self.assertEqual(report["hardware"]["throttling"], {"status": expected})
                self.assertNotIn("SECRET", json.dumps(report))
                self.assertNotIn("PRIVATE_NAME", json.dumps(report))
        self.adapters.command = original

    def test_exhausted_global_command_budget_still_exports_fixed_timeout_metrics(self):
        with mock.patch.object(diagnostic.time, "monotonic", side_effect=[0] + [36] * 30):
            report = self.export()["report"]
        self.assertEqual(self.commands, [])
        self.assertEqual(report["hardware"]["throttling"], {"status": "timeout"})
        self.assertTrue(all(value == {"status": "timeout"} for value in report["services"].values()))
        self.assertEqual(report["identity"]["coherence"]["status"], "ok")

    def test_canonical_throttling_rejects_unknown_bits_extra_fields_and_oversized_numbers(self):
        original = self.adapters.command
        for text in ("throttled=0x10\n", "throttled=0x100000000\n", "throttled=0x0\nserial=PRIVATE_SERIAL\n", "throttled=0x0FFFF\n"):
            def command(argv, **kwargs):
                return ({"status": "ok"}, text) if argv[0] == "/usr/bin/vcgencmd" else original(argv, **kwargs)
            self.adapters.command = command
            report = self.export()["report"]
            self.assertEqual(report["hardware"]["throttling"], {"status": "invalid"})
            self.assertNotIn("PRIVATE_SERIAL", json.dumps(report))

    def test_atomic_write_checkpoints_recover_without_partial_reports_or_tempfiles(self):
        for stage in ("report:temp_fsynced", "report:replaced", "report:directory_fsynced"):
            with self.subTest(stage=stage):
                def cut(current):
                    if current == stage:
                        raise SimulatedPowerLoss(stage)
                self.adapters.checkpoint = cut
                with self.assertRaises(SimulatedPowerLoss):
                    self.export()
                reports = list(self.output.glob("*.json"))
                for path in reports:
                    self.assertEqual(json.loads(path.read_text())["schema_version"], 1)
                self.assertFalse(list(self.output.glob(".*")))
                self.adapters.checkpoint = lambda _stage: None
                self.export()
                self.assertEqual(len(list(self.output.glob("*.json"))), 1)

    def test_fsync_failure_is_reported_and_no_secret_exception_text_escapes(self):
        original = os.fsync
        def fail(fd):
            if self.output.exists() and (os.fstat(fd).st_mode & 0o170000) == 0o100000:
                raise OSError("PRIVATE_SECRET_PATH")
            return original(fd)
        with mock.patch.object(diagnostic.os, "fsync", side_effect=fail):
            with self.assertRaisesRegex(diagnostic.DiagnosticError, "^report_write_failed$") as caught:
                self.export()
        self.assertNotIn("PRIVATE", str(caught.exception))
        self.assertFalse(list(self.output.iterdir()))

    def test_cli_rejects_paths_and_nonroot_and_never_touches_fixture(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--root", str(self.root)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrecognized arguments", result.stderr)
        self.assertFalse(self.output.exists())
        with mock.patch.object(diagnostic.sys, "argv", [str(SCRIPT)]), mock.patch.object(diagnostic.os, "geteuid", return_value=1000):
            with mock.patch.object(diagnostic, "export_report") as export:
                self.assertEqual(diagnostic.main(), 1)
                export.assert_not_called()


class BoundedCommandTests(unittest.TestCase):
    def test_actual_timeout_and_stdout_limit_discard_private_outputs(self):
        started = time.monotonic()
        status, result = diagnostic.bounded_command((sys.executable, "-c", "import time; print('PRIVATE_SECRET', flush=True); time.sleep(5)"), timeout=0.05, limit=128)
        self.assertEqual(status, {"status": "timeout"})
        self.assertIsNone(result)
        self.assertLess(time.monotonic() - started, 2)
        status, result = diagnostic.bounded_command((sys.executable, "-c", "print('PRIVATE_SECRET' * 1000)"), timeout=2, limit=128)
        self.assertEqual(status, {"status": "too_large"})
        self.assertIsNone(result)

    def test_actual_failure_invalid_encoding_and_success_are_canonical(self):
        cases = (("import sys; sys.stderr.write('PRIVATE_SECRET'); sys.exit(5)", "command_error", None),
                 ("import sys; sys.stdout.buffer.write(b'\\xff')", "invalid", None),
                 ("print('throttled=0x0')", "ok", "throttled=0x0\n"))
        for code, expected, content in cases:
            status, result = diagnostic.bounded_command((sys.executable, "-c", code), timeout=2, limit=128)
            self.assertEqual(status, {"status": expected})
            self.assertEqual(result, content)


if __name__ == "__main__":
    unittest.main()
