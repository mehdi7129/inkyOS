import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "acquire_sd", Path(__file__).resolve().parents[1] / "scripts/acquire-sd-macos.py")
acquisition = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acquisition)


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        # The production walker deliberately rejects world-writable /tmp.
        self.tmp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.private = self.root / "private"
        self.private.mkdir(mode=0o700)
        self.output = self.private / "new-return"
        self.payload = b"fixture card bytes" * 17
        self.expected = {"device": "disk6", "capacity_bytes": len(self.payload), "registry_id": 1234}
        self.raw = self.root / "fake-card"
        self.raw.write_bytes(self.payload)

    @contextlib.contextmanager
    def environment(self, records=None):
        original_open = os.open
        raw_flags = []

        def guarded_open(path, flags, *args, **kwargs):
            if path == "/dev/rdisk6":
                raw_flags.append(flags)
                self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
                # Fixtures have no device lock; production flags are tested separately.
                return original_open(self.raw, os.O_RDONLY | os.O_NOFOLLOW)
            return original_open(path, flags, *args, **kwargs)

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(acquisition.platform, "system", return_value="Darwin"))
            stack.enter_context(patch.object(acquisition.os, "geteuid", return_value=0))
            stack.enter_context(patch.object(acquisition.os, "O_EXLOCK", 0x20, create=True))
            stack.enter_context(patch.object(acquisition, "media_record",
                                              side_effect=records, return_value=self.expected))
            command = stack.enter_context(patch.object(acquisition, "run"))
            stack.enter_context(patch.object(acquisition, "require_raw_device"))
            stack.enter_context(patch.object(acquisition.os, "open", side_effect=guarded_open))
            yield command, raw_flags

    def test_default_dry_run_creates_nothing_and_never_unmounts_or_opens_card(self):
        with self.environment() as (command, flags):
            result = acquisition.acquire_sd(str(self.output), self.expected)
        self.assertEqual(result["status"], "dry_run")
        self.assertFalse(result["copy_complete"])
        self.assertFalse(self.output.exists())
        self.assertEqual(flags, [])
        command.assert_not_called()

    def test_success_copies_full_card_private_and_without_eject_or_raw_write(self):
        with self.environment() as (command, flags):
            result = acquisition.acquire_sd(str(self.output), self.expected, acquire=True)
        self.assertEqual(result["status"], "complete", result)
        self.assertTrue(result["copy_complete"])
        self.assertTrue(result["local_readback_verified"])
        self.assertTrue(result["receipt_saved"])
        self.assertFalse(result["ejected"])
        self.assertEqual((self.output / "returned.img").read_bytes(), self.payload)
        self.assertEqual(result["sha256"], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(json.loads((self.output / "acquisition.json").read_text()), result)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        for filename in ("returned.img", "acquisition.json"):
            self.assertEqual(stat.S_IMODE((self.output / filename).stat().st_mode), 0o600)
        self.assertEqual(len(flags), 1)
        command.assert_called_once_with(["/usr/sbin/diskutil", "unmountDisk", "/dev/disk6"])

    def test_reinserted_medium_refused_before_unmount_and_preserves_failed_receipt(self):
        changed = dict(self.expected, registry_id=5678)
        with self.environment(records=[self.expected, self.expected, changed]) as (command, flags):
            result = acquisition.acquire_sd(str(self.output), self.expected, acquire=True)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error"], "medium_changed")
        self.assertEqual(flags, [])
        command.assert_not_called()
        self.assertEqual((self.output / "returned.img").stat().st_size, 0)
        self.assertEqual(json.loads((self.output / "acquisition.json").read_text()), result)

    def test_changed_medium_after_copy_never_marks_return_complete(self):
        changed = dict(self.expected, registry_id=5678)
        with self.environment(records=[self.expected] * 5 + [changed]):
            result = acquisition.acquire_sd(str(self.output), self.expected, acquire=True)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["copy_complete"])
        self.assertIsNone(result["sha256"])
        self.assertEqual((self.output / "returned.img").read_bytes(), self.payload)

    def test_existing_destination_and_symlink_are_never_overwritten(self):
        self.output.mkdir()
        sentinel = self.output / "keep"
        sentinel.write_text("existing")
        with self.environment() as (command, flags):
            result = acquisition.acquire_sd(str(self.output), self.expected, acquire=True)
        self.assertEqual(result["error"], "destination_already_exists")
        self.assertEqual(sentinel.read_text(), "existing")
        self.assertEqual(flags, [])
        command.assert_not_called()
        link = self.private / "symlink-return"
        link.symlink_to(self.output)
        with self.environment():
            result = acquisition.acquire_sd(str(link), self.expected, acquire=True)
        self.assertEqual(result["error"], "destination_already_exists")

    def test_symlink_and_writable_ancestors_refused(self):
        alias = self.root / "alias"
        alias.symlink_to(self.private)
        with self.assertRaises(acquisition.Refused):
            acquisition.open_destination_parent(str(alias / "new"), None)
        real = self.root / "other"
        real.mkdir(mode=0o700)
        (real / "private").symlink_to(self.private)
        with self.assertRaises(OSError):
            acquisition.open_destination_parent(str(real / "private" / "new"), None)
        self.root.chmod(0o777)
        try:
            with self.assertRaises(acquisition.Refused):
                acquisition.open_destination_parent(str(self.output), None)
        finally:
            self.root.chmod(0o700)

    def test_eof_preserves_partial_image_and_failed_receipt(self):
        self.raw.write_bytes(b"partial")
        with self.environment():
            result = acquisition.acquire_sd(str(self.output), self.expected, acquire=True)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error"], "card_ended_early")
        self.assertEqual((self.output / "returned.img").read_bytes(), b"partial")
        self.assertEqual(json.loads((self.output / "acquisition.json").read_text()), result)
        with self.environment():
            second = acquisition.acquire_sd(str(self.output), self.expected, acquire=True)
        self.assertEqual(second["error"], "destination_already_exists")
        self.assertEqual((self.output / "returned.img").read_bytes(), b"partial")

    def test_partial_writes_and_sparse_zero_blocks_reconstruct_exact_bytes(self):
        block = 4096
        for payload in (bytes(block * 3), b"x" * block + bytes(block) + b"y" * block,
                        b"x" * block + bytes(block * 2), b"abc" * 3000):
            with self.subTest(length=len(payload)), tempfile.TemporaryFile() as source, \
                    tempfile.TemporaryFile() as target:
                source.write(payload)
                source.seek(0)
                original_write = os.write
                with patch.object(acquisition, "BLOCK_SIZE", block), \
                        patch.object(acquisition.os, "write", side_effect=lambda fd, data:
                                     original_write(fd, data[:17])):
                    digest = acquisition.copy_card(source.fileno(), target.fileno(), len(payload))
                self.assertEqual(os.fstat(target.fileno()).st_size, len(payload))
                self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
                self.assertEqual(acquisition.local_readback(target.fileno(), len(payload)), digest)
                target.seek(0)
                self.assertEqual(target.read(), payload)

    def test_no_progress_write_is_refused(self):
        with patch.object(acquisition.os, "write", return_value=0):
            with self.assertRaises(acquisition.Refused):
                acquisition.write_all(3, b"fixture")

    def test_raw_flags_are_read_only_and_exclusive(self):
        with patch.object(acquisition.os, "O_EXLOCK", 0x20, create=True):
            flags = acquisition.raw_device_flags()
        self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
        self.assertEqual(flags & os.O_NOFOLLOW, os.O_NOFOLLOW)
        self.assertEqual(flags & os.O_NONBLOCK, os.O_NONBLOCK)
        self.assertEqual(flags & 0x20, 0x20)
        with patch.object(acquisition.os, "O_EXLOCK", None, create=True):
            with self.assertRaises(acquisition.Refused):
                acquisition.raw_device_flags()

    def test_raw_regular_file_and_symlink_are_refused(self):
        fd = os.open(self.raw, os.O_RDONLY)
        try:
            with self.assertRaises(acquisition.Refused):
                acquisition.require_raw_device(fd, self.raw)
        finally:
            os.close(fd)
        with tempfile.TemporaryFile() as ordinary:
            with self.assertRaises(acquisition.Refused):
                acquisition.require_raw_device(ordinary.fileno(), "/dev/null")

    def test_replaced_local_image_name_is_refused_before_success(self):
        readback = acquisition.local_readback

        def replace_after_readback(fd, size):
            digest = readback(fd, size)
            (self.output / "returned.img").rename(self.output / "preserved.img")
            (self.output / "returned.img").write_bytes(b"replacement")
            return digest

        with self.environment(), patch.object(acquisition, "local_readback", side_effect=replace_after_readback):
            result = acquisition.acquire_sd(str(self.output), self.expected, acquire=True)
        self.assertEqual(result["error"], "local_image_entry_changed")
        self.assertFalse(result["copy_complete"])
        self.assertEqual((self.output / "preserved.img").read_bytes(), self.payload)

    def test_owner_handoff_requires_sudo_identity(self):
        with patch.dict(os.environ, {"SUDO_UID": "501", "SUDO_GID": "20"}, clear=True):
            self.assertEqual(acquisition.owner_identity(501, 20, True), (501, 20))
            with self.assertRaises(acquisition.Refused):
                acquisition.owner_identity(502, 20, True)
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(acquisition.Refused):
                acquisition.owner_identity(501, 20, True)

    def test_local_readback_detects_corruption(self):
        with tempfile.TemporaryFile() as target:
            target.write(self.payload)
            target.flush()
            expected = hashlib.sha256(self.payload).hexdigest()
            self.assertEqual(acquisition.local_readback(target.fileno(), len(self.payload)), expected)
            target.seek(0)
            target.write(b"changed")
            target.flush()
            self.assertNotEqual(acquisition.local_readback(target.fileno(), len(self.payload)), expected)

    def test_interrupt_preserves_partial_with_failed_receipt(self):
        with self.environment(), patch.object(acquisition, "copy_card", side_effect=KeyboardInterrupt):
            result = acquisition.acquire_sd(str(self.output), self.expected, acquire=True)
        self.assertEqual(result["error"], "interrupted")
        self.assertEqual(result["status"], "failed")
        self.assertTrue((self.output / "returned.img").exists())
        self.assertTrue((self.output / "acquisition.json").exists())

    def test_progress_preserves_exact_copy_and_hash_including_sparse_bytes(self):
        payload = b"nonzero" * 1024 + bytes(8192)
        events = []
        callback = lambda phase, count, total: events.append((phase, count, total))
        with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as target:
            source.write(payload)
            source.seek(0)
            with patch.object(acquisition, "BLOCK_SIZE", 4096):
                digest = acquisition.copy_card(source.fileno(), target.fileno(), len(payload), callback)
                readback = acquisition.local_readback(target.fileno(), len(payload), callback)
            target.seek(0)
            self.assertEqual(target.read(), payload)
        self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
        self.assertEqual(readback, digest)
        for phase in ("copy", "local_readback"):
            counts = [count for observed, count, total in events if observed == phase]
            self.assertEqual(counts[0], 0)
            self.assertEqual(counts[-1], len(payload))
            self.assertEqual(counts, sorted(counts))
        self.assertTrue(all(total == len(payload) for _, _, total in events))

    def test_progress_throttles_by_time_or_bytes_with_explicit_phase_start(self):
        stream = io.StringIO()
        progress = acquisition.StderrProgress()
        total = 1024**3
        with contextlib.redirect_stderr(stream), \
                patch.object(acquisition.time, "monotonic", side_effect=[0, 1, 2, 2.1, 2.2, 2.3]):
            progress("copy", 0, total)
            progress("copy", 1, total)  # Suppressed: neither threshold reached.
            progress("copy", 2, total)  # Time threshold.
            progress("copy", 2 + 256 * 1024**2, total)  # Byte threshold.
            progress("copy", total, total)
            progress("local_readback", 0, total)
        lines = stream.getvalue().splitlines()
        self.assertEqual(len(lines), 5)
        self.assertEqual(lines[0], f"copy: 0.0% (0/{total} bytes)")
        self.assertEqual(lines[-1], f"local_readback: 0.0% (0/{total} bytes)")
        for line in lines:
            self.assertRegex(line, r"^(copy|local_readback): [0-9]+\.[0-9]% \([0-9]+/[0-9]+ bytes\)$")

    def test_progress_cli_keeps_stdout_one_json_document(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        argv = ["acquire-sd-macos.py", "--output-dir", str(self.output), "--device", "disk6",
                "--capacity-bytes", str(len(self.payload)), "--registry-id", "1234", "--acquire",
                "--progress"]
        with self.environment(), patch.object(acquisition.sys, "argv", argv), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = acquisition.main()
        self.assertEqual(status, 0)
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["sha256"], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(len(stderr.getvalue().splitlines()), 4)
        self.assertNotIn(str(self.output), stderr.getvalue())
        self.assertNotIn(result["sha256"], stderr.getvalue())
        self.assertNotIn(self.payload.decode(), stderr.getvalue())

    def test_progress_dry_run_is_silent_and_creates_nothing(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        argv = ["acquire-sd-macos.py", "--output-dir", str(self.output), "--device", "disk6",
                "--capacity-bytes", str(len(self.payload)), "--registry-id", "1234", "--progress"]
        with self.environment(), patch.object(acquisition.sys, "argv", argv), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = acquisition.main()
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "dry_run")
        self.assertEqual(stderr.getvalue(), "")
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
