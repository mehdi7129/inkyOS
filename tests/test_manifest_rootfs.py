"""Metadata fixtures only; no mount, VM, device open, personal tree or image boot."""

import contextlib
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/manifest-rootfs.py"
spec = importlib.util.spec_from_file_location("manifest_rootfs", SCRIPT)
manifest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manifest)
HAS_LINUX_XATTRS = (sys.platform.startswith("linux") and
                   all(hasattr(os, name) for name in ("listxattr", "getxattr", "setxattr")))


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # macOS /var is a host symlink: choose the canonical fixture root.
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "root"
        self.boot = self.base / "boot"
        self.root.mkdir()
        self.boot.mkdir()

    def test_root_metadata_file_hash_and_schema_are_present(self):
        self.root.chmod(0o751)
        (self.root / "data").write_bytes(b"generic fixture\x00\xff")
        result = manifest.build_manifest(self.root, self.boot)
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["scope"], "content-and-metadata-without-timestamps")
        self.assertEqual(result["rootfs"]["."]["type"], "directory")
        self.assertEqual(result["rootfs"]["."]["mode"], "0751")
        self.assertEqual(result["rootfs"]["data"]["sha256"],
                         hashlib.sha256(b"generic fixture\x00\xff").hexdigest())
        self.assertEqual(result["rootfs"]["data"]["size_bytes"], 17)
        self.assertIn(".", result["bootfs"])

    def test_symlinks_are_not_followed_and_fifo_socket_do_not_block(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "secret").write_text("DO_NOT_READ_SENTINEL")
        (self.root / "external").symlink_to(outside, target_is_directory=True)
        (self.root / "broken").symlink_to("missing-target")
        os.mkfifo(self.root / "fifo")
        sock = socket.socket(socket.AF_UNIX)
        self.addCleanup(sock.close)
        sock.bind(str(self.root / "socket"))
        records = manifest.inventory(self.root)
        self.assertEqual(records["external"]["type"], "symlink")
        self.assertNotIn("external/secret", records)
        self.assertNotIn("DO_NOT_READ_SENTINEL", json.dumps(records))
        self.assertEqual(records["fifo"]["type"], "fifo")
        self.assertEqual(records["socket"]["type"], "socket")
        self.assertNotIn("size_bytes", records["fifo"])

    def test_input_root_and_parent_symlinks_are_refused(self):
        alias = self.base / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            manifest.inventory(alias)
        (self.root / "child").mkdir()
        with self.assertRaises(OSError):
            manifest.inventory(alias / "child")

    def test_hardlink_topology_is_relative_and_deterministic(self):
        (self.root / "a").write_text("same content")
        os.link(self.root / "a", self.root / "b")
        first = manifest.inventory(self.root)
        other = self.base / "other"
        other.mkdir()
        (other / "b").write_text("same content")
        os.link(other / "b", other / "a")
        second = manifest.inventory(other)
        self.assertEqual(first, second)
        self.assertEqual(first["a"]["hardlinks"], ["a", "b"])
        self.assertEqual(first["b"]["hardlinks"], ["a", "b"])
        self.assertNotIn("inode", json.dumps(first))
        (other / "a").unlink()
        (other / "a").write_text("same content")
        independent = manifest.inventory(other)
        self.assertNotEqual(first, independent)
        self.assertNotIn("hardlinks", independent["a"])

    def test_hardlink_crossing_root_boundary_is_explicitly_refused(self):
        outside = self.base / "outside-file"
        outside.write_text("same inode outside root")
        os.link(outside, self.root / "linked")
        with self.assertRaisesRegex(manifest.ManifestError, "Hardlink group is incomplete"):
            manifest.inventory(self.root)

    def test_xattr_empty_result_is_inspected_not_a_capability_claim(self):
        with mock.patch.object(manifest.sys, "platform", "linux"), \
             mock.patch.object(manifest.os, "listxattr", return_value=[], create=True), \
             mock.patch.object(manifest.os, "getxattr", create=True) as get:
            result = manifest._xattrs(123)
        self.assertEqual(result, {"status": "inspected", "entries": {}})
        get.assert_not_called()

    def test_linux_acl_values_are_hashed_and_not_serialized(self):
        values = {"system.posix_acl_access": b"ACL_VALUE_SENTINEL", "user.fixture": b"OTHER_VALUE_SENTINEL"}
        with mock.patch.object(manifest.sys, "platform", "linux"), \
             mock.patch.object(manifest.os, "listxattr", return_value=list(values), create=True), \
             mock.patch.object(manifest.os, "getxattr", side_effect=lambda _fd, name: values[name], create=True):
            result = manifest._xattrs(123)
        self.assertEqual(result["entries"]["system.posix_acl_access"],
                         {"size_bytes": len(values["system.posix_acl_access"]),
                          "sha256": hashlib.sha256(values["system.posix_acl_access"]).hexdigest()})
        self.assertNotIn("VALUE_SENTINEL", json.dumps(result))

    def test_filesystem_xattr_unsupported_is_distinct_and_permission_denied_fails(self):
        for number in (errno.ENOTSUP, errno.EOPNOTSUPP, errno.EACCES, errno.EPERM):
            with self.subTest(errno=number), \
                 mock.patch.object(manifest.sys, "platform", "linux"), \
                 mock.patch.object(manifest.os, "listxattr", side_effect=OSError(number, "fixture"), create=True), \
                 mock.patch.object(manifest.os, "getxattr", create=True):
                if number in (errno.ENOTSUP, errno.EOPNOTSUPP):
                    self.assertEqual(manifest._xattrs(123), {"status": "unsupported", "reason": "filesystem"})
                else:
                    with self.assertRaises(manifest.ManifestError):
                        manifest._xattrs(123)

    def test_non_linux_does_not_translate_platform_xattrs_into_linux_acls(self):
        with mock.patch.object(manifest.sys, "platform", "darwin"), \
             mock.patch.object(manifest.os, "listxattr", create=True) as listing:
            self.assertEqual(manifest._xattrs(123), {"status": "unsupported", "reason": "platform"})
        listing.assert_not_called()

    def test_xattr_value_permission_denied_cannot_become_absence(self):
        with mock.patch.object(manifest.sys, "platform", "linux"), \
             mock.patch.object(manifest.os, "listxattr", return_value=["security.fixture"], create=True), \
             mock.patch.object(manifest.os, "getxattr", side_effect=PermissionError(errno.EACCES, "fixture"), create=True):
            with self.assertRaises(manifest.ManifestError):
                manifest._xattrs(123)

    @unittest.skipUnless(HAS_LINUX_XATTRS, "Linux xattr APIs unavailable; macOS ACLs are not Linux ACLs")
    def test_real_linux_xattr_change_changes_inventory_without_value_leak(self):
        target = self.root / "data"
        target.write_text("same file")
        try:
            os.setxattr(target, "user.inkyos-fixture", b"FIRST_XATTR_SENTINEL")
        except OSError as exc:
            if exc.errno in {errno.ENOTSUP, errno.EOPNOTSUPP, errno.EPERM}:
                self.skipTest("Fixture filesystem does not permit user xattrs")
            raise
        first = manifest.inventory(self.root)
        os.setxattr(target, "user.inkyos-fixture", b"SECOND_XATTR_SENTINEL")
        second = manifest.inventory(self.root)
        self.assertNotEqual(first["data"]["xattrs"], second["data"]["xattrs"])
        self.assertEqual(first["data"]["sha256"], second["data"]["sha256"])
        self.assertNotIn("XATTR_SENTINEL", json.dumps(first))

    @unittest.skipUnless(HAS_LINUX_XATTRS, "Linux ACL xattrs unavailable; no macOS ACL substitution")
    def test_real_linux_posix_acl_is_included_as_an_xattr_digest(self):
        target = self.root / "acl-file"
        target.write_text("generic fixture")
        # Linux POSIX ACL xattr v2: owner, named user, group, mask, other.
        undefined = 0xffffffff
        acl = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", tag, perms, identity)
                                             for tag, perms, identity in (
                                                 (1, 7, undefined), (2, 4, 1001),
                                                 (4, 5, undefined), (16, 5, undefined),
                                                 (32, 0, undefined)))
        try:
            os.setxattr(target, "system.posix_acl_access", acl)
        except OSError as exc:
            if exc.errno in {errno.ENOTSUP, errno.EOPNOTSUPP, errno.EPERM}:
                self.skipTest("Fixture filesystem does not permit Linux POSIX ACL xattrs")
            raise
        stored = os.getxattr(target, "system.posix_acl_access")
        records = manifest.inventory(self.root)
        self.assertEqual(records["acl-file"]["xattrs"]["entries"]["system.posix_acl_access"],
                         {"size_bytes": len(stored), "sha256": hashlib.sha256(stored).hexdigest()})

    @unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0,
                         "Character/block device fixtures require Linux root; never opened")
    def test_char_and_block_device_types_are_distinguished_without_open(self):
        try:
            os.mknod(self.root / "char", stat.S_IFCHR | 0o600, os.makedev(1, 3))
            os.mknod(self.root / "block", stat.S_IFBLK | 0o600, os.makedev(7, 0))
        except PermissionError:
            self.skipTest("Fixture environment lacks CAP_MKNOD")
        records = manifest.inventory(self.root)
        self.assertEqual(records["char"]["type"], "char")
        self.assertEqual(records["block"]["type"], "block")
        self.assertEqual(records["char"]["device"], {"major": 1, "minor": 3})
        self.assertEqual(records["block"]["device"], {"major": 7, "minor": 0})

    def test_output_inside_either_tree_existing_or_symlink_is_refused(self):
        outside = self.base / "existing.json"
        outside.write_text("PRESERVE_SENTINEL")
        alias = self.base / "output-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        linked_output = self.base / "linked.json"
        linked_output.symlink_to(outside)
        for output in (self.root / "report.json", self.boot / "report.json", outside,
                       alias / "report.json", linked_output):
            with self.subTest(output=output), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(manifest.main(["--rootfs", str(self.root), "--bootfs", str(self.boot),
                                                "--output", str(output)]), 1)
        self.assertEqual(outside.read_text(), "PRESERVE_SENTINEL")
        self.assertFalse((self.root / "report.json").exists())
        self.assertFalse((self.boot / "report.json").exists())
        output = self.base / "new.json"
        self.assertEqual(manifest.main(["--rootfs", str(self.root), "--bootfs", str(self.boot),
                                       "--output", str(output)]), 0)
        self.assertEqual(json.loads(output.read_text())["schema_version"], 2)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
