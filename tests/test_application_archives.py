"""Real adversarial tar/gzip/ZIP fixtures, inspected without extraction or execution."""

import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile
import zlib
import tarfile


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/inspect-application-archives.py"
spec = importlib.util.spec_from_file_location("inspect_application_archives", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
COMMIT = "a" * 40
APP_FILES = {
    "server/pyproject.toml": b"[build-system]\nrequires=['hatchling']\n",
    "server/SOURCE_COMMIT": (COMMIT + "\n").encode(),
    "client/dist/index.html": b"<!doctype html><title>Fixture</title>",
    "shared/fixture.json": b"{}",
    "scripts/fixture.py": b"raise RuntimeError('MUST NEVER EXECUTE')\n",
    "VERSION": b"0.5.0rc2\n",
}
ZIP_FILES = {
    "fixture-1.0-py3-none-any.whl": b"opaque wheel bytes, deliberately not opened",
    "provenance.json": b"{}",
    "licenses/index.json": b"{}",
    "licenses/fixture.txt": b"generic license fixture",
}


def tar_bytes(extra=(), *, prefix="", omit=(), replacements=None, compressed=True, pax=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in APP_FILES.items():
            if name in omit:
                continue
            data = (replacements or {}).get(name, data)
            info = tarfile.TarInfo(prefix + name)
            info.size = len(data)
            info.mode = 0o644
            if pax and name == "server/pyproject.toml":
                info.pax_headers = pax
            archive.addfile(info, io.BytesIO(data))
        for name, data, kind, mode in extra:
            info = tarfile.TarInfo(name)
            info.type, info.mode = kind, mode
            info.size = len(data)
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                info.linkname = "../../outside"
            archive.addfile(info, io.BytesIO(data))
    result = output.getvalue()
    return gzip.compress(result, mtime=0) if compressed else result


class NonSeekable(io.BytesIO):
    def seek(self, *_args):
        raise io.UnsupportedOperation("fixture stream")


def zip_bytes(extra=(), *, compression=zipfile.ZIP_DEFLATED, omit=(), prefix=b"", descriptor=False):
    output = NonSeekable() if descriptor else io.BytesIO(prefix)
    if not descriptor:
        output.seek(0, os.SEEK_END)
    with warnings.catch_warnings(), zipfile.ZipFile(output, "w", compression=compression) as archive:
        warnings.simplefilter("ignore", UserWarning)
        for name, data in ZIP_FILES.items():
            if name not in omit:
                archive.writestr(name, data)
        for name, data, mode in extra:
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = mode << 16
            info.compress_type = compression
            archive.writestr(info, data)
    return output.getvalue()


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.manifest = self.root / "manifest.json"

    def bundle(self, app=None, wheels=None):
        data = {"schema_version": 1, "application_version": "0.5.0rc2", "source_commit": COMMIT,
                "compatibility": {**module.verifier.TARGET,
                                  **{key: "git:" + COMMIT + "#server/inky_web"
                                     for key in module.verifier.CONTRACTS}},
                "qualification": {"evidence": []}, "assets": []}
        values = {"application": tar_bytes() if app is None else app,
                  "wheelhouse": zip_bytes() if wheels is None else wheels,
                  "python_lock": b"# fixture lock; syntax is not inspected\n"}
        for role, value in values.items():
            name = role + module.verifier.ROLES[role]
            (self.assets / name).write_bytes(value)
            data["assets"].append({"role": role, "filename": name, "size_bytes": len(value),
                                   "sha256": hashlib.sha256(value).hexdigest()})
        self.manifest.write_text(json.dumps(data))
        return hashlib.sha256(self.manifest.read_bytes()).hexdigest()

    def test_pinned_flat_bundle_is_inert_and_remains_unqualified(self):
        pin = self.bundle()
        before = {path.name: path.read_bytes() for path in self.assets.iterdir()}
        report = module.inspect_application(self.manifest, pin, self.assets)
        self.assertTrue(report["passed"])
        self.assertFalse(report["integration_enabled"])
        self.assertFalse(report["qualification_granted"])
        self.assertFalse(report["target_code_executed"])
        self.assertEqual(report["files_extracted"], 0)
        self.assertTrue(report["archives"]["application"]["source_commit_declaration_matches"])
        self.assertFalse(report["archives"]["wheelhouse"]["wheel_contents_inspected"])
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.assets.iterdir()})

    def test_bad_manifest_pin_and_changed_archive_fail(self):
        pin = self.bundle()
        with self.assertRaises(module.verifier.ManifestError):
            module.inspect_application(self.manifest, "0" * 64, self.assets)
        path = self.assets / "application.tar.gz"
        content = path.read_bytes()
        path.write_bytes(content[:-1] + bytes([content[-1] ^ 1]))
        with self.assertRaises(module.verifier.ManifestError):
            module.inspect_application(self.manifest, pin, self.assets)

    def test_archive_mutation_on_same_inode_after_rehash_is_rejected(self):
        pin = self.bundle()
        path = self.assets / "application.tar.gz"
        inode = path.stat().st_ino
        def changed_during_parse(_stream, _commit, _limits):
            content = path.read_bytes()
            path.write_bytes(content[:-1] + bytes([content[-1] ^ 1]))
            return {"pretend": "parsed"}
        with mock.patch.object(module, "scan_tar", side_effect=changed_during_parse):
            with self.assertRaises(module.ArchiveError):
                module.inspect_application(self.manifest, pin, self.assets)
        self.assertEqual(path.stat().st_ino, inode)

    def test_tar_wrapper_and_foreign_entries_are_rejected(self):
        cases = [tar_bytes(prefix="inky-studio-v0.5.0/"),
                 tar_bytes(extra=[("docs/private.txt", b"x", tarfile.REGTYPE, 0o644)]),
                 tar_bytes(extra=[("client/src/app.ts", b"x", tarfile.REGTYPE, 0o644)]),
                 tar_bytes(extra=[("SOURCE_COMMIT", COMMIT.encode(), tarfile.REGTYPE, 0o644)])]
        for archive in cases:
            with self.subTest(size=len(archive)), self.assertRaises(module.ArchiveError):
                module.scan_tar(io.BytesIO(archive), COMMIT)

    def test_tar_paths_duplicates_and_file_directory_collisions_are_rejected(self):
        for name in ("/server/bad", "../outside", "server/../bad", "server//bad", "server/./bad",
                     "server/evil\\name", "C:/bad", "server/evil\nname", "server/pyproject.toml"):
            with self.subTest(name=name), self.assertRaises(module.ArchiveError):
                module.scan_tar(io.BytesIO(tar_bytes(extra=[(name, b"x", tarfile.REGTYPE, 0o644)])), COMMIT)
        for extra in ([('server/a', b'x', tarfile.REGTYPE, 0o644), ('server/a/b', b'x', tarfile.REGTYPE, 0o644)],
                      [('server/a/b', b'x', tarfile.REGTYPE, 0o644), ('server/a', b'x', tarfile.REGTYPE, 0o644)],
                      [('server/empty/', b'', tarfile.DIRTYPE, 0o755), ('server/empty/', b'', tarfile.DIRTYPE, 0o755)]):
            with self.assertRaises(module.ArchiveError):
                module.scan_tar(io.BytesIO(tar_bytes(extra=extra)), COMMIT)

    def test_tar_links_specials_sparse_and_privileged_modes_are_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE,
                     tarfile.BLKTYPE, tarfile.GNUTYPE_SPARSE, tarfile.GNUTYPE_LONGNAME):
            with self.subTest(kind=kind), self.assertRaises(module.ArchiveError):
                module.scan_tar(io.BytesIO(tar_bytes(extra=[("server/special", b"", kind, 0o644)])), COMMIT)
        for mode in (0o4755, 0o2755):
            with self.assertRaises(module.ArchiveError):
                module.scan_tar(io.BytesIO(tar_bytes(extra=[("scripts/privileged", b"x", tarfile.REGTYPE, mode)])), COMMIT)

    def test_tar_requires_payload_and_matching_source_declaration(self):
        for omitted in module.APPLICATION_REQUIRED_FILES | {"shared/fixture.json", "scripts/fixture.py"}:
            with self.subTest(omitted=omitted), self.assertRaises(module.ArchiveError):
                module.scan_tar(io.BytesIO(tar_bytes(omit={omitted})), COMMIT)
        for declaration in (b"b" * 40, b"main\n", COMMIT.encode() + b"\r\n"):
            with self.assertRaises(module.ArchiveError):
                module.scan_tar(io.BytesIO(tar_bytes(replacements={"server/SOURCE_COMMIT": declaration})), COMMIT)
        self.assertTrue(module.scan_tar(io.BytesIO(tar_bytes(replacements={"server/SOURCE_COMMIT": COMMIT.encode()})), COMMIT)["source_commit_declaration_matches"])

    def test_gzip_crc_truncation_concat_and_tar_trailing_data_are_rejected(self):
        raw = tar_bytes(compressed=False)
        archive = gzip.compress(raw, mtime=0)
        corrupt = bytearray(archive)
        corrupt[-8] ^= 1
        cases = (archive[:-4], bytes(corrupt), archive + archive, archive + b"garbage",
                 gzip.compress(raw + b"garbage", mtime=0), gzip.compress(raw + raw, mtime=0),
                 gzip.compress(raw.rstrip(b"\x00"), mtime=0))
        for candidate in cases:
            with self.subTest(size=len(candidate)), self.assertRaises(module.ArchiveError):
                module.scan_tar(io.BytesIO(candidate), COMMIT)

    def test_pax_is_bounded_before_read_and_safe_long_paths_are_supported(self):
        header = tarfile.TarInfo("PaxHeader")
        header.type = tarfile.XHDTYPE
        header.size = 1024**3
        raw = header.tobuf(format=tarfile.USTAR_FORMAT) + bytes(1024)
        with self.assertRaisesRegex(module.ArchiveError, "Oversized"):
            module.scan_tar(io.BytesIO(gzip.compress(raw, mtime=0)), COMMIT)
        valid = tar_bytes(extra=[("server/" + "a" * 120 + ".py", b"x", tarfile.REGTYPE, 0o644)])
        self.assertTrue(module.scan_tar(io.BytesIO(valid), COMMIT)["required_paths_present"])

    def test_standard_pax_metadata_is_allowed_but_effective_path_stays_strict(self):
        standard = tar_bytes(pax={"mtime": "1700000000.125"})
        self.assertIn(b"././@PaxHeader", gzip.decompress(standard))
        self.assertTrue(module.scan_tar(io.BytesIO(standard), COMMIT)["required_paths_present"])
        for name in ("../outside", "/server/pyproject.toml", "server/../pyproject.toml"):
            with self.subTest(path=name), self.assertRaises(module.ArchiveError):
                module.scan_tar(io.BytesIO(tar_bytes(pax={"path": name})), COMMIT)

    def test_zip_local_central_disagreement_and_overlapping_members_fail(self):
        original = zip_bytes()
        bad_name = bytearray(original)
        bad_name[30] ^= 1
        bad_count = bytearray(original)
        end = bad_count.rfind(b"PK\x05\x06")
        struct.pack_into("<HH", bad_count, end + 8, 3, 3)
        overlap = bytearray(original)
        first = overlap.find(b"PK\x01\x02")
        second = overlap.find(b"PK\x01\x02", first + 4)
        struct.pack_into("<I", overlap, second + 42, 0)
        for archive in (bad_name, bad_count, overlap):
            with self.subTest(size=len(archive)), self.assertRaises(module.ArchiveError):
                module.scan_zip(io.BytesIO(archive))

    def test_archive_limits_are_enforced_without_large_fixtures(self):
        for limits in (module.DEFAULT_LIMITS._replace(members=1),
                       module.DEFAULT_LIMITS._replace(member_bytes=8),
                       module.DEFAULT_LIMITS._replace(total_bytes=64)):
            with self.subTest(limits=limits), self.assertRaises(module.ArchiveError):
                module.scan_tar(io.BytesIO(tar_bytes()), COMMIT, limits)
            with self.subTest(zip_limits=limits), self.assertRaises(module.ArchiveError):
                module.scan_zip(io.BytesIO(zip_bytes()), limits)

    def test_zip_stored_deflate_and_descriptors_are_supported(self):
        for archive in (zip_bytes(), zip_bytes(compression=zipfile.ZIP_STORED), zip_bytes(descriptor=True)):
            with self.subTest(size=len(archive)):
                result = module.scan_zip(io.BytesIO(archive))
                self.assertTrue(result["zip_crc_verified"])
                self.assertEqual(result["wheel_files"], 1)

    def test_zip_layout_paths_duplicates_and_collisions_are_rejected(self):
        for name in ("/bad.whl", "../bad.whl", "licenses/../bad", "licenses//bad", "licenses/./bad",
                     "licenses/evil\\name", "other.txt", "wheels/other.whl", next(iter(ZIP_FILES))):
            with self.subTest(name=name), self.assertRaises(module.ArchiveError):
                module.scan_zip(io.BytesIO(zip_bytes(extra=[(name, b"x", stat.S_IFREG | 0o644)])))
        with self.assertRaises(module.ArchiveError):
            module.scan_zip(io.BytesIO(zip_bytes(extra=[("licenses/a", b"x", stat.S_IFREG | 0o644),
                                                       ("licenses/a/b", b"x", stat.S_IFREG | 0o644)])))
        for omitted in ZIP_FILES:
            with self.subTest(omitted=omitted), self.assertRaises(module.ArchiveError):
                module.scan_zip(io.BytesIO(zip_bytes(omit={omitted})))

    def test_zip_links_specials_and_suid_sgid_are_rejected(self):
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o600, stat.S_IFCHR | 0o600,
                     stat.S_IFBLK | 0o600, stat.S_IFSOCK | 0o600, stat.S_IFREG | 0o4755,
                     stat.S_IFREG | 0o2755):
            with self.subTest(mode=mode), self.assertRaises(module.ArchiveError):
                module.scan_zip(io.BytesIO(zip_bytes(extra=[("licenses/special", b"../../outside", mode)])))

    def test_zip_encryption_trailing_data_prefix_and_crc_corruption_fail(self):
        encrypted = bytearray(zip_bytes())
        central = encrypted.find(b"PK\x01\x02")
        struct.pack_into("<H", encrypted, 6, 1)
        struct.pack_into("<H", encrypted, central + 8, 1)
        corrupt = bytearray(zip_bytes(compression=zipfile.ZIP_STORED))
        name_size, extra_size = struct.unpack_from("<HH", corrupt, 26)
        corrupt[30 + name_size + extra_size] ^= 1
        for archive in (bytes(encrypted), bytes(corrupt), zip_bytes() + b"tail", zip_bytes(prefix=b"MZ"), zip_bytes()[:-1]):
            with self.subTest(size=len(archive)), self.assertRaises(module.ArchiveError):
                module.scan_zip(io.BytesIO(archive))

    def test_zip_payload_cannot_expand_past_declared_prefix_even_if_prefix_crc_matches(self):
        archive = bytearray(zip_bytes())
        central = archive.find(b"PK\x01\x02")
        contents = ZIP_FILES[next(iter(ZIP_FILES))]
        crc = zlib.crc32(contents[:-1]) & 0xffffffff
        struct.pack_into("<I", archive, 14, crc)
        struct.pack_into("<I", archive, 22, len(contents) - 1)
        struct.pack_into("<I", archive, central + 16, crc)
        struct.pack_into("<I", archive, central + 24, len(contents) - 1)
        with self.assertRaisesRegex(module.ArchiveError, "beyond its declared size"):
            module.scan_zip(io.BytesIO(archive))

    def test_cli_refuses_existing_output_and_output_inside_bundle(self):
        pin = self.bundle()
        output = self.root / "report.json"
        args = ["--manifest", str(self.manifest), "--sha256", pin,
                "--assets-dir", str(self.assets), "--output", str(output)]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(module.main(args), 0)
        before = output.read_bytes()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(module.main(args), 1)
            self.assertEqual(module.main(args[:-1] + [str(self.assets / "report.json")]), 1)
        self.assertEqual(output.read_bytes(), before)
        self.assertFalse((self.assets / "report.json").exists())


if __name__ == "__main__":
    unittest.main()
