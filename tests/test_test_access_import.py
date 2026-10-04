"""Private synthetic capsule consumption; no radio/service/SD or user keys."""
import copy
import hashlib
import importlib.util
import io
import json
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("access_import_tests", ROOT / "scripts/test-access-import.py")
imp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(imp)
legacy_spec = importlib.util.spec_from_file_location("import_legacy_tests", ROOT / "scripts/test-enrollment-firstboot.py")
legacy = importlib.util.module_from_spec(legacy_spec)
legacy_spec.loader.exec_module(legacy)


def expected():
    return {"profile_sha256": "1" * 64, "challenge": "2" * 64, "host_public_key_sha256": "3" * 64,
            "application_source_commit": "4" * 40, "application_manifest_sha256": "5" * 64,
            "access_runtime_manifest_sha256": "6" * 64}


def wifi():
    return {"security": "wpa2-personal", "band": "2.4GHz", "ssid_hex": b"IEEE".hex(), "psk": "password"}


class Fixture:
    def __init__(self):
        self.cache, self.calls, self.fail = {}, [], None
        self.capsule_raw, self.sig = imp.canonical({"wifi": wifi()}), b"synthetic-signature"
        self.valid_signature, self.stable = True, True

    def step(self, name):
        self.calls.append(name)
        if self.fail == name:
            raise OSError("PRIVATE_SSID PRIVATE_PSK /private/example")

    def target(self): self.step("target"); return True
    def bind(self): self.step("bind"); return expected()
    def acquire(self): self.step("lock")
    def state(self):
        self.step("read-state")
        if not self.cache:
            return None
        imp.require(set(self.cache) == {imp.STATE, imp.CAPSULE, imp.SIGNATURE, imp.NETWORK}, "review_required")
        return json.loads(self.cache[imp.STATE])
    def capsule(self, *, cached):
        self.step("cached-capsule" if cached else "fat-capsule")
        return (self.cache[imp.CAPSULE], self.cache[imp.SIGNATURE]) if cached else (self.capsule_raw, self.sig)
    def authenticate(self, raw, signature):
        self.step("authenticate")
        imp.require(self.valid_signature and signature == self.sig, "signature_invalid")
        return json.loads(raw)
    def unchanged(self): self.step("unchanged"); return self.stable
    def write_state(self, value):
        self.step("state-" + value["state"])
        self.cache[imp.STATE] = imp.canonical(value)
    def write_cache(self, name, raw):
        self.step("write-" + name)
        imp.require(name not in self.cache)
        self.cache[name] = raw
    def read_cache(self, name): return self.cache[name]
    def close(self): self.step("close")


class FilesystemFixture(Fixture):
    """Native cache methods on a private synthetic filesystem; no live bind."""
    def __init__(self, root):
        super().__init__()
        self.directory = None
        self.state_stamp = None
        self.files = legacy.Files(str(root), owner=os.getuid())
        def rename(directory, source, target):
            if sys.platform.startswith("linux"):
                legacy.rename_noreplace(directory, source, target)
            else:
                # Fixture-only substitute for Linux renameat2 on macOS.
                os.link(source, target, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
                os.unlink(source, dir_fd=directory)
        def write(directory, name, raw, **kwargs):
            return legacy.write_atomic(directory, name, raw, owner=os.getuid(), rename=rename, **kwargs)
        self.lib = {**vars(legacy), "write_atomic": write}
    names = imp.NativeAdapter.names
    state = imp.NativeAdapter.state
    read_cache = imp.NativeAdapter.read_cache
    acquire = imp.NativeAdapter.acquire
    write_state = imp.NativeAdapter.write_state
    write_cache = imp.NativeAdapter.write_cache
    close = imp.NativeAdapter.close
    def capsule(self, *, cached):
        return (self.read_cache(imp.CAPSULE), self.read_cache(imp.SIGNATURE)) if cached else (self.capsule_raw, self.sig)


class ImportTests(unittest.TestCase):
    def test_wpa2_known_vector_and_fixed_non_autoconnect_profile(self):
        raw = imp.network_profile(wifi()).decode("ascii")
        self.assertIn("psk=f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e\n", raw)
        for text in ("autoconnect=false\n", "interface-name=wlan0\n", "band=bg\n", "proto=rsn;\n", "ssid=73;69;69;69;\n"):
            self.assertIn(text, raw)
        self.assertNotIn("password", raw)

    def test_binary_ssid_and_special_passphrase_cannot_inject_keyfile(self):
        value = {**wifi(), "ssid_hex": bytes(range(32)).hex(), "psk": " ;#=\\[] with spaces "}
        raw = imp.network_profile(value).decode("ascii")
        self.assertIn("ssid=" + ";".join(map(str, range(32))) + ";\n", raw)
        self.assertNotIn(value["psk"], raw)
        self.assertEqual(raw.count("[connection]"), 1)
        self.assertEqual(raw.count("psk="), 1)
        hex_psk = "ab" * 32
        self.assertIn("psk=" + hex_psk + "\n", imp.network_profile({**wifi(), "psk": hex_psk}).decode())

    def test_invalid_wifi_refused(self):
        for key, value in (("security", "open"), ("band", "5GHz"), ("ssid_hex", ""),
                           ("ssid_hex", "aa" * 33), ("ssid_hex", "AA"), ("psk", "short"),
                           ("psk", "injected\n[connection]"), ("psk", "a" * 65)):
            with self.subTest(key=key, value=value), self.assertRaises(imp.ImportError):
                imp.network_profile({**wifi(), key: value})

    def test_import_commits_consumption_before_payload_and_ready_last(self):
        fixture = Fixture()
        result = imp.import_access(fixture)
        self.assertTrue(result["passed"])
        self.assertTrue(result["imported"])
        self.assertFalse(result["reused_committed_cache"])
        self.assertFalse(result["live_evidence"])
        self.assertFalse(result["connection_authorized"])
        self.assertLess(fixture.calls.index("authenticate"), fixture.calls.index("state-importing"))
        self.assertLess(fixture.calls.index("state-importing"), fixture.calls.index("write-capsule.json"))
        self.assertLess(fixture.calls.index("write-network.nmconnection"), fixture.calls.index("state-imported"))
        self.assertEqual(json.loads(fixture.cache[imp.STATE])["state"], "imported")
        self.assertNotIn("password", json.dumps(result))

    def test_committed_cache_reused_without_reconsuming_fat(self):
        fixture = Fixture()
        self.assertTrue(imp.import_access(fixture)["passed"])
        snapshot = dict(fixture.cache)
        fixture.calls.clear()
        fixture.capsule_raw = b"malicious replacement on FAT"
        result = imp.import_access(fixture)
        self.assertTrue(result["passed"])
        self.assertTrue(result["reused_committed_cache"])
        self.assertNotIn("fat-capsule", fixture.calls)
        self.assertFalse(any(call.startswith(("write-", "state-")) for call in fixture.calls))
        self.assertEqual(snapshot, fixture.cache)

    def test_failure_at_each_transaction_write_preserves_artifacts_and_never_grants_access(self):
        for failure in ("state-importing", "write-capsule.json", "write-capsule.sig", "write-network.nmconnection", "state-imported"):
            fixture = Fixture(); fixture.fail = failure
            result = imp.import_access(fixture)
            self.assertFalse(result["passed"], failure)
            self.assertFalse(result["connection_authorized"])
            self.assertNotIn("PRIVATE", json.dumps(result))
            saved = dict(fixture.cache)
            fixture.fail = None
            if saved:
                self.assertFalse(imp.import_access(fixture)["passed"], failure)
                self.assertEqual(saved, fixture.cache)

    def test_wrong_signature_or_changed_binding_cannot_begin_consumption(self):
        fixture = Fixture(); fixture.valid_signature = False
        self.assertEqual(imp.import_access(fixture)["error"], "signature_invalid")
        self.assertEqual(fixture.cache, {})

    def test_newly_committed_payload_is_revalidated_before_success(self):
        for name in (imp.CAPSULE, imp.SIGNATURE, imp.NETWORK):
            fixture = Fixture()
            write_state = fixture.write_state
            def corrupt_after_commit(value):
                write_state(value)
                if value["state"] == "imported":
                    fixture.cache[name] += b"changed"
            fixture.write_state = corrupt_after_commit
            result = imp.import_access(fixture)
            self.assertFalse(result["passed"], name)
            self.assertEqual(result["error"], "state_changed")
        fixture = Fixture(); fixture.stable = False
        self.assertEqual(imp.import_access(fixture)["error"], "state_changed")
        self.assertEqual(fixture.cache, {})

    def test_corrupt_cache_or_different_enrollment_refused_and_preserved(self):
        for change in ("network", "profile", "state", "extra"):
            fixture = Fixture(); self.assertTrue(imp.import_access(fixture)["passed"])
            if change == "network": fixture.cache[imp.NETWORK] += b"bad"
            elif change == "extra": fixture.cache[".state.json.tmp"] = b"partial"
            else:
                state = json.loads(fixture.cache[imp.STATE])
                state["profile_sha256" if change == "profile" else "state"] = "0" * 64 if change == "profile" else "importing"
                fixture.cache[imp.STATE] = imp.canonical(state)
            snapshot = dict(fixture.cache)
            self.assertFalse(imp.import_access(fixture)["passed"], change)
            self.assertEqual(snapshot, fixture.cache)

    def test_state_is_closed_and_bound(self):
        state = imp.state_record(expected(), b"x", b"y", b"z", "imported")
        self.assertTrue(imp.valid_state(state, expected()))
        for key, value in (("schema_version", True), ("state", "ready"), ("kind", "other"),
                           ("host_public_key_sha256", "0" * 64), ("capsule_sha256", "bad"), ("extra", "value")):
            self.assertFalse(imp.valid_state({**state, key: value}, expected()))

    def test_static_allowlist_cannot_open_credentials(self):
        for forbidden in ("etc/shadow", "etc/inkyos-test-enrollment/ssh_host_ed25519_key",
                          "etc/inkyos-test-enrollment/profile.json", "var/lib/inkyos-test-access/network.nmconnection"):
            self.assertNotIn(forbidden, imp.STATIC_PATHS)

    def test_no_cli_root_override(self):
        output = io.StringIO()
        with patch.object(imp, "NativeAdapter") as constructor, patch("sys.stdout", output):
            self.assertEqual(imp.main(["--root", "/private/path"]), 1)
        constructor.assert_not_called()
        self.assertNotIn("/private/path", output.getvalue())

    def filesystem(self, root):
        directory = root / imp.CACHE[1:]
        directory.mkdir(parents=True, mode=0o700)
        for path in (root / "var", root / "var/lib"):
            path.chmod(0o755)
        directory.chmod(0o700)
        return directory

    def test_real_private_cache_durable_reopen_and_reuse(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); directory = self.filesystem(root)
            self.assertTrue(imp.import_access(FilesystemFixture(root))["passed"])
            snapshot = {p.name: p.read_bytes() for p in directory.iterdir()}
            self.assertEqual(set(snapshot), {imp.STATE, imp.CAPSULE, imp.SIGNATURE, imp.NETWORK})
            self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in directory.iterdir()))
            result = imp.import_access(FilesystemFixture(root))
            self.assertTrue(result["passed"])
            self.assertTrue(result["reused_committed_cache"])
            self.assertEqual(snapshot, {p.name: p.read_bytes() for p in directory.iterdir()})

    def test_real_partial_temp_symlink_and_wrong_permissions_refused(self):
        for corruption in ("temp", "symlink", "permissions"):
            with self.subTest(corruption=corruption), tempfile.TemporaryDirectory() as name:
                root = Path(name); directory = self.filesystem(root)
                self.assertTrue(imp.import_access(FilesystemFixture(root))["passed"])
                if corruption == "temp":
                    (directory / ".state.json.tmp").write_bytes(b"preserve-partial")
                elif corruption == "symlink":
                    (directory / imp.CAPSULE).rename(directory / "saved-capsule")
                    (directory / imp.CAPSULE).symlink_to("saved-capsule")
                else:
                    (directory / imp.CAPSULE).chmod(0o644)
                self.assertFalse(imp.import_access(FilesystemFixture(root))["passed"])
                if corruption == "temp":
                    self.assertEqual((directory / ".state.json.tmp").read_bytes(), b"preserve-partial")

    def test_real_lock_excludes_second_importer(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); self.filesystem(root)
            first = FilesystemFixture(root)
            try:
                first.acquire()
                self.assertEqual(imp.import_access(FilesystemFixture(root))["error"], "operation_busy")
            finally:
                first.close()


if __name__ == "__main__":
    unittest.main()
