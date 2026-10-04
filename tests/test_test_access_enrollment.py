"""Real temporary rootfs, synthetic keys, and no native device/service commands."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from test_test_access_policy import policy, profile, public_key

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


runtime = module("access_enrollment_tests", ROOT / "scripts/test-access-enrollment.py")
legacy = module("access_enrollment_legacy_tests", ROOT / "scripts/test-enrollment-firstboot.py")


def put(root, path, raw, mode=0o555):
    item = root / path.lstrip("/")
    item.parent.mkdir(parents=True, exist_ok=True)
    parent = item.parent
    while parent != root:
        # Enrollment's private directories are restored explicitly below.
        parent.chmod(0o755)
        parent = parent.parent
    item.write_bytes(raw)
    item.chmod(mode)
    return item


def rename_fixture(directory, old, new):
    # Fixture-only macOS equivalent. Production uses Linux RENAME_NOREPLACE.
    try:
        os.stat(new, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        os.rename(old, new, src_dir_fd=directory, dst_dir_fd=directory)
    else:
        raise legacy.EnrollmentError("existing_artifact")


class FixtureFiles(legacy.Files):
    def __init__(self, root):
        super().__init__(root, owner=os.getuid())
        self.reads = []
        self.device = root.stat().st_dev
    def read(self, path, **options):
        self.reads.append(path)
        if path == runtime.HOST_KEY_PATH:
            raise AssertionError("A private key must never be read")
        if path == f"/proc/{os.getpid()}/mountinfo":
            return (f"23 1 {os.major(self.device)}:{os.minor(self.device)} / /boot/firmware rw - vfat fixture rw\n").encode()
        if path.startswith(f"/proc/{os.getpid()}/fdinfo/"):
            return b"mnt_id:\t23\n"
        return super().read(path, **options)


class TreeAdapter(runtime.NativeAdapter):
    """Native filesystem methods with explicit fixture owner and effect seams."""
    def __init__(self, root):
        self.legacy, self.policy = legacy, policy
        self.files = FixtureFiles(root)
        self.fds, self.state_stamp, self.sources = [], None, {}
        self.deadline = time.monotonic() + 60
        self.states, self.calls = [], []
        self.failure, self.target = None, True
        self.facts = {key: True for key in runtime.GUARDS}
        self.closed = False
    def environment(self):
        self.calls.append("environment")
        return self.target
    def guards(self):
        self.calls.append("guards")
        return self.facts
    def write_state(self, state, profile_hash):
        self.calls.append("state:" + state)
        if self.failure == "state:" + state:
            raise OSError("PRIVATE_PATH PRIVATE_SECRET")
        value = {"schema_version": 1, "kind": "test-lan-enrollment-state", "state": state,
                 "profile_sha256": profile_hash, "application_activation_authorized": False}
        legacy.write_atomic(self.state, "state.json", policy.canonical(value), owner=os.getuid(),
                            rename=rename_fixture, replace_stamp=self.state_stamp,
                            published=lambda stamp: setattr(self, "state_stamp", stamp))
        self.states.append(state)
    def key(self):
        self.calls.append("key")
        if self.failure == "key":
            raise OSError("PRIVATE_KEY")
        for name, raw, mode in (
            ("ssh_host_ed25519_key", b"SYNTHETIC FIXTURE, NOT A PRIVATE KEY", 0o600),
            ("ssh_host_ed25519_key.pub", (public_key(b"h") + " inkyos-test-host\n").encode(), 0o644)):
            legacy.write_atomic(self.private, name, raw, owner=os.getuid(), rename=rename_fixture, mode=mode)
        if self.failure == "after-key":
            raise OSError("PRIVATE_KEY")
        return public_key(b"h")
    def observations(self):
        self.calls.append("observations")
        if self.failure == "observations":
            raise OSError("PRIVATE_OBSERVATION")
        return {"panel": {"PRIVATE_ID": True}, "radio": {"PRIVATE_ID": True}}
    def report(self, value):
        self.calls.append("report")
        if self.failure == "report":
            raise OSError("PRIVATE_REPORT")
        legacy.write_atomic(self.boot, "inkyos-test-enrollment.json", policy.canonical(value),
                            owner=os.getuid(), rename=rename_fixture, fat=True)
    def sync(self):
        raise AssertionError("Fixtures never sync the host")
    def poweroff(self):
        raise AssertionError("Fixtures never power off the host")
    def close(self):
        self.closed = True
        super().close()


class RootfsCase(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.root.chmod(0o755)
        files = {}
        for path in (*runtime.SOURCE_PINS, runtime.SCRIPT_PATH):
            raw = (ROOT / "scripts" / path.rsplit("/", 1)[1]).read_bytes()
            put(self.root, path, raw)
            files[path[1:]] = {"sha256": hashlib.sha256(raw).hexdigest(), "mode": "0555"}
        self.manifest = {"schema_version": 1, "kind": "test-access-runtime", "application_source_commit": policy.SOURCE,
                         "application_manifest_sha256": policy.MANIFEST_HASH,
                         "parent_image_sha256": policy.PARENT_IMAGE_SHA256, "files": files}
        self.profile = profile()
        self.write_manifest()
        put(self.root, runtime.MARKER_PATH, policy.canonical(
            {"source_commit": policy.SOURCE, "manifest_sha256": policy.MANIFEST_HASH}), 0o644)
        for path in ("etc/inkyos-test-enrollment", "var/lib/inkyos-test-enrollment", "var/lib/inkyos-test-access", "boot/firmware"):
            directory = self.root / path
            directory.mkdir(parents=True, exist_ok=True)
            # Every fixture ancestor is nonwritable by group even under umask002.
            parent = directory.parent
            while parent != self.root:
                parent.chmod(0o755)
                parent = parent.parent
            directory.chmod(0o700 if "inkyos-test-" in path else 0o755)
        self.write_profile()
    def write_manifest(self):
        raw = policy.canonical(self.manifest)
        put(self.root, runtime.MANIFEST_PATH, raw, 0o644)
        self.profile["access_runtime_manifest_sha256"] = hashlib.sha256(raw).hexdigest()
    def write_profile(self, raw=None):
        value = put(self.root, runtime.PROFILE_PATH, raw or policy.canonical(self.profile), 0o600)
        value.parent.chmod(0o700)
    def adapter(self):
        adapter = TreeAdapter(self.root)
        self.addCleanup(lambda: None if adapter.closed else adapter.close())
        return adapter
    def state(self):
        return policy.strict_json((self.root / runtime.STATE_PATH[1:]).read_bytes())
    def report(self):
        return policy.strict_json((self.root / runtime.PUBLIC_REPORT_PATH[1:]).read_bytes())


class FlowTests(RootfsCase):
    def test_default_is_inert_with_no_root_reads_or_effects(self):
        adapter = SimpleNamespace()
        with mock.patch.object(runtime.os, "open", side_effect=AssertionError("inert")):
            result = runtime.enroll(adapter)
        self.assertFalse(result["passed"])
        self.assertFalse(result["poweroff_requested"])

    def test_real_filesystem_enrollment_closed_report_and_no_private_key_read(self):
        adapter = self.adapter()
        result = runtime.enroll(adapter, live=True)
        self.assertTrue(result["passed"], result)
        self.assertEqual(adapter.states, ["pending", "enrolled"])
        self.assertTrue(policy.validate_enrolled_state(
            (self.root / runtime.STATE_PATH[1:]).read_bytes(), (self.root / runtime.PROFILE_PATH[1:]).read_bytes()))
        self.assertEqual(stat.S_IMODE((self.root / runtime.STATE_PATH[1:]).stat().st_mode), 0o600)
        report = self.report()
        self.assertEqual(set(report), runtime.REPORT_FIELDS)
        self.assertEqual(report["schema_version"], 2)
        self.assertEqual(report["application_source_commit"], policy.SOURCE)
        self.assertEqual(report["parent_image_sha256"], policy.PARENT_IMAGE_SHA256)
        self.assertEqual(report["access_runtime_manifest_sha256"], self.profile["access_runtime_manifest_sha256"])
        self.assertEqual(report["host_public_key_sha256"], hashlib.sha256(policy.public_key(public_key(b"h"))).hexdigest())
        self.assertFalse(report["live_evidence"])
        self.assertFalse(result["live_evidence"])
        self.assertTrue(all(report[key] is False for key in runtime.FALSE_FIELDS))
        self.assertNotIn(runtime.HOST_KEY_PATH, adapter.files.reads)
        self.assertNotIn("PRIVATE", json.dumps(report))
        self.assertNotIn(public_key(b"h"), json.dumps(result))
        self.assertNotIn(self.profile["challenge"], json.dumps(result))
        self.assertFalse(result["poweroff_requested"])

    def test_second_pass_preserves_identity_state_report_and_rejects_keygen(self):
        self.assertTrue(runtime.enroll(self.adapter(), live=True)["passed"])
        paths = (runtime.STATE_PATH, runtime.PUBLIC_REPORT_PATH, runtime.HOST_KEY_PATH, runtime.HOST_KEY_PATH + ".pub")
        before = {path: (self.root / path[1:]).stat() for path in paths}
        adapter = self.adapter()
        result = runtime.enroll(adapter, live=True)
        self.assertEqual(result["error"], "existing_artifact")
        self.assertNotIn("key", adapter.calls)
        self.assertEqual(adapter.states, [])
        self.assertEqual({path: (self.root / path[1:]).stat() for path in paths}, before)

    def test_preexisting_capsule_case_variants_temporaries_and_access_state_block_before_pending(self):
        entries = ["boot/firmware/INKYACC.JSN", "boot/firmware/inkyacc.sig", "boot/firmware/.INKYACC.JSN.tmp",
                   "boot/firmware/INKYACC.SIG.sig", "var/lib/inkyos-test-access/state.json",
                   "var/lib/inkyos-test-access/.state.json.tmp", "boot/firmware/INKYOS-TEST-ENROLLMENT.JSON"]
        for path in entries:
            with self.subTest(path=path):
                item = self.root / path
                item.write_bytes(b"SYNTHETIC")
                item.chmod(0o600)
                adapter = self.adapter()
                result = runtime.enroll(adapter, live=True)
                self.assertEqual(result["error"], "existing_artifact")
                self.assertNotIn("key", adapter.calls)
                self.assertEqual(adapter.states, [])
                self.assertEqual(item.read_bytes(), b"SYNTHETIC")
                item.unlink()

    def test_preexisting_partial_key_and_state_never_recover_automatically(self):
        for relative in ("etc/inkyos-test-enrollment/ssh_host_ed25519_key", "var/lib/inkyos-test-enrollment/.state.json.tmp"):
            item = self.root / relative
            item.write_bytes(b"SYNTHETIC")
            item.chmod(0o600)
            adapter = self.adapter()
            result = runtime.enroll(adapter, live=True)
            self.assertEqual(result["error"], "existing_artifact")
            self.assertNotIn("key", adapter.calls)
            item.unlink()

    def test_invalid_target_profile_or_guard_has_no_writes(self):
        for failure in ("target", "canonical", "old-profile", *runtime.GUARDS):
            self.write_profile()
            adapter = self.adapter()
            if failure == "target":
                adapter.target = False
            elif failure == "canonical":
                self.write_profile(json.dumps(self.profile).encode())
            elif failure == "old-profile":
                self.write_profile(policy.canonical(dict(self.profile, schema_version=1)))
            else:
                adapter.facts[failure] = 1
            result = runtime.enroll(adapter, live=True)
            self.assertFalse(result["passed"])
            self.assertEqual(adapter.states, [])
            self.assertNotIn("key", adapter.calls)

    def test_key_failure_marks_only_owned_state_review_and_retry_refuses(self):
        adapter = self.adapter()
        adapter.failure = "after-key"
        result = runtime.enroll(adapter, live=True)
        self.assertEqual(result["state"], "review-required")
        self.assertEqual(self.state()["state"], "review-required")
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertTrue((self.root / runtime.HOST_KEY_PATH[1:]).exists())
        retry = self.adapter()
        self.assertFalse(runtime.enroll(retry, live=True)["passed"])
        self.assertNotIn("key", retry.calls)

    def test_report_failure_never_marks_enrolled_or_claims_report_written(self):
        adapter = self.adapter()
        adapter.failure = "report"
        result = runtime.enroll(adapter, live=True)
        self.assertFalse(result["passed"])
        self.assertFalse(result["report_written"])
        self.assertEqual(self.state()["state"], "review-required")
        self.assertFalse((self.root / runtime.PUBLIC_REPORT_PATH[1:]).exists())

    def test_final_state_failure_preserves_report_but_requires_review(self):
        adapter = self.adapter()
        adapter.failure = "state:enrolled"
        result = runtime.enroll(adapter, live=True)
        self.assertFalse(result["passed"])
        self.assertTrue(result["report_written"])
        self.assertEqual(self.state()["state"], "review-required")
        self.assertFalse(policy.validate_enrolled_state(
            (self.root / runtime.STATE_PATH[1:]).read_bytes(), policy.canonical(self.profile)))

    def test_initial_directory_fsync_failure_after_publish_marks_review_without_keygen(self):
        adapter = self.adapter()
        real_fsync = os.fsync
        failed = False
        def fail_once(fd):
            nonlocal failed
            if not failed and fd == getattr(adapter, "state", None):
                failed = True
                raise OSError("PRIVATE_FSYNC_ERROR")
            return real_fsync(fd)
        with mock.patch.object(legacy.os, "fsync", side_effect=fail_once):
            result = runtime.enroll(adapter, live=True)
        self.assertTrue(failed)
        self.assertEqual(result["state"], "review-required")
        self.assertEqual(self.state()["state"], "review-required")
        self.assertNotIn("key", adapter.calls)
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_changed_profile_between_key_and_report_blocks_publication(self):
        adapter = self.adapter()
        original = adapter.observations
        def mutate():
            result = original()
            self.write_profile(policy.canonical(dict(self.profile, challenge="c" * 64)))
            return result
        adapter.observations = mutate
        result = runtime.enroll(adapter, live=True)
        self.assertEqual(result["error"], "state_changed")
        self.assertEqual(self.state()["state"], "review-required")
        self.assertFalse((self.root / runtime.PUBLIC_REPORT_PATH[1:]).exists())


class ManifestTests(RootfsCase):
    def test_exact_manifest_sources_and_legacy_pin(self):
        adapter = self.adapter()
        self.assertTrue(adapter.runtime_manifest(self.profile))
        self.assertEqual(set(adapter.sources), set(runtime.SOURCE_PINS) | {runtime.SCRIPT_PATH})
        self.assertEqual(hashlib.sha256((ROOT / "scripts/test-enrollment-firstboot.py").read_bytes()).hexdigest(), runtime.LEGACY_SHA256)
        self.assertEqual(hashlib.sha256((ROOT / "scripts/test-access-policy.py").read_bytes()).hexdigest(), runtime.POLICY_SHA256)

    def test_complete_static_manifest_does_not_read_unneeded_entries(self):
        for path in runtime.STATIC_PATHS - set(self.manifest["files"]):
            mode = "0440" if path.startswith("etc/sudoers.d/") else "0644"
            self.manifest["files"][path] = {"sha256": "a" * 64, "mode": mode}
        self.write_manifest()
        self.write_profile()
        adapter = self.adapter()
        self.assertTrue(adapter.runtime_manifest(self.profile))
        self.assertEqual(set(adapter.files.reads), {runtime.MANIFEST_PATH, runtime.SCRIPT_PATH, *runtime.SOURCE_PINS})

    def test_manifest_wrong_binding_duplicate_and_noncanonical_fail_before_writes(self):
        original = copy.deepcopy(self.manifest)
        changes = [{"schema_version": True}, {"kind": "factory"}, {"application_source_commit": legacy.SOURCE},
                   {"application_manifest_sha256": legacy.MANIFEST_HASH}, {"parent_image_sha256": legacy.PARENT_IMAGE_SHA256},
                   {"extra": False}]
        for change in changes:
            self.manifest = dict(original, **change)
            self.write_manifest()
            self.write_profile()
            adapter = self.adapter()
            result = runtime.enroll(adapter, live=True)
            self.assertEqual(result["error"], "runtime_manifest_invalid")
            self.assertEqual(adapter.states, [])
        self.manifest = original
        self.write_manifest()
        for raw in (json.dumps(original).encode(), b'{"schema_version":1,"schema_version":1}'):
            put(self.root, runtime.MANIFEST_PATH, raw, 0o644)
            self.profile["access_runtime_manifest_sha256"] = hashlib.sha256(raw).hexdigest()
            self.write_profile()
            self.assertFalse(runtime.enroll(self.adapter(), live=True)["passed"])

    def test_manifest_arbitrary_paths_private_key_and_wrong_mode_are_never_opened(self):
        for path in (runtime.HOST_KEY_PATH[1:], runtime.PROFILE_PATH[1:], runtime.MANIFEST_PATH[1:],
                     "usr/local/lib/inkyos/../private", "/etc/passwd", "var/lib/inkyos/system.json"):
            self.manifest["files"][path] = {"sha256": "a" * 64, "mode": "0600"}
            self.write_manifest()
            self.write_profile()
            adapter = self.adapter()
            result = runtime.enroll(adapter, live=True)
            self.assertEqual(result["error"], "runtime_manifest_invalid")
            self.assertNotIn("/" + path, [name for name in adapter.files.reads
                                         if name not in {runtime.PROFILE_PATH, runtime.MANIFEST_PATH}])
            del self.manifest["files"][path]
        row = self.manifest["files"][runtime.LEGACY_PATH[1:]]
        for mode in (0o555, "0755", "0644", True):
            row["mode"] = mode
            self.write_manifest()
            self.write_profile()
            self.assertFalse(runtime.enroll(self.adapter(), live=True)["passed"])

    def test_tampered_legacy_even_with_rebound_manifest_is_rejected_before_exec(self):
        item = self.root / runtime.LEGACY_PATH[1:]
        raw = item.read_bytes() + b"\nraise RuntimeError('EXECUTION MUST NOT OCCUR')\n"
        item.chmod(0o755)
        item.write_bytes(raw)
        item.chmod(0o555)
        self.manifest["files"][runtime.LEGACY_PATH[1:]]["sha256"] = hashlib.sha256(raw).hexdigest()
        self.write_manifest()
        self.write_profile()
        adapter = self.adapter()
        result = runtime.enroll(adapter, live=True)
        self.assertEqual(result["error"], "source_pin_invalid")
        self.assertNotIn("guards", adapter.calls)
        self.assertEqual(adapter.states, [])

    def test_old_crossed_or_changed_marker_cannot_use_shared_multi_pair_guard(self):
        adapter = self.adapter()
        adapter.runtime_manifest(self.profile)
        marker = {"source_commit": policy.SOURCE, "manifest_sha256": policy.MANIFEST_HASH}
        for change in ({"source_commit": legacy.SOURCE}, {"manifest_sha256": legacy.MANIFEST_HASH}):
            put(self.root, runtime.MARKER_PATH, policy.canonical(dict(marker, **change)), 0o644)
            with mock.patch.object(runtime, "_module", side_effect=AssertionError("No code execution")):
                self.assertTrue(all(value is False for value in runtime.NativeAdapter.guards(adapter).values()))
        put(self.root, runtime.MARKER_PATH, policy.canonical(marker), 0o644)
        seen = {}
        class PreparedGuard:
            def __init__(_self, *, helpers, command):
                seen["helpers"] = helpers
            def collect(_self):
                put(self.root, runtime.MARKER_PATH, policy.canonical(dict(marker, source_commit=legacy.SOURCE)), 0o644)
                return {name: True for name in runtime.GUARDS}
        helper = SimpleNamespace(reviewed=True)
        with mock.patch.object(runtime, "_module", side_effect=[helper, SimpleNamespace(PreparedGuard=PreparedGuard)]):
            self.assertTrue(all(value is False for value in runtime.NativeAdapter.guards(adapter).values()))
        self.assertEqual(seen["helpers"], helper.__dict__)


class BootstrapTests(RootfsCase):
    def test_secure_real_reader_then_fixed_public_loader(self):
        raw = runtime._bootstrap_source(runtime.LEGACY_PATH, root=self.root, owner=os.getuid())
        self.assertEqual(hashlib.sha256(raw).hexdigest(), runtime.LEGACY_SHA256)
        with mock.patch.object(runtime, "_bootstrap_source", return_value=raw) as reader:
            loaded = runtime.load_legacy()
        reader.assert_called_once_with(runtime.LEGACY_PATH)
        self.assertEqual(loaded.SOURCE, legacy.SOURCE)
        self.assertTrue(callable(loaded.Files))
        self.assertTrue(callable(loaded.write_atomic))

    def test_wrong_hash_is_rejected_before_compilation(self):
        with mock.patch.object(runtime, "_bootstrap_source", return_value=b"PRIVATE_UNTRUSTED"), \
                mock.patch("builtins.compile", side_effect=AssertionError("No compile")):
            with self.assertRaisesRegex(runtime.EnrollmentError, "^source_pin_invalid$"):
                runtime.load_legacy()

    def test_root_owner_file_modes_writable_ancestors_and_symlink_parent_are_rejected(self):
        item = self.root / runtime.LEGACY_PATH[1:]
        for mode in (0o444, 0o755, 0o777, 0o6555):
            item.chmod(mode)
            with self.assertRaises(runtime.EnrollmentError):
                runtime._bootstrap_source(runtime.LEGACY_PATH, root=self.root, owner=os.getuid())
        item.chmod(0o555)
        with self.assertRaises(runtime.EnrollmentError):
            runtime._bootstrap_source(runtime.LEGACY_PATH, root=self.root, owner=os.getuid() + 1)
        item.parent.chmod(0o775)
        with self.assertRaises(runtime.EnrollmentError):
            runtime._bootstrap_source(runtime.LEGACY_PATH, root=self.root, owner=os.getuid())
        item.parent.chmod(0o755)
        renamed = item.parent.with_name("safe-directory")
        item.parent.rename(renamed)
        item.parent.symlink_to(renamed)
        with self.assertRaises(OSError):
            runtime._bootstrap_source(runtime.LEGACY_PATH, root=self.root, owner=os.getuid())


class LegacyPrimitivesTests(RootfsCase):
    def test_unchanged_key_primitive_only_stats_private_key_and_reads_public_key(self):
        adapter = self.adapter()
        adapter.runtime_manifest(self.profile)
        adapter.fresh()
        commands, opened = [], []
        original_open = os.open
        original_metadata = legacy._metadata
        def fixture_metadata(info, _owner=0, **options):
            # Explicit fixture ownership seam; all mode/link/type checks remain.
            return original_metadata(info, os.getuid(), **options)
        def tracked_open(path, flags, *args, **kwargs):
            opened.append(os.fspath(path))
            if os.fspath(path).endswith("ssh_host_ed25519_key"):
                raise AssertionError("Private key opened by runtime")
            return original_open(path, flags, *args, **kwargs)
        def keygen(argv, timeout, limit):
            commands.append(argv)
            # This stub creates synthetic bytes. It is not ssh-keygen.
            private = self.root / runtime.HOST_KEY_PATH[1:]
            private.write_bytes(b"SYNTHETIC NOT A KEY")
            private.chmod(0o600)
            public = private.with_name(private.name + ".pub")
            public.write_bytes((public_key(b"h") + " inkyos-test-host\n").encode())
            public.chmod(0o644)
            return (0, b"")
        adapter.run = keygen
        with mock.patch.object(legacy, "_metadata", side_effect=fixture_metadata), \
                mock.patch.object(runtime.os, "open", side_effect=tracked_open):
            result = runtime.NativeAdapter.key(adapter)
        self.assertEqual(result, public_key(b"h"))
        self.assertEqual(commands, [legacy.KEYGEN])
        self.assertNotIn(runtime.HOST_KEY_PATH, adapter.files.reads)
        self.assertIn(runtime.HOST_KEY_PATH + ".pub", adapter.files.reads)
        self.assertTrue(any(path.endswith("ssh_host_ed25519_key.pub") for path in opened))

    def test_native_shutdown_acknowledgement_does_not_claim_physical_shutdown(self):
        fixture = self.adapter()
        native = runtime.NativeAdapter.__new__(runtime.NativeAdapter)
        native.__dict__ = fixture.__dict__
        for name in ("environment", "guards", "write_state", "key", "observations", "report", "close"):
            setattr(native, name, getattr(fixture, name))
        # Only native instances enter the shutdown branch; all commands remain
        # fixture callbacks, and observers return the same closed blocked data.
        native.observations = lambda: {kind: {"status": "blocked", "live_evidence": False, "data": None}
                                       for kind in ("panel", "radio")}
        calls = []
        native.sync = lambda: calls.append("sync")
        native.poweroff = lambda: calls.append("poweroff") or True
        result = runtime.enroll(native, live=True)
        self.assertTrue(result["passed"], result)
        self.assertTrue(result["poweroff_requested"])
        self.assertEqual(calls, ["sync", "poweroff"])
        self.assertNotIn("poweroff_completed", result)
        self.assertFalse(result["hardware_qualified"])


class BootstrapMutationTests(RootfsCase):
    def test_file_symlink_hardlink_fifo_and_oversized_source_are_rejected(self):
        item = self.root / runtime.LEGACY_PATH[1:]
        original = item.read_bytes()
        other = self.root / "source"
        other.write_bytes(original)
        other.chmod(0o555)
        for kind in ("symlink", "hardlink", "fifo", "oversized"):
            item.unlink()
            if kind == "symlink":
                item.symlink_to(other)
            elif kind == "hardlink":
                os.link(other, item)
            elif kind == "fifo":
                os.mkfifo(item, 0o555)
            else:
                item.write_bytes(b"x" * 65537)
                item.chmod(0o555)
            with self.assertRaises((OSError, runtime.EnrollmentError)):
                runtime._bootstrap_source(runtime.LEGACY_PATH, root=self.root, owner=os.getuid())

    def test_mutating_source_is_rejected(self):
        item = self.root / runtime.LEGACY_PATH[1:]
        original = os.read
        def mutate(fd, limit):
            raw = original(fd, limit)
            item.chmod(0o755)
            with item.open("ab") as stream:
                stream.write(b"\n")
            item.chmod(0o555)
            return raw
        with mock.patch.object(runtime.os, "read", side_effect=mutate):
            with self.assertRaises(runtime.EnrollmentError):
                runtime._bootstrap_source(runtime.LEGACY_PATH, root=self.root, owner=os.getuid())


class CliTests(unittest.TestCase):
    def test_default_and_disallowed_arguments_are_inert_and_private_safe(self):
        path = ROOT / "scripts/test-access-enrollment.py"
        for args, code in (([], 1), (["--profile", "PRIVATE_PATH"], 2), (["--key", "PRIVATE_KEY"], 2)):
            result = subprocess.run([sys.executable, "-I", str(path), *args], capture_output=True, text=True, timeout=3)
            self.assertEqual(result.returncode, code)
            self.assertEqual(result.stderr, "")
            self.assertNotIn("PRIVATE", result.stdout)
            self.assertFalse(json.loads(result.stdout)["passed"])


if __name__ == "__main__":
    unittest.main()
