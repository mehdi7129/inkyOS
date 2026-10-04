"""Synthetic rootfs/manager only; no SD, VM, systemd or application execution."""
import copy
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_test_access_policy import policy, profile


ROOT = Path(__file__).resolve().parents[1]


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


runtime = module("test_access_drain_fixture", "scripts/test-access-drain.py")
legacy = module("test_access_drain_legacy_fixture", "scripts/test-enrollment-firstboot.py")
BOOT = "11111111-2222-3333-4444-555555555555"


def put(root, relative, raw, mode=0o644):
    path = root / relative.lstrip("/")
    path.parent.mkdir(parents=True, exist_ok=True)
    for parent in path.parents:
        if parent == root:
            break
        parent.chmod(0o755)
    path.write_bytes(raw)
    path.chmod(mode)
    return path


def rename_fixture(directory, old, new):
    # Fixture only. Production uses pinned Linux RENAME_NOREPLACE.
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

    def read(self, path, **options):
        self.reads.append(path)
        if "ssh_host_ed25519_key" in path or path.startswith(("/home/", "/var/lib/inky-studio", "/var/lib/inky-network")):
            raise AssertionError("Private keys and application data are outside drain scope")
        return super().read(path, **options)


class TreeAdapter(runtime.NativeAdapter):
    def __init__(self, root):
        super().__init__()
        self.root = root
        self.files = FixtureFiles(root)
        self.lib = dict(vars(legacy))
        self.lib["write_atomic"] = lambda *a, **kw: legacy.write_atomic(*a, rename=rename_fixture, **kw)
        self.boot_id = BOOT
        self.calls, self.records = [], []
        self.failure, self.on_wait, self.after_mask, self.on_status = None, None, None, None
        self.waits = self.elapsed = 0
        self.delay = {runtime.APP: 2, runtime.HELPER: 1}
        self.remaining = dict(self.delay)
        self.stopping = set()
        self.masked = set()
        self.safety_override = {}
        self.job_after_exit = 0
        self.fail_write_at = None
        self.closed = False

    def target(self):
        self.calls.append("target")
        return self.failure != "target"

    def write_status(self, value):
        self.records.append(copy.deepcopy(value))
        if self.fail_write_at == value["phase"]:
            raise OSError("PRIVATE_PATH_OR_SECRET")
        result = super().write_status(value)
        if self.on_status:
            self.on_status(value)
        return result

    def invalidate_permit(self):
        self.calls.append("invalidate-permit")
        return super().invalidate_permit()

    def release_operation(self):
        self.calls.append("release-operation")
        return super().release_operation()

    def command(self, argv):
        self.calls.append(tuple(argv))
        if "show" in argv:
            unit = argv[argv.index("show") + 1]
            names = set(argv[-1].removeprefix("--property=").split(","))
            if self.failure == "observe:" + unit:
                return None
            alive = unit not in self.stopping or self.remaining[unit] > 0
            if unit in self.stopping and self.remaining[unit] > 0:
                self.remaining[unit] -= 1
            job = "1" if alive and unit in self.stopping else ""
            if not alive and unit == runtime.APP and self.job_after_exit:
                job = "8"
                self.job_after_exit -= 1
            value = {"ActiveState": ("deactivating" if unit in self.stopping else "active") if alive else "inactive",
                     "SubState": "stop-sigterm" if alive else "dead", "MainPID": "123" if alive else "0",
                     "ControlPID": "0", "Job": job,
                     "LoadState": "masked" if unit in self.masked else "loaded",
                     "UnitFileState": "masked" if unit in self.masked else "disabled",
                     "FragmentPath": runtime.VENDOR[unit], "DropInPaths": " ".join(sorted(runtime.DROPINS[unit])),
                     **runtime.DRAIN_PROPERTIES}
            value.update(self.safety_override.get(unit, {}))
            return 0, ("\n".join(name + "=" + value[name] for name in sorted(names)) + "\n").encode()
        if "stop" in argv:
            unit = argv[-1]
            already_inactive = unit in self.stopping and self.remaining[unit] == 0
            self.stopping.add(unit)
            if not already_inactive:
                self.remaining[unit] = self.delay[unit]
            # A client timeout cannot retract the already enqueued synthetic job.
            return None if self.failure == "stop:" + unit else (0, b"")
        if "mask" in argv:
            unit = argv[-1]
            if self.failure == "mask:" + unit:
                return 1, b""
            self.masked.add(unit)
            if self.after_mask:
                self.after_mask(unit)
            return 0, b""
        if "poweroff" in argv:
            return None if self.failure == "poweroff" else (0, b"")
        raise AssertionError("No fixture command is executable on the host")

    def wait(self):
        self.calls.append("wait")
        self.waits += 1
        self.elapsed += 10  # synthetic time, never sleep on the test host
        if self.on_wait:
            self.on_wait(self)

    def close(self):
        self.calls.append("close")
        self.reads = list(self.files.reads)
        super().close()
        self.closed = True


class DrainTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        static = {
            runtime.LEGACY: ((ROOT / "scripts/test-enrollment-firstboot.py").read_bytes(), 0o555),
            runtime.POLICY: ((ROOT / "scripts/test-access-policy.py").read_bytes(), 0o555),
            runtime.SELF: ((ROOT / "scripts/test-access-drain.py").read_bytes(), 0o555),
            runtime.SERVICE: ((ROOT / "overlay-test-access/inkyos-test-drain.service").read_bytes(), 0o644),
            runtime.ACTIVATION: (b"# INERT FIXTURE; NEVER EXECUTED\n", 0o555),
            **{path: (b"# INERT TEST TEMPLATE\n" + unit.encode() + b"\n", 0o644)
               for unit, path in runtime.TEMPLATES.items()},
        }
        # Vendors are synthetic: only the fixture's known-pin mapping changes.
        # Immutable reader and policy hashes remain their actual production pins.
        fixture_pins = {}
        for path, (pin, mode) in runtime.PINS.items():
            if path not in static:
                raw = ("# INERT REVIEWED VENDOR FIXTURE " + path + "\n").encode()
                static[path] = (raw, mode)
                fixture_pins[path] = (runtime.digest(raw), mode)
        pins = mock.patch.dict(runtime.PINS, fixture_pins)
        pins.start()
        self.addCleanup(pins.stop)
        for path, (raw, mode) in static.items():
            put(self.root, path, raw, mode)
        for unit, path in runtime.RUNTIME_DROPINS.items():
            put(self.root, path, static[runtime.TEMPLATES[unit]][0])
        manifest = {"schema_version": 1, "kind": "test-access-runtime", "application_source_commit": policy.SOURCE,
                    "application_manifest_sha256": policy.MANIFEST_HASH, "parent_image_sha256": policy.PARENT_IMAGE_SHA256,
                    "files": {path[1:]: {"sha256": runtime.digest(raw), "mode": f"{mode:04o}"}
                              for path, (raw, mode) in static.items()}}
        self.manifest_raw = runtime.canonical(manifest)
        self.profile = profile()
        self.profile["access_runtime_manifest_sha256"] = runtime.digest(self.manifest_raw)
        profile_raw = runtime.canonical(self.profile)
        state = {"schema_version": 1, "kind": "test-lan-enrollment-state", "state": "enrolled",
                 "profile_sha256": runtime.digest(profile_raw), "application_activation_authorized": False}
        self.request = {"schema_version": 1, "kind": "test-access-drain-request", "boot_id": BOOT,
                        "profile_sha256": runtime.digest(profile_raw),
                        "access_runtime_manifest_sha256": runtime.digest(self.manifest_raw)}
        for path, raw, mode in (
            (runtime.MANIFEST, self.manifest_raw, 0o644), (runtime.PROFILE, profile_raw, 0o600),
            (runtime.STATE, runtime.canonical(state), 0o600), (runtime.BOOT_ID, (BOOT + "\n").encode(), 0o444),
            (runtime.APPLICATION_MANIFEST, (ROOT / "tests/fixtures/application-manifest-c31b13af.json").read_bytes(), 0o444),
            (runtime.DIRECTORY + "/" + runtime.REQUEST, runtime.canonical(self.request), 0o600),
            (runtime.DIRECTORY + "/" + runtime.PERMIT, b'{"SYNTHETIC":true}\n', 0o600),
        ):
            put(self.root, path, raw, mode)
        for path in (runtime.DIRECTORY, runtime.PROFILE.rsplit("/", 1)[0], runtime.STATE.rsplit("/", 1)[0]):
            (self.root / path[1:]).chmod(0o700)
        self.adapter = TreeAdapter(self.root)
        self.addCleanup(lambda: None if self.adapter.closed else self.adapter.close())

    def run_drain(self):
        return runtime.drain(self.adapter)

    def commands(self, verb):
        return [item for item in self.adapter.calls if type(item) is tuple and verb in item]

    def private_status(self):
        path = self.root / runtime.DIRECTORY[1:] / runtime.STATUS
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        return json.loads(path.read_bytes())

    def test_order_waits_for_spi_then_helper_before_mask_and_poweroff(self):
        code, result = self.run_drain()
        self.assertEqual(code, 0, result)
        self.assertTrue(result["passed"])
        calls = self.adapter.calls
        stop = lambda unit: ("/usr/bin/systemctl", "--no-block", "stop", unit)
        mask = lambda unit: ("/usr/bin/systemctl", "mask", unit)
        self.assertLess(calls.index("invalidate-permit"), calls.index(stop(runtime.APP)))
        self.assertLess(calls.index(stop(runtime.APP)), calls.index(mask(runtime.APP)))
        self.assertLess(calls.index(mask(runtime.APP)), calls.index(stop(runtime.HELPER)))
        self.assertLess(calls.index(stop(runtime.HELPER)), calls.index(mask(runtime.HELPER)))
        self.assertLess(calls.index(mask(runtime.HELPER)), calls.index(self.commands("poweroff")[0]))
        self.assertEqual(self.private_status(), result)
        projected = runtime.status_projection(result)
        self.assertNotIn("boot_id", projected)
        self.assertFalse(projected["hardware_qualified"])
        self.assertFalse(projected["release_qualified"])
        self.assertFalse((self.root / runtime.DIRECTORY[1:] / runtime.PERMIT).exists())
        self.assertFalse(any("ssh_host" in path or "/home/" in path for path in self.adapter.reads))

    def test_driver_stays_busy_beyond_client_timeout_without_escalation(self):
        self.adapter.delay[runtime.APP] = 8
        code, result = self.run_drain()
        self.assertEqual(code, 0, result)
        self.assertGreater(self.adapter.elapsed, 35)
        self.assertEqual(len(self.commands("stop")), 2)
        self.assertFalse(any(any(word in cmd for word in ("kill", "cancel", "--force", "--now"))
                             for cmd in self.adapter.calls if type(cmd) is tuple))

    def test_indefinitely_busy_application_never_stops_helper_or_powers_off(self):
        self.adapter.delay[runtime.APP] = 1000000
        def fixture_break(value):
            if value.waits == 50:
                raise RuntimeError("fixture stops observing an intentionally endless worker")
        self.adapter.on_wait = fixture_break
        code, result = self.run_drain()
        self.assertEqual(code, 1)
        self.assertEqual(self.adapter.elapsed, 500)
        self.assertFalse(result["application_inactive"])
        self.assertEqual(len(self.commands("stop")), 1)
        self.assertEqual(self.commands("mask"), [])
        self.assertEqual(self.commands("poweroff"), [])

    def test_pending_job_with_pid_zero_is_not_inactive_evidence(self):
        self.adapter.delay[runtime.APP] = 0
        self.adapter.job_after_exit = 3
        code, result = self.run_drain()
        self.assertEqual(code, 0, result)
        self.assertGreaterEqual(self.adapter.waits, 3)

    def test_timeout_after_enqueue_never_claims_cancellation_or_powers_off(self):
        self.adapter.failure = "stop:" + runtime.APP
        code, result = self.run_drain()
        self.assertEqual(code, 1)
        self.assertEqual(result["error"], "stop_submission_unconfirmed")
        self.assertIn(runtime.APP, self.adapter.stopping)
        self.assertFalse(result["application_stop_acknowledged"])
        self.assertFalse(result["application_inactive"])
        self.assertEqual(self.commands("poweroff"), [])
        self.assertEqual(self.commands("mask"), [])
        self.assertEqual(self.private_status(), result)

    def test_each_ack_failure_blocks_poweroff(self):
        for failure in ("mask:" + runtime.APP, "stop:" + runtime.HELPER, "mask:" + runtime.HELPER):
            with self.subTest(failure=failure):
                case = DrainTests()
                case.setUp()
                try:
                    case.adapter.failure = failure
                    code, result = case.run_drain()
                    self.assertEqual(code, 1)
                    self.assertFalse(result["poweroff_requested"])
                    self.assertEqual(case.commands("poweroff"), [])
                finally:
                    case.doCleanups()

    def test_unsafe_effective_drain_settings_refuse_before_stop(self):
        for unit in (runtime.APP, runtime.HELPER):
            for key, value in (("Restart", "on-failure"), ("SendSIGKILL", "yes"), ("TimeoutStopUSec", "1min 30s"),
                               ("KillMode", "control-group"), ("KillSignal", "9"), ("FragmentPath", "/other.service"),
                               ("DropInPaths", " ".join(runtime.DROPINS[unit]) + " /extra.conf")):
                with self.subTest(unit=unit, property=key):
                    case = DrainTests()
                    case.setUp()
                    try:
                        case.adapter.safety_override[unit] = {key: value}
                        code, result = case.run_drain()
                        self.assertEqual(code, 1)
                        self.assertEqual(result["error"], "unsafe_unit")
                        self.assertEqual(case.commands("stop"), [])
                        self.assertEqual(case.commands("poweroff"), [])
                    finally:
                        case.doCleanups()

    def test_source_change_during_wait_blocks_helper_and_poweroff(self):
        def mutate(value):
            path = self.root / runtime.RUNTIME_DROPINS[runtime.APP][1:]
            path.write_bytes(b"CHANGED AFTER ADMISSION\n")
        self.adapter.on_wait = mutate
        code, result = self.run_drain()
        self.assertEqual(code, 1)
        self.assertEqual(result["error"], "state_changed")
        self.assertEqual(len(self.commands("stop")), 1)
        self.assertEqual(self.commands("poweroff"), [])

    def test_permit_recreation_before_final_gate_blocks_poweroff(self):
        def mutate(unit):
            if unit == runtime.HELPER:
                (self.root / runtime.DIRECTORY[1:] / runtime.PERMIT).write_bytes(b"unexpected")
        self.adapter.after_mask = mutate
        code, result = self.run_drain()
        self.assertEqual(code, 1)
        self.assertEqual(result["error"], "state_changed")
        self.assertEqual(self.commands("poweroff"), [])

    def test_request_must_match_current_boot_profile_and_manifest(self):
        for field, value in (("boot_id", "ffffffff-2222-3333-4444-555555555555"),
                             ("profile_sha256", "0" * 64), ("access_runtime_manifest_sha256", "1" * 64),
                             ("schema_version", True), ("extra", "SECRET")):
            with self.subTest(field=field):
                case = DrainTests()
                case.setUp()
                try:
                    request = dict(case.request)
                    request[field] = value
                    (case.root / runtime.DIRECTORY[1:] / runtime.REQUEST).write_bytes(runtime.canonical(request))
                    code, result = case.run_drain()
                    self.assertEqual(code, 1)
                    self.assertEqual(result["error"], "request_invalid")
                    self.assertEqual(case.commands("stop"), [])
                    self.assertNotIn("SECRET", json.dumps(result))
                    self.assertEqual(case.private_status(), result)
                finally:
                    case.doCleanups()

    def test_never_started_masked_pair_without_runtime_dropins_can_poweroff(self):
        for unit, path in runtime.RUNTIME_DROPINS.items():
            (self.root / path[1:]).unlink()
            self.adapter.stopping.add(unit)
            self.adapter.remaining[unit] = 0
            self.adapter.masked.add(unit)
            self.adapter.safety_override[unit] = {"Restart": "on-failure", "TimeoutStopUSec": "1min 30s"}
        code, result = self.run_drain()
        self.assertEqual(code, 0, result)
        self.assertEqual(self.adapter.waits, 0)
        self.assertTrue(result["poweroff_requested"])

    def test_absent_runtime_cannot_relax_checks_for_active_or_queued_unit(self):
        for field, value in (("ActiveState", "active"), ("MainPID", "123"), ("ControlPID", "5"), ("Job", "7")):
            with self.subTest(field=field):
                case = DrainTests()
                case.setUp()
                try:
                    for unit, path in runtime.RUNTIME_DROPINS.items():
                        (case.root / path[1:]).unlink()
                        case.adapter.stopping.add(unit)
                        case.adapter.remaining[unit] = 0
                        case.adapter.masked.add(unit)
                    case.adapter.safety_override[runtime.APP] = {field: value}
                    code, result = case.run_drain()
                    self.assertEqual(code, 1)
                    self.assertEqual(result["error"], "unsafe_unit")
                    self.assertEqual(case.commands("stop"), [])
                    self.assertEqual(case.commands("poweroff"), [])
                finally:
                    case.doCleanups()

    def test_partial_runtime_pair_is_refused(self):
        (self.root / runtime.RUNTIME_DROPINS[runtime.HELPER][1:]).unlink()
        code, result = self.run_drain()
        self.assertEqual(code, 1)
        self.assertEqual(result["error"], "unsafe_unit")
        self.assertEqual(self.commands("stop"), [])

    def test_waits_for_activation_without_operation_lock_before_reading_runtime_pair(self):
        directory = self.root / runtime.DIRECTORY[1:]
        lock = os.open(directory / "activation.lock", os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, lock)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        helper = self.root / runtime.RUNTIME_DROPINS[runtime.HELPER][1:]
        original = helper.read_bytes()
        helper.unlink()  # model another worker publishing the runtime pair
        def finish_activation(value):
            if value.waits != 1:
                return
            self.assertEqual(self.commands("stop"), [])
            self.assertEqual(self.private_status()["phase"], "waiting-activation")
            with (directory / "operation.lock").open("r+b") as operation:
                fcntl.flock(operation, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertTrue((directory / runtime.REQUEST).exists())
            helper.write_bytes(original)
            helper.chmod(0o644)
            fcntl.flock(lock, fcntl.LOCK_UN)
        self.adapter.on_wait = finish_activation
        code, result = self.run_drain()
        self.assertEqual(code, 0, result)

    def test_final_source_recheck_occurs_after_status_fsync_before_poweroff(self):
        def change_after_status(value):
            if value["phase"] == "ready-for-poweroff":
                (self.root / runtime.TEMPLATES[runtime.APP][1:]).write_bytes(b"CHANGED AFTER STATUS WRITE")
        self.adapter.on_status = change_after_status
        code, result = self.run_drain()
        self.assertEqual(code, 1)
        self.assertEqual(result["error"], "state_changed")
        self.assertEqual(self.commands("poweroff"), [])

    def test_existing_status_is_preserved_and_no_job_restarted(self):
        path = self.root / runtime.DIRECTORY[1:] / runtime.STATUS
        path.write_bytes(b"PREVIOUS RESULT\n")
        path.chmod(0o600)
        code, result = self.run_drain()
        self.assertEqual(code, 1)
        self.assertEqual(result["error"], "existing_drain")
        self.assertEqual(path.read_bytes(), b"PREVIOUS RESULT\n")
        self.assertEqual(self.commands("stop"), [])

    def test_changed_static_template_does_not_rebind_itself(self):
        (self.root / runtime.TEMPLATES[runtime.APP][1:]).write_bytes(b"CHANGED BEFORE ADMISSION")
        code, result = self.run_drain()
        self.assertEqual(code, 1)
        self.assertEqual(result["error"], "binding_invalid")
        self.assertEqual(self.commands("stop"), [])
        self.assertEqual(self.commands("poweroff"), [])

    def test_invalid_target_is_inert(self):
        self.adapter.failure = "target"
        code, result = self.run_drain()
        self.assertEqual(code, 1)
        self.assertEqual(result["error"], "target_unverified")
        self.assertEqual(self.commands("stop"), [])
        self.assertEqual(self.commands("poweroff"), [])

    def test_symlink_permit_or_request_is_not_followed(self):
        for name in (runtime.REQUEST, runtime.PERMIT):
            with self.subTest(name=name):
                case = DrainTests()
                case.setUp()
                try:
                    path = case.root / runtime.DIRECTORY[1:] / name
                    target = case.root / "private-key-sentinel"
                    target.write_bytes(b"UNREAD PRIVATE SENTINEL")
                    path.unlink()
                    path.symlink_to(target)
                    code, result = case.run_drain()
                    self.assertEqual(code, 1)
                    self.assertTrue(path.is_symlink())
                    self.assertEqual(target.read_bytes(), b"UNREAD PRIVATE SENTINEL")
                    self.assertEqual(case.commands("stop"), [])
                    self.assertNotIn("SENTINEL", json.dumps(result))
                finally:
                    case.doCleanups()

    def test_operation_and_drain_locks_coordinate_without_holding_operation_during_wait(self):
        def probe(value):
            directory = self.root / runtime.DIRECTORY[1:]
            with (directory / "operation.lock").open("r+b") as operation:
                fcntl.flock(operation, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with (directory / "drain.lock").open("r+b") as drain:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(drain, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.adapter.on_wait = probe
        code, result = self.run_drain()
        self.assertEqual(code, 0, result)

    def test_busy_lock_refuses_without_overwriting_request_or_status(self):
        path = self.root / runtime.DIRECTORY[1:] / "drain.lock"
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        code, result = self.run_drain()
        self.assertEqual(code, 1)
        self.assertEqual(result["error"], "operation_busy")
        self.assertFalse((path.parent / runtime.STATUS).exists())

    def test_worker_may_start_before_submitting_runner_releases_operation_lock(self):
        directory = self.root / runtime.DIRECTORY[1:]
        fd = os.open(directory / "operation.lock", os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        def release_runner(value):
            if value.waits != 1:
                return
            self.assertEqual(self.commands("stop"), [])
            self.assertFalse((directory / runtime.STATUS).exists())
            self.assertTrue((directory / runtime.REQUEST).exists())
            with (directory / "drain.lock").open("r+b") as drain:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(drain, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
        self.adapter.on_wait = release_runner
        code, result = self.run_drain()
        self.assertEqual(code, 0, result)

    def test_status_write_failure_prevents_any_later_action(self):
        self.adapter.fail_write_at = "waiting-application"
        code, result = self.run_drain()
        self.assertEqual(code, 1)
        self.assertEqual(len(self.commands("stop")), 1)
        self.assertEqual(self.commands("mask"), [])
        self.assertEqual(self.commands("poweroff"), [])
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_poweroff_ack_then_status_failure_keeps_ack_without_claiming_shutdown(self):
        self.adapter.fail_write_at = "poweroff-requested"
        code, result = self.run_drain()
        self.assertEqual(code, 1)
        self.assertTrue(result["poweroff_requested"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["phase"], "blocked")
        self.assertEqual(self.private_status(), result)
        runtime.status_projection(result)

    def test_projection_rejects_external_fields_prose_and_qualification(self):
        valid = runtime.initial_status(BOOT)
        for field, value in (("hardware_qualified", True), ("release_qualified", True),
                             ("error", "PRIVATE DETAIL"), ("extra", "SECRET"), ("passed", True),
                             ("phase", {}), ("error", []), ("poweroff_requested", True)):
            with self.subTest(field=field):
                invalid = dict(valid)
                invalid[field] = value
                with self.assertRaises(runtime.DrainError):
                    runtime.status_projection(invalid)

    def test_service_is_detached_manual_only_and_does_not_escalate(self):
        raw = (ROOT / "overlay-test-access/inkyos-test-drain.service").read_text()
        for line in ("Type=oneshot", "TimeoutStartSec=infinity", "TimeoutStopSec=infinity",
                     "Restart=no", "SendSIGKILL=no", "RefuseManualStop=yes", "User=root"):
            self.assertIn(line + "\n", raw)
        self.assertNotIn("[Install]", raw)
        self.assertNotIn("ExecStop=", raw)
        self.assertNotIn("--force", raw)
        with mock.patch.object(runtime, "NativeAdapter", side_effect=AssertionError("No live CLI allowed")):
            self.assertEqual(runtime.main(["--root", "/synthetic"]), 64)


class OperatorDrainTests(unittest.TestCase):
    def setUp(self):
        self.seed = DrainTests()
        self.seed.setUp()
        self.addCleanup(self.seed.doCleanups)
        self.root = self.seed.root
        put(self.root, legacy.MODEL_PATH, legacy.PI_MODEL, 0o444)
        self.path = self.root / runtime.DIRECTORY[1:]
        (self.path / runtime.REQUEST).unlink()
        files = FixtureFiles(self.root)
        self.addCleanup(files.close)
        directory = files.directory(runtime.DIRECTORY, private=True)
        self.addCleanup(os.close, directory)
        lock = os.open("operation.lock", os.O_RDWR | os.O_CREAT, 0o600, dir_fd=directory)
        self.addCleanup(os.close, lock)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        snapshots = {}
        for path, mode, private in ((runtime.PROFILE, 0o600, True), (runtime.STATE, 0o600, True),
                                    (runtime.MANIFEST, 0o644, False)):
            snapshots[path] = (files.read(path, mode=mode, private=private, limit=65536), mode, private)
        self.commands, self.answer, self.after_command = [], (0, b""), None
        def command(argv, **kwargs):
            self.commands.append((argv, kwargs))
            if self.after_command:
                self.after_command()
            return self.answer
        lib = dict(vars(legacy))
        lib["write_atomic"] = lambda *a, **kw: legacy.write_atomic(*a, rename=rename_fixture, **kw)
        lib["command"] = command
        self.operator = SimpleNamespace(runtime=lib, files=files, directory=directory, lock=lock,
            snapshot=snapshots, profile=self.seed.profile,
            config={"profile_sha256": runtime.digest(snapshots[runtime.PROFILE][0])},
            unchanged=lambda: all(files.read(path, mode=mode, private=private, limit=65536) == raw
                                 for path, (raw, mode, private) in snapshots.items()))

    def write_request(self, value=None):
        path = self.path / runtime.REQUEST
        path.write_bytes(runtime.canonical(self.seed.request if value is None else value))
        path.chmod(0o600)

    def write_status(self, value=None):
        path = self.path / runtime.STATUS
        path.write_bytes(runtime.canonical(runtime.initial_status(BOOT) if value is None else value))
        path.chmod(0o600)

    def test_enqueue_records_request_before_fixed_asynchronous_start(self):
        def check_record():
            self.assertEqual((self.path / runtime.REQUEST).read_bytes(), runtime.canonical(self.seed.request))
            self.assertEqual(stat.S_IMODE((self.path / runtime.REQUEST).stat().st_mode), 0o600)
            # The API leaves the caller's short lock held.
            fd = os.open(self.path / "operation.lock", os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
        self.after_command = check_record
        code, result = runtime.enqueue(self.operator)
        self.assertEqual(code, 0, result)
        self.assertEqual(result["status"], "QUEUED")
        self.assertTrue(result["request_created"])
        self.assertTrue(result["job_acknowledged"])
        self.assertEqual(self.commands, [(("/usr/bin/systemctl", "--no-block", "start", runtime.SERVICE_NAME),
                                         {"timeout": 3.0, "limit": 4096})])
        self.assertNotIn(BOOT, json.dumps(result))

    def test_duplicate_exact_request_only_observes_and_never_restarts_worker(self):
        self.write_request()
        self.write_status()
        code, result = runtime.enqueue(self.operator)
        self.assertEqual(code, 0, result)
        self.assertEqual(result["status"], "EXISTING")
        self.assertFalse(result["request_created"])
        self.assertFalse(result["job_acknowledged"])
        self.assertEqual(result["drain"]["phase"], "accepted")
        self.assertEqual(self.commands, [])

    def test_different_boot_request_is_preserved_and_never_submitted(self):
        wrong = dict(self.seed.request, boot_id="ffffffff-2222-3333-4444-555555555555")
        self.write_request(wrong)
        code, result = runtime.enqueue(self.operator)
        self.assertEqual(code, 1)
        self.assertEqual(result["error"], "request_invalid")
        self.assertEqual((self.path / runtime.REQUEST).read_bytes(), runtime.canonical(wrong))
        self.assertEqual(self.commands, [])

    def test_submission_timeout_preserves_request_without_cancelling_or_retrying(self):
        self.answer = None
        code, result = runtime.enqueue(self.operator)
        self.assertEqual(code, 1)
        self.assertEqual(result["error"], "worker_submission_unconfirmed")
        self.assertTrue(result["request_created"])
        self.assertFalse(result["job_acknowledged"])
        self.assertEqual(len(self.commands), 1)
        code, result = runtime.enqueue(self.operator)
        self.assertEqual(code, 0, result)
        self.assertEqual(result["status"], "EXISTING")
        self.assertEqual(len(self.commands), 1)

    def test_final_recheck_keeps_job_ack_when_binding_changes_after_submission(self):
        def mutate():
            (self.root / runtime.SERVICE[1:]).write_bytes(b"CHANGED AFTER ACK")
        self.after_command = mutate
        code, result = runtime.enqueue(self.operator)
        self.assertEqual(code, 1)
        self.assertEqual(result["error"], "state_changed")
        self.assertTrue(result["job_acknowledged"])
        self.assertEqual(len(self.commands), 1)

    def test_status_absent_requested_and_observed_are_distinct(self):
        code, result = runtime.status(self.operator)
        self.assertEqual((code, result["status"]), (0, "ABSENT"))
        self.write_request()
        code, result = runtime.status(self.operator)
        self.assertEqual((code, result["status"]), (0, "REQUESTED"))
        self.assertIsNone(result["drain"])
        self.write_status()
        code, result = runtime.status(self.operator)
        self.assertEqual((code, result["status"]), (0, "OBSERVED"))
        self.assertEqual(result["drain"]["phase"], "accepted")
        self.assertNotIn(BOOT, json.dumps(result))
        self.assertEqual(self.commands, [])

    def test_status_reads_while_worker_holds_both_long_locks(self):
        self.write_request()
        self.write_status()
        fds = []
        try:
            for name in ("activation.lock", "drain.lock"):
                fd = os.open(self.path / name, os.O_RDWR | os.O_CREAT, 0o600)
                fds.append(fd)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            code, result = runtime.status(self.operator)
            self.assertEqual(code, 0, result)
            self.assertEqual(result["status"], "OBSERVED")
            self.assertEqual(self.commands, [])
        finally:
            for fd in fds:
                os.close(fd)

    def test_status_cannot_expose_arbitrary_producer_fields_or_another_boot(self):
        self.write_request()
        for change in ({"private": "SENTINEL_SECRET"}, {"boot_id": "ffffffff-2222-3333-4444-555555555555"},
                       {"hardware_qualified": True}):
            with self.subTest(change=change):
                value = runtime.initial_status(BOOT)
                value.update(change)
                self.write_status(value)
                code, result = runtime.status(self.operator)
                self.assertEqual(code, 1)
                self.assertEqual(result["error"], "status_invalid")
                self.assertIsNone(result["drain"])
                self.assertNotIn("SENTINEL", json.dumps(result))

    def test_orphan_status_and_partial_atomic_write_refuse_new_request(self):
        self.write_status()
        code, result = runtime.enqueue(self.operator)
        self.assertEqual(code, 1)
        self.assertEqual(result["error"], "existing_drain")
        self.assertEqual(self.commands, [])
        (self.path / runtime.STATUS).unlink()
        temporary = self.path / ("." + runtime.REQUEST + ".tmp")
        temporary.write_bytes(b"PREEXISTING PARTIAL WRITE")
        temporary.chmod(0o600)
        code, result = runtime.enqueue(self.operator)
        self.assertEqual(code, 1)
        self.assertFalse(result["request_present"])
        self.assertEqual(temporary.read_bytes(), b"PREEXISTING PARTIAL WRITE")
        self.assertEqual(self.commands, [])

    def test_request_symlink_never_reads_target_or_starts_worker(self):
        (self.path / runtime.REQUEST).symlink_to("/etc/ssh/ssh_host_ed25519_key")
        code, result = runtime.enqueue(self.operator)
        self.assertEqual(code, 1)
        self.assertFalse(result["request_present"])
        self.assertEqual(self.commands, [])
        self.assertNotIn("ssh_host", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
