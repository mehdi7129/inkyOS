"""Factory reader mount regression, without a namespace, service or hardware.

The real runtime context verifier and main graph parser inspect synthetic
mountinfo for the same ordinary temporary directory FD. A RO view is represented
in the fixture text; this is not a native ProtectSystem or Pi qualification.
"""
import importlib.util
import io
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch

from test_factory_runtime_contract import ContractFixture, runtime


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'inkyos_offline_boot_graph_tests', ROOT / 'staging/bootstrap/writer-graph.py')
graph = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = graph
spec.loader.exec_module(graph)


class OfflineBootReaderTests(ContractFixture):
    def setUp(self):
        super().setUp()
        self.run_fd = os.open(self.root / 'run', os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.run_fd)
        self.sources = graph.InstalledSources(runtime, self.contract())
        self.sources._lease = SimpleNamespace(run=self.run_fd)

    def graph_mountinfo(self, **kwargs):
        # The observer's mount namespace exposes the same FD-backed mount at
        # /run; the runtime fixture spells it below its explicit non-/ root.
        return self.mountinfo(**kwargs).replace(str(self.root / 'run'), '/run')

    def observe(self, text):
        def fixture_open(path, mode):
            self.assertEqual((path, mode), ('/proc/self/mountinfo', 'rb'))
            return io.BytesIO(text.encode('ascii'))
        with patch.object(graph, 'open', side_effect=fixture_open, create=True):
            return self.sources._run_binding()

    def test_readonly_main_view_agrees_with_real_runtime_context_verifier(self):
        writable = self.contract()
        runtime.prepare_boot_context(writable)
        before = self.snapshot()
        readonly = self.contract(mounts=self.mountinfo(options='ro,nosuid,nodev'))
        self.assertEqual(runtime.validate_context(readonly), runtime.validate_context(writable))
        self.assertIn('ro,nosuid,nodev', self.observe(self.graph_mountinfo(options='ro,nosuid,nodev')))
        self.assertEqual(self.snapshot(), before)

    def test_writable_reader_view_remains_accepted(self):
        self.assertIn('rw,nosuid,nodev', self.observe(self.graph_mountinfo()))

    def test_readonly_view_still_cannot_create_a_boot_context(self):
        readonly = self.contract(mounts=self.mountinfo(options='ro,nosuid,nodev'))
        self.assert_refused(lambda: runtime.prepare_boot_context(readonly), 'invalid_run')

    def test_reader_refuses_missing_or_conflicting_access_modes(self):
        for options in ('nosuid,nodev', 'ro,rw,nosuid,nodev'):
            with self.subTest(options=options), self.assertRaises(graph.Refused) as caught:
                self.observe(self.graph_mountinfo(options=options))
            self.assertEqual(caught.exception.reason, 'run_mount_changed')

    def test_reader_retains_filesystem_root_device_and_unique_mount_guards(self):
        invalid = (
            self.graph_mountinfo(filesystem='ext4'),
            self.graph_mountinfo(mount_root='/subtree'),
            self.graph_mountinfo(device='0:999999'),
            self.graph_mountinfo(mountpoint='/elsewhere'),
            self.graph_mountinfo() * 2,
            'not mountinfo\n',
        )
        for text in invalid:
            with self.subTest(mountinfo=text), self.assertRaises(graph.Refused) as caught:
                self.observe(text)
            self.assertEqual(caught.exception.reason, 'run_mount_changed')

    def test_full_binding_still_detects_changed_access_flags_and_mount_id(self):
        contract, admission = self.ready()
        self.sources.runtime, self.sources.contract = runtime, contract
        self.sources._context = (self.root / runtime.CONTEXT).read_bytes()
        self.sources._boot = runtime.validate_context(contract)
        self.sources._identity = ()
        self.sources._numeric_identity = lambda: ()  # No kernel UID claim.
        self.sources._tokens = (('attempted', admission.ATTEMPTED), ('Ready', admission.READY))
        parent = os.open(self.root / 'run/inkyos-admission', os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, parent)
        self.sources._lease.parent = parent
        # Capture a real finite source baseline for this synthetic tree. The
        # fresh check must exercise the DFS rather than bypassing metadata.
        self.sources._plan = graph.SourceWalkPlan(self.inventory('.'))
        deadline = time.monotonic() + 5
        with contract.tree() as tree:
            self.sources._state_metadata = {path: self.sources._stamp(tree, path) for path in (
                runtime.MANIFEST, runtime.CONTEXT_DIR, runtime.CONTEXT,
                'run/inkyos-admission/attempted', 'run/inkyos-admission/Ready')}
            self.sources._metadata = graph.walk_metadata(
                tree, self.sources._plan, tick=lambda: graph.remaining(deadline))
        text = self.graph_mountinfo(options='ro,nosuid,nodev')
        self.sources._run = self.observe(text)

        def fixture_open(path, mode):
            self.assertEqual(mode, 'rb')
            if path == '/proc/self/mountinfo':
                return io.BytesIO(text.encode('ascii'))
            self.assertEqual(path, '/proc/sys/kernel/random/boot_id')
            return io.BytesIO((self.sources._boot['boot_id'] + '\n').encode('ascii'))

        # Exercise the actual fresh source check, including its comparison to
        # the bound row, rather than merely comparing two parser results.
        with patch.object(graph, 'open', side_effect=fixture_open, create=True):
            self.assertIsNone(self.sources.check(time.monotonic() + 5))
            for changed in (self.graph_mountinfo(), text.replace('71 29 ', '72 29 ', 1)):
                with self.subTest(mountinfo=changed):
                    original, text = text, changed
                    with self.assertRaises(graph.Refused) as caught:
                        self.sources.check(time.monotonic() + 5)
                    self.assertEqual(caught.exception.reason, 'run_mount_changed')
                    text = original

            source = self.root / runtime.MODULE_DIR / 'writer-admission.py'
            source.chmod(0o544)
            with self.assertRaises(graph.Refused) as caught:
                self.sources.check(time.monotonic() + 5)
            self.assertEqual(caught.exception.reason, 'source_changed')

