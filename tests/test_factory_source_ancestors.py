"""Source ancestry regressions using real POSIX files and descriptor bindings.

macOS explicitly simulates the unavailable Linux fd/xattr API. Linux uses its
real API except the isolated xattr-injection tests. No service, image, runtime
admission, hardware, VM or Pi timing qualification is exercised here.
"""
import dataclasses
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


graph = module('inkyos_source_ancestors_graph', ROOT / 'staging/bootstrap/writer-graph.py')
runtime = module('inkyos_source_ancestors_runtime', ROOT / 'scripts/factory-runtime-contract.py')


class SourceAncestorTests(unittest.TestCase):
    def setUp(self):
        if sys.platform != 'linux':
            seam = patch.object(os, 'listxattr', create=True, return_value=[])
            seam.start()
            self.addCleanup(seam.stop)
        temporary = tempfile.TemporaryDirectory(prefix='source-ancestor-inert.')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / 'root'
        self.root.mkdir(mode=0o755)
        # Outside the pinned root so probing a filesystem tick cannot become
        # the reason a source scan refuses the unrelated target under test.
        self.clock_probe = self.base / 'metadata-clock-probe'
        self.clock_probe.write_bytes(b'INERT filesystem timestamp probe\n')
        for name in ('etc/inky-studio', 'run/systemd', 'var/lib/owned', 'app', 'exporter',
                     'usr/lib/inkyos'):
            (self.root / name).mkdir(mode=0o755, parents=True)
        for name in ('etc/pinned', 'run/systemd/pinned', 'var/lib/owned/source.py',
                     'app/source.py', 'exporter/source.py', 'usr/lib/inkyos/source.py',
                     'etc/inky-studio/pinned'):
            (self.root / name).write_bytes(b'INERT fixed source\n')
            (self.root / name).chmod(0o644)
        (self.root / 'etc/link').symlink_to('pinned')
        self.records = self.inventory()
        self.support = {
            'paths': {path: record for path, record in self.records.items()
                      if path not in {'var/lib/owned', 'var/lib/owned/source.py'}},
            'trees': {'var/lib/owned': {}},
        }
        self.runtime_names = SimpleNamespace(APP='app', EXPORTER='exporter')
        self.plan = graph.SourceWalkPlan.installed(self.runtime_names, self.support, self.records)
        self.real_open, self.real_close = os.open, os.close
        self.real_stat, self.real_fstat = os.stat, os.fstat

    def inventory(self):
        result = {}
        for path in (self.root, *sorted(self.root.rglob('*'))):
            info = path.lstat()
            name = str(path.relative_to(self.root))
            record = {'mode': format(stat.S_IMODE(info.st_mode), '04o')}
            if stat.S_ISDIR(info.st_mode):
                record['type'] = 'directory'
            elif stat.S_ISLNK(info.st_mode):
                record.update(type='symlink', target=os.readlink(path))
            else:
                raw = path.read_bytes()
                record.update(type='file', size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            result[name] = record
        return result

    def tree(self):
        return runtime.Tree(self.root, os.getuid(), os.getgid())

    def capture(self, tree, plan=None):
        return graph.walk_metadata(tree, self.plan if plan is None else plan, tick=lambda: None)

    def check(self, tree, baseline, *, tick=lambda: None):
        return graph.walk_metadata(tree, self.plan, expected=baseline, tick=tick)

    def wait_for_metadata_tick(self, target, baseline_ctime):
        """Prove a later same-filesystem timestamp before one target mutation.

        Linux may stamp several operations in one coarse clock tick. Never
        retry the target mutation or the walker to manufacture a refusal.
        """
        self.assertEqual(self.clock_probe.stat().st_dev, target.stat().st_dev)
        deadline = time.monotonic() + 2.0
        while True:
            os.utime(self.clock_probe, None)
            observed = self.clock_probe.stat().st_ctime_ns
            if observed > baseline_ctime:
                return observed
            if time.monotonic() >= deadline:
                self.fail('fixture metadata clock did not advance past baseline within 2 seconds')
            time.sleep(0.005)

    def test_legacy_strict_plan_reproduces_unowned_child_false_positive(self):
        strict = graph.SourceWalkPlan(self.records)
        with self.tree() as tree:
            baseline = self.capture(tree, strict)
            (self.root / 'var/lib/logrotate-unowned').mkdir()
            with self.assertRaisesRegex(graph.Refused, '^source_changed$'):
                graph.walk_metadata(tree, strict, expected=baseline, tick=lambda: None)

    def test_installed_plan_masks_only_open_ancestors_not_closed_tree_or_app_roots(self):
        self.assertEqual(self.plan.ancestors, {'.', 'etc', 'run', 'run/systemd', 'var', 'var/lib'})
        self.support['paths'].clear()
        self.assertEqual(len(self.plan.ancestors), 6)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.plan.ancestors = frozenset()
        with self.tree() as tree:
            baseline = self.capture(tree)
        for path in self.plan.ancestors:
            self.assertEqual(len(baseline[path][0]), 5)
        for path in ('app', 'exporter', 'var/lib/owned', 'etc/pinned', 'usr/lib/inkyos',
                     'etc/inky-studio'):
            self.assertEqual(len(baseline[path][0]), 9)

    def test_invalid_or_non_directory_ancestor_refuses_before_traversal(self):
        for value in ({'missing'}, {'etc/pinned'}, {'etc/link'}, {'etc', 1}, ['etc'], 'etc'):
            with self.subTest(value=value), self.assertRaisesRegex(graph.Refused, '^source_ancestors$'):
                graph.SourceWalkPlan(self.records, ancestors=value)

    def test_closed_tree_or_owned_bundle_overrides_mutable_ancestor_allowlist(self):
        for closed_kind in ('support', 'app', 'exporter'):
            with self.subTest(closed_kind=closed_kind):
                support = {**self.support, 'trees': dict(self.support['trees'])}
                names = SimpleNamespace(**vars(self.runtime_names))
                if closed_kind == 'support':
                    support['trees']['var'] = {}
                else:
                    setattr(names, 'APP' if closed_kind == 'app' else 'EXPORTER', 'var')
                plan = graph.SourceWalkPlan.installed(names, support, self.records)
                self.assertNotIn('var', plan.ancestors)
                self.assertNotIn('var/lib', plan.ancestors)
                self.assertIn('.', plan.ancestors)

    def test_closed_filesystem_root_never_becomes_open_ancestry(self):
        for closed_kind in ('support', 'app', 'exporter'):
            with self.subTest(closed_kind=closed_kind):
                support = {**self.support, 'trees': dict(self.support['trees'])}
                names = SimpleNamespace(**vars(self.runtime_names))
                if closed_kind == 'support':
                    support['trees']['.'] = {}
                else:
                    setattr(names, 'APP' if closed_kind == 'app' else 'EXPORTER', '.')
                plan = graph.SourceWalkPlan.installed(names, support, self.records)
                self.assertEqual(plan.ancestors, frozenset())

    def test_unowned_child_add_and_remove_under_each_open_ancestor_preserves_baseline(self):
        with self.tree() as tree:
            baseline = self.capture(tree)
            original = dict(baseline)
            for parent in sorted(self.plan.ancestors):
                with self.subTest(parent=parent):
                    path = self.root / parent / 'UNOWNED'
                    path.mkdir(mode=0o700)
                    (path / 'child').write_bytes(b'Unrelated system child')
                    self.assertIsNone(self.check(tree, baseline))
                    (path / 'child').unlink()
                    path.rmdir()
                    self.assertIsNone(self.check(tree, baseline))
            self.assertEqual(baseline, original)

    def test_unowned_ancestor_child_mutation_during_scan_is_allowed(self):
        with self.tree() as tree:
            baseline = self.capture(tree)
            changed = False
            def tick():
                nonlocal changed
                if not changed:
                    changed = True
                    (self.root / 'run/systemd/UNOWNED').mkdir()
            self.assertIsNone(self.check(tree, baseline, tick=tick))
            self.assertTrue(changed)

    def test_every_closed_directory_still_refuses_new_unplanned_child(self):
        with self.tree() as tree:
            baseline = self.capture(tree)
            for parent in ('app', 'exporter', 'var/lib/owned', 'usr/lib/inkyos', 'etc/inky-studio'):
                with self.subTest(parent=parent):
                    path = self.root / parent / 'UNPLANNED'
                    before = path.parent.stat()
                    self.wait_for_metadata_tick(path.parent, before.st_ctime_ns)
                    path.write_bytes(b'not in closed inventory')
                    self.assertNotEqual(path.parent.stat().st_ctime_ns, before.st_ctime_ns)
                    with self.assertRaisesRegex(graph.Refused, '^source_changed$'):
                        self.check(tree, baseline)
                    path.unlink()
                    # Once a later ctime was actually observed, removal does
                    # not restore the original metadata-only baseline.
                    self.assertNotEqual(path.parent.stat().st_ctime_ns, before.st_ctime_ns)
                    with self.assertRaisesRegex(graph.Refused, '^source_changed$'):
                        self.check(tree, baseline)
                    baseline = self.capture(tree)

    def test_owned_file_same_size_bytes_and_restored_mtime_still_refuse(self):
        path = self.root / 'etc/pinned'
        with self.tree() as tree:
            baseline = self.capture(tree)
            before = path.stat()
            self.wait_for_metadata_tick(path, before.st_ctime_ns)
            path.write_bytes(b'X' * before.st_size)
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            self.assertNotEqual(path.stat().st_ctime_ns, before.st_ctime_ns)
            with self.assertRaisesRegex(graph.Refused, '^source_changed$'):
                self.check(tree, baseline)

    def test_metadata_tick_precondition_has_a_bounded_failure_without_clock_progress(self):
        target = self.root / 'etc/pinned'
        before = target.stat()
        self.clock_probe = SimpleNamespace(stat=lambda: SimpleNamespace(
            st_dev=before.st_dev, st_ctime_ns=before.st_ctime_ns))
        clock = SimpleNamespace(monotonic=Mock(side_effect=(10.0, 12.0)), sleep=Mock())
        with patch.object(os, 'utime', return_value=None), patch.object(sys.modules[__name__], 'time', clock):
            with self.assertRaisesRegex(AssertionError, 'metadata clock did not advance'):
                self.wait_for_metadata_tick(target, before.st_ctime_ns)
        clock.sleep.assert_not_called()

    def test_open_ancestor_mode_drift_still_refuses(self):
        with self.tree() as tree:
            baseline = self.capture(tree)
            for parent in sorted(self.plan.ancestors):
                with self.subTest(parent=parent):
                    path = self.root / parent
                    path.chmod(0o700)
                    with self.assertRaisesRegex(graph.Refused, '^source_changed$'):
                        self.check(tree, baseline)
                    path.chmod(0o755)
            self.assertIsNone(self.check(tree, baseline))

    def test_open_ancestor_inode_replacement_refuses(self):
        with self.tree() as tree:
            baseline = self.capture(tree)
            old = self.root / 'etc'
            old.rename(self.root / 'etc-moved')
            old.mkdir(mode=0o755)
            with self.assertRaisesRegex(graph.Refused, '^source_changed$'):
                self.check(tree, baseline)

    def test_open_ancestor_replaced_after_name_stat_refuses_fresh_fd(self):
        with self.tree() as tree:
            baseline = self.capture(tree)
            changed = False
            def opened(path, flags, **kwargs):
                nonlocal changed
                if path == 'etc' and not changed:
                    changed = True
                    (self.root / 'etc').rename(self.root / 'etc-moved')
                    (self.root / 'etc').mkdir(mode=0o755)
                return self.real_open(path, flags, **kwargs)
            with patch.object(os, 'open', side_effect=opened), \
                    self.assertRaisesRegex(graph.Refused, '^source_metadata$'):
                self.check(tree, baseline)
            self.assertTrue(changed)

    def test_open_ancestor_rename_under_open_fd_refuses_final_name_binding(self):
        with self.tree() as tree:
            baseline = self.capture(tree)
            changed = False
            def opened(path, flags, **kwargs):
                nonlocal changed
                fd = self.real_open(path, flags, **kwargs)
                if path == 'pinned' and kwargs.get('dir_fd') is not None and not changed:
                    changed = True
                    (self.root / 'etc').rename(self.root / 'etc-moved')
                    (self.root / 'etc').mkdir(mode=0o755)
                return fd
            with patch.object(os, 'open', side_effect=opened), \
                    self.assertRaisesRegex(graph.Refused, '^source_changed$'):
                self.check(tree, baseline)
            self.assertTrue(changed)

    def test_open_ancestor_symlink_and_fifo_substitutions_refuse_before_open(self):
        for kind in ('symlink', 'fifo'):
            with self.subTest(kind=kind), self.tree() as tree:
                baseline = self.capture(tree)
                path = self.root / 'etc'
                path.rename(self.root / 'etc-moved')
                if kind == 'symlink':
                    path.symlink_to('etc-moved')
                else:
                    os.mkfifo(path, 0o755)
                def opened(leaf, flags, **kwargs):
                    self.assertNotEqual(leaf, 'etc', 'substituted type must be rejected before open')
                    return self.real_open(leaf, flags, **kwargs)
                try:
                    with patch.object(os, 'open', side_effect=opened), \
                            self.assertRaisesRegex(graph.Refused, '^source_metadata$'):
                        self.check(tree, baseline)
                finally:
                    path.unlink()
                    (self.root / 'etc-moved').rename(path)

    def test_open_ancestor_owner_and_group_substitution_refuse(self):
        with self.tree() as tree:
            baseline = self.capture(tree)
            for field in ('st_uid', 'st_gid'):
                def observed(path, **kwargs):
                    info = self.real_stat(path, **kwargs)
                    if path == 'etc' and kwargs.get('dir_fd') is not None:
                        values = {key: getattr(info, key) for key in (
                            'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                            'st_size', 'st_mtime_ns', 'st_ctime_ns')}
                        values[field] += 1
                        return SimpleNamespace(**values)
                    return info
                with self.subTest(field=field), patch.object(os, 'stat', side_effect=observed), \
                        self.assertRaisesRegex(graph.Refused, '^source_metadata$'):
                    self.check(tree, baseline)

    def test_open_ancestor_xattrs_still_refuse(self):
        with self.tree() as tree:
            baseline = self.capture(tree)
            inode = (self.root / 'etc').stat().st_ino
            def xattrs(fd, **kwargs):
                return ['user.INERT-drift'] if type(fd) is int and self.real_fstat(fd).st_ino == inode else []
            with patch.object(os, 'listxattr', side_effect=xattrs), \
                    self.assertRaisesRegex(graph.Refused, '^source_metadata$'):
                self.check(tree, baseline)

    def test_unchanged_walk_retains_same_fd_stat_and_xattr_observation_counts(self):
        # This correction deliberately removes no source observation or scan.
        counts = []
        with self.tree() as tree:
            for plan in (graph.SourceWalkPlan(self.records), self.plan):
                with patch.object(os, 'open', wraps=self.real_open) as opened, \
                        patch.object(os, 'stat', wraps=self.real_stat) as named, \
                        patch.object(os, 'fstat', wraps=self.real_fstat) as descriptors, \
                        patch.object(os, 'listxattr', return_value=[]) as xattrs:
                    baseline = self.capture(tree, plan)
                    graph.walk_metadata(tree, plan, expected=baseline, tick=lambda: None)
                    counts.append((opened.call_count, named.call_count,
                                   descriptors.call_count, xattrs.call_count))
        self.assertEqual(counts[0], counts[1])
        self.assertGreater(counts[0][0], 0)


if __name__ == '__main__':
    unittest.main()
