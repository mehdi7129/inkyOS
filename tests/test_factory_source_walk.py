"""Pinned metadata traversal fixtures; no PID1, admission, backend or hardware.

Linux cases exercise real Tree fds/xattrs and the production walker. Host cases
cover the immutable bounded plan. These tests do not qualify Pi timing budgets.
"""
from contextlib import contextmanager
import dataclasses
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


graph = module('inkyos_factory_source_walk', ROOT / 'staging/bootstrap/writer-graph.py')
runtime = module('inkyos_source_walk_runtime', ROOT / 'scripts/factory-runtime-contract.py')


class SourcePlanTests(unittest.TestCase):
    def records(self):
        return {'.': {'type': 'directory', 'mode': '0755'},
                'a': {'type': 'directory', 'mode': '0755'},
                'a/data': {'type': 'file', 'mode': '0644', 'size_bytes': 3},
                'link': {'type': 'symlink', 'mode': '0777', 'target': 'a/data'}}

    def test_plan_is_an_immutable_snapshot_of_validated_records(self):
        records = self.records()
        plan = graph.SourceWalkPlan(records)
        records['a/data']['mode'] = '0000'
        records.clear()
        self.assertEqual(plan.nodes['a/data'], ('file', 0o644, 3, None))
        self.assertEqual(plan.children['.'], (('a', 'a'), ('link', 'link')))
        with self.assertRaises(TypeError):
            plan.nodes['extra'] = ('file', 0o644, 0, None)
        with self.assertRaises(TypeError):
            plan.children['.'] = ()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            plan.nodes = {}

    def test_twenty_thousand_record_bound_refuses_before_traversal(self):
        records = {'.': {'type': 'directory', 'mode': '0755'}}
        records.update({str(index): {'type': 'file', 'mode': '0644', 'size_bytes': 0}
                        for index in range(graph.MAX_RECORDS - 1)})
        self.assertEqual(len(graph.SourceWalkPlan(records).nodes), 20000)
        records['overflow'] = {'type': 'file', 'mode': '0644', 'size_bytes': 0}
        with self.assertRaisesRegex(graph.Refused, '^source_inventory_limit$'):
            graph.SourceWalkPlan(records)

    def test_missing_or_non_directory_parent_and_unsafe_paths_refuse(self):
        for bad in ('missing/child', '/absolute', '../escape', 'a//child', 'a/./child', 'a/../child'):
            with self.subTest(path=bad), self.assertRaises(graph.Refused):
                graph.SourceWalkPlan({**self.records(), bad: {'type': 'file', 'mode': '0644'}})
        records = self.records()
        records['a/data/child'] = {'type': 'file', 'mode': '0644'}
        with self.assertRaisesRegex(graph.Refused, '^source_parent_not_directory$'):
            graph.SourceWalkPlan(records)
        records = self.records()
        del records['.']
        with self.assertRaisesRegex(graph.Refused, '^source_root_missing$'):
            graph.SourceWalkPlan(records)


@unittest.skipUnless(sys.platform.startswith('linux') and hasattr(os, 'setxattr'),
                     'requires actual Linux fd/xattr metadata semantics')
class SourceWalkLinuxTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='source-walker-fixture.')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        (self.root / 'a').mkdir(mode=0o755)
        (self.root / 'a/data').write_bytes(b'INERT source fixture\n')
        (self.root / 'a/data').chmod(0o644)
        (self.root / 'plain').write_bytes(b'INERT other\n')
        (self.root / 'plain').chmod(0o444)
        (self.root / 'link').symlink_to('a/data')
        self.real_open, self.real_close = os.open, os.close
        self.records = self.inventory()
        self.plan = graph.SourceWalkPlan(self.records)
        self.legacy = graph.InstalledSources(runtime, None)

    def inventory(self):
        records = {}
        for path in (self.root, *sorted(self.root.rglob('*'))):
            info = path.lstat(); name = str(path.relative_to(self.root))
            record = {'mode': format(stat.S_IMODE(info.st_mode), '04o')}
            if stat.S_ISDIR(info.st_mode):
                record['type'] = 'directory'
            elif stat.S_ISLNK(info.st_mode):
                record.update(type='symlink', target=os.readlink(path))
            else:
                raw = path.read_bytes()
                record.update(type='file', size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            records[name] = record
        return records

    def tree(self):
        return runtime.Tree(self.root, os.getuid(), os.getgid())

    @contextmanager
    def track(self, tree):
        active, maximum = set(), [0]
        def opened(*args, **kwargs):
            fd = self.real_open(*args, **kwargs)
            self.assertNotIn(fd, active); active.add(fd)
            maximum[0] = max(maximum[0], len(active))
            return fd
        def closed(fd):
            self.assertNotEqual(fd, tree.fd, 'borrowed root FD must survive')
            self.assertIn(fd, active); active.remove(fd)
            return self.real_close(fd)
        with patch.object(os, 'open', side_effect=opened), patch.object(os, 'close', side_effect=closed):
            try:
                yield maximum
            finally:
                self.assertEqual(active, set(), 'source walker leaked a descriptor')
        os.fstat(tree.fd)

    def test_capture_exactly_matches_old_metadata_then_stamp_for_all_types(self):
        with self.tree() as tree:
            expected = {}
            for path in sorted(self.records):
                self.legacy._record_metadata(tree, path, self.records[path])
                expected[path] = self.legacy._stamp(tree, path)
            with self.track(tree):
                actual = graph.walk_metadata(tree, self.plan, tick=lambda: None)
                self.assertEqual(actual, expected)
                self.assertIsNone(graph.walk_metadata(tree, self.plan, tick=lambda: None, expected=actual))

    def test_changed_file_mode_and_symlink_target_refuse_pinned_capture(self):
        with self.tree() as tree:
            for mutate, restore in (
                (lambda: (self.root / 'a/data').chmod(0o600), lambda: (self.root / 'a/data').chmod(0o644)),
                (lambda: self.replace_link('plain'), lambda: self.replace_link('a/data')),
            ):
                mutate()
                try:
                    with self.track(tree), self.assertRaises(graph.Refused):
                        graph.walk_metadata(tree, self.plan, tick=lambda: None)
                finally:
                    restore()

    def replace_link(self, target):
        (self.root / 'link').unlink()
        (self.root / 'link').symlink_to(target)

    def test_real_file_xattr_refuses_and_closes_its_fd(self):
        path = self.root / 'a/data'
        key = 'user.inkyos.source-walker-fixture'
        os.setxattr(path, key, b'INERT ACL/xattr drift')
        self.assertIn(key, os.listxattr(path))
        with self.tree() as tree, self.track(tree), self.assertRaises(graph.Refused):
            graph.walk_metadata(tree, self.plan, tick=lambda: None)

    def test_parent_rename_during_callback_refuses_fresh_name_binding(self):
        with self.tree() as tree:
            baseline = graph.walk_metadata(tree, self.plan, tick=lambda: None)
            count = 0
            def race():
                nonlocal count
                count += 1
                if count == 3:  # root/a FD is open; before its first child.
                    (self.root / 'a').rename(self.root / 'a-moved')
                    (self.root / 'a').mkdir(mode=0o755)
                    (self.root / 'a/data').write_bytes(b'INERT source fixture\n')
                    (self.root / 'a/data').chmod(0o644)
            with self.track(tree), self.assertRaisesRegex(graph.Refused, '^source_changed$'):
                graph.walk_metadata(tree, self.plan, tick=race, expected=baseline)
            self.assertGreaterEqual(count, 3)

    def test_tick_exception_closes_open_parent_stack(self):
        count = 0
        def tick():
            nonlocal count
            count += 1
            if count == 4:
                raise TimeoutError('inert absolute deadline')
        with self.tree() as tree, self.track(tree), self.assertRaises(TimeoutError):
            graph.walk_metadata(tree, self.plan, tick=tick)

    def test_depth_15_is_bounded_and_16_refuses_before_open(self):
        parent = self.root
        for index in range(15):
            parent /= 'deep' + str(index); parent.mkdir(mode=0o755)
        (parent / 'file').write_bytes(b'INERT depth boundary')
        (parent / 'file').chmod(0o644)
        plan = graph.SourceWalkPlan(self.inventory())
        with self.tree() as tree, self.track(tree) as maximum:
            graph.walk_metadata(tree, plan, tick=lambda: None)
            self.assertLessEqual(maximum[0], 16)  # 15 directory FDs + one leaf.
        (parent / 'too-deep').mkdir(mode=0o755)
        with self.tree() as tree, self.track(tree), self.assertRaisesRegex(graph.Refused, '^source_depth_limit$'):
            graph.SourceWalkPlan(self.inventory())

    def test_capture_and_check_never_read_contents_or_list_directories(self):
        with self.tree() as tree, self.track(tree), \
                patch.object(os, 'read', side_effect=AssertionError('content read')), \
                patch.object(os, 'scandir', side_effect=AssertionError('directory listing')), \
                patch.object(os, 'listdir', side_effect=AssertionError('directory listing')):
            baseline = graph.walk_metadata(tree, self.plan, tick=lambda: None)
            self.assertEqual(set(baseline), set(self.records))
            graph.walk_metadata(tree, self.plan, tick=lambda: None, expected=baseline)

    def test_same_size_content_change_with_restored_mtime_still_refuses(self):
        path = self.root / 'a/data'
        with self.tree() as tree:
            baseline = graph.walk_metadata(tree, self.plan, tick=lambda: None)
            before = path.stat()
            raw = path.read_bytes()
            time.sleep(0.02)  # Cross the Linux coarse timestamp tick before mutation.
            path.write_bytes(b'X' * len(raw))
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            self.assertNotEqual(path.stat().st_ctime_ns, before.st_ctime_ns)
            with self.track(tree), self.assertRaisesRegex(graph.Refused, '^source_changed$'):
                graph.walk_metadata(tree, self.plan, tick=lambda: None, expected=baseline)

    def test_original_absolute_deadline_refuses_and_closes_parent_stack(self):
        count = 0
        def tick():
            nonlocal count
            count += 1
            graph.remaining(time.monotonic() + (1 if count < 4 else -1))
        with self.tree() as tree, self.track(tree), self.assertRaisesRegex(graph.Refused, '^observation_timeout$'):
            graph.walk_metadata(tree, self.plan, tick=tick)
        self.assertEqual(count, 4)

    def test_directory_xattr_added_under_open_parent_refuses(self):
        count = 0
        def tick():
            nonlocal count
            count += 1
            if count == 3:  # root/a is open; mutation precedes its first child.
                os.setxattr(self.root / 'a', 'user.inkyos.walk-parent', b'INERT')
        with self.tree() as tree, self.track(tree), self.assertRaises(graph.Refused):
            graph.walk_metadata(tree, self.plan, tick=tick)

    def test_missing_or_extra_baseline_path_never_qualifies(self):
        with self.tree() as tree:
            baseline = graph.walk_metadata(tree, self.plan, tick=lambda: None)
            missing = dict(baseline)
            del missing['a/data']
            with self.track(tree), self.assertRaisesRegex(graph.Refused, '^source_baseline$'):
                graph.walk_metadata(tree, self.plan, tick=lambda: None, expected=missing)
            wrong = dict(baseline)
            wrong['outside'] = wrong.pop('a/data')
            with self.track(tree), self.assertRaisesRegex(graph.Refused, '^source_changed$'):
                graph.walk_metadata(tree, self.plan, tick=lambda: None, expected=wrong)


if __name__ == '__main__':
    unittest.main()
