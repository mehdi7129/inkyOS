"""Closed staging files and inert installed candidates; never starts systemd.

macOS uses ContractFixture's explicit FD xattr seam. These checks do not prove
PID1's effective graph, native identities, /run provisioning or runtime readiness.
"""
import configparser
import os
import unittest
from unittest.mock import patch

from test_factory_runtime_contract import ContractFixture, ROOT, digest, runtime


WRITERS = {'inky-studio.service': 'main', 'inky-network.service': 'helper',
           'inkyos-initialization.service': 'ipc'}


def config(unit):
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    parser.read_string((ROOT / 'staging/bootstrap' / unit).read_text())
    return parser


class TemplatePolicyTests(unittest.TestCase):
    def test_all_five_staging_templates_match_closed_policy(self):
        self.assertEqual(set(runtime.UNIT_TEMPLATES), set(WRITERS) | {
            'inkyos-admission-prepare.service', 'inkyos-factory-supervisor.service'})
        for unit, wanted in runtime.UNIT_TEMPLATES.items():
            with self.subTest(unit=unit):
                self.assertEqual(digest((ROOT / 'staging/bootstrap' / unit).read_bytes()), wanted)

    def test_every_writer_exec_owns_the_existing_launcher_role(self):
        for unit, role in WRITERS.items():
            with self.subTest(unit=unit):
                service = config(unit)['Service']
                self.assertEqual(service['ExecStart'],
                                 '/usr/bin/python3.13 -I -B -S /usr/lib/inkyos/writer-launcher.py ' + role)
                self.assertFalse(any(key.startswith('Exec') and key != 'ExecStart' for key in service))
                self.assertFalse(any(key.startswith('Environment') for key in service))

    def test_identity_groups_are_exact(self):
        for unit, expected in {
            'inky-studio.service': ('inky', 'inky', 'spi i2c gpio inky-provisioning'),
            'inky-network.service': ('inky-network', 'inky-provisioning', None),
            'inkyos-initialization.service': ('root', 'inky-provisioning', 'root'),
        }.items():
            with self.subTest(unit=unit):
                service = config(unit)['Service']
                self.assertEqual((service['User'], service['Group'], service.get('SupplementaryGroups')), expected)

    def test_only_ipc_has_notify_readiness(self):
        for unit in WRITERS:
            service = config(unit)['Service']
            if unit == 'inkyos-initialization.service':
                self.assertEqual(service['Type'], 'notify')
                self.assertEqual(service['NotifyAccess'], 'main')
                self.assertEqual(service['TimeoutStartSec'], '10s')
            else:
                self.assertEqual(service['Type'], 'exec')
                self.assertNotIn('NotifyAccess', service)

    def test_order_uses_no_stop_propagation(self):
        for unit in runtime.UNIT_TEMPLATES:
            with self.subTest(unit=unit):
                stanza = config(unit)['Unit']
                for key in ('Requires', 'Requisite', 'BindsTo', 'PartOf', 'Conflicts',
                            'PropagatesStopTo', 'StopPropagatedFrom'):
                    self.assertNotIn(key, stanza)
        expected = {
            'inky-studio.service': {'inkyos-initialization.service', 'inky-network.service'},
            'inky-network.service': {'inkyos-initialization.service', 'NetworkManager.service'},
            'inkyos-initialization.service': {'inkyos-admission-prepare.service',
                                              'inkyos-factory-supervisor.service'},
        }
        for unit, names in expected.items():
            for key in ('Wants', 'After'):
                self.assertLessEqual(names, set(config(unit)['Unit'][key].split()))

    def test_no_pid1_lifecycle_recreates_locks_or_interrupts_drain(self):
        for unit in runtime.UNIT_TEMPLATES:
            with self.subTest(unit=unit):
                parser = config(unit)
                self.assertNotIn('Install', parser)
                service = parser['Service']
                self.assertEqual(service['Restart'], 'no')
                self.assertEqual(service['KillMode'], 'mixed')
                self.assertEqual(service['TimeoutStopSec'], 'infinity')
                self.assertEqual(service['SendSIGKILL'], 'no')
                for key in service:
                    self.assertFalse(key.startswith(('RuntimeDirectory', 'StateDirectory')))
                self.assertNotIn('ExecStop', service)
                self.assertNotIn('ExecStopPost', service)

    def test_systemd_lookup_and_influence_sets_are_bounded_and_complete(self):
        self.assertEqual(len(runtime.UNIT_LOOKUP_DIRS), 12)
        self.assertEqual(runtime.UNIT_EXTENSION_NAMES, {
            *runtime.UNIT_TEMPLATES, 'service', 'inky-.service', 'inkyos-.service',
            'inkyos-admission-.service', 'inkyos-factory-.service'})
        self.assertEqual(len(runtime.UNIT_ABSENT), 535)


class InstalledUnitPolicyTests(ContractFixture):
    def setUp(self):
        super().setUp()
        # Include these empty paths in the inert support before mutation tests.
        # In particular /usr/local/lib is a closed, inventoried support tree.
        for base in runtime.UNIT_LOOKUP_DIRS:
            self.mkdir(base)
        self.value = self.full_candidate()

    def repin(self, path):
        self.support['paths'][path] = self.record(self.root / path)
        self.publish_candidate()
        return self.contract()

    def test_repinned_arbitrary_template_cannot_define_policy(self):
        for unit in runtime.UNIT_TEMPLATES:
            with self.subTest(unit=unit):
                relative = runtime.UNIT_VENDOR_DIR + '/' + unit
                path = self.root / relative
                original = path.read_bytes()
                self.write(relative, original + b'\n[Service]\nExecStart=/inert-bypass\n')
                contract = self.repin(relative)
                self.assert_refused(lambda: runtime.verify_candidate(contract), 'invalid_candidate')
                self.write(relative, original)
                self.repin(relative)

    def test_repin_cannot_change_identity_restart_or_drain(self):
        cases = {
            b'User=inky\n': b'User=root\n',
            b'SupplementaryGroups=spi i2c gpio inky-provisioning\n': b'SupplementaryGroups=root\n',
            b'Restart=no\n': b'Restart=on-failure\n',
            b'TimeoutStopSec=infinity\n': b'TimeoutStopSec=1s\n',
            b'KillMode=mixed\n': b'KillMode=control-group\n',
            b'SendSIGKILL=no\n': b'SendSIGKILL=yes\n',
            b'Type=exec\n': b'Type=notify\n',
        }
        relative = runtime.UNIT_VENDOR_DIR + '/inky-studio.service'
        original = (self.root / relative).read_bytes()
        for before, after in cases.items():
            with self.subTest(before=before):
                self.assertIn(before, original)
                self.write(relative, original.replace(before, after))
                contract = self.repin(relative)
                self.assert_refused(lambda: runtime.verify_candidate(contract), 'invalid_candidate')
        self.write(relative, original)
        self.write(relative, original + b'\n[Install]\nWantedBy=multi-user.target\n')
        contract = self.repin(relative)
        self.assert_refused(lambda: runtime.verify_candidate(contract), 'invalid_candidate')

    def test_all_influence_paths_reject_files_directories_and_dangling_links(self):
        # One inert candidate, all 535 roots/stems/suffix combinations. Empty
        # directories and dangling links must not turn absence into acceptance.
        for index, relative in enumerate(sorted(runtime.UNIT_ABSENT)):
            with self.subTest(path=relative):
                if index % 3 == 0:
                    path = self.write(relative, b'# INERT_OVERRIDE\n')
                elif index % 3 == 1:
                    path = self.mkdir(relative)
                else:
                    path = self.symlink(relative, '/INERT_DANGLING')
                self.assert_refused(lambda: runtime.verify_candidate(self.value), 'invalid_candidate')
                if path.is_dir() and not path.is_symlink(): path.rmdir()
                else: path.unlink()
        runtime.verify_candidate(self.value)

    def test_support_must_pin_every_unit_and_every_influence_absence(self):
        for relative in sorted(runtime.WRITER_FILES):
            original = self.support['paths'].pop(relative)
            self.publish_candidate()
            self.assert_refused(lambda: runtime.verify_candidate(self.contract()), 'invalid_candidate')
            self.support['paths'][relative] = original
        for relative in ('run/systemd/transient/inky-studio.service',
                         'etc/systemd/system/service.d',
                         'usr/lib/systemd/system/inkyos-.service.upholds'):
            self.support['absent'].remove(relative)
            self.publish_candidate()
            self.assert_refused(lambda: runtime.verify_candidate(self.contract()))
            self.support['absent'].append(relative)

    def test_aliases_and_enable_links_are_rejected_in_all_lookup_roots(self):
        for base in runtime.UNIT_LOOKUP_DIRS:
            for name, target in (
                ('alternate.service', 'inky-network.service'),
                ('indirect.service', 'alternate.service'),
                ('multi-user.target.wants/inky-studio.service', '/usr/lib/systemd/system/inky-studio.service'),
                ('other.target.requires/not-the-unit.service', '../../inkyos-initialization.service'),
                ('other.target.upholds/not-the-unit.service', '/lib/systemd/system/inky-studio.service'),
            ):
                with self.subTest(base=base, name=name):
                    first = None
                    if name == 'indirect.service':
                        first = self.symlink(base + '/alternate.service', 'inky-network.service')
                    path = self.symlink(base + '/' + name, target)
                    try:
                        self.assert_refused(lambda: runtime.verify_candidate(self.value), 'invalid_candidate')
                    finally:
                        path.unlink()
                        if first is not None: first.unlink()
                        parent = path.parent
                        while parent != self.root / base:
                            parent.rmdir()
                            parent = parent.parent

    def test_merged_lib_is_same_vendor_not_a_shadow(self):
        for target in ('usr/lib', '/usr/lib'):
            with self.subTest(target=target):
                path = self.symlink('lib', target)
                runtime.verify_candidate(self.value)
                path.unlink()

    def test_split_lib_or_mutable_alias_is_refused(self):
        for target in ('usr/local/lib', '/INERT_UNCONTROLLED', 'usr/lib/../lib'):
            path = self.symlink('lib', target)
            self.assert_refused(lambda: runtime.verify_candidate(self.value), 'invalid_candidate')
            path.unlink()
        self.mkdir('lib/systemd/system')
        self.assert_refused(lambda: runtime.verify_candidate(self.value), 'invalid_candidate')

    def test_extension_directory_links_cannot_hide_incoming_dependencies(self):
        outside = self.mkdir('var/lib/inert-links')
        self.symlink('var/lib/inert-links/inky-studio.service',
                     '/usr/lib/systemd/system/inky-studio.service')
        for base in runtime.UNIT_LOOKUP_DIRS:
            for suffix in ('d', 'wants', 'requires', 'upholds'):
                with self.subTest(base=base, suffix=suffix):
                    path = self.symlink(base + '/other.target.' + suffix, '/var/lib/inert-links')
                    try:
                        self.assert_refused(lambda: runtime.verify_candidate(self.value), 'invalid_candidate')
                    finally:
                        path.unlink()
        self.assertTrue(outside.is_dir())
        runtime.verify_candidate(self.value)

    def test_lookup_directory_symlink_or_mutable_parent_is_refused(self):
        original = self.root / 'run/systemd/transient'
        original.rmdir()
        link = self.symlink('run/systemd/transient', '/INERT_UNCONTROLLED')
        self.assert_refused(lambda: runtime.verify_candidate(self.value))
        link.unlink()
        self.mkdir('run/systemd/transient')
        parent = self.root / 'etc/systemd'
        parent.chmod(0o777)
        try:
            self.assert_refused(lambda: runtime.verify_candidate(self.value), 'invalid_metadata')
        finally:
            parent.chmod(0o755)

    def test_depth_budget_rejects_before_following_an_unbounded_tree(self):
        self.mkdir('run/systemd/generator/' + '/'.join('level' + str(index) for index in range(9)))
        self.assert_refused(lambda: runtime.verify_candidate(self.value), 'invalid_candidate')

    def test_entry_collection_stops_before_allocating_past_budget(self):
        # Explicit iterator fixture complements the real FD budget test below.
        # It must not advance beyond the first refused entry.
        observations = []
        class Entry:
            def __init__(self, name): self.name = name
        class Iterator:
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def __iter__(self):
                for index in range(100):
                    observations.append(index)
                    yield Entry('entry' + str(index))
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        before = self.snapshot()
        try:
            with patch.object(runtime.os, 'scandir', return_value=Iterator()):
                with self.assertRaises(runtime.Refused) as caught:
                    runtime._unit_entries(fd, 3)
                self.assertEqual(caught.exception.reason, 'invalid_candidate')
        finally:
            os.close(fd)
        self.assertEqual(observations, [0, 1, 2, 3])
        self.assertEqual(before, self.snapshot())

    def test_real_entry_budget_rejects_with_no_filesystem_mutation(self):
        with patch.object(runtime, 'UNIT_SCAN_LIMIT', 3):
            self.assert_refused(lambda: runtime.verify_candidate(self.value), 'invalid_candidate')

    def test_unrelated_vendor_unit_and_dependency_remain_inert_and_accepted(self):
        self.write(runtime.UNIT_VENDOR_DIR + '/unrelated.service', b'# INERT\n')
        self.symlink('etc/systemd/system/unrelated.target.wants/unrelated.service',
                     '/usr/lib/systemd/system/unrelated.service')
        before = self.snapshot()
        runtime.verify_candidate(self.value)
        self.assertEqual(before, self.snapshot())


if __name__ == '__main__':
    unittest.main()
