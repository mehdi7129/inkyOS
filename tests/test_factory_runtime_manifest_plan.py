"""Real contract verification on inert files; no services, ABI or hardware."""
import copy
import json
import os
from pathlib import Path

from test_factory_runtime_contract import ContractFixture, encoded, load_module, runtime


planner = load_module('factory_manifest_planner_test', 'scripts/plan-factory-runtime-manifest.py')


class RuntimeManifestPlanTests(ContractFixture):
    def setUp(self):
        super().setUp()
        self.full_candidate()
        self.expected = copy.deepcopy(self.manifest)
        (self.root / runtime.MANIFEST).unlink()
        self.write('etc/passwd', (
            'root:x:0:0:root:/root:/bin/sh\n'
            'inky:x:1000:1000:Inky:/home/inky:/usr/sbin/nologin\n'
            'inky-network:x:991:992:Network:/nonexistent:/usr/sbin/nologin\n').encode())
        self.write('etc/group', (
            'root:x:0:\ninky:x:1000:\nspi:x:101:inky\ni2c:x:102:inky\n'
            'gpio:x:103:inky\ninky-provisioning:x:992:inky\n').encode())
        self.write('etc/shadow', (
            'root:!:0:0:99999:7:::\ninky:!:0:0:99999:7:::\n'
            'inky-network:!:0:0:99999:7:::\n').encode(), 0o600)
        self.arguments = {'bundle_sha256': self.manifest['bundle_manifest_sha256'],
                          'exporter_sha256': self.manifest['exporter_manifest_sha256'],
                          'support_sha256': self.manifest['support_manifest_sha256'],
                          'helper_uid': 991, 'provisioning_gid': 992,
                          '_owner': (os.geteuid(), os.getegid())}

    def plan(self, **changed):
        return planner.plan(self.root, **{**self.arguments, **changed})

    def refused(self, **changed):
        before = self.snapshot()
        with self.assertRaises((planner.Refused, ValueError)):
            self.plan(**changed)
        self.assertEqual(self.snapshot(), before)

    def test_round_trip_is_consumed_by_real_installed_contract(self):
        before = self.snapshot()
        raw, receipt = self.plan()
        self.assertEqual(json.loads(raw), self.expected)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(receipt['runtime_manifest_installed'])
        self.assertFalse(receipt['boot_state_created'])
        self.write(runtime.MANIFEST, raw)
        actual = runtime.load_contract(_root=self.root, **self.owner)
        self.assertIsNone(runtime.verify_candidate(actual))

    def test_each_reviewed_inventory_pin_is_required(self):
        for key in ('bundle_sha256', 'exporter_sha256', 'support_sha256'):
            with self.subTest(pin=key):
                self.refused(**{key: '0' * 64})
                self.refused(**{key: None})

    def test_wrong_installed_identity_is_refused(self):
        self.refused(helper_uid=993)
        self.refused(provisioning_gid=994)
        self.refused(helper_uid=True)
        self.refused(provisioning_gid=1000)

    def test_mutated_installed_payload_is_refused_without_repin(self):
        self.write(runtime.APP + '/server/.venv/lib/python3.13/site-packages/inky_web/main.py',
                   b'# altered after assembly\n')
        self.refused()

    def test_stale_support_is_refused(self):
        self.write('usr/lib/python3/dist-packages/dbus/__init__.py', b'# changed IPC support\n')
        self.refused()

    def test_missing_mandatory_dist_packages_tree_is_refused(self):
        self.support['trees'].pop('usr/lib/python3/dist-packages')
        self.publish_candidate()
        self.arguments.update(bundle_sha256=self.manifest['bundle_manifest_sha256'],
                              exporter_sha256=self.manifest['exporter_manifest_sha256'],
                              support_sha256=self.manifest['support_manifest_sha256'])
        (self.root / runtime.MANIFEST).unlink()
        self.refused()

    def test_enable_alias_to_closed_unit_is_refused(self):
        self.symlink('etc/systemd/system/multi-user.target.wants/inky-studio.service',
                     '/usr/lib/systemd/system/inky-studio.service')
        self.refused()

    def test_existing_manifest_cannot_be_replaced(self):
        self.write(runtime.MANIFEST, encoded(self.expected))
        self.refused()

    def test_running_boot_cannot_be_planned_as_unbooted(self):
        self.mkdir('run/inkyos-admission', 0o700)
        self.refused()

    def test_preexisting_test_payload_is_refused(self):
        self.write('etc/inkyos-test-lan.json', b'{}\n')
        self.refused()

    def test_unlocked_account_is_refused(self):
        self.write('etc/shadow', b'inky:unlocked:0:0:99999:7:::\n'
                   b'inky-network:!:0:0:99999:7:::\n', 0o600)
        self.refused()

    def test_host_root_and_relative_roots_are_refused(self):
        for path in (Path('/'), Path('.')):
            with self.subTest(path=str(path)), self.assertRaises(planner.Refused):
                planner.plan(path, **self.arguments)

    def test_cli_policy_cannot_plan_an_arbitrary_fixture_root(self):
        arguments = dict(self.arguments)
        arguments.pop('_owner')
        before = self.snapshot()
        with self.assertRaises(planner.Refused):
            planner.plan(self.root, **arguments)
        self.assertEqual(self.snapshot(), before)
