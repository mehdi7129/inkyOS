"""Inactive app integration fixtures: no app execution, chroot, mount or network."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


configure = module('configure_app_fixture', 'configure-application-rootfs.py')
verify = module('verify_app_fixture', 'verify-application-rootfs.py')
PRODUCTION_SOURCE_HASHES = copy.deepcopy(configure.SOURCE_HASHES)


class ApplicationRootfsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / 'root'
        self.root.mkdir()
        self.manifest = self.base / 'manifest.json'
        self.manifest.write_bytes((ROOT / 'tests/fixtures/application-manifest-758a2bf7.json').read_bytes())
        source = json.loads(self.manifest.read_bytes())['source_commit']
        self.digest = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        self.write('etc/inkyos-release.json', json.dumps({'schema_version': 1, 'kind': 'system-prototype',
                   'application': None, 'status': 'not-hardware-qualified',
                   'recipe_inputs': {'files': {'application-manifest.json': self.digest}}}))
        self.write('etc/machine-id', 'uninitialized\n')
        self.write('etc/passwd', 'root:x:0:0:root:/root:/bin/bash\ninky:x:1000:1000::/home/inky:/usr/sbin/nologin\n'
                   'inky-network:x:995:994::/nonexistent:/usr/sbin/nologin\n')
        self.write('etc/shadow', 'root:*:0:0:99999:7:::\ninky:!:20000:0:99999:7:::\ninky-network:!:0:0:99999:7:::\n', 0o600)
        self.write('etc/group', 'root:x:0:\ninky:x:1000:\nspi:x:997:inky\ni2c:x:998:inky\ngpio:x:996:inky\ninky-provisioning:x:994:inky\n')
        self.write('etc/passwd-', 'old-account-metadata\n')
        self.write('var/lib/NetworkManager/NetworkManager.state', '[main]\nWirelessEnabled=true\n', 0o600)
        # Minimal public templates, deliberately not copies of sibling-repo files.
        # The patched hashes apply only to tests; production pins remain immutable.
        self.sources = {
            'install.sh': ('REPO_SLUG="${INKY_STUDIO_REPO_SLUG:-example/inky-studio}"\n'
                           'sudo tee "/etc/systemd/system/${SERVICE_NAME}" >/dev/null <<EOF\n'
                           '[Unit]\nDescription=Inky Studio\nAfter=network.target\n\n[Service]\nType=simple\nUser=${RUN_USER}\n'
                           'WorkingDirectory=${INSTALL_DIR}/server\nEnvironment="INKY_STUDIO_DATA_DIR=${DATA_DIR}"\n'
                           'Environment="INKY_STUDIO_REPO_SLUG=${REPO_SLUG}"\n'
                           'ExecStart=${INSTALL_DIR}/server/.venv/bin/inky-studio-server\n\n[Install]\nWantedBy=multi-user.target\nEOF\n'
                           'cat > "${SUDOERS_TMP}" <<EOF\n'
                           '${RUN_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl --no-block restart ${SERVICE_NAME}, '
                           '/usr/bin/systemctl restart ${SERVICE_NAME}, /usr/bin/systemctl stop ${SERVICE_NAME}, '
                           '/usr/bin/systemctl start ${SERVICE_NAME}\nEOF\n'),
            'scripts/install-bluetooth.sh': ("cat > /etc/systemd/system/inky-network.service <<'UNIT'\n"
                           '[Unit]\nAfter=NetworkManager.service\nRequires=NetworkManager.service\n[Service]\n'
                           'User=inky-network\nGroup=inky-provisioning\n'
                           'ExecStart=/usr/bin/python3 -I /usr/local/lib/inky-studio/network-helper.py\n'
                           'CapabilityBoundingSet=\nNoNewPrivileges=yes\n[Install]\nWantedBy=multi-user.target\nUNIT\n'
                           "cat > /etc/polkit-1/rules.d/49-inky-network.rules <<'POLKIT'\n"
                           'polkit.addRule(function(action, subject) {\n'
                           'if (subject.user !== "inky-network") return polkit.Result.NOT_HANDLED;\n'
                           'var permitted = ["org.freedesktop.NetworkManager.wifi.scan",\n'
                           '"org.freedesktop.NetworkManager.network-control",\n'
                           '"org.freedesktop.NetworkManager.settings.modify.system",\n'
                           '"org.freedesktop.NetworkManager.checkpoint-rollback"];\n'
                           'if (permitted.indexOf(action.id) !== -1) return polkit.Result.YES;\n'
                           'return polkit.Result.NOT_HANDLED;\n});\nPOLKIT\n'
                           "cat > /etc/systemd/system/inky-studio.service.d/bluetooth.conf <<'UNIT'\n"
                           '[Unit]\nWants=bluetooth.service inky-network.service\nAfter=bluetooth.service inky-network.service\n'
                           '[Service]\nSupplementaryGroups=inky-provisioning\nEnvironment=INKY_STUDIO_BLUETOOTH=1\nUNIT\n'),
            'scripts/inky-studio-launcher': ("  cat <<'HEADER'\n#!/usr/bin/env bash\nset -euo pipefail\nHEADER\n"
                           "  cat <<'BODY'\n" + 'exec /bin/bash -- "${INKY_DEFAULT_INSTALL_DIR}/scripts/inky-studio-cli" "$@"\nBODY\n'),
            'scripts/inky-network-helper.py': '# fixture helper, never executed\nraise AssertionError("NO_EXECUTION")\n',
        }
        for path, content in self.sources.items():
            self.write(configure.APP + '/' + path, content)
        candidate_install = self.sources['install.sh'].replace(
            'ExecStart=${INSTALL_DIR}', 'Environment="INKY_STUDIO_DISPLAY_MODE=hardware"\nExecStart=${INSTALL_DIR}').replace(
            '\n\n[Install]', '\nKillSignal=SIGTERM\nKillMode=mixed\nTimeoutStopSec=infinity\nSendSIGKILL=no\n\n[Install]')
        self.candidate_sources = dict(self.sources, **{'install.sh': candidate_install})
        hashes = {pair: {path: hashlib.sha256(content.encode()).hexdigest() for path, content in
                  (self.candidate_sources if pair[0] == configure.SOURCE_COMMIT else self.sources).items()}
                  for pair in configure.SOURCE_HASHES}
        self.patches = [patch.dict(configure.SOURCE_HASHES, hashes), patch.dict(verify.configuration.SOURCE_HASHES, hashes)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        self.write(configure.APP + '/server/SOURCE_COMMIT', source + '\n')
        self.write(configure.APP + '/server/pyproject.toml', '[project]\nname="inky-studio-server"\nversion="0.5.0rc2"\n'
                   '[project.scripts]\ninky-studio-server="inky_web.main:run"\n')
        venv = configure.APP + '/server/.venv'
        self.write(venv + '/pyvenv.cfg', 'home = /usr/bin\ninclude-system-site-packages = false\nversion = 3.13.5\n')
        self.write(venv + '/bin/inky-studio-server', '#!/' + venv + '/bin/python\nfrom inky_web.main import run\n', 0o755)
        metadata = venv + '/lib/python3.13/site-packages/inky_studio_server-0.5.0rc2.dist-info'
        self.write(metadata + '/METADATA', 'Metadata-Version: 2.3\nName: inky-studio-server\nVersion: 0.5.0rc2\n')
        self.write(metadata + '/direct_url.json', json.dumps({'dir_info': {'editable': True}, 'url': 'file:///' + configure.APP + '/server'}))

    def write(self, relative, content, mode=0o644):
        path = self.root / relative
        # Model root-owned vendor directories, independent of the host's
        # default umask (the Linux test account uses 0002, macOS uses 0022).
        missing = []
        parent = path.parent
        while not parent.exists():
            missing.append(parent)
            parent = parent.parent
        for directory in reversed(missing):
            directory.mkdir(mode=0o755)
            directory.chmod(0o755)
        path.write_text(content)
        path.chmod(mode)
        return path

    def configure(self):
        configure.configure(self.root, self.manifest, self.digest, _app_uid=os.getuid(), _app_gid=os.getgid())

    def report(self):
        return verify.verify(self.root, self.manifest, self.digest, _owner_uid=os.getuid(), _owner_gid=os.getgid(),
                             _app_uid=os.getuid(), _app_gid=os.getgid())

    def select_candidate(self):
        raw = (ROOT/'tests/fixtures/application-manifest-c31b13af.json').read_bytes()
        self.manifest.write_bytes(raw)
        self.digest = hashlib.sha256(raw).hexdigest()
        release = json.loads((self.root/'etc/inkyos-release.json').read_bytes())
        release['recipe_inputs']['files']['application-manifest.json'] = self.digest
        self.write('etc/inkyos-release.json',json.dumps(release))
        self.write(configure.APP+'/server/SOURCE_COMMIT',json.loads(raw)['source_commit']+'\n')
        for path, content in self.candidate_sources.items():
            self.write(configure.APP+'/'+path,content)

    def test_static_integration_is_pinned_inactive_and_identity_free(self):
        self.configure()
        report = self.report()
        self.assertTrue(report['passed'], report['failed_checks'])
        self.assertEqual(report['scope'], 'offline-application-prototype-contract')
        self.assertFalse(report['release_qualified'])
        self.assertFalse(report['method']['image_code_executed'])
        self.assertEqual(report['manifest_sha256'], self.digest)
        self.assertEqual(len(report['expected_file_sha256']), 9)
        self.assertEqual(os.readlink(self.root / 'etc/systemd/system/inky-studio.service'), '/dev/null')
        self.assertEqual(os.readlink(self.root / 'etc/systemd/system/inky-network.service'), '/dev/null')
        self.assertEqual(list((self.root / 'var/lib/inky-studio/photos').iterdir()), [])
        self.assertFalse((self.root / 'etc/passwd-').exists())
        launcher = (self.root / 'usr/local/bin/inky-studio').read_text()
        self.assertIn('INKY_DEFAULT_INSTALL_DIR=/home/inky/inky-studio\n', launcher)
        self.assertIn('INKY_DEFAULT_DATA_DIR=/var/lib/inky-studio\n', launcher)
        sudoers = (self.root / 'etc/sudoers.d/inky-studio').read_text()
        self.assertEqual(sudoers.count('/usr/bin/systemctl'), 4)
        self.assertNotIn('timedate', sudoers)
        app_unit = (self.root / 'usr/lib/systemd/system/inky-studio.service').read_text()
        self.assertIn('INKY_STUDIO_REPO_SLUG=example/inky-studio', app_unit)

    def test_repository_declaration_is_unique_literal_and_never_evaluated(self):
        declaration = 'REPO_SLUG="${INKY_STUDIO_REPO_SLUG:-example/inky-studio}"\n'
        self.assertEqual(configure.installer_repository(declaration), 'example/inky-studio')
        for source in ('', declaration * 2, declaration + 'REPO_SLUG="$UNREVIEWED"\n',
                       declaration.replace('example', '$(id)'),
                       declaration.replace('example', 'https://example')):
            with self.subTest(source=source), self.assertRaises(ValueError):
                configure.installer_repository(source)

    def test_original_manifest_still_configures_and_verifies_without_repinning(self):
        self.manifest.write_bytes((ROOT / 'tests/fixtures/application-manifest-6a697d1.json').read_bytes())
        source = json.loads(self.manifest.read_bytes())['source_commit']
        self.digest = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        release = json.loads((self.root / 'etc/inkyos-release.json').read_bytes())
        release['recipe_inputs']['files']['application-manifest.json'] = self.digest
        self.write('etc/inkyos-release.json', json.dumps(release))
        self.write(configure.APP + '/server/SOURCE_COMMIT', source + '\n')
        self.configure()
        report = self.report()
        self.assertTrue(report['passed'], report['failed_checks'])
        self.assertEqual(report['source_commit'], source)
        self.assertEqual(report['manifest_sha256'], self.digest)

    def test_exact_reviewed_pairs_reject_crossed_and_repackaged_manifests(self):
        fixtures = [ROOT / 'tests/fixtures' / name for name in
                    ('application-manifest-6a697d1.json', 'application-manifest-758a2bf7.json',
                     'application-manifest-c31b13af.json')]
        pins = {json.loads(path.read_bytes())['source_commit']: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in fixtures}
        self.assertEqual(len(pins), 3)
        self.assertEqual(configure.REVIEWED_APPLICATIONS, pins)
        self.assertEqual(verify.configuration.REVIEWED_APPLICATIONS, pins)
        for path in fixtures:
            source = json.loads(path.read_bytes())['source_commit']
            for other_source, pin in pins.items():
                with self.subTest(source=source, other_source=other_source):
                    if source == other_source:
                        self.assertEqual(configure.load_manifest(path, pin)['source_commit'], source)
                    else:
                        with self.assertRaises(ValueError):
                            configure.load_manifest(path, pin)
            self.manifest.write_bytes(path.read_bytes() + b' ')
            with self.assertRaisesRegex(ValueError, 'reviewed source/manifest pair'):
                configure.load_manifest(self.manifest, hashlib.sha256(self.manifest.read_bytes()).hexdigest())

    def test_source_hash_policy_preserves_both_historical_pairs_and_is_selected_explicitly(self):
        self.assertEqual(set(PRODUCTION_SOURCE_HASHES), set(configure.REVIEWED_APPLICATIONS.items()))
        old = [hashes for pair,hashes in PRODUCTION_SOURCE_HASHES.items() if pair[0] != configure.SOURCE_COMMIT]
        self.assertEqual(len(old),2)
        self.assertEqual(old[0],old[1])
        self.assertEqual(old[0]['install.sh'],'541a98b9f3dc220b0dc89162e98affb97be200360ec7ad8e0650960d7d15944d')
        candidate = PRODUCTION_SOURCE_HASHES[(configure.SOURCE_COMMIT,configure.MANIFEST_SHA256)]
        self.assertEqual(candidate['install.sh'],'0d91f8016dd2eebf8619bdaa4c54b7afe1ee8e41f13d4f7cbb68f85810ff4e26')
        self.assertEqual({name:value for name,value in candidate.items() if name!='install.sh'},
                         {name:value for name,value in old[0].items() if name!='install.sh'})
        tree = Mock()
        with self.assertRaises(TypeError): configure.expected_files(tree)
        with self.assertRaises(ValueError):
            configure.expected_files(tree,source_commit='758a2bf7ed099aad41ef35316e53228e797b0b2b',
                                     manifest_sha256=configure.MANIFEST_SHA256)
        tree.metadata.assert_not_called();tree.read.assert_not_called()

    def test_candidate_static_unit_preserves_drain_settings_and_remains_masked_without_panel_profile(self):
        self.select_candidate();self.configure()
        report = self.report()
        self.assertTrue(report['passed'],report['failed_checks'])
        self.assertEqual(report['source_commit'],configure.SOURCE_COMMIT)
        self.assertEqual(report['manifest_sha256'],configure.MANIFEST_SHA256)
        path = self.root/'usr/lib/systemd/system/inky-studio.service'
        original = path.read_text()
        for line in ('Environment="INKY_STUDIO_DISPLAY_MODE=hardware"','KillSignal=SIGTERM','KillMode=mixed',
                     'TimeoutStopSec=infinity','SendSIGKILL=no'):
            self.assertEqual(original.splitlines().count(line),1)
            path.write_text(original.replace(line,'# removed by fixture'))
            self.assertIn('EXACT_USR_LIB_SYSTEMD_SYSTEM_INKY_STUDIO_SERVICE',self.report()['failed_checks'])
            path.write_text(original)
        for unit in configure.SERVICES:
            self.assertEqual(os.readlink(self.root/'etc/systemd/system'/unit),'/dev/null')
        self.assertFalse((self.root/'etc/inkyos-panel.json').exists())
        self.assertNotIn('AC073',original)
        self.assertFalse(report['release_qualified'])

    def test_installers_cannot_be_exchanged_between_old_and_candidate_pairs(self):
        self.write(configure.APP+'/install.sh',self.candidate_sources['install.sh'])
        with self.assertRaisesRegex(ValueError,'installer source hash mismatch'):self.configure()
        self.assertFalse((self.root/'usr/local/bin/inky-studio').exists())
        self.select_candidate()
        self.write(configure.APP+'/install.sh',self.sources['install.sh'])
        with self.assertRaisesRegex(ValueError,'installer source hash mismatch'):self.configure()
        self.assertFalse((self.root/'usr/local/bin/inky-studio').exists())
        self.write(configure.APP+'/install.sh',self.candidate_sources['install.sh']);self.configure()
        self.write(configure.APP+'/install.sh',self.sources['install.sh'])
        self.assertIn('REVIEWED_INSTALLER_SOURCES',self.report()['failed_checks'])

    def test_installed_metadata_cannot_select_a_different_reviewed_source_policy(self):
        self.configure()
        release = json.loads((self.root/'etc/inkyos-release.json').read_bytes())
        release['application']['source_commit'] = configure.SOURCE_COMMIT
        release['application']['manifest_sha256'] = configure.MANIFEST_SHA256
        self.write('etc/inkyos-release.json',json.dumps(release))
        self.write(configure.APP+'/server/SOURCE_COMMIT',configure.SOURCE_COMMIT+'\n')
        self.write(configure.APP+'/install.sh',self.candidate_sources['install.sh'])
        failed = self.report()['failed_checks']
        self.assertIn('APPLICATION_METADATA',failed)
        self.assertIn('SOURCE_COMMIT_PIN',failed)
        self.assertIn('REVIEWED_INSTALLER_SOURCES',failed)

    def test_tampered_source_or_manifest_is_rejected_before_configuration(self):
        with self.assertRaises(ValueError):
            configure.configure(self.root, self.manifest, 'f' * 64)
        self.write(configure.APP + '/scripts/inky-network-helper.py', 'tampered\n')
        with self.assertRaises(ValueError):
            self.configure()
        self.assertFalse((self.root / 'usr/local/bin/inky-studio').exists())

    def test_wrong_commit_or_recipe_pin_is_rejected(self):
        self.write(configure.APP + '/server/SOURCE_COMMIT', 'b' * 40)
        with self.assertRaises(ValueError):
            self.configure()
        self.write(configure.APP + '/server/SOURCE_COMMIT', json.loads(self.manifest.read_bytes())['source_commit'])
        release = json.loads((self.root / 'etc/inkyos-release.json').read_text())
        release['recipe_inputs']['files']['application-manifest.json'] = 'b' * 64
        self.write('etc/inkyos-release.json', json.dumps(release))
        with self.assertRaises(ValueError):
            self.configure()

    def test_runtime_mask_and_extra_dropin_tampering_fail(self):
        self.configure()
        mask = self.root / 'etc/systemd/system/inky-studio.service'
        mask.unlink()
        mask.symlink_to('/usr/lib/systemd/system/inky-studio.service')
        self.write('etc/systemd/system/inky-network.service.d/99-extra.conf', '[Service]\nAmbientCapabilities=CAP_SYS_TIME\n')
        failed = self.report()['failed_checks']
        self.assertIn('APP_MASK_inky-studio.service', failed)
        self.assertIn('NO_EXTRA_APP_OVERRIDES', failed)

    def test_privileged_file_mode_and_contents_are_verified(self):
        self.configure()
        (self.root / 'usr/local/lib/inky-studio/network-helper.py').chmod(0o755)
        self.write('etc/polkit-1/rules.d/49-inky-network.rules', 'polkit.addRule(function() { return polkit.Result.YES; });\n')
        failed = self.report()['failed_checks']
        self.assertIn('EXACT_USR_LOCAL_LIB_INKY_STUDIO_NETWORK_HELPER_PY', failed)
        self.assertIn('EXACT_ETC_POLKIT_1_RULES_D_49_INKY_NETWORK_RULES', failed)

    def test_helper_privileged_group_or_unlocked_account_is_rejected(self):
        content = (self.root / 'etc/group').read_text()
        self.write('etc/group', content + 'sudo:x:27:inky-network\n')
        with self.assertRaises(ValueError):
            self.configure()
        self.write('etc/group', content)
        self.write('etc/shadow', (self.root / 'etc/shadow').read_text().replace('inky-network:!:', 'inky-network::'), 0o600)
        with self.assertRaises(ValueError):
            self.configure()

    def test_country_radio_and_runtime_identity_tampering_are_detected_without_disclosure(self):
        self.configure()
        self.write('var/lib/NetworkManager/NetworkManager.state', '[main]\nWirelessEnabled=true\n', 0o600)
        self.write('etc/modprobe.d/country.conf', 'options cfg80211 ieee80211_regdom=FR\n')
        self.write('var/lib/inky-studio/identity.json', '{"sentinel":"PRIVATE_FIXTURE"}\n')
        report = self.report()
        for item in ('WIFI_DISABLED', 'NO_PRESEEDED_COUNTRY', 'NO_APP_RUNTIME_STATE'):
            self.assertIn(item, report['failed_checks'])
        self.assertNotIn('PRIVATE_FIXTURE', json.dumps(report))

    def test_generated_bytecode_and_nonfinal_venv_path_are_rejected(self):
        self.configure()
        self.write(configure.APP + '/server/inky_web/__pycache__/main.cpython-313.pyc', 'bytecode\n')
        self.write(configure.APP + '/server/.venv/bin/inky-studio-server', '#!/var/tmp/build/python\nfrom inky_web.main import run\n', 0o755)
        failed = self.report()['failed_checks']
        self.assertIn('NO_PYTHON_BYTECODE', failed)
        self.assertIn('APP_VENV', failed)

    def test_parent_symlink_cannot_redirect_privileged_files(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (self.root / 'usr').symlink_to(outside)
        with self.assertRaises(ValueError):
            self.configure()
        self.assertEqual(list(outside.iterdir()), [])

    def test_source_symlink_and_privileged_hardlink_fail(self):
        source = self.root / configure.APP / 'scripts/inky-network-helper.py'
        original = source.read_text()
        source.unlink()
        sentinel = self.base / 'sentinel'
        sentinel.write_text(original)
        source.symlink_to(sentinel)
        with self.assertRaises(ValueError):
            self.configure()
        source.unlink()
        source.write_text(original)
        target = self.root / 'usr/local/bin/inky-studio'
        target.parent.mkdir(parents=True)
        os.link(sentinel, target)
        with self.assertRaises(ValueError):
            self.configure()
        self.assertEqual(sentinel.read_text(), original)

    def test_malformed_installed_metadata_fails_closed(self):
        self.configure()
        path = configure.APP + '/server/.venv/lib/python3.13/site-packages/inky_studio_server-0.5.0rc2.dist-info/METADATA'
        self.write(path, 'Name: inky-studio-server\nVersion: 99.0\n')
        self.assertIn('APP_VENV', self.report()['failed_checks'])

    def test_restrictive_build_umask_does_not_make_helper_parents_inaccessible(self):
        old_mask = os.umask(0o077)
        try:
            self.configure()
        finally:
            os.umask(old_mask)
        for path in ('usr/local/lib/inky-studio', 'usr/local/bin', 'usr/lib/systemd/system',
                     'etc/systemd/system/inky-studio.service.d'):
            self.assertEqual((self.root / path).stat().st_mode & 0o777, 0o755, path)
        self.assertTrue(self.report()['passed'])

    def test_vendor_parent_group_is_preserved_but_writable_parents_fail(self):
        self.configure()
        original = verify.inspection.SafeTree.metadata

        def vendor_group(tree, path):
            result = original(tree, path)
            if path == 'etc/polkit-1/rules.d':
                values = list(result)
                values[5] = 987  # Pinned OS vendor directory group; never change it.
                return os.stat_result(values)
            return result

        with patch.object(verify.inspection.SafeTree, 'metadata', vendor_group):
            self.assertTrue(self.report()['passed'])
        (self.root / 'etc/polkit-1/rules.d').chmod(0o775)
        self.assertIn('EXACT_ETC_POLKIT_1_RULES_D_49_INKY_NETWORK_RULES', self.report()['failed_checks'])

    def test_reconfiguration_requires_fresh_system_prototype(self):
        self.configure()
        with self.assertRaises(ValueError):
            self.configure()


if __name__ == '__main__':
    unittest.main()
