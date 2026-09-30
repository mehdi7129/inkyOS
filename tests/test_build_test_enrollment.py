"""Inert private-transfer fixtures only: no key generation, VM, image or bus."""
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/build-test-enrollment.sh'
embedded = SCRIPT.read_text().split("<<'PY_ENROLLMENT'\n", 1)[1].rsplit('\nPY_ENROLLMENT', 1)[0]
driver = {'__name__': 'inert_test_enrollment_builder'}
exec(compile(embedded, str(SCRIPT) + ':PY_ENROLLMENT', 'exec'), driver)


def public_fixture():
    # Synthetic wire bytes, not a generated key pair or a usable identity.
    wire = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + bytes(range(32))
    return 'ssh-ed25519 ' + base64.b64encode(wire).decode()


def parent_fixture():
    return {'schema_version': 1, 'kind': 'test-lan-prepared', 'hardware_qualified': False,
            'release_qualified': False, 'no_active_application': True, 'ready_for_activation': False,
            'application': {'source_commit': driver['SOURCE'], 'manifest_sha256': driver['APPLICATION_MANIFEST'],
                'application_version': '0.5.0-rc.2', 'startup': 'masked-pending-firstboot-contract', 'release_qualified': False},
            'image': {'filename': 'inkyos-test-lan-prepared.img', 'size_bytes': 4096, 'sha256': driver['PARENT_IMAGE']}}


class EnrollmentBuilderTests(unittest.TestCase):
    def test_help_and_invalid_arguments_do_not_touch_inputs_or_print_private_values(self):
        result = subprocess.run(['bash', str(SCRIPT), '--help'], capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0)
        self.assertIn(b'--country', result.stdout)
        for args in (['PRIVATE_PARENT'], ['PRIVATE_PARENT', '--country', 'PRIVATE_COUNTRY'],
                     ['PRIVATE_PARENT', '--country', 'FR', '--profile', 'PRIVATE_PROFILE']):
            result = subprocess.run(['bash', str(SCRIPT), *args], capture_output=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b'PRIVATE_', result.stdout + result.stderr)
            self.assertNotIn(b'Traceback', result.stderr)

    def test_profile_is_exact_canonical_enrollment_only_with_explicit_country(self):
        result = driver['profile'](public_fixture(), 'a' * 64, 'FR')
        self.assertEqual(len(result), 15)
        self.assertEqual(result['purpose'], 'test-enroll-and-stop')
        self.assertEqual(result['parent_image_sha256'], driver['PARENT_IMAGE'])
        for field in ('network_profile_present', 'ssh_access_enabled', 'application_activation_authorized',
                      'hardware_qualified', 'release_qualified'):
            self.assertIs(result[field], False)
        self.assertEqual(driver['canonical'](result), (json.dumps(result, sort_keys=True, indent=2) + '\n').encode())
        for challenge, country in (('0' * 64, 'FR'), ('A' * 64, 'FR'), ('a' * 63, 'FR'), ('a' * 64, None),
                                   ('a' * 64, 'fr'), ('a' * 64, 'ZZ')):
            with self.assertRaises(ValueError):
                driver['profile'](public_fixture(), challenge, country)

    def test_generated_public_key_requires_two_tokens_and_canonical_ed25519_wire(self):
        value = public_fixture()
        self.assertEqual(driver['public_key']((value + ' \n').encode()), value)
        for raw in (b'', (value + ' PRIVATE_COMMENT').encode(), value.replace('ssh-ed25519', 'ssh-rsa').encode(),
                    b'ssh-ed25519 !!!!', b'ssh-ed25519 ' + base64.b64encode(b'wrong-wire'),
                    b'ssh-ed25519 ' + b'x' * 1024):
            with self.assertRaises(ValueError):
                driver['public_key'](raw)

    def test_parent_pin_and_inactive_flags_are_mandatory_before_any_transfer(self):
        original = parent_fixture()
        self.assertEqual(driver['validate_parent'](json.dumps(original)), original)
        for field, value in (('kind', 'system-prototype'), ('schema_version', True),
                             ('ready_for_activation', True), ('no_active_application', False), ('hardware_qualified', True)):
            altered = copy.deepcopy(original); altered[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                driver['validate_parent'](json.dumps(altered))
        for section, field, value in (('application', 'source_commit', 'f' * 40),
                                     ('application', 'manifest_sha256', 'f' * 64),
                                     ('image', 'sha256', 'f' * 64), ('image', 'filename', '../PRIVATE.img')):
            altered = copy.deepcopy(original); altered[section][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                driver['validate_parent'](json.dumps(altered))

    def test_private_directory_refuses_existing_unsafe_or_linked_base(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = driver['private_directory'](root)
            self.assertRegex(work.name, r'^test-enrollment\.[0-9a-f]{8}$')
            for path in (work.parent, work):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
                self.assertEqual(path.stat().st_uid, os.geteuid())
            work.parent.chmod(0o755)
            with self.assertRaises(ValueError):
                driver['private_directory'](root)
            self.assertEqual(stat.S_IMODE(work.parent.stat().st_mode), 0o755)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'private').symlink_to(root)
            with self.assertRaises(ValueError):
                driver['private_directory'](root)

    def test_snapshot_transfer_whitelist_excludes_private_key_and_binds_profile_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); parent = base / 'parent'; parent.mkdir()
            work = base / 'test-enrollment.12345678'; work.mkdir(mode=0o700)
            private = work / driver['PRIVATE_KEY']; private.write_bytes(b'PRIVATE_SENTINEL_NOT_A_KEY')
            application = (ROOT / 'tests/fixtures/application-manifest-758a2bf7.json').read_bytes()
            (parent / 'application-manifest.json').write_bytes(application)
            inventory = b'{"synthetic_fixture":true}\n'
            (parent / 'filesystem-manifest.json').write_bytes(inventory)
            sources = {name: ('synthetic source ' + name + '\n').encode() for name in driver['RECIPE_FILES']}
            data = parent_fixture()
            data['reports'] = {'filesystem-manifest.json': hashlib.sha256(inventory).hexdigest()}
            data['recipe'] = {'files': {name: hashlib.sha256(sources[name]).hexdigest() for name in driver['INHERITED']}}
            raw = driver['canonical'](data)
            profile = driver['canonical'](driver['profile'](public_fixture(), 'a' * 64, 'FR'))
            original_read = driver['read_regular']
            def guarded_read(path, *args, **kwargs):
                self.assertNotEqual(path, private, 'Private key content must never be read')
                return original_read(path, *args, **kwargs)
            with patch.dict(driver, {'read_regular': guarded_read}):
                recipe = driver['snapshot'](work, parent, raw, sources, profile, 'b' * 40, True)
            self.assertEqual(recipe['files']['private-profile.json'], hashlib.sha256(profile).hexdigest())
            archive_bytes = (work / 'recipe.tar').read_bytes()
            self.assertNotIn(b'PRIVATE_SENTINEL_NOT_A_KEY', archive_bytes)
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode='r:') as archive:
                self.assertEqual(set(archive.getnames()), {'recipe/' + name for name in recipe['files']} | {'recipe/recipe-inputs.json'})
                member = archive.getmember('recipe/private-profile.json')
                self.assertEqual(member.mode, 0o600)
                self.assertEqual(archive.extractfile(member).read(), profile)
            target, copies = driver['transfers'](work, parent, data)
            self.assertEqual(target, '/var/tmp/inkyos-work/test-enrollment.12345678')
            self.assertEqual([path.name for path, _ in copies], ['recipe.tar', 'inkyos-test-lan-prepared.img'])
            self.assertNotIn(private, [path for path, _ in copies])
            self.assertTrue(all(stat.S_IMODE((work / name).stat().st_mode) == 0o600
                                for name in ('recipe.tar', 'recipe-inputs.json', 'parent-manifest.json')))
            with self.assertRaises(ValueError):
                driver['snapshot'](work, parent, raw, dict(sources, unexpected=b'PRIVATE_EXTRA'), profile, 'b' * 40, True)

    def test_transfer_and_receipt_files_refuse_links_and_existing_destinations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); original = root / 'original'; original.write_bytes(b'synthetic')
            link = root / 'link'; link.symlink_to(original)
            for function in (driver['read_regular'], driver['transfer_file']):
                with self.assertRaises(OSError):
                    function(link)
            hardlink = root / 'hardlink'; os.link(original, hardlink)
            for function in (driver['read_regular'], driver['transfer_file']):
                with self.assertRaises(ValueError):
                    function(hardlink)
            with self.assertRaises(FileExistsError):
                driver['write_new'](original, b'overwrite')
            self.assertEqual(original.read_bytes(), b'synthetic')

    def test_command_errors_are_captured_without_shell_or_raw_log_forwarding(self):
        failed = subprocess.CompletedProcess(['fixture'], 1, stdout=b'PRIVATE_NONCE', stderr=b'PRIVATE_KEY')
        with patch.object(driver['subprocess'], 'run', return_value=failed) as run:
            with self.assertRaises(driver['ClosedError']):
                driver['invoke'](['fixture'])
            self.assertEqual(run.call_args.kwargs['stdout'], subprocess.DEVNULL)
            self.assertEqual(run.call_args.kwargs['stderr'], subprocess.DEVNULL)
            self.assertNotIn('shell', run.call_args.kwargs)


if __name__ == '__main__':
    unittest.main()
