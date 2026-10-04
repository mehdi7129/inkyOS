#!/usr/bin/env python3
"""Verify a PRIVATE enroll-and-stop export without mounting or activating it.

The private recipe contains the operator public key and nonce. Neither these,
their fingerprint nor profile contents are returned or printed. Unsigned
inventories establish consistency, not independent authenticity or hardware.
"""
import sys
sys.dont_write_bytecode = True

import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import tarfile


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


lan = module('_enrollment_prepared_integrity', 'verify-test-lan.py')
overlay = module('_enrollment_configuration', 'configure-test-access-rootfs.py')
artifacts, diagnostic = lan.artifacts, lan.diagnostic
ArtifactError, require = lan.ArtifactError, lan.require
REQUIRED_REPORTS = (lan.REQUIRED_REPORTS - {'test-lan-configuration.json'}) | {
    'test-access-configuration.json', 'qualification-prepared.json', 'build.log', 'sudoers-verify.txt',
}
PROTECTED_FILES = lan.PROTECTED_FILES
INHERITED_RECIPE_FILES = lan.INHERITED_RECIPE_FILES | {
    'application-manifest.json', 'scripts/configure-test-lan-rootfs.py', 'scripts/test-lan-preflight.py',
    'scripts/configure-rootfs.py',
}
PREPARED_CHECKS = lan.overlay.CHECKS
builder = module('_access_export_recipe', 'build-test-access.py')
CONFIGURATION_KEYS = {
    'schema_version', 'kind', 'scope', 'passed', 'private_artifact', 'bootstrap_action',
    'application_started', 'ssh_started', 'network_connected', 'no_active_application',
    'ready_for_activation', 'hardware_qualified', 'release_qualified',
    'removed_rootfs_paths', 'removed_bootfs_paths', 'checks', 'parent_image_sha256', 'profile_sha256',
    'source_file_sha256', 'recipe_source_commit', 'recipe_worktree_dirty', 'recipe_inputs_sha256',
    'preserved_parent_file_sha256', 'protected_boot_grow_sha256', 'bootfs_snapshot_sha256',
    'access_runtime_manifest_sha256', 'account_file_sha256', 'account_parent_metadata',
}
sha = lan.sha
MANIFEST_KEYS = {'schema_version', 'kind', 'private_artifact', 'bootstrap_action', 'no_active_application',
                 'ready_for_activation', 'hardware_qualified', 'release_qualified', 'application',
                 'parent', 'personalization', 'image', 'recipe', 'reports'}


def validate_manifest(value):
    require(type(value) is dict and set(value) == MANIFEST_KEYS and type(value.get('schema_version')) is int and value['schema_version'] == 1
            and value.get('kind') == 'test-lan-access' and value.get('private_artifact') is True
            and value.get('bootstrap_action') == 'enrollment-then-signed-access' and value.get('no_active_application') is True
            and all(value.get(name) is False for name in ('ready_for_activation', 'hardware_qualified', 'release_qualified')),
            'Expected private inactive enroll-and-stop export')
    application = value.get('application')
    require(lan.overlay.reviewed_application(application) and application['source_commit'] == overlay.SOURCE_COMMIT
            and application['manifest_sha256'] == overlay.MANIFEST_SHA256, 'Exact enrollment application pin required')
    artifacts.validate_recipe(value.get('recipe'))
    require(set(value['recipe']) == {'schema_version', 'source_commit', 'worktree_dirty', 'files'}
            and set(value['recipe']['files']) == set(builder.RECIPE_FILES) | {'application-manifest.json', 'parent-manifest.json', overlay.PRIVATE_PROFILE, overlay.PRIVATE_MANIFEST}, 'Enrollment recipe differs from the closed source whitelist')
    image = value.get('image')
    require(type(image) is dict and set(image) == {'filename', 'size_bytes', 'sha256'}
            and image['filename'] == 'inkyos-test-access.img' and type(image['size_bytes']) is int
            and 0 < image['size_bytes'] <= artifacts.MAX_IMAGE_BYTES and artifacts.valid_hash(image['sha256']), 'Invalid enrollment image')
    parent = value.get('parent')
    require(type(parent) is dict and set(parent) == {'kind', 'image_sha256', 'size_bytes', 'manifest_sha256'}
            and parent['kind'] == 'test-lan-prepared' and parent['image_sha256'] == overlay.PARENT_IMAGE_SHA256
            and type(parent['size_bytes']) is int and parent['size_bytes'] == image['size_bytes']
            and artifacts.valid_hash(parent['manifest_sha256']), 'Exact prepared parent pin required')
    personalization = value.get('personalization')
    require(type(personalization) is dict and set(personalization) == {'profile_sha256', 'network_profile_present', 'country_requested'}
            and artifacts.valid_hash(personalization['profile_sha256']) and personalization['network_profile_present'] is False
            and personalization['country_requested'] == 'FR'
            and value['recipe']['files'][overlay.PRIVATE_PROFILE] == personalization['profile_sha256'], 'Invalid private profile provenance')
    reports = value.get('reports')
    require(type(reports) is dict and set(reports) == REQUIRED_REPORTS
            and all(artifacts.basename(name) and artifacts.valid_hash(digest) for name, digest in reports.items()), 'Exact enrollment reports required')
    return value


def validate_parent(reports, manifest):
    raw = reports['parent-manifest.json']
    parent = lan.validate_manifest(artifacts.parse_json(raw))
    pin = manifest['parent']
    require(parent['image']['sha256'] == pin['image_sha256'] and parent['image']['size_bytes'] == pin['size_bytes']
            and sha(raw) == pin['manifest_sha256'] and parent['application'] == manifest['application'], 'Prepared parent provenance differs')
    integrity = artifacts.parse_json(reports['parent-integrity.json'])
    require(type(integrity) is dict and integrity.get('scope') == 'local-test-lan-prepared-export-integrity'
            and all(integrity.get(name) is True for name in ('passed', 'image_sha256_verified', 'no_active_application'))
            and all(integrity.get(name) is False for name in ('authenticity_verified', 'hardware_qualified', 'release_qualified', 'ready_for_activation')),
            'Prepared parent integrity scope differs')
    require(manifest['recipe']['files'].get('parent-manifest.json') == pin['manifest_sha256'], 'Parent manifest missing from recipe')
    raw = reports['parent-filesystem-manifest.json']
    require(sha(raw) == parent['reports']['filesystem-manifest.json'], 'Prepared parent inventory hash differs')
    inventory = artifacts.validate_filesystem(artifacts.parse_json(raw))
    require(inventory['schema_version'] == 2, 'Prepared parent requires metadata inventory')
    return parent, inventory


def validate_configuration(reports, manifest, recipe_raw):
    value = artifacts.parse_json(reports['test-access-configuration.json'])
    require(type(value) is dict and set(value) == CONFIGURATION_KEYS and type(value.get('schema_version')) is int
            and value['schema_version'] == 1 and value.get('kind') == 'test-lan-access'
            and value.get('scope') == 'offline-test-access-configuration' and value.get('passed') is True
            and value.get('private_artifact') is True and value.get('bootstrap_action') == 'enrollment-then-signed-access'
            and value.get('no_active_application') is True and all(value.get(name) is False for name in (
                'application_started', 'ssh_started', 'network_connected', 'ready_for_activation', 'hardware_qualified', 'release_qualified')),
            'Invalid enrollment configuration scope')
    require(type(value['checks']) is dict and set(value['checks']) == overlay.CHECKS
            and all(item is True for item in value['checks'].values()), 'Incomplete enrollment checks')
    require(value['parent_image_sha256'] == overlay.PARENT_IMAGE_SHA256
            and value['profile_sha256'] == manifest['personalization']['profile_sha256']
            and value['removed_rootfs_paths'] == value['removed_bootfs_paths'] == [], 'Unexpected enrollment pin or removal')
    require(type(value['source_file_sha256']) is dict and set(value['source_file_sha256']) == overlay.SOURCES
            and all(value['source_file_sha256'][name] == manifest['recipe']['files'].get(name) for name in overlay.SOURCES), 'Enrollment sources differ')
    require(value['recipe_source_commit'] == manifest['recipe']['source_commit']
            and type(value['recipe_worktree_dirty']) is bool and value['recipe_worktree_dirty'] == manifest['recipe']['worktree_dirty']
            and value['recipe_inputs_sha256'] == sha(recipe_raw) and artifacts.valid_hash(value['bootfs_snapshot_sha256']), 'Enrollment recipe provenance differs')
    for field, expected in (('preserved_parent_file_sha256', overlay.PRESERVED_FILES), ('protected_boot_grow_sha256', PROTECTED_FILES)):
        require(type(value[field]) is dict and set(value[field]) == expected and all(artifacts.valid_hash(item) for item in value[field].values()), 'Incomplete preserved parent hashes')
    return value


def validate_prepared_constraints(raw, parent_filesystem):
    value = artifacts.parse_json(raw)
    require(type(value) is dict and value.get('schema_version') == 1
            and value.get('scope') == 'pristine-parent-before-access-configuration'
            and value.get('kind') == 'test-lan-prepared' and value.get('passed') is True
            and value.get('marker_sha256') == parent_filesystem['rootfs'][lan.METADATA_PATH]['sha256']
            and all(value.get(key) is False for key in ('application_started', 'hardware_qualified', 'release_qualified', 'ready_for_activation'))
            and type(value.get('checks')) is dict and set(value['checks']) == PREPARED_CHECKS
            and all(item is True for item in value['checks'].values()), 'Pristine parent pre-configuration evidence differs')


def private_profile(blobs, reports, manifest_raw, recipe_raw):
    raw = blobs[overlay.PRIVATE_PROFILE]
    require(len(raw) <= 4096, 'Oversized private profile')
    profile = overlay.policy.strict_json(raw)
    require(overlay.policy.validate_profile(profile) and raw == overlay.policy.canonical(profile), 'Private enrollment profile schema refused')
    # Prevent copying personalization into a report or public manifest. The
    # private archive is the only declared evidence allowed to contain it.
    wire = base64.b64decode(profile['operator_public_key'].split(' ')[1], validate=True)
    fingerprint = b'SHA256:' + base64.b64encode(hashlib.sha256(wire).digest()).rstrip(b'=')
    forbidden = (profile['operator_public_key'].encode(), profile['operator_public_key'].split(' ')[1].encode(),
                 profile['challenge'].encode(), fingerprint)
    for evidence in [manifest_raw, recipe_raw] + [data for name, data in reports.items() if name != 'recipe.tar']:
        require(not any(token in evidence for token in forbidden), 'Personalization leaked into a report')
    return raw


def validate_inventory(parent, filesystem, configuration, blobs):
    require(filesystem['schema_version'] == 2 and filesystem['bootfs'] == parent['bootfs'], 'Access bootfs must remain identical')
    boot_snapshot = {}
    for path, row in filesystem['bootfs'].items():
        if path == '.':
            continue
        require(row['type'] in {'file', 'directory'}, 'Unexpected bootfs entry')
        boot_snapshot[path] = {key: row[key] for key in ('type', 'uid', 'gid')}
        boot_snapshot[path]['mode'] = int(row['mode'], 8)
        if row['type'] == 'file':
            boot_snapshot[path]['sha256'] = row['sha256']
    require(sha(overlay.policy.canonical(boot_snapshot))
            == configuration['bootfs_snapshot_sha256'], 'Bootfs receipt differs from inventory')
    root, old = filesystem['rootfs'], parent['rootfs']
    lan.no_runtime_or_diagnostic(filesystem)
    allowed = {overlay.PROFILE_PATH, overlay.MANIFEST_PATH, overlay.AUTHORIZED_KEYS, overlay.ENABLE_PATH}
    directories = {overlay.PROFILE_DIRECTORY: '0700', overlay.STATE_DIRECTORY: '0700',
                   overlay.CACHE_DIRECTORY: '0700', overlay.SSH_DIRECTORY: '0755', overlay.SSH_PUBLIC_DIRECTORY: '0755'}
    allowed.update(directories)
    for name, (path, mode) in overlay.PAYLOADS.items():
        lan.regular(root.get(path), sha(blobs[name]), format(mode, '04o'), size=len(blobs[name]))
        if path in overlay.INHERITED_PAYLOADS:
            require(old.get(path) == root[path], 'Inherited source changed')
        else:
            require(path not in old, 'Access destination already present in parent')
            allowed.add(path)
    profile_raw = blobs[overlay.PRIVATE_PROFILE]
    profile = overlay.policy.strict_json(profile_raw)
    runtime_raw = blobs[overlay.PRIVATE_MANIFEST]
    require(runtime_raw == overlay.policy.canonical(overlay._manifest(blobs))
            and sha(runtime_raw) == configuration['access_runtime_manifest_sha256']
            == profile['access_runtime_manifest_sha256'], 'Runtime manifest differs from payloads or profile')
    lan.regular(root.get(overlay.PROFILE_PATH), sha(profile_raw), '0600', size=len(profile_raw))
    lan.regular(root.get(overlay.MANIFEST_PATH), sha(runtime_raw), '0644', size=len(runtime_raw))
    public = ('restrict ' + profile['operator_public_key'] + '\n').encode()
    lan.regular(root.get(overlay.AUTHORIZED_KEYS), sha(public), '0644', size=len(public))
    for path, mode in directories.items():
        row = root.get(path, {})
        require(row.get('type') == 'directory' and row.get('mode') == mode
                and row.get('uid') == row.get('gid') == 0 and lan.plain_xattrs(row), 'Access directory metadata differs')
    for path in (overlay.STATE_DIRECTORY, overlay.CACHE_DIRECTORY):
        require(not any(name.startswith(path + '/') for name in root), 'Access runtime cache/state was precreated')
    require({name for name in root if name.startswith(overlay.PROFILE_DIRECTORY + '/')} == {overlay.PROFILE_PATH},
            'Access private host key or unknown profile file was precreated')
    link = root.get(overlay.ENABLE_PATH, {})
    require(link.get('type') == 'symlink' and link.get('target') == overlay.UNIT_TARGET
            and link.get('mode') == '0777' and link.get('uid') == link.get('gid') == 0 and lan.plain_xattrs(link), 'Sole access boot hook differs')
    accounts = configuration['account_file_sha256']
    metadata = configuration['account_parent_metadata']
    require(type(accounts) is dict and set(accounts) == set(overlay.ACCOUNT_APPEND)
            and type(metadata) is dict and set(metadata) == set(overlay.ACCOUNT_APPEND), 'Incomplete account append hashes or metadata')
    for path, suffix in overlay.ACCOUNT_APPEND.items():
        before, after = old.get(path), root.get(path)
        require(type(before) is dict and type(after) is dict and before['type'] == after['type'] == 'file'
                and accounts[path] == {'before': before['sha256'], 'after': after['sha256']}
                and after['size_bytes'] == before['size_bytes'] + len(suffix), 'Account append inventory differs')
        lan.unchanged_metadata(before, after, content=True)
        require(metadata[path] == {'mode': int(before['mode'], 8), 'uid': before['uid'], 'gid': before['gid']},
                'Declared account metadata differs from parent')
    parents = {str(parent) for path in allowed for parent in PurePosixPath(path).parents if str(parent) != '.'}
    for path in set(old) | set(root):
        before, after = old.get(path), root.get(path)
        if before == after or path in overlay.ACCOUNT_APPEND:
            continue
        require(before is None and after is not None, 'Existing parent entry changed or removed')
        if path in allowed:
            continue
        require(path in parents and after.get('type') == 'directory' and after.get('mode') == '0755'
                and after.get('uid') == after.get('gid') == 0 and lan.plain_xattrs(after), 'Forbidden access addition')
    for path, expected in configuration['preserved_parent_file_sha256'].items():
        require(old.get(path, {}).get('sha256') == root.get(path, {}).get('sha256') == expected, 'Preserved file differs')
    for name, expected in configuration['protected_boot_grow_sha256'].items():
        section, _, path = name.partition('/')
        require(parent[section + 'fs'].get(path, {}).get('sha256') == filesystem[section + 'fs'].get(path, {}).get('sha256') == expected,
                'Protected boot/grow hash differs')
    for unit in overlay.MASKS:
        row = root.get('etc/systemd/system/' + unit, {})
        require(row.get('type') == 'symlink' and row.get('target') == '/dev/null', 'Required unit mask differs')


def load_export(directory, *, verify_images=True):
    export = artifacts.ExportDirectory(directory)
    try:
        manifest_raw = export.read('manifest.json')
        manifest = validate_manifest(artifacts.parse_json(manifest_raw))
        recipe_raw = export.read('recipe-inputs.json')
        recipe = artifacts.validate_recipe(artifacts.parse_json(recipe_raw))
        require(recipe == manifest['recipe'], 'Recipe metadata differs from private export')
        reports = {name: export.read(name) for name in manifest['reports']}
        require(all(sha(data) == manifest['reports'][name] for name, data in reports.items()), 'Enrollment report hash differs')
        diagnostic.validate_archive(reports['recipe.tar'], recipe)
        with tarfile.open(fileobj=io.BytesIO(reports['recipe.tar']), mode='r:') as archive:
            private = archive.getmember('recipe/' + overlay.PRIVATE_PROFILE)
            require(private.mode == 0o600 and private.uid == private.gid == 0, 'Private recipe profile archive metadata differs')
        parent, inventory = validate_parent(reports, manifest)
        require(all(recipe['files'].get(name) == parent['recipe']['files'].get(name) for name in INHERITED_RECIPE_FILES), 'Inherited audit source changed')
        diagnostic.validate_static(reports, manifest)
        validate_prepared_constraints(reports['qualification-prepared.json'], inventory)
        configuration = validate_configuration(reports, manifest, recipe_raw)
        blobs = lan.archived_bytes(reports['recipe.tar'], set(overlay.PAYLOADS) | {overlay.PRIVATE_PROFILE, overlay.PRIVATE_MANIFEST})
        private_profile(blobs, reports, manifest_raw, recipe_raw)
        filesystem = artifacts.validate_filesystem(artifacts.parse_json(reports['filesystem-manifest.json']))
        validate_inventory(inventory, filesystem, configuration, blobs)
        inspected = artifacts.parse_json(reports['image-inspection.json'])
        image = inspected.get('image') if type(inspected) is dict else None
        require(type(image) is dict and image.get('sha256') == manifest['image']['sha256']
                and type(image.get('size_bytes')) is int and image['size_bytes'] == manifest['image']['size_bytes'], 'Enrollment image inspection differs')
        export.image(manifest['image'], verify_hash=verify_images)
    finally:
        export.close()
    report = {'schema_version': 1, 'scope': 'local-test-access-export-integrity', 'passed': True,
              'private_artifact': True, 'bootstrap_action': 'enrollment-then-signed-access', 'no_active_application': True,
              'ready_for_activation': False, 'hardware_qualified': False, 'release_qualified': False,
              'authenticity_verified': False, 'image_sha256_verified': verify_images,
              'recipe_source_hashes_verified': True, 'private_profile_sha256_verified': True,
              'filesystem_delta_allowlist_verified': True, 'protected_boot_grow_files_verified': len(PROTECTED_FILES),
              'pristine_parent_constraints_verified_before_changes': len(PREPARED_CHECKS),
              'parent_image_sha256': overlay.PARENT_IMAGE_SHA256, 'declared_reports_verified': sorted(reports),
              'limits': ['Unsigned local hashes establish consistency, not independent authenticity.',
                         'Parent image bytes were checked when building, not rehashed here.',
                         'Filesystem inventories are not regenerated from image bytes.',
                         'Account append content was checked by the configurator; the export checks its hashes, size delta and metadata.',
                         'No enrollment boot, host key binding, SD recovery, network, hardware or activation is qualified.']}
    if not verify_images:
        report['limits'].append('Image bytes were not hashed; only type and size were checked.')
    return {'manifest': manifest, 'filesystem': filesystem, 'report': report}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    try:
        result = load_export(args.directory)['report']
        if args.output:
            artifacts.write_report(args.output, result, [args.directory])
            os.chmod(args.output, 0o600, follow_symlinks=False)
        else:
            print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (ArtifactError, OSError, ValueError, TypeError, KeyError, tarfile.TarError):
        print('Private enrollment export verification refused.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
