#!/usr/bin/env python3
"""Validate an inactive TEST LAN export; never mount, import the app or activate it.

Unsigned hashes establish consistency only. The inventory is not regenerated
from image bytes; full-image hashing is an additional, distinct integrity check.
"""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import sys
import tarfile


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


diagnostic = module('_test_lan_diagnostic_integrity', 'verify-sd-diagnostic.py')
artifacts = diagnostic.artifacts
overlay = module('_test_lan_configuration_contract', 'configure-test-lan-rootfs.py')
ArtifactError = artifacts.ArtifactError
require = diagnostic.require
REQUIRED_REPORTS = ((diagnostic.REQUIRED_REPORTS - {'diagnostic-configuration.json'})
                    | {'test-lan-configuration.json'})
PROTECTED_FILES = diagnostic.PROTECTED_FILES
INHERITED_RECIPE_FILES = frozenset({
    'config/base-image.lock.json', 'config/system-packages.lock.json',
    'scripts/configure-application-rootfs.py', 'scripts/verify-application-rootfs.py',
})
METADATA_PATH = overlay.METADATA_PATH


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def validate_manifest(value):
    require(isinstance(value, dict) and type(value.get('schema_version')) is int
            and value['schema_version'] == 1 and value.get('kind') == 'test-lan-prepared'
            and value.get('hardware_qualified') is False and value.get('release_qualified') is False
            and value.get('no_active_application') is True and value.get('ready_for_activation') is False,
            'Expected an inactive, unqualified TEST LAN prepared export')
    require(overlay.reviewed_application(value.get('application')), 'TEST LAN requires an exact reviewed masked application pair')
    artifacts.validate_recipe(value.get('recipe'))
    require(value['recipe']['files'].get('application-manifest.json') == value['application']['manifest_sha256'],
            'Application manifest is not the pinned recipe input')
    image = value.get('image')
    require(isinstance(image, dict) and set(image) == {'filename', 'size_bytes', 'sha256'}
            and artifacts.basename(image.get('filename')) and image['filename'].endswith('.img')
            and artifacts.integer(image.get('size_bytes')) and 0 < image['size_bytes'] <= artifacts.MAX_IMAGE_BYTES
            and artifacts.valid_hash(image.get('sha256')), 'Invalid prepared image record')
    parent = value.get('parent')
    require(isinstance(parent, dict) and set(parent) == {'kind', 'image_sha256', 'size_bytes', 'manifest_sha256'}
            and parent['kind'] == 'application-prototype' and artifacts.valid_hash(parent['image_sha256'])
            and artifacts.valid_hash(parent['manifest_sha256']) and type(parent['size_bytes']) is int
            and parent['size_bytes'] == image['size_bytes'], 'Invalid application-prototype parent pin or size')
    reports = value.get('reports')
    require(isinstance(reports, dict) and REQUIRED_REPORTS <= set(reports) and len(reports) <= 64
            and all(artifacts.basename(name) and artifacts.valid_hash(digest) for name, digest in reports.items())
            and not {'manifest.json', 'recipe-inputs.json', image['filename']} & set(reports),
            'Missing TEST LAN reports or invalid report names/hashes')
    return value


def archived_bytes(raw, names):
    """Read declared source members only after validate_archive; never extract."""
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        result = {}
        for name in names:
            member = archive.getmember('recipe/' + name)
            with archive.extractfile(member) as source:
                result[name] = source.read(artifacts.MAX_REPORT_BYTES + 1)
        return result


def validate_configuration(reports, manifest, recipe_raw):
    value = artifacts.parse_json(reports['test-lan-configuration.json'])
    require(isinstance(value, dict) and type(value.get('schema_version')) is int
            and value['schema_version'] == 1 and value.get('kind') == 'test-lan-prepared'
            and value.get('scope') == 'offline-test-lan-prepared-configuration'
            and value.get('passed') is True and value.get('parent_image_sha256') == manifest['parent']['image_sha256']
            and value.get('application_started') is False and value.get('ready_for_activation') is False
            and value.get('hardware_qualified') is False and value.get('release_qualified') is False,
            'TEST LAN configuration must remain inactive and unqualified')
    checks = value.get('checks')
    require(isinstance(checks, dict) and set(checks) == set(overlay.CHECKS)
            and all(result is True for result in checks.values()), 'Configuration PASS omits or contradicts checks')
    sources = value.get('source_file_sha256')
    require(isinstance(sources, dict) and set(sources) == set(overlay.SOURCES)
            and all(artifacts.valid_hash(digest) and manifest['recipe']['files'].get(name) == digest
                    for name, digest in sources.items()), 'Configuration source hashes differ from recipe inputs')
    require(value.get('recipe_source_commit') == manifest['recipe']['source_commit']
            and type(value.get('recipe_worktree_dirty')) is bool
            and value['recipe_worktree_dirty'] == manifest['recipe']['worktree_dirty']
            and value.get('recipe_inputs_sha256') == sha(recipe_raw),
            'Configuration provenance differs from recipe metadata')
    delta = value.get('boot_config_delta')
    require(isinstance(delta, dict) and set(delta) == {'parent_sha256', 'configured_sha256', 'append'}
            and artifacts.valid_hash(delta['parent_sha256']) and artifacts.valid_hash(delta['configured_sha256'])
            and delta['append'] == overlay.BOOT_APPEND, 'Unexpected boot configuration delta')
    require(artifacts.valid_hash(value.get('marker_sha256')) and value.get('metadata_path') == METADATA_PATH
            and value.get('removed_pending_boot_artifacts') == [], 'Invalid marker or unexpected boot artifact removal')
    return value


def plain_xattrs(record):
    return record.get('xattrs') == {'status': 'inspected', 'entries': {}}


def regular(record, digest, mode, *, size=None):
    require(isinstance(record, dict) and record.get('type') == 'file' and record.get('sha256') == digest
            and record.get('mode') == mode and record.get('uid') == record.get('gid') == 0
            and 'hardlinks' not in record and (size is None or record.get('size_bytes') == size)
            and plain_xattrs(record), 'Installed prepared file differs in content or metadata')


def unchanged_metadata(original, configured, *, content=False):
    omit = {'sha256', 'size_bytes'} if content else set()
    require({key: value for key, value in original.items() if key not in omit}
            == {key: value for key, value in configured.items() if key not in omit},
            'Existing file or directory metadata changed outside the permitted delta')


def no_runtime_or_diagnostic(filesystem):
    root = filesystem['rootfs']; boot = filesystem['bootfs']
    for name in ('var/lib/inky-studio', 'var/lib/inky-studio/photos'):
        value = root.get(name)
        require(isinstance(value, dict) and value.get('type') == 'directory' and value.get('mode') == '0755'
                and value.get('uid') == value.get('gid') == 1000, 'Expected empty app-owned data directories missing')
    for name, record in root.items():
        require('inkyos-sd-diagnostic' not in name and name not in {
                    'usr/local/lib/inkyos/sd-diagnostic.py', 'etc/inkyos-diagnostic.json',
                    'etc/systemd/system/inkyos-test-lan.service', 'etc/systemd/system/inkyos-test-lan.timer'},
                'Diagnostic timer, hook or payload present in TEST LAN export')
        require(not name.startswith(('var/lib/inky-network', 'run/inky-network/'))
                and name not in {'var/lib/inkyos/system.json', 'var/lib/systemd/random-seed'}
                and not name.startswith('etc/ssh/ssh_host_'), 'Runtime state or identity present in prepared image')
        if name == 'var/lib/inky-studio' or name.startswith('var/lib/inky-studio/'):
            require(name in {'var/lib/inky-studio', 'var/lib/inky-studio/photos'}
                    and record['type'] == 'directory', 'Application state or content present in prepared image')
        if name.startswith(('etc/NetworkManager/system-connections/', 'run/NetworkManager/system-connections/')):
            raise ArtifactError('Prepared image contains a network profile')
        require(not (('.wants/' in name or '.requires/' in name)
                     and name.rsplit('/', 1)[-1] in {'inky-studio.service', 'inky-network.service'}),
                'Application service is unexpectedly enabled')
    for name in boot:
        require(name not in {'INKYOS-DIAGNOSTIC.txt', 'inkyos-diagnostics', 'ssh', 'ssh.txt',
                            'userconf', 'userconf.txt', 'user-data', 'network-config', 'meta-data'}
                and not name.startswith('inkyos-diagnostics/'), 'Diagnostic or provisioning hook present on bootfs')


def validate_inventory(parent, filesystem, configuration, source_blobs, protected, recipe, application):
    require(filesystem['schema_version'] == 2, 'Prepared export requires metadata schema 2')
    root, boot = filesystem['rootfs'], filesystem['bootfs']
    oldroot, oldboot = parent['rootfs'], parent['bootfs']
    no_runtime_or_diagnostic(filesystem)
    for path, (digest, mode) in overlay.STATIC_PARENT_FILES.items():
        regular(root.get(path), digest, format(mode, '04o'))
    for path, data in (
        ('etc/machine-id', b'uninitialized\n'),
        ('home/inky/inky-studio/server/SOURCE_COMMIT', (application['source_commit'] + '\n').encode()),
        ('var/lib/NetworkManager/NetworkManager.state', b'[main]\nWirelessEnabled=false\n'),
    ):
        record = root.get(path)
        require(isinstance(record, dict) and record.get('type') == 'file' and record.get('sha256') == sha(data)
                and record.get('size_bytes') == len(data), 'Prepared identity, application pin or Wi-Fi state changed')
    for name, expected in protected.items():
        section, _, path = name.partition('/')
        original, current = parent[section + 'fs'].get(path), filesystem[section + 'fs'].get(path)
        require(isinstance(current, dict) and current.get('type') == 'file'
                and current.get('sha256') == expected and current == original,
                'Protected boot/grow file changed from parent')
    allowed_root = {METADATA_PATH}
    for name, (path, mode) in overlay.PAYLOADS.items():
        data = source_blobs[name]
        regular(root.get(path), configuration['source_file_sha256'][name], format(mode, '04o'), size=len(data))
        require(path not in oldroot, 'Prepared payload already existed in parent')
        allowed_root.add(path)
    for unit in overlay.MASKS:
        path = 'etc/systemd/system/' + unit
        record = root.get(path)
        require(isinstance(record, dict) and record.get('type') == 'symlink' and record.get('target') == '/dev/null'
                and record.get('uid') == record.get('gid') == 0 and record.get('mode') == '0777'
                and 'hardlinks' not in record and plain_xattrs(record), 'Required application, SSH or update mask absent')
        allowed_root.add(path)
    require(configuration.get('protected_boot_grow_sha256') == protected,
            'Configuration protected-file hashes differ from preserved inventory')
    # This pure constructor does not read or import target code. Bind every
    # generated marker field, including its inactive/nonfactory status.
    metadata = overlay.expected_metadata(configuration['parent_image_sha256'],
        configuration['source_file_sha256'], recipe, configuration['recipe_inputs_sha256'], '', protected,
        application=application)
    metadata['boot_config_delta'] = configuration['boot_config_delta']
    metadata_raw = (json.dumps(metadata, indent=2, sort_keys=True) + '\n').encode()
    require(sha(metadata_raw) == configuration['marker_sha256'], 'Prepared marker contradicts its declared provenance')
    regular(root.get(METADATA_PATH), configuration['marker_sha256'], '0644', size=len(metadata_raw))
    require(METADATA_PATH not in oldroot, 'Prepared metadata already existed in parent')
    delta = configuration['boot_config_delta']
    require(isinstance(oldboot.get('config.txt'), dict) and oldboot['config.txt'].get('sha256') == delta['parent_sha256']
            and isinstance(boot.get('config.txt'), dict) and boot['config.txt'].get('sha256') == delta['configured_sha256'],
            'Boot configuration hashes differ from declared parent/configured values')
    require(oldboot['config.txt']['type'] == boot['config.txt']['type'] == 'file', 'Boot configuration must remain a file')
    unchanged_metadata(oldboot['config.txt'], boot['config.txt'], content=True)
    possible_parents = set()
    for path in allowed_root:
        possible_parents.update(str(parent) for parent in PurePosixPath(path).parents if str(parent) != '.')
    for path in set(oldroot) | set(root):
        original, current = oldroot.get(path), root.get(path)
        if original == current:
            continue
        require(current is not None, 'Unexpected rootfs removal: ' + path)
        if path in allowed_root:
            continue
        require(original is None and path in possible_parents and current.get('type') == 'directory'
                and current.get('uid') == current.get('gid') == 0 and current.get('mode') == '0755'
                and plain_xattrs(current), 'Forbidden rootfs delta: ' + path)
    removed = configuration['removed_pending_boot_artifacts']
    require(set(oldboot) - set(boot) == set(removed), 'Bootfs removals differ from explicit configuration declaration')
    for path in set(oldboot) | set(boot):
        original, current = oldboot.get(path), boot.get(path)
        if original == current or path == 'config.txt':
            continue
        require(path in removed and original is not None and original.get('type') == 'file' and current is None,
                'Forbidden bootfs delta: ' + path)
    require(not any(name.casefold().startswith(('recovery.', 'pieeprom', 'vl805')) for name in boot),
            'Pending bootloader artifact remains')


def load_export(directory, *, verify_images=True):
    export = artifacts.ExportDirectory(directory)
    try:
        manifest = validate_manifest(artifacts.parse_json(export.read('manifest.json')))
        recipe_raw = export.read('recipe-inputs.json')
        recipe = artifacts.validate_recipe(artifacts.parse_json(recipe_raw))
        require(artifacts.canonical(recipe) == artifacts.canonical(manifest['recipe']), 'Recipe metadata differs from export')
        reports = {}
        for name, expected in manifest['reports'].items():
            raw = export.read(name)
            require(sha(raw) == expected, 'Report SHA-256 mismatch: ' + name)
            reports[name] = raw
        diagnostic.validate_archive(reports['recipe.tar'], recipe)
        parent_manifest, parent_filesystem = diagnostic.validate_parent(reports, manifest)
        for name in INHERITED_RECIPE_FILES:
            require(artifacts.valid_hash(recipe['files'].get(name))
                    and recipe['files'][name] == parent_manifest['recipe']['files'].get(name),
                    'Inherited base/package/application audit source changed')
        protected = diagnostic.validate_static(reports, manifest)
        configuration = validate_configuration(reports, manifest, recipe_raw)
        source_blobs = archived_bytes(reports['recipe.tar'], overlay.PAYLOADS)
        filesystem = artifacts.validate_filesystem(artifacts.parse_json(reports['filesystem-manifest.json']))
        validate_inventory(parent_filesystem, filesystem, configuration, source_blobs, protected, recipe, manifest['application'])
        inspected = artifacts.parse_json(reports['image-inspection.json'])
        image = inspected.get('image') if isinstance(inspected, dict) else None
        require(isinstance(image, dict) and image.get('sha256') == manifest['image']['sha256']
                and type(image.get('size_bytes')) is int and image['size_bytes'] == manifest['image']['size_bytes'],
                'Image inspection differs from prepared image')
        export.image(manifest['image'], verify_hash=verify_images)
    finally:
        export.close()
    report = {
        'schema_version': 1, 'scope': 'local-test-lan-prepared-export-integrity', 'passed': True,
        'image_sha256_verified': verify_images, 'recipe_source_hashes_verified': True,
        'declared_reports_verified': sorted(reports), 'parent_image_sha256': manifest['parent']['image_sha256'],
        'filesystem_delta_allowlist_verified': True, 'protected_boot_grow_files_verified': len(PROTECTED_FILES),
        'authenticity_verified': False, 'hardware_qualified': False, 'release_qualified': False,
        'no_active_application': True, 'ready_for_activation': False,
        'limits': [
            'Unsigned local hashes establish consistency, not independent authenticity.',
            'The parent image was checked when building; its bytes are not retained or rehashed here.',
            'Reports and archived recipe sources are checked; build commands and static tests are not rerun.',
            'Filesystem inventories are not regenerated from image bytes by this verifier.',
            'No boot, SD, Pi, display, radio, operator access or application activation is qualified.',
        ],
    }
    if not verify_images:
        report['limits'].append('Image bytes were not hashed; only regular-file type and size were checked.')
    return {'manifest': manifest, 'filesystem': filesystem, 'report': report}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--output', type=Path, help='New integrity receipt outside the input export')
    args = parser.parse_args(argv)
    try:
        result = load_export(args.directory)['report']
        if args.output:
            artifacts.write_report(args.output, result, [args.directory])
        else:
            print(json.dumps(result, indent=2, sort_keys=True))
    except (ArtifactError, OSError, ValueError, TypeError, KeyError, tarfile.TarError) as error:
        print(f'verify-test-lan: {error}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
