#!/usr/bin/env python3
"""Check a derived SD diagnostic export without mounting, booting or flashing it."""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile


SPEC = importlib.util.spec_from_file_location('_sd_artifacts', Path(__file__).with_name('verify-artifacts.py'))
artifacts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifacts)
ArtifactError = artifacts.ArtifactError
REQUIRED_REPORTS = frozenset({
    'parent-manifest.json', 'parent-filesystem-manifest.json', 'parent-integrity.json', 'recipe.tar',
    'diagnostic-configuration.json', 'qualification-static.json',
    'qualification-application.json', 'application-manifest.json',
    'filesystem-manifest.json', 'image-inspection.json', 'systemd-verify.txt',
    'boot-preserved.sha256', 'fsck-ext4.txt', 'fsck-fat.txt',
})
PROTECTED_FILES = frozenset({
    'boot/cmdline.txt', 'boot/initramfs8', 'boot/initramfs_2712',
    'boot/kernel8.img', 'boot/kernel_2712.img', 'root/etc/fstab',
    'root/usr/lib/systemd/system/rpi-resize.service',
    'root/usr/lib/systemd/system/systemd-growfs-root.service',
    'root/usr/share/initramfs-tools/scripts/local-premount/resize_early',
    'root/usr/share/initramfs-tools/scripts/local-bottom/set_partuuid',
})
DIAGNOSTIC_PAYLOADS = {
    'diagnostic/sd-diagnostic.py': 'usr/local/lib/inkyos/sd-diagnostic.py',
    'diagnostic/inkyos-sd-diagnostic.service': 'etc/systemd/system/inkyos-sd-diagnostic.service',
    'diagnostic/inkyos-sd-diagnostic.timer': 'etc/systemd/system/inkyos-sd-diagnostic.timer',
}
DIAGNOSTIC_SOURCES = frozenset(DIAGNOSTIC_PAYLOADS) | {
    'scripts/configure-diagnostic-rootfs.py', 'scripts/configure-rootfs.py',
}
DIAGNOSTIC_MASKS = (
    'inky-studio.service', 'inky-network.service', 'ssh.service', 'ssh.socket', 'sshswitch.service',
    'rpi-eeprom-update.service', 'apt-daily.timer', 'apt-daily.service',
    'apt-daily-upgrade.timer', 'apt-daily-upgrade.service',
)
DIAGNOSTIC_CHECKS = frozenset({
    'application_runtime_masked', 'ssh_masked', 'firmware_and_package_updates_masked',
    'pending_bootloader_artifacts_absent', 'bootloader_update_disabled_directly',
    'wifi_disabled_diagnostic_only', 'boot_config_delta_matches', 'timer_enabled',
    'payload_hashes_match', 'payload_modes_match', 'auto_poweroff_after_success',
    'metadata_matches', 'not_booted', 'resize_hook_preserved', 'no_precreated_report',
    'diagnostic_marker_matches',
})


def require(condition, message):
    if not condition:
        raise ArtifactError(message)


def validate_manifest(value):
    require(isinstance(value, dict) and type(value.get('schema_version')) is int
            and value['schema_version'] == 1 and value.get('kind') == 'sd-diagnostic'
            and value.get('hardware_qualified') is False and value.get('release_qualified') is False
            and value.get('no_active_application') is True,
            'Expected an unqualified SD diagnostic with application explicitly inactive')
    artifacts.validate_recipe(value.get('recipe'))
    image = value.get('image')
    require(isinstance(image, dict) and set(image) == {'filename', 'size_bytes', 'sha256'}
            and artifacts.basename(image.get('filename')) and image['filename'].endswith('.img')
            and artifacts.integer(image.get('size_bytes')) and 0 < image['size_bytes'] <= artifacts.MAX_IMAGE_BYTES
            and artifacts.valid_hash(image.get('sha256')), 'Invalid diagnostic image record')
    parent = value.get('parent')
    require(isinstance(parent, dict) and set(parent) == {
            'kind', 'image_sha256', 'size_bytes', 'manifest_sha256'}
            and parent['kind'] == 'application-prototype'
            and artifacts.valid_hash(parent['image_sha256'])
            and artifacts.valid_hash(parent['manifest_sha256'])
            and type(parent['size_bytes']) is int and parent['size_bytes'] == image['size_bytes'],
            'Diagnostic must retain the application prototype parent image size and pin')
    app = value.get('application')
    require(isinstance(app, dict) and app.get('startup') == 'masked-pending-firstboot-contract'
            and app.get('release_qualified') is False,
            'Diagnostic application must remain masked and unqualified')
    reports = value.get('reports')
    require(isinstance(reports, dict) and REQUIRED_REPORTS <= set(reports) and len(reports) <= 64
            and all(artifacts.basename(name) and artifacts.valid_hash(digest) for name, digest in reports.items())
            and not {'manifest.json', 'recipe-inputs.json', image['filename']} & set(reports),
            'Missing diagnostic evidence or invalid report names/hashes')
    return value


def validate_archive(raw, recipe):
    """Hash the bounded whitelist snapshot in place; never extract archive entries."""
    expected = {'recipe/' + name: digest for name, digest in recipe['files'].items()}
    expected['recipe/recipe-inputs.json'] = None
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            require(member.name in expected and member.name not in seen and member.isfile()
                    and not member.linkname and 0 <= member.size <= artifacts.MAX_REPORT_BYTES,
                    'Recipe archive has an unexpected, duplicated or nonregular member')
            seen.add(member.name)
            stream = archive.extractfile(member)
            require(stream is not None, 'Recipe archive member cannot be read')
            with stream:
                data = stream.read(artifacts.MAX_REPORT_BYTES + 1)
            require(len(data) == member.size, 'Recipe archive member has invalid size')
            if expected[member.name] is None:
                require(artifacts.canonical(artifacts.parse_json(data)) == artifacts.canonical(recipe),
                        'Archived recipe metadata differs from the export')
            else:
                require(hashlib.sha256(data).hexdigest() == expected[member.name],
                        'Recipe source-file SHA-256 mismatch')
    require(seen == set(expected), 'Recipe archive omits declared source inputs')


def validate_parent(reports, manifest):
    raw = reports['parent-manifest.json']
    parent = artifacts.validate_build(artifacts.parse_json(raw))
    pin = manifest['parent']
    require(parent['kind'] == pin['kind'] and parent['image']['sha256'] == pin['image_sha256']
            and parent['image']['size_bytes'] == pin['size_bytes']
            and hashlib.sha256(raw).hexdigest() == pin['manifest_sha256']
            and artifacts.canonical(parent['application']) == artifacts.canonical(manifest['application']),
            'Parent manifest or application pin differs from diagnostic provenance')
    integrity = artifacts.parse_json(reports['parent-integrity.json'])
    require(isinstance(integrity, dict) and integrity.get('scope') == 'local-export-integrity'
            and integrity.get('passed') is True and integrity.get('image_sha256_verified') is True
            and integrity.get('authenticity_verified') is False and integrity.get('hardware_qualified') is False,
            'Parent integrity receipt must report its original unsigned, unqualified scope')
    require(manifest['recipe']['files'].get('parent-manifest.json') == pin['manifest_sha256'],
            'Parent manifest must be part of the diagnostic recipe snapshot')
    filesystem_raw = reports['parent-filesystem-manifest.json']
    require(hashlib.sha256(filesystem_raw).hexdigest() == parent['reports']['filesystem-manifest.json'],
            'Parent filesystem inventory differs from original parent manifest')
    filesystem = artifacts.validate_filesystem(artifacts.parse_json(filesystem_raw))
    require(filesystem['schema_version'] == 2, 'Parent filesystem metadata must use schema 2')
    return parent, filesystem


def validate_static(reports, manifest):
    gate = artifacts.parse_json(reports['qualification-static.json'])
    checks = gate.get('checks') if isinstance(gate, dict) else None
    require(isinstance(gate, dict) and gate.get('scope') == 'offline-system-prototype-contract'
            and gate.get('passed') is True and gate.get('failed_checks') == []
            and isinstance(checks, list) and checks
            and all(isinstance(check, dict) and isinstance(check.get('id'), str)
                    and check.get('passed') is True for check in checks)
            and len({check['id'] for check in checks}) == len(checks)
            and artifacts.REQUIRED_STATIC_CHECKS | {'BOOT_NO_COUNTRY'} <= {check['id'] for check in checks},
            'Diagnostic system static gate is inconsistent or incomplete')
    app = artifacts.parse_json(reports['qualification-application.json'])
    checks = app.get('checks') if isinstance(app, dict) else None
    require(isinstance(app, dict) and app.get('scope') == 'offline-application-prototype-contract'
            and app.get('passed') is True and app.get('failed_checks') == []
            and isinstance(checks, list) and checks
            and all(isinstance(check, dict) and isinstance(check.get('id'), str)
                    and check.get('passed') is True for check in checks)
            and len({check['id'] for check in checks}) == len(checks)
            and artifacts.APPLICATION_CHECKS <= {check['id'] for check in checks},
            'Diagnostic application static gate is inconsistent or incomplete')
    for key in ('source_commit', 'application_version', 'manifest_sha256'):
        require(app.get(key) == manifest['application'][key], 'Diagnostic static gate differs from app pin')
    source_raw = reports['application-manifest.json']
    source = artifacts.parse_json(source_raw)
    require(hashlib.sha256(source_raw).hexdigest() == manifest['application']['manifest_sha256']
            and all(source.get(key) == manifest['application'][key] for key in ('source_commit', 'application_version'))
            and manifest['recipe']['files'].get('application-manifest.json') == manifest['application']['manifest_sha256'],
            'Application source manifest differs from the inherited pin')
    protected = {}
    for line in reports['boot-preserved.sha256'].decode('ascii').splitlines():
        digest, separator, name = line.partition('  ')
        require(separator and name in PROTECTED_FILES and name not in protected and artifacts.valid_hash(digest),
                'Invalid protected boot/grow hash inventory')
        protected[name] = digest
    require(set(protected) == PROTECTED_FILES, 'Protected boot/grow inventory must include exactly ten files')
    return protected


def validate_diagnostic_configuration(reports, manifest, recipe_raw):
    value = artifacts.parse_json(reports['diagnostic-configuration.json'])
    require(isinstance(value, dict) and value.get('schema_version') == 1
            and value.get('scope') == 'offline-sd-diagnostic-configuration'
            and value.get('passed') is True and value.get('parent_image_sha256') == manifest['parent']['image_sha256']
            and value.get('application_started') is False and value.get('hardware_qualified') is False,
            'Diagnostic configuration must preserve its inert, unqualified scope and parent hash')
    checks = value.get('checks')
    require(isinstance(checks, dict) and DIAGNOSTIC_CHECKS <= set(checks)
            and all(result is True for result in checks.values()),
            'Diagnostic configuration PASS contradicts or omits required checks')
    sources = value.get('source_file_sha256')
    require(isinstance(sources, dict) and set(sources) == DIAGNOSTIC_SOURCES
            and all(artifacts.valid_hash(digest) and manifest['recipe']['files'].get(name) == digest
                    for name, digest in sources.items()),
            'Diagnostic payload source hashes differ from recipe sources')
    require(value.get('recipe_source_commit') == manifest['recipe']['source_commit']
            and type(value.get('recipe_worktree_dirty')) is bool
            and value['recipe_worktree_dirty'] == manifest['recipe']['worktree_dirty']
            and value.get('recipe_inputs_sha256') == hashlib.sha256(recipe_raw).hexdigest(),
            'Diagnostic configuration provenance differs from recipe metadata')
    delta = value.get('boot_config_delta')
    require(isinstance(delta, dict) and set(delta) == {'parent_sha256', 'configured_sha256', 'append'}
            and artifacts.valid_hash(delta['parent_sha256']) and artifacts.valid_hash(delta['configured_sha256'])
            and delta['append'] == '\n\n[all]\nbootloader_update=0\ndtoverlay=disable-wifi\n',
            'Diagnostic boot configuration delta must explicitly disable firmware updates and Wi-Fi')
    return value


def load_export(directory, *, verify_images=True):
    export = artifacts.ExportDirectory(directory)
    try:
        manifest = validate_manifest(artifacts.parse_json(export.read('manifest.json')))
        recipe_raw = export.read('recipe-inputs.json')
        recipe = artifacts.validate_recipe(artifacts.parse_json(recipe_raw))
        require(artifacts.canonical(recipe) == artifacts.canonical(manifest['recipe']),
                'Recipe metadata differs from diagnostic manifest')
        reports = {}
        for name, expected in manifest['reports'].items():
            raw = export.read(name)
            require(hashlib.sha256(raw).hexdigest() == expected, 'Report SHA-256 mismatch: ' + name)
            reports[name] = raw
        validate_archive(reports['recipe.tar'], recipe)
        _parent, parent_filesystem = validate_parent(reports, manifest)
        protected = validate_static(reports, manifest)
        configuration = validate_diagnostic_configuration(reports, manifest, recipe_raw)
        filesystem = artifacts.validate_filesystem(artifacts.parse_json(reports['filesystem-manifest.json']))
        require(filesystem['schema_version'] == 2, 'Diagnostic export requires complete metadata schema 2')
        for name, expected in protected.items():
            section, _separator, path = name.partition('/')
            record = filesystem[section + 'fs'].get(path)
            require(isinstance(record, dict) and record.get('type') == 'file' and record.get('sha256') == expected,
                    'Protected boot/grow file differs from filesystem inventory')
            original = parent_filesystem[section + 'fs'].get(path)
            require(isinstance(original, dict) and original.get('type') == 'file' and original.get('sha256') == expected,
                    'Protected boot/grow file differs from original parent filesystem')
        for name, path in DIAGNOSTIC_PAYLOADS.items():
            record = filesystem['rootfs'].get(path)
            require(isinstance(record, dict) and record.get('type') == 'file'
                    and record.get('sha256') == configuration['source_file_sha256'][name]
                    and record.get('uid') == 0 and record.get('gid') == 0
                    and record.get('mode') == ('0555' if name.endswith('.py') else '0644'),
                    'Installed diagnostic payload differs from the recipe')
        record = filesystem['bootfs'].get('config.txt')
        require(isinstance(record, dict) and record.get('type') == 'file'
                and record.get('sha256') == configuration['boot_config_delta']['configured_sha256'],
                'Diagnostic boot configuration differs from filesystem inventory')
        original = parent_filesystem['bootfs'].get('config.txt')
        require(isinstance(original, dict) and original.get('type') == 'file'
                and original.get('sha256') == configuration['boot_config_delta']['parent_sha256'],
                'Diagnostic boot configuration delta differs from original parent config')
        for unit in DIAGNOSTIC_MASKS:
            record = filesystem['rootfs'].get('etc/systemd/system/' + unit)
            require(isinstance(record, dict) and record.get('type') == 'symlink' and record.get('target') == '/dev/null',
                    'Diagnostic app, SSH or update policy is not masked in the filesystem inventory')
        record = filesystem['rootfs'].get('etc/systemd/system/timers.target.wants/inkyos-sd-diagnostic.timer')
        require(isinstance(record, dict) and record.get('type') == 'symlink'
                and record.get('target') == '/etc/systemd/system/inkyos-sd-diagnostic.timer',
                'Diagnostic timer is not enabled in the filesystem inventory')
        inspected = artifacts.parse_json(reports['image-inspection.json'])
        image = inspected.get('image') if isinstance(inspected, dict) else None
        require(isinstance(image, dict) and image.get('sha256') == manifest['image']['sha256']
                and type(image.get('size_bytes')) is int and image['size_bytes'] == manifest['image']['size_bytes'],
                'Image inspection differs from exported diagnostic image')
        export.image(manifest['image'], verify_hash=verify_images)
    finally:
        export.close()
    report = {'schema_version': 1, 'scope': 'local-sd-diagnostic-export-integrity', 'passed': True,
              'image_sha256_verified': verify_images, 'recipe_source_hashes_verified': True,
              'declared_reports_verified': sorted(reports), 'parent_image_sha256': manifest['parent']['image_sha256'],
              'authenticity_verified': False, 'hardware_qualified': False, 'release_qualified': False,
              'no_active_application': True,
              'limits': ['Unsigned local hashes establish consistency, not independent authenticity.',
                         'The parent image was verified when building; its bytes are not retained or rehashed here.',
                         'Reports and archived recipe sources are checked; the build and static tests are not rerun.',
                         'Filesystem inventory is not regenerated from image bytes by this verifier.',
                         'No boot, SD, Pi, display, radio or application runtime qualification is established.']}
    if not verify_images:
        report['limits'].append('Image bytes were not hashed; only file type and size were checked.')
    return {'manifest': manifest, 'filesystem': filesystem, 'report': report}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--output', type=Path, help='New receipt outside the input export')
    args = parser.parse_args(argv)
    try:
        result = load_export(args.directory)['report']
        if args.output:
            artifacts.write_report(args.output, result, [args.directory])
        else:
            print(json.dumps(result, indent=2, sort_keys=True))
    except (ArtifactError, OSError, ValueError, TypeError, KeyError, tarfile.TarError) as error:
        print(f'verify-sd-diagnostic: {error}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
