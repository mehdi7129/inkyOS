#!/usr/bin/env python3
"""Compare a v2 enrollment through existing READ ONLY ext4/FAT mounts.

No mounting, image read, target-code execution, private-key read or connection.
An optional new private output directory receives context.json and known_hosts
only after a native comparison passes. It is root-owned; a later private export
must give it to the operator before prepare-test-access-capsule.py can use it.
Unsigned local consistency is not authenticity, boot or hardware attestation.
"""
import sys
sys.dont_write_bytecode = True

import argparse
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import tarfile


def module(name, filename):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


legacy = module('_access_return_readonly_primitives', 'verify-test-enrollment-return.py')
export_contract = module('_access_return_export_contract', 'verify-test-access.py')
policy = export_contract.overlay.policy
runtime = export_contract.overlay.runtime
ReadTree, readonly_mount = legacy.ReadTree, legacy.readonly_mount
require, digest = legacy.require, legacy.digest
PROFILE, STATE, PUBLIC_KEY, PRIVATE_KEY, REPORT = (
    legacy.PROFILE, legacy.STATE, legacy.PUBLIC_KEY, legacy.PRIVATE_KEY, legacy.REPORT)
RUNTIME = runtime.SCRIPT_PATH.lstrip('/')
MANIFEST = runtime.MANIFEST_PATH.lstrip('/')
SYSTEM = 'var/lib/inkyos/system.json'
HOSTNAME = 'etc/hostname'
APPLICATION_MANIFEST = 'usr/local/share/inkyos/inky-studio-manifest-v1.json'
MARKER = 'etc/inkyos-test-lan.json'
APPLICATION_FILES = (APPLICATION_MANIFEST, MARKER)
CACHE = 'var/lib/inkyos-test-access'
CHECKS = legacy.CHECKS + (
    'state_canonical', 'access_manifest_metadata', 'access_manifest_canonical',
    'access_manifest_matches_expected_bytes', 'access_manifest_profile_report_binding',
    'installed_payloads_metadata', 'installed_payloads_binding', 'reviewed_application_binding',
    'application_metadata', 'application_installed_binding', 'system_identity_private_metadata',
    'system_identity_schema', 'system_hostname_binding', 'access_not_started',
)
LIMITS = [
    'Unsigned local files establish consistency, not independent authenticity.',
    'Expected image bytes are not read or hashed; only metadata and size are checked.',
    'Inventories are not regenerated; only the declared access payloads and two application metadata files are rehashed.',
    'Runtime execution, boot duration, shutdown and physical identity are not attested.',
    'Radio and panel observations do not qualify country application or hardware.',
    'No capsule is signed and no network, SSH, application activation or release is authorized.',
    'Read-only applies to the observed mounts; other writable views are not excluded.',
    'Read bounds and deadlines cannot interrupt a kernel-blocked filesystem read.',
    'Context output is root-owned; controlled private transfer to the signing operator is a separate step.',
]


def expected_export(tree):
    """Validate the new export independently; never redirect the v1 comparator."""
    contract, artifacts, lan = export_contract, export_contract.artifacts, export_contract.lan
    manifest_raw = tree.read('manifest.json', limit=1024 * 1024)
    manifest = contract.validate_manifest(policy.strict_json(manifest_raw))
    recipe_raw = tree.read('recipe-inputs.json', limit=1024 * 1024)
    recipe = artifacts.validate_recipe(policy.strict_json(recipe_raw))
    require(recipe == manifest['recipe'])
    names = set(manifest['reports']) | {'manifest.json', 'recipe-inputs.json'}
    sizes = {name: tree.info(name).st_size for name in names}
    require(all(size <= (legacy.MAX_ARCHIVE if name == 'recipe.tar' else legacy.MAX_PROOF)
                for name, size in sizes.items()) and sum(sizes.values()) <= legacy.MAX_TOTAL)
    reports = {name: tree.read(name, limit=legacy.MAX_ARCHIVE if name == 'recipe.tar' else legacy.MAX_PROOF,
                              mode=0o600 if name == 'recipe.tar' else None)
               for name in manifest['reports']}
    require(all(digest(raw) == manifest['reports'][name] for name, raw in reports.items()))
    for name, raw in reports.items():
        if name.endswith('.json'):
            policy.strict_json(raw)
    contract.diagnostic.validate_archive(reports['recipe.tar'], recipe)
    with tarfile.open(fileobj=io.BytesIO(reports['recipe.tar']), mode='r:') as archive:
        private = archive.getmember('recipe/' + contract.overlay.PRIVATE_PROFILE)
        require(private.mode == 0o600 and private.uid == private.gid == 0)
    parent, inventory = contract.validate_parent(reports, manifest)
    require(all(recipe['files'].get(name) == parent['recipe']['files'].get(name)
                for name in contract.INHERITED_RECIPE_FILES))
    contract.diagnostic.validate_static(reports, manifest)
    contract.validate_prepared_constraints(reports['qualification-prepared.json'], inventory)
    configuration = contract.validate_configuration(reports, manifest, recipe_raw)
    blobs = lan.archived_bytes(reports['recipe.tar'], set(contract.overlay.PAYLOADS)
                               | {contract.overlay.PRIVATE_PROFILE, contract.overlay.PRIVATE_MANIFEST})
    profile_raw = contract.private_profile(blobs, reports, manifest_raw, recipe_raw)
    filesystem = artifacts.validate_filesystem(policy.strict_json(reports['filesystem-manifest.json']))
    contract.validate_inventory(inventory, filesystem, configuration, blobs)
    inspected = policy.strict_json(reports['image-inspection.json'])
    image = inspected.get('image') if type(inspected) is dict else None
    require(type(image) is dict and image.get('sha256') == manifest['image']['sha256']
            and type(image.get('size_bytes')) is int and image['size_bytes'] == manifest['image']['size_bytes'])
    require(tree.info(manifest['image']['filename'], mode=0o600).st_size == manifest['image']['size_bytes'])
    return {'profile_bytes': profile_raw, 'profile_sha256': digest(profile_raw),
            'runtime_sha256': recipe['files']['scripts/test-access-enrollment.py'],
            'manifest_bytes': blobs[contract.overlay.PRIVATE_MANIFEST],
            'payloads': {path: {'sha256': digest(blobs[name]), 'mode': mode}
                         for name, (path, mode) in contract.overlay.PAYLOADS.items()},
            'application_files': {path: filesystem['rootfs'][path] for path in APPLICATION_FILES}}


def validate_report(value):
    require(type(value) is dict and set(value) == runtime.REPORT_FIELDS
            and type(value['schema_version']) is int and value['schema_version'] == 2
            and value['kind'] == 'test-lan-enrollment-report' and value['state'] == 'enrolled'
            and type(value['live_evidence']) is bool and all(value[key] is False for key in policy.FALSE_FIELDS)
            and policy.public_key(value['host_public_key']) is not None
            and all(type(value[key]) is str and re.fullmatch(r'[0-9a-f]{64}', value[key]) is not None
                    for key in ('challenge', 'profile_sha256', 'host_public_key_sha256',
                                'runtime_source_sha256', 'access_runtime_manifest_sha256'))
            and value['challenge'] != '0' * 64
            and all(type(value[key]) is str for key in ('application_source_commit',
                        'application_manifest_sha256', 'parent_image_sha256')))


class NativeAdapter(legacy.NativeAdapter):
    def __init__(self, rootfs, bootfs, expected, context_output=None):
        super().__init__(rootfs, bootfs, expected)
        self.context_output = context_output

    def expected(self):
        self.expected_value = expected_export(self.export)
        return self.expected_value

    def output_device_allowed(self, parent):
        # A different lexical path can still be a writable bind of an image
        # filesystem. Private output belongs on the observer host, never there.
        return os.fstat(parent.fd).st_dev not in {
            os.fstat(self.root.fd).st_dev, os.fstat(self.boot.fd).st_dev}

    def close(self):
        failed = False
        for tree in reversed(self.trees):
            try:
                tree.close()
            except Exception:
                failed = True
        if failed:
            raise OSError('read_only_cleanup_failed')

    def returned(self):
        root, boot = self.root, self.boot
        private = root.info(PRIVATE_KEY, mode=0o600, private=True)
        require(0 < private.st_size <= 4096)
        raw = {
            'profile': root.read(PROFILE, limit=4096, mode=0o600, private=True),
            'state': root.read(STATE, limit=4096, mode=0o600, private=True),
            'pub': root.read(PUBLIC_KEY, limit=256, mode=0o644, private=True),
            'report': boot.read(REPORT, limit=32768),
            'manifest': root.read(MANIFEST, limit=65536, mode=0o644),
            'system': root.read(SYSTEM, limit=4096, mode=0o600, private=True),
            'hostname': root.read(HOSTNAME, limit=256, mode=0o644),
        }
        # Paths come exclusively from the locally validated export whitelist,
        # never from an untrusted returned manifest. Target bytes are not exec'd.
        payloads = {path: root.read(path, limit=65536, mode=row['mode'])
                    for path, row in self.expected_value['payloads'].items()}
        application = {}
        for path, row in self.expected_value['application_files'].items():
            require(row['type'] == 'file' and row['uid'] == row['gid'] == 0)
            application[path] = root.read(path, limit=65536, mode=int(row['mode'], 8))
        clean = (root.names(str(PurePosixPath(PROFILE).parent), limit=3, private=True)
                    == {'profile.json', 'ssh_host_ed25519_key', 'ssh_host_ed25519_key.pub'}
                 and root.names(str(PurePosixPath(STATE).parent), limit=1, private=True) == {'state.json'}
                 and boot.absent('.' + REPORT + '.tmp'))
        boot_names = boot.names('.', limit=4096)
        access_absent = (root.names(CACHE, limit=0, private=True) == set()
                         and root.absent('etc/inkyos-test-operator.json')
                         and boot_names is not None
                         and not any(name.lower().startswith(('inkyacc.', '.inkyacc.')) for name in boot_names))
        return raw, payloads, application, clean, access_absent


def summary(*, native=False):
    result = legacy.summary(native=native)
    result.update(kind='test-access-return-comparison', scope='offline-readonly-v2-enrollment-consistency',
                  checks=dict.fromkeys(CHECKS, False), limits=list(LIMITS), context_written=False,
                  private_output_files_written=0)
    return result


def _context(profile, profile_hash, host_wire_hash, manifest_hash):
    return {'schema_version': 1, 'kind': 'verified-test-access-context',
            'bindings': {'profile_sha256': profile_hash, 'challenge': profile['challenge'],
                'host_public_key_sha256': host_wire_hash,
                'application_source_commit': profile['application_source_commit'],
                'application_manifest_sha256': profile['application_manifest_sha256'],
                'access_runtime_manifest_sha256': manifest_hash},
            'operator_public_key': profile['operator_public_key']}


def _write_context(adapter, context, known_hosts):
    """Exclusive durable private output; failures preserve their own artifacts."""
    require(type(adapter) is NativeAdapter and adapter.environment() is True)
    path = Path(os.fspath(adapter.context_output))
    require(path.is_absolute() and str(path) == os.fspath(adapter.context_output)
            and '..' not in path.parts and path.name not in {'', '.', '..'})
    require(all(path != Path(item) and path not in Path(item).parents and Path(item) not in path.parents
                for item in adapter.paths))
    parent = ReadTree(str(path.parent), private=True)
    directory = output = None
    try:
        require(adapter.output_device_allowed(parent) is True)
        require(adapter.stable() is True)
        os.mkdir(path.name, mode=0o700, dir_fd=parent.fd)
        directory = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent.fd)
        legacy.metadata(os.fstat(directory), 0, 0, directory=True, mode=0o700)
        for name, raw in (('context.json', policy.canonical(context)), ('known_hosts', known_hosts)):
            output = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
            os.fchmod(output, 0o600)
            legacy.metadata(os.fstat(output), 0, 0, mode=0o600)
            offset = 0
            while offset < len(raw):
                size = os.write(output, raw[offset:])
                require(size > 0)
                offset += size
            os.fsync(output)
            os.lseek(output, 0, os.SEEK_SET)
            require(os.read(output, len(raw) + 1) == raw)
            require(legacy.stamp(os.fstat(output)) == legacy.stamp(os.stat(name, dir_fd=directory,
                                                                        follow_symlinks=False)))
            os.close(output)
            output = None
        require(set(os.listdir(directory)) == {'context.json', 'known_hosts'})
        require(adapter.stable() is True)
        for name, raw in (('context.json', policy.canonical(context)), ('known_hosts', known_hosts)):
            output = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                before = os.fstat(output)
                legacy.metadata(before, 0, 0, mode=0o600)
                require(before.st_size == len(raw) and os.read(output, len(raw) + 1) == raw
                        and legacy.stamp(before) == legacy.stamp(os.fstat(output))
                        == legacy.stamp(os.stat(name, dir_fd=directory, follow_symlinks=False)))
            finally:
                os.close(output)
                output = None
        require(legacy.stamp(os.fstat(directory)) == legacy.stamp(os.stat(path.name, dir_fd=parent.fd,
                                                                       follow_symlinks=False)))
        os.fsync(directory)
        os.fsync(parent.fd)
    finally:
        for fd in (output, directory):
            if fd is not None:
                os.close(fd)
        parent.close()


def compare(adapter):
    native = type(adapter) is NativeAdapter
    result = summary(native=native)
    checks = result['checks']
    stage = 'compare'
    try:
        require(adapter.environment() is True)
        adapter.open()
        mounted = adapter.mounts()
        require(type(mounted) is dict and set(mounted) == set(legacy.CHECKS[:2])
                and all(type(value) is bool for value in mounted.values()))
        checks.update(mounted)
        if not all(mounted.values()):
            result.update(status='FAIL', error='readonly_mount_required')
            return result, 1
        result['native_readonly_evidence'] = native
        expected = adapter.expected()
        checks['expected_export_consistent'] = checks['expected_image_stat_checked'] = True
        raw, payloads, application, clean, access_absent = adapter.returned()
        require(type(raw) is dict and set(raw) == {'profile', 'state', 'pub', 'report', 'manifest', 'system', 'hostname'}
                and all(type(value) is bytes for value in raw.values())
                and type(payloads) is dict and set(payloads) == set(expected['payloads'])
                and type(application) is dict and set(application) == set(APPLICATION_FILES)
                and all(type(value) is bytes for value in (*payloads.values(), *application.values()))
                and type(clean) is bool and type(access_absent) is bool)
        profile, state, report, manifest, system = (policy.strict_json(raw[key])
            for key in ('profile', 'state', 'report', 'manifest', 'system'))
        require(policy.validate_profile(profile))
        legacy.validate_state(state)
        validate_report(report)
        for name in ('profile_private_metadata', 'state_private_metadata', 'host_public_metadata',
                     'host_private_metadata_only', 'runtime_metadata', 'access_manifest_metadata',
                     'installed_payloads_metadata', 'application_metadata', 'system_identity_private_metadata'):
            checks[name] = True
        profile_hash, manifest_hash = digest(raw['profile']), digest(raw['manifest'])
        checks['profile_canonical'] = raw['profile'] == policy.canonical(profile)
        checks['profile_matches_expected_bytes'] = raw['profile'] == expected['profile_bytes']
        checks['state_canonical'] = raw['state'] == policy.canonical(state)
        checks['state_enrolled'] = state['state'] == 'enrolled'
        checks['state_profile_binding'] = state['profile_sha256'] == profile_hash == expected['profile_sha256']
        checks['public_report_schema'] = True
        checks['public_report_live_claim'] = report['live_evidence'] is True
        checks['report_profile_binding'] = (report['profile_sha256'] == profile_hash == expected['profile_sha256']
            and all(report[key] == profile[key] for key in ('challenge', 'application_source_commit',
                    'application_manifest_sha256', 'parent_image_sha256')))
        match = re.fullmatch(rb'(ssh-ed25519 [A-Za-z0-9+/]{68}) inkyos-test-host\n', raw['pub'])
        require(match is not None)
        host = match[1].decode('ascii')
        wire = policy.public_key(host)
        require(wire is not None)
        wire_hash = digest(wire)
        checks['host_public_binding'] = host == report['host_public_key'] and wire_hash == report['host_public_key_sha256']
        checks['runtime_binding'] = digest(payloads[RUNTIME]) == expected['runtime_sha256'] == report['runtime_source_sha256']
        checks['observations_closed'] = legacy.public_observations(report['observations'])
        checks['no_partial_artifacts'] = clean
        checks['access_manifest_canonical'] = raw['manifest'] == policy.canonical(manifest)
        checks['access_manifest_matches_expected_bytes'] = raw['manifest'] == expected['manifest_bytes']
        checks['access_manifest_profile_report_binding'] = (
            manifest_hash == profile['access_runtime_manifest_sha256'] == report['access_runtime_manifest_sha256'])
        checks['installed_payloads_binding'] = all(digest(raw) == expected['payloads'][path]['sha256']
                                                    for path, raw in payloads.items())
        pins = {'application_source_commit': policy.SOURCE, 'application_manifest_sha256': policy.MANIFEST_HASH,
                'parent_image_sha256': policy.PARENT_IMAGE_SHA256}
        marker = policy.strict_json(application[MARKER])
        checks['reviewed_application_binding'] = (type(manifest) is dict
            and all(profile[key] == report[key] == manifest.get(key) == value for key, value in pins.items())
            and digest(application[APPLICATION_MANIFEST]) == policy.MANIFEST_HASH
            and type(marker) is dict and marker.get('kind') == 'test-lan-prepared'
            and marker.get('state') == 'prepared-inactive' and marker.get('source_commit') == policy.SOURCE
            and marker.get('manifest_sha256') == policy.MANIFEST_HASH)
        checks['application_installed_binding'] = all(digest(raw) == expected['application_files'][path]['sha256']
                                                       for path, raw in application.items())
        checks['system_identity_schema'] = (type(system) is dict and set(system) == {'version', 'hostname'}
            and type(system['version']) is int and system['version'] == 1
            and type(system['hostname']) is str and re.fullmatch(r'inky-[0-9a-f]{32}', system['hostname']) is not None)
        checks['system_hostname_binding'] = (checks['system_identity_schema']
                                            and raw['hostname'] == (system['hostname'] + '\n').encode('ascii'))
        checks['access_not_started'] = access_absent
        checks['reads_stable'] = adapter.stable() is True
        result['passed'] = all(value is True for value in checks.values())
        result['status'] = 'PASS' if result['passed'] else 'FAIL'
        result['error'] = None if result['passed'] else 'return_inconsistent'
        if result['passed'] and getattr(adapter, 'context_output', None) is not None:
            stage = 'context'
            known_hosts = ('[' + system['hostname'] + '.local]:2222 ' + host + '\n').encode('ascii')
            _write_context(adapter, _context(profile, profile_hash, wire_hash, manifest_hash), known_hosts)
            result['context_written'] = True
            result['private_output_files_written'] = 2
        return result, 0 if result['passed'] else 1
    except FileNotFoundError:
        result.update(passed=False, status='FAIL', error='return_incomplete' if stage == 'compare' else 'context_output_refused')
        return result, 1
    except Exception:
        result.update(passed=False, status='INVALID', error='invalid_input' if stage == 'compare' else 'context_output_refused')
        return result, 2
    finally:
        try:
            adapter.close()
        except Exception:
            result.update(passed=False, status='INVALID', error='readonly_cleanup_failed', context_written=False)
            return result, 2


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise legacy.InvalidInput('invalid_input')


def main(argv=None):
    try:
        parser = Parser(description=__doc__, allow_abbrev=False)
        for name in ('rootfs', 'bootfs', 'expected-export'):
            parser.add_argument('--' + name, required=True)
        parser.add_argument('--context-output')
        args = parser.parse_args(argv)
        result, code = compare(NativeAdapter(args.rootfs, args.bootfs, args.expected_export, args.context_output))
    except Exception:
        result, code = summary(), 2
        result['error'] = 'invalid_input'
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == '__main__':
    sys.exit(main())
