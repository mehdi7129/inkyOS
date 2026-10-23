#!/usr/bin/env python3
"""Build the self-contained local macOS app from an explicitly selected InkyOS image."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import plistlib

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--destination', type=Path, default=Path.home() / 'Applications/inkyImager.app')
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    assert manifest['schemaVersion'] == 1 and manifest['configurationFile'] == 'inky-imager.json'
    assert manifest['imageFile'] == 'InkyOS.img.xz'
    assert digest(args.image) == manifest['compressedSHA256'], 'Selected image checksum mismatch'
    scratch = Path.home() / 'Library/Caches/inkyImager-build'
    command = ['swift', 'build', '--scratch-path', str(scratch), '-c', 'release']
    subprocess.run(command, cwd=ROOT, check=True)
    products = Path(subprocess.check_output(command + ['--show-bin-path'], cwd=ROOT).decode().strip())
    destination = args.destination.resolve()
    assert destination.suffix == '.app' and destination.name == 'inkyImager.app'
    assert not destination.exists(), 'Choose a new destination; do not overwrite an installed app'
    destination.parent.mkdir(parents=True, exist_ok=True)
    contents = destination / 'Contents'
    macos = contents / 'MacOS'
    resources = contents / 'Resources'
    macos.mkdir(parents=True)
    resources.mkdir()
    for executable in ('inkyImager', 'inkyImagerHelper'):
        shutil.copyfile(products / executable, macos / executable)
        (macos / executable).chmod(0o755)
        linked = subprocess.check_output(['/usr/bin/otool', '-L', str(macos / executable)]).decode()
        assert '/opt/homebrew/' not in linked and '/usr/local/' not in linked, 'Developer-only dynamic dependency'
    # APFS clone avoids another physical copy of the large image on the development Mac.
    target_image = resources / 'InkyOS.img.xz'
    clone = subprocess.run(['/bin/cp', '-c', str(args.image.resolve()), str(target_image)], capture_output=True)
    if clone.returncode:
        assert not target_image.exists()
        shutil.copyfile(args.image, target_image)
    assert digest(target_image) == manifest['compressedSHA256']
    (resources / 'InkyOS.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    (resources / 'NOTICE.txt').write_text('inkyImager uses the macOS system liblzma for XZ decoding.\nInkyOS includes Raspberry Pi OS and Inky Studio; copyright notices are retained in the image.\n')
    iconset = scratch / 'inkyImager.iconset'
    subprocess.run(['xcrun', 'swift', str(ROOT / 'scripts/draw-icon.swift'), str(iconset)], check=True)
    subprocess.run(['/usr/bin/iconutil', '-c', 'icns', str(iconset), '-o', str(resources / 'AppIcon.icns')], check=True)
    info = {'CFBundleName': 'inkyImager', 'CFBundleDisplayName': 'inkyImager',
            'CFBundleIdentifier': 'fr.mehdiguiard.inkyimager', 'CFBundleExecutable': 'inkyImager',
            'CFBundlePackageType': 'APPL', 'CFBundleShortVersionString': '0.1.1',
            'CFBundleVersion': '2', 'LSMinimumSystemVersion': '14.0',
            'CFBundleIconFile': 'AppIcon',
            'NSHighResolutionCapable': True,
            'NSRemovableVolumesUsageDescription': 'inkyImager prépare uniquement la carte SD que vous sélectionnez.',
            'NSHumanReadableCopyright': 'Copyright © 2026 Mehdi Guiard'}
    with (contents / 'Info.plist').open('wb') as stream:
        plistlib.dump(info, stream)
    subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', str(macos / 'inkyImagerHelper')], check=True)
    subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', str(destination)], check=True)
    subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(destination)], check=True)
    print(json.dumps({'app': str(destination), 'image_sha256': manifest['imageSHA256'],
                      'compressed_sha256': manifest['compressedSHA256'], 'signed_local': True,
                      'notarized': False, 'sd_written': False}, sort_keys=True))


if __name__ == '__main__':
    main()
