#!/usr/bin/env python3
"""Content/ownership manifest for a generic build tree; never follow symlinks.

Only called before any boot of a pristine prototype. Do not use on personal
runtime filesystems. Timestamps and filesystem allocation are intentionally
excluded: this compares content, not byte-for-byte disk reproducibility.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat


def inventory(root):
    records = {}
    def visit(directory, prefix):
        for item in sorted(os.scandir(directory), key=lambda entry: entry.name):
            path = prefix + item.name
            info = item.stat(follow_symlinks=False)
            record = {'mode': format(stat.S_IMODE(info.st_mode), '04o'),
                      'uid': info.st_uid, 'gid': info.st_gid}
            if stat.S_ISLNK(info.st_mode):
                record.update(type='symlink', target=os.readlink(item.path))
            elif stat.S_ISDIR(info.st_mode):
                record['type'] = 'directory'
                visit(item.path, path + '/')
            elif stat.S_ISREG(info.st_mode):
                with open(item.path, 'rb') as stream:
                    record.update(type='file', size_bytes=info.st_size,
                                  sha256=hashlib.file_digest(stream, 'sha256').hexdigest())
            else:
                record.update(type='special', device=info.st_rdev)
            records[path] = record
    visit(root, '')
    return records


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--rootfs', type=Path, required=True)
    p.add_argument('--bootfs', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    result = {'schema_version': 1, 'scope': 'content-without-timestamps',
              'rootfs': inventory(a.rootfs), 'bootfs': inventory(a.bootfs)}
    with a.output.open('x') as output:
        json.dump(result, output, sort_keys=True, separators=(',', ':'))
        output.write('\n')
