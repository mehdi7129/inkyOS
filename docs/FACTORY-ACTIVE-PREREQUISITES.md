# Offline prerequisites for a future active factory profile

`scripts/configure-factory-active-prerequisites.py` is a standalone offline build
primitive. It prepares the persistent accounts and parents that the existing
`staging/bootstrap/writer-parents.py` expects. It is deliberately **not called by
the file-only `factory-assembly` recipe**, and does not change that profile's
inputs, reports or qualifications.

## Invocation and allowed input

Only invoke this command in the dedicated Linux builder, as real/effective/saved
root with root GID, against an exclusive private, unbooted rootfs:

```sh
python3 -I -B -S scripts/configure-factory-active-prerequisites.py \
  --rootfs /var/lib/inkyos-build/factory-image.EXAMPLE/root \
  --helper-uid 991 --provisioning-gid 992 --check-only
```

Replace `EXAMPLE` with the actual new builder workspace suffix. The two system
IDs are **explicit reservations by the caller**, not defaults or an allocation
algorithm. Each must be an unused integer in 1..999. A successful `--check-only`
does not authorize a later write by itself: omit that option to run the complete
preflight again immediately before preparation. The executable accepts no host,
ownership or platform override.

The existing materializer's directory-FD safety code is reused. Production
requires `/var/lib/inkyos-build/factory-(studio|image).ALNUM/root`, a root-owned
0700 workspace, root-owned non-writable ancestors without symlinks or xattrs,
and the genuine `inkyos-builder-v1` marker. Root, `etc`, `var` and `var/lib` must
already exist as trusted 0755 directories. `/` is independently refused before
any fixture seam. The rootfs machine-id must be exactly `uninitialized\n`.

## Complete preflight before mutations

The tool reads the four bounded local account databases, `nsswitch.conf`,
machine-id, and subordinate-ID files when present. It checks all of these before
creating any file or directory:

- `passwd`/`group` are single-link regular root:root0644 files. `shadow` and
  `gshadow` are root:shadow0640 or root:{root,shadow}0600. All input paths reject
  symlinks, unexpected modes, xattrs including ACLs, and changing inodes/bytes.
- Names and numeric IDs are canonical, with no duplicate names, UID or GID, NIS
  records or mismatched passwd/shadow and group/gshadow inventories. Every primary
  GID exists. Group and gshadow members agree and refer to existing users.
- Password fields are placeholders in passwd/group and only locked markers in
  shadow/gshadow. An existing password hash, even prefixed by a lock marker, is
  refused. No password hash or input content is included in output.
- NSS for passwd, group, shadow and gshadow is exactly `files` or `files systemd`.
  External NSS providers, compat records and ambiguous duplicate declarations
  are refused; there is no execution of NSS or target libc.
- Existing `inky` is UID/GID1000, home `/home/inky`, locked, shell
  `/usr/sbin/nologin`. Its groups are exactly `inky`, `spi`, `i2c`, `gpio`, with
  no group-administrator privilege. The reserved names `inky-network` and
  `inky-provisioning` must be absent from all four databases; the two requested
  numeric IDs must be unused in their respective namespaces.
- The two final persistent parents `var/lib/inky-studio` and
  `var/lib/inky-network` must be absent, including dangling links. Existing empty
  directories are refused, never adopted, chmodded, chowned or repaired.
- Account locks, known backup files and this command's reserved staging files
  must be absent. No pi/app/helper subordinate-ID grants may remain.

The four complete output databases are validated in memory as well, then the
entire input preflight is repeated immediately before staging.

## Exact preparation and readback

Existing records and their order are preserved byte-for-byte. One record is
appended to each database:

```text
passwd:  inky-network:x:HELPER_UID:PROVISIONING_GID::/nonexistent:/usr/sbin/nologin
group:   inky-provisioning:x:PROVISIONING_GID:inky
shadow:  inky-network:!:0:0:99999:7:::
gshadow: inky-provisioning:!::inky
```

The helper has only its primary `inky-provisioning` group. The app is the sole
explicit member of that group, matching the existing application configuration;
its hardware groups are preserved. No home directory is created for the helper.

New database staging files are created with `O_EXCL|O_NOFOLLOW`, fully written,
assigned the original file ownership/mode and fsynced. All originals are reread
and their identities rechecked before the first replacement. Individual atomic
renames publish each database and fsync `etc`. New empty persistent parents are
created exclusively and fsynced with these final policies:

| Path | Owner | Mode |
| --- | --- | --- |
| `var/lib/inky-studio` | `inky:inky` (1000:1000) | 0700 |
| `var/lib/inky-network` | `inky-network:inky-provisioning` (reserved IDs) | 0700 |

The command rereads all four resulting databases, repeats the account policy and
checks each empty directory's actual inode, ownership, mode and xattrs. The JSON
receipt only reports IDs and bounded status flags.

## Failure and qualification limits

The four renames and two mkdirs are **not one transaction**. A disk/I/O failure
may leave a partial build; no cleanup, rollback or repair is attempted. Staging
files or reserved accounts/parents make subsequent preparation refuse. Discard
that private rootfs and restart a fresh build after investigating the error.
Concurrent writers, especially another root process or account editor, are not
supported; the directory checks do not confer a lock against privileged peers.

This command does not execute the image, call chroot/useradd/systemctl, import
application code, create identities/certificates/tokens, write Wi-Fi settings,
produce factory permission/admission/context, install runtime/support manifests,
enable services, create `/run` parents or provide a boot trigger. It is not an
exhaustive image, secret, NSS runtime, mount-provenance or Wi-Fi audit. A success
receipt establishes only this offline account/parent preparation, with all
factory-authority, service, runtime and hardware qualifications remaining false.

The complete offline QR → adopted owner → native system setup → normal mode
continuation and the native packaging/boot graph described in
[`FACTORY-OFFLINE-BOOT.md`](FACTORY-OFFLINE-BOOT.md) are separate requirements.

## Focused validation

`python3.13 -m unittest discover -s tests -p test_factory_active_prerequisites.py`
executes 19 focused cases: exact preparation, read-only checking, refused IDs and
collisions, malformed/inconsistent accounts, privileges and credentials, external
NSS, existing state, link/hardlink/mode guards, host refusal, interrupted staging
and non-disclosing CLI output. On macOS, 17 pass and two native Linux cases skip.
The Linux-root cases additionally inspect actual xattrs and actual final numeric
owners including Debian root:shadow0640 database preservation. Synthetic fixture
owner/platform seams never apply to `/` and are not exposed by the CLI. A native
builder run is still required before claiming those two cases pass there.
