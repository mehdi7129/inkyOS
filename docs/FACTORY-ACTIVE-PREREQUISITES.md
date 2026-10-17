# Offline prerequisites for a future active factory profile

`scripts/configure-factory-active-prerequisites.py` is a standalone offline build
primitive. It prepares the persistent accounts and parents that the existing
`staging/bootstrap/writer-parents.py` expects, and the helper's limited
NetworkManager polkit rule. It is deliberately **not called by
the file-only `factory-assembly` recipe**, and does not change that profile's
inputs, reports or qualifications.

## Invocation and allowed input

Only invoke this command in the dedicated Linux builder, as real/effective/saved
root with root GID, against an exclusive private, unbooted rootfs:

```sh
python3 -I -B -S scripts/configure-factory-active-prerequisites.py \
  --rootfs /var/lib/inkyos-build/factory-image.EXAMPLE/root \
  --helper-uid 980 --provisioning-gid 980 --check-only
```

Replace `EXAMPLE` with the actual new builder workspace suffix. The two system
IDs are **explicit reservations by the caller**, not defaults or an allocation
algorithm. Each must be an unused integer in 1..999. In the currently pinned
official base, 980 is free in both namespaces; UID991 and GID992 already belong
to vendor identities and are correctly refused. A successful `--check-only`
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
  no group-administrator privilege. Each of `spi`, `i2c` and `gpio` must have a
  distinct non-root system GID in 1..999, matching runtime `check_identity()`.
  The reserved names `inky-network` and
  `inky-provisioning` must be absent from all four databases; the two requested
  numeric IDs must be unused in their respective namespaces.
- The two final persistent parents `var/lib/inky-studio` and
  `var/lib/inky-network` must be absent, including dangling links. Existing empty
  directories are refused, never adopted, chmodded, chowned or repaired.
- `etc/polkit-1` must already be root:root0755. Its existing `rules.d` must be
  root:root0755 or root:polkitd0750/0755, with a named system `polkitd` GID, no links or
  xattrs. Debian's root:polkitd0750 directory is preserved. The final
  `49-inky-network.rules` must be absent, including dangling links; even an
  identical existing rule is refused before any account or parent write.
  root:root0750 is refused because the daemon could not read the directory.
- Per-database account locks, known backup files and this command's reserved
  staging files must be absent. The official base's existing `.pwd.lock` has the
  narrowly checked exception below. No pi/app/helper subordinate-ID grants may
  remain.

The four complete output databases are validated in memory as well, then the
entire input preflight is repeated immediately before staging.

### Existing official password lock

The official image already contains `etc/.pwd.lock`. It is accepted only as an
empty root:root0600 regular file, with one link and no xattrs or ACL. Its inode,
metadata and directory binding are pinned without following links. Before the
account preflight, the command takes a real nonblocking POSIX exclusive record
lock (`fcntl.lockf(LOCK_EX | LOCK_NB)`) covering the entire existing file, and
holds that same descriptor through complete account/parent readback. A competing
process's lock causes refusal before staging or any other write.

The file itself is never written, truncated, chmodded, chowned, replaced or
deleted. No second descriptor for it is opened/closed while the POSIX lock is
held: closing any descriptor for that inode would release the process's record
locks. The held descriptor and unchanged directory entry are rechecked during
the operation. If the file is absent, it stays absent, including in
`--check-only`; the exclusive private-workspace precondition still applies.
Other `passwd.lock`, `group.lock`, `shadow.lock`, `gshadow.lock`, backup and
staging files continue to be refused without adoption or repair.

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
| `etc/polkit-1/rules.d/49-inky-network.rules` | root:root | 0644 |

The policy is the exact 496-byte heredoc from Studio commit
`87c0820808a9824885c6009bf6b68354fb0dbbe9`, `scripts/install-bluetooth.sh`
(source SHA-256 `e0f301c97830860bcc1778579d7f4181370fb4cef8d64aeac4c226ab8aeafb69`).
The rule SHA-256 is
`894de12a283581ddbc0f50e5d86edf207ad936f9c456fb43f002ae67001643d3`.
It returns YES only for the named `inky-network` subject and the existing four
actions: `wifi.scan`, `network-control`, `settings.modify.system`, and
`checkpoint-rollback` in the `org.freedesktop.NetworkManager` namespace. Other
subjects/actions return NOT_HANDLED. The active builder still reserves UID980
and GID980; the app receives no direct NetworkManager grant.

The rule is created with `O_EXCL|O_NOFOLLOW`, root:root0644 and fsync, then its
complete bytes, metadata and xattrs are reread. `--check-only` creates no rule.
The receipt reports its exact hash and whether installation occurred. The final
support/runtime inventory must pin the installed policy and its parent paths;
this configurator does not change a support review or manifest itself.

The command rereads all four resulting databases, repeats the account policy and
checks each empty directory's actual inode, ownership, mode and xattrs. The JSON
receipt only reports IDs and bounded status flags.

## Failure and qualification limits

The four renames, two mkdirs and policy creation are **not one transaction**. A disk/I/O failure
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

The active88 recipe omitted this policy although backend87 checks all four
permissions through the helper's real D-Bus identity before publishing READY.
The prepared rootfs inventory independently showed an empty local `rules.d`.
This source defect is established; it does not establish the cause of the
observed physical first boot, whose logs were unavailable. No image or SD is
changed by this source correction.

The complete offline QR → adopted owner → native system setup → normal mode
continuation and the native packaging/boot graph described in
[`FACTORY-OFFLINE-BOOT.md`](FACTORY-OFFLINE-BOOT.md) are separate requirements.

## Focused validation

`python3.13 -m unittest discover -s tests -p test_factory_active_prerequisites.py`
contains 31 focused cases: exact preparation, read-only checking, refused IDs and
collisions, malformed/inconsistent accounts, privileges and credentials, external
NSS, existing state, link/hardlink/mode guards, host refusal, interrupted staging
and non-disclosing CLI output. The existing `.pwd.lock` cases additionally cover
unchanged successful preparation, absent/existing read-only checks, invalid
size/modes/kinds/hardlinks/xattrs, contention held by a separate process, a probe
showing the lock remains held before and after readback, and release on return.
The policy cases additionally cover exact pinned bytes and four-action scope,
preserved directory metadata, existing/link/directory targets, unsafe or missing
parents/group, payload drift and failed readback. The macOS run covers 31 cases
(29 pass, two native Linux skips).
The added hardware-group range regression is run independently: each named
hardware group assigned GID65530 must refuse before any account/parent write.
The Linux-root cases additionally inspect actual xattrs and actual final numeric
owners including refusal of a non-root-group password lock and Debian
root:shadow0640 database preservation. Synthetic fixture
owner/platform seams never apply to `/` and are not exposed by the CLI. A native
builder run is still required before claiming those two cases pass there.
Separate affected composition groups pass on Mac: `test_factory_active_image.py`
(27 cases) and `test_factory_active_profile.py` (16 cases).

Before qualifying runtime permissions, a separate bounded native check must
query only `org.freedesktop.NetworkManager.GetPermissions` over the real system
bus under UID980 and the helper's exact groups, with the installed pinned rule.
Record the four actual values and the rule hash. Do not scan, activate a
profile, attach a VM network interface to NM, or treat a fake adapter as that
proof. The native ownership/xattr cases and the real permission check have not
been run by this source-only Mac validation.
