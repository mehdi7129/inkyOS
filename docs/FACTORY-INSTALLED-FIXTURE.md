# Installed factory composition fixture — staging only

`staging/bootstrap/probe-factory-installed-linux.py` is an opt-in Linux ARM64
fixture. Its unit tests are inert. It has no image installation target and does
not alter the existing inert probe, service template or historical receipts.
A native execution and its controller remain separate qualification steps.

## Controller contract

A trusted external controller prepares a **new private copy** of the previously
verified exporter image. While that copy is writable, it creates only the two
missing empty mountpoints: `/etc/inky-studio` root:root `0755` and
`/var/lib/inkyos` root:root `0700`. It records the resulting image SHA-256, then
exposes partition 2 globally to PID1 as an ext4 loop mount, read-only with
`nosuid,nodev` and execution allowed. The entire loop device must be read-only.
The probe never mounts or unmounts anything.

The exact layout is `/var/lib/inkyos-build/factory-installed.<alnum>/root` with
the loop backing file `image.img` beside `root`. That parent is root:root `0700`,
the image is root:root `0600`, and every ancestor is root-owned, without ACLs,
symlinks or group/other write access. The probe and PID1 must share the mount
namespace. A mount visible only inside a controller's private namespace is
refused. Inputs and the source snapshot must also have trusted ancestors; input
paths are under `/var/lib/inkyos-build` and outside the mounted rootfs.

The marked builder prerequisite is the same as the existing service probe.
Invocation, **only after separate controller review and authorization**:

```text
/usr/bin/python3.13 -I -B -S <snapshot>/staging/bootstrap/probe-factory-installed-linux.py \
  --installed-composition --fixture-token <8-lowercase-hex> \
  --rootfs /var/lib/inkyos-build/factory-installed.<alnum>/root \
  --prepared-image-sha256 <prepared-image-sha256> \
  --sources-dir <trusted-source-inputs> --wheels-dir <trusted-wheel-inputs> \
  --support-manifest <trusted-support-manifest>
```

For token `01234567`, all possible units are known before launch:

```text
inkyos-factory-probe-installed-01234567-fresh.service
inkyos-factory-probe-installed-01234567-validate.service
inkyos-factory-probe-installed-01234567-restart.service
inkyos-factory-probe-installed-01234567-consumed_no_authority.service
inkyos-factory-probe-installed-01234567-no_permission.service
```

Their cgroups are `/system.slice/<unit>`. The controller must use this exact
list for emergency cleanup if the probe is killed; no wildcard cleanup is
needed. The exclusive private work directory is
`/var/lib/inkyos-build/inkyos-factory-probe-installed-01234567`. Existing work or
units are refused. The probe retains private fixtures and emits only a closed
JSON report on stdout. The controller owns retention and final unmount/loop
cleanup; the probe stops every unit it attempted and verifies empty cgroups.

## Composition checked

Before fixture mutation or systemd execution, pinned source and lock files,
the prepared image, full exporter support and bundle are verified. The existing
verifier and inventory helpers are reused. The complete base `/usr/local/lib`
inventory is preserved in the expected view. An exact copy of its `inkyos`
subtree receives three pinned OS modules and the inert observer; extra or
changed entries are refused. This is an explicit augmented view, not a claim
that the original support manifest describes the bind overlay.

Each unit uses `RootDirectory` with four explicit binds: private state and data
read-write, marker and OS modules read-only. `MountAPIVFS=yes`,
`BindLogSockets=no`, `TasksMax=2`, the template's five capabilities and sandbox
settings are retained. The timeout is 40 seconds, with a 50-second controller
wait and a separate bounded stop/cgroup cleanup. Hook stdout is private and
file-size bounded; the only accepted output is one expected JSON object of at
most 512 bytes. Serializer output remains the publisher's anonymous pipe.

`ExecStartPre` runs the system Python with `-I -B -S`. It checks its root/bind
identities, mount restrictions, capability state, cgroup limit, and exact
augmented `/usr/local/lib` and exporter inventories, then writes a closed
receipt. **Its namespace and process are not the hook's.** This observation does
not directly observe `ExecStart` or the serializer. The hook is a direct
`ExecStart` of system Python `-I -B -S` and `factory-authority.py`; its installed
serializer keeps the staging v2 argv (`venv/bin/python -I -B -m … --emit-v2`).

The critical mount allowlist also requires the exact `/usr/lib/modules` mask
created by `ProtectKernelModules=yes`. It must occur once, be an empty root:root
directory with mode `0000` on a filesystem distinct from the image, and be
read-only and `noexec`. This checks the effective mask without attesting its
host source inode; the builder and its PID1 remain trusted. Other additional
mounts under `/usr`, `/etc` or `/lib`
remain refused. This accounts for the documented implementation in
[systemd v257.13 `namespace.c`](https://raw.githubusercontent.com/systemd/systemd/v257.13/src/core/namespace.c)
(`protect_kernel_modules_table`, `MOUNT_INACCESSIBLE`, and remount handling);
the source node is selected by
[`mode_to_inaccessible_node`](https://raw.githubusercontent.com/systemd/systemd/v257.13/src/shared/mount-util.c).
The unit's protection is retained.

A failed Pre check writes a bounded closed failure receipt when its private
output directory is available. The report exposes only `pre_failure_phase`,
chosen from fixed phase names; no exception text, traceback, credential or
credential hash is included. Even if the receipt cannot be written, the Pre
exit code is `64 + phase index`, with this fixed zero-based ordering:
`arguments`, `manifest`, `identity`, `capabilities`, `isolation`, `binds`,
`mount_flags`, `critical_mounts`, `inventory_helper`, `local_inventory`,
`bundle_inventory`, `cgroup`, `receipt`. Earlier receipts without such a code
do not establish which predicate failed first. The fallback code is available
only through the manager/journal; if the receipt could not be written,
`pre_failure_phase` remains null in the probe report. Hook stdout remains unchanged.

| Case | Expected hook result | State check after stop |
| --- | --- | --- |
| Fresh permission | `created`, `authorized` | Permission consumed, credential metadata valid, real receipt inspector reports authorized |
| Restart, same fixture, new unit | `existing`, `authorized` | Private state and credential bytes unchanged |
| Consumed permission, credential, no authority | `recovery_required` | Private state and credential bytes unchanged |
| No permission directory | `permission_unavailable` | Private state and empty app data unchanged |

After stopping the fresh unit, a separate validation unit drops supplementary
groups and all three numeric UID/GID values to 1000 before executing the
installed venv. It checks zero effective/permitted/inheritable/ambient
capabilities and `NoNewPrivs` before exec and again before importing Studio.
The inherited bounded capability set does not grant effective capabilities.
The actual Studio parser validates version 2 and checks the bootstrap password
and a wrong password in memory. Only fixed boolean results are returned;
credentials, passwords and their hashes never enter reports. Validation must
leave the fixture unchanged.

A PASS requires four distinct completed cases, the separate Studio validation,
final base/bundle/overlay readback and cleanup of every attempted unit. It does
not qualify a production recipe, a real application writer barrier, a complete
application candidate, hardware, or resistance to a hostile builder/root.
