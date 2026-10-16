# Factory system setup — source integration

This source lot connects the admitted main, a separate privileged setup service,
the native network helper and the reviewed factory continuation. It does not
execute or activate an image, set the Mac clock/radio, or qualify the Pi.

The shared reviewed IPC is copied byte-for-byte to
`staging/bootstrap/system-setup-contract.json`. The source implementation uses
that closed schema and numeric `time-policy.py`. The reviewed addendum in
`design/factory-system-setup-20261016` records the later source decisions (notify
readiness, root primary group and append-only completion history). No historical
TEST module/receipt/capsule is an active dependency.

## Installed pieces

`verify-factory-writer-rootfs.py` extends its closed mapping with:

- `/usr/lib/inkyos/system-setup.py`, `system-setup-native.py`,
  `system-setup-gate.py` and `time-policy.py` (0555);
- `/usr/lib/inkyos/system-setup-contract.json` (0444);
- `/usr/lib/systemd/system/inkyos-system-setup.service` and
  `inkyos-wlan-close.service` (0644).

The separate explicit active-profile installer owns both systemd-rfkill masks,
the NetworkManager Requires/After drop-in and the absent-only persistent
`/var/lib/inkyos/system-setup` root:root0700 parent. The writer installer creates
none of these activation selections. Trusted prepare-boot verifies that parent
and includes its inode plus the new runtime parent root:provisioning0750 in the
writer-parent receipt. Missing or unsafe objects refuse; the setter repairs no
parent and adopts no pre-existing socket.

Runtime support must pin the new sources, units, contract and the ELF closure
for busctl, iw, nmcli and systemctl. These are mandatory inputs to the runtime
candidate verifier. The final Studio commit must be the matching clean backend
commit, pinned by both writer graph and writer-file verifier before packaging.

## Authority and effects

The setup service runs root:root, supplementary inky-provisioning, with only
SYS_TIME/NET_ADMIN and fixed commands. Root journal files therefore need no
CHOWN capability. The owner can change its socket group to its supplementary
provisioning group. The initialization service keeps its empty capability set.
There is no Studio import or execution under root.

The graph authenticates the actual setup/main/helper peers with live pidfds,
PID1 GetUnitByPIDFD, exact unit/MainPID/InvocationID/argv/security policy and the
fresh current boot/candidate/context lease. UID alone is never authority. Main
and helper validate the setup peer reciprocally. Setup and helper announce
READY only after their real sockets listen, so main's After ordering cannot
race their initialization.

The main performs first-owner/token/claim/current epoch checks. Root independently
inspects the real consumed initialization receipt and pins the historical first
owner and claim identifiers. Owner tokens, QR secrets, private keys and Wi-Fi
passwords do not enter this IPC. Inspect/status and ordinary completion resume
need no old phone session and do not reactivate a revoked first owner.

Each admitted apply has a root-fsynced PENDING record before the clock syscall.
A fresh OS-random challenge uses real CLOCK_BOOTTIME, TTL30s. The real clock
setter and actual REALTIME readback use the separately pinned numeric policy.
This is an authenticated owner's UTC assertion, not independent UTC certification.
The setter then performs standard `iw reg set CC` with an explicit app country,
reads firmware country/ccode/revision, global kernel country, PHY/interface and
bounded channel observations, checks the closed Wi-Fi profile inventory, and
only then opens WLAN. No vendor SET, scan or profile creation is performed here.
These readbacks do not measure RF output or certify regulatory compliance.

Every sub-effect rechecks the live session. EOF/RESET/shutdown closes future
admission. Already started work is owned and drained/reaped. Failure attempts
NM WirelessEnabled=false plus WLAN-only softblock with readbacks. Unconfirmed
closure holds the service/lease; it never becomes readiness or process exit.
Status/inspect freshly re-observe firmware/country/radio/NM owner before positive
readiness. A cached receipt alone cannot authorize wifi.begin. HTTPS origin
requires matching root system.json, /etc/hostname, runtime hostname, current
Avahi and the connected wlan0 NM device; otherwise it is null.

## Reboot and recovery

The early gate runs before NetworkManager on every boot and requires the two
rfkill restore units masked/inactive. It writes WirelessEnabled=false durably,
softblocks WLAN only, and publishes a current-boot/candidate closed observation.
Bluetooth and profiles are preserved. Resume restores/readbacks country before
unblocking WLAN, never replays an old clock assertion, and follows only the
attested helper's latest genuine committed transaction checked against NM.
Absent/pending/uncertain helper state leaves NORMAL_RECOVERY with WLAN closed.
No absence condition selects factory or creates initialization authority.

The root journal bounds challenges/operations/completions to64 without eviction.
Interrupted pending operations reopen as UNCERTAIN and never automatically rerun.
A fresh owner-authorized op with a fresh challenge may explicitly supersede a
drained prior op. Every Completion is immutable. Explicit post-completion
recovery can append a new current Completion after real apply/complete, with the
same initial publication/UUID/SPKI; old Completions remain audit records. A new
pending op is not completed just because a historical Completion exists.
Ordinary Wi-Fi changes retain Completion and update a separate NetworkHead.
NetworkHead is a durable past observation; readonly Live may legitimately differ
as IP or the latest committed transaction changes.

The factory main composes the real SystemSetupClient and NetworkClient with
reciprocal graph guards and passes `DATA/provisioning` to the continuation. It
keeps the same identity, ownership ledger, display and normal service. Historical
clock receipts do not authorize certificate renewal on a new boot.

## Verification boundaries

Relevant Mac fixtures cover durable-before-effect ordering, strict grammar,
idempotent retry/conflict, expired challenges, EOF partial effects, interrupted
pending recovery, initial publication lineage, lost completion reply, new Wi-Fi
on reboot, missing helper state, immutable completion history, stale native
readiness, the actual clock adapter with patched syscalls, notify datagrams,
rfkill restore refusal, peer roles/capabilities, unit policies and offline file
installation. Fixture overrides are confined to canonical non-/ roots. None of
these tests attests Linux permissions, actual PID1/Avahi/NM output, Pi firmware,
clock/radio effects, display or a built image.

Native review should first exercise an inert inherited-pidfd busctl query and
real notify ordering, then installed role admission and negative peer fixtures.
The physical Pi must separately establish the real country/firmware/rfkill path
and the complete scan → owner → time/country → TLS → Wi-Fi → PHOTO → reboot flow.
EOF, RESET, lost replies and ordinary Wi-Fi changes remain required bench cases.
