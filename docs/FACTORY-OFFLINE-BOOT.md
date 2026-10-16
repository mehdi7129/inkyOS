# Offline first boot: reader fix and remaining composition

The requested product flow is a fresh SD without a Wi-Fi profile, a physical
bootstrap QR before any LAN connection, then iPhone association and system setup.
This source change fixes one native-contract contradiction. It does not activate
an image profile, emit an initialization receipt, enable a unit or resume the
historically paused Phase B storage work.

## Main reader under its intended sandbox

The pinned main unit has `ProtectSystem=strict` and grants writes only to
`/var/lib/inky-studio`. It therefore may observe `/run` read-only. The runtime
contract already accepts that view for `validate_context()`, while requiring
`rw` for `prepare_boot_context()`. The main graph's `_run_binding()` incorrectly
required `rw` even though it only reads the existing context/admission.

The graph now accepts exactly one of `ro` and `rw`. It still requires a unique
tmpfs mount rooted at `/`, bound to the held `/run` FD's device. The entire mount
row remains in its binding, so a subsequent remount, flag or mount-ID change
invalidates that observation. No unit gets broader `ReadWritePaths`; prepare-boot
still refuses a read-only mount. The regression runs the real runtime verifier
and graph parser against ordinary temporary files and synthetic mountinfo; it
does not qualify a real namespace, PID1 graph, Bluetooth or display.

## Where the existing QR-only composition stops

The existing `staging/bootstrap/factory-main.py` calls Studio's
`serve_factory_phase_a()` under the native graph proof. It injects the graph's
admission callback and connected initialization-peer guard. Studio's existing
bootstrap runtime displays QR v2 before advertising BLE, supports claim/status,
and reports `factory_state=adopted`, `next_step=system_setup` after a durable
claim. It does not instantiate a NetworkClient or start normal HTTP/photo mode.
Those public phase-A results are observations of association, not OS grants.

The future handoff must retain these boundaries:

- Studio owns the owner/claim ledger and authenticated bootstrap response. OS
  must not infer adoption from an empty photos DB, a missing identity, a Boolean
  readiness flag, an old TEST receipt or a normal login session.
- A `system_setup` result does not authorize clock, country or Wi-Fi mutations.
  A future native adapter must bind the actual admitted owner/session, current
  boot/candidate and connected peer for its narrow operations. No new operation,
  caller, token, storage migration or permission is implemented by this patch.
- Only a reviewed continuation can transition to normal TLS/photo mode after
  system setup. Loss of its response must preserve the current authority and
  remain uncertain; never mint a second factory initialization.
- Reboots of a completed normal device preserve its identity, owner, network and
  displayed photo. They must not run the factory QR/welcome merely because of a
  reboot, loss of network, revoked last owner or deleted application data. A
  pending display confirmation remains conservative rather than causing an
  automatic replacement refresh. The existing TEST one-use resume is separate.

## Activation dependency that remains closed

`factory-assembly` is a file-only recipe. It intentionally does not provision
accounts, DATA/helper parents, factory permission, exporter/support/runtime
manifests, boot context, admission or enable links. The existing native contract
requires the genuine bundle and exporter plus their complete system/ELF closure,
reserved accounts, unit policies and fresh boot-bound admission. The historical
`config/factory-exporter-system-support.json` is not such an active candidate:
it lacks the mandatory dist-packages tree and factory graph records and retains
TEST entries disallowed by this contract. It cannot be repurposed as a grant.

Moreover `check_unit_files()` rejects enable/alias symlinks to any of its five
closed units. Adding `WantedBy` or simply enabling `inky-studio.service` would
invalidate the candidate; the old fixture service is not a production launcher.
A future active recipe needs its reviewed boot trigger, native support closure,
source hashes and observed PID1 graph, while retaining the fixed writer order
and drains. No manifest/pin is invented here to stand in for those artifacts.

The corrected graph bytes need fresh writer-input/support hashes from the real
packager. Existing artifacts/reports and the TEST payload are unchanged. Until
the active native composition and Studio continuation are supplied, this lot
cannot claim a bootable offline QR product flow or normal adopted startup.
