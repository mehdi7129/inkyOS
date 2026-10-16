# Plan the installed factory runtime manifest

`scripts/plan-factory-runtime-manifest.py` closes the gap between the reviewed
installed inventories and the runtime's eight-field manifest. It accepts the
three explicit reviewed hashes for the Studio bundle, exporter and system
support, plus the reserved helper UID and provisioning GID. It derives module
hashes from their installed bytes and the Studio commit from its pinned bundle.

The planner checks the offline account databases, checks the IDs against them,
and runs the real `factory-runtime-contract.verify_candidate()` over the image.
The candidate manifest is supplied through a read-only in-memory view for these
checks. Every other read uses the actual installed files and metadata, including
the complete support trees, exact service templates and absent TEST/override
paths. There is no temporary manifest in the image and no target-code execution.

The CLI requires Linux root and a private builder workspace matching
`/var/lib/inkyos-build/factory-image.<ASCII token>/root`. The rootfs must have no
runtime manifest or active `/run` state. Its optional output is actually required
by the CLI, is created exclusively outside the rootfs, and contains the proposed
manifest only. Existing output files are never replaced. The Python fixture
owner option is unavailable through the CLI and cannot select the host root.

This is a planning and installed-file-contract check. It does not independently
establish the supplied inventories' provenance or recompute the ELF closure
review, execute a native import, provision factory permission, install the
manifest, prepare a boot context, enable a unit or qualify QR/BLE/hardware.
Those later steps must consume the exact planned bytes and retain their own
checks. An old TEST support manifest is still refused: the mandatory complete
`usr/lib/python3/dist-packages` tree and current factory files cannot be omitted.

Tests use inert payloads and the real verifier, then materialize the proposed
bytes only inside a temporary fixture to exercise the real installed loader.
They cover stale inventory pins, changed payload/support, omitted mandatory
support, wrong IDs, unlocked accounts, active boot state, TEST state, forbidden
enable links and replacement of an existing runtime manifest.
