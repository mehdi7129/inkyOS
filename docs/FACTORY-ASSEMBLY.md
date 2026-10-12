# Private inactive factory assembly

`factory-assembly` is a file-only recipe on a pinned ARM64 base image. It copies
and reads back the real Studio bundle and the closed 17-file OS/helper mapping.
It is separate from `factory-passive` and the system/application TEST prototypes.
It does not constitute a configured base OS, installed graph, first boot or release.

The recipe source is implemented; a production build and its resulting image
still require a separate reviewed execution. Synthetic tests, the earlier empty
native fixture and this source change do not qualify that image.

## Inputs

The existing base lock remains authoritative. Eight explicit inputs are required:

```bash
PYTHON=python3.13 bash scripts/build-prototype.sh \
  --profile factory-assembly \
  --studio-input-manifest /private-inputs/studio-inputs.json \
  --studio-input-sha256 <reviewed-studio-input-sha256> \
  --studio-sources-dir /private-inputs/studio-sources \
  --studio-wheels-dir /private-inputs/wheels \
  --studio-bundle-manifest /private-inputs/expected-bundle-manifest.json \
  --writer-input-manifest /private-inputs/writer-inputs.json \
  --writer-input-sha256 <reviewed-writer-input-sha256> \
  --writer-sources-dir /private-inputs/writer-sources
```

The writer manifest retains its existing seven-field schema. Its externally
reviewed SHA-256 binds the expected bundle and the helper's source record. The
expected bundle must also match the planner byte for byte. Studio must be R35;
the closed 16 OS source hashes must match the separately frozen recipe sources.
`os_commit` is declared correlation, not independent Git evidence. The earlier
fixture38 graph and legacy launcher cannot be substituted into this assembly.
No alternate helper is accepted: it is copied only from the installed bundle.

Incorrect pins, missing/extra inputs and mixed profile options refuse before
the host creates a snapshot or accesses the builder. The staged closure is read
again before mounting or writing the base copy. Recipe hashes and the base hash
are checked independently by the existing Linux builder.

## Inactive composition

The private Linux ARM64 root workspace keeps the existing builder marker and
exact `factory-image.<ASCII-alphanumeric-token>/root` path. The builder reuses
its private namespaces, verified base copy, loop/ext4/vfat mounts, boot-file
preservation, readonly freeze, full filesystem manifest and fsck checks.

The new branch precedes `/dev` fabrication, package installation, NSS changes,
rootfs/firstboot configuration and all target commands. It does not fetch or
install the system package additions, import target Python, run an exporter or
backend, start services, activate radios, set the clock or use a Pi/SD.

Before the first bundle write, the recipe uses the writer verifier's existing
`Environment` and `_preflight` guards with destination names derived exclusively
from `SOURCE_MAP` and `HELPER`. This is an internal recipe dependency, not a new
policy or native ABI. It refuses existing passive/TEST state, occupied writer
destinations and known unit influences without removing or normalizing them.
The held environment is closed on success and failure. `_load_payload` is not
called before the helper exists in the installed bundle.

The only materialization operations are the four unchanged production APIs:

1. `install_bundle`
2. `verify_bundle`
3. `install_writer`
4. `verify_writer`

Existing files/parents are preserved. No accounts, DATA, authority permission,
`Ready`, credentials, support/exporter/runtime manifests or enable links are
created. Inactive means this recipe schedules no factory launch; root can still
explicitly start the installed unit templates. It is not a barrier against root.

Any failure preserves partial exclusive creations and their individual receipts.
There is no repair, rollback, retry or positive whole-build result. Inspect the
failure privately and start a new dedicated workspace.

## Export integrity and remaining gates

The export has its own `factory-assembly` kind and closed report set: builder,
filesystem/image inspection, preserved boot hashes, both fsck reports, the
assembly metadata, Studio inputs/expected bundle, writer inputs and four API
receipts. It borrows no firstboot smoke, systemd or passive static PASS.

`verify-artifacts.py` remains mandatory. It binds the recipe/input/receipt hashes,
the whole installed bundle and all 17 writer records to the filesystem inventory
and checks the exported image's size and hash. This establishes local unsigned
integrity, not independent authenticity or regenerated image contents.

The exact assembly metadata keeps `abi`, `boot`, `hardware`, `image`,
`installed_graph`, `release`, `runtime` and `support` qualifications at `false`.
Support/exporter assembly, target libraries/ELF/ABI, reserved accounts, installed
PID1 graph, licenses/privacy release review, boot and physical app/BLE/Wi-Fi/display
flows remain separate gates. This private image must not be distributed or flashed
as a finished system.
