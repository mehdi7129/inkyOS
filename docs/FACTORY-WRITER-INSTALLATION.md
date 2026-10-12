# Inactive factory writer files

`install-factory-writer-rootfs.py` materializes and reads back a closed mapping of
17 files in an offline build root. `verify-factory-writer-rootfs.py` inspects the
same bytes and metadata without writing. This is a source integration step, not
an image recipe or a runtime admission.

The production entry points require a root-owned Linux workspace at
`/var/lib/inkyos-build/factory-image.<ASCII-alphanumeric-token>/root`. The workspace
parent has mode `0700`; the root and other existing directories must be trusted,
without group/other write permission or xattrs. The existing builder marker is
required. No fixture ownership or platform override is exposed by the CLI.

The root is a dedicated base OS with a newly materialized Studio bundle at
`usr/lib/inky-studio`. Normal base OS files are allowed and are not inventoried.
It must contain no previous factory authority, runtime support, permission,
credentials/data or TEST state. Known unit overrides, masks, drop-ins, aliases and
enable links are refused, including the closed `UNIT_ABSENT` set and a bounded
metadata scan of the twelve system unit lookup directories. No existing mask is
removed and no existing directory is chmod/chowned.
Links to unit extension directories are refused instead of traversed. A legacy
split `lib` directory is refused; an existing exact `usr/lib` alias is preserved.

## Reviewed inputs

Inputs and the exclusive receipt path stay outside `root`, inside its private
workspace. Provide a dedicated source directory containing exactly the sixteen
repository files and their ancestor directories. Links, hardlinks, special files,
extra entries, untrusted owners/modes and xattrs are refused. All reads are bounded
and rechecked before the first write and before a successful return.

The input manifest is canonical JSON (sorted keys, compact separators, ASCII,
one final newline), pinned by an externally reviewed SHA-256. Its exact fields are:

| Field | Required value |
| --- | --- |
| `schema_version` | Integer `1` |
| `kind` | `factory-writer-file-inputs` |
| `os_commit` | Lowercase 40-hex declared source correlation |
| `studio_commit` | `eb117903cb647a14e9722d7387a41058ea8807b3` |
| `os_source_sha256` | Exactly the sixteen source paths in the verifier's `SOURCE_MAP`, each with a lowercase 64-hex pin |
| `studio_bundle_manifest_sha256` | SHA-256 of the externally reviewed Studio bundle manifest |
| `helper_source_sha256` | SHA-256 of `scripts/inky-network-helper.py` in that bundle |

The source hashes and reviewed manifest hash are the byte authority.
`os_commit` is a caller declaration, not independent Git verification. The bundle
manifest uses the existing planner schema: `schema_version`, `kind`,
`studio_commit`, `records`. Its installed `manifest.json` must be byte-identical
to the external plan. The helper's bytes, single-link root ownership, mode `0555`,
empty xattrs and exact source record must agree. Inspecting this record does not
qualify the complete Studio bundle or its dependency closure.

## Closed mapping and operations

Seven modules go to `usr/lib/inkyos`: `factory-main.py`, `writer-graph.py`,
`writer-admission.py`, `writer-parents.py`, `factory-runtime-contract.py`,
`factory-supervisor.py`, `writer-launcher.py`. Four hooks go to
`usr/local/lib/inkyos`: `factory-authority.py`, `factory-credentials-publisher.py`,
`initialization-receipt.py`, `initialization-server.py`. The five existing unit
templates go to `usr/lib/systemd/system`. The helper is copied exclusively from
the installed bundle to `usr/local/lib/inky-studio/network-helper.py`.

Modules and helper have root:root ownership and mode `0555`; units have mode
`0644`. Newly created parents have root:root ownership and mode `0755`. Every
destination must be absent before installation. Files use `O_EXCL`/`O_NOFOLLOW`,
held directory identities, fsync and byte readback. Existing parent inodes and
permissions are preserved. The verifier requires those exact installed modes,
owners, single-link files and empty xattrs.

```sh
python3 -I -B -S scripts/install-factory-writer-rootfs.py \
  --rootfs "$workspace/root" \
  --input-manifest "$workspace/writer-inputs.json" \
  --input-sha256 "$reviewed_writer_inputs_sha256" \
  --sources-dir "$workspace/writer-sources" \
  --bundle-manifest "$workspace/studio-bundle-manifest.json" \
  --receipt "$workspace/writer-install-receipt.json"

python3 -I -B -S scripts/verify-factory-writer-rootfs.py \
  --rootfs "$workspace/root" \
  --input-manifest "$workspace/writer-inputs.json" \
  --input-sha256 "$reviewed_writer_inputs_sha256" \
  --sources-dir "$workspace/writer-sources" \
  --bundle-manifest "$workspace/studio-bundle-manifest.json"
```

No target module, interpreter or service is executed. No enable link, boot trigger,
account, authority permission, admission state, credentials, support/exporter or
runtime manifest is created. Inactive means this operation schedules no launch;
the installed unit templates remain explicitly startable by root. This is not a
barrier against root.

An I/O failure retains the partial tree and may retain an incomplete receipt.
There is no rollback, normalization or automatic retry. A failed invocation has
no successful result; retained receipt bytes alone are not a success attestation.
Inspect the failure privately and prepare a new dedicated workspace.

## Remaining integration gates

The current graph pins Studio R35 and the main launcher targets the OS
`factory-main.py` wrapper. A new assembly must pin the updated graph and launcher
bytes in its reviewed inputs and manifests. Earlier R33 and materialization
fixtures retain their own source pins and results; they do not qualify this
source alignment.
The support/exporter/runtime manifests, native dependency and ELF review,
accounts/groups, authority/lifecycle provisioning, effective systemd graph,
explicit boot integration and hardware tests remain separate work.

A successful receipt establishes the seventeen file bytes and metadata only.
Bundle, support, runtime, image and hardware qualification flags remain false.
The inert tests verify refusal and materialization behavior; macOS uses explicit
fixture seams for ownership/workspace and Linux xattr observations. They do not
replace a native installation review or qualify a bootable SD.
