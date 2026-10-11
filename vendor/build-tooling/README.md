# Offline dependency tooling

`packaging-26.3-py3-none-any.whl` is build tooling only. It is never an input to
the Studio bundle, copied to a rootfs, or used by the application. The exact
129,956-byte wheel is pinned by SHA-256
`d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c` in
[`factory-studio-dependency-tooling.lock.json`](../../config/factory-studio-dependency-tooling.lock.json)
and in the loader. Its recorded public origin is
[the PyPI release wheel](https://files.pythonhosted.org/packages/63/34/ba1c580383c9eada3711951fef0795c80b829a078d72188184bcab9dd527/packaging-26.3-py3-none-any.whl).
It was copied from an existing local wheelhouse and checked against that pin;
this acquisition did not independently authenticate a remote publisher.

The three adjacent `packaging-26.3-LICENSE*` files preserve the exact wheel
notices. Packaging declares `Apache-2.0 OR BSD-2-Clause`; the notices and their
hashes also remain inside the wheel and tooling lock. The project source is
[pypa/packaging](https://github.com/pypa/packaging).

## Validator

Run from the repository with an isolated host interpreter:

```sh
python3 -I -B -S scripts/verify-factory-studio-dependencies.py \
  --input-manifest /absolute/inputs/factory-studio.json \
  --input-sha256 <sha256-of-the-canonical-input-manifest> \
  --sources-dir /absolute/inputs/sources \
  --wheels-dir /absolute/inputs/wheels \
  --receipt /absolute/output/dependency-receipt.json
```

The inputs use the existing `factory-studio-bundle-inputs` schema. The validator
reuses the Studio planner's exact source/wheel inventory and static payload
adapter, including pins, RECORD hashes, tags, native headers, hooks and path
collisions. It then checks dependency metadata starting from the pinned app
wheel with its required `pi` extra. It does not read `pyproject.toml`, resolve
versions, install anything, or require the seven build-only distributions.
Every selected wheel must be reached; there is no fixed distribution count for
synthetic fixtures or later reviewed app releases. For the current 34-wheel
input, all 34 would have to be reached. That real input has not been qualified
by the mere addition of this tool.

The target is fixed: CPython 3.13.5, aarch64 Linux, Debian Trixie. Eleven marker
environment values are explicit constants. `platform_release` and
`platform_version` have no known kernel values, so referencing either is refused;
their empty placeholders cannot influence a dependency decision. Plural
`extras`, `dependency_groups`, variable-to-variable comparisons and unknown
variables are refused. The scalar `extra` is evaluated for the base context and
each activated extra. An AST walk and the pinned packaging evaluator implement
this without using the host's marker environment or rewriting quoted strings.

Extras are accumulated per normalized distribution until a fixed point, even
through cycles. Every active constraint is checked; a later extra can expose a
missing dependency or a conflicting version. URLs are refused even on inactive
edges. Normalized distribution duplicates, conflicting metadata identity,
duplicate scalar headers or normalized extras, malformed requirements and
incompatible `Requires-Python` are refused. Multiple distinct requirements for
one distribution remain valid and all active constraints apply.

For a prebuilt wheel, [`Dynamic`](https://packaging.python.org/en/latest/specifications/core-metadata/#dynamic-multiple-use)
is informational: the value was calculated during wheel construction. It does
not make the delivered `Requires-Dist`, `Requires-Python` or `Provides-Extra`
unresolved, and those fields undergo the same complete checks above. `Dynamic`
requires metadata version 2.2 or later; `Name`, `Version` and `Metadata-Version`
are forbidden dynamic field names, compared case-insensitively. This does not
authenticate correspondence with an sdist or another wheel, and does not run
the build or infer missing metadata.

The root app may have an explicitly pinned release-candidate version. A
transitive prerelease or development release is accepted only when **every
active incoming requirement** explicitly admits prereleases through its version
specifier and also matches that version. The root's version does not opt other
dependencies into prereleases. No resolver fallback is attempted.

## Import boundary and outputs

The CLI requires `-I -B -S`. The loader rejects an ambient `packaging` namespace,
checks the fixed tooling lock and wheel using bounded, no-follow regular-file
reads, then writes a new private temporary copy with `O_EXCL`. That copy is
read back and imported using `zipimport`. Candidate wheels and source directories
are never added to `sys.path` or imported. All packaging modules must originate
in that private copy. The copy, modules and associated zip caches are removed
at the end, including on failure. This is a single-threaded host CLI; it does
not defend against another process with the same owner or a hostile root.

The expected third-party tooling executes on the host; **candidate code does
not execute**. The private packaging AST/evaluator APIs are deliberately bound
to this exact wheel hash. An upgrade requires review and the synthetic tests,
not a changed requirements resolver result. Vendoring avoids network bootstrap,
site-package dependencies and skipped tests when packaging is not installed.

The receipt is separate from bundle/runtime manifests. Its scope is
`factory-studio-dependency-metadata-only`; it records the input/tooling pins,
target, reached distributions and activated extras. It is written exclusively
after successful validation. Existing output is preserved. An I/O failure
while creating the receipt can leave a partial file requiring inspection;
there is no overwrite or repair path.

This checks declared dependency metadata against selected bytes. It does not
authenticate build provenance, audit privacy, determine license compliance,
prove ELF loader closure or ABI behavior, qualify runtime imports, or activate
an image, service, radio or hardware. The final OS support and installed runtime
checks remain separate.
