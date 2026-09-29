# Lift the object lookup's cached string hash

This supplies a real retained dependency of the [object lookup](../jq-object-get/README.md).
The complete consuming `jv_string_hash` entry now has an ordinary C implementation:
a little-endian 32-bit hash loop, a cache-hit path, writes to a shared cache and
reference release. The [boundary](BOUNDARY.md) records the live allocation,
aliases, seed, lifetime and platform assumptions. No checker, artifact or compiler
extension is needed to prepare, edit, compare or select it.

## Prepare and edit

Enter the pinned lifting shell and retain an object-get local comparison:

```sh
python tests/fixtures/jq-string-hash/prepare.py OBJECT_GET_PACKAGE prepared
spaghetti-extractor component start jq string-hash \
  --comparison-package prepared/string-hash --output work
spaghetti-headless-wayland --interactive bash
spaghetti-extractor component check jq string-hash \
  --comparison-package work --output baseline
```

The existing release contract, live-value transport and allocation observer are
reused. New operator C defines a live cache view and the pinned backend's seed
service. The seed implementation must be included in `export_adapters`, so a
consumer receives that executable service along with the entry bridge. The test
driver's seed setter is only fixture support; ordinary consumers retain process
initialization and entropy.

The three existing case inputs exercise shared/unique ownership, two controlled
seed extremes, cached sentinels, embedded NUL/malformed UTF-8 bytes and every tail
length through several loop iterations. Observations include cache words, string
bytes, surviving references and allocation lifetime. An uncached hash word need
not be initialized by jq: the live view reads it only when its validity flag is
set. The fixture separately initializes that word for diagnostic observations.

Edit `work/source/hash.c` and check with `--reuse-comparison baseline`. To see a
memory discrepancy that a return-value-only comparison misses, temporarily change
`view.length_hashed | 1U` to `view.length_hashed`, then check
`--case retained-zero`. The returned hash is unchanged; the CLI identifies
`$.samples[0].after.length_hashed` and prints a retained replay command. Restore
the cache update and check again. This is finite experimental evidence.

To resume from a retained result, use `component start jq string-hash
--comparison-result HASH_CHECK --output work`. It reopens the bound inputs and
prints the next check with the result as its reuse baseline. Add
`--reuse-source PROJECT/lifted` to carry only this component's edited C back from
the portable project. The same operation accepts a consumer result containing
the hash: its check still executes the enclosing consumer, preserving any selected
case. It does not turn that consumer comparison into an independent local check.
The handoff in `build/component-source-local-return-2026-09-24/` follows these
printed commands after extracting a private C load helper in the source project.
Local and consumer checks each compile one changed file, and an unchanged reopen
does zero compiler/link/execution work. Publishing just the hash rebuilds one
component in the normal host source program and preserves its neighbors.

## Connect the existing consumer

The lookup borrows its key while this public hash entry consumes a reference.
The reviewed C call wrapper takes a temporary reference, just like the previous
native adapter. The connection recipe uses `bind_dependencies` and
`revise_comparison_package` on the selected lookup; it preserves the surrounding
network, C, cases and other suppliers:

```sh
python tests/fixtures/jq-string-hash/connect.py \
  NETWORK HASH_CHECK/inputs connected
spaghetti-extractor component start jq string-hash \
  --comparison-package connected --output connected-work
spaghetti-extractor component check jq string-hash \
  --comparison-package connected-work --case program-builtins \
  --reuse-comparison PREVIOUS_NETWORK_CHECK --output consumer-check
spaghetti-extractor component status jq string-hash \
  --comparison-result consumer-check --details
```

Choose a case retained by your network. This check runs the enclosing path-set
consumer; its service observations do not replace the local comparison. The
recorded interpreter case calls the hash and seed services four times under
`path-set → value-get → object-get → string-hash`. Subsequent local edits return
through `--dependency-source string-hash=work`. Changed adapters or boundary
premises use explicit requirement refinement.

## Carry the selection into the source program

For an existing [portable jq project](../jq-portable/README.md) containing the
lookup, publish both the reviewed consumer requirement and the new supplier:

```sh
spaghetti-extractor candidate export jq \
  --comparison HASH_CHECK --comparison consumer-check --output PROJECT/lifted \
  --update-components --component object-get --component string-hash \
  --accept-boundary-change object-get --accept-boundary-change string-hash
python tests/fixtures/jq-portable/refresh.py PROJECT \
  --bindings tests/fixtures/jq-string-hash/portable-bindings.json
```

The binding declaration distinguishes the generated 32-bit `fixture_string_hash`
entry from the superseded `jv_string_hash` backend body. `hash-source.h` provides
the ordinary C public wrapper returning `unsigned long`. That type is 32-bit on
Win32 and 64-bit on the exercised source hosts; the wrapper zero-extends the hash.
The same JSON explicitly supplies both required adapter headers and redirects
the lookup to its source backend adapter.

The same binding includes [hash-seed-backend.h](hash-seed-backend.h) after the
private definitions in `PROJECT/backends/jq/src/jv.c`. Its ordinary C accessor
shares the seed with the remaining native-derived object/hash operations;
creating an unrelated global seed would make the bucket lookup incorrect. No
manual source append is needed. An older project using the handwritten accessor
should remove that exact function before adopting the header, preserving other
backend edits. The recipe retains the header beside the backend C file and adds
one managed include block. Rebuild
and run affected normal-entry workloads, using the same public source handoff as
other components. Subsequent refreshes need only the project, because its binding
choices and C headers are retained. The project remains independently buildable.
Editing the retained backend header invalidates program validation and rebuilds
that backend translation unit; lifted components keep their existing objects.
Conflicting incoming header changes use the source recipe's existing
`--keep-reviewed` merge workflow.

The recorded handoff under `build/component-string-hash-2026-09-24/` passes local
comparisons, deliberate cache-defect diagnosis and repair, the connected native
consumer and normal program execution on x86-64 and AArch64 under QEMU. Existing
neighbor component objects are preserved. Initial assembly caught an omitted
adapter header; the explicit binding now carries it. The source recipe needed
separate removed-body/generated-entry names; no new proof machinery was added.
The private backend hash helper, allocation, entropy and the rest of jq remain
explicit dependencies. Big-endian backend hashing and concurrent cache/seed
access are outside this checkpoint; this is a partial source-assisted jq lift.
