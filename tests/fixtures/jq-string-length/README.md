# Local workspace and a fresh jq boundary

This trial defines `jv_string_length_codepoints` using the existing string
contents/release services and C adapters. The purpose is to exercise reusable
boundary knowledge and local authoring on a previously unprepared operation.
It is source-assisted analysis of the pinned jq DLL, not automatic binary recovery
or an independent human usability study.

[BOUNDARY.md](BOUNDARY.md) records inputs, aliases, lifetime, outcomes and exact
native entry. The 27-line C loop counts decoder advances, including malformed
groups and embedded NUL. In particular, a truncated group consumes all remaining
bytes before checking continuation bytes. The component consumes one string
reference and leaves retained aliases' contents unchanged.

`prepare.py` selects the exact existing `contents` and `release` declarations from
the supplied workspace with `services_from_interface`. It no longer imports the
string-slice preparation recipe to reconstruct them. It reuses `string-view.h`, value transport,
allocation observations and `jq-portable/string.c` without duplicating their
implementations. The new manual work is the boundary, algorithm, native entry
hook and cases. The public source recipe also needs a reviewed symbol binding.
No new semantic checker, artifact format, compiler mechanism or proof rule is
needed for this operation. The workspace projection itself is new shared tooling.

The current recipe derives entry-hook glue with the installed `native_entry_header`
helper. Its reviewed RVA range and pinned DLL replace hand-copied prefixes and
saved-body setup. Native signatures, live-object adapters and observations remain
explicit, as described in the [authoring API](../../../docs/components.md#author-a-new-comparison-boundary).

The subsequent [byte-length trial](../jq-string-byte-length/README.md) removes the
contents adapter's call to native byte length. Current preparation includes the
shared `string-storage.h` view of the reviewed live allocation. This keeps the
same logical contents contract while permitting byte length itself to be lifted;
previously retained packages keep their original adapter bytes.

## Reproduce and work locally

Enter `nix develop .#lifting`. Obtain the pinned string-slice package using its
[documented preparation](../jq-string-slice/README.md). That package supplies
retained tools, libraries and headers, not this operation's behavior. Then run:

```sh
python tests/fixtures/jq-string-length/prepare.py \
  build/jq-string-slice-2026-09-22/packages-v3/string-slice build/length-package

spaghetti-extractor component start jq string-length \
  --comparison-package build/length-package/string-length --output build/length
spaghetti-extractor component status jq string-length \
  --comparison-package build/length

spaghetti-headless-wayland spaghetti-extractor component check jq string-length \
  --comparison-package build/length --output build/length-check
```

Read `generated/workspace.md` for the inputs, shared types, services/adapters,
outcomes, assumptions, requirements and cases. It links the actual contract and C
files. `component status --comparison-package` refreshes that view; `--json` exposes
the full projection. Neither command evaluates assurance or invokes a provider
build. Generated guides are outside comparison/proof authority and do not change
component dependencies. Establishing or changing the boundary still needs analysis
of surrounding code; routine C edits use the recorded boundary.

To revise declarations after making local C edits, prepare the revised package
separately and retain those edits through the public start command:

```sh
spaghetti-extractor component start jq string-length \
  --comparison-package build/revised-length-package --reuse-source build/length \
  --output build/revised-length
```

The revised package supplies its adapters and boundary; the current component's
C and source headers come from `build/length`. Both inputs remain intact. Check
the new workspace with the previous result supplied via `--reuse-comparison` to
see which inputs changed and rerun the affected cases. Renamed/added/removed source
files need explicit transfer. The retained trial in
`build/component-boundary-restart-2026-09-23/` refines the declared input name and
resource path, preserves a local C edit, reruns real consumers, reuses the
string-slice neighbor and exports/builds the revised source library.

The complete public sequence is:

```sh
spaghetti-headless-wayland python tests/fixtures/jq-string-length/walkthrough.py \
  build/jq-string-slice-2026-09-22/packages-v3/string-slice build/length-workflow
```

It prepares a fresh package, starts/inspects the workspace, compares the original,
edits ordinary C, reuses the independent string-slice neighbor, introduces two
defects, replays retained failures after repairing the working source, and checks
repair. All Wine applications and servers stay inside the headless desktop.

Six cases cover 1,380 direct calls on unique/shared strings plus actual jq
interpreter `length` and slicing consumers. Direct cases include all byte values,
retained malformed prefixes and three deterministic generated-byte seeds.
Observations include counts, kept bytes/references, program results and residual
allocations after cleanup. The complete selected native body is trapped on the
source side. This is finite execution evidence, not all-path coverage.

## Source-program integration

The existing [portable source recipe](../jq-portable/README.md) accepts this
reviewed additional binding:

```sh
python tests/fixtures/jq-portable/prepare.py \
  --comparison build/jq-portable-subsystem-2026-09-22/workflow-v3/network-edit \
  --extra-comparison build/length-workflow/local-repaired \
  --original-derivation build/jq-portable-subsystem-2026-09-22/original-derivation.json \
  --output /tmp/my-jq-with-length
```

Follow its build/run instructions on each architecture. The selected native source
body is removed, the existing string and live-value adapters are reused, and
observation names follow the selection. This adds one explicitly supported
binding; it is not a generic mapper for arbitrary new native services. Existing
CLI/compiler/VM and other unlifted dependencies remain in the source backend.

## Retained results and effort

`build/component-workspace-2026-09-22/public-workflow-v3/` passes the public sequence
in 54.147s. Final automatic preparation takes 0.250s, the baseline check 8.830s and
a compatible edit/check 7.137s. The edit compiles one file in 0.032s; Wine startup
takes 4.293s wall time. The unchanged neighbor reuses its result in 1.018s with
zero compiler/link/execution/model/solver work. Initial analysis and adapter work
are separate from these prepared-operation timings.

The truncated-group defect reports `$.sequences[11].count` (2 versus 3); the
byte-count defect reports `$.program[0][0]` (4 versus 9). Both replay from retained
bad inputs after source repair. The first public recipe attempt had a variable
shadowing error, and a later launch supplied a nonexistent package path. Those
failed attempts remain retained; neither is a semantic checker limitation.

Clean standalone builds take 19.946s on x86-64 and 240.148s with an AArch64 compiler
itself running under QEMU. Both pass 61 normal CLI comparisons, 32 live-value
scenarios and seven selected allocation-failure cases. All thirteen selected
operations execute in the CLI suite, including 43 calls to the new operation.
Model and solver work is zero; no extraction/proof pilot is rebuilt.

The algorithm is 27 C lines; the entry/scenario observer is 79, preparation is 73
Python lines, and the walkthrough is 65. Generated code and reused adapters are
excluded. These are an effort inventory, not productivity scores. Existing live
objects, retained initialization/allocator/interpreter behavior, synchronous
single-thread execution and the source backend's documented limits still apply.
Tested behavior, declared premises and unobserved behavior remain distinct.

The service-reuse follow-up at `build/service-boundary-reuse-2026-09-22/` repeats
the public sequence using declarations selected from the retained workspace,
without importing the original declaration recipe. It passes edit/replay/neighbor
reuse and source export; the 129 exported files are unchanged, so standalone
program evidence is retained without another build. This follow-up improves an
existing operation's setup, rather than claiming a second unprepared-boundary trial.
