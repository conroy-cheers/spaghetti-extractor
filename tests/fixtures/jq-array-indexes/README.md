# Lift the path getter's array-search dependency

This previously unprepared boundary replaces the real `jv_array_indexes` service
used by `value-get`, then returns through both `path-get` and `path-set` consumers.
It exercises a complete local-to-network handoff using the existing shared-value
transport, service declarations, authoring API and public comparison commands.
Read [BOUNDARY.md](BOUNDARY.md) for the original instruction range, inputs,
aliases, lifetime, lower services and scope. Analysis used the pinned source and
native disassembly; this is not an independent human or blind-decompilation trial.

[indexes.c](indexes.c) is ordinary C with a nested loop and consuming service
calls. It preserves overlapping matches, the empty-pattern result and continued
comparisons after a mismatch. The independent package imports no neighboring
authored bodies. Equality, numeric construction, append and native storage remain
explicit lower services in that check.

The local comparison now uses a nine-line entry wrapper around the
[shared two-value driver](../jq-value-transport/README.md#reusable-comparison-driver-for-two-owned-values).
Kinds, original/replacement entries and native body ranges remain explicit.
The existing retained, aliased, empty-pattern and interpreter case arguments are
unchanged. Observations now use `samples` (results, both aliases and reference
counts) plus `allocation_lifetime`; older receipts retain their original format.
An additional input can be passed with `--case-arguments` without changing C or
recompiling the driver. The shared header is copied into each prepared workspace;
external operator projects can keep it with their other reusable C support.

## Prepare, edit and compare

Use `nix develop /path/to/spaghetti-extractor#lifting` and a current reviewed
path-network workspace containing `value-get` and the shared runtime inputs.
Copy this directory to an operator project if desired; the recipe reads no
sibling fixture files:

```sh
python prepare.py /path/to/path-network prepared
spaghetti-extractor component start jq array-indexes \
  --comparison-package prepared/array-indexes --output local
spaghetti-extractor component status jq array-indexes --comparison-package local
spaghetti-headless-wayland spaghetti-extractor component check jq array-indexes \
  --comparison-package local --history checks
```

Edit `local/source/indexes.c` and repeat the check. The four cases cover retained
references, aliasing between the two arguments, an empty pattern and a real jq
interpreter consumer. The direct driver accepts two JSON arrays and a mode, so
`--case NAME --case-arguments '["[1,2,1,2]","[1,2]","retained"]'` can try another
input without changing the driver. Dropping the final pattern release preserves
positions but changes reference/allocation observations; the CLI supplies replay.

## Return the supplier through its callers

The C adapter declaration and requirement are explicit operator inputs:

```sh
python connect.py /path/to/path-network local connected
spaghetti-extractor component start jq value-get \
  --comparison-package connected/value-get --output getter
spaghetti-headless-wayland spaghetti-extractor component check jq value-get \
  --comparison-package getter --history getter-checks
spaghetti-extractor component status jq path-set \
  --comparison-package /path/to/path-network --dependency-package value-get=getter
spaghetti-extractor component start jq path-set \
  --comparison-package /path/to/path-network \
  --refine-requirement path-get/get=getter \
  --refine-requirement path-set/get=getter --output network
```

The caller C and its other selected suppliers remain intact. This example names
the new search supplier and its paths through both callers in the status preview,
before changing the selected network. The preview also prints its local inspection
command. The start command names
both call sites for review; the getter's public contract itself is unchanged, so
one selecting refinement suffices here. When a required contract changes, every
affected caller must still be reviewed. Later C-only
search edits use `--dependency-source array-indexes=local` on the network check;
they do not require reviewing those unchanged contracts again.

The first integration attempt exposed a shared-tool limitation: reviewed
refinement rejected a newly added transitive supplier. That path now imports the
reviewed package's declared closure while preserving compatible selected neighbors
and frozen requirements. Ordinary implementation replacement still rejects this
boundary change. Record this as toolkit work required during the new-boundary
trial, even though local authoring/checking needed no new semantics or compiler
support. The earlier standalone getter/local results remain valid evidence.

For the complete edit, defect/replay, refinement and consumer sequence:

```sh
spaghetti-headless-wayland python walkthrough.py /path/to/path-network workflow
```

The network workload `[.items[[1,2]],getpath(["items",[1,2]])]` exercises the new
search beneath the selected value/path entries on `{"items":[1,2,1,2,3]}`. It must
produce `[[0,2],[0,2]]` with matching reference and allocation observations.
The walkthrough uses existing driver inputs and records each command and cost.

## Update a standalone source program

The [portable jq recipe](../jq-portable/README.md) has the explicit source-backend
entry/header binding for this component. An existing project can use a partial
export of the checked `array-indexes`, `value-get`, `path-get` and `path-set`, with
`--accept-boundary-change` for each reviewed changed boundary, followed by that
recipe's `refresh.py --bindings portable-bindings.json` (using this directory's
[reviewed choices](portable-bindings.json)). It removes the old backend search definition and generates
the new service wiring while preserving unrelated C and eligible object files.
Build and run affected program workloads after the update. The entry, header and
getter service choices are retained in the source project; subsequent refreshes
need neither this JSON file nor its original header location. No per-component
edit to the shared source recipe is needed.

The scope remains partial source-assisted jq. Parser, VM, allocator, equality
and other native/source services remain dependencies. Allocation failure,
arbitrary callbacks/concurrency and strong qualification are not established by
these comparisons.

Evidence is retained in `build/component-array-indexes-2026-09-24/checkpoint.json`.
The local edit compiles one C file and reuses six; the connected follow-up compiles
one and reuses 35. The same source selection passes the affected normal CLI
workload on x86-64 and AArch64 under QEMU, with two calls through the new search
and no original search definition in the backend archive. Thirteen host and
twelve ARM neighboring component objects are preserved. The toolkit update
requires a separate local compiler-context refresh; those seven compilations are
recorded separately from the warm edit. No pilot or formal model was rebuilt.
