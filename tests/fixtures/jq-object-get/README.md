# Lift lookup over a shared jq object table

This previously unprepared component replaces the complete `jv_object_get`
operation. It owns a real collision-chain loop over native heap storage, acquires
the result reference, then releases its inputs. The existing value/path network
uses that operation. Its inputs, shared view and lifecycle assumptions are in
[BOUNDARY.md](BOUNDARY.md); the portable implementation is [get.c](get.c).

The boundary is deliberately the complete operation. The private slot-search
helper would also need a private-entry adapter in every backend, while callers
already share this consuming object/key API. The native object-lookup helpers are not
used by the lifted lookup. Hashing, equality, reference management and the rest of
the jq backend remain explicit dependencies.

The [object-deletion handoff](../jq-object-delete/README.md) reuses this layout
and driver for mutation. It establishes a new view after copy-on-write, detects
an alias-only discrepancy and integrates alongside lookup through normal entry.

## Prepare once, then edit locally

Use the existing lifting shell and a retained jq path-network workspace containing
`value-get`, such as
`build/component-boundary-recipe-2026-09-24/jq-reopened`:

```sh
python tests/fixtures/jq-object-get/prepare.py /path/to/network prepared
spaghetti-extractor component start jq object-get \
  --comparison-package prepared/object-get --output work
spaghetti-extractor component status jq object-get --comparison-package work
spaghetti-headless-wayland --interactive bash
```

Keep that desktop shell open for checks. Edit `work/source/get.c`; the workspace
retains the native image, reviewed boundary, object view, services, adapters and
case inputs. Ordinary edits need no changes in neighboring components:

```sh
spaghetti-extractor component check jq object-get \
  --comparison-package work --output baseline
spaghetti-extractor component check jq object-get \
  --comparison-package work --reuse-comparison baseline --output edited
```

There are three comparison cases: a batch with a collision table, absent keys and
present null; unique ownership with a nested returned object; and an interpreter
workload reading retained aliases around updates and deletion. The shared driver
observes returned values, retained inputs/reference counts and allocation lifetime.
The tiny driver wrapper distinguishes an absent key from present JSON null.
The native DLL uses a process-specific string hash seed, so raw bucket layouts
and collision counts are diagnostics, not cross-process equality observations.
The driver can call the replaced entry during parsing or serialization too;
its total entry count is not application branch coverage.

A useful defect exercise is to replace `while (index != -1)` with
`while (index != -1 && 0)`. Check only `--case unique-owner`; the first difference
identifies a present value incorrectly reported absent. The command exits 2 for
this mismatch and prints the exact replay command. Restore the loop and reuse
the matching receipt. Neither the boundary nor neighboring implementations need
to change for this repair.

## Connect the existing native comparison network

Open the getter inside the existing network:

```sh
spaghetti-extractor component start jq value-get \
  --comparison-package /path/to/network --output network-work
```

Edit `network-work/dependencies/value-get/revise-boundary.py`. Its existing
`WORKSPACE` refers to the complete workspace; replace `boundary_changes` with:

```python
def boundary_changes(unit):
    import copy
    from spaghetti_extractor.components.comparison_composition import bind_dependencies

    added = bind_dependencies(services={"object_get": Path("/path/to/edited/inputs")})
    bridge = copy.deepcopy(unit["service_bridge"])
    bridge["adapters"]["object_get"].update(symbol="fixture_object_get", declare=True)
    # Review this C call boundary: both entries consume two jv values and return
    # an owned jv result. An edge alone does not implement or validate that call.
    return dict(dependencies=added["dependencies"],
        requirements=[*unit.get("requirements", []), *added["requirements"]],
        service_bridge=bridge)
```

`declare=True` emits the supplier's C prototype from this service's selected
transport. The caller's adapter C stays unchanged. This generates a declaration;
the reviewed consuming ABI and actual supplier behavior still need comparison.

Then prepare and check the retained consumer:

```sh
python network-work/dependencies/value-get/revise-boundary.py --output connected
spaghetti-extractor component start jq object-get \
  --comparison-package connected --output connected-work
spaghetti-extractor component check jq object-get \
  --comparison-package connected-work --case nested-negative-refactor \
  --reuse-comparison /path/to/previous-network-result --output connected-check
spaghetti-extractor component status jq object-get \
  --comparison-result connected-check --details
```

Use a case actually retained by your network. The check names the enclosing
`path-set` comparison; the final inspection reports the selected lookup's service
participation. Its standalone comparison remains the separate local evidence.
This revision preserves the getter's authored C, its two callers, other suppliers,
original runtime and case definitions. It adds the reviewed supplier and changes
only the executable service binding. Later C edits use the ordinary
`--dependency-source object-get=/path/to/work` workflow. No local getter fixture,
manual digest editing or new contract format is needed.

`build/component-service-declarations-2026-09-24/` follows this shorter recipe:
all 54 existing C/adapter files stay unchanged, the interpreter case observes the
lookup, and the binding returns through source export/refresh to the normal
portable program. Only that program's getter binding recompiles; its 19 component
objects and backend objects reuse. The older handoff below used an explicit C
prototype; its behavioral results remain historical evidence.

The installed handoff in `build/component-selected-service-2026-09-24/` uses this
recipe, retaining 53 existing C/adapter files and all case definitions. Its existing
`program-builtins` case matches and observes four lookup service scopes. A local
refactor removes the `goto`, passes the standalone cases and returns through
`--dependency-source`; the consumer compiles only that file. Repeating the check
takes 3.095s with zero compiler/link/model/solver/execution work.

## Use it in the existing source program

Given the existing partial portable jq project and a matching edited comparison:

```sh
spaghetti-extractor candidate export jq --comparison edited \
  --output /path/to/project/lifted --update-components \
  --component object-get --accept-boundary-change object-get
python tests/fixtures/jq-portable/refresh.py /path/to/project \
  --bindings tests/fixtures/jq-object-get/portable-bindings.json
python tests/fixtures/jq-portable/build.py /path/to/project build/object-program \
  --cc "$(command -v cc)" --ar "$(command -v ar)" --ranlib "$(command -v ranlib)"
/path/to/project/jq -nc \
  '{"a":[{"b":7,"keep":11}],"other":3} | setpath(["a",-1,"b"];8)'
```

The existing binding recipe removes the backend's `jv_object_get` and supplies
the lifted entry under that same API. Existing lifted getters and path operations
therefore reach it without changing their C. The C adapters use the backend's
public services; no private native addresses enter the portable project. Other
object operations, parser, VM, allocator and platform services remain unlifted.

When exporting the connected comparison above, select both `object-get` and
`value-get` so the reviewed getter binding travels with the edited supplier.
The native comparison calls `fixture_object_get`; the source project supplies
the public `jv_object_get` entry. Add this explicit service mapping to the JSON
passed to `refresh.py --bindings` (existing project choices are retained):

```json
{"value-get": {"service_symbols": {"object_get": "jv_object_get"}}}
```

That round trip passes the same native-derived interpreter workload through
normal source-program entry. The incremental build takes 0.164s, compiling only
the lookup C and reusing existing bindings and the backend. This mapping is a
reviewed C assembly choice, not an inferred compatibility proof.

## Preparation findings

No compiler, checker or artifact internals were changed. The trial reuses the
existing service declarations, value transport, native entry helper, allocation
observer, two-value comparison driver and source-project update commands.
The new work is the shared table view/adapters, a small observation wrapper,
declarations/cases and a normal source binding. The reviewed layout is defined
once; the loop reads the original live allocation through that view.

Establishing this boundary still takes more work than writing or editing the loop:
an operator must identify the complete entry, check the native layout and ownership,
choose observations and review public-service adapters. Those are explicit C and
boundary tasks, not solver development, but this is not a turnkey arbitrary-target
workflow or an independent human usability study. The automated preparation time
does not include that manual investigation.

The installed walkthrough, actual costs, deliberate defect/replay, repair and
source integration are retained under `build/component-object-lookup-2026-09-24/`.
All three native cases match. The local edit compiles one file and reuses five;
a repeated matching check takes 0.764s with no compilation or execution. Normal
source-program entry passes on x86-64 and AArch64 under QEMU. This addition also
exposed diagnostic counter renumbering that rebuilt every binding. The source
recipe now uses stable names: after its one-time migration, adding this component
preserves existing binding C and objects and compiles two binding/observation
files instead of eighteen. That counter change is exercised on x86-64; the
AArch64 result uses the same component before the diagnostic migration.
They are practical finite evidence; this component has no universal equivalence
qualification and does not make the remaining jq backend portable recovery.
