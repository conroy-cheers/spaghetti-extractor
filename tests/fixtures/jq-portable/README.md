# Portable jq subsystem handoff

The latest [path and source-delivery continuation](../../../docs/jq-path-services-continuation.md)
finishes the shared Windows path provider, including drive/UNC module consumers.
All application stages are now selected C components or explicitly reviewed C
libraries/generated syntax code. `deliver.py PROJECT OUTPUT` packages a reviewed
built selection without objects, native binaries or old proposal trees. It keeps
licenses, component boundaries and a library source inventory. Build the result
with ordinary `make`; native comparison remains a separate development action.
The historical subsystem steps below remain useful for starting a partial project.

The latest [IR/lifecycle continuation](../../../docs/jq-ir-continuation.md) adds
instruction-graph construction/binding and execution lifecycle beside the existing
bytecode compiler and interpreter. Its assembly-refinement blocker is resolved by
[`candidate apply`](../../../docs/component-assembly-updates.md): stage export,
this recipe's desired bindings and integration checks together. Refresh now
reconciles changed entry providers and backend replacement groups, including
restoration of retained bodies. Failed preparation preserves the working project.

The preceding [value continuation](../../../docs/jq-value-continuation.md) adds
value ordering/deletion and recursive equality/containment/merging, with a shared
C sorting provider for the pinned CRT's observable NaN behavior. The build recipe
distinguishes removed private helpers from the native entries that must remain
callable. The original handoff below records the earlier array/path subsystem;
the continuation report identifies the current complete source projects.

For operator-written adapters exposing multiple native entries, use the shared
[`assembly` binding declaration](../../../docs/component-module-workflow.md).
Initial preparation and refresh accept the same sources, entry mappings,
replacement definitions and lifetime description. Portable service choices can
be supplied independently of the native comparison harness.

This carries the existing twelve-unit array/path/string network into a conventional
source project and jq's normal command-line entry. A subsequent reviewed addition
also accepts the independently compared string-length operation described below.
The pinned jq CLI, parser, compiler, VM, objects, number/string primitives,
allocation and bundled oniguruma remain an explicit source backend. This is a
source-assisted partial lift, not complete portable recovery of jq.

The [array-search component](../jq-array-indexes/README.md) can now replace the
getter's retained search service through the same source-update/refresh path.
Its new entry and C adapter are explicit operator `--bindings` inputs; the old backend
definition is removed. The affected workload runs through normal CLI entry on
x86-64 and AArch64, while independently edited neighboring components remain
selected. This closes a concrete lower-service dependency, not a component-count
or complete-jq milestone.

The selected public operation bodies are removed from the backend. `jv_free`
retains only a renamed, guarded foreign-value destructor; nested array releases
return through the selected component. The build checks that the backend archive
defines none of the selected public symbols and that each final public
entry exists once. Original PE bodies and Behavioral-C are absent from the
delivered source project.

## Reproduce

Use `nix develop .#lifting`, which now supplies the standard autotools needed for
initial source preparation. All Wine applications and servers run through
`spaghetti-headless-wayland`. Obtain a matching connected comparison through the
[string-slice walkthrough](../jq-string-slice/README.md). Retained inputs for this
checkpoint are `build/jq-string-slice-2026-09-22/workflow-v2/network-repaired`.

Keep `nix derivation show <original-jq-derivation>` JSON with the pinned original
input. Preparation reads its source archive and ordered patches, verifying their
exact hashes against the DLL used in the comparison. It also accepts explicit
`--upstream-tar` and seven ordered `--patch` arguments. It never silently replaces
the patched target with a stock upstream release.

```sh
python tests/fixtures/jq-portable/prepare.py \
  --comparison build/jq-string-slice-2026-09-22/workflow-v2/network-repaired \
  --original-derivation build/jq-portable-subsystem-2026-09-22/original-derivation.json \
  --output /tmp/my-portable-jq

python tests/fixtures/jq-portable/build.py \
  /tmp/my-portable-jq build/my-jq-build \
  --cc "$(command -v cc)" --ar "$(command -v ar)" --ranlib "$(command -v ranlib)"
```

Preparation exports through the existing source API, generates service bridges
through the existing service generator, and packages ordinary C adapters. The
result also builds with ordinary `make` outside the checkout, without Python,
Nix, Wine or the extractor. It needs a C11 compiler, binutils, GNU make and the
ordinary configure utilities. The original executable is only the comparison
oracle. `make live-values` builds the separate diagnostic C API consumer.

You can separate native comparison from source assembly entirely:

```sh
spaghetti-extractor candidate export jq \
  --comparison build/jq-portable-subsystem-2026-09-22/workflow-v3/network-edit \
  --comparison build/component-workspace-2026-09-22/public-workflow-v3/local-repaired \
  --output build/jq-source-handoff

python tests/fixtures/jq-portable/prepare.py \
  --source-export build/jq-source-handoff \
  --original-derivation build/jq-portable-subsystem-2026-09-22/original-derivation.json \
  --output /tmp/my-jq-from-source
```

The second step reads only the source handoff, the pinned upstream source/patch
inputs and this recipe's C adapters. Comparison workspaces, the original DLL and
native compiler/Wine paths are not needed. The derivation JSON locates source
archives and patches; preparation does not evaluate or build that derivation.
Only inventoried source files are copied from the handoff, excluding old compiled
objects and unrelated files. `--source-export` and comparison inputs are exclusive.

The existing source export now includes original input identities and comparison
binding references. This recipe reviews their entry/service mapping for its known
backend, then calls the shared `render_source_service_bridges` API. It rejects
missing/ambiguous reference bindings and unsupported selections. Older libraries
need a fresh public export to supply these references; unchanged native comparison
evidence can be reused. The underlying library reader still accepts old exports
when callers supply their own explicit bindings.

For another architecture use a separate project copy, corresponding `--cc`,
`--ar`, `--ranlib` and `--host aarch64-linux-gnu`. The retained AArch64 measurement
uses an AArch64 compiler running under existing QEMU binfmt, not an efficient
host cross compiler; its initial build time is consequently much higher.

```sh
spaghetti-headless-wayland python tests/fixtures/jq-portable/run.py \
  build/my-jq-build /path/to/pinned-original/bin build/my-jq-run \
  --runner "$(command -v wine)" --server "$(command -v wineserver)" \
  --pe-cc "$(command -v i686-w64-mingw32-gcc)"
```

Add `--qemu /path/to/qemu-aarch64` for an AArch64 build. The oracle directory must
contain the untouched pinned `jq.exe` and its DLLs; the adjacent `lib` directory
supplies the import library for the diagnostic consumer. The runner compares raw
stdout, stderr and exit status, using jq's actual `--binary` option on Windows.
It does not normalize output or remove unexpected diagnostics.

When the source selection grows, append program workloads with repeatable
`--case-file FILE` arguments. Each file contains a JSON array in the same form
as the runner's retained `cases.json`, for example:

```json
[{"id":"operator-object-delete","arguments":["--binary","-c","del(.drop)"],"stdin_hex":"7b2264726f70223a317d0a"}]
```

These cases run alongside the built-in workloads against both executables; use
`--case operator-object-delete` to focus diagnosis. Duplicate identifiers and
invalid case inputs reject before creating the output directory. The full run
still requires every selected component to execute. Extra cases and their exact
arguments/input bytes are retained in `cases.json` and bound by the run report.
No runner-code edit or component rebuild is needed merely to add a workload.
The delivery audit at `build/practical-product-audit-2026-09-25/` uses this path
to cover array/string indexes and object deletion in the expanded selection:
62 normal-entry cases and the existing 32 live-value scenarios pass on x86-64
and AArch64 with the same retained builds.

`walkthrough.py --help` lists the explicit component/neighbor/network receipts,
project/build directories and tools. It performs public start/check/export-update,
checks unchanged-neighbor reuse, rebuilds and exercises both programs, then injects
a wrong backend exit, retains and replays the wrong executable after source repair,
and verifies repair. Revalidation after an environment change is recorded before
warm editing; it is not counted as free neighbor reuse.

## What the backend trial found

The [workspace/string-length trial](../jq-string-length/README.md) adds a separately
compared `jv_string_length_codepoints` through repeatable
`prepare.py --extra-comparison PATH`. This source recipe currently implements that
specific additional binding; it is not an arbitrary automatic backend mapper.
The added receipt must use the same pinned original. Preparation removes that
public body too, reuses the existing string/view/transport C adapters, and derives
observation names from the resulting thirteen-component selection. Initial
preparation supplies these reviewed bindings; an existing project can also accept
additional checked components through a partial export after integration review.

For a local edit, `candidate export jq --comparison LOCAL_CHECK --output
PROJECT/lifted --update-components` retains the remaining exported units without
their comparison directories. It refreshes every unit selected by the supplied
comparison, so use a local package when updating only one component. The checkpoint
at `build/component-partial-export-2026-09-23/` updates string-byte-length, retains
13 neighbors and rebuilds one unit plus the final link in 0.067s. Normal CLI output
is byte-identical before/after. This is a portable consumer and handoff check;
the native component comparison is retained rather than rerun.

For current assembled projects, use `candidate apply` with `--project PROJECT`
and `--assembly-command 'python /absolute/path/to/refresh.py {project}'`. Supply
the comparison and component flags shown below, and a `--check-command` for the
build and affected workloads. This stages the following export/refresh steps as
one operation; the separate commands remain useful for library-only handoffs.

For an addition, name the new unit and acknowledge its integration review:

```sh
spaghetti-extractor candidate export jq --comparison STRING_INDEX_CHECK \
  --output PROJECT/lifted --update-components --component string-indexes \
  --accept-boundary-change string-indexes
```

For entries already declared in the project or recipe, refresh the application integration:

```sh
python tests/fixtures/jq-portable/refresh.py PROJECT
make -C PROJECT -j2
```

Run these preparation commands in the lifting shell. The refresh uses the same
reviewed bindings as initial preparation: it generates the entry and required
header, removes the superseded backend definition, updates the Makefile and
observation names, and records source provenance. It needs the existing project
and its updated `lifted/` library, with no original executable, comparison folders,
upstream extraction or backend reconfiguration. Existing components and build
products remain. Then exercise the affected workloads through normal program entry.

Conflicting operator edits leave the project unchanged and retain proposed files
in the printed sibling directory. Merge the relevant binding/build changes with
your edits, then acknowledge those files explicitly:

```sh
python tests/fixtures/jq-portable/refresh.py PROJECT --keep-reviewed Makefile
```

Repeat the flag for other reviewed merges. The recipe retains the actual merged
bytes, records their hashes separately from the generated baseline, and keeps a
backup of replaced files. Unchanged refreshes preserve source mtimes. Accepting a
merge does not validate the program; rebuild and run its affected workloads.
New service implementations, changed shared layouts, backend edits conflicting
with definition removal, and component removal still require explicit assembly
work. The recipe does not infer arbitrary platform bindings.

Entry counters use stable component names with a cached lookup, so adding a
component does not rewrite existing bindings merely to renumber diagnostics.
The counter implementation/table and the new binding rebuild; unchanged binding
and component objects remain reusable. Refreshing an older project migrates its
counter API once through the same proposal/backup checks. The
[object-table handoff](../jq-object-get/README.md) records the measured reduction
from eighteen binding compilations to two while preserving normal program output.

`build/component-source-addition-2026-09-24/` extends the existing fourteen-unit
project with its already compared string-indexes implementation. It reuses nine
reviewed integration files from the prepared fifteen-unit recipe. Export takes
0.523s and the incremental build 0.765s: one new lifted unit, one changed backend
file, six binding/observation files and two links. All fourteen existing component
objects and provenance remain intact. Five normal CLI searches match both the
previous executable and retained native observations, and execute the new entry
five times. This is a host integration handoff; it does not repeat native or
AArch64 execution or establish another newly prepared boundary.

The follow-up at `build/component-binding-refresh-2026-09-24/` performs the same
handoff through `refresh.py`, eliminating those manual copies and metadata edits.
It exercises conflict diagnosis and a reviewed Makefile merge, then retains all
fourteen neighboring component objects. Export takes 0.529s, refresh 0.255s and
incremental build 0.715s. Five normal CLI searches match retained native results.
Initial generated bindings remain byte-identical after the recipe refactor; the
incremental compiled inputs match the existing reviewed preparation. The scope
remains a prepared x86-64 handoff, not a new boundary or full jq lift.

The [object-deletion handoff](../jq-object-delete/README.md) subsequently reaches
this path with a manually edited backend C file. Function replacement and managed
adapter includes now start from the exact current backend bytes, preserving other
C edits without requiring a redundant manual merge. The old backend is backed up;
an edited managed include block, conflicting replacement header or concurrent
source change still requires resolution. Generated binding/Makefile conflicts
continue to use the proposal and `--keep-reviewed` path. Both x86-64 and AArch64
program execution pass after integrating the new mutable-table component.

Start from `PROJECT/lifted/README.md` to open each component's generated boundary
guide beside its C. It records shared state, service/lifecycle declarations,
assumptions, dependencies and comparison examples, with local source links.
These refresh on export; keep personal notes separately. Native comparison binding
examples do not select or validate this project's portable backend.

For the bindings actually selected by the portable program, open
`PROJECT/COMPONENTS.md`. Each linked `bindings/COMPONENT.md` identifies its C entry,
service adapter symbols, declared component suppliers and consumers, shared C
support, reviewed headers and private-state backend adapters. An undeclared
supplier may still call selected components through its ordinary C binding;
the guide does not infer that implementation's dependency closure.
Preparation and `refresh.py` generate these guides from the same choices that
generate the C bindings. Documentation-only refreshes retain prior validation
scope and do not request compilation or new execution. Conflicting operator edits
still use the existing proposal/review workflow.

You may edit C directly under `PROJECT/lifted/components/COMPONENT/sources`, then
run `component start jq COMPONENT --comparison-result LOCAL_CHECK
--reuse-source PROJECT/lifted --output DRAFT`. Check that draft against the original
using the printed `component check` command, then publish the matching comparison
with the partial update above. The retained result supplies its oracle, adapters,
cases and reuse baseline. Its selected case is retained unless you append cases
with `--reuse-cases`. The checker reassesses reuse after C or environment changes;
opening a draft does not carry old assurance to changed C. If you have only a
prepared package, use `--comparison-package LOCAL_PACKAGE` instead.
The printed command uses a check history: its initial result seeds the first
check, then the same command follows the newest result after every edit. Use the
history's `latest` path for export after a matching check; a mismatch also advances
`latest` and remains available for diagnosis.
Headers/contracts/source-layout changes
use authoring/refinement instead. The installed trial at
`build/component-source-roundtrip-2026-09-23/` imports a string-byte-length edit in
0.331s, freshly compares the selected native case in 7.537s, updates in 0.427s and
rebuilds one component plus the final link in 0.076s. Thirteen neighbors remain
built, and normal portable CLI output is byte-identical before/after.

The recipe also accepts the separately compared
[`string-byte-length`](../jq-string-byte-length/README.md) selection. Its original
`jv_string_length_bytes` definition is removed. Both string operations share a
reviewed live-allocation view which obtains contents without calling byte length,
so the selected replacement cannot recurse through its own adapter. This is an
explicit source-backend binding, using the same export/build facilities.

The [two-input string-index search](../jq-string-indexes/README.md) uses the same
`--extra-comparison` option. Its binding reuses the shared live string view and
value transport, with an explicit small number/array-append adapter. Preparation
removes `jv_string_indexes` from the backend and includes that adapter in the
standalone project. New boundary preparation and platform integration remain
separate tasks; successfully exporting component C alone does not supply a backend.

For a new operation, supply reviewed choices through `--bindings FILE` to either
`prepare.py` or `refresh.py`. No shared recipe edit is needed. For example,
[the array-search declaration](../jq-array-indexes/portable-bindings.json) is:

```json
{
  "array-indexes": {
    "native_symbol": "jv_array_indexes",
    "backend_file": "src/jv.c",
    "headers": {"array-indexes-native.h": "array-indexes-native.h"}
  },
  "value-get": {
    "service_symbols": {"indexes": "jv_array_indexes"}
  }
}
```

After the public partial source export selects the new unit, apply its choices:

```sh
python tests/fixtures/jq-portable/refresh.py PROJECT \
  --bindings tests/fixtures/jq-array-indexes/portable-bindings.json
make -C PROJECT -j2
```

The component's retained comparison binding supplies argument/result transport
and services. `native_symbol` names the reviewed generated entry; `backend_file`
locates its superseded definition relative to `backends/jq`. By default that
definition has the same name; optional `backend_symbol` names a different body
when an ordinary C adapter must preserve a platform ABI. The
[string-hash example](../jq-string-hash/README.md) uses a `uint32_t` component
entry and an `unsigned long` public wrapper on 32-bit and 64-bit platforms.
Both initial preparation and refresh retain this explicit choice and remove the
named original body. The wrapper remains reviewed operator C.
The [object lifecycle example](../jq-object-storage/README.md) also replaces
private `static` definitions. Their former positions retain external C
declarations for existing callers; the supplied wrapper definitions belong in
`bindings/`, outside the backend archive. The ordinary original-body absence and
single-definition checks remain required. Opaque/scalar entries without value
transports use their explicitly supplied headers, without assuming the token
transport declaration.
`headers` maps plain
destination filenames to C files relative to the JSON file (absolute paths also
work). They are copied into `bindings/` and included by the generated bridge.
`service_symbols` explicitly redirects named services in an existing component's
binding. This example redirects the getter's `indexes` service from the comparison
hook to the portable search entry. Symbol names alone do not establish semantic
compatibility; review transport, shared state and interactions, then exercise the
affected program workloads.

When a service needs a backend's private state or functions, supply ordinary C
headers to include at the end of the reviewed backend translation unit:

```json
{
  "string-hash": {
    "backend_headers": {
      "src/jv.c": {"hash-seed-backend.h": "hash-seed-backend.h"}
    }
  }
}
```

Each key names an existing `src/*.c` backend file; its header paths are relative
to this JSON file, like the ordinary binding headers above. Preparation and
refresh copy them beside that C file and maintain one include block after its
private definitions. Headers are included in filename order; make them
self-contained, with normal include guards. Shared destinations must have
identical bytes. This exposes no service automatically: write the C accessor and
its declaration and select its existing service binding explicitly. The
[hash seed accessor](../jq-string-hash/hash-seed-backend.h) reuses the same private
seed/once state as unlifted consumers.

These headers are retained as project inputs. Subsequent refreshes need no original
operator folder. A local header edit marks program validation stale, and ordinary
compiler dependencies rebuild the affected backend file while preserving lifted
component objects. Conflicting incoming C goes through the same proposal/backup
and `--keep-reviewed backends/jq/src/HEADER.h` flow as other source integration.
Keep unrelated code outside the managed include block; a changed block requires
reconciliation with the recorded binding choices. Existing vendor headers are
not overwritten by newly named adapters. Changing `backend_headers` replaces that
component's map; cleared entries remove the managed includes, leaving unused
header files available for operator review.

Choices augment this recipe's existing defaults. An input updates the supplied
fields of each named component; service mappings merge by name and a supplied
`headers` map replaces that component's header list. Initial preparation and
refresh retain selected choices in `portable-project.json`, using project-relative
header paths and the existing file inventory. Later `refresh.py PROJECT` needs
neither the JSON file nor its original header locations. New choices may be
supplied with the same option. Existing entry names/backend locations cannot be
silently changed during refresh. Projects prepared before this input was added
need the array-search declaration once, after which it is retained.

This is an input to the jq source recipe, not a new proof artifact or an automatic
backend mapper. The pinned backend definition scanner handles its ordinary
`jv`, `int`, `void` and `unsigned long` definitions, including `static` ones, in
`src/*.c`. The recipe still requires its
shared live-value transport and core storage/path selection. Separate new
translation units or different representation/layouts require ordinary
adapter/build integration. Backend headers are reviewed C, not inferred state
transport or checked service summaries. Unsupported service names and missing headers report
the affected binding; exporting C does not invent those dependencies.

`build/component-backend-inputs-2026-09-24/checkpoint.json` records this handoff
from operator inputs, a normal CLI run and a refresh after the original input
directory was moved away. Preparation/refresh reproduce the previously executed
array-search selection's generated C/backend files; native comparisons and the
second architecture are retained evidence, not rerun for this recipe change.

`build/component-workspace-2026-09-22/` retains clean standalone builds, 61 CLI
cases, 32 live-value scenarios and seven allocation-failure comparisons on each
architecture for that selection. The new operation executes 43 times across the
CLI cases. This closes one measured workspace/boundary reuse trial; it does not
change the unlifted backend or the environment/failure limits below.

The PE32 CLI's input callback is an executable import thunk. Its address differs
from the DLL function, despite identical call behavior. A naive static source
assembly changes `input_filename`, `input_line_number` and fatal error handling.
The original emits a UTF-16LE assertion and exits 3 where stock source reports an
ordinary error and exits 5. `import-runtime.c` preserves the distinct callback
identity and the observed redirected binary-stream assertion behavior. It keeps
that original defect explicit; it is not a new proof/checker exception.

Shared array layouts are defined once in the exported storage headers. Private
authored descriptors load/store actual native-backed values. The path/string
binding copies the complete host `jv`, including real live pointers. It needs no
bounded token table, but it also inherits no proof or runtime-observation authority
from the PE32 comparison's token instrumentation. The additional live-value
consumer checks logical contents, actual pointer alias relationships, reference
counts and view-release effects on both architectures.

## Evidence and limits

### Source handoff without the native comparison environment

`build/source-binding-handoff-2026-09-22/` retains preparation with comparison
readers and Wine execution disabled. Preparation takes 5.696s; all 316 compiled
source/build inputs equal the preceding thirteen-component project. Source
bindings also reproduce the existing Hello stream and four-unit DX-Ball graphics
bindings without reading comparisons during generation. That is binding reuse,
not fresh execution of those targets.

Public updates of the existing standalone projects preserve all 27 library build
outputs on each architecture. Make compiles zero objects and performs only its
three final links (0.164s host / 1.316s with the emulated AArch64 compiler). The
program, live-value and allocation-failure executables stay byte-identical on
each architecture. Their previously retained 61 CLI, 32 live-value and seven
failure comparisons remain applicable; this checkpoint does not claim fresh
program execution. No extraction/proof pilot or solver runs.

The unit regression removes the original comparison directories before generating
and compiling a portable binding, and a deliberately wrong backend fails its
consumer. Separate compared bindings are retained rather than silently choosing
one. Source tampering, incomplete provenance and incompatible service contracts
reject. This removes a dependency on the native test environment; target-specific
application entry, body replacement and executable service semantics still need
reviewed C and program validation.

### Allocation failure in this source backend

Add `--allocation-failures` to `build.py` to package the separate `failure`
executable and exact diagnostic sources in its build receipt. Existing prepared
projects need the new `diagnostics/` files; fresh `prepare.py` packages them.
The delivered Make overlay also works without the extractor:
`make -f Makefile -f diagnostics/failure.mk failure`. It reuses existing objects,
observing the source backend through GNU linker wrappers. Ordinary program builds
omit these wrappers. The same allocation observer retains the existing PE32 import
hooks for the oracle; neither path clones the target heap.

```sh
spaghetti-headless-wayland python tests/fixtures/jq-portable/failure.py \
  build/my-jq-build /path/to/pinned-original/bin build/my-jq-failure-run \
  --runner "$(command -v wine)" --server "$(command -v wineserver)" \
  --pe-cc "$(command -v i686-w64-mingw32-gcc)"
```

Add `--qemu /path/to/qemu-aarch64` for AArch64. Eight cases exercise copied,
empty and invalid strings, array creation, shared mutation, growth and an actual
`jq_start`/`jq_next` string-slice failure with warm and cold numeric contexts.
Exact inputs are in `failure.c`.
An entry hook on the pinned original, or a link wrapper on source execution,
arms the next real allocator failure. The real registered callback delivers
`longjmp`. Compare callback/context, sentinel output, retained contents and
references, fault size/count and residual allocations after real cleanup.
Results name the differing JSON fields and retain exact streams/executables.
Allocation activity totals are diagnostic; unexpected stderr is rejected.

Handler registration happens before observation. `program-string` initializes
numeric conversion first. `program-string-cold` now runs without that preparation
and uses an explicit representation observation for its thread-local context.
The C adapter intercepts the real initializer, executes its original body, and
records the actual observed heap allocation's generation. The same initializer
also serves stack objects, which are not this allocation. After failure and
cleanup, the adapter checks that the captured allocation is still live, has the
expected extent, and contains nine null pointers. Reuse of its address does not
preserve its generation. A populated context needs a richer adapter and is
reported as unsupported by this one.

The C driver maps only that named object: 36 physical bytes on Win32 and 72 on
either portable host. It emits its logical existence, lifetime and nine null slots
alongside exact remaining allocation sizes/totals, reference counts, values,
callbacks and faults. All eight cases now use exact stdout and exit comparisons;
there is no Python normalization rule. Raw `[26,36,392]` / `[26,72,392]` physical
sizes and totals are retained separately in stderr and checked against that logical
view, with `physical_differences` and `representation_relation` in the result.
There is no general pointer-width adjustment or suppression of heap differences.

The C observer's `allocation_observer_generation` and
`allocation_observer_live_allocation` queries can support other reviewed object
adapters without changing the checker. They identify a lifetime and report its
physical extent; the operator still defines the logical contents and relation.
This is concrete observation, not a universal memory or representation proof.
`allocation_observer_snapshot`, `allocation_observer_remaining_sizes` and
`allocation_observer_end` let a C adapter describe an identified object separately
while retaining exact observations of the remaining heap. The existing `finish`
convenience function keeps its raw lifetime output for other consumers.

The [string-slice preparation recipe](../jq-string-slice/README.md#use-the-failure-consumer-in-the-ordinary-component-workspace)
uses this same C driver through public component start/check/history/status/replay
and partial source export. Its five string cases include the actual cold interpreter
failure. A checked local implementation edit returns to the portable projects
without changing the component contract or rechecking neighboring components.
Current evidence is in `build/component-jq-failure-workflow-2026-09-24/`.

`build/component-jq-cold-context-2026-09-24/` retains all eight passing cases on
x86-64 and AArch64, including the cold case. An extra `jv_copy(value)` in the
ordinary string constructor still produces a `references.0` mismatch under this
relation. Repair passes, rebuilding one binding in 0.214s and preserving all
component/backend objects. The new observer needs only diagnostic recompilation;
the build recipe relinks the executables, and the normal jq and live-value hashes
remain equal to the earlier validated handoff. No pilot was rebuilt. Native
executions use headless Wayland.

The earlier `build/jq-portable-failure-2026-09-22/` retains seven-case comparisons on
both architectures and a defect/replay/repair workflow. Adding an unbalanced
`jv_copy(value)` to the ordinary `bindings/string.c` constructor changes only
the program failure's observed reference count from two to three. The comparison
identifies `references.0`; callback, contents and residual bytes still match.
Restoring the source does not alter the retained wrong executable: running that
build receipt again reproduces the defect. Rebuilding the repaired binding and
running all seven cases passes. Each edit compiles one binding and links in about
0.215s, without recompiling components or the backend. No checker, compiler
infrastructure, artifact format or proof rule was extended for this trial.

These are selected single-threaded failures with a nonreturning handler.
Returning handlers, concurrency, arbitrary allocation sites and physical
exhaustion remain outside the evidence. Nonzero residuals preserve observed
original behavior; they are not a claim of leak-free operation. The initial
diagnostic-only handoff preserved the ordinary program/live-value executable
hashes. The later local C edit rebuilds one component and reruns the affected
failure consumer on both architectures; it does not repeat the entire program suite.

### Program handoff

Retained work is under `build/jq-portable-subsystem-2026-09-22/`. Clean source
builds run in separate `/tmp/spaghetti-jq-portable-2026-09-22-*-v2` directories.
`host-normal-v1` and `arm-normal-v1` each compare 61 normal-entry cases and 32
live-value scenarios. Cases include generated nested paths, shared mutation,
Unicode/NUL contents, growth, input errors, callbacks, regex, streaming input,
file input and a 500-record aggregation workload. All twelve selected entries
execute through the normal program. Per-stage and final workflow status are
retained separately; the [current ledger](../../../docs/current-goal.md) records
the accepted terminal checkpoint.

The terminal `workflow-v3/walkthrough.json` and `checkpoint-audit.json` pass,
alongside ten integrated source-export tests and seven repository/SDK/build gates.
`portable-project/` contains the fresh prepared source project for the edited
selection; its compiled source/build inputs match the repaired executable's
retained snapshot. No new compilation is claimed for that identical source copy.

Preparation, configure, backend compilation, binding compilation, component
compilation, link, execution and environment revalidation have separate records.
Compiler phase times sum child process durations and may overlap; they are not
the build wall time. Build snapshots retain inputs, executables, tools and symbol
inventories. Compatible edits retain backend objects. This is ordinary make
dependency reuse within one toolchain/configuration, not a general semantic
compiler cache; use a clean build when changing flags or toolchains.

Initial attempts remain retained, including missing preparation tools, missing
static libc, backend make ordering, the actual callback discrepancy and an
incorrect assumption that old-environment receipts could be reused immediately.
Workflow v2 then exposes unconditional deletion of all exported component objects;
the shared exporter now retains unchanged units and conservatively invalidates
them when the generated build recipe changes. This was a tooling gap during the
trial. Workflow v3 passes the complete edit/update/replay/repair sequence, rebuilding
one component on each architecture and preserving all backend objects.
They are setup findings, not passing outcomes. Restoring the GC'd original costs
22.057s after the online cache reduces it to two builds and three small downloads;
the initial offline attempt fails. No extraction or formal-proof pilot is rebuilt.

This demonstrates transfer of source assembly and local updates beyond Hello.
It does not establish an independent human usability trial, full jq lifting,
general Win32 coverage or strong qualification. Single-threaded well-formed live
objects, target-width allocation bounds and executed redirected workloads define
the scope. Other CRT assertions, terminal/locale behavior, arbitrary callbacks,
physical exhaustion and full heap-lifetime assurance remain unobserved. The earlier
PE32 allocation-failure comparisons remain their own evidence; the additional
source-backend failure comparisons above establish only their explicitly tested
cases and initialization preconditions.
