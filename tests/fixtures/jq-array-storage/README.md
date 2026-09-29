# Authored jq array storage through executable C boundaries

This is the first connected implementation for P1/P2 of the
[practical subsystem milestone](../../../docs/whole-target-independent-lifting.md#practical-subsystem-milestone-and-sequencing).
It moves array allocation initialization, reference accounting, reads, mutation,
copy-on-write and slicing into ordinary C. The seven units share a reviewed object
layout and explicit services. No new proof rule, machine model or artifact format
is involved. This is finite native-oracle comparison, not qualified whole-jq lifting.

The latest checkpoint (2026-09-22) completes the
[private descriptor migration](#private-descriptor-representation-change),
including mixed-selection rejection, conversion-defect replay/repair, a local C
edit and a fresh eleven-unit experimental assembly with all 42 cases passing.
Evidence is under `build/jq-array-storage-2026-09-21/representation-workflow-v1/`;
eight Nix shards pass 58 tests plus six repository/SDK gates in
`representation-validation-v1/`. The new assembly runs in 26.723s. The preceding
shared-admission checkpoint reduced execution of the old assembly from 212.155s
to 25.262s without changing its policy or executable. The
[performance ledger](../../../docs/performance-and-invalidation.md) records their
separate scopes and phase costs. No proof or pilot rebuild was needed.

## Hand-defined boundaries

The oracle is the existing jq 1.8.1 PE32 `libjq-1.dll`, SHA-256
`50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d`.
Image base is `0x6e380000`. The retained symbol map identifies these real entries:

| Authored unit | Original entry RVA | Boundary and retained dependencies |
|---|---|---|
| `storage-copy` | `jv_copy`, `0x27cce` | Borrow a descriptor, increment its allocation's reference count and return an owned descriptor with the same identity and view |
| `storage-release` | Array branch of `jv_free`, `0x27e4f`; `jvp_array_free`, `0x281a2` | Consume the array reference; on last release, release every initialized backing element and dispose the allocation; foreign destructors remain native |
| `storage-create` | `jv_array_sized`, `0x27808`; `jvp_array_alloc`, `0x25eb5` | Obtain storage from the guarded allocator, initialize reference/length/capacity and return an owned empty array |
| `storage-length` | `jv_array_length`, `0x28056` | Read the view length and consume its reference |
| `storage-get` | `jv_array_get`, `0x280cb` | Consume the view, copy its selected element or return invalid; preserve the backing offset and ownership |
| `storage-set` | `jv_array_set`, `0x28543`; `jvp_array_write`, `0x28273` | Consume array/item, normalize the index, preserve negative/large-index errors, reuse unique capacity or allocate/copy/release, fill holes and replace the selected slot |
| `storage-slice` | `jv_array_slice`, `0x28dc0` | Consume a view, clamp bounds, retain shared backing when possible, allocate for an empty slice or a 16-bit offset overflow |

These are experimental replacement responsibilities. The table does not establish
control-flow coverage, a machine binding or native admission. In particular,
`storage-release` has a native foreign-kind branch, and its recursive progress is
declared unproved. `jv_array`, append, concat and other unselected operations can
remain native consumers; selecting this family does not intercept every native call.

`value-layout.h` describes ordinary C objects, with actual pointers, not integer
tokens purporting to recreate heap contents. The native adapter checks descriptor
field offsets, the 16-byte descriptor and the 16-byte backing-array header. A
descriptor contains a view offset/length; the allocation separately contains its
reference count, initialized length and capacity. Distinct descriptors can share
that allocation. Destruction uses the initialized backing length, including values
outside a slice, and mutation copies only the visible view when sharing requires it.

Each generated operation takes typed descriptor holders. The C adapter copies
the original by-value descriptor into a local holder and transfers the output
descriptor back; it does not serialize or clone the pointed-to graph. The common
layout forms the `jq-array-storage` replacement group. Ordinary source edits do not
change that representation. A later representation change must account for every
native reader and writer, not merely update a revision label.

The source archive `/nix/store/6vr4s2af89acwmpjrr0awdk50lakzpjk-jq-1.8.1.tar.gz`
is an authoring reference, not binary-equivalence evidence. `COPYING.jq` retains
upstream licensing. This is source-assisted lifting with an independent native
oracle; both sides do not call the same authored array algorithm.

### Native representation crossings reviewed 2026-09-22

The selected array/path adapters and pinned source expose these crossings. This
inventory describes the current executable network, not exhaustive machine access
coverage of the DLL. The complete native image remains bound in every comparison.

| Crossing | Current implementation and consequence |
|---|---|
| Path values to array operations | `path-bridge.h` uses `storage_pack`/`storage_unpack` and the seven selected operations. `native.h` checks the descriptor offsets and descriptor/backing-header sizes. `memcpy` copies descriptors; it preserves their existing pointers and does not transport a different heap layout. |
| Array to array destruction | `release.c` walks every initialized backing element, including elements outside a slice, and routes array children through the authored release service. The allocator/disposer remain `jv_mem_alloc`/`jv_mem_free`. |
| Array to foreign object destruction and back | `storage_foreign_release` rejects a direct array argument but calls native `jv_free` for other kinds. Native `jvp_object_free` and `jvp_invalid_free` recursively call `jv_free`; an array nested inside such an object can therefore reach native array destruction. The direct-kind guard does not close this crossing. |
| Native constructors and the interpreter | `jv_parse`, `jq_compile`, `jq_start` and `jq_next` retain native construction and internal value operations. The four entry hooks route only the selected path/value entries. They do not intercept every internal append, concat, constructor or destructor. |
| Retained path services | Object get/set, string slicing, array indexes, error construction, numeric conversion and slice normalization still execute native operations or explicit C adapters around them. They can read or retain array-containing values and allocate. Their declared nonlocal outcomes cover the selected callback experiments, not their full semantics. |
| Observations and cleanup | JSON/error serialization still uses native jq readers, constructors and frees; diagnostic allocations are excluded from lifetime totals. Top-level retained-reference counts, alias matrices and observed residual allocations are compared. This does not enumerate all internal references or inspect every reachable byte. |

In the pinned `jv.c`, `jvp_array_ptr/read/write/slice/free`, array equality and
containment directly depend on the backing layout. Native public array operations
and foreign destruction can reach them. Thus the seven-unit replacement group is
coherent for the current shared native layout, but its declaration alone cannot
authorize a private backing-layout change. Such a change must supply executable
transport at the relevant remaining crossings or select their implementations
together. A native facade would itself need explicit contents, alias and lifetime
synchronization; reconstructing equal JSON values would lose that information.

## Public workflow without a pilot rebuild

Use an existing jq comparison package containing its pinned DLL, import library,
header and tools. For example, the prior path experiment retains one at
`build/behavior-faithful-workflow-2026-09-16/resource-packages-v1/value-get`.
Run in the project's Nix development environment so its Python modules and
cross-compiler linker dependencies are available. A compiler executable alone is
not its complete environment; preserve the target's Nix linker flags.

```sh
PYTHONPATH=".:src:$PYTHONPATH" python tests/fixtures/jq-array-storage/prepare.py \
  "$jq_retained_package" build/jq-array-packages
spaghetti-headless-wayland env \
  -u LD_LIBRARY_PATH -u LD_PRELOAD -u GCC_EXEC_PREFIX -u COMPILER_PATH \
  PYTHONPATH=".:src:$PYTHONPATH" \
  python tests/fixtures/jq-array-storage/walkthrough.py \
  build/jq-array-packages build/jq-array-workflow
```

The walkthrough uses public start/check, dependency selection, exact reuse and
retained-case replay. Keep its checks in one headless Wayland desktop. The selected
Nix toolchains have their own dependencies; the example removes ambient compiler
loader/search overrides so the compilation cache can establish its tool closure.
When those overrides are required, preserve them and expect conservative recompilation.

The connected entry can also be checked directly:

```sh
spaghetti-headless-wayland spaghetti-extractor component check jq storage-slice \
  --comparison-package build/jq-array-packages/storage-slice \
  --output build/jq-array-check
```

Formal checking is optional. Add `--local-contracts` to the direct check or either
helper when its checker tools are available. The normal walkthrough/assembly path
does not require CBMC to run executable comparisons.

To connect the existing path/value callers and actual interpreter consumers:

```sh
PYTHONPATH=".:src:$PYTHONPATH" python tests/fixtures/jq-path-network/prepare.py \
  "$jq_retained_package" build/jq-array-path-packages --resource-checks \
  --array-storage-packages build/jq-array-packages
spaghetti-headless-wayland env \
  -u LD_LIBRARY_PATH -u LD_PRELOAD -u GCC_EXEC_PREFIX -u COMPILER_PATH \
  PYTHONPATH=".:src:$PYTHONPATH" \
  python tests/fixtures/jq-array-storage/walkthrough.py \
  build/jq-array-packages build/jq-array-path-workflow \
  --path-package build/jq-array-path-packages/path-set-network
```

Assemble that repaired selection and execute it under an explicit experimental
policy, using the same prepared packages and walkthrough:

```sh
spaghetti-headless-wayland env \
  -u LD_LIBRARY_PATH -u LD_PRELOAD -u GCC_EXEC_PREFIX -u COMPILER_PATH \
  PYTHONPATH=".:src:$PYTHONPATH" \
  python tests/fixtures/jq-array-storage/assemble.py \
  build/jq-array-packages build/jq-array-path-packages \
  build/jq-array-path-workflow build/jq-array-assembly
```

This helper checks the remaining selected units, then invokes public
`candidate build --experimental-comparison` and
`candidate test --experimental-package`. Its policy binds the selected assumptions,
representations, services and resource instrumentation, including retained native
dependencies and unavailable formal checking. The recorded commands and terminal
manifest make that configuration reviewable; it supplies no strong qualification.

The path algorithms use declared service interfaces. A small C bridge
connects those descriptor services to the typed holders; the same objects cross
both boundaries. The declared graph selects the array family transitively and
preserves its separate representation group. The native interpreter still uses
the existing explicit entry-redirection fixture; this is experimental integration,
not strong native ingress or complete removal of the original bodies.

The current storage and selected-array path drivers also observe the pinned DLL's
real `malloc`, `calloc`, `realloc`, `free` and `_strdup` imports. The reusable
`pe32-import-hook.h` fixture binds each resolved import to its actual provider,
retains the original callable, and rejects missing, ambiguous or already changed
slots. It restores the imports afterward. The native allocation algorithms are
unchanged. This machinery is explicitly for single-threaded PE32 experiments.

The observer follows actual allocation addresses and reuse through final cleanup.
It compares remaining live blocks/bytes and detects repeated release of recorded
allocations. Total allocation/release activity and frees of pre-existing unregistered
allocations are diagnostics, not equality requirements: a replacement need not
use the same allocation strategy. Diagnostic JSON serialization is excluded from
the allocation counts while its allocation generations remain tracked. This does
not observe all loads/stores, prove heap correspondence, or require a target to be
free of its original memory defects. Native consumer residuals remain visible.
Standalone checks begin observing before input construction. Interpreter checks
begin after `jq_compile`; allocations already held by compiled constants are
outside that live-allocation count. Their later frees are diagnostic. A matching
zero count is therefore a scoped observation, not complete interpreter cleanup.

The optional formal result is unavailable for this interface. The normal comparison
still runs. Generated wrappers check selected service identities, nesting and
returns; their coverage explicitly leaves opaque-object contents, aliases and
lifetime to the adapters. Empty-service leaves need no fictitious service catalog.

The cases cover shared/unique mutation, growth with initialized holes, negative
and excessive indices, shared/empty slices, nested shared arrays, invalid reads,
and slice-offset overflow using a real allocation exceeding 65,536 elements.
Observations include values, the alias matrix and reference counts before cleanup,
followed by observed allocation lifetime after cleanup. Eight retained seeds each
drive 48 operations over multiple owned/shared array views: mutation, copy, slice,
replacement, read, nested-array creation and length consumption. Every seed and
generated operation is retained for replay. A separate slice case requires release
of allocated backing elements outside the final visible view.
All selected C sources must pass the existing dialect checker. The wrong-copy-on-write
edit changes the uniqueness test from `== 1` to `>= 1`; retained aliases then expose
the changed contents. The compatible edit rewrites an equivalent length comparison.
Add `--lifetime-negatives` to the walkthrough to omit array disposal deliberately,
replay a lifetime-only discrepancy after repair, and test the erroneous release
loop that uses the visible slice length instead of the initialized backing length.
It selects edited setter and release packages together, then reuses repaired local
and integration evidence. `--reuse-workflow DIR` offers earlier retained results
to public checks; differences in execution context still invalidate them.
The assembly helper likewise accepts `--reuse-assembly DIR` for retained local
checks. Both options use public evidence validation and conservative invalidation.

## Private descriptor representation change

The array algorithms use the small `jq_value_load` / `jq_value_store` C boundary.
`value-layout.h` keeps the original packed descriptor; `unpacked-value-layout.h`
places the payload first and uses separate ordinary fields for kind, flags,
padding and the slice offset. The private holder therefore has a different size
and layout. `native-storage.h` separately defines the array backing layout still
read by native jq. Native inputs/outputs and stored array elements cross explicit
conversions; live pointers are preserved without rebuilding values or their heap.
Allocation size uses the native element size even with the larger private holder.

Select the alternate header and an explicit revision through the existing recipe:

```sh
PYTHONPATH=".:src:$PYTHONPATH" python tests/fixtures/jq-array-storage/prepare.py \
  "$jq_retained_package" build/jq-unpacked-arrays \
  --descriptor-layout tests/fixtures/jq-array-storage/unpacked-value-layout.h \
  --descriptor-revision unpacked-descriptors-native-arrays-v1
```

The preparer binds the source and adapter copies of both layout headers in the
seven-member replacement group. Path and controlled-caller bridges take their
descriptor headers from the selected storage package. Routine metadata and
contract identities are generated; an operator changes C and declares the revision.
Same-signature mixed revisions, or independently changed shared header bytes,
are rejected before compilation. A coherent group still needs behavioral checks:
its matching declarations cannot establish correct conversion semantics.

Run the complete migration example inside one headless Wayland desktop:

```sh
spaghetti-headless-wayland env \
  -u LD_LIBRARY_PATH -u LD_PRELOAD -u GCC_EXEC_PREFIX -u COMPILER_PATH \
  PYTHONPATH=".:src:$PYTHONPATH" \
  python tests/fixtures/jq-array-storage/representation.py \
  "$jq_retained_package" build/jq-representation-workflow
```

The script records public commands for native and changed layouts, mixed-selection
rejection, a coherent but wrong slice-offset conversion, retained replay after
repair, a compatible setter edit and experimental assembly. The independent native
get-service comparison reuses across the layout change; the affected path network
reruns. That reused result is finite service-conformance evidence, not a theorem
about the authored caller. The existing getter reuse after a setter-only edit is
also exercised in the new representation. No new solver rule or checker is used.

`test_jq_descriptor_transport` separately compiles both headers and checks every
tag/padding byte, representative boundary offsets and signed lengths, payload bits
including NaNs and signed zero, and a live shared reference. These are transport
tests; they do not establish a general representation theorem. Native foreign
destructors, constructors and unselected readers still require the packed backing
array layout. This example changes private descriptors, not that retained heap ABI.

## Current evidence and limits

`build/jq-array-storage-2026-09-21/boundary-inputs-v2.json` binds the symbol inventory
and source archive, including the later length entry. The original inventory is
retained. `packages-v4/preparation.json` records preparation inputs.
`network-check-v1/` passes all ten comparisons with all six C profiles accepted;
formal checking is separately unavailable and performs no model/compiler/solver
work. Compilation takes 0.696s, linking 0.314s, test execution 1.280s and Wine
startup 23.417s. Those are development measurements, not a controlled benchmark.
`workflow-v1/audit.json` retains the complete first six-unit edit/reuse walkthrough.
The seven-unit family in `packages-v5/` adds length for the real path callers;
`packages-v6/` also observes length directly in each unit's standalone corpus.
`path-network-check-v1/` passes 37 comparisons, including ten native interpreter
programs, with all eleven profiles and all observed resource/service checks
satisfied. `path-workflow-v1/audit.json` retains the corresponding connected
edit/reuse/bug/replay/repair walkthrough. The compatible setter edit compiles one
translation unit and reuses 28. The broken uniqueness condition produces eight
value mismatches (including `program-shared`) and one invalid observation. Its
overall result is incomplete, not a clean mismatch-only result. The retained
`nested` case replays the discrepancy after the draft has been repaired. Repair
and the unaffected getter reuse evidence without any compiler/link/execution/model/
solver work. All formal results remain unavailable.

`assembly-v1/audit.json` records the successful experimental build and test. All
eleven selected component checks bind to this configuration, including the
equivalent edited setter retained in the walkthrough draft. The repository setter
is the original equivalent source. The assembled configuration passes all 37
cases and their observed resource/service checks, and current readers validate
its exact retained evidence. It retains the pinned native DLL and test entry
redirection. Build takes 9.989s without recompilation or relinking; suite execution
takes 180.314s, including 160.798s evidence validation and 10.861s candidate execution.
See [the phase measurements](../../../docs/performance-and-invalidation.md).
`checkpoint-audit.json` binds the fixture/service implementation at that checkpoint and
revalidates the retained comparisons, manifest, all 37 case outputs and resource
observations. Four targeted Nix shards pass 32 tests. The final six repository/SDK
gates pass in `validation-v3/` after refreshing the registry for the new assembly
script; no proof or pilot rebuild is part of this checkpoint. That audit is
historical after the cleanup and contract changes below.

The seven authored operations contain 160 lines of C. The shared layout, runtime,
native/path adapters and standalone driver add 295 lines; Python declarations,
preparation, walkthrough and assembly add 245. Counts include comments and blank
lines, exclude the existing path fixture and generated files, and describe this
checkpoint rather than an ergonomics score. First-time setup still requires that
authoring work. The edit/replay loop uses public commands, but eliminating routine
Python package setup for new boundaries remains an operator-workflow gap. The
generic production changes support opaque service objects and service-free leaves;
no per-unit solver machinery was required.

The follow-up at `lifetime-check-v2/` passes all nineteen retained/generated
sequences with zero observed live allocations after cleanup. Its eight generated
cases execute all seven operation kinds. `lifetime-path-check-v1/` passes all 37
real-consumer cases with matching post-cleanup allocation observations. Some native
consumer allocations remain live on both sides; their origins have not yet been
classified, so this does not claim a leak-free native consumer.

`lifetime-path-workflow-v3/` completes the public workflow and the two intended
lifetime negatives. Missing disposal exposes 35 discrepancies for which all
ordinary value observations still match. The incorrect backing-length loop leaves
one observed allocation live in `sequence-10`, versus zero for the native oracle.
The previous v2 walkthrough assertion failed because it chose evidence from an
earlier engine and execution environment for the unchanged getter; the actual
checks conservatively reran. The corrected helper prefers current-run evidence.

The subsequent local checks in `lifetime-assembly-v1/` expose a real original
lifetime defect: `jv_set` loses the incoming item's reference on its NaN-index
branch, while the earlier authored setter released it. The `nan-index` case's
ordinary observations match, but the native side retains an additional 34-byte
literal-number allocation. Allocation origin/refcount probes and the pinned
source identify that lost reference. The assembly correctly stops at the mismatch.

The corrected setter declares an explicit `abandon` service and implements it with
an ordinary C adapter that consumes the logical token without freeing the native
reference. This is a value-set contract refinement, not permission to ignore leaks
or relax resource accounting. Dependent packages are regenerated through the
existing service authoring interfaces. No solver rule or new heap model is needed.
`lifetime-value-set-corrected-v1/` passes 29 local comparisons, including scalar,
nested-array and aliased-item NaN cases with matching allocations left alive.
`lifetime-path-corrected-v1/` passes 38 connected cases, including eleven interpreter
programs. The NaN interpreter case executes the authored path/set boundary, but its
compiled constants are outside the allocation observation window described above.

`lifetime-path-workflow-v4/audit.json` completes all seventeen public commands for
the revised boundary. It replays both copy-on-write and lifetime discrepancies,
repairs them, and preserves zero-work reuse for the unchanged getter and repaired
local/network checks. The compatible integrated edit compiles one translation unit
and reuses 29. Missing disposal now produces 36 lifetime-only discrepancies in the
expanded corpus. `lifetime-assembly-v2/audit.json` records successful public
experimental build and execution with all eleven selected local checks and all
38 consumer cases bound to the revised configuration. Observed resource/service
and cleanup-allocation checks pass. Formal checking remains unavailable.
Build reuses the compared binary in 11.138s; the suite takes 200.244s, including
179.550s evidence validation and 11.496s candidate execution. Six current
repository/SDK gates pass in 26.750s (`lifetime-validation-v3/`). The earlier
integrated native/composition shards pass eighteen tests with no skips for the
production code at that checkpoint. These finite results are
separate from the older checkpoint and retain the original runtime dependencies.
`audit-lifetime-checkpoint.py` revalidates them without executing Wine and writes
`lifetime-checkpoint-audit.json`, including the selected configuration, exact
observations, lifetime negatives, correction/reuse evidence and current code hashes.

`nomem-probe-v1/` observes the pinned native allocator itself: after registration,
one injected 144-byte array-allocation failure invokes the callback once with its
context preserved and escapes through `longjmp`. This is a diagnostic native
probe, not a public original/replacement failure comparison. It established the
behavior needed by the subsequent executable nonlocal protocol.

### Guarded allocation failure through the public workflow

The current definitions mark `allocate`, `create`, `set`, `slice` and `error` with
the `nomem` nonlocal outcome. Existing generated service headers and the shared
handler runtime compose those permissions. The driver registers the real native
handler, injects a null result at the next observed `malloc`, and receives an actual
callback and `longjmp`. It checks the context and observes retained arrays,
reference counts, unchanged output and post-cleanup allocations. Only references
still owned by the caller are cleaned up; the observer does not repair lost native
references. State inspected after the jump has persistent storage, avoiding C's
indeterminate modified automatic locals.

`nonlocal-packages-v2/` includes relevant failure cases in each local unit:
creation has one, mutation four, and the connected slice consumer all five.
Units without allocating selected operations keep their nineteen ordinary cases.
The service reader rejects a purported nonlocal interruption with no recorded
interrupted call, so native-only failure paths are not counted as evidence for
an unrelated selected unit.

`nonlocal-array-check-v4/` passes all 24 connected cases. Each failure invokes one
callback with the correct context. The requested allocation sizes are 144 bytes
for creation, 80 for shared mutation, 320 for growth, 272 for empty slicing and 51
for error construction. Shared/growth failures retain the lost input references
on both sides; the observer reports 184 live bytes, versus eight in the other
failure cases. These observations are not a process-wide leak-freedom claim.

Add `--nonlocal-negatives --lifetime-negatives` to the storage walkthrough to run
the complete current negative/replay/repair loop. Nonlocal negatives currently
use the storage consumer, not `--path-package`. `nonlocal-workflow-v1/` passes
24 public commands and twenty comparisons. Prematurely writing null to the output
changes a failure's retained sentinel from 12345 to null, while normal completion
still produces the right array. The full mutant corpus in
`nonlocal-normal-negative-v1/` confirms nineteen normal matches and exactly that
failure mismatch. Local and connected checks expose the discrepancy;
retained replay remains failing after repair. The repaired creator and network
reuse evidence with zero compiler/link/execution/model/solver work. This walkthrough
runs with formal checking not requested. `nonlocal-path-check-v1/` additionally
passes all 38 ordinary path/interpreter cases using the updated engine and storage
contracts. The higher-consumer failure work was still open at that checkpoint;
the following section records its subsequent implementation.

The earlier lifetime audit binds the earlier engine/contract implementation. It
does not establish current nonlocal support. The current integrated check passes
67 tests with no skips in seven Nix shards plus six repository/SDK gates. The final
additional caller-instance negative and six gates pass in `nonlocal-validation-v2/`,
for 68 covered tests. `audit-nonlocal-checkpoint.py` revalidates current comparisons,
negative/replay/repair evidence, engine/source bindings and integrated reports and
writes `nonlocal-checkpoint-audit.json`. That earlier checkpoint did not yet include
an expanded experimental assembly for nonlocal cases.

### Allocation failure in path operations and a real interpreter

`path-failure-packages-v3/` extends the path corpus with allocation failure. Normal
`nomem` cases warm native numeric conversion before the allocation-observation
window; `nomem-cold` also exercises its first allocation. The selected cases use
the actual native `jv_nomem_handler`, callback context and `longjmp`.
`program-nomem-path` compiles and runs `setpath([0,1]; .[1])` in the real interpreter.
Its test entry hook retains caller aliases on both sides and arms failure only
when the interpreter reaches `jv_setpath`. On the original side it restores that
pinned entry before calling the original body. It also runs actual interpreter
teardown before the final observations. This does not establish general teardown
safety after arbitrary failures or observe allocations made before compilation.

| Connected case | Failed allocation | Observed result |
|---|---:|---|
| `nomem-path-detach` | 64 bytes | Shared-array detachment jumps to the caller; retained contents/references and residual allocations match |
| `nomem-empty-rest` | 272 bytes | Empty path-tail construction jumps with the original reference effects |
| `nomem-path-number` | 36 bytes | Cold numeric conversion jumps through the selected value getter and path caller |
| `program-nomem-path` | 64 bytes | The native interpreter reaches the selected subsystem; callback context, teardown effects and retained aliases match |

The experiments exposed two mistakes that ordinary successful calls missed.
`set.c` released its numeric index before array allocation/mutation; the original
retains it until mutation returns. Its corrected release order preserves the lost
reference on failure. `getpath.c` previously iterated directly over the input path,
omitting the original's empty-tail allocation. It now iterates over successive
consumed path views, preserving that allocation and failure behavior while keeping
the authored implementation iterative.

Named `nomem` allowances apply only at the matching nonlocal resource-frame exit:
four untransferred tokens for the selected path-set fault contexts, two for the
other path/value operations, and zero retained tokens. Ordinary returns still
require zero untransferred/retained tokens. These are bounded premises for the
selected cases. They do not prove arbitrary recursive failures correct, and the
native reference/allocation observations remain independent comparisons. The
setter negative still has satisfied resource premises while the comparison detects
its prematurely released native reference.

`path-local-repair-v1/` records ten public start/check/replay commands. The wrong
setter passes 29 ordinary cases and differs in two failure cases. The old path
reader passes 26 ordinary cases but never delivers the required callback in the
remaining case; that run is incomplete with an explicit runtime diagnostic.
Both failures replay from their retained `inputs` after the drafts are repaired.
Both repaired local checks reuse with zero compiler/link/execution/model/solver work.
For example, after preparing packages with the commands above:

```sh
spaghetti-extractor component start jq value-set \
  --comparison-package build/jq-array-path-packages/value-set \
  --output build/jq-value-set-draft
spaghetti-headless-wayland spaghetti-extractor component check jq value-set \
  --comparison-package build/jq-value-set-draft --case nomem-array-create \
  --output build/jq-value-set-failure-check
```

`path-failure-workflow-v1/` passes seventeen commands and fourteen comparisons,
including the copy-on-write and lifetime negatives, replay and zero-work repair.
`path-failure-assembly-v1/` passes public experimental build/test with all eleven
selected local checks and all 42 consumer cases. Formal checking is not requested.
The current integrated validation passes 71 tests in seven Nix shards without
skips plus six repository/SDK gates. All evidence is retained under
`build/jq-array-storage-2026-09-21/`; earlier audits bind historical versions.
`audit-path-failure-checkpoint.py` revalidates the executable, all case outputs and
resource observations, 29 retained comparisons, repair/reuse and integrated reports.
Its `path-failure-checkpoint-audit.json` records the current implementation bindings
and keeps `authorizing` and `whole_program_complete` false.

P1–P4 remain open for controlled callee-body absence, representation-change
transport/reuse, repeatable first-time setup and DX-Ball transferability. The
native crossing inventory above documents the current coupling; it does not close
those boundaries for a changed heap representation.

The guarded native allocator (`jv_mem_alloc`, RVA `0x2d680`) and disposal
(`jv_mem_free`, RVA `0x2d745`) remain runtime services. Non-array destruction and
error construction remain native, and a native foreign destructor can still release
a nested array natively. That gap must be closed or precisely bounded before claiming
complete array-lifetime replacement in a real consumer. Input objects must be live
and well formed, and allocation spans must not wrap PE32 `size_t`; unsupported
overflowing allocations produce an explicit fixture failure. There is no arbitrary
heap-state, original memory-defect, callback, concurrency or portability theorem.
