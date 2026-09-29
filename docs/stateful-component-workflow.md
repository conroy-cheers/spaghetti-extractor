# Shared state in practical C components

Practical components can retain ordinary writable C module storage and runtime
thread-local state. Operators declare its ownership and lifecycle at the existing
boundary, compare real behavior, and export one provider through the existing
source assembly. The compiler still inventories every authored translation unit.
Formal source eligibility and strong qualification keep their existing rules.

This addresses the [jq allocator admission blocker](jq-compiler-lifting-continuation.md).
It does not transform globals into artificial per-call contexts, emulate pthread
objects, or move the allocator algorithm into adapter code.

## Author a state owner

Supply `--state-owners state-owners.json` when creating an interface-first workspace:

```sh
spaghetti-extractor component start jq allocator-runtime \
  --interface-intent interface.json --state-owners state-owners.json \
  --assumption-file BOUNDARY.md \
  --source-file source/allocator.c=allocator.c \
  --source-file source/component.c=component.c --output allocator-work

spaghetti-extractor component check jq allocator-runtime --source \
  --authoring-workspace allocator-work --compiler-view --output allocator-source-check
```

An example declaration is:

```json
[
  {
    "id": "jq.allocator-runtime",
    "scope": "module-instance",
    "sources": ["allocator.c"],
    "thread_state": "runtime-managed",
    "reset": "process-restart",
    "lifetime": "One registry per linked jq runtime. pthread_once creates its key. Callers on a thread share the latest callback/data; thread exit and atexit free their records."
  }
]
```

`scope` is `process` or `module-instance`. `thread_state` is `none` or
`runtime-managed`. Source names are local to the authored source directory;
do not prefix them with `source/` or a dependency namespace. Each declared C
translation unit has one owner. Storage introduced through its includes/macros
is covered too, and actual compiler-observed symbols remain in the result.
Private state can evolve without a separate symbol-name manifest; such C changes
still invalidate implementation evidence and require behavioral checks.

The declaration describes the intended boundary. It does not prove scope,
thread-safety, aliasing, cleanup or compatibility. `process-restart` is the only
supported workbench reset: each scenario gets a new program process. External
files, shared memory and other persistent services still need an explicit fixture
or runtime boundary. OS handles, mutexes and pthread keys are never copied or
zeroed as if they were portable snapshots. C and its selected runtime execute
initializers and destruction normally.

The public workspace retains `state-owners.json`, displays its assumptions in
`BOUNDARY.md`, and passes it through generated `prepare.py`. API callers may
supply `state_owners=[...]` to `prepare_comparison_package`. Storage without a
covering declaration or explicit context remains incomplete; the diagnostic
points to the declaration workflow. Missing/failed compiler storage inspection
remains incomplete. Declared components use practical profile v3; undeclared
components keep their existing v2 contract/profile representation.

## Share one provider and edit locally

Keep related entries sharing the same state in one component when appropriate.
Its private helpers need not become component APIs. Existing service definitions,
supplier selections and ordinary C bindings connect other components to that
provider. Declare requirements on the supplier through the existing composition
workflow when using a component network. Native replacement groups must disable
all old entry paths that would otherwise retain a second registry.

Comparison selection and source export reject multiple providers claiming the
same state-owner identity. The linker and reviewed entry/service bindings must
also route consumers correctly; uniqueness of a declaration cannot detect an
undeclared registry, mistaken alias, or bypass in arbitrary adapter C. Source
assembly already checks that selected native entries have one linked definition.

Ownership metadata travels through selected dependencies, retained-component
inputs, boundary refinement, source-library handoff and partial export. It is part
of contract identity, so changing a lifetime assumption or ownership scope is a
boundary change even when C signatures stay identical. A C-only import cannot
silently change it. Use the existing reviewed refinement/update workflow for such
changes. No new independent artifact or proof authority is introduced.

Ordinary implementation edits recompile affected translation units and rerun
relevant comparisons; unchanged neighbors remain reusable. Changes to owner
declarations invalidate dependent boundary evidence. An unchanged repeat can
reuse the exact result. Assumptions, finite comparisons and proved properties
remain distinct in workspace feedback and source exports.

## jq allocator exercise

The retained experiment is `build/stateful-component-workflow-2026-09-26/`.
`allocator/authoring/` contains the initial C and boundary; the installed toolkit
and public preparation/check receipts are retained beside it. The reusable
[fixture recipe](../tests/fixtures/jq-allocator/prepare.py) takes that authoring
workspace, an existing native environment and the Winpthreads import library. It
uses public comparison APIs and C adapters, without a pilot rebuild.

The provider contains all nine allocation/registration entries, its once/key
state, thread-local callback/data and cleanup. The allocation backend is a normal
C service used consistently by retained and lifted callers. Native comparison
binds the pinned original DLL and replaces all nine entries together, trapping
their original bodies and private allocator-state helpers on the source side.

Two concrete lifecycle scenarios match the original. They exercise allocation
and reallocation bytes, guarded and unguarded calls, two real jq contexts sharing
the latest handler, callback data and `longjmp`, a worker's separate handler,
worker destruction and main-thread cleanup at process exit. A parent reads the
child's observations after complete CRT/DLL teardown, so the last cleanup is
observed rather than assumed from a snapshot before `main` returns. Native helper
patching occurs before worker creation; these sequential thread scenarios do not
cover all concurrent interleavings, cancellation, DLL unload or OS failures.

The local refactor selects that pthread configuration and removes the inactive
fallback branches. A deliberately omitted thread destructor produces a retained
mismatch: the worker's record remains live after join. Repair restores both
matches; each edit compiles one object and reuses four. The refactor's first check
crosses an installed-toolkit change and recompiles all five objects, so that step
is not counted as local-edit reuse. The repair spends 0.032 seconds compiling,
0.064 linking and 0.457 executing cases; Wine startup costs another 5.572 seconds.
Model and solver work are zero. These are tool execution costs; manual boundary
analysis and C adapter preparation were not separately timed.

Repeating within one unchanged headless environment reuses the exact result with
zero compiler, link, execution, model or solver work. A fresh desktop changes the
execution-environment digest and conservatively reruns the comparison, while
reusing all five compiler objects. That is environment invalidation, not a
state-owner contract change.

Partial export adds the provider to both existing standalone projects and keeps
all 27 neighboring component records and their files unchanged. Assembly removes
the nine old entry definitions. Selecting the pthread branch in the backend is a
reviewed ordinary source edit: its original three conditional handler definitions
are ambiguous to the existing single-definition removal helper. No new parsing
or target-specific compiler rule is needed. The resulting backend archive also
contains no old allocator registry or private state helpers.

Both x86-64 and AArch64 under QEMU match **86 normal CLI cases and 32 live-value
scenarios** against the original PE32 program. Normal CLI execution reaches the
allocator provider 1,167,283 times on each architecture. Each incremental build
changes six objects, taking 0.415 seconds on the host and 3.821 seconds for
AArch64. All Wine applications run in a headless Wayland desktop. Program-entry
diagnostic counters cover these single-threaded CLI workloads; the separate
native lifecycle driver checks the sequential multi-thread scenario above.

Fifty focused tooling tests and eight Nix repository gates pass: metadata,
format registry, production Python lint, module closure, build infrastructure,
boundary workbench, retired architecture and native-kernel dependencies.

This is source-assisted lifting of the pinned pthread-backed configuration, not
general recovery of allocator semantics from a binary. The generic workflow also
has compiled counter/provider tests covering two caller contexts, dependency
selection, lifecycle-change rejection, local edit reuse, defect detection and
export. A new component can use the same declaration and ordinary C facilities
without allocator-specific checker or compiler rules.

The retained handoff includes `allocator/refactored-workspace/` for C edits,
`allocator/refactored/`, `allocator/defect/` and `allocator/repaired/` for exact
comparison inputs and observations, `program/` and `arm-project/` for standalone
source, `allocator/cached/` for exact result reuse, and their build/run receipts.
`result.json` records costs, scope and the
audit against the starting dirty tree. The projects still use upstream source
for unlifted runtime services; this milestone does not complete a jq lift.

Compiler-assisted global-to-context conversion remains deferred. It may be useful
for explicit multiple runtime instances later; it is not needed to preserve this
target's existing shared-state semantics.
