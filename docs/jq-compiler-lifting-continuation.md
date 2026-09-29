# jq continuation: bytecode compiler and allocator boundary

The allocator stopping point below is historical. The subsequent
[stateful component workflow](stateful-component-workflow.md) adds explicit state
ownership for practical execution and validates the allocator's shared handlers
and cleanup against the original. Its separate evidence supersedes that blocker.

The 2026-09-26 attempt adds a working bytecode compiler replacement through the
installed public workflow, then stops at the allocator's persistent-state
admission requirement. No tool internals, source assembly recipes or Nix
infrastructure were changed. This continues the
[frontend milestone](compiler-backed-practical-c.md), using its retained inputs
and incremental source projects instead of rebuilding the pilot.

## Delivered compiler replacement

The `bytecode-compiler` boundary consumes a bound, mutable instruction graph and
an argument-object reference, borrows its source location, and returns an owned
bytecode tree or NULL with a diagnostic error count. It retains the existing IR
and bytecode representations, including instruction aliases, closure bindings,
parent links and the shared symbol table. Parser, binder, IR construction and
destruction, values, allocator, opcode metadata and diagnostics remain explicit
runtime dependencies. The boundary guide records these premises; its opaque
types alone do not check them.

The source-assisted implementation extracts the pinned jq compiler core, then
separates instruction emission from recursive lowering into ordinary private C.
The final implementation has 348 lines of C and 61 lines of authored headers.
The emitter is a private helper, not a synthetic production API or another
component. A Windows macro guard was corrected, and the original GNU `MAX`
expression was replaced with an ordinary conditional expression.

**All 26 native comparison cases match.** They exercise two jq contexts and two
starts per context, closures, nested and recursive functions, filter arguments,
global arguments, backtracking, callbacks, compile/runtime errors, environment
capture and early teardown. Observations include emitted bytecode and constants,
debug metadata, parent/shared-table relationships, execution results, callbacks,
retained input values and allocation lifetime. Native comparison binds DLL SHA256
`50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d` and disables the
original `block_compile`, `compile` and `expand_call_arglist` bodies on the source
side. Eleven ordinary native helper bindings reuse the prior boundary's facilities.

The first comparison matched 25 cases. Its environment case exposed a fixture
difference: the two runtime directories produce different `PATH` values, which
the compiler captures into bytecode. Giving both sides the same explicit C
environment resolves that difference without masking a field or weakening the
comparator. Arbitrary process environments are outside this controlled case.

The refactor rebuilds two translation units and reuses four objects. Its measured
compiler time is 0.096 seconds, link time 0.064 seconds, case execution 8.545
seconds and Wine startup wall time 5.647 seconds; model and solver work are zero.
These are execution phases, not a measurement of manual operator effort. Boundary
analysis, layout review, native bindings and observation authoring still require
manual work; only recipe execution is separately timed in the retained inputs.

## Program integration

Partial source export preserves all **26 neighboring component records and their
source bytes** in each project. An ordinary C entry adapter supplies `block_compile`
through the existing grouped assembly declaration. The selected original body
and its now-unused lowering helpers are absent from the backend archive.

The resulting standalone projects pass **86 normal CLI cases and 32 live-value
scenarios on both x86-64 and AArch64 under QEMU**, compared with the original
PE32 program. Normal entry reaches the new compiler 82 times in each CLI suite.
Each incremental build changes six objects: the three new component objects,
its entry adapter, the affected backend translation unit and the diagnostic
entry table. Host build time is 0.665 seconds; AArch64 build time is 6.927 seconds.
All Wine executions use a headless Wayland desktop.

These remain partial, source-assisted jq lifts. The retained upstream source
supplies unlifted compiler/IR, linker, lexer, builtins, value/allocation and platform
services. This does not demonstrate complete recovery from machine-decompiled C.
Finite comparisons, recorded assumptions and formal qualification remain separate;
no universal equivalence, allocation-failure or thread-interleaving claim is made.

## Confirmed stopping point

The next attempted boundary is jq's allocation/failure-handler module. The pinned
original uses a process-wide `pthread_once` state and pthread key, with per-thread
handler/data, thread-exit destruction and main-thread `atexit` cleanup. Its symbols
include `mem_once`, `nomem_handler_key`, `tsd_init` and `tsd_fini`. Two jq objects on
one thread share this handler registry; they do not own separate copies of it.

After retaining the Winpthreads SDK headers, **both host and PE32 compilation
pass**. The public source check nevertheless returns `incomplete`, solely for:

```
practical_persistent_storage_requires_context
Writable persistent storage must use declared component context:
mem_once, nomem_handler_key
```

The PE32 diagnostic names the same symbols with leading underscores. This is the
existing practical admission rule, not a solver limitation or the optional formal
profile. `comparison_run.py` also stops before executing cases when the compiled
practical storage profile is incomplete. The allocator probe is only compilation
and admission evidence: no allocator comparison or integration was performed.

An explicit process/thread context supplied by ordinary C adapters remains a
possible workaround. It would require a lifecycle rewrite and review of shared
caller identity, once-initialization, callback routing, nonlocal failure returns
and cleanup. An automatic per-call context is incorrect. Delegating the whole
module to adapter code would leave its shared-state behavior outside the authored
component. This is sufficient friction to stop this attempt
under the instruction to stop at significant tooling limitations; it is not a
claim that the behavior is inexpressible in C or in an authored adapter.

The initial SDK import also exposed preparation friction: adding a directory
containing Windows `pthread.h` made it shadow the host system header. Prefixing
the retained SDK header names and their internal includes fixed that using the
existing authoring commands. Original SDK identities and this mechanical rewrite
are retained. No compiler infrastructure change was made.

The next systematic decision is how practical components declare and execute
shared module/process/thread state and its lifecycle. Preserve the original state
semantics and keep stronger proof eligibility separate. This attempt stops before
implementing such a facility or a custom lifecycle adapter.

## Retained handoff

`build/jq-compiler-lifting-2026-09-26/` contains:

- `compiler/workspace/`: editable C and boundary; `compiler/refactored/`: matching
  native evidence and exact inputs.
- `program/`, `arm-project/`: standalone source projects; `program-build/`,
  `arm-build/`, `program-run/`, `arm-run/`: builds and original comparisons.
- `allocator/authoring-namespaced/`: compiler-valid allocator candidate;
  `allocator/confirmed-storage-check/`: the isolated admission failure and
  compiler views.
- Operator preparation/refactoring/integration scripts, `bindings.json`, cases,
  `baseline.json` and `result.json`: reproduction, costs and preservation audit.

The retained `README.md` gives the installed commands for reopening the compiler
and reproducing the allocator diagnostic. The attempt changes only this report,
the current-goal summary and documentation indexes outside ignored build outputs.
All unrelated starting worktree bytes are preserved. Validation consists of the
native comparison, both actual program runs, both allocator compiler checks and
`git diff --check`; no extra proof campaign or pilot rebuild was introduced.
