# jq continuation: compiler IR and execution lifecycle

**Follow-up:** the [component assembly update](component-assembly-updates.md)
resolves the assembly-refinement stopping point below. The installed
`candidate apply` command now exercises the retained 27-to-28-entry transition,
failed-link recovery and both architectures without rebuilding the pilot.
The account below records the original continuation and its limitations.

This continuation moves instruction-graph construction/binding and execution
lifecycle into ordinary C components using the existing authoring, comparison
and source-assembly workflow. The bytecode compiler and `jq_next` remain separate
neighbors. Their shared instruction/state layouts are checked during preparation,
and routine implementation edits operate on the new modules' own workspaces.

Native comparisons match **38 IR and 39 lifecycle scenarios**. The combined
standalone programs match **148 CLI and 32 live-value cases** on x86-64 and
AArch64 under QEMU. All 33 prior component records and their 387 host/384 ARM
files retain their bytes. Both new modules run through normal program entry.
Further expansion stops at the assembly boundary-refinement gap described below;
the successful recovery of this new module does not remove that workflow gap.

The [IR module](../tests/fixtures/jq-compiler-ir/README.md) supplies 58 existing
operations, with loops, mutable linked graphs, nested scopes, binding/branch
aliases, value ownership and source-location retention. Private helpers stay
inside its implementation. The
[lifecycle module](../tests/fixtures/jq-execution-lifecycle/README.md) supplies 27
existing public operations plus the internal path-tracking entry used by
`getpath`. It owns state creation, compilation/reset, execution setup, attributes,
callback registration, errors/halts and destruction. Existing production APIs
are preserved; no synthetic split/step API or new heap model is introduced.

This remains **source-assisted partial lifting**. The authored code derives from
the available jq source and is compared with the pinned PE32 binary. It does not
establish recovery from arbitrary machine code without source, universal
equivalence, or a complete jq lift. Practical behavioral evidence and formal
qualification remain separate. No checker/compiler/proof machinery changed.

## What actual consumers exposed

The IR comparison initially reported repeated releases. Its new C duplicated
strings through the executable's CRT, while deallocation crossed the observed
DLL allocator. Routing duplication and release through the existing unguarded
allocation services made acquisition and release visible to the same observer;
the target's failure convention was retained. The observer was not weakened.

The next comparison exposed a real native calling convention detail. An original
lowering routine kept ECX live across `gen_noop`, a tiny leaf that leaves it alone.
A replacement obeying only the ordinary C calling convention clobbered ECX and
crashed that caller. Native entry adapters now preserve general registers other
than ABI return values using GCC's
[`no_caller_saved_registers`](https://gcc.gnu.org/onlinedocs/gcc/x86-Attributes.html)
and general-register-only code generation. This is ordinary native glue; exported
portable C uses its normal platform ABI. The scope explicitly excludes general
EFLAGS/SIMD/x87 preservation. A failing native exception now produces diagnostic
registers and a failure exit rather than waiting in an interactive debugger.

The lifecycle's first source link caught an omitted cross-file entry:
`builtin.c` calls `_jq_path_append` to update path tracking in the live interpreter
state. That existing entry was added to the component boundary, with a real
`path(getpath(...))`/update consumer. Public header declarations alone were not a
complete inventory of inter-component calls. A clean link and actual consumers
remain necessary after a local comparison passes. The corrected native boundary
matches all 39 scenarios, including that getpath consumer.

Integrating that refinement exposed a tooling gap. `candidate export` supports
the explicit `--accept-boundary-change` update, but jq's `refresh.py` rejects any
change to an already integrated component's native entry list. Its message asks
for explicit assembly review, yet it provides no argument for accepting the
reviewed entry-set change. `--keep-reviewed` only resolves file merges after
that check; it cannot perform this transition. Replacing the entire project
would also need to carry its retained binding inputs and local edits forward.

For this newly introduced component, the prior validated IR-only checkpoint
makes recovery possible: retain the failed integration, restore the exact source
and assembly transaction backups, then add the corrected lifecycle boundary as
a fresh component. This reuses neighboring component packages and build objects.
It is manual recovery, not a supported incremental boundary-refinement command.
Repeatedly needing such recovery would undermine the intended operator workflow.

The backend definition scanner also requires the return type and function name
on one line. Five obsolete definitions were normalized before removal:
`make_env`, `_jq_path_append`, `args2obj`, `jq_halt` and `jq_halted`. Their meanings
did not change. This is a small operator rough edge, documented in the recipes;
it did not require a new artifact format or compiler rule. Removed helpers and
declared native entries remain distinct sets, checked separately by assembly.

## Evidence

The retained experiment is `build/jq-ir-lifting-2026-09-27/`:

- `source-provenance.json`, `lifecycle-provenance.json`, the checked-in boundaries
  and preparation recipes identify the reviewed inputs and shared layouts.
- `compiler-ir/checked/` retains the allocator-observation failure;
  `compiler-ir/repaired/` and `native-caller-ecx.txt` retain the crashing adapter
  attempt and its native caller. The failed sweep was interrupted after the
  fault was diagnosed; it is not passing evidence.
- `compiler-ir/abi-probe-forks/` checks the repaired native calling convention;
  `handoff/` and `compiler-ir/final/` retain the fresh handoff and complete
  38-scenario native comparison. All six compiler objects were reused there.
- `lifecycle/probe/` and `lifecycle/checked/` retain the first lifecycle consumer;
  `program-final-build/` and `arm-project-final-build/` retain its missing-entry
  link failure. Those failures are not overwritten by subsequent delivery.
- `lifecycle-boundary/` and `lifecycle/final/` retain the corrected 28-entry
  boundary and its 39 passing native scenarios. The refused integration is
  recorded in `program-lifecycle-final-refresh.log`; complete failed source
  projects are retained as `*-lifecycle-attempt/`.
- `program/` and `arm-project/` are the recovered, delivered 35-component source
  projects. `*-delivered-build/`, `*-delivered-run/`, `reassembly.json` and
  `result.json` identify their exact inputs, results and preserved neighbors.
  All selected original definitions are absent from the backend, and every
  declared native entry is defined exactly once in each delivered executable.

The compiler consumer uses two jq contexts and repeated starts, observing
bytecode words/constants/debug metadata, parent/global-table correspondence,
outputs, callbacks, input aliases and final allocation lifetime. The lifecycle
consumer additionally observes callback identities and owned attributes,
recompilation while results remain pending, recovery from a compilation error,
formatted errors and nulling/repeated teardown. Wine always runs inside isolated
headless Wayland desktops.

The IR-only source projects match 147 normal CLI cases and 32 live-value cases
on both x86-64 and AArch64 under QEMU. That integration rebuilt five objects on
each architecture; it did not rebuild a pilot or reconfigure the source backend.
Its native final comparison performed no compilation, model or solver work.
Manual boundary analysis, C authoring and discrepancy investigation are not
independently timed; retained tool receipts separate preparation, compilation,
linking and execution costs instead of presenting them as total operator effort.

The corrected lifecycle integration rebuilt five objects on each architecture,
taking 0.415 seconds on x86-64 and 4.471 seconds for AArch64. Summed child times
for host component compilation/linking were 0.152/0.095 seconds; for AArch64 they
were 3.069/1.161 seconds. Its changed boundary recompiled four native objects and
reused two. No model or solver was run. Three repository gates
(`repository-metadata`, `production-python-lint`, `format-registry`) and
`git diff --check` pass. No broad proof campaign was rerun for unchanged internals.
Trailing blank whitespace in adapters and the lifecycle C file was cleaned after
native comparison; the exact compared inputs remain retained, and the receipt
checks that this cleanup changed no non-whitespace text.

## Stopping point and remaining work

Further jq expansion stops at the assembly-refinement gap above, as requested.
The component C, callbacks and native calling convention were handled with the
existing facilities; changing a reviewed component boundary after integration
still lacks a practical public assembly transition. The next tooling change
should reconcile the old/new entry and replacement sets as one reviewed update,
preserve unrelated C and component evidence, and invalidate affected integration
results. It should reuse existing export, binding proposal and backup machinery.
It should not require synthetic extra components or hand-editing provenance.

A bounded implementation should:

- Present the added/removed native entries, their operation mappings and backend
  replacement ownership for the named changed component. A stable C signature
  does not make that boundary change automatically compatible.
- Accept an explicit reviewed component update, then use the existing binding
  proposal/merge/backup path. Reject duplicate providers, unknown operations,
  inconsistent replacement ownership and overwritten local edits. Ordinary C
  adapters remain responsible for any changed calling or lifecycle conventions.
- Coordinate source export and assembly so a rejected assembly cannot leave the
  live project with a new export and old bindings. Retain proposals for review
  and preserve unchanged package files and compiler objects.
- Mark affected program validation stale and run the real consumer. The retained
  27-to-28-entry lifecycle change is a sufficient regression case; no new solver
  model or qualification campaign is needed.

Full jq remains incomplete. Its broad next areas are builtins, primitive
number/string/object services, bytecode/location helpers, program entry and
platform/math/time/regex support. Those retained source dependencies are not
silently counted as independently lifted components. The earlier scoped file
and stream behavior, including the recorded default stdout CRLF difference,
remains a limitation of the delivered runtime profile.
