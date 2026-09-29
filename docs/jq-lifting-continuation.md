# jq lifting continuation: serializer, interpreter and frontend boundary

The subsequent [compiler-backed practical C milestone](compiler-backed-practical-c.md)
addresses the stopping point below and exercises generated frontend comparison and
progressive refactoring. This document retains the 2026-09-25 attempt's evidence.

The 2026-09-25 continuation delivered two further source-assisted C replacements
through the existing public workflow, then stopped at a significant practical
source-profile limitation. No toolkit, checker, assembly-recipe or Nix code was
changed. The preceding parser and other selected components remain intact.

## Working replacements

| Component | Boundary and implementation | Local native comparison |
|---|---|---|
| JSON serializer | Five operations for initialization, colour configuration, string rendering, stream output and truncation; 389 lines of component C. Colour state is explicit caller-owned storage. Six ordinary public jq entries use the shared assembly declaration. | 17 cases with colour-state transitions, output bytes, truncation guards, retained aliases and allocation lifetime. |
| Interpreter next result | Opcode dispatch, frames, fork/data stacks and backtracking; 946 lines of component C plus 99 lines of stack helpers. Existing lifecycle/compiler/builtin code shares the explicitly described live state. | 18 cases covering two contexts, restarts, closures, callbacks, errors, halt and early teardown. The original `jq_next` body at RVA `[0x1be4d, 0x1f5ee)` is redirected and trapped throughout source-side execution. |

The resulting conventional source project passes **78 normal CLI cases and 32
live-value scenarios on both x86-64 and AArch64 under QEMU**, compared with the
pinned original PE32 jq. Normal execution reaches both replacements, including
colour/ASCII/pretty output, closures, recursion, generators, exception handling,
destructuring, callbacks and halt behavior. All Wine execution uses headless
Wayland. The original DLL identity remains
`50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d`.

Public partial exports preserve all 23 pre-existing component records and source
files in each retained project. Adding each component took about 0.415 seconds
of incremental host build time. Only the new component/adapter objects, its
affected backend translation unit and the entry-observation table rebuilt. The
combined AArch64 incremental build took 8.33 seconds; no full pilot regeneration
was needed.

Local serializer comparison costs were 0.59 seconds compiling, 0.064 linking and
2.33 executing, plus 5.22 seconds of Wine startup wall time. The corresponding VM
costs were 0.56, 0.064 and 5.92 seconds, plus 5.15 seconds of startup. Model and
solver work were zero. These are machine phase timings, not total preparation
effort: manually establishing boundaries, state layouts, native helper addresses,
adapters and observations remained the main authoring work.

Initial operator corrections were ordinary C/header warning cleanup and encoding
UTF-8 driver inputs as ASCII hex so Windows narrow-argument conversion did not
damage the cases. Changing that argument encoding required a fresh comparison
baseline. These corrections did not require tool changes.

## Stopping point

The next boundary was the jq language parser: borrowed source locations in,
an owned compiler instruction block and error count out, with lexer/IR-building
and diagnostic services retained as dependencies. Its first implementation keeps
the pinned Bison-generated syntax engine and semantic actions as a baseline for
progressive refactoring. It is not yet an idiomatic rewrite or a behavior-validated
component.

After marking two unused callback parameters explicitly unused, both host and
PE32 compilation pass for the wrapper, parser and generated conformance unit.
The public source check nevertheless returns `incomplete`:

- 100 `restricted_c_macro_definition` diagnostics.
- `restricted_c_conditional_compilation`.
- `restricted_c_unrestricted_allocation` for a `malloc` declaration inside an
  inactive fallback: this source already defines `YYMALLOC` as `jv_mem_alloc`.
- Storage inspection remains unresolved; compilation alone does not establish
  acceptable persistent storage or effects.

The practical comparison path requires a satisfied practical source profile.
Optional proof settings do not remove this gate. The documented advice to replace
macros with ordinary functions or select variants externally requires substantial
normalization of this 4,188-line generated parser before the operator can compare
and progressively refactor it. This is an ergonomic limitation of the current
restricted dialect and its raw-source checker, not a demonstrated behavior defect
or solver-performance problem.

The attempt stops here. Keeping this frontend as an explicit backend remains a
working partial configuration. Continuing its migration needs either substantial
manual rewriting or a supported compiler-aware practical source workflow that
binds configuration and header dependencies, retains source locations and checks
the active implementation. Formal proof eligibility should remain separately
reported. No such tooling change was made during this attempt.

## Evidence and scope

Retained work is under `build/jq-lifting-continued-2026-09-25/`:

- `serializer/authoring/`, `serializer/check-v3/`: C, boundary, adapters and matching
  native observations.
- `vm/authoring/`, `vm/check/`: C, shared-state assumptions, original-body
  interception and matching native observations.
- `program/`, `program-vm-build/`, `program-vm-run/`: updated host source project,
  incremental build and full selected program comparison.
- `arm-project/`, `arm-build/`, `arm-run/`: corresponding AArch64 source and runs.
- `frontend/authoring/`, `frontend/source-check-v2/`: reproducible rejected
  frontend boundary, successful compiler results and exact profile diagnostics.
- `bindings.json`, `prepare-*.py`, `author-*.py`, `result.json`: operator recipes,
  assembly choices, input/evidence hashes, costs and unchanged-neighbor audit.

This remains a source-assisted partial jq lift. The compiler, linker, many builtin
and value operations, allocation/TLS and other runtime code remain backend
dependencies. Finite comparisons do not establish arbitrary-state equivalence,
concurrency, all console/locale behavior or strong qualification. No native
frontend comparison or activation followed its source-profile rejection.
