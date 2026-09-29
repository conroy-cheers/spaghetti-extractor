# Controlled jq get service

This experiment checks the real native `jv_getpath` caller and the authored
iterative `getpath.c` against the same explicit finite get scenarios. Its current
recipe defines the caller boundary afresh from retained jq runtime/type inputs,
ordinary C and reusable service declarations. A prepared path-get interface or
source package is not required. It is finite conditional comparison, not a checked
summary. The [current goal](../../../docs/current-goal.md) distinguishes this
workflow from complete target qualification.

## First-time boundary setup

Use the project's Nix development environment with its cross-linker dependencies.
The retained input can be the original value-get package; none of its selected
bodies or contracts are inherited. `prepare.py` checks the pinned DLL and reuses
only its tools, link/runtime files, native header and canonical jq value types.
It declares `run(root, key) -> value`, selects the nine required services, requests
resource instrumentation, writes the short adapter include unit and generates
the existing comparison package. There is no per-component solver or checker code.

```sh
PYTHONPATH=src python tests/fixtures/jq-path-controlled/prepare.py \
  build/behavior-faithful-workflow-2026-09-16/resource-packages-v1/value-get \
  build/controlled-jq \
  --array-storage-packages build/jq-array-packages
spaghetti-headless-wayland env \
  -u LD_LIBRARY_PATH -u LD_PRELOAD -u GCC_EXEC_PREFIX -u COMPILER_PATH \
  PYTHONPATH=".:src:$PYTHONPATH" \
  python tests/fixtures/jq-path-controlled/walkthrough.py \
  build/controlled-jq build/jq-array-path-packages build/controlled-jq-workflow
```

The array and path packages are prepared using the
[connected storage recipe](../jq-array-storage/README.md#public-workflow-without-a-pilot-rebuild).
Omitting `--array-storage-packages` retains native storage services instead.
`preparation.json` records the manual input categories, generated products and
preparation time. The common API accepts ordinary files and a boundary object;
its [documented entry point](../../../docs/components.md#practical-originalsource-execution)
also supports other targets and richer full-interface declarations.

Manual work remains identifying the native ABI/operation, choosing observations,
reviewing the services, defining useful cases and writing semantic C adapters.
For this recipe the existing jq adapters and scenario evaluator are reused. Adding
the two convenience paths to the common package preparer was a one-time toolkit
change; it is not hidden as per-component operator work. This is an executable
recipe, not a first-time-user usability study or evidence of arbitrary-target setup.

## Add lifted services to an edited caller

An existing caller using native storage can now adopt the already authored array
components through `revise_comparison_package(..., dependencies=..., requirements=...)`.
Use `bind_dependencies` to name its `copy`, `release`, `length`, `array_get` and
`array_slice` services. The selection imports transitive storage components and
retains the caller's edited C, cases and operator notes. Shared selection conflicts
reject; other callers' requirements remain explicit.

This transition also needs the reviewed `array-path-bridge.h`, storage headers,
allocation observer, service bindings and lifecycle declarations already used by
this recipe's array mode. Supply those root roles/declarations in the same revision.
They implement the actual native-value/selected-C route; dependency declarations
alone do not. Original/runtime inputs stay pinned. No manual plan, digest or
composition-graph editing is required.

`build/component-supplier-addition-2026-09-24/` retains the installed handoff. It
starts a native-storage caller, keeps a local loop edit and notes, adopts the
reviewed seven-component storage selection in 0.382s, then passes the existing
`nested` case in 6.933s. An edit to storage length compiles one file and retains
22 objects; unchanged reuse takes 1.339s with zero work. Public source export also
passes. The get behavior remains an explicit transcript; this is a focused caller
handoff, not a fresh six-case suite, interpreter run or formal composition proof.
All Wine applications and servers run inside headless Wayland.

## Local checks and real integration

Run each package using `component check jq path-get --comparison-package DIR
--output NEW_DIR`, inside the repository's headless Wayland wrapper. The two
packages have different scopes:

- `service`: nine individual get scenarios are checked against the pinned native
  `jv_get`, including its actual recoverable invalid-value outcome. This rejects
  invented results. It does not exercise the authored caller.
- `caller`: six caller cases check ordered arguments, current logical state,
  returned values/errors, retained root/path contents, complete call coverage,
  and stopping after an invalid value. The original `jv_get` body is overwritten
  on **both sides**, and all interior bytes are checked for trap instructions
  before and after the caller runs. No authored `value-get` implementation is
  selected or linked. The caller's reference transport is instrumented. With array
  packages selected, creation/copy/release/length/get/set/slice execute their real
  authored C behind the caller's storage services; they remain dependencies of
  that check. Retained caller reference counts and residual allocations are also
  observed, with diagnostic serialization excluded from allocation counts.

The pinned DLL COFF symbol offsets are `.text+0x2e806` for `jv_get` and
`.text+0x2f2b4` for the following `jv_set`: 2734 bytes. The preparer requires
DLL SHA-256 `50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d`.
The patch writes a jump to the controlled service and traps throughout the
remaining body, including all internal branch destinations. This fixture is
single-threaded and not a native replacement activation mechanism.

The scenario list is the dependency behavior consumed by the local check.
Changing it invalidates that evidence. The walkthrough extracts an ordinary C
helper in the real `value-get` supplier, rechecks that supplier and reuses the
controlled caller. The actual path-get integration executes the changed supplier
and must rerun. A deliberately wrong negative-index edit still leaves the
conditional caller result reusable, while supplier and integration checks reject
it. Retained replay preserves the discrepancy after repair. This makes the local
evidence's limitation visible in normal operator actions. Source, contract and
runtime bindings remain exact; changing the pinned original DLL still invalidates
the caller, even though get's body is trapped during its local execution.

Limits: these are sampled logical transcripts, not a general contract for every
jq value or allocation failure. Responses are retained fixture values; native
heap identity and alias equivalence are not established. Resource instrumentation
covers source reference transport, not original/native leaf internals. No
recoverable failure is substituted for native allocator termination. Empty and
invalid paths make no get calls but still check the caller operation boundary.
The preparer reuses the shared service catalog and production bridge generator.
The logical scenario evaluator remains target-specific C: generation does not
invent native jq semantics or turn these transcripts into a checked summary.

## Retained authoring checkpoint, 2026-09-22

Evidence is under `build/jq-array-storage-2026-09-21/`:

- `controlled-authoring-packages-v2/`: fresh boundary preparation, 0.465s;
  no prepared caller interface/source package or pilot build.
- `controlled-authoring-workflow-v1/`: 15 public commands, 13 comparisons;
  six controlled caller cases, nine service scenarios and 27 real integration
  cases. Supplier and integration negatives fail at `$.result`, then replay after
  repair. Controlled caller reuse takes 1.321s with no compilation or execution.
- `controlled-authoring-validation-v1/`: seven integrated Nix shards, 74 passing
  tests without skips, and six repository/SDK gates.
- `controlled-authoring-checkpoint-audit.json`: current-reader and engine binding
  audit of those receipts. The retained earlier eleven-unit experimental manifest
  remains readable; its 42-case suite was not reexecuted for this checkpoint.

The first preparation attempt (`controlled-authoring-packages-v1/`) materialized
its packages but failed to write its preparation report because the recipe used
the wrong interface identity attribute. Version 2 corrects that reporting error;
the complete public walkthrough consumes version 2.
