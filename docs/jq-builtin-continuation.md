# jq continuation: builtin library

The [builtin module](../tests/fixtures/jq-builtins/README.md) moves jq's eleven
binary value operators and builtin registration into ordinary authored C through
the existing public workflow. Its approximately 2,000 lines contain the private
arithmetic, conversion, formatting, regex, path, input/debug/halt and calendar
handlers, a persistent C callback table, and the bytecoded/jq-coded definitions.
This is one existing production boundary, not a synthetic API for each handler.

**94 native component scenarios match. Both standalone source projects match
204 CLI and 32 live-value cases on x86-64 and AArch64/QEMU.** The projects now
select 36 components; all 35 prior component records and 426 host/423 ARM exported
files retain their exact bytes. No proof, compiler, artifact or assembly tooling
changed. All Wine execution used headless Wayland desktops.

The component remains source-assisted: it derives from available jq source and
is compared against the pinned PE32 binary. This does not establish recovery
from arbitrary machine code, universal equivalence or complete jq lifting.
Primitive value/storage services, decimal conversion, bytecode/location support,
program entry and platform libraries still contain retained backend code.

## Boundary and consumers

`builtins_bind` parses the builtin jq text, constructs instruction graphs,
registers the C function table, and binds referenced definitions into the caller's
graph. Graphs initially borrow descriptors; compiled bytecode copies descriptors
and retains callback addresses until the jq state is destroyed. The table/code
therefore have module lifetime. Values use the existing consuming `jv` API;
callers preserve aliases explicitly with `jv_copy`.

The native comparison invokes normal compilation and execution in two jq states,
with repeated starts. It observes bytecode/constants/debug structure, outputs and
errors, callback events, retained input values, and allocation lifetime. Entry
hooks replace the twelve public operations and trap intervening private builtin
handlers in the reviewed native implementation span. A syntax error rejected
before builtin binding has no component entry; successful compilation requires
the selected implementation to run. The immutable callback table is admitted by
the existing compiler-backed practical C path. Formal eligibility stays separate.

Portable integration uses `candidate apply` with the existing jq refresh recipe,
the grouped entry declaration, a build command and normal-program comparisons.
It retires the twelve public backend definitions. The unreferenced private
handlers/table disappear from the compiled `builtin.o` on both architectures;
the retained archive-symbol inventories confirm that member has no symbols.
All declared replacement entries occur exactly once in the final executable.

## What comparisons exposed

The initial C compilation required ordinary cleanup of unused callback arguments
and explicit platform defines. The native adapter then needed private runtime
bindings, including an ordinary import library derived from the retained
Oniguruma DLL exports. No native library or pilot rebuild was needed.

Real consumers caught an incomplete `_jq_path_append` prototype: it consumes four
arguments, including the already-computed path result. They also caught temporary
buffers allocated through observed jq services but released through an unobserved
executable CRT path. The adapter signature now matches the actual API; buffer
release uses the existing jq allocator pair. The observer was not weakened.

Inspecting the native binary found six unavailable math functions (`drem`,
`exp10`, `gamma`, `lgamma_r`, `scalb`, `significand`). Their original error responses
are preserved in the module's feature profile instead of depending on which
functions happen to exist in the host libc.

The first standalone run matched 199/201 CLI cases. Two calendar cases differed:
the host accepted negative or post-2038 epoch values that the pinned Windows CRT
rejects. The C implementation now retains that 32-bit conversion range, including
the original treatment of negative fractional seconds, and preserves supplied
UTC formatting fields. Three additional boundary cases exercise those rules.
The corrected component matches the native comparison and both architectures.
This is a runtime compatibility adjustment expressed in C, not a checker rule.

Time/locale/environment remain declared runtime dependencies. Clock tests observe
result type rather than equal wall-clock samples. Arbitrary locales, concurrent
environment changes, allocation failure, corrupt pointers and stack exhaustion
are outside this finite comparison. The earlier default-output CRLF difference
also remains outside the delivered `--binary` normal-entry profile.

## Evidence and costs

`build/jq-builtin-lifting-2026-09-27/` retains:

- `builtin/authoring/` and the successive comparison packages/results. The initial
  compiler, private-ABI and allocator discrepancies remain inspectable.
  `builtin/calendar-checked/` is the matching 94-case comparison with private
  native handlers trapped.
- `host-native-profile-build/` and `host-native-profile-run/`: the successful first
  link and two calendar mismatches. The failed staged transaction leaves the
  existing 35-component project unchanged.
- `program/`, `arm-project/`, `host-final-*` and `arm-final-*`: the delivered
  36-component projects, exact source snapshots, compiler/link costs and matching
  normal-entry comparisons. `result.json` binds neighbor retention and the empty
  legacy builtin object; the application transaction retains the prior projects.

Each final integration compiles five objects: two component objects, its entry
adapter, observation names and `builtin.o`. **167 host / 166 ARM objects retain
bytes and mtimes.** Builds take 0.77s / 9.98s; normal-program comparisons take
11.10s / 19.38s. The last native refinement compiles two files and reuses four.
The retained receipts separate preparation/compiler/link/execution costs. No
model or solver ran, and no pilot was rebuilt. These measurements exclude manual
boundary analysis, C authoring and discrepancy investigation.

The assembly-refinement fix is now exercised by a new substantial component.
No significant tooling blocker was found here; the jq lifting goal remains
active, with the remaining value runtime as the next substantial area.
