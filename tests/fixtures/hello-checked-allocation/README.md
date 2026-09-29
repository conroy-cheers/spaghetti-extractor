# Hello's checked allocation family as one component

Eight public allocation operations share the machine `check_nonnull` tail at
`[6220, 622d)`. Treating each symbol's text range as a complete operation would
omit its return and failure path. This fixture manually groups those operations
and the shared tail into one `checked-allocation` component. Its ordinary C keeps
the check as a private helper; no synthetic helper API is exposed to operators.

The [declaration recipe](declarations.py) uses the installed
`OperationDefinition` and `component_interface(operations=...)` authoring API.
Each entry lists its signature, nullable old block and two permitted services;
the helper generates the existing signature/projection bookkeeping. Migration
reduced this recipe from 62 to 39 lines while preserving the complete interface,
service contracts and generated C headers. Manual entry/shared-tail ownership and
executable adapters remain explicit. The shared-context form is documented in the
[authoring guide](../../../docs/components.md#reusable-c-service-authoring).

| Operation | Primary RVA | Lower service | Alternate machine entry |
|---|---:|---|---:|
| `allocate` | `622d` | `rpl_malloc` | `xcharalloc`, `6255` |
| `allocate_indexed` | `6241` | `imalloc` | |
| `resize` | `6257` | `rpl_realloc` | |
| `resize_indexed` | `6273` | `irealloc` | |
| `resize_array` | `628f` | `reallocarray` | `xnrealloc`, `62b6` |
| `resize_array_indexed` | `62b8` | `ireallocarray` | |
| `allocate_zeroed` | `6462` | `rpl_calloc` | |
| `allocate_zeroed_indexed` | `649c` | `icalloc` | |

The two alternate entries are two-byte jumps to primary entries. They represent
the same C operations. The native adapter validates their exact branches and
selected destinations, avoiding a five-byte detour that would overwrite the next
entry. It removes all eight wrapper bodies and the shared tail. Runtime checks
verify those removals and execution of every selected operation.

The boundary preserves nullable old allocations and all 32-bit size/count words,
including bit patterns passed to indexed variants. Lower services decide size
normalization and overflow behavior. A nonnull result is returned unchanged;
null calls the declared nonreturning failure service. The private adapter
preserves object aliases and unwraps returned proxies before its context expires.
Lower memory, lifetime and errno effects remain explicit adapter premises.

The failure callback is naturally `void(void)`. Interaction contracts now accept
empty value-type and port lists for such services while still binding effects,
outcomes and the exact schema. The existing service wrapper renderer generates
call traces, service-table wiring and scope helpers. `service_bridge` selects
manual entry mode with `native_symbol=None`; the fixture supplies ordinary
multi-operation entry C and calls the generated scope helpers. Existing handler
instrumentation checks actual `nomem` delivery. Returning
from the failure adapter rejects; no dummy value or new proof rule is introduced.

## Local preparation and editing

Within the project Python/compiler environment:

```sh
PYTHONPATH=.:src python tests/fixtures/hello-checked-allocation/prepare.py \
  /path/to/retained-hello/executable-transfer-plan.json \
  targets/gnu-hello/intent/whole-program-partition.json build/hello-checked
PYTHONPATH=.:src python -m spaghetti_extractor component start \
  gnu-hello checked-allocation \
  --comparison-package build/hello-checked/checked-allocation \
  --output build/hello-checked-draft
PYTHONPATH=.:src python -m spaghetti_extractor component check \
  gnu-hello checked-allocation --comparison-package build/hello-checked-draft \
  --output build/hello-checked-local
```

Preparation verifies the pinned original/plan identity and reviewed partition,
retains all 27 owned transfers including the shared tail, and excludes all nine
lower/failure supplier bodies. The existing exact-C renderer combines those
entries in one original-side function. Retained declarations, adapter source,
generated service scaffolding and oracle inputs are bound by the comparison.

The authoring follow-up at `build/component-operation-groups-2026-09-24/` uses
retained original inputs through the installed public start/status/check/export
workflow. Nine focused comparisons cover all eight public entries and one
nonlocal allocation failure. A compatible private-helper edit recompiles one C
file and passes in 0.569s; original recovery, native pilots and solver work are not
repeated. This is a focused authoring regression, with the broader existing native
and program observations retained separately below.

`build/component-manual-entry-bindings-2026-09-24/` follows this with generated
service wiring around the manual entries. The real recipe runs from the retained
transfer plan, and the same nine focused observations match the preceding handoff.
An omitted scope-end call is rejected as incomplete service instrumentation even
though values match; repair reuses the passing result without execution. The
exported source project can regenerate the same helpers through
`render_source_service_bridges`. C object transport, entry dispatch and context
lifetime remain in [bridge.c](bridge.c).

The 630 cases cover all ten machine entries, zero/high-bit/extreme size/count
words, null/live old blocks and in-place/moving/failing lower allocation. They
compare arguments and call order, normal/nonlocal outcome, errno, logical sizes,
aliases and lifetimes, 64-byte prefixes and adjacent frame words. This controlled
allocator deliberately tests wrapper behavior independently of lower bodies;
it does not establish their native size restrictions or large allocation behavior.

## Native consumer integration

For an existing native consumer, select a newly prepared allocation package through
the public dependency workflow. Its exported adapter and generated service binding
travel with the component; the caller's C and other selected components stay intact:

```sh
spaghetti-extractor component start gnu-hello quote-slots \
  --comparison-package /path/to/native-consumer/inputs \
  --dependency-package checked-allocation=/path/to/checked-allocation \
  --output build/updated-consumer
spaghetti-extractor component status gnu-hello quote-slots \
  --comparison-package build/updated-consumer \
  --reuse-comparison /path/to/native-consumer --case style-0-kind-0
spaghetti-headless-wayland spaghetti-extractor component check gnu-hello quote-slots \
  --comparison-package build/updated-consumer --case style-0-kind-0 \
  --reuse-comparison /path/to/native-consumer --output build/updated-consumer-check
```

`build/component-group-consumer-2026-09-24/` records this handoff with the generated
manual-entry bindings. The selected case executes real quoting and twenty native
allocation success/failure probes, covering all eight entries and both aliases.
Every selected C entry runs, with the original bodies and shared tail trapped.
Original/replacement observations match; caller/neighbor inputs and all boundary
contracts remain unchanged. The updated check takes 7.194s, and subsequent reuse
0.926s with zero compiler/link/execution work. Source export also passes.
The resumed Nix shell changed the compiler environment, making all fourteen files
ineligible for object reuse; the preview predicts that actual work. This is not a
warm two-file compilation measurement. No new consumer adapter or toolkit change
is needed. This routine comparison retains its explicit initialization and fatal
handler interception, rather than claiming normal program startup or termination.

To prepare the native consumer for the first time:

Prepare the existing [allocation/quoting](../hello-allocation-growth/README.md),
[cleanup](../hello-quoting-cleanup/README.md) and
[reallocation](../hello-reallocation/README.md) packages, then run:

```sh
env -u LD_LIBRARY_PATH -u LD_PRELOAD -u GCC_EXEC_PREFIX -u COMPILER_PATH \
  PYTHONPATH=.:src spaghetti-headless-wayland \
  python tests/fixtures/hello-native-quoting/walkthrough.py \
  build/hello-components /path/to/retained-pe32-comparison/inputs \
  /path/to/original/hello.exe build/hello-checked-native --component-packages \
  --cleanup-package build/hello-cleanup/quote-cleanup \
  --reallocate-package build/hello-reallocation/allocation-reallocate \
  --checked-allocation-package build/hello-checked/checked-allocation
```

Actual quoting/growth consumers execute the selected family, which calls actual
lower native routines and selected realloc C. Every family entry additionally
runs a success and controlled failure probe, with live old contents, calloc
initialization and errno observations. The fixture injects raw allocation failures
and intercepts `xalloc_die` as an explicit nonlocal service. It does not execute
the original fatal diagnostic/process-termination path. Normal quoting allocation
still forwards actual CRT imports.

The public recipe edits the private check compatibly, compares locally and through
native consumers, and reuses the lower realloc neighbor. A wrong resize request
is diagnosed locally and through the connected network, then replayed from retained
inputs after repairing the draft. Finally it builds and runs the six-component
experimental selection. Commands, phase costs and receipts remain in the output.

The accepted 2026-09-22 checkpoint uses
`build/hello-checked-allocation-2026-09-22/packages-v4/` and `native-workflow-v1/`.
All 47 recipe commands and 39 comparisons pass in 198.331s, including the 21-case
experimental run. Initial local checking is 3.448s; a compatible local edit is
4.766s and native integration 10.954s. Each edit compiles one translation unit.
The unchanged realloc neighbor reuses in 0.972s with no new compiler, link,
execution, model or solver work. The earlier five-component Hello recipe, the
connected DX-Ball walkthrough and the 42-case jq network also pass.
Integrated Nix validation passes 56 tests and six repository/SDK gates. The retained
`audit-checkpoint.py` revalidates 86 comparison receipts, three assemblies, current
producers, all native entry/tail guards and the negative/reuse evidence. Formal
checking remains not requested throughout this practical checkpoint.

This is a manual component-boundary demonstration with multiple operations,
shared implementation and ABI aliases. It is not an automatic split/merge proof,
general interception rule, checked heap summary or strong native qualification.
The original quoting engine, remaining lower allocators, CRT, process startup/TLS,
arbitrary callbacks and another architecture remain outside this checkpoint.
