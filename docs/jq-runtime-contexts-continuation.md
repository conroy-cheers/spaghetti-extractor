# jq numeric context and seed lifecycle

The remaining decimal/dtoa registries and seed initializer now run as one
source-assisted C component through the existing stateful workflow. All twelve
native lifecycle scenarios match. Both standalone architectures match 288 CLI and
32 live-value cases, including the normal `--run-tests` path and its three worker
threads. No tool internals changed, and no significant tooling blocker surfaced.

## Boundary and observed discrepancy

The [component](../tests/fixtures/jq-runtime-contexts/README.md) owns the decimal
key/once state, dtoa key/once state and hash seed/once state. Every caller on one
thread borrows the same live context; different live threads have distinct
objects. Sticky decimal status and dtoa caches persist between calls. Explicit
finalization clears and releases a context; a subsequent getter allocates another.
Worker destruction and process cleanup remain separate lifecycle paths.

The boundary carries shared allocation, pthread, conversion and exit-registration
services. Native comparison checks exact values, context alias relations,
allocation effects and complete process teardown using an OS observation handle.
Deterministic entropy inputs cover a full four-byte read and the original fallback
after failed open, short read or failed read. The C decodes the original
little-endian seed explicitly. Repeated reads reuse the initialized seed.

The first executable comparison matched the contexts, values and live heap, but
all twelve cases detected a different release order at process exit. The source
had registered callbacks with the test executable's `atexit` table; the original
uses its DLL's table, shared with the allocator. Routing the explicit exit service
through that same native table resolves the difference. The standalone program
uses its one CRT registry. This required ordinary C service/adaptor changes,
not a new checker rule or a weaker observation. The corrected check recompiles
three of seven translation units and reuses the other four.

All seven entry adapters are exercised, and the selected old entry bodies plus
private seed initialization and dtoa destruction are disabled on the source side.
Every completed native process ends with zero observed live blocks, live bytes
and invalid releases. This is practical evidence under the recorded boundary;
declared state ownership and finite comparison are not universal qualification.

## Program integration and reuse

`candidate apply` stages source export, the existing assembly recipe, build and
normal-entry checks before publication. A short C source adapter normalizes two
conditional linkage prefixes in `jv_dtoa_tsd.c` and retains the exact edit in
project provenance. The shared retirement machinery then removes the original
definitions. Existing numeric and hash bindings keep their component identities
and forward to the new provider through their existing accessors.

`jv_dtoa_tsd.o` now has no functions. `jv.o` contains only the three forwarding
accessors for decimal context, object unsharing and hash seed. Each selected
runtime entry has exactly one final definition. The native context keys are not
reconstructed or transplanted into portable runtime state.

The existing CLI test runner provides a real threaded consumer. Its execution
also required the shared diagnostic counters to use atomic slot/count access and
one-time report registration. That changes observation support, without changing
neighboring authored components or their entry adapters.

| Evidence | x86-64 | AArch64 |
| --- | ---: | ---: |
| Selected components | 41 | 42 |
| Unchanged neighboring component records | 40 | 41 |
| Unchanged neighboring exported files | 512 | 518 |
| Objects retaining bytes and mtime | 186 | 187 |
| Changed/new objects | 7 | 7 |
| Build wall time | 0.415 s | 4.622 s |
| Program comparison wall time | 14.740 s | 27.173 s |
| CLI cases matched | 288 | 288 |
| Live-value cases matched | 32 | 32 |

The seven objects are two retired backend files, the observation support object,
two new entry/runtime adapters and two authored source objects. Native repair
preparation takes 0.012 seconds, compiler child time 0.361 seconds, and linking
0.064 seconds. Wine startup takes 3.718 seconds wall time; the 24 executions take
5.798 seconds summed. These timings exclude operator analysis. Model, solver
and pilot-rebuild costs are zero. Every Wine invocation uses headless Wayland.

## Remaining scope

The stateful component preserves the original initialization/cleanup behavior,
including repeated key creation if callers misuse the explicit init entries.
Its contract admits startup initialization before live contexts. It does not
claim exhaustive failure handling, cancellation, arbitrary DLL unloading, or
simultaneous finalization and use of one context. Entropy is an explicit runtime
input; independent programs need not receive identical random seeds. The portable
provider retains 32-bit time failure outside the original representable range.

Full jq remains incomplete. The remaining implementation/review queue is path
canonicalization, the retained slice helper and internal test-runner delivery,
followed by explicit generated-lexer/numeric/regex library reuse and final source
delivery. The successful built-in test execution is useful consumer evidence; it
does not itself reclassify those retained bodies as completed lifts. No significant
tooling impasse was found, and the active goal remains active.

Evidence lives under `build/jq-runtime-contexts-lifting-2026-09-27/`:
`contexts/authoring/`, `contexts/fixed/` (the retained cleanup mismatch),
`contexts/shared-exit/` (the matching repair), `program/`, `arm-project/`,
`host-integrated-*`, `arm-integrated-*`, `result.json`, `validation.json` and
`tree-audit.json`.
