# jq program-support continuation

Seventeen more jq entries now use ordinary C through the existing component
workflow. All 44 native scenarios match. Both standalone architectures match
285 CLI workloads and 32 live-value cases, preserving every prior component.
No new tool internals or significant tooling blocker were needed.

## Real boundaries and consumers

The [program-support module](../tests/fixtures/jq-program-support/README.md)
contains 397 lines of source-assisted C in three files. It uses the existing
shared layouts and production entry names:

- UTF-8 routines borrow bounded buffers and report cursor offsets, decoding
  results, missing-byte counts and encoder writes. Direct cases cover every
  leading byte, malformed sequences, truncation, scalar boundaries and output
  frames. Input bytes remain unchanged.
- Source-location objects own copied input bytes, filename and line map. Retain
  preserves alias identity and increments the existing reference count. Tests
  mutate the caller's old buffer, release one alias, use the retained object,
  report diagnostics through a real jq callback, and release the final alias.
- Bytecode support returns immutable descriptors, traverses parent/subfunction
  relationships, disassembles code and frees graphs. Children borrow the root's
  symbol table; the root alone releases it. Real compiler scenarios exercise
  closures, recursion, patterns, errors, execution and teardown in two contexts.

Variadic source diagnostics transport a live `va_list` through ordinary C adapters.
The source does not reconstruct heap state from native pointer values. Native
comparisons use the pinned original libjq, remove all 17 selected old bodies and
four private helpers, and check that the traps remain intact after execution.
Allocation/lifetime observations reuse the existing fixture.

The first 44-case check already matched. A coverage audit found that
`dump_operation` was reached inside the authored disassembler but its distinct
native entry was not exercised. The final comparison adds that direct call;
all 17 entry adapters now have observed calls. No original behavior or mismatch
was discarded to obtain the final result.

## Portable implementation and integration

Two UTF-8 expressions needed careful C spelling: backtracking could form a pointer
before the borrowed buffer, and the forward scanner could form a pointer beyond
its extent before comparing it. The authored version checks the boundary before
decrementing and compares remaining lengths. Native results still match, including
the original one-byte backtracking exception, unchanged missing-byte output and
surrogate encoding. It does not replace the API with stricter Unicode validation.

`candidate apply` exports the checked module, runs the existing binding recipe,
builds the staged project and compares actual program execution before publishing.
The new normal-entry cases cover disassembly, nested closures, multiline compiler
diagnostics, invalid input bytes, encoding boundaries and whitespace behavior.
Both text-output and binary-output workloads from the previous milestone remain.
All Wine runs use a headless Wayland desktop.

The old `bytecode.o`, `jv_unicode.o` and `locfile.o` now contain no function
definitions in either delivered build. Every selected production entry has exactly
one definition in the final executable. Neighboring component records, exported
source files and unaffected compiler objects are reused.

The delivered project guide also now describes the existing unified apply command
and the actual default text/binary stream policy. The binding recipe refreshes
that guide while preserving operator edits through its existing three-way checks.
Documentation-only changes remain excluded from executable invalidation.

| Evidence | x86-64 | AArch64 |
| --- | ---: | ---: |
| Selected components | 40 | 41 |
| Previous component records preserved | 39 | 40 |
| Previous exported component files preserved | 492 | 498 |
| Objects retained by bytes and mtime | 179 | 180 |
| Changed or new objects | 9 | 9 |
| Build wall time | 0.465 s | 5.674 s |
| Program comparison wall time | 14.144 s | 25.753 s |
| CLI cases matched | 285 | 285 |
| Live-value cases matched | 32 | 32 |

The nine objects are three retired backend files, four authored source objects,
one entry adapter and the shared entry-counter table. Native preparation takes
0.018 seconds, compilation of eight translation units 0.736 seconds, and linking
0.064 seconds. Wine startup takes 5.547 seconds wall time; the 88 case executions
take 7.447 seconds summed. Model, solver and pilot-rebuild costs are zero.

## Remaining scope

These are practical comparisons of a source-assisted lift. The practical C
profile passes; formal checking was not requested and stronger qualification
remains separate. Corrupt graphs/pointers, arithmetic outside the original valid
domain, allocation failure, concurrent mutation and arbitrary CRT assertions are
outside this component's declared profile.

Full jq remains incomplete. The next dependencies include the remaining shared
value-release dispatcher, seed/TLS lifecycle and path services, followed by an
explicit review of generated frontend, numeric/regex library reuse and final
source delivery. Additional fixtures alone cannot establish completion. The
goal remains active, with no verified tooling impasse.

Retained evidence is under `build/jq-program-support-lifting-2026-09-27/`:
`support/authoring/` and `support/entry-comparison/` are editable workspaces;
`support/entry-checked/` is the current native result; `program/` and
`arm-project/` are the delivered sources. `host-integrated-*` and
`arm-integrated-*` contain builds and workloads. `native-entry-counts.json`,
`result.json`, `validation.json` and `tree-audit.json` retain coverage, cost,
validation and dirty-tree preservation evidence.
