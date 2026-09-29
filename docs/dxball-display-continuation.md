# DX-Ball display setup continuation

The complete windowed and fullscreen initializers now have ordinary C
implementations, including their private table-reset and destination-binding
helpers. The 114-line component uses existing application, scene, damage, title,
font and sprite-bank objects through explicit platform services. No original
game source was consulted, and no checker, compiler or artifact internals changed.
This extends the real startup path beyond the earlier DirectDraw tail pilot;
Win32/DirectDraw and other runtime dependencies still need portable backends.

The [boundary](../tests/fixtures/dxball-display/BOUNDARY.md) records resource
identity, aliases, shared ownership, callback effects, descriptor reuse and the
original's asymmetric failure paths. The C preserves nonzero-status failure,
outputs published on failure, exact error strings and callback-sensitive reloads.
Reset clears three banks' 255 slots and counts while preserving their six tail
words and the former objects' contents and lifetime. Source-side traps reject
fallback to the two private original helpers.

Forty-six local comparisons execute the original entry bodies without starting
the game or actual DirectDraw. They cover both modes, allocation/service failures,
positive statuses, partial capability outputs, low-memory decisions, clipping,
callbacks that redirect resources and descriptor changes between surface calls.
They observe state, bank contents, object lifetime and ordered interactions.
All match the first executable behavioral C unchanged.

A deliberate wrong destination-binding store is rejected by the local
`windowed-success` case at `$.display.final.roots[6]`: original one, replacement
zero. Both initializers still return success. Retained inputs and observations
make this semantic defect diagnosable without any normal application workload.

## Capability history and backend scope

The original ignores GetCaps' status and can consume two unwritten words from
its previous stack contents. The component represents those words as an explicit
`display_history` input. Local native invocations seed the corresponding original
entry-frame locations; source consumers supply the same values. Failed, partial
and unwritten outputs are checked without introducing uninitialized portable C.

The current normal backend requires successful GetCaps with complete consumed
outputs. On failure it stops with an explicit missing-history-transport diagnostic.
Its placeholder inputs are not claimed to reproduce original caller history;
complete provider outputs must overwrite them before any component decision.
Successful status alone is not a general check of output completeness: that is
an explicit backend assumption. Original-side instrumentation captures and
restores actual entry history before its C wrapper changes the stack.

Whole-program delivery still needs original-caller history transport on this
failure path, or a justified backend contract that always supplies complete
outputs. Passing the normal success workload does not discharge this obligation.
The component interface and independent comparisons already express the behavior;
this is remaining backend work, not an unsupported component proof rule.

## Reuse and normal execution

Public `candidate apply` adds the component to copies of the preceding source
project. All 46 cases pass on x86-64 and emulated AArch64 without Wine or the
original executable. Both retain all 34 neighboring component records, 109 prior
objects including timestamps and 41 previous consumer binaries byte-for-byte.
The project now contains 35 components, 138 public entries and 704 covered
consumer cases. Unchanged consumers were retained rather than rerun.

Normal execution reaches the lifted fullscreen initializer once and matches
64 gameplay frames, application streams, exit status and all 32 preceding
observation fields. Those fields also equal the previous normal result. Windowed
setup and failure alternatives are covered by the independent consumers.

The first normal comparison exposed an observer assumption: its graphics trace
expected a call to the old private destination-binding helper. The store is now
inside the initializer, so the observer records the actual resulting binding at
successful component completion. No platform call follows that store before
return. It does not execute a production helper or synthesize the expected
destination. The C is unchanged, every preceding observation is preserved, and
the deliberate local defect confirms that a wrong store remains observable.
The recheck recompiles one observer unit and reuses the other 71.

End-to-end findings must remain reducible to local or small connected consumers.
A new trigger is a coverage gap; inability to express, drive or observe it is a
boundary/tooling gap. A passing full-game rerun cannot close such a gap. Observer
assumptions about private instruction addresses must not constrain valid C
refactoring. Finite comparisons do not guarantee exhaustive equivalence.

## Evidence and costs

Retained work is in `build/dxball-display-2026-09-28/`: `local-check/`,
`wrong-binding-check/`, `normal-check-v2/`, `program/` and `arm-program/`.
The first normal mismatch remains in `normal-check/`. Public apply receipts,
`authored-first.json`, `validation.json`, `reuse.json`, `tree-audit.json` and
`repository-gates.json` record source identity, outcomes, reuse and repository
checks. See the [reproduction recipe](../tests/fixtures/dxball-display/README.md).

| Passing comparison | Preparation | Compiler | Link | Execution |
| --- | ---: | ---: | ---: | ---: |
| Local, 46 cases | 0.067 s | 0.310 s | 0.064 s | 6.485 s |
| Normal, 64 frames | 1.773 s | 0.765 s | 0.114 s | 36.552 s |

These are comparison phases, excluding Wine startup and bookkeeping. Package
preparation took 0.367 s. Model and solver costs are zero. Public source apply,
build and new consumer execution took 6.512 s on x86-64 and 22.694 s on emulated
AArch64. Every Wine invocation ran inside headless Wayland; no pilot regeneration
was required. The source profiles accept the C, but no formal proof was requested
or granted. Remaining runtime helpers, capability-failure history transport and
portable platform/address-space backends keep the full goal active.
