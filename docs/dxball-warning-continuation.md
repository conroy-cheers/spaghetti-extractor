# DX-Ball warning and historical input transport — 2026-09-28

The two warning entries now have a 71-line portable C implementation. Twenty-six
original/source comparisons pass with the first C unchanged. The actual lifted
frame, paddle, pickup, particle and warning implementations also reproduce all
eight retained native history traces on x86-64 and AArch64. This carries the
previously missing input through ordinary adapters; no checker or compiler
internals changed and no original game source was consulted.

## Boundary and implementation

Preparation at `0x408c20` shares the existing progression, brick/motion, board,
gameplay and sprite objects. Drawing at `0x408ed0` uses the same deadline,
coordinates, rectangle and remaining-frame counter. The additional warning view
holds x, the source rectangle and an explicit per-invocation fallback input.
The [boundary](../tests/fixtures/dxball-warning/BOUNDARY.md) states its alias,
lifetime, callback and historical-input obligations.

The original's empty-board behavior is retained. The C snapshots y, row and
column from the explicit input, then scans in the original column-major order.
An eligible cell replaces the fallback; otherwise the raw words supply queue and
explosion coordinates. There are no uninitialized C locals or accesses beyond a
host board object. Queue requests cross the existing service boundary; the
preceding queue refinement handles the separately checked memory-read behavior.

Clock arithmetic, countdown volume, fast/slow particle counts, clipping and
ordered random calls match the original. Drawing exposes the actual shared source
rectangle to its blit service and reloads current coordinates/dimensions for the
damage rectangle. Callback changes to frame count survive until the final
decrement. Direct cases cover these interactions, signed/wrapping values,
nonstandard tile bytes and a prepare/draw sequence.

## Historical state through real portable callers

The three-word input is produced by
[`history.h`](../tests/fixtures/dxball-warning/history.h), with bindings in the
connected and native-platform adapters. It is target compatibility code, not a
new production game API or a checker special case.

- The actual lifted paddle's final sprite service supplies its selected sprite
  and retained vertical offset. The saved native EBX supplies one.
- Frame and pickup sprite services project the distinct saved-register layouts
  using explicit original-environment EBP/ESI values.
- Particle descriptor words 20/21/22 carry the same state. Partial describe/lock
  writes preserve the other words, and empty lists preserve preceding history.

The connected consumer starts at the frame boundary with the empty-board/count-one
state previously established by the native count/hit experiment. It runs the
existing lifted frame, paddle, pickup and particle bodies plus the new warning.
Rendering/audio and queue/explosion/particle-creation requests are controlled
services. This is not a complete out-of-grid event lifecycle.

Its expected observations come from the eight retained **actual native frame**
traces, which ran the original producer and warning bodies without seeding the
warning words. The portable replay supplies each trace's recorded incoming
register values, including the original import addresses as numeric environment
inputs, and compares history, queue/explosion arguments, calls and drawing
interactions. It does not substitute host function pointers. The original
count/hit preparation is not claimed as newly lifted by this replay. Native
traces are retained with the delivered source project; no repeated Wine build
was needed to check this transport.

## Assembly, reuse and normal execution

`candidate apply` installs the new selection and the ordinary assembly recipe in
copies of the existing source projects. On both x86-64 and AArch64, all 32
neighboring component records and 102 previous compiled objects retain their
bytes and mtimes; all 38 previous consumer binaries retain their bytes. The
projects contain 33 components, 132 public native entries and 624 covered consumer
cases: the preceding 590, 26 warning cases and eight caller-history cases. The
standalone source consumers require neither Wine nor the original executable.

The normal network retains the prior 32-component selection and execution/input
schedule. Native adapters carry the same history, including raw descriptor bytes
through describe, lock retries and unlock. The reviewed WinMain/flow/gameplay
call path supplies the original import values. Other caller contexts must supply
their own input contract.

Normal comparison matches 64 frames, preserves every prior observation, and
reaches the lifted warning draw 64 times with an inactive warning. Preparation
is not reached. Its expired/empty-board behavior is covered by the independent
consumers, not the normal workload. The adapter captures original warning entry
words before its own C wrapper and transports them into the original body.
Earlier original-side wrappers still have their instrumented contexts; the
separate unwrapped native frame experiment supplies the canonical history
reference. This distinction must remain explicit for future workloads.

Two setup/compiler issues are retained: the source consumer initially initialized
256 slots in a 255-slot portable sprite bank, and the normal adapter initially
used the local fixture's object variable name. Both were caught before behavioral
execution and fixed in adapters. No behavioral correction to `warning.c` was
needed. Game-scene reporting was factored into reusable observer/diagnostic
functions so the new wrapper retains existing observations without rewriting JSON.

## Evidence and remaining work

Evidence is in `build/dxball-warning-lift-2026-09-28/`: `check/` contains the 26
native comparisons, `program/` and `arm-program/` the portable projects and
retained producer traces, `normal-check/` the compilation failure and
`normal-check-v2/` the matching normal run. `validation.json`, `reuse.json` and
`tree-audit.json` record exact bindings, timings and preservation of unrelated
work. Preparation/compiler/link/runtime costs remain separate; no solver or
proof-model work was performed. Required repository checks also pass.

The direct practical C profile accepts this source; optional formal source
eligibility is satisfied, but no formal proof or activation authority is claimed.
The historical projections have finite connected evidence, not universal stack
or heap qualification.

Next, refine the **downstream queued-event consumer**. The native frame can read
pending-cell storage using the raw out-of-grid coordinates, and a subsequent hit
can read/write another native owner. Current frame/hit/blast grid contracts do
not cover that lifecycle. Use the established original-address services and
shared owners; do not discard the event, invent an access fault, or broaden C
array indexing. Remaining runtime helpers, startup and portable platform/address
backends still prevent full DX-Ball completion. The goal remains active.
