# DX-Ball pickup lifecycle — 2026-09-28

The [pickup component](../tests/fixtures/dxball-pickups/README.md) lifts four actual
native entries into 148 lines of ordinary C: creation, movement/collection,
drawing and removal. Its explicit linked objects borrow the existing motion,
play, menu and sprite views. Sixteen services describe allocation, randomness,
particles, audio, collision, graphics and existing powerup helpers. Those helper
bodies remain separate work. Authoring used executable instructions/data and
established interfaces, without original game source or tool-internal changes.

The first authored C matches all 22 local native scenarios unchanged. These cover
every pickup kind, rare random gates, particle modes, wall/top/bottom handling,
resizing, callbacks, removal and generated sequences. Observations retain live
payloads/links, allocation/free identity, shared fields, sprite bytes/aliases,
board bytes and ordered service effects. The original's quirks remain: count is
decremented even for removal with no current object; iteration advances again
after removal; creation draws a random value before checking the active count;
and one generated kind is remapped to another.

Five connected cases also match, each running four actual gameplay frames over
the same state. They exercise pickup collection and frame flag consumption,
resizing, list disposal, event-driven creation and movement. The frame is an
existing independently authored component; its implementation and interface
remain unchanged. These consumers need neither game startup nor a graphics
backend. They cover collection and disposal independently of the normal game's
ability to reach those situations.

The source project now has twenty-four components implementing 99 native entries,
with cumulative coverage of 340 source-consumer cases on x86-64 and emulated
AArch64. This continuation runs the new 22 direct and five connected cases on
both architectures and reuses unaffected consumer evidence. All twenty-three
neighboring component records and all 66 prior compiled objects remain unchanged.
The archive update relinks consumers; all twenty preceding consumer binaries
remain byte-identical. Public `candidate apply` stages the changed assembly and
checks it before publishing the updated project.

## Normal integration

The existing 64-frame launch/close workload also matches with the pickup C
selected. Creation runs once through the lifted brick caller, and update/draw
run 64 times through the lifted frame, including the empty-list calls before
creation. The newly allocated pickup moves from (559,230) to (570,208) in the
remaining eleven frames. All 129 outer pickup records match, together with the
preceding board, brick, motion, damage, pixel and palette observations. All three
processes exit zero; the damage observer retains 870 records without drops.

The workload does not collect or remove that pickup. Those behaviors are checked
by the direct and connected consumers. Existing seed, paddle and palette-clock
inputs and their observations are retained unchanged. Actual allocation,
particles and other unlifted helpers remain active services. The untouched
original controls startup/output/exit; equality of uncontrolled environmental
pixels is not claimed.

No behavioral correction to the pickup C was needed after local, connected,
portable or normal execution. The normal adapter needed distinct macro names
when included alongside preceding adapters. The brick observer was factored for
reuse without changing its observations or authored implementation. Fresh
allocation payloads are copied without following uninitialized links, and
subsequent transport follows live reachable pickup objects around service calls.

End-to-end execution remains an additional check. Any discrepancy must become a
retained component, boundary or small connected regression that runs without the
complete application. If existing interfaces and ordinary adapters cannot express
the necessary state, lifetime or interactions, that is a tooling gap. No such gap
was encountered here.

## Evidence and limits

Retained evidence is under `build/dxball-pickups-2026-09-28/`:

- `create.asm`, `update.asm`, `draw-remove.asm`, `authored-first.json`, `prepared/`
  and `check/` retain binary-derived authoring and the first 22-case match.
- `prepared-final/`, `check-final/`, `frame-prepared/` and `frame-check/` contain
  the reusable local runtime and five connected consumers.
- `normal-prepared-final/` and `normal-check-2/` retain the final normal adapter
  and passing program comparison. `normal-check/` retains the initial compiler
  diagnostic and two objects reused after the adapter naming correction.
- `program/`, `arm-program/` and their public apply transactions retain portable
  assembly. `validation.json`, `reuse.json` and `tree-audit.json` record exact
  inputs, incremental reuse and preservation of unrelated dirty-tree work.

Initial package preparation takes 0.396s, excluding manual boundary analysis and
adapter authoring. The first direct comparison compiles three units in 0.278s,
links in 0.064s, spends 28.630s in Wine startup wall time and 3.973s in 44
executions. The connected check compiles five units in 0.392s, links in 0.064s,
starts Wine in 3.959s and executes ten runs in 1.142s. Normal integration compiles
47 units in 1.864s, reuses two, links in 0.064s, spends 56.584s in startup and
31.992s in three executions. Source applies take 11.240s and 46.431s. All
comparisons perform zero model or solver work; startup remains variable.

The boundary admits successful allocations, finite acyclic lists, live objects
after callbacks and valid sprite metadata. Arithmetic preserves native 32-bit
wrapping, signed branches and truncation. Finite cases observe memory and
lifetime; they are not checked heap summaries or strong composition proofs. The
normal view retains 64 encountered pickup addresses and 256 outer calls, and does
not qualify every unseen allocation reuse or callback lifetime. The practical C
profile accepts the implementation; optional formal eligibility remains incomplete.

Repository metadata, production Python lint and format registry checks accompany
the work. All Wine runs use headless Wayland. Remaining particle, paddle, shot,
powerup and scene lifecycle operations, startup and portable platform backends
still require lifting. This is a portable subsystem project, not a complete
standalone DX-Ball. The full goal remains active.
