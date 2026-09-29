# DX-Ball queued events through live memory

The warning investigation established that the real queue can receive `(0,84)`
and read saved-board storage. Its downstream frame/blast lifecycle now runs
through explicit memory services, using the existing workbench and ordinary C
adapters. No checker, compiler or artifact machinery changed; no original game
source was consulted.

This is a local boundary refinement. The full portable game and its general
platform/address-space backend remain unfinished. Tests are finite evidence;
the existing strong proof standards are unchanged.

## Recovered behavior and boundary

The frame's service named `hit_tile` calls blast creation at `0x406070`, rather
than the collision hit routine at `0x405c80`. The relevant sequence is queue,
frame pending-byte read, blast creation, neighbor propagation, cell clearing,
expiry and disposal. This corrects the preceding next-action wording about
downstream "hit effects."

The frame now calls `read_pending`. Brick queue/blast operations use `read_cell`,
`write_cell` and `write_pending`. The same live memory owner supplies every alias.
Address arithmetic wraps at 32 bits; reads return one unsigned byte, and writes
change only the addressed low byte. An unknown mapping is an adapter capability
error. It is not permission to return zero or manufacture a native fault.

At `(0,84)`, the current-board-relative address is `0x42d0f0`, saved-board offset
760. The pending-relative address is `0x42d2a0`, saved-board offset 1192. These are
real aliases to different bytes, not extended indexing into a host C array.

Blast creation sets pending using the incoming coordinates. Later stages recover
coordinates from the wrapped drawing positions using signed division. For input
column 143165577, row 84, the reconstructed column is zero: creation and expiry
access different pending bytes. The original leaves the initial pending byte set.
The lifted C preserves this behavior. Neighbor tests also retain the original
signed comparisons; callbacks can change the center byte or expiry coordinates.

The native integration adapter accesses synchronized native memory. The local
portable adapter maps live current/saved boards, pending storage and explicitly
supplied external storage. It does not claim a complete map of arbitrary native
addresses. Existing hit/flash and unrelated consumers retain their reviewed
domains. See the [brick](../tests/fixtures/dxball-brick-actions/BOUNDARY.md) and
[frame](../tests/fixtures/dxball-gameplay/BOUNDARY.md) contracts.

## Independent checks

The native frame suite's 16 cases and brick suite's 29 cases pass. The connected
suite adds six 16-frame cases to its four existing collision cases:

| New case | Distinction checked |
| --- | --- |
| Saved-board alias | Creation, clearing and expiry modify the correct live bytes. |
| Occupied pending byte | The frame removes the event without creating a blast or adding score. |
| Signed neighbors | A negative column preserves the original ordered propagation and leaves an excluded neighbor untouched. |
| Wrapped position | Initial and final pending accesses have different owners/offsets. |
| Center callback | Allocation changes the center byte before the remaining-brick decision reloads it. |
| Expiry callback | Drawing changes the coordinates used by the pending clear. |

All ten connected cases execute the actual native or lifted frame, motion and
brick bodies without game startup or DirectDraw. Observations retain complete
live payloads, links, lifetime, shared bytes and ordered interactions. The new
saved-memory observations use an extent plus indexed nonzero bytes, preserving
complete contents without repeatedly printing large zero-filled buffers.

All 55 direct/connected comparisons match. The revised behavioral C is unchanged
since its first comparison. A deliberate mutation writes zero instead of setting
the pending byte. The public checker rejects it locally at
`$.bricks.calls[16].after.saved_boards.nonzero`: original has `[1192,1]`, while the
mutant omits it. The retained result supplies a replay command. No full game run
is needed to detect or diagnose that error.

The source project passes all twelve affected consumer suites on x86-64 and
emulated AArch64. Both retain 31 neighboring component records, 90 of 106 existing
objects including timestamps, and 28 of 40 consumer binaries byte-for-byte.
The frame/brick contract changes correctly rebuild their affected bridges and
consumers. The project remains 33 components and 132 public entries, with 630
covered source-consumer cases. Backups are excluded from these reuse counts.

Normal execution also matches 64 frames, with every preceding observation
unchanged. It recompiles five units and reuses 63. This workload does not supply
the new out-of-grid coverage; that comes from the independent consumers above.

## Retained work and costs

Evidence is in `build/dxball-event-memory-2026-09-28/`. `validation.json` collects
the receipts, deliberate defect, source checks and reuse audit. `frame-check/`,
`brick-check/`, `connected-check-v3/` and `normal-check/` are the passing native
results. `wrong-pending-check/` retains the rejected mutation. `program/` and
`arm-program/` are the updated source projects; their `candidate apply` receipts
retain assembly/build/check logs and previous project copies.

The initial setup attempts are retained: an unpinned child Python lacked a
dependency; Windows page reservation needed 64 KiB allocation granularity; and
a repeated recipe revision unnecessarily named an already unchanged contract
edge. The recipe now avoids redundant reviews. None required behavioral C fixes.

| Passing native check | Preparation | Compiler | Link | Execution |
| --- | ---: | ---: | ---: | ---: |
| Frame, 16 cases | 0.076 s | 0.310 s | 0.064 s | 2.198 s |
| Brick, 29 cases | 0.070 s | 0.310 s | 0.064 s | 4.666 s |
| Connected, 10 cases | 0.208 s | 0.315 s | 0.064 s | 2.642 s |
| Normal program | 1.640 s | 0.843 s | 0.064 s | 37.052 s |

These are separate receipt phases, not end-to-end totals. Connected recheck
reuses seven of eight compiled units; normal recheck reuses 63 of 68. Model and
solver work are zero. Public source apply plus build and the twelve affected
checks takes 12.457 s on x86-64 and 66.511 s for emulated AArch64 in this run.
Wine always runs inside headless Wayland. Repository gates are recorded in
`repository-gates.json`; no new whole-pilot preparation is needed.

The [reproduction recipe](../tests/fixtures/dxball-brick-actions/README.md#refine-queued-event-memory)
uses retained inputs, reviewed contract edges and existing public revision/apply
APIs. Remaining native runtime helpers, startup and portable platform/address
backends are subsequent work. No significant tooling limitation was established
by this refinement.
