# DX-Ball gameplay frame continuation — 2026-09-28

The [gameplay component](../tests/fixtures/dxball-gameplay/README.md) lifts the
actual frame at `0x4044d0..0x404ac2` into 192 lines of ordinary C. It sequences
existing services and directly implements ball/shot iteration, pending-event
unlinking and disposal, score changes, powerup adjustments, velocity arithmetic
and mouse input. Its interface borrows complete list records and shared menu/scene
state. Physics, allocation, remaining rendering helpers and platform services are
explicit dependencies; they are not counted as lifted by naming their services.
Authoring used executable instructions/data and existing interfaces, without
original game source or changes to the checker, compiler or artifact machinery.

Sixteen local native cases match without the game UI or neighboring bodies.
Observations retain complete payloads and links, pointer identities, list cursors,
live/dead event identities, pending bytes and ordered interactions before and after
callbacks. Cases include pause, multiple frames, cursor changes during drawing,
mutation during hit/free callbacks, powerup sequences, signed flags, mouse input
and binary64 rounding. The native routine advances its event iterator again after
unlinking; an intervening node can remain pending. Replacing that iterator with
a conventional drain condition is diagnosed at
`$.frame.calls[28].after.events[1][0]`: original live identity 1, replacement 0.
Restoring the iterator passes, recompiling one implementation unit and reusing
the two adapter units. This exercise needs no full application.

The source project now contains twenty-one components implementing 82 native
entries. The new sixteen source-consumer cases pass on x86-64 and AArch64. All
twenty neighboring component identities and all 55 preceding compiled objects
remain unchanged; their consumer binaries and 237-case evidence are reused.
The cumulative portable source-consumer coverage is 253 cases. This is a portable
subsystem project, not a complete standalone game.

## Reduce integration discoveries to independent cases

The first live gameplay comparison found a one-pixel difference in a damage
rectangle: `[478,436,551,450]` versus `[478,436,551,449]`. Frame scalar state, ball
payloads and list links matched. Inspection of the retained native paddle helper
at `0x4067b0` showed a clock-dependent random sprite selection. The four sprites
at slots 128–131 in the retained `Mball2.sbk` have heights 14, 13, 18 and 17. The
uncontrolled runs therefore did not provide corresponding environment inputs.

`prepare-paddle.py` reduces this to a small connected comparison. It calls the
actual native drawing helper under either the original frame or the C frame,
with asset-derived sprite dimensions, controlled clocks and observed graphics
calls. It needs no game startup or DirectDraw. All four random choices match,
producing rectangle bottoms 450, 449, 454 and 453. Deliberately supplying choice
0 to the original and choice 1 to C reproduces the live 450-versus-449 difference.
The workbench first reports the random-result divergence at
`$.frame.calls[9].drawing[1].result`, before its visible consequence. Both the
negative result and the matching cases are retained.

The normal-game harness now supplies an explicit clock/random schedule to that
same synchronous paddle helper on both observed sides. Clock inputs advance by
64 per frame from `0xf0000000`; random results are frame modulo limit. Thirty
input observations retain call order, arguments and results. Outside the helper,
the native clock/random implementation remains active. No frame, physics or
drawing implementation was changed to obtain the match, and no differing pixel
observations were discarded. The original first-authored `play.c` remains byte
identical throughout local, connected, portable and live checks.

The resulting twenty-one-component normal network matches through six gameplay
frames and close. All three processes exit zero, the C frame is selected six
times, and state, lists, pending bytes, damage rectangles and pixel hashes match.
The untouched original control checks startup, output and exit. Pixel equivalence
is checked between the two observed sides under the stated environment schedule;
it is not a claim that separate uncontrolled random runs draw identical pixels.
The workload keeps the ball attached and does not establish a full playthrough.

This exposes a preparation weakness: a no-op rendering service did not reveal
the environment inputs consumed inside its native implementation. The existing
interfaces and ordinary C adapters could express and execute the missing
connected case, so no new tool internals were necessary. The operator guide now
requires environment inputs to be included when reducing integration failures,
alongside memory, aliases, lifetime and callbacks. A new input is a coverage gap;
an interaction that cannot be represented or executed locally is a tooling gap.
Finite comparisons cannot promise that integration never discovers another case.

## Evidence and remaining work

Retained evidence is in `build/dxball-gameplay-2026-09-28/`:

- `gameplay.asm`, `authored-first.json`, `prepared/`, `prepared-final/` and
  `check-final/`: executable-derived authoring, first C digest and sixteen direct
  native cases using the current adapter.
- `edit-behavior-wrong/`, `edit-behavior-corrected/`: local event-iteration defect
  and repair. An earlier edit that left an unused static helper is separately
  retained as `edit-wrong/` with `compile-failed`, not behavioral evidence.
- `paddle-prepared/`, `paddle-check/`, `paddle-unequal-check/`: asset provenance,
  four connected comparisons and the deliberate unequal-input reproduction.
- `normal-check/`: the original uncontrolled mismatch, preserved for diagnosis.
  `normal-controlled-prepared/` and `normal-controlled-check/`: explicit input
  schedule and matching normal execution.
- `program/`, `arm-program/`: public source-project updates and native-derived
  portable observations. `validation.json` and `tree-audit.json` bind results,
  source digests, reuse and the preserved unrelated tree.

Final direct comparisons spend 0.073s preparing, 0.278s compiling, 0.064s linking,
9.619s in Wine startup wall time and 2.549s executing 32 runs. The four connected
cases spend 0.278s compiling and 0.512s executing eight runs, with 4.009s startup.
The live comparison compiles 43 units in 1.656s and links in 0.114s; startup takes
39.302s and three executions take 30.691s. There is no model or solver work in
these checks. Initial manual boundary analysis and adapter authoring are not
included in these measurements.

The admitted numeric environment is nearest rounding with 53-bit x87 precision,
checked at live frame entry. The C materializes binary64 operations before
integer truncation. INT32_MIN angles lie outside the supplied 361-word table
view. Native list borrowing follows live roots between services; snapshots do not
qualify allocation identity across an unseen free/reallocate cycle inside a helper.
Live capacity is explicit at 64 encountered addresses per object kind and 32
outer frames. These are visible experimental boundaries, not strong heap proofs.

The compiler-backed practical C profile is satisfied. The optional formal profile
reports `restricted_c_volatile_storage`; no strong qualification is claimed.
Repository metadata, production Python lint and format registry checks accompany
this continuation. No broad pilot rebuild or full repository proof campaign is
needed for these fixture/adapter changes. Every Wine run uses headless Wayland.
Gameplay helper bodies, scene entry/exit/input, startup and portable platform
backends remain open, and the full DX-Ball goal stays active.
