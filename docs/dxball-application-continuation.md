# DX-Ball application shell continuation

WinMain, window dispatch and the named-semaphore instance lifecycle now have
ordinary C implementations. They reuse the existing shared scene, title, flow,
surface and palette objects through 35 explicit services. No original game source
was consulted, and no checker/compiler/artifact internals changed. The four
native entries add one independently editable component to the source project.
Actual graphics setup, sound, clocks and remaining native helpers still require
platform/runtime backends; this is not a complete portable game.

## Behavior without normal application execution

The [boundary](../tests/fixtures/dxball-application/BOUNDARY.md) describes inputs,
state ownership, aliases, lifetimes, callbacks and message output initialization.
The local driver runs original entry bodies or their replacements with controlled
services, without opening a game window or initializing DirectDraw. Twenty-eight
cases check:

- Semaphore creation, existing-instance rejection, failed creation and cleanup
  callbacks that change the stored handle.
- Startup selection, failed graphics setup, inactive waiting, nonlocal process
  termination and a callback into the actual window procedure during setup.
- Ordered message schedules, translation changes, negative GetMessage results
  and preservation of the 32-bit quit result.
- Focus, activation, power, keyboard, mouse and palette events, including failed
  cursor output and mouse motion's subsequent default-window call.
- Destruction with missing or populated resources, and callbacks that redirect
  subsequent disposal to a different surface/palette.

The C preserves the original quirks: an opened existing semaphore is abandoned,
destruction clears DirectDraw without releasing it, and GetMessage's minus one
result is dispatched as nonzero. Observations retain complete palette bytes,
shared fields, stable object identities, lifetimes and ordered interactions
before and after callbacks. The selected termination service never returns;
the existing nonlocal handler records its process-exit outcome.

All 28 native comparisons match. The first executable behavioral C is unchanged
after local and normal feedback. Before execution, compiler warnings required
braces in adapter macros; the source profile also required moving two mutable
static string wrappers into invocation-local storage. These were authoring
corrections, not corrections based on whole-game behavior.

A deliberate mutation treats only GetMessage result one as success. The local
`get-message-error` case rejects it at `$.application.calls`: the original makes
22 observed outer calls and the mutation stops after 14. Original/source traces
and a replay command are retained. No normal game workload is needed to detect
or diagnose this behavioral error.

## Source reuse and integration

Public `candidate apply` adds the component and its standalone consumer to copies
of the preceding source project. All 28 cases pass on x86-64 and emulated AArch64
without Wine or the original executable. Both projects preserve all 33 neighboring
component records, 106 prior objects including timestamps, and 40 prior consumer
binaries byte-for-byte. They contain 34 components, 136 public native entries
and 658 retained consumer cases. Only the new consumer needed fresh execution;
unchanged neighboring evidence and binaries remain available.

The normal comparison then executes the lifted WinMain and window procedure in
the actual game alongside the preceding network. It matches 64 gameplay frames,
application streams, exit status and all 32 preceding observation fields. Those
fields also equal the prior normal result. Diagnostics record one selected run
and 98 window events. Internal C acquire/release calls bypass their public entry
wrappers, so zero public counts there do not mean those operations were skipped.
Message failure, cleanup alternatives and uncommon callbacks have local coverage;
the normal workload does not establish it.

This integration found a controller dependency, not a behavioral C defect. The
old driver stopped at `0x40d110`, an instruction inside original WinMain. Replacing
WinMain bypassed it, so the input schedule never advanced and title rendering
eventually exhausted the output limit. The corrected shared driver stops at
frame entry `0x40ab10`, then at that outer call's return address. This counts the
same frames with either caller and avoids counting original-body observation
wrappers twice. The unchanged C and observations then match; no output limit was
raised and no application output was filtered away. All 70 compiled units were
reused on that rerun.

Driver/observer contracts must follow preserved boundaries instead of requiring
the original implementation's internal instructions. For semantic differences,
the stronger practical rule remains: reduce the trigger to a local or small
connected consumer before closing the issue. Missing inputs are coverage gaps;
inability to represent, drive or observe them is a tooling/boundary gap. Neither
passing normal execution nor finite local cases guarantee exhaustive equivalence.

## Evidence and costs

Retained work is in `build/dxball-startup-2026-09-28/`:
`local-check-v3/`, `wrong-message-check/`, `normal-check-v3/`, `program/` and
`arm-program/`. Public apply receipts retain commands, checks and previous
projects. `validation.json`, `reuse.json`, `tree-audit.json` and
`repository-gates.json` collect the evidence. Earlier setup failures and the
controller failure remain retained. An attempted reuse of the preceding normal
receipt under a different root component was rejected; the first shell normal
build compiled 70 units, and subsequent reuse worked within the new root.

| Passing comparison | Preparation | Compiler | Link | Execution |
| --- | ---: | ---: | ---: | ---: |
| Local, 28 cases | 0.092 s | 0.032 s | 0.064 s | 3.784 s |
| Normal, 64 frames | 1.682 s | 0 s | 0.064 s | 36.451 s |

These are receipt phases for cached rechecks, excluding Wine setup and other
bookkeeping. Local recheck compiles one unit and reuses three; normal recheck
reuses all 70. Model and solver costs are zero. Public source apply, build and
the new consumer check took 4.696 s on x86-64 and 18.870 s on emulated AArch64.
Wine always ran inside headless Wayland; no expensive pilot regeneration was
needed. See the [reproduction recipe](../tests/fixtures/dxball-application/README.md).

The existing source profiles accept the C, but no formal proof was requested or
granted. Remaining runtime helpers, actual display setup and portable platform
and original-address backends are subsequent work. No significant lifting-tool
limitation was established by this component; the full goal remains active.
