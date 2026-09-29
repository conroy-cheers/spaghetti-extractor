# DX-Ball sound bank continuation

Nine real sound-control entries now use 95 lines of ordinary C: play, loop, stop,
stop-all, restore, release-one, release-all, suspend and shutdown. They share one
bank of fifty sample references, a device and a primary buffer. Each sample keeps
its buffer reference and 33 original payload bytes. No original game source was
consulted, and no checker/compiler/artifact internals changed. Sample loading,
device creation, music and remaining runtime/platform services are still open.

The [boundary](../tests/fixtures/dxball-audio/BOUNDARY.md) distinguishes sample
records, buffer/device references and their lifetimes. Suspend preserves records
while releasing buffers; release-one disposes the currently selected record;
shutdown disposes records before suspending. Callbacks can redirect slots and
resources between interactions. The C reloads the fields that the original reloads,
including the buffer used after recovery and the record cleared after release.

The original skips zero-valued playback settings and retries exactly once for
results 2 or `0x88780096`. Recovery scans the whole bank and copies each saved name
before loading may dispose its record. A pointer into that disposed record would
not be an equivalent implementation.

## Independent behavior and history

All 36 native comparisons match the first executable C unchanged. Cases cover
settings, playback, both retry results, retry failure, missing resources, every
disposal operation, boundary slots, resource redirection and a sequence through
all nine entries. Recovery's controlled loader calls the actual release operation
over the shared bank, then publishes a new record. Providers overwrite freed
storage so an incorrect borrowed name cannot pass merely because bytes survived.
Observations retain all slots, sample bytes, lifetimes and ordered interactions.
Neither game startup nor an audio device is needed.

Status output has two distinct initial states. Stop supplies its original slot
number because the native GetStatus call writes into that argument's stack slot.
Recovery reuses one local word across loop iterations; its initial value is an
explicit historical input. Original local calls seed recovery entry ESP minus
`0x104`, including nested recovery calls. Cases exercise unwritten status and a
previous iteration's retained value. The C does not use uninitialized host storage
or invent a zero result for failed queries.

A deliberately cached sample pointer in release-one is diagnosed locally at
`$.audio.calls[1].after.records[0].buffer`: original one, replacement zero.
The callback redirects the slot, so clearing the old record changes observable
memory. This gives a retained regression independent of normal execution.
The first mutation-package attempt accidentally omitted its unchanged header
through a low-level replacement helper and failed compilation. Public
`component start --source-file` retained that header and the focused comparison
then rejected the behavioral defect. This was setup misuse, not a required tool
extension or a correction to the lifted C.

## Reuse and integration

Public `candidate apply` adds the component and its standalone consumer to copies
of the preceding source project. All 36 cases pass on x86-64 and emulated AArch64
without Wine or the original executable. Both retain all 35 neighboring component
records, 112 prior objects including timestamps and 42 existing consumer binaries
byte-for-byte. The project contains 36 components, 147 public entries and 740
covered consumer cases. Unchanged consumers were retained rather than rerun.

The first normal comparison matches 64 gameplay frames and all 33 preceding
observation fields, which also equal the previous normal result. It exercises
selected playback, looping, stopping, release and suspension with real sample
records and a sound device. Lost-buffer recovery and alternative callback/error
paths get their coverage from the independent consumers. Private calls within
the C bypass public entry counters. No integration feedback required a behavioral
C change or a harness correction; the preceding display reporter only gained a
reusable include seam for the extended observer.

The mixed backend requires live incoming records and complete successful
GetStatus output. On query failure it stops explicitly because original-caller
recovery history transport is not yet provided. Original-side instrumentation
captures and restores actual entry history; the source backend's placeholder is
unobservable only under its complete-output assumption. Pointer reconstruction
does not establish lifetime. The remaining native sample loader's failure paths,
including its dangling-slot behavior, need their own lifting and transport work.
These restrictions remain backend obligations, not proof of whole-program closure.

Every semantic end-to-end finding must remain reproducible in a component or
small connected consumer. Missing cases are coverage gaps; missing representation,
execution or observation is a boundary/tooling gap. A normal rerun cannot close
such a gap. The tested component needed no new tool internals; the full goal stays
active with loader, device, music, historical-input and portable-backend work open.

## Evidence and costs

Retained work is in `build/dxball-audio-2026-09-28/`: `sound.asm`, `local-check/`,
`wrong-cached-record-check-v2/`, `normal-check/`, `program/` and `arm-program/`.
Public apply receipts and `authored-first.json`, `validation.json`, `reuse.json`,
`tree-audit.json` and `repository-gates.json` record provenance, source identity,
outcomes, reuse and repository checks. See the
[reproduction recipe](../tests/fixtures/dxball-audio/README.md).

| Passing comparison | Preparation | Compiler | Link | Execution |
| --- | ---: | ---: | ---: | ---: |
| Local, 36 cases | 0.041 s | 0.278 s | 0.064 s | 5.360 s |
| Normal, 64 frames | 1.870 s | 2.977 s | 0.064 s | 36.952 s |

These phases exclude Wine startup and bookkeeping. Package preparation took
0.363 s. Model and solver costs are zero. Public source apply/build/check took
5.022 s on x86-64 and 19.010 s on emulated AArch64. Wine always ran in headless
Wayland, and no pilot regeneration was needed. The source profiles accept the C;
no formal proof was requested or granted.
