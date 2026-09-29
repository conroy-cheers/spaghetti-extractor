# DX-Ball sound device setup continuation

Initialization and focus/reload now use 76 lines of ordinary C over the existing
sound bank and application owner. All 36 independent comparisons match the first
executable C unchanged. The original PE32 bodies provide the oracle; no original
game source or new checker/compiler/artifact internals were needed. See the
[boundary](../tests/fixtures/dxball-audio-setup/BOUNDARY.md) and
[reproduction recipe](../tests/fixtures/dxball-audio-setup/README.md).

## Behavior independent of the game

Initialization releases all sample records before setup, even when an existing
device makes setup return immediately. Focus creates the device and primary
buffer, starts primary playback, then reloads saved samples in slot order.
The original treats every nonzero creation, cooperation and playback result as
failure, including positive values. Its exact dialogs, flags, retry choices and
termination codes are retained. Failed creation can publish a device which is
then abandoned without release; the replacement preserves that behavior.

The component shares existing sample identities, payloads and lifetime rules.
Release-all and the reload provider execute actual lifted bank operations.
The provider overwrites disposed record bytes, exposing failure to copy a saved
name before loading. Cases exercise callbacks which redirect slots, graphics,
device and primary references, published and unpublished failure outputs,
multiple retries, nonlocal termination and focus/suspend/refocus/initialize.
No game startup or sound device is needed. Production C adds no retry bound.

A deliberate edit treating positive creation status as success is rejected by
`create-positive-published`. The first discrepancy is the second interaction's
argument at `$.audio_setup.calls[1].arguments[1]`: original 36, replacement 1.
The original displays its failure dialog; the defective replacement proceeds
to cooperation setup. Only the edited C unit is recompiled. This error class
is detectable locally even when normal application execution is unavailable.

## Reuse and normal integration

The public source apply workflow adds the component to both standalone projects.
All 36 new cases pass on x86-64 and emulated AArch64. Both projects retain all
36 preceding implementations and contracts, 115 compiled objects including
timestamps and 43 existing consumer binaries. Thirty-five component records
are entirely unchanged; the bank's comparison-binding references are updated
for the connected evidence. The project has 37 components, 149 public entries and 776
covered consumer cases. Unchanged consumers were retained rather than rerun.

Normal execution matches 64 frames and all 34 preceding observation fields,
which also equal the previous normal result. It executes initialization and
publishes a sound device. Focus is called privately by initialization; its public
source entry counter remains zero. Alternative retry, failure, callback and
refocus behavior is covered by the independent consumers. No integration finding
required a behavioral C correction. The bank reporter gained an include seam
so the extended observer can retain its observations.

The first normal preparation correctly rejected conflicting local and normal
bank selections. The preparation recipe now explicitly replaces the selected
adapter and binds the normal package's dependencies. This was a preparation
correction, not a change to the bank C, contract or tool internals.

The mixed backend retains native DirectSound and WAV loading. It requires live
sample-loader outputs and the preceding complete successful GetStatus/GetCaps
outputs; failed-query caller history remains explicit backend work. Pointer maps
do not establish lifetime. Investigation of the next loader boundary found that
some failures free a record without clearing its slot, and malformed RIFF input
can expose an unwritten format pointer. Those behaviors need explicit memory,
history and lifetime transport, rather than an implicitly safer WAV decoder.
The loader and music are still native. No full portable game or formal
qualification is claimed; the full goal remains active.

Every semantic integration finding must be reproducible in a retained component,
boundary or small connected check. Missing cases are coverage gaps; missing
representation, execution or observation is a boundary/tooling gap. A successful
normal rerun alone cannot close such a gap. Finite checks cannot guarantee that
future integration runs discover no new discrepancies.

## Evidence and costs

Retained work is in `build/dxball-audio-setup-2026-09-28/`: `setup.asm`,
`messages.json`, `local-check/`, `wrong-positive-check/`, `normal-check/`,
`program/` and `arm-program/`. Public apply receipts and `authored-first.json`,
`normal-observation-audit.json`, `validation.json`, `reuse.json`, `tree-audit.json`
and `repository-gates.json` record source identity, outcomes, reuse and checks.

| Passing comparison | Preparation | Compiler | Link | Execution |
| --- | ---: | ---: | ---: | ---: |
| Local, 36 cases | 0.092 s | 0.374 s | 0.064 s | 5.359 s |
| Normal, 64 frames | 1.925 s | 3.191 s | 0.164 s | 38.059 s |

These phase sums exclude Wine startup, indexing and bookkeeping; the normal
check compiled its full selection. Package preparation took 0.420 s. Model and
solver costs are zero. Public source apply/build/check took 5.361 s on x86-64
and 20.928 s on emulated AArch64. Wine ran in headless Wayland throughout; no
pilot regeneration was needed. Source-profile acceptance and finite comparison
results remain distinct from formal proof.
