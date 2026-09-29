# DX-Ball MDS stream continuation

The remaining MDS operations—start, pause, stop, completion and release—are now
75 lines of ordinary C in [`stream.c`](../tests/fixtures/dxball-mds-stream/stream.c).
Together with the existing loader, parser and event expander, this replaces the
MDS implementation used by the music controller. No original application source
was consulted. The shared object definitions are reused; callbacks borrow an
existing header and owner rather than reconstructing their storage or lifetime.

All 49 local cases match the first C unchanged. They cover all six bundled music
files, multiple live streams, partial startup, failed handle publication, resume
failure, requeue, pending-count wraparound, deferred reset returns, zero-length
payloads and cleanup failures. A deliberately wrong callback decrement is caught
by a single local replay. The [boundary](../tests/fixtures/dxball-mds-stream/BOUNDARY.md)
states the readable storage, fixed geometry and callback schedule assumptions.

Two shared-backend capabilities were needed. Translated MIDI headers can bind
their logical extent to live allocation identity/offset, preserving retirement
even for zero-length payloads on a wider-pointer host. An explicit controlled
experiment can record an original program freeing still-retained MIDI storage.
It preserves the invalid state and rejects subsequent API/callback access instead
of inventing use-after-free semantics. Default disposal checks stay strict.
Independent SDK/binding consumers exercise these features, with x86-64 and
emulated AArch64 runs as well; the backend remains candidate-neutral.

Normal execution exposed a transport defect: publishing a callback copied
unchanged header fields back while Wine was updating private queue links. Some
completion callbacks were consequently lost. A small local provider-interleaving
case reproduces the overwrite before the fix. The shared MDS transport now keeps
field baselines separate from observation snapshots and publishes only actual
C changes. The local case and normal execution both pass afterward. No change
to the authored lifecycle C was needed. This field-preservation rule is documented
in the general [component workflow](component-workflow.md); it does not replace
synchronization for conflicting writes to the same field.

Normal execution matches all 64 frames, all 42 preceding observation fields,
the added lifecycle observations and all 766 platform interactions. It reaches
one start, stop and release plus 27 callback entries, including 25 returned
buffers. The final comparison compiles one affected translation unit and reuses
94 objects. Every Wine application runs under the headless Wayland desktop.

Both exported architectures pass 278 affected consumer cases. The source project
now has 44 components, 164 entries and 1,046 retained cases. All 43 preceding
component implementations remain unchanged. Three old objects change: the shared
MIDI backend and the parser/loader consumer transports. The other 138 objects and
44 unaffected consumer binaries retain their exact contents. The six consumers
linked to the changed backend are rebuilt and checked. Evidence references for
the loader/parser/expander bind their new consumer; their implementations are reused.

The [fixture README](../tests/fixtures/dxball-mds-stream/README.md) contains the
public prepare/check/edit/apply/normal workflow. Evidence is retained under
`build/dxball-mds-stream-2026-09-29/`, including the original transport failure,
local reproduction, corrected comparison, defect replay, both export receipts,
independent backend consumers, phase timings and preservation audit. Repository
metadata, production Python lint, format registry and shared MIDI/storage Nix
checks pass. This remains practical experimental evidence, not a universal heap,
concurrency or whole-program equivalence proof.

The next task is to inventory remaining native runtime and platform calls and
move the connected source selection toward a standalone normal-entry program.
Completing MDS does not supply production portable Win32/DirectDraw/DirectSound/
MIDI backends or finish the full game. The full DX-Ball lifting goal stays active.
