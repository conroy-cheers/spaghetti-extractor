# DX-Ball MDS event continuation

The MDS event expander is now 39 lines of portable C in
[`events.c`](../tests/fixtures/dxball-mds-events/events.c). It replaces the complete
machine body at `0x401d60..0x401e33`, a loop called by the MDS parser. All six
bundled music files use this compact-event format. No original application source
was consulted; the implementation follows the pinned PE32 instructions and binary
asset contents.

The [boundary](../tests/fixtures/dxball-mds-events/BOUNDARY.md) has two ordinary
byte-backed descriptors. It exposes input size, output capacity and historical
bytes-used state. Expansion inserts the stream field and preserves long-event
padding. Failure can leave partial output writes while leaving bytes-used
unchanged. It needs no surrounding game state, allocation or platform service.
The remainder of the MDS library retains its own boundaries.

All 34 local cases match the first C unchanged: 29 synthetic/generated calls and
188 blocks from the six bundled files, for 217 calls altogether. The observations
include complete source/destination regions, guards, descriptor fields and the
otherwise unused native header fields. Short/truncated buffers, unaligned data,
long payload padding, ignored input capacity and a success followed by a partial
failure are covered. A deliberately wrong inserted stream field is caught by a
single local replay, before game execution.

Both x86-64 and emulated AArch64 source consumers pass these cases. The source
selection contains 41 components, 157 entries and 914 retained cases. All 40 prior
component records, 132 objects and 47 consumer binaries remain identical on each
architecture after `candidate apply`; this does not requalify the whole game from
one unit's local evidence.

Normal execution selects the new body 25 times through the actual native MDS
parser. Original and selected programs match all 64 frames, all 39 preceding
observation fields and the added expansion-call observations. The shared Wine
backend continues to compare all 766 platform interactions and complete queued
buffer bytes. No end-to-end behavioral correction to the C was needed.

The integration recipe uses the existing `program_entry_packages` facility to
add the unit to the retained program selection. The enclosing `music-control`
comparison keeps its identity; the new unit has its own independent local
comparison. This retains 84 compiled objects and compiles five new/affected
translation units in the program check. Trying to use a different component's
receipt as the local refinement baseline is rejected; it is unnecessary when
adding an independent program entry. No checker, compiler, artifact format or
shared platform extension was needed for this lift.

Reproduction commands are in the [fixture README](../tests/fixtures/dxball-mds-events/README.md).
Evidence is retained under `build/dxball-mds-events-2026-09-29/`, including the local
comparison, defect replay, normal program comparison, both source-export receipts,
phase timings and dirty-tree preservation audit in `validation.json`. Repository
metadata, production Python lint and format-registry Nix checks pass. All 2,963
unrelated baseline files remain unchanged; no commit was made.

The MDS container parser at `0x401b60`, file/memory loader at `0x401a20`, release
at `0x401e40`, stream start/pause/stop and completion callback remain to be lifted.
The parser is the next connected consumer: it should use the checked event unit
and shared allocation services, preserving header history and cleanup behavior.
Its format fields, allocation ownership and buffer collection need an explicit
shared object boundary. The shared Wine backend already supplies the mapped
storage, allocation and queued MIDI surface. A production portable platform
backend and a complete standalone game also remain outstanding. The full DX-Ball
lifting goal remains active.
