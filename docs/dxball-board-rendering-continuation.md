# DX-Ball board-rendering continuation — 2026-09-28

The full-board loop and cell renderer are now ordinary C in
[`tests/fixtures/dxball-board-rendering/`](../tests/fixtures/dxball-board-rendering/README.md).
They borrow the existing board/menu/scene/font objects and graphics services.
Tile 0 copies the background; tile 7 does so only in gameplay scene 1. Unknown
bytes leave pixels alone but still record damage in mode zero. The full loop
selects its destination once, visits columns before rows and rereads shared state
for each cell. No new tool internals or original game source were needed.

Eight local native scenarios match. Every case drives all 256 byte values through
a cell, alongside full-board drawing. They cover damage modes, aliased surfaces,
callback changes to grid/scene/destination state, a mutated local rectangle and
the retained board file. Full board and pixel storage, object state and ordered
graphics/damage calls compare without requiring normal game execution.

The first native check matched, but portable source assembly found a discrepancy
at `$.objects.guards[0]`. The initial fixture gave different values to two views of
one native word: the last menu offset also precedes the sprite table. Native
transport reconciled those values on both native sides, while the standalone C
consumer exposed their inconsistency. Initializing both views consistently fixes
the fixture. The renderer C is unchanged. The failed public apply retains its
proposal and leaves the previous project intact. The corrected native comparison
recompiles one adapter and reuses twenty units. This error was caught locally,
before normal game integration; it remains a regression in the source check.

The expanded source project contains eighteen components and 65 native entries.
All seventeen neighboring implementation/interface/contract identities remain
unchanged. The shared controlled graphics recorder gains a configurable capacity,
retaining its previous default. This recompiles five old test-consumer objects;
41 old objects remain byte-identical and three objects are added. All 209 x86-64
source-consumer cases pass. Successful apply/build/check takes 9.658s. A clean
AArch64 build also passes all 209 cases through QEMU; all thirteen consumers have
AArch64 ELF headers. Its build takes 59.019s and checks 74.133s.

The normal eighteen-component network also matches. Plain, instrumented original
and selected C all exit zero through the real editor clear/save/close workload.
The C renderer executes two full-board operations; internal cell calls remain
ordinary C calls. Two outer renderer records retain scene/mode, full board bytes
and destination/back surface and palette hashes. Existing editor/board/graphics
observations remain in the result. All sides save the same 20,000-byte
`Default.bds`, clearing the first board and preserving the other 49. No authored
C correction was needed after this full application run.

The corrected local comparison records 0.334s preparation, 0.264s compilation,
0.064s link, 4.062s Wine startup wall time and 3.150s across sixteen executions.
The live comparison records 0.781s preparation, 1.130s compilation (25 compiled,
12 reused), 0.064s link, 45.351s startup wall time and 28.189s across three
executions; its output-capture launcher compiles in 0.214s. Model/solver work is
zero. Manual preparation is separate, and no large pilot rebuild is involved.

Evidence root: `build/dxball-board-rendering-2026-09-28/`.

- `prepared-2/`, `check-2/`: corrected local boundary and eight matching cases.
- `check/`, `program.apply-xt1oofze/`, `source-difference.json`: initial fixture
  mismatch and rejected portable apply.
- `program/`, `program.apply-iz1282tm/`, `apply-2-time.json`: successful assembly
  and all fourteen build/check commands.
- `prior-export.json`, `prior-files.json`, `reuse.json`: unchanged neighboring
  identities and compiled-object reuse.
- `normal-prepared/`, `normal-check/`: reviewed live boundary, matching receipt,
  renderer observations, exact saved files and separate application/host logs.
- `arm-program/`, `arm-validation.json`, `arm-build.log`, `arm-check.log`: clean
  second-architecture build and execution.
- `validation.json`, `tree-audit.json`, `nix-checks.log`: evidence revalidation,
  repository checks and preservation of unrelated dirty-tree work.

Region, cursor and damage helpers, remaining gameplay, startup and portable
platform backends remain open. These finite checks do not establish a complete
portable game or strong qualification. All Wine executions use headless Wayland;
the full DX-Ball lifting goal remains active.
