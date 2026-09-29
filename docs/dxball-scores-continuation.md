# DX-Ball persistent score-table continuation — 2026-09-27

The [score-table component](../tests/fixtures/dxball-scores/README.md) lifts the
three real initialization, load and insertion entries. Its ordinary C uses named
records, a fixed little-endian file representation and explicit file services.
The table boundary is independent of score-screen rendering and input. All 660
record bytes remain observable, including bytes after name terminators. Only
binary instructions/data and the retained `score.dat` were used; no original
game source or third-party implementation was consulted.

Twenty native cases match. They cover initialization, failed opens, short reads
and writes, access results, equal and unsigned scores, rejected scores, insertion
into an unsorted table, empty/maximum-length names and the real retained file.
Names move only through their NUL; destination padding stays unchanged. Insertion
reloads first and inserts before equal scores. Initialization creates a file only
for access result exactly -1; insertion saves only for zero. Closed file identity
remains in shared state, with no right to read closed storage. Local observations
retain byte backing, file contents, handle state and service ordering; source-side
native bodies are trapped.

The first native run matched nineteen cases. The last case's test name was one
byte longer than its stated bound. Correcting the input rebuilt one adapter unit
and reused the two implementation/bridge objects. The C implementation itself
needed no behavioral correction. The live adapter required the existing scene
type headers as explicit inputs and a macro parameter rename; these were ordinary
C/preparation fixes, not changes to checker, compiler or artifact machinery.

Normal title/menu/gameplay/close execution also matches. Startup selects the C
initializer and loader once each, retaining two complete score-table records
alongside all existing scene, graphics and lifecycle observations. The real CRT
and retained score file supply this consumer's file services. All three runs exit
zero; different Wine/host warning counts remain in separate diagnostic streams.
This workload does not select insertion or exercise new-score entry/save.

The public apply transaction extends the source project to fourteen components
implementing 45 native entries. All ten build/integration commands pass, covering
151 cases on x86-64. A clean source build and all 151 cases also pass on AArch64
under QEMU, with all nine executable ELF headers identifying AArch64. All thirteen
prior component implementations/interfaces remain identical, as do all 34 prior
active compiled objects. Three objects are added for the table body, bridge and
consumer. Source consumers compile without lifting tools or the original binary.

Measured local correction costs are preparation 0.022s, compilation 0.165s,
link 0.064s, Wine startup 5.570s wall time and forty executions 2.862s. The clean
AArch64 build takes 38.100s and its nine consumer suites 33.472s. Manual boundary
analysis and adapter authoring are separate from those timings. No model/solver
work or pilot rebuild was required.

The score screen, options, gameplay, startup and portable platform backends still
need lifting. New-score entry/save must also be exercised through the score-screen
consumer. The local file backend is controlled; finite cases do not establish
behavior for arbitrary corrupt files or nonterminated names. No significant
tooling limitation was found. The full DX-Ball goal remains active.

Evidence root: `build/dxball-scores-2026-09-27/`.

- `scores-*.txt`: retained binary disassembly.
- `prepared-4/`, `check-2/`: public authoring package and twenty matching native cases.
- `check/`: the original overlong test input and nineteen matching cases.
- `normal-prepared-3/`, `normal-check-3/`: matching actual startup and existing
  title/menu/gameplay/close consumer, with separate application and host streams.
- `program.apply-5dc2_scu/`, `program/`: successful apply and ten integration commands.
- `arm-program/`, `arm-build.log`, `arm-check.log`, `arm-validation.json`: clean
  source build and all 151 cases on AArch64.
- `reuse.json`: unchanged prior component files and compiled objects.

All Wine execution uses headless Wayland. Strong qualification and the full
repository suite are not claimed by these finite checks.
