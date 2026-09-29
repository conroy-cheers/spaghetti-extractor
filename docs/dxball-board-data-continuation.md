# DX-Ball board-data continuation — 2026-09-28

The [board-data component](../tests/fixtures/dxball-board-data/README.md) lifts
five actual entries: load/save the board collection, select/store the current
board, and map tile kinds to sprite IDs. The scene previously described as
“options” is the built-in board editor. Its native callers establish a useful
boundary shared with gameplay: a current 20-by-20 byte grid, fifty saved boards,
and synchronous file services. The editor UI remains to be lifted.

The C uses ordinary arrays, `memcpy` and a small constant mapping table derived
from the executable's jump table and return instructions. It preserves all tile
bytes, unsigned default mapping, short-read suffixes, short-write prefixes, failed
opens and the shared last-file identity after close. It does not reconstruct file
contents or stream lifetime from a pointer. Copy indices are explicitly in 0..49;
out-of-range native memory corruption is outside this boundary. Only executable
instructions/data and retained assets were consulted, without original source or
third-party implementations.

All fourteen native cases match, exercising every new entry with complete
current/saved/disk bytes, frame canaries, handle state and service order retained.
The initial adapter used a nonexistent observation helper; correcting it compiled
one unit and reused the two others. No behavioral edit to the lifted C was needed.
The normal adapter reuses the existing score-screen consumer through a library
guard. These changes require no checker, compiler, artifact or proof machinery.

The public apply extends the source project to sixteen components and 56 native
entries. All twelve supplied build/integration commands pass, covering 185 cases
on x86-64. All fifteen previous implementation, interface and contract identities,
all 158 prior component files, and all 40 prior active compiled objects remain
unchanged. Three new objects implement the component and its consumer. The
project builds from source without the lifting tools or original executable;
it remains a collection of connected subsystem consumers rather than a complete
portable game.

The clean AArch64 source build also passes all 185 cases through eleven consumer
executables, each identified as AArch64 by its ELF header. The previously used
compiler had disappeared from the local Nix store; it was restored from the
project's pinned Nixpkgs cache. The first failed build and its diagnostic remain
retained; the successful build starts from a fresh source copy. Building takes
52.957s and the eleven check suites take 52.721s.

Normal title/menu/initial gameplay/close execution matches with the complete
sixteen-component selection installed. Plain, original and source all exit zero.
The new C loader and selector execute once each, with both full 20,400-byte board
snapshots matching the native run. Save, store and sprite mapping are installed
but not executed by this workload. Their evidence remains the local cases;
live editor interaction is still outstanding. Wine/host diagnostics remain
separate from application output.

Preparation takes 0.362s. After the adapter fix, compilation is 0.215s, linking
0.064s, Wine startup 3.719s wall time, and 28 native executions 3.205s. The public
source-project transaction takes 6.856s including all twelve commands. Manual
boundary analysis and C authoring are separate costs. No model/solver work or
large pilot rebuild is involved.

Next, lift the editor scene against these board operations and the existing
scene/font/graphics objects. Its seven remaining entries handle initialization,
redraw, update, keys, palette/status rendering and exit. Native hit-region helpers
and board/cell rendering still need ordinary reusable boundaries. A counted
Ctrl+F1 menu route can then exercise actual editor interactions. Remaining
gameplay, live score entry, startup and portable platform backends also remain;
the full DX-Ball goal stays active. No significant tooling limitation was found.

Evidence root: `build/dxball-editor-2026-09-27/` (created before local midnight).

- `editor.txt`, `regions.txt`: native disassembly and caller analysis.
- `board-prepared-2/`, `board-check-2/`: public preparation and fourteen matching
  native cases; `board-check/` retains the initial adapter compile failure.
- `program.apply-z9u1xvs5/`, `program/`: successful public apply and twelve checks.
- `reuse.json`: unchanged neighboring identities, files and compiled objects.
- `normal-prepared/`, `normal-check/`: actual CRT/assets and the matching normal
  workload, including selected-entry counts and complete board backing.
- `arm-program-2/`, `arm-validation.json`, `arm-build-2.log`, `arm-check-2.log`:
  clean AArch64 build and all 185 cases; `arm.log` retains the missing-toolchain
  failure.
- `validation.json`, `tree-audit.json`: completed checks and preservation of
  unrelated worktree changes.

Repository metadata, production Python lint, format registry and whitespace
checks pass. All Wine executions use headless Wayland. These finite practical
checks do not claim strong qualification, the full repository suite or a complete
portable DX-Ball.
