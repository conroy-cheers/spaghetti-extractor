# DX-Ball capture and restoration continuation — 2026-09-27

The binary-derived sprite lifecycle component adds capture (`be10`) and bank
restoration (`bd00`). It reuses the existing sprite layout, allocation, graphics,
file, loader, font and cleanup boundaries. The [public recipe](../tests/fixtures/dxball-sprite-lifecycle/README.md)
and [manual contract](../tests/fixtures/dxball-sprite-lifecycle/BOUNDARY.md) record
the inputs and limitations. No original DX-Ball source or third-party
implementation was consulted, and no tool internals changed.

All sixteen connected native cases match. Capture preserves creation errors and
partial state, retries surface description, transports the aliased destination
rectangle and retains the graphics result. Restoration visits the final slot,
skips null objects/surfaces, tests mode exactly against one, ignores restore errors
and reloads two real asset banks through the existing C loader. Observations cover
shared bytes, pixels, service ordering, allocation/lifetime records and subsequent
font use and cleanup. Original entry bodies are trapped on the source side.

The checked `candidate apply` transaction extends the existing project to eight
components implementing fifteen native entries. All seven prior component C
implementations and interfaces remain unchanged. Fifteen of sixteen active
compiled objects are reused; the reusable asset consumer is rebuilt to support
reopening files, alongside the new operation, bridge and consumer. All 37
retained cases pass on x86-64 and a clean AArch64 build under QEMU. These are
portable subsystem consumers with a controlled graphics backend, not the complete
game.

The first apply attempt correctly withheld publication when the standalone
consumer exposed an inconsistent initial file-state observation in the new
adapter. The corrected native check recompiles two units and reuses thirteen;
its six neighboring unit inputs are unchanged. The successful apply runs the
build and all three workloads before replacing the project.

Live execution now has ordinary C adapters for actual native allocation, file
I/O and DirectDraw, with all eight components selected. The first normal-game
run exercised the C loader five times and matched all five bank-load observations
and 32 metric calls. It was not a passing integration result: graphics surface
identifiers depended on internal transport view discovery, and the old timed
input controller closed before exercising capture/restoration. Observation IDs
now follow externally observed destination selection, preserving handle equality.
The external controller now waits for splash/menu readiness and the game
transition, using window messages and read-only process inspection. An isolated
untouched-original probe confirms game initialization and sprite capture. Earlier
attempts retained readiness failures; their receipts remain incomplete.

The latest connected run (`normal-check-6/`) reaches gameplay on all three sides
and exits zero. The source selects the loader seven times and capture once,
alongside drawing, fonts and cleanup. Seven bank-load records, the capture record
(including its successful result and 160-byte pitch), and 32 metric observations
match. Restoration is selected but does not execute in this live workload; its
evidence remains the local native cases.

The overall live receipt is still **mismatch**: the source draws an additional
`E` at `(600,470)` in the splash animation before reaching the menu. Binary review
locates this at `a780`, which advances a scrolling character according to splash
update calls; the controller delivers external input at different update points.
This is consistent with execution/input timing differences, not evidence of an
incorrect capture or loader result. It has not been filtered out or recast as a
passing game comparison. The next integration work needs a defined frame/input
boundary so corresponding observations refer to corresponding game updates.
No new checker/compiler/artifact limitation was encountered in authoring or
applying these components; whole-game behavioral assurance remains open.

Evidence root: `build/dxball-capture-continuation-2026-09-27/`.

- `prepared-2/`, `check-2/`: public package and sixteen matching native cases.
- `program.apply-bn20vd1e/`: rejected first transaction and its mismatch.
- `program.apply-9syd61w2/`, `program/`: successful transaction and resulting source project.
- `arm-program/`, `arm-build.log`, `arm-check.log`: clean source build and all 37 cases on AArch64.
- `normal-prepared*/`, `normal-check*/`: retained live adapters, controller investigations and exact classifications.
- `scene-probe-1/`: bounded untouched-original game-entry/capture probe.
- `reuse.json`, `validation.json`, `tree-audit.json`: reuse, final evidence and preservation of unrelated work.

All Wine execution uses headless Wayland. No pilot rebuild or proof campaign is
involved. Allocation exhaustion and permanently failing services remain outside
these finite cases; complete frame/audio comparison and whole-game portability
are not established. The DX-Ball translation goal remains active.
