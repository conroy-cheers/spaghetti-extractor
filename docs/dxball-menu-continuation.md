# DX-Ball main menu continuation — 2026-09-27

The [main-menu component](../tests/fixtures/dxball-menu/README.md) replaces seven
actual native entries with ordinary C: enter, redraw, update, key, leave,
initialize dots and animate. The leave entry is shared by two scenes and is
implemented once. The existing scene, animation, font, palette and frame objects
carry the neighboring state; the menu adds dot/offset arrays and explicit clock
services. Literal display spans and the dot mask come from the executable.
No original DX-Ball source or third-party implementation was consulted.

All twelve local native comparisons match. They cover exact text spans, unsigned
score formatting, presentation modes, signed mouse coordinates, key low-byte
behavior, conditional cleanup, clock branches and wrap, lock retry, palette
updates and pixel writes. All seven source-side native bodies are trapped.
Existing fonts, drawing and cleanup compose through their current interfaces.
Platform calls use a controlled backend with real owned pixel storage; actual
file, audio and DirectDraw integration is checked separately in the game.

The normal game comparison matches with all thirteen components selected. Menu
enter, nested redraw, two updates and leave execute in C. Four outer menu records
retain dot and offset hashes, pixels, palettes and shared state. Existing frame,
image, title, lifecycle, font and graphics observations remain and match. All
three processes exit zero after the same counted title/menu/gameplay/close input
sequence. Absolute clock readings are explicit external inputs and remain in
diagnostics; their resulting state and pixel effects are compared. Key handling
and zero-reason leave are exercised locally rather than in this live workload.
The C animation helpers are ordinary calls inside the enclosing operations;
their local checks exercise the separate native entries as well.

The public `candidate apply` transaction produces a thirteen-component source
project implementing 42 native entries. All nine supplied build/integration
commands pass, covering 131 cases on x86-64. A clean AArch64 source build and
all 131 cases also pass under QEMU; all eight executable ELF headers identify
AArch64. All twelve prior component
implementations and interfaces remain byte-identical. Of 31 prior active objects,
29 retain identical bytes; the reusable title and scene consumers rebuild to
support menu inclusion and transparent sprite blits. Three new objects contain
the menu body, bridge and consumer.

Two ordinary adapter issues were found. The controlled graphics backend first
accepted only opaque blits; the menu needs the existing transparent-blit flag,
implemented with its declared zero color key. The first standalone apply then
caught an old cleanup guard at `433d14`: the larger boundary identifies that word
as the final menu offset, not independent guard storage. The consumer now retains
the alias value, checks native correspondence and preserves the three independent
guards. The corrected local recheck rebuilds one unit and reuses eighteen. No
checker, compiler, artifact or proof-engine changes were needed.

The live handoff uses the existing named requirement-refinement API to select
the actual scene consumer. Ordinary C wrappers transport menu state around
shared scene services, including reentrant redraw. The original counted-input
controller is unchanged. This is manual boundary and adapter work within the
documented workflow, with no new tooling limitation found.

Measured local correction costs are preparation 0.320s, compilation 0.315s,
link 0.064s, Wine startup 5.428s wall time and 24 executions 5.180s. The live
comparison compiles 27 units in 1.081s, links in 0.064s, builds output capture in
0.214s and spends 32.097s on three executions. Clean AArch64 compilation takes
35.646s and all eight consumer suites take 33.239s. Manual binary analysis and adapter
authoring are separate from these command timings. Model/solver work is zero;
no pilot rebuild was performed.

The exported project still consists of portable subsystem consumers with
controlled backends. Other scenes, gameplay, startup and portable graphics/audio/
window backends remain before it becomes a complete portable game. The bounded
live observations assume quiescent eight-bit surfaces for extra read locks and
do not establish arbitrary playthrough or audio equivalence. The full DX-Ball
translation goal remains active.

Evidence root: `build/dxball-menu-2026-09-27/`.

- `prepared-3/`, `check-3/`: public package and twelve matching native cases.
- `check/`, `check-2/`: initial graphics diagnostic and the first matching native run.
- `program.apply-9xm83rje/*-check.log`: initial standalone alias diagnostic.
- `program.apply-3cahd54w/`, `program/`: successful apply and nine integration commands.
- `normal-prepared/`, `normal-check/`: reviewed live selection and matching game run.
- `arm-program/`, `arm-build.log`, `arm-check.log`, `arm-validation.json`: clean
  AArch64 build and all 131 cases.
- `reuse.json`, `validation.json`, `tree-audit.json`: neighboring component reuse,
  validation and preservation of unrelated work.

Every Wine application runs in headless Wayland. Repository metadata, production
Python lint, format-registry and whitespace checks pass. Strong qualification and
the full repository suite are not claimed by these finite checks.
