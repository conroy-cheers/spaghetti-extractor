# DX-Ball title scene continuation — 2026-09-27

The [title-scene component](../tests/fixtures/dxball-title-scene/README.md) lifts
the real enter, redraw, update, key and leave functions. The C coordinates existing
animation, font, sprite, image, palette and frame components through their shared
objects and ordinary adapters. Binary disassembly and data are the authority;
no original DX-Ball source, checker changes or new proof machinery were needed.

All twelve native comparisons match. They retain nested redraw during scene entry,
post-callback state reads, palette rotation storage, exact display byte spans,
signed mouse clamping and conditional cleanup. The source-side original bodies
are trapped. Local platform services are explicit controlled boundaries, with
owned pixel backing and observations of state, palettes, pixels and interactions.
Actual file, audio and DirectDraw behavior is exercised separately in the game.

Normal title/menu/gameplay/close execution matches with all five scene operations
selected: enter once, redraw once, update four times, key once and leave once.
All eight scene records match, including pixel and palette hashes and shared state.
The thirteen existing animation records, five image records and frame/sprite/font
observations remain in place. Untouched original, observed original and selected
C all exit zero. The same external controller supplies counted inputs on each
side; Wine diagnostics are retained separately from application output.

The public apply transaction produces a twelve-component source project replacing
35 native entries. Its eight build/integration commands pass, covering 119 cases.
A clean source build and all 119 cases also pass on AArch64 under QEMU; executable
ELF headers identify AArch64. All eleven prior component implementations and
interfaces are unchanged. Of 28 prior active objects, 27 retain identical bytes;
the reusable animation consumer rebuilds to allow library inclusion and six owned
surfaces. Three objects are added for the new component, bridge and consumer.

The local adapter initially collided with Windows' `CALLBACK` macro. Renaming
that fixture macro allowed two already compiled units to be reused. The live
handoff initially attempted to combine the controlled animation contract with its
live counterpart. The resolver rejected those inconsistent selections. Using the
existing named requirement-refinement API explicitly selects the live consumer
and its assumptions. This required ordinary preparation changes, not a special
case in the tooling.

Measured matching-local costs are preparation 0.216s, compilation 0.647s, link
0.064s, Wine startup 5.170s wall time and 24 executions 5.036s. The live check
compiles 25 units in 0.966s, links in 0.064s, builds the capture launcher in 0.214s
and spends 31.496s on three executions. The clean AArch64 build and all cases take
53.398s. Manual boundary analysis and adapter authoring are separate from these
command timings. Model/solver work is zero; no pilot rebuild was performed.

The delivered source project still uses controlled platform consumers. Other
scenes/gameplay, startup and portable graphics/audio/window backends remain to be
lifted before it becomes a complete portable game. The live observer assumes
quiescent eight-bit surfaces when taking extra read locks; these finite hashes
and workloads do not establish arbitrary playthrough or audio equivalence.
No significant tooling limitation was found. The full DX-Ball goal stays active.

Evidence root: `build/dxball-title-scene-2026-09-27/`.

- `prepared/`, `check-2/`: public authoring and twelve matching native cases.
- `check/`: retained initial compile failure and eligible objects.
- `normal-prepared-3/`, `normal-check/`: reviewed live selection and matching game run.
- `program.apply-5i5skrko/`, `program/`: successful apply and eight integration commands.
- `arm-program/`, `arm-build.log`, `arm-check.log`: clean source build and 119 AArch64 cases.
- `reuse.json`, `validation.json`, `tree-audit.json`: reuse, validation and preservation evidence.

All Wine execution uses headless Wayland. Repository metadata, production Python
lint and format-registry checks accompany this continuation. The full repository
suite and strong qualification are not claimed.
