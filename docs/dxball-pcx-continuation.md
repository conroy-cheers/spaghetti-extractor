# DX-Ball PCX continuation — 2026-09-27

The [PCX component](../tests/fixtures/dxball-pcx/README.md) lifts image decoding and
current/staged palette loading into ordinary C. It consumes real assets through
a buffered reader and writes live graphics storage. The reader preserves buffer
contents, cursor, count and lifetime through refill/seek/close. Graphics views
retain the native description across lock retries and end at unlock. This uses
existing component interfaces and C adapters; no compiler, checker or proof-engine
extension was needed. No original DX-Ball source was consulted.

All twenty native cases match. They include the five shipped images, clipping,
malformed/short inputs, zero-length runs, final-run overshoot, pre-lock descriptor
snapshots and writes through the palette callback. Complete pixel backing,
padding, guards, palettes, file consumption and ordered interactions are compared.
The native side executes the original three bodies; selected bodies are trapped
on the C side. The implementation keeps the binary's unusual inclusive decode
threshold and palette flag bytes rather than substituting a conventional decoder.

The public `candidate apply` transaction adds the component to the source project.
All 89 cases pass on x86-64 and in a clean AArch64 build under QEMU. All 22 prior
active objects are reused; the nine neighboring implementations and interfaces
are unchanged. The project now contains ten components implementing 26 native
entries. Its controlled portable consumers still do not constitute the full game.

A reopened public workspace catches a one-character decoder error: changing
`<= limit` to `< limit` reads one fewer byte and leaves a pixel unwritten.
The first diagnostic is `$.files[0][2]`, original 141 versus edited C 140.
Only one translation unit is compiled and two are reused. Restoring the condition
matches again. This demonstrates executable comparison reuse, not formal proof
qualification.

Normal execution passes with the decoder selected alongside the existing sprite
and control components. The same counted-input protocol drives all three sides
through splash, menu, gameplay and close; all exit zero. Four C image calls load
`intro.pcx`, `mainmenu.pcx`, `mbbkgrnd.pcx` and `bigbolt.pcx`, with an additional
staged-palette entry. All five image/palette records match, alongside fourteen
control, 32 metric, 128 graphics and eight lifecycle records. Current-palette
application is covered locally but is not exercised by this particular live path.

The live observer hashes visible pixels and palette bytes, taking one additional
surface read lock on each instrumented side. Its boundary explicitly assumes
quiescent eight-bit surfaces; hashes and the untouched-original output control
do not prove universal observer transparency or arbitrary pixel/audio equivalence.
The real application still supplies scene logic and native platform services.
Complete scene/gameplay lifting and portable platform backends remain work toward
the unchanged DX-Ball goal. No significant core tooling limitation was found.

Measured costs for the twenty-case check: preparation 0.031s, compiler 0.311s,
link 0.064s, Wine startup 5.42s wall time and forty executions 4.57s. Recipe
preparation takes 0.36s, excluding manual binary analysis and adapter authoring.
The live check compiles 21 units in 0.86s, links in 0.064s and spends 31.75s on its
three executions. The clean AArch64 build plus 89 checks takes 28.55s. These are
retained timings, not latency guarantees. Model and solver work are zero; no pilot
rebuild was required. A local Python import-name collision in the preparation
recipe was fixed without changing tooling.

Evidence: `build/dxball-pcx-2026-09-27/`.

- `prepared/`, `check/`: public authoring, pinned inputs and twenty native cases.
- `program.apply-wq0han04/`, `program/`: successful application and six integration commands.
- `arm-program/`, `arm-validation.json`: source-only AArch64 build and all five workloads.
- `normal-prepared/`, `normal-check/`: actual game integration, output capture and counted inputs.
- `edit/`, `edit-wrong/`, `edit-corrected/`: focused edit, meaningful difference and repair.
- `reuse.json`, `validation.json`, `tree-audit.json`: reuse, validation and unrelated-work preservation.

All Wine runs use headless Wayland. Repository metadata, production Python lint
and the format registry are checked separately; no full repository suite rerun
or strong qualification is claimed.
