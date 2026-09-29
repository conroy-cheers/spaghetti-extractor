# DX-Ball brick rules and effects — 2026-09-28

The [brick component](../tests/fixtures/dxball-brick-actions/README.md) lifts eight
native entries into 188 lines of C: board reset, brick hit, effect iteration,
blast creation/step, event queuing and flash creation/step. It borrows the existing
board, pending-cell storage, motion flags, event list and counters. Effects have
explicit payloads, links and allocation/free identities; adapters reconcile those
views with the frame's existing opaque references. Authoring used executable
instructions/data and established interfaces, without original game source or
changes to tool internals.

Twenty-one local native scenarios match. They cover all tile kinds, invalid tile
bytes, piercing, particles, board/cursor mutations during callbacks, queued
neighbors, delayed animation, unlink/free order and generated sequences. Full
initialized payloads, preserved allocation bytes, links, board/pending bytes and
ordered service effects are observed. Four connected cases also match: twelve
actual gameplay frames call actual motion and brick operations over the same
objects, including collisions, blast propagation, allocation and disposal.
Neither comparison needs game startup or a graphics backend.

The first authored C passed those comparisons. The AArch64 compiler subsequently
rejected wrapped signed neighbor tests with an array-bounds warning. Rewriting
them as ordinary grid bounds preserves behavior within the already documented
0..19 coordinate domain and compiles cleanly. All local and connected comparisons
pass again, recompiling only the brick implementation and reusing the other
units. This was a portable compilation issue; end-to-end feedback required no
behavioral correction to the authored C.

The source project now has twenty-three components, 95 native entries and
cumulative coverage of 313 source-consumer cases on x86-64 and emulated AArch64.
This continuation runs the new 21 direct and four connected cases on each
architecture; unaffected consumer evidence is reused. All twenty-two neighboring
component records and all 62 prior compiled objects remain unchanged. The archive
update relinks consumers, with all eighteen preceding consumer binaries still
byte-identical. Public `candidate apply` stages and validates the project before
publication; the failed ARM preparation remains available separately.

## Integration findings remain locally diagnosable

The first 64-frame game comparison differed when a brick hit called the native
pickup generator, historically named `debris` in the interface. Its clock-seeded
random generator gave separate runs different pickup outcomes. A retained small
consumer now executes that actual helper and native CRT generator under either
brick implementation at the observed collision coordinates and velocity. Seeds
1 and 2 cover pickup/no-pickup in both particle modes: four matches. A deliberately
unequal seed is diagnosed locally at the random result, original 1 versus source
5, before the changed allocation and particles. No game startup is needed.

After equalizing the seed, a palette observation still differed because the
frame crossed its palette clock deadline on different iterations. A second small
consumer invokes the actual native elapsed and palette-cycle helpers under the
original or C frame. Four cases cover immediately before and at both paused and
running deadlines. They compare complete palette bytes and `SetEntries` effects
through a local palette object. A deliberate one-tick difference is diagnosed
locally as 131 versus 132 and changes whether palette cycling occurs.

The normal comparison now supplies explicit inputs at those environment
boundaries: clock 1 during native random initialization, and
`0xf0000000 + frame * 16` for the frame's palette elapsed/now operations. Native
initialization, random generation, elapsed logic and palette mutation bodies
remain active. The preceding paddle schedule remains; other helper clocks and
delay loops retain their inputs. Supplied values are recorded, and palette,
pixel, memory and interaction observations remain compared.

All three processes exit zero and the final normal comparison matches. The C
brick reset and hit run once each, and advance runs 64 times. There are 66 outer
brick records, 65 motion records, 64 gameplay snapshots, 870 damage records with
none dropped, five rendering records, 140 paddle inputs and 96 palette clock
inputs. The untouched original controls startup, output and exit; it does not
claim equality of pixels produced with uncontrolled environmental inputs.

These two reductions use the existing public comparison workflow and ordinary
adapters. They are native helper comparisons, additional to the 313 portable
source-consumer cases. End-to-end tests must not become the sole diagnostic route
for a supported behavior: preserve each finding as an independently executable
component, boundary or small connected regression. Missing inputs are coverage
gaps; inability to express state, interactions or observations locally is a
tooling gap. Finite comparisons cannot guarantee discovery of every unseen bug.

## Evidence, costs and remaining work

Evidence is retained in `build/dxball-brick-actions-2026-09-28/`:

- `actions.asm`, `debris.asm`, `authored-first.json`, `check-2/` and
  `connected-check/` retain binary-derived authoring and first-draft matches.
- `prepared-portable/`, `check-portable/` and `connected-portable-check/`
  contain the final grid-bound implementation and passing local comparisons.
- `pickup-portable-check/`, `pickup-unequal-portable-check/`, `palette-check/`
  and `palette-unequal-check/` retain the independent integration reductions.
- `normal-check/` and `normal-controlled-check/` retain the two discovered
  discrepancies. `normal-final-prepared/` and `normal-final-check/` retain the
  explicit-input normal comparison.
- `program/` and `arm-program/` contain the portable projects. `validation.json`,
  `reuse.json`, `tree-audit.json` and the apply transactions record exact bindings,
  incremental reuse and preservation of unrelated dirty work.

Initial package preparation takes 0.444s, excluding manual analysis and adapter
authoring. The final local edit compiles one unit in 0.032s, links in 0.064s,
spends 3.974s in Wine startup wall time and 3.090s in 42 executions. The connected
edit compiles one unit in 0.032s, reuses six, links in 0.064s, starts Wine in
4.259s and executes eight runs in 1.066s. Final normal integration compiles two
units in 0.497s, reuses 45, links in 0.064s, spends 65.795s in startup and 42.610s
in three executions. The final source applies take 16.312s and 30.559s. All
comparisons perform zero model or solver work; startup remains variable.

The boundary admits successful allocations, finite acyclic lists, live objects
across callbacks and valid grid accesses. Uninitialized allocation bytes are
preserved, but the normal observer does not treat flash padding or the unused
blast tile word as deterministic outputs; initialized-byte preservation is
checked locally. Live observation retains 64 encountered addresses per object
kind, 128 outer brick/motion calls and 64 frames. It does not qualify every native
allocation reuse or callback lifetime. This is practical evidence, without strong
heap or composition qualification.

Repository metadata, production Python lint and format registry checks accompany
the fixture and documentation changes. All Wine runs use headless Wayland. The
project remains a portable subsystem project: remaining paddle, pickup, particle,
shot and scene lifecycle operations, startup and platform backends still need
lifting. No significant new tooling limitation was found; the full goal remains
active.
