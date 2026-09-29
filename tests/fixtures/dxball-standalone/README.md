# DX-Ball standalone assembly worklist

The current exported project contains source components and connected subsystem
consumers. Assembly also adds `make dxball.exe`: a normal WinMain executable built
from all 49 selected C components, owned program state and Win32 SDK bindings.
It runs from assets without loading the original executable. Its `all` target
still builds the subsystem consumers. Earlier mixed Wine comparisons retain
their meaning; the first whole-program runs are integration smoke evidence,
not complete behavior or portability qualification.

## Normal-entry Win32 program

The clean handoff's [Windows guide](WINDOWS.md) describes the standalone build,
runtime dependencies, bundled assets and local editing. A source-only archive is
retained at `build/dxball-program-scenes-windows-2026-09-29/dxball-windows-source.tar.gz`.
It builds with Make/MinGW-w64 outside the repository, without the original image
or workbench. Original embedded icon payloads are compiled through `windres`;
`WINDRES` defaults to the companion of the selected GCC and can be overridden.

Use a fresh source project for a different compiler; do not reuse ELF objects in
the PE32 build. Apply the assembly with the same `candidate apply` command below,
replacing the check commands with:

```sh
make -C PROJECT CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar dxball.exe
```

The target statically links the compiler runtime. The only DLL imports are
DirectDraw, DirectSound, GDI, kernel/CRT, user, NT and WinMM platform services.
The SDK adapter currently requires 32-bit pointers for the original message ABI;
this does not claim a complete 64-bit desktop backend. `program-seed.h` carries
reviewed immutable data spans, never executable code. Supply the packaged data
files beside the binary. Do not copy the original executable into that runtime.

Run through the generic [desktop workload driver](../wine-desktop/README.md)
inside `spaghetti-headless-wayland`. `DXBALL_PROGRAM_REPORT=program-report.json`
optionally records scene, gameplay state and entry counts. It is diagnostic
output, not a replacement for original-versus-source observations. The retained
public apply receipt builds the PE32 binary and executes the desktop workload.
Use `desktop-actions.txt` for the retained title/menu/play workload. It requests
an optional GDI capture and normal close; the report remains separate from app
streams. Normal program assembly omits service protocol logging using the shared
source-binding generator's `trace_services=False` option. Pass `--trace-services`
to `assemble.py` to enable it. Adapter calls, transport, outcome predicates and
failure diagnostics remain enabled. Separate program bridge objects preserve
the traced local consumers and their existing compiler recipes. The retained
14-second workload drops from 45,807,480 trace bytes to zero; gameplay still
executes, removes a brick and scores 10 points. These wall-clock runs do not
establish a throughput comparison. Required comparison observations remain traced.
Both candidates pass title/menu/input/close; source diagnostics confirm actual
gameplay frame execution, and the longer workload launches the ball and scores
after removing a brick. Hold a mouse button across a frame: back-to-back down
and up messages can be drained before the game samples its button state.

Use `desktop-paused-actions.txt` with `spaghetti-headless-wayland --capture` for
a compositor snapshot after entering gameplay and pressing P. The generic driver
captures either binary without hooks. The final pair's visible 640x480 game image
matches pixel-for-pixel. Earlier paused captures differ only within the eight
colours cycled by paused gameplay; these are wall-clock observations, not a
deterministic pixel-equivalence test. The full desktop images remain available.
The retained comparison region is an explicit operator choice in compositor
coordinates; Wine reports virtual client geometry that includes more than that
visible game image. Evidence: `build/dxball-program-observation-2026-09-29/`.

`desktop-editor-actions.txt` enters the editor with Ctrl+F1, clears/saves the
first board and navigates to the next board and back. `desktop-scores-actions.txt`
clears two boards through the editor before starting the game; normal progression
then enters the score screen and returns through the table to the menu. Use
`--capture` and private asset copies: these workloads intentionally save boards.
The original and C programs produce identical board/score files, three editor
images and both score images. The moving menu dots/ball differ in their wall-clock
captures. No component correction was needed; all five scenes now have normal
Windows execution evidence. See `build/dxball-program-scenes-windows-2026-09-29/`.

`win32-window.c`, `win32-draw.c`, `win32-sound.c` and `win32-midi.c` translate
component views into SDK calls. The platform sees actual COM identities. The
adapters preserve borrowed surface aliases, callback entry through
`dxball_program_event`, descriptor storage across retries, and info-owned MIDI
headers. `resource-files.c` supplies buffered PCX input and sprite/WAV/file-reader
storage; `reader-entry.c` invokes the existing C API with its program owner.
These are application boundary adapters, not a target-specific Wine emulator.

The SDK MIDI adapter imports a header once for both its C view and write baseline,
and publishes only fields the C changed. It carries private-field history from
the owned parser allocation rather than introducing another uninitialized SDK
header. The separate `program-midi-check.exe` target compiles the exact adapter
with the exported stream C and shared Wine backend:

```sh
make -C /tmp/dx-source CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar program-midi-check.exe
spaghetti-headless-wayland python /tmp/dx-source/program/check-midi.py \
  /tmp/dx-source/program-midi-check.exe /tmp/dx-midi-check \
  --compiler /path/to/i686-w64-mingw32-gcc --wine /path/to/wine --server /path/to/wineserver
```

The check script uses the installed workbench's existing process capture/session
helpers; the delivered game itself has no workbench runtime dependency. Seven
cases cover native completion/reset/requeue and controlled provider updates/open
failure without game startup. Failed native MIDI opening is a failure, not a
passing skip. Application streams and Wine diagnostics remain separate. Native
unprepare errors are retained, including the original ignored `STILLPLAYING`
result before successful close returns the buffers. The before/fixed queue-link
and flag reproductions are in `build/dxball-program-midi-2026-09-29/`.

`memory-bindings.c` retains wrapped original-address lookup across live board,
pending and saved-board arrays. Unknown addresses stop with a capability
diagnostic. The frame-history adapter reuses the reviewed predecessor and
descriptor projection; it does not infer valid storage from reconstructed
pointers. Failed DirectSound status and malformed WAV history still need explicit
bindings. MIDI callback/reset/requeue now have the finite assembly checks above;
arbitrary callback/failure lifetime correspondence, deterministic rendering
comparison and wider failure coverage remain outstanding. Black GDI
screenshots are retained separately from the new compositor observations.
The delivery target is the Windows source application; native non-Windows
porting is outside project scope. Existing cross-architecture subsystem checks
are retained evidence, not a requirement to provide another desktop runtime.

Evidence: `build/dxball-program-tracing-2026-09-29/validation.json` and
`build/dxball-program-platform-2026-09-29/validation.json`, the public
`win32-program.apply-*` receipt, `source-seat` / `original-seat`, and the retained
cursor-failure reproductions. Headless Weston now includes a virtual input seat;
without it Xwayland crashed on ordinary cursor warps. That shared environment fix
has an application-independent X11 regression.

## Portable state and subsystem checks

`audit.py PROJECT OUTPUT` uses the existing source-export loader, then performs a
relocatable link of every selected bridge and the component archive. Run the
project make first. `--ld` and `--nm` select another architecture's tools. It
reports linker collisions and unresolved symbols without manufacturing stubs.
Its service map comes from the exported binding references. Entry-observer hooks
and remaining runtime symbols are listed separately. The census includes all
exported entries and is not a whole-program reachability or equivalence proof.
A library with unresolved C service bindings is not an executable.

The assembly layer consists of `program-state.c`, startup/file bindings and
flow/scene/menu/screen/editor/gameplay/audio, MDS resource and library bindings. It uses the existing component types,
source bridges and C entry points.
`prepare-state.py` extracts only named initial data from the pinned executable;
the resulting source project has no runtime image dependency. Resource handles
and dynamic allocation lifetimes still belong to their respective owners.

Apply this layer to a copy of the current 49-component raster source project:

```sh
spaghetti-extractor candidate apply dxball --project /tmp/dx-source \
  --assembly-command 'python /path/to/repo/tests/fixtures/dxball-standalone/assemble.py {project} /path/to/DXBall.exe' \
  --check-command 'make -C {project} program-startup-check program-input-check program-ownership-check program-resources-check' \
  --check-command 'python /path/to/repo/tests/fixtures/dxball-standalone/check-startup.py {project} /path/to/normal-delivery' \
  --check-command 'python /path/to/repo/tests/fixtures/dxball-standalone/check-input.py {project}' \
  --check-command '{project}/program-ownership-check' \
  --check-command 'python /path/to/repo/tests/fixtures/dxball-standalone/check-resources.py {project} /path/to/normal-delivery/inputs/runtime'
```

This adapter-only application keeps the same selected component implementations;
no comparison or boundary-acceptance flags are needed. For AArch64, supply its
`CC`/`AR` to make, `--runner /path/to/qemu-aarch64` to the Python checks, and invoke
the ownership executable through that runner. The
script copies the retained score and board inputs into an isolated directory,
using the application's expected spelling for packaged asset filenames. It
compares complete startup storage against the normal native report, including
board selection observed through a different component view. It does not fake
missing platform calls or claim to execute WinMain. `program-startup-check` is
an assembly check, not the game's executable.

`make program-state` builds `libprogram-state.a`. Include it in the link census:

```sh
python tests/fixtures/dxball-standalone/audit.py /tmp/dx-source /tmp/dx-audit \
  --assembly-library /tmp/dx-source/libprogram-state.a
```

The preceding platform-independent library resolved 377 declared service symbols;
the remaining 143 are now connected by the normal-entry assembly. Gameplay,
allocation and audio composition added 194 connections to the preceding 157;
MDS resource assembly adds another 26. The
dispatch table preserves score leave's menu-leave target. Executed checks cover
scores, boards, numeric initialization, 24 retained menu/title key outcomes,
14 damage routes and real cleanup of 36 allocated nodes across two owners.
The new normal-entry run exercises scene dispatch, window events, clock, display
and palette connections. Explicit history operands must be bound
when checking native failures; zero initialization does not recover stack history.

Shell is the sole writer of control/shift, read by menu and score-screen views.
Scene dispatch refreshes those views. A backend must route every window callback
through `dxball_program_event`, which refreshes on entry and return, preserving
the shell's key-before-modifier-write order. Common forwarders need no snapshots:
their other state is shared C storage. Title remains the owner of primary/back
surface roots published to flow. Brick publishes its list roots to frame without
copying node payloads. Audio owns the device/primary objects; flow borrows primary
identity and tests device presence. This does not establish every resource or
heap lifetime relationship.

`menu-input.c` and `title-input.c` call the exported C API with an empty context
because those operations have no allowed services. `check-input.py` verifies
that premise, replays retained key outcomes with stale read views, and checks a
second owner is unaffected. It does not substitute a mock graphics/audio backend
or execute full event dispatch. `damage-bindings.c` likewise calls the existing
service-free mark/damage C entries. The two methods have identical signatures but
different page effects: menu/progress/power call mirrored damage; score/paddle/
particle/warning mark only the current page. The check catches the menu mapping
mistake found during assembly review.

`round-clear.c` calls the selected implementation's free-only clear path. Its
conservative interface also allows leave's other services, so this partial
consumer is bound to the checked implementation rather than assuming a narrower
contract. General service-using calls use existing bridges. No generated component
implementation or evidence record is edited to make assembly easier.

`library-bindings.c` supplies real typed malloc/free and neighbor calls. The
ownership check exercises progression -> round cleanup -> those frees over nine
list families; it preserves retained words and independent owners. Additional
host ASan/UBSan/leak checking passes; restoring the wrong menu route fails locally.
Neither experiment needs an original image at runtime or a mock graphics backend.

`mds-storage.c` owns typed info/header records and their event bytes. The existing
loader -> parser -> event expander chain runs with those allocations, using
`mds-files.c` for immutable asset input through ordinary stdio. A file and its
mapping retain their stream independently; mapped input is released after
parsing. `mds-bindings.c` connects music records to the loader and the existing
stream lifecycle entries. The loaded info retains its program owner for future
MIDI callbacks; each event buffer retains its info owner.

`check-resources.py` compares all six bundled MDS files in file and memory modes
with retained native loader observations: metadata, all used event bytes and
header relationships. File mode enters through the music adapter; memory mode
overwrites and frees the input before observing output. The 12 cases contain
376 buffers and 1,513,032 event bytes, counting each asset in both modes. They
pass on x86-64 and emulated AArch64 and under host ASan/UBSan/leak detection. The
existing startup, input and ownership checks also pass. No Wine pilot rebuild or
new workbench machinery is needed.

This file adapter supports immutable packaged assets with explicit filenames;
it is not a general Win32 sharing/mapping implementation. Backslashes are
translated to slashes, but filename case is not emulated. Overflowed native
allocation geometry stops with a diagnostic requiring explicit memory transport.
Malformed inputs, failed allocation/lifetime histories, untouched header/payload
bytes and MIDI device/callback execution are outside this assembly check. The
retained local component comparisons still describe those component behaviors;
they do not qualify a new allocator or platform backend automatically. Resource
cleanup here exercises storage services directly, not MIDI stream release.

The normal-entry bindings above now supply resource I/O, platform methods,
board/pending-cell services and last-brick frame history. Audio/WAV history
operands remain explicit owner fields, whose defaults do not prove native failure
equivalence. These subsystem checks still do not qualify the desktop backend.

Evidence: `build/dxball-program-resources-2026-09-29/validation.json`. No preceding
component implementation or record changes; all 161 preceding component/consumer
objects and 56 subsystem binaries remain identical on both architectures.

## Remaining application bodies

This is a reviewed worklist from the normal adapters and pinned disassembly,
not a claim that every function reachable from every original entry is listed.
Original image SHA-256:
`191c113582e1f31016a158d40372fa21ea68d9348bf847bbfbc8e7c7bdfe195f`.

| Work | Original entry points | Consumers / assembly consequence |
| --- | --- | --- |
| Palette fade, shifts, sequence rotation, RGB update | `402770`, `402a50`, `402af0`, `402ba0`, `402c10` | Now provided by `palette-effects`; title, menu, gameplay, progression and cleanup share the existing palette objects. |
| Initial palette creation | `4022b0` | Now provided by `application-bootstrap`: initializes RGB while retaining flag bytes, creates the palette, conditionally attaches it. |
| First-frame initialization | `40ad10` | Now provided by `application-bootstrap`: overlay publication, scores/boards services, scene state, seeding, palette setup and refresh measurement. Clock/random bodies are provided by `runtime-support`. |
| Full-surface clear | `402710` | Now provided by `application-bootstrap`: exact rectangle, descriptor fields and full-width color, through the existing surface boundary. |
| Timing and refresh waits | `40db20`, `40db80`, `40dba0`, `402240` | Now provided by `runtime-support`: low-word counters, fallback, explicit scratch history, wrapping comparisons and wait policy. Actual clock/vertical-blank APIs remain platform services. |
| Random state | `40ae20`, `40ae30`, CRT `40ea60`, `40ea70` | Now provided by `runtime-support`: shared generator state, signed limits, seed remainder and arithmetic-fault outcomes; no host `rand()` substitution. |
| Trigonometric tables, readers and projections | `40d6b0..40d846` | Now provided by `math-support`: original approximate constant, signed angle/remainder policy, neighboring storage and wrapping projections. Every initialized sample matches on x86-64 and AArch64. |
| Sound pan conversion | `403550` | Now provided by `math-support`: exact integer expression preserves original truncation and returned low word. |
| Raster line and region fill helpers | `40d850`, `40d990` | Now provided by `raster-drawing`: exact byte rasterization, wrapped offsets, strict thresholds and fill arguments, through the shared DirectDraw test backend. |

The separately selected trigonometric readers at `40d710..40d846` are covered
locally; several lifted callers already express their arithmetic inline. The
normal numeric workload reaches initialization and pan. A hook declaration in
`native-image.h` alone does not show a body is lifted;
some hooks supply controlled inputs or invoke the original body again.

## Assembly and platform delivery

1. The reviewed application-body list above is now selected as C. Continue auditing
   actual normal-program reachability during assembly; this list was never an
   exhaustive decompilation inventory. More variants of completed examples cannot
   substitute for a normal-entry source program.
2. Complete the program-owned C object graph and service bindings for the exported
   components. `program-state.c` supplies the first owner and startup connections.
   Some views duplicate the same original cells: shell control/menu input,
   shell shift/score-screen shift and title/flow surfaces. Surface publication
   and the callback/dispatch entries synchronize these specific read views.
   Preserve other aliases between scene/flow/surface views, linked object
   lifetimes, callback owners and the historically unsafe event-memory behavior.
   The mixed program currently transports these through original image cells;
   the standalone program needs real owners and shared storage. Linker resolution
   alone does not establish correct state transport.
3. Replace retained CRT services with explicit portable library adapters, including
   buffered file state, allocation failure, random behavior and process exit.
   Extract immutable data/resource inputs with their provenance; do not copy the
   executable's code into a supposed source-only runtime.
4. Normal Windows execution now reaches title/menu/gameplay/editor/score scenes,
   progression, cleanup and shutdown. Review the specific unsupported status and
   scratch-history paths; local counterexamples remain the primary debugging path.
5. The standalone C source archive now includes declared Windows dependencies,
   data/resources and reproducible build/run instructions. Extraction and a fresh
   build outside the workbench pass. Complete the remaining fidelity/coverage
   review before declaring the full translation complete. Native non-Windows
   backends are outside project scope.

The shared Wine environment supplies candidate-neutral test capabilities. Target
boundaries and state mappings belong here; platform behavior belongs in reusable
backends. Existing interfaces, C service bridges, `candidate apply`, source export
and Nix infrastructure remain the path. No new authority format is introduced.
