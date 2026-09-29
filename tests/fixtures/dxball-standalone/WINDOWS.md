# DX-Ball from lifted C

This source project builds a 32-bit Windows application from the selected C
components, program-owned state and Windows SDK adapters. Building and running
the game requires neither the original executable nor the lifting workbench.
The original binary supplied disassembly and immutable data during preparation;
`program/program-seed.json` records those data spans and their provenance.

## Build and run

Use GNU Make and a 32-bit MinGW-w64 C toolchain, including its Windows headers,
import libraries and `windres` resource compiler:

```sh
make -j2 CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar dxball.exe
```

This explicit target builds the game. The existing default `all` target builds
separate component consumers. A fresh source handoff contains no object files;
keep builds for different toolchains in separate directories.
`WINDRES` defaults to the companion of the selected GCC and can be overridden.
The original icon payloads are retained in `program/icon-*.bin` and compiled
through `program/windows-resources.rc`; they contain no executable code.

The clean handoff supplies its PCX, SBK, WAV, MDS and board files in `assets/`.
Copy `dxball.exe` there and run with that directory as the working directory:

```sh
cp dxball.exe assets/
cd assets
```

Windows supplies Win32, DirectDraw,
DirectSound and WinMM. The compiler runtime is linked statically; the executable
imports only Windows platform DLLs. Board editing writes `Default.bds`, and the
game can update `score.dat`, so use a writable copy of the supplied assets.

On Linux, use the repository's headless Wayland environment for Wine:

```sh
spaghetti-headless-wayland wine ./dxball.exe
```

The window remains in that headless desktop until closed. For automated input
and screenshots, use the shared `tests/fixtures/wine-desktop/run.py` runner from
an installed lifting environment, inside `spaghetti-headless-wayland --capture`.
The supplied `program/desktop-*-actions.txt` workloads exercise gameplay, the
editor and score screens through ordinary window messages. The runner copies
assets into a private runtime directory before executing a candidate.

## Where to work

- `lifted/components/NAME/sources/source/` contains authored component C and
  shared boundary types. Each component's README and interface describe its
  inputs, services and comparison scope.
- `program/` owns the application state, connects neighboring components and
  adapts their services to Windows. `win32-entry.c` supplies WinMain.
- `program/bridges/` contains generated service bindings for normal execution.
  `bridges/` retains the traced bindings used by local comparison consumers.
- `common/` contains shared types, adapters and optional diagnostic consumers.
  They are selected by Makefile targets; they are not all linked into the game.

Edit C and rerun the same make command for an ordinary local rebuild. That does
not refresh its comparison evidence. To retain checked provenance, perform the
component check/edit/replay workflow in the workbench and use `candidate apply`
to update this project and run the affected integration workloads. Unchanged
neighboring sources and objects remain reusable.

`DXBALL_PROGRAM_REPORT=program-report.json` enables optional scene and entry-count
diagnostics. Normal assembly omits service protocol logging. Its diagnostic
targets and Python checks are optional; the game has no Python dependency.

## Evidence and limits

The retained selection has 49 components and 190 entries, with 1,180 original/C
comparison cases. Normal Windows runs exercise title, menu and gameplay; SDK
adapter checks also cover MIDI completion, reset and callback requeue. These
finite comparisons are practical assurance, not universal formal equivalence.
The accompanying integration record gives the current scene and handoff results.

Some original behavior depends on unsafe memory access or untouched scratch
bytes. The adapters retain reviewed aliases and histories; unsupported addresses
produce explicit capability diagnostics. Arbitrary malformed assets and device
failure histories are not claimed equivalent. Windows runtime dependencies are
intentional. Porting this application away from Windows is outside project scope.
